from hashlib import sha256
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


PATH_CONTROL_TYPE = 0x20


def build_path_control_payload(data: bytes) -> bytes:
    return bytes(data)


CF_SUBTYPE = 0x01


def build_cf_payload(queue_depth: int, rtt_ms: int, level: int) -> bytes:
    return bytes([CF_SUBTYPE]) + queue_depth.to_bytes(2, "big") + rtt_ms.to_bytes(2, "big") + bytes([level & 0xFF])


def parse_cf_payload(data: bytes):
    if not data or data[0] != CF_SUBTYPE:
        return None
    if len(data) < 6:
        return None
    q = int.from_bytes(data[1:3], "big")
    rtt = int.from_bytes(data[3:5], "big")
    lvl = data[5]
    return {"queue_depth": q, "rtt_ms": rtt, "level": lvl}


def _u16(n: int) -> bytes:
    return int(n).to_bytes(2, "big")


def _u32(n: int) -> bytes:
    return int(n).to_bytes(4, "big")


def _u64(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def _sig_input(version: int, typ: int, flags: int, next_node20: bytes, expiry_u32: int, prev_node20: bytes, ts_u64: int) -> bytes:
    return sha256(b"BN-L1-seg" + bytes([version & 0xFF]) + bytes([typ & 0xFF]) + bytes([flags & 0xFF]) + next_node20 + _u32(expiry_u32) + prev_node20 + _u64(ts_u64)).digest()


def sign_segment(version: int, typ: int, flags: int, prev_node20: bytes, next_node20: bytes, expiry_u32: int, ts_u64: int, priv: Ed25519PrivateKey) -> bytes:
    if len(prev_node20) != 20 or len(next_node20) != 20:
        raise ValueError("node id must be 20 bytes")
    msg = _sig_input(version, typ, flags, next_node20, expiry_u32, prev_node20, ts_u64)
    return priv.sign(msg)


def verify_segment(version: int, typ: int, flags: int, prev_node20: bytes, next_node20: bytes, expiry_u32: int, ts_u64: int, sig: bytes, pub: Ed25519PublicKey) -> bool:
    try:
        msg = _sig_input(version, typ, flags, next_node20, expiry_u32, prev_node20, ts_u64)
        pub.verify(sig, msg)
        return True
    except Exception:
        return False


def build_l1_payload(version: int, typ: int, flags: int, prev_node20: bytes, segments: List[Tuple[bytes, int, int, Ed25519PrivateKey]], cf: Optional[bytes] = None) -> bytes:
    seg_bytes: List[bytes] = []
    for next_node, expiry, ts, priv in segments:
        sig = sign_segment(version, typ, flags, prev_node20, next_node, int(expiry), int(ts), priv)
        seg = next_node + _u32(expiry) + _u64(ts) + _u16(len(sig)) + sig
        seg_bytes.append(seg)
    seg_block = b"".join(seg_bytes)
    cf_block = cf if cf else b""
    segcnt = len(segments)
    header = bytes([version & 0xFF]) + bytes([typ & 0xFF]) + _u16(6 + len(seg_block) + len(cf_block)) + _u16(6 + len(seg_block) + len(cf_block)) + bytes([flags & 0xFF]) + bytes([segcnt & 0xFF])
    return header + seg_block + cf_block


def parse_l1_payload(payload: bytes) -> Optional[Dict[str, object]]:
    if len(payload) < 6:
        return None
    version = payload[0]
    typ = payload[1]
    hlen = int.from_bytes(payload[2:4], "big")
    plen = int.from_bytes(payload[4:6], "big")
    flags = payload[6]
    segcnt = payload[7]
    off = 8
    segs: List[Dict[str, object]] = []
    for _ in range(segcnt):
        if off + 20 + 4 + 8 + 2 > len(payload):
            return None
        next_node = payload[off:off+20]
        off += 20
        expiry = int.from_bytes(payload[off:off+4], "big")
        off += 4
        ts = int.from_bytes(payload[off:off+8], "big")
        off += 8
        sl = int.from_bytes(payload[off:off+2], "big")
        off += 2
        if off + sl > len(payload):
            return None
        sig = payload[off:off+sl]
        off += sl
        segs.append({"next_node": next_node, "expiry": expiry, "timestamp": ts, "sig": sig})
    cf = payload[off:] if off < len(payload) else b""
    return {"version": version, "type": typ, "header_len": hlen, "payload_len": plen, "flags": flags, "segments": segs, "cf": cf}


