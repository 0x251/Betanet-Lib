import os
import time
from typing import Dict, Tuple

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM



def _cbor_encode_uint(n: int) -> bytes:
    if n < 0:
        raise ValueError("only unsigned supported")
    if n <= 23:
        return bytes([0x00 | n])
    if n <= 0xFF:
        return bytes([0x18]) + n.to_bytes(1, "big")
    if n <= 0xFFFF:
        return bytes([0x19]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([0x1A]) + n.to_bytes(4, "big")
    return bytes([0x1B]) + n.to_bytes(8, "big")


def _cbor_encode_bstr(b: bytes) -> bytes:
    l = len(b)
    if l <= 23:
        head = bytes([0x40 | l])
    elif l <= 0xFF:
        head = bytes([0x58, l])
    elif l <= 0xFFFF:
        head = bytes([0x59]) + l.to_bytes(2, "big")
    elif l <= 0xFFFFFFFF:
        head = bytes([0x5A]) + l.to_bytes(4, "big")
    else:
        head = bytes([0x5B]) + l.to_bytes(8, "big")
    return head + b


def _cbor_encode_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    l = len(b)
    if l <= 23:
        head = bytes([0x60 | l])
    elif l <= 0xFF:
        head = bytes([0x78, l])
    elif l <= 0xFFFF:
        head = bytes([0x79]) + l.to_bytes(2, "big")
    elif l <= 0xFFFFFFFF:
        head = bytes([0x7A]) + l.to_bytes(4, "big")
    else:
        head = bytes([0x7B]) + l.to_bytes(8, "big")
    return head + b


def _cbor_encode_map(m: Dict[str, object]) -> bytes:
    l = len(m)
    if l <= 23:
        head = bytes([0xA0 | l])
    elif l <= 0xFF:
        head = bytes([0xB8, l])
    else:
        raise ValueError("map too large")
    out = bytearray(head)
    for k, v in m.items():
        out.extend(_cbor_encode_tstr(k))
        if isinstance(v, int):
            out.extend(_cbor_encode_uint(v))
        elif isinstance(v, (bytes, bytearray)):
            out.extend(_cbor_encode_bstr(bytes(v)))
        else:
            raise ValueError("unsupported type")
    return bytes(out)


def _cbor_expect(data: bytes, pos: int, want_major: int) -> Tuple[int, int, int]:
    if pos >= len(data):
        raise ValueError("short")
    ib = data[pos]
    major = ib >> 5
    addl = ib & 0x1F
    if major != want_major:
        raise ValueError("major mismatch")
    pos += 1
    if addl <= 23:
        val = addl
    elif addl == 24:
        val = data[pos]
        pos += 1
    elif addl == 25:
        val = int.from_bytes(data[pos:pos+2], "big")
        pos += 2
    elif addl == 26:
        val = int.from_bytes(data[pos:pos+4], "big")
        pos += 4
    elif addl == 27:
        val = int.from_bytes(data[pos:pos+8], "big")
        pos += 8
    else:
        raise ValueError("indefinite not supported")
    return val, addl, pos


def _cbor_decode_tstr(data: bytes, pos: int) -> Tuple[str, int]:
    l, addl, pos = _cbor_expect(data, pos, 3)
    s = data[pos:pos+l].decode("utf-8")
    return s, pos + l


def _cbor_decode_bstr(data: bytes, pos: int) -> Tuple[bytes, int]:
    l, addl, pos = _cbor_expect(data, pos, 2)
    b = data[pos:pos+l]
    return b, pos + l


def _cbor_decode_uint(data: bytes, pos: int) -> Tuple[int, int]:
    val, addl, pos = _cbor_expect(data, pos, 0)
    return val, pos


def cbor_decode_map(data: bytes) -> Dict[str, object]:
    l, addl, pos = _cbor_expect(data, 0, 5)
    out: Dict[str, object] = {}
    for _ in range(l):
        k, pos = _cbor_decode_tstr(data, pos)
        # Peek major
        major = data[pos] >> 5
        if major == 0:
            v, pos = _cbor_decode_uint(data, pos)
        elif major == 2:
            v, pos = _cbor_decode_bstr(data, pos)
        else:
            raise ValueError("unsupported value major")
        out[k] = v
    return out


def build_control_payload(prev_as: int, next_as: int, ts: int, flow: bytes, nonce: bytes, sig: bytes) -> bytes:
    m = {
        "prevAS": prev_as,
        "nextAS": next_as,
        "TS": ts,
        "FLOW": flow,
        "NONCE": nonce,
        "SIG": sig,
    }
    return _cbor_encode_map(m)


def is_control_stream(stream_id: int) -> bool:
    return stream_id == 2


def make_control_frame(sess: HtxSession, prev_as: int, next_as: int) -> bytes:
    ts = int(time.time())
    flow = os.urandom(8)
    nonce = os.urandom(8)
    sig = os.urandom(64)  # placeholder
    payload = build_control_payload(prev_as, next_as, ts, flow, nonce, sig)
    return sess.encrypt_frame(STREAM, 2, payload)


