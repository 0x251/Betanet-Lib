from dataclasses import dataclass
from typing import Tuple, Optional, Dict

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from betanet.core.crypto import DirectionKeys, hkdf_expand_label, derive_ns
from betanet.core.frames12 import Frame12, encode_frame12, decode_frame12


def _aad_bytes(length_u24: int, typ: int, stream_id: int, aad_u16: int) -> bytes:
    return length_u24.to_bytes(3, "big") + bytes([typ & 0xFF]) + int(stream_id).to_bytes(4, "big") + int(aad_u16).to_bytes(2, "big")


@dataclass
class Session12:
    send: DirectionKeys
    recv: DirectionKeys
    def __init__(self, send: DirectionKeys, recv: DirectionKeys):
        self.send = send
        self.recv = recv
        self.conn_window_send = 65535
        self.conn_window_recv = 65535
        self.stream_window_send: Dict[int, int] = {}
        self.stream_window_recv: Dict[int, int] = {}
        self.init_stream_window = 32768
        self.prev_recv: Optional[DirectionKeys] = None
        self.accepted_new_after_update = 0
        self._pending: list[bytes] = []

    def encrypt(self, typ: int, stream_id: int, aad_u16: int, plaintext: bytes) -> bytes:
        if typ == 0:
            sw = self.stream_window_send.get(stream_id, self.init_stream_window)
            if len(plaintext) > sw or len(plaintext) > self.conn_window_send:
                raise ValueError("flow_control_violation")
            self.stream_window_send[stream_id] = sw - len(plaintext)
            self.conn_window_send -= len(plaintext)
        length = 1 + 4 + 2 + len(plaintext) + 16
        aad = _aad_bytes(length, typ, stream_id, aad_u16)
        ct = self.send.seal(aad, plaintext)
        if len(ct) < 16:
            raise ValueError("bad_ciphertext")
        tag = ct[-16:]
        body = ct[:-16]
        frame = Frame12(length=length, type=typ, stream_id=stream_id, aad=aad_u16, ciphertext=body, tag=tag)
        return encode_frame12(frame)

    def decrypt(self, buf: bytes, offset: int = 0) -> Tuple[int, int, int, bytes, int]:
        f, off = decode_frame12(buf, offset)
        aad = _aad_bytes(f.length, f.type, f.stream_id, f.aad)
        ct = f.ciphertext + f.tag
        pt: bytes
        try:
            pt = self.recv.open(aad, ct)
            if self.prev_recv is not None:
                self.accepted_new_after_update += 1
                if self.accepted_new_after_update >= 3:
                    self.prev_recv = None
        except Exception:
            if self.prev_recv is not None:

                pt = self.prev_recv.open(aad, ct)
            else:
                raise
        if f.type == 3:
            th = pt
            self._switch_recv(th)
            return f.type, f.stream_id, f.aad, pt, off
        if f.type == 0:
            sw = self.stream_window_recv.get(f.stream_id, self.init_stream_window)
            sw -= len(pt)
            self.stream_window_recv[f.stream_id] = sw
            self.conn_window_recv -= len(pt)
            if sw <= self.init_stream_window // 2 and f.stream_id > 0:
                credit = self.init_stream_window // 2
                payload = bytes([1]) + int(credit).to_bytes(4, "big")
                self._pending.append(self.encrypt(1, f.stream_id, 0, payload))
                self.stream_window_recv[f.stream_id] = sw + credit
            if self.conn_window_recv <= 65535 // 2:
                credit_c = 65535 // 2
                payload_c = bytes([0]) + int(credit_c).to_bytes(4, "big")
                self._pending.append(self.encrypt(1, 0, 0, payload_c))
                self.conn_window_recv += credit_c
        if f.type == 1 and len(pt) >= 5:
            scope = pt[0]
            credit = int.from_bytes(pt[1:5], "big")
            if scope == 0:
                self.conn_window_send += credit
            elif scope == 1:
                cur = self.stream_window_send.get(f.stream_id, self.init_stream_window)
                self.stream_window_send[f.stream_id] = cur + credit
        return f.type, f.stream_id, f.aad, pt, off

    def request_key_update(self, transcript_hash: bytes) -> bytes:
        buf = self.encrypt(3, 0, 0, transcript_hash)
        self._switch_send(transcript_hash)
        self.accepted_new_after_update = 0
        return buf

    def close(self, code: int, reason: bytes = b"") -> bytes:
        if not isinstance(reason, (bytes, bytearray)):
            raise ValueError("reason must be bytes")
        if len(reason) > 65535:
            raise ValueError("reason too long")
        payload = int(code & 0xFFFF).to_bytes(2, "big") + len(reason).to_bytes(2, "big") + bytes(reason)
        return self.encrypt(4, 0, 0, payload)

    def pop_pending(self) -> Optional[bytes]:
        if not self._pending:
            return None
        return self._pending.pop(0)

    def _switch_send(self, th: bytes) -> None:
        new_key = hkdf_expand_label(self.send.key, b"next", 32)
        self.send = DirectionKeys(new_key, derive_ns(new_key), 0)

    def _switch_recv(self, th: bytes) -> None:
        self.prev_recv = self.recv
        new_key = hkdf_expand_label(self.recv.key, b"next", 32)
        self.recv = DirectionKeys(new_key, derive_ns(new_key), 0)


def new_session12_from_k0(k0: bytes, is_client: bool) -> Session12:
    from betanet.core.crypto import derive_inner_keys_from_k0
    keys = derive_inner_keys_from_k0(k0)
    send = keys.client if is_client else keys.server
    recv = keys.server if is_client else keys.client
    return Session12(send, recv)


