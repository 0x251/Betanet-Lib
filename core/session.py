from dataclasses import dataclass
from typing import Optional, Tuple, List
import os
import time

from betanet.core.frames import (
    Frame,
    encode_frame,
    decode_frame,
    STREAM,
    KEY_UPDATE,
    WINDOW_UPDATE,
)
from betanet.core.crypto import derive_inner_keys_from_k0
from betanet.core.varint import encode_varint, decode_varint


@dataclass
class FlowState:
    window: int = 65535

    def consume(self, n: int) -> bool:
        if n > self.window:
            return False
        self.window -= n
        return True

    def add(self, n: int) -> None:
        self.window += n


class HtxSession:
    def __init__(
        self,
        k0: bytes,
        is_client: bool,
        max_bytes: int = 8 * 1024 * 1024 * 1024,
        max_frames: int = 65536,
        max_seconds: int = 3600,
    ):
        self.keys = derive_inner_keys_from_k0(k0)
        self.is_client = is_client
        self.send = self.keys.client if is_client else self.keys.server
        self.recv = self.keys.server if is_client else self.keys.client
        self.prev_recv = None
        self.has_switched = False
        self.stream_windows: dict[int, FlowState] = {}
        self.buffered: List[bytes] = []
        self.awaiting_update = False
        self.pending: List[bytes] = []
        self.max_bytes = max_bytes
        self.max_frames = max_frames
        self.max_seconds = max_seconds
        self.sent_bytes = 0
        self.sent_frames = 0
        self.last_rekey = time.time()

    def _flow_for(self, sid: int) -> FlowState:
        st = self.stream_windows.get(sid)
        if st is None:
            st = FlowState()
            self.stream_windows[sid] = st
        return st

    def _seal(self, typ: int, stream_id: Optional[int], plaintext: bytes) -> bytes:
        aad = bytes([typ]) + (b"" if stream_id is None else encode_varint(stream_id))
        ct = self.send.seal(aad, plaintext)
        f = Frame(length=len(ct), type=typ, stream_id=stream_id, ciphertext=ct)
        return encode_frame(f)

    def encrypt_frame(
        self, typ: int, stream_id: Optional[int], plaintext: bytes
    ) -> bytes:
        buf = self._seal(typ, stream_id, plaintext)
        self.sent_frames += 1
        self.sent_bytes += len(plaintext)
        self._maybe_schedule_key_update()
        return buf

    def _maybe_schedule_key_update(self) -> None:
        if (
            (self.sent_bytes >= self.max_bytes)
            or (self.sent_frames >= self.max_frames)
            or (time.time() - self.last_rekey >= self.max_seconds)
        ):
            th = os.urandom(32)
            ku = self._seal(KEY_UPDATE, None, th)
            self.pending.append(ku)
            self._switch_send(th)
            self.sent_bytes = 0
            self.sent_frames = 0
            self.last_rekey = time.time()

    def pop_pending(self) -> Optional[bytes]:
        if not self.pending:
            return None
        return self.pending.pop(0)

    def request_key_update(self, transcript_hash: bytes) -> bytes:
        buf = self._seal(KEY_UPDATE, None, transcript_hash)
        self._switch_send(transcript_hash)
        self.last_rekey = time.time()
        self.sent_bytes = 0
        self.sent_frames = 0
        return buf

    def _switch_send(self, transcript_hash: bytes) -> None:
        self.keys = self.keys.next(transcript_hash)
        self.send = self.keys.client if self.is_client else self.keys.server

    def _switch_recv(self, transcript_hash: bytes) -> None:
        self.keys = self.keys.next(transcript_hash)
        self.prev_recv = self.recv
        self.recv = self.keys.server if self.is_client else self.keys.client
        self.awaiting_update = False
        self.has_switched = True

    def decrypt_frame(
        self, buf: bytes, offset: int = 0
    ) -> Tuple[Optional[int], Optional[int], Optional[bytes], int, Optional[bytes]]:
        f, off = decode_frame(buf, offset)
        aad = bytes([f.type]) + (
            b"" if f.stream_id is None else encode_varint(f.stream_id)
        )
        if self.has_switched and self.prev_recv is not None:
            try:
                _ = self.prev_recv.try_open_at(
                    aad, f.ciphertext, self.prev_recv.counter
                )
                return None, None, None, off, None
            except Exception:
                pass
        try:
            pt = self.recv.open_with_lookahead(aad, f.ciphertext, max_skip=8)
        except Exception:
            if self.has_switched:
                return None, None, None, off, None
            if self.prev_recv is not None:
                try:
                    _ = self.prev_recv.open_with_lookahead(
                        aad, f.ciphertext, max_skip=8
                    )
                    return None, None, None, off, None
                except Exception:
                    pass
            self.buffered.append(buf[offset:off])
            self.awaiting_update = True
            return None, None, None, off, None
        if f.type == KEY_UPDATE:
            th = pt
            self._switch_recv(th)
            return KEY_UPDATE, None, th, off, None
        if f.type == WINDOW_UPDATE:
            inc, _ = decode_varint(pt, 0)
            if f.stream_id is not None:
                self._flow_for(f.stream_id).add(inc)
            return WINDOW_UPDATE, f.stream_id, pt, off, None
        if f.type == STREAM:
            out = None
            if f.stream_id is not None:
                st = self._flow_for(f.stream_id)
                st.consume(len(pt))
                if st.window <= 65535 // 2:
                    inc = 65535 // 2
                    st.add(inc)
                    out = self._seal(WINDOW_UPDATE, f.stream_id, encode_varint(inc))
            return STREAM, f.stream_id, pt, off, out
        return f.type, f.stream_id, pt, off, None

    def drain_buffered(self) -> List[Tuple[int, int, bytes]]:
        out: List[Tuple[int, int, bytes]] = []
        remaining: List[bytes] = []
        for frag in self.buffered:
            try:
                f, _ = decode_frame(frag, 0)
                aad = bytes([f.type]) + (
                    b"" if f.stream_id is None else encode_varint(f.stream_id)
                )
                pt = self.recv.open(aad, f.ciphertext)
                if f.type == STREAM and f.stream_id is not None:
                    out.append((f.type, f.stream_id, pt))
            except Exception:
                remaining.append(frag)
        self.buffered = remaining
        return out
