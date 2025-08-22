from dataclasses import dataclass
from typing import Dict, Tuple, List, Optional
import os
import time
import random


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _u24(n: int) -> bytes:
    return n.to_bytes(3, "big")


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def build_settings_frame(settings: Dict[int, int]) -> bytes:
    payload = bytearray()
    for sid, val in sorted(settings.items()):
        payload.extend(sid.to_bytes(2, "big"))
        payload.extend(val.to_bytes(4, "big"))
    length = _u24(len(payload))
    typ = bytes([0x4])
    flags = bytes([0x0])
    stream_id = _u32(0)
    return length + typ + flags + stream_id + bytes(payload)


def build_ping_frame(opaque: bytes, ack: bool = False) -> bytes:
    if len(opaque) != 8:
        raise ValueError("opaque must be 8 bytes")
    length = _u24(8)
    typ = bytes([0x6])
    flags = bytes([0x1 if ack else 0x0])
    stream_id = _u32(0)
    return length + typ + flags + stream_id + opaque


def build_data_frame(stream_id: int, data: bytes, end_stream: bool = True) -> bytes:
    if stream_id <= 0 or stream_id % 2 == 0:
        raise ValueError("stream_id must be positive odd for client-initiated")
    length = _u24(len(data))
    typ = bytes([0x0])
    flags = bytes([0x1 if end_stream else 0x0])
    sid = _u32(stream_id & 0x7FFFFFFF)
    return length + typ + flags + sid + data


def parse_frames(data: bytes, offset: int = 0) -> Tuple[List[Tuple[int, int, int, bytes]], int]:
    out: List[Tuple[int, int, int, bytes]] = []
    off = offset
    n = len(data)
    while off + 9 <= n:
        length = int.from_bytes(data[off:off+3], "big")
        typ = data[off+3]
        flags = data[off+4]
        sid = int.from_bytes(data[off+5:off+9], "big") & 0x7FFFFFFF
        end = off + 9 + length
        if end > n:
            break
        pl = data[off+9:end]
        out.append((typ, flags, sid, pl))
        off = end
    return out, off


@dataclass
class OuterPingScheduler:
    base_interval_ms: int
    next_at_ms: int

    @staticmethod
    def now_ms() -> int:
        return int(time.time() * 1000)

    @classmethod
    def start(cls, base_interval_ms: int) -> "OuterPingScheduler":
        now = cls.now_ms()
        jitter = int(round(base_interval_ms * 0.1 * (random.random() * 2 - 1)))
        return cls(base_interval_ms=base_interval_ms, next_at_ms=now + base_interval_ms + jitter)

    def due(self, now_ms: int | None = None) -> bool:
        t = self.now_ms() if now_ms is None else now_ms
        return t >= self.next_at_ms

    def roll(self, now_ms: int | None = None) -> None:
        t = self.now_ms() if now_ms is None else now_ms
        jitter = int(round(self.base_interval_ms * 0.1 * (random.random() * 2 - 1)))
        self.next_at_ms = t + self.base_interval_ms + jitter


@dataclass
class OuterH2StreamTransport:
    settings: Dict[int, int]

    def preface_and_settings(self) -> bytes:
        return H2_PREFACE + build_settings_frame(self.settings)

    def data_frames(self, stream_id: int, payload: bytes) -> List[bytes]:
        return [build_data_frame(stream_id, payload, True)]

    def ping(self, scheduler: OuterPingScheduler) -> Tuple[bool, bytes | None]:
        if scheduler.due():
            opaque = os.urandom(8)
            scheduler.roll()
            return True, build_ping_frame(opaque, ack=False)
        return False, None


@dataclass
class OuterH2Receiver:
    buf: bytes = b""

    def feed(self, data: bytes) -> None:
        self.buf += data

    def read_frames(self) -> List[Tuple[int, int, int, bytes]]:
        if self.buf.startswith(H2_PREFACE):
            self.buf = self.buf[len(H2_PREFACE):]
        frames, used = parse_frames(self.buf, 0)
        self.buf = self.buf[used:]
        return frames

    def read_stream_data(self, stream_id: int) -> bytes:
        frames = self.read_frames()
        parts: List[bytes] = []
        for typ, flags, sid, pl in frames:
            if typ == 0x0 and sid == stream_id:
                parts.append(pl)
        return b"".join(parts)


