from dataclasses import dataclass
from typing import Optional, Tuple

from betanet.core.varint import encode_varint, decode_varint
from betanet.core.enums import FrameType


STREAM = FrameType.STREAM
PING = FrameType.PING
CLOSE = FrameType.CLOSE
KEY_UPDATE = FrameType.KEY_UPDATE
WINDOW_UPDATE = FrameType.WINDOW_UPDATE

FLOW_WINDOW_DEFAULT = 65535


@dataclass
class Frame:
    length: int
    type: FrameType
    stream_id: Optional[int]
    ciphertext: bytes


def encode_frame(frame: Frame) -> bytes:
    buf = bytearray()
    buf.extend(frame.length.to_bytes(3, "big"))
    buf.append(int(frame.type) & 0xFF)
    if int(frame.type) in (int(STREAM), int(WINDOW_UPDATE)):
        buf.extend(encode_varint(frame.stream_id or 0))
    buf.extend(frame.ciphertext)
    return bytes(buf)


def decode_frame(data: bytes, offset: int = 0) -> Tuple[Frame, int]:
    if offset + 4 > len(data):
        raise ValueError("short header")
    length = int.from_bytes(data[offset : offset + 3], "big")
    typ = data[offset + 3]
    off = offset + 4
    stream_id = None
    if typ in (int(STREAM), int(WINDOW_UPDATE)):
        stream_id, off = decode_varint(data, off)
    end = off + length
    if end > len(data):
        raise ValueError("short ciphertext")
    ciphertext = data[off:end]
    return Frame(
        length=length, type=FrameType(typ), stream_id=stream_id, ciphertext=ciphertext
    ), end
