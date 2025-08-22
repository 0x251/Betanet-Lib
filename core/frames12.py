from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class Frame12:
    length: int
    type: int
    stream_id: int
    aad: int
    ciphertext: bytes
    tag: bytes


def encode_frame12(f: Frame12) -> bytes:
    buf = bytearray()
    buf.extend(f.length.to_bytes(3, "big"))
    buf.append(f.type & 0xFF)
    buf.extend(int(f.stream_id).to_bytes(4, "big"))
    buf.extend(int(f.aad).to_bytes(2, "big"))
    buf.extend(f.ciphertext)
    buf.extend(f.tag)
    return bytes(buf)


def decode_frame12(data: bytes, offset: int = 0) -> Tuple[Frame12, int]:
    if offset + 10 > len(data):
        raise ValueError("short header")
    length = int.from_bytes(data[offset:offset+3], "big")
    typ = data[offset+3]
    sid = int.from_bytes(data[offset+4:offset+8], "big")
    aad = int.from_bytes(data[offset+8:offset+10], "big")
    end = offset + 3 + length
    if end > len(data):
        raise ValueError("short ciphertext")
    if length + 3 > 65535:
        raise ValueError("length_exceeds_max")
    if end - 16 < offset + 10:
        raise ValueError("short_tag")
    ct = data[offset+10:end-16]
    tag = data[end-16:end]
    return Frame12(length=length, type=typ, stream_id=sid, aad=aad, ciphertext=ct, tag=tag), end


