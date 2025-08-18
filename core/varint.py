from typing import Tuple


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value <= 0x3F:
        return bytes([value & 0x3F])
    if value <= 0x3FFF:
        v = 0x40 << 8 | value
        return v.to_bytes(2, "big")
    if value <= 0x3FFFFFFF:
        v = 0x80 << 24 | value
        return v.to_bytes(4, "big")
    if value <= 0x3FFFFFFFFFFFFFFF:
        v = 0xC0 << 56 | value
        return v.to_bytes(8, "big")
    raise ValueError("value too large")


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("buffer too short")
    first = data[offset]
    prefix = first >> 6
    if prefix == 0:
        return first & 0x3F, offset + 1
    if prefix == 1:
        if offset + 2 > len(data):
            raise ValueError("buffer too short")
        v = int.from_bytes(data[offset : offset + 2], "big") & 0x3FFF
        return v, offset + 2
    if prefix == 2:
        if offset + 4 > len(data):
            raise ValueError("buffer too short")
        v = int.from_bytes(data[offset : offset + 4], "big") & 0x3FFFFFFF
        return v, offset + 4
    if prefix == 3:
        if offset + 8 > len(data):
            raise ValueError("buffer too short")
        v = int.from_bytes(data[offset : offset + 8], "big") & 0x3FFFFFFFFFFFFFFF
        return v, offset + 8
    raise ValueError("invalid prefix")
