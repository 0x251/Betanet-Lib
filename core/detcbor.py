from typing import Any, Dict, List, Tuple


def _encode_uint(n: int) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    if n <= 23:
        return bytes([0x00 | n])
    if n <= 0xFF:
        return bytes([0x18, n])
    if n <= 0xFFFF:
        return bytes([0x19]) + n.to_bytes(2, "big")
    if n <= 0xFFFFFFFF:
        return bytes([0x1A]) + n.to_bytes(4, "big")
    return bytes([0x1B]) + n.to_bytes(8, "big")


def _encode_nint(n: int) -> bytes:
    if n >= 0:
        raise ValueError("n must be negative")
    val = -1 - n
    if val <= 23:
        return bytes([0x20 | val])
    if val <= 0xFF:
        return bytes([0x38, val])
    if val <= 0xFFFF:
        return bytes([0x39]) + val.to_bytes(2, "big")
    if val <= 0xFFFFFFFF:
        return bytes([0x3A]) + val.to_bytes(4, "big")
    return bytes([0x3B]) + val.to_bytes(8, "big")


def _encode_len(major: int, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    if length <= 23:
        return bytes([((major & 0x7) << 5) | length])
    if length <= 0xFF:
        return bytes([((major & 0x7) << 5) | 24, length])
    if length <= 0xFFFF:
        return bytes([((major & 0x7) << 5) | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([((major & 0x7) << 5) | 26]) + length.to_bytes(4, "big")
    return bytes([((major & 0x7) << 5) | 27]) + length.to_bytes(8, "big")


def _encode_bstr(b: bytes) -> bytes:
    head = _encode_len(2, len(b))
    return head + b


def _encode_tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    head = _encode_len(3, len(b))
    return head + b


def _encode_array(items: List[Any]) -> bytes:
    encoded_items = [encode(item) for item in items]
    head = _encode_len(4, len(encoded_items))
    return head + b"".join(encoded_items)


def _encode_map(m: Dict[Any, Any]) -> bytes:
    encoded_pairs: List[Tuple[bytes, bytes]] = []
    for key, value in m.items():
        ek = encode(key)
        ev = encode(value)
        encoded_pairs.append((ek, ev))
    encoded_pairs.sort(key=lambda p: p[0])
    dedup_check: Dict[bytes, bool] = {}
    for ek, _ in encoded_pairs:
        if ek in dedup_check:
            raise ValueError("duplicate map key under bytewise equality")
        dedup_check[ek] = True
    head = _encode_len(5, len(encoded_pairs))
    buf = bytearray(head)
    for ek, ev in encoded_pairs:
        buf.extend(ek)
        buf.extend(ev)
    return bytes(buf)


def _encode_simple(value: Any) -> bytes:
    if value is False:
        return bytes([0xF4])
    if value is True:
        return bytes([0xF5])
    if value is None:
        return bytes([0xF6])
    raise ValueError("unsupported simple value")


def encode(value: Any) -> bytes:
    if isinstance(value, bool):
        return _encode_simple(value)
    if value is None:
        return _encode_simple(value)
    if isinstance(value, int):
        return _encode_uint(value) if value >= 0 else _encode_nint(value)
    if isinstance(value, (bytes, bytearray)):
        return _encode_bstr(bytes(value))
    if isinstance(value, str):
        return _encode_tstr(value)
    if isinstance(value, (list, tuple)):
        return _encode_array(list(value))
    if isinstance(value, dict):
        return _encode_map(value)
    raise TypeError("unsupported type for deterministic CBOR")


def dumps(value: Any) -> bytes:
    return encode(value)



def _read_len(data: bytes, offset: int, ai: int) -> Tuple[int, int]:
    if ai <= 23:
        return ai, offset
    if ai == 24:
        if offset + 1 > len(data):
            raise ValueError("truncated")
        return data[offset], offset + 1
    if ai == 25:
        if offset + 2 > len(data):
            raise ValueError("truncated")
        return int.from_bytes(data[offset : offset + 2], "big"), offset + 2
    if ai == 26:
        if offset + 4 > len(data):
            raise ValueError("truncated")
        return int.from_bytes(data[offset : offset + 4], "big"), offset + 4
    if ai == 27:
        if offset + 8 > len(data):
            raise ValueError("truncated")
        return int.from_bytes(data[offset : offset + 8], "big"), offset + 8
    raise ValueError("indefinite length not allowed")


def _decode_item(data: bytes, offset: int) -> Tuple[Any, int]:
    if offset >= len(data):
        raise ValueError("truncated")
    ib = data[offset]
    offset += 1
    mt = (ib >> 5) & 0x7
    ai = ib & 0x1F
    if mt == 0:
        n, offset = _read_len(data, offset, ai)
        return n, offset
    if mt == 1:
        n, offset = _read_len(data, offset, ai)
        return -1 - n, offset
    if mt == 2:
        ln, offset = _read_len(data, offset, ai)
        end = offset + ln
        if end > len(data):
            raise ValueError("truncated")
        return bytes(data[offset:end]), end
    if mt == 3:
        ln, offset = _read_len(data, offset, ai)
        end = offset + ln
        if end > len(data):
            raise ValueError("truncated")
        s = bytes(data[offset:end]).decode("utf-8")
        return s, end
    if mt == 4:
        ln, offset = _read_len(data, offset, ai)
        out: List[Any] = []
        for _ in range(ln):
            v, offset = _decode_item(data, offset)
            out.append(v)
        return out, offset
    if mt == 5:
        ln, offset = _read_len(data, offset, ai)
        out_map: Dict[Any, Any] = {}
        for _ in range(ln):
            k, offset = _decode_item(data, offset)
            v, offset = _decode_item(data, offset)
            if k in out_map:
                raise ValueError("duplicate map key")
            out_map[k] = v
        return out_map, offset
    if mt == 7:
        if ai == 20:
            return False, offset
        if ai == 21:
            return True, offset
        if ai == 22:
            return None, offset
        raise ValueError("unsupported simple value")
    raise ValueError("unsupported major type")


def loads(data: bytes) -> Any:
    v, off = _decode_item(data, 0)
    if off != len(data):
        raise ValueError("extra bytes after value")
    return v