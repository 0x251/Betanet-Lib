import base64
from typing import Dict, Optional, Tuple


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_token_char(ch: int) -> bool:
    return ch in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"


def _parse_params(s: bytes) -> Dict[str, str]:
    parts = [p.strip() for p in s.split(b";") if p.strip()]
    out: Dict[str, str] = {}
    for p in parts:
        if b"=" not in p:
            continue
        k, v = p.split(b"=", 1)
        out[k.decode("ascii", errors="ignore")] = v.decode("ascii", errors="ignore")
    return out


def build_header_value(tok120: bytes, ctx: Optional[str] = None) -> bytes:
    if len(tok120) != 120:
        raise ValueError("tok must be 120 bytes")
    b64 = _b64url_nopad(tok120)
    items = [f"v=v1", f"tok={b64}"]
    if ctx is not None:
        items.append(f"ctx={ctx}")
    return ("; ".join(items)).encode("ascii")


def validate_header(name: bytes, value: bytes) -> Tuple[bool, str]:
    line_len = len(name) + 2 + len(value)
    if line_len > 256:
        return False, "oversize"
    if name.strip().lower() != b"bn-ticket":
        return False, "wrong_name"
    params = _parse_params(value)
    v = params.get("v", "")
    if v != "v1":
        return False, "bad_version"
    tok = params.get("tok", "")
    if not tok or ("=" in tok):
        return False, "padding"
    try:
        pad = "=" * (-len(tok) % 4)
        blob = base64.urlsafe_b64decode(tok + pad)
    except Exception:
        return False, "b64"
    if len(blob) != 120:
        return False, "tok_len"
    ctx = params.get("ctx")
    if ctx is not None:
        if not ctx or any((not _is_token_char(ord(c))) for c in ctx):
            return False, "ctx"
        if len(ctx) > 32:
            return False, "ctx_len"
    return True, "ok"


