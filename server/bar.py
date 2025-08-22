from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple, Optional

from betanet.core.detcbor import dumps as detcbor_dumps, loads as detcbor_loads
from server.core import Request, Response


def _headers_to_map(headers: Dict[bytes, bytes]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    for k, v in headers.items():
        ks = (k.decode("ascii", errors="ignore").lower().strip())
        out[ks] = bytes(v)
    return out


def _map_to_headers(m: Dict[str, object]) -> Dict[bytes, bytes]:
    out: Dict[bytes, bytes] = {}
    for k, v in m.items():
        key = str(k).lower().encode("ascii", errors="ignore")
        if isinstance(v, (bytes, bytearray)):
            out[key] = bytes(v)
        else:
            out[key] = str(v).encode("utf-8", errors="ignore")
    return out


def encode_bar_request(req: Request) -> bytes:
    obj = {
        "m": req.method.decode("ascii", errors="ignore"),
        "u": req.path.decode("utf-8", errors="ignore"),
        "h": _headers_to_map(req.headers),
        "b": bytes(req.body),
    }
    return detcbor_dumps(obj)


def decode_bar_request(data: bytes) -> Request:
    obj = detcbor_loads(data)
    if not isinstance(obj, dict):
        raise ValueError("bad_bar_request")
    method = str(obj.get("m", "GET")).encode("ascii", errors="ignore")
    path = str(obj.get("u", "/")).encode("utf-8", errors="ignore")
    headers_map = obj.get("h", {})
    if not isinstance(headers_map, dict):
        headers_map = {}
    headers = _map_to_headers(headers_map)
    body = obj.get("b", b"")
    if not isinstance(body, (bytes, bytearray)):
        body = bytes(str(body).encode("utf-8", errors="ignore"))
    return Request(method=method, path=path, headers=headers, body=bytes(body))


def encode_bar_response(resp: Response) -> bytes:
    hdr_map: Dict[str, bytes] = {}
    for k, v in resp.headers:
        ks = k.decode("ascii", errors="ignore").lower().strip()
        hdr_map[ks] = bytes(v)
    obj = {
        "s": int(resp.status) & 0xFFFF,
        "h": hdr_map,
        "b": bytes(resp.body),
    }
    return detcbor_dumps(obj)


def decode_bar_response(data: bytes) -> Response:
    obj = detcbor_loads(data)
    if not isinstance(obj, dict):
        raise ValueError("bad_bar_response")
    status = int(obj.get("s", 200)) & 0xFFFF
    headers_map = obj.get("h", {})
    if not isinstance(headers_map, dict):
        headers_map = {}
    headers = tuple((str(k).encode("ascii", errors="ignore"), bytes(v) if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8", errors="ignore")) for k, v in headers_map.items())
    body = obj.get("b", b"")
    if not isinstance(body, (bytes, bytearray)):
        body = bytes(str(body).encode("utf-8", errors="ignore"))
    return Response(status=status, headers=headers, body=bytes(body))


