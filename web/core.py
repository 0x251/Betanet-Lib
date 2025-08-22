from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple, List


@dataclass
class Request:
    method: bytes
    path: bytes
    headers: Dict[bytes, bytes]
    body: bytes
    params: Dict[str, str] | None = None


@dataclass
class Response:
    status: int
    headers: Tuple[Tuple[bytes, bytes], ...]
    body: bytes


class Handler(ABC):
    @abstractmethod
    def handle(self, req: Request) -> Optional[Response]:
        ...


class Router(Handler):
    def __init__(self) -> None:
        self._exact: Dict[Tuple[bytes, bytes], Callable[[Request], Response]] = {}
        self._dyn: List[Tuple[bytes, List[str], List[str], Callable[[Request], Response]]] = []

    def add(self, method: bytes, path: bytes, fn: Callable[[Request], Response]) -> None:
        p = path.decode("utf-8", errors="ignore")
        if "{" in p and "}" in p:
            parts = [x for x in p.strip().split("/") if x != ""]
            names: List[str] = []
            pattern: List[str] = []
            for seg in parts:
                if seg.startswith("{") and seg.endswith("}"):
                    names.append(seg[1:-1])
                    pattern.append("*")
                else:
                    pattern.append(seg)
            self._dyn.append((method.upper(), pattern, names, fn))
        else:
            self._exact[(method.upper(), path)] = fn

    def handle(self, req: Request) -> Optional[Response]:
        fn = self._exact.get((req.method.upper(), req.path))
        if not fn:
            p = req.path.decode("utf-8", errors="ignore").strip("/")
            parts = [] if p == "" else p.split("/")
            for m, patt, names, f in self._dyn:
                if m != req.method.upper():
                    continue
                if len(patt) != len(parts):
                    continue
                params: Dict[str, str] = {}
                ok = True
                for i, seg in enumerate(patt):
                    if seg == "*":
                        params[names[len(params)]] = parts[i]
                    elif seg != parts[i]:
                        ok = False
                        break
                if ok:
                    req.params = params
                    return f(req)
            return None
        return fn(req)


