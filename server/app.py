from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple, List

from server.core import Router, Request, Response
import pathlib
import html
import mimetypes
from server.bar import decode_bar_request, encode_bar_response


class BetanetApp:
    def __init__(self) -> None:
        self.router = Router()
        self._loaded: list[str] = []
        self._template_roots: list[pathlib.Path] = [pathlib.Path(__file__).resolve().parents[0] / "templates"]
        self._tpl_cache: dict[str, tuple[float, str]] = {}
        self._before: list[Callable[[Request], None]] = []
        self._after: list[Callable[[Request, Response], None]] = []
        self._error_handlers: dict[int, Callable[[Request, Exception], Response]] = {}
        self._static: list[tuple[bytes, pathlib.Path]] = []

    def route(self, method: bytes, path: bytes) -> Callable[[Callable[[Request], Response]], Callable[[Request], Response]]:
        def _wrap(fn: Callable[[Request], Response]) -> Callable[[Request], Response]:
            self.router.add(method, path, fn)
            return fn
        return _wrap

    def blueprint(self, mount: bytes, routes: List[Tuple[bytes, bytes, Callable[[Request], Response]]]) -> None:
        for m, p, fn in routes:
            if p.startswith(b"/"):
                full = mount + p
            else:
                full = mount + b"/" + p
            self.router.add(m, full, fn)

    def load_plugin(self, dotted: str) -> None:
        mod = importlib.import_module(dotted)
        reg = getattr(mod, "register", None)
        if callable(reg):
            reg(self)
            self._loaded.append(dotted)

    def load_plugins_from(self, package_or_path: str) -> int:
        count = 0
        try:
            import pkgutil, importlib.util, pathlib
            if ("/" in package_or_path) or ("\\" in package_or_path):
                base = pathlib.Path(package_or_path)
                if base.is_dir():
                    for py in base.glob("*.py"):
                        name = py.stem
                        spec = importlib.util.spec_from_file_location(f"plugins.{name}", py)
                        if spec and spec.loader:
                            mod = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(mod)  # type: ignore
                            reg = getattr(mod, "register", None)
                            if callable(reg):
                                reg(self)
                                count += 1
                return count
            pkg = importlib.import_module(package_or_path)
            for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
                try:
                    m = importlib.import_module(info.name)
                    reg = getattr(m, "register", None)
                    if callable(reg):
                        reg(self)
                        count += 1
                except Exception:
                    continue
            return count
        except Exception:
            return count

    def add_template_root(self, path: str) -> None:
        p = pathlib.Path(path)
        if p.is_dir() and p not in self._template_roots:
            self._template_roots.append(p)

    def add_static(self, url_prefix: bytes, root: str) -> None:
        up = url_prefix if url_prefix.startswith(b"/") else (b"/" + url_prefix)
        self._static.append((up.rstrip(b"/"), pathlib.Path(root)))

    def _find_template(self, name: str) -> pathlib.Path | None:
        for root in self._template_roots:
            cand = root / name
            if cand.exists() and cand.is_file():
                return cand
        return None

    def render_template(self, name: str, context: dict[str, object] | None = None) -> bytes:
        ctx = dict(context or {})
        p = self._find_template(name)
        if p is None:
            return b""
        try:
            mt = p.stat().st_mtime
        except Exception:
            mt = 0.0
        cached = self._tpl_cache.get(str(p))
        if cached and abs(cached[0] - mt) < 1e-6:
            s = cached[1]
        else:
            s = p.read_text(encoding="utf-8")
            self._tpl_cache[str(p)] = (mt, s)
        
        out = []
        i = 0
        while i < len(s):
            start = s.find("{{", i)
            if start == -1:
                out.append(s[i:])
                break
            out.append(s[i:start])
            end = s.find("}}", start + 2)
            if end == -1:
                out.append(s[start:])
                break
            expr = s[start+2:end].strip()
            safe = False
            if "|" in expr:
                var, filt = [x.strip() for x in expr.split("|", 1)]
                if filt == "safe":
                    safe = True
                expr = var
            val = ctx.get(expr, "")
            if val is None:
                val = ""
            if not isinstance(val, (str, bytes)):
                val = str(val)
            if isinstance(val, bytes):
                try:
                    val = val.decode("utf-8", errors="ignore")
                except Exception:
                    val = ""
            out.append(val if safe else html.escape(val, quote=True))
            i = end + 2
        return ("".join(out)).encode("utf-8")

    def before_request(self, fn: Callable[[Request], None]) -> None:
        self._before.append(fn)

    def after_request(self, fn: Callable[[Request, Response], None]) -> None:
        self._after.append(fn)

    def error_handler(self, code: int, fn: Callable[[Request, Exception], Response]) -> None:
        self._error_handlers[int(code) & 0xFFFF] = fn

    def handle(self, req: Request) -> Response:
        # Static files
        if req.method.upper() == b"GET":
            p = req.path
            for prefix, root in self._static:
                if p.startswith(prefix + b"/") or p == prefix:
                    rel = p[len(prefix):].decode("utf-8", errors="ignore")
                    rel = rel.lstrip("/")
                    rel = "index.html" if rel == "" else rel
                    candidate = (root / rel).resolve()
                    try:
                        root_resolved = root.resolve()
                    except Exception:
                        root_resolved = root
                    if not str(candidate).startswith(str(root_resolved)):
                        return self.error(403, "forbidden")
                    if not candidate.exists() or not candidate.is_file():
                        return self.error(404, "not found")
                    data = candidate.read_bytes()
                    ctype, _ = mimetypes.guess_type(candidate.name)
                    ctype_b = (ctype or "application/octet-stream").encode("ascii", errors="ignore")
                    return Response(200, ((b"content-type", ctype_b), (b"cache-control", b"public, max-age=3600")), data)
        for h in self._before:
            try:
                h(req)
            except Exception:
                continue
        resp = self.router.handle(req)
        if resp is None:
            resp = Response(404, ((b"content-type", b"text/plain"),), b"not found")
        for h in self._after:
            try:
                h(req, resp)
            except Exception:
                continue
        return resp

    # Response helpers
    def json(self, obj: object, status: int = 200) -> Response:
        import json as _json
        return Response(status, ((b"content-type", b"application/json"),), _json.dumps(obj).encode("utf-8"))

    def text(self, data: str, status: int = 200) -> Response:
        return Response(status, ((b"content-type", b"text/plain; charset=utf-8"),), data.encode("utf-8"))

    def html(self, html_bytes: bytes | str, status: int = 200) -> Response:
        if isinstance(html_bytes, str):
            html_bytes = html_bytes.encode("utf-8")
        return Response(status, ((b"content-type", b"text/html; charset=utf-8"),), html_bytes)

    def redirect(self, location: str, status: int = 302) -> Response:
        return Response(status, ((b"location", location.encode("utf-8")),), b"")

    def error(self, status: int, msg: str = "") -> Response:
        return Response(int(status) & 0xFFFF, ((b"content-type", b"text/plain"),), msg.encode("utf-8"))

    def handle_bar(self, payload: bytes) -> bytes:
        req = decode_bar_request(payload)
        resp = self.router.handle(req)
        if resp is None:
            return encode_bar_response(Response(404, ((b"content-type", b"text/plain"),), b"not found"))
        return encode_bar_response(resp)


