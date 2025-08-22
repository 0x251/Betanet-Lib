import time
import pathlib
from typing import Tuple

from server.core import Request, Response
from server.app import BetanetApp
from server.metrics import Metrics, get_global_metrics


_metrics = get_global_metrics()
_started_at = time.time()
_tpl_path = pathlib.Path(__file__).resolve().parents[1] / "templates" / "dashboard.html"


def _render_dashboard() -> bytes:
    uptime = int(time.time() - _started_at)
    snap = _metrics.snapshot()
    try:
        tpl = _tpl_path.read_text(encoding="utf-8")
    except Exception:
        tpl = "<html><body><h1>Betanet Dashboard</h1><div>Uptime {{uptime}} s</div></body></html>"
    html = (
        tpl.replace("{{uptime}}", str(uptime))
        .replace("{{requests}}", str(snap.requests))
        .replace("{{errors}}", str(snap.errors))
        .replace("{{bytes_in}}", str(snap.bytes_in))
        .replace("{{bytes_out}}", str(snap.bytes_out))
        .replace("{{gw_host}}", "127.0.0.1")
        .replace("{{gw_port}}", "8082")
        .replace("{{up_host}}", "127.0.0.1")
        .replace("{{up_port}}", "35100")
    )
    return html.encode("utf-8")


def register(app: BetanetApp) -> None:
    app.add_template_root(str(_tpl_path.parent))
    @app.route(b"GET", b"/hello/{name}")
    def hello(req: Request) -> Response:
        _metrics.inc_req(len(req.body))
        name = (req.params or {}).get("name", "world")
        body = f"hello {name}".encode()
        _metrics.inc_out(len(body))
        return Response(200, ((b"content-type", b"text/plain"),), body)

    @app.route(b"GET", b"/dashboard")
    def dashboard(req: Request) -> Response:
        _metrics.inc_req(len(req.body))
        snap = _metrics.snapshot()
        ctx = {
            "uptime": int(time.time() - _started_at),
            "requests": snap.requests,
            "errors": snap.errors,
            "bytes_in": snap.bytes_in,
            "bytes_out": snap.bytes_out,
            "avg_ms": f"{snap.avg_ms:.2f}",
            "last_ms": f"{snap.last_ms:.2f}",
            "gw_host": "127.0.0.1",
            "gw_port": "8082",
            "up_host": "127.0.0.1",
            "up_port": "35100",
        }
        body = app.render_template("dashboard.html", ctx)
        if not body:
            _metrics.inc_err()
            return Response(500, ((b"content-type", b"text/plain"),), b"render error")
        _metrics.inc_out(len(body))
        return Response(200, ((b"content-type", b"text/html; charset=utf-8"),), body)


