from server.core import Request, Response
from server.app import BetanetApp
from server.metrics import get_global_metrics


def register(app: BetanetApp) -> None:
    @app.route(b"GET", b"/metrics")
    def metrics(req: Request) -> Response:
        m = get_global_metrics().snapshot()
        lines = [
            f"betanet_requests_total {m.requests}",
            f"betanet_errors_total {m.errors}",
            f"betanet_bytes_in_total {m.bytes_in}",
            f"betanet_bytes_out_total {m.bytes_out}",
            f"betanet_response_ms_avg {m.avg_ms}",
            f"betanet_response_ms_last {m.last_ms}",
        ]
        body = ("\n".join(lines) + "\n").encode("utf-8")
        return Response(200, ((b"content-type", b"text/plain; version=0.0.4"),), body)


