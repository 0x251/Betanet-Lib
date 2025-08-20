import socket
from typing import Optional
import h11
import logging

from betanet.transport.tcp import HtxTcpClientPersistent
from betanet.transport.fallback import roundtrip_with_udp_fallback
from betanet.path import PathManager, PathEndpoint
from betanet.gateway.enums import TicketCarrier, HttpMethod
from betanet.gateway.types import RequestHead, UpstreamMessage
from betanet.tickets import TicketVerifier


logger = logging.getLogger("betanet")


def recv_until(sock: socket.socket, marker: bytes, max_bytes: int = 1 << 20) -> bytes:
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise ConnectionError("header too large")
    return bytes(buf)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def _read_request(
    conn: socket.socket,
    max_header: int = 1 << 16,
    max_body: int = 1 << 20,
    max_headers: int = 64,
    max_header_line: int = 8192,
):
    conn.settimeout(5.0)
    c = h11.Connection(h11.SERVER)
    headers = {}
    method = b"GET"
    target = b"/"
    body_chunks: list[bytes] = []
    total = 0
    header_count = 0
    while True:
        event = c.next_event()
        if event is h11.NEED_DATA:
            chunk = conn.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            total += len(chunk)
            if total > max_header + max_body:
                raise ConnectionError("too large")
            c.receive_data(chunk)
            continue
        if isinstance(event, h11.Request):
            method = event.method.upper()
            target = event.target
            for k, v in event.headers:
                headers[k.lower()] = v.strip()
                header_count += 1
                if (
                    header_count > max_headers
                    or len(k) > max_header_line
                    or len(v) > max_header_line
                ):
                    raise ConnectionError("headers too large")
        elif isinstance(event, h11.Data):
            body_chunks.append(event.data)
            if sum(len(x) for x in body_chunks) > max_body:
                raise ConnectionError("body too large")
        elif isinstance(event, h11.EndOfMessage):
            body = b"".join(body_chunks)
            return method, target, headers, body, c
        else:
            continue


def _send_response(
    conn: socket.socket,
    c: h11.Connection,
    status: int,
    body: bytes,
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    if headers is None:
        headers = []
    hdrs = [(b"content-length", str(len(body)).encode())] + headers
    conn.sendall(c.send(h11.Response(status_code=status, headers=hdrs)))
    if body:
        conn.sendall(c.send(h11.Data(data=body)))
    conn.sendall(c.send(h11.EndOfMessage()))


class ProxyServer:
    def __init__(
        self,
        listen_host: str,
        listen_port: int,
        upstream_host: str,
        upstream_port: int,
        client_priv: bytes,
        server_pub: bytes,
        ticket_verifier: Optional[TicketVerifier] = None,
        ticket_cookie_name: Optional[str] = None,
        forward_path: bool = False,
        transport: str = "tcp",
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.client_priv = client_priv
        self.server_pub = server_pub
        self.ticket_verifier = ticket_verifier
        self.ticket_cookie_name = ticket_cookie_name
        self.forward_path = forward_path
        self.transport = (transport or "tcp").lower().strip()
        self.up_client: Optional[HtxTcpClientPersistent] = None
        self.paths = PathManager(
            [PathEndpoint(upstream_host, upstream_port)], max_paths=3
        )

    def serve_once(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.bind((self.listen_host, self.listen_port))
        s.listen(1)
        conn, addr = s.accept()
        try:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            logger.info("conn addr=%s", addr)
            try:
                method_bytes, target, headers, body, c = _read_request(conn)
            except Exception as e:
                emsg = str(e).lower()
                c = h11.Connection(h11.SERVER)
                if (
                    "headers too large" in emsg
                    or "header too large" in emsg
                    or "headers too big" in emsg
                ):
                    _send_response(conn, c, 431, b"")
                    return
                if "body too large" in emsg or "too large" in emsg:
                    _send_response(conn, c, 413, b"")
                    return
                _send_response(conn, c, 400, b"")
                return
            path = target

            if self.ticket_verifier is not None and self.ticket_cookie_name:
                carrier = None
                val = None

                cv = headers.get(b"cookie")
                if cv is not None:
                    parts = [p.strip() for p in cv.split(b";")]
                    for p in parts:
                        needle = self.ticket_cookie_name.encode() + b"="
                        if p.startswith(needle):
                            val = p.split(b"=", 1)[1].decode()
                            carrier = TicketCarrier.COOKIE.value
                            break
                # query
                if val is None:
                    q = path.split(b"?", 1)
                    if len(q) == 2:
                        for part in q[1].split(b"&"):
                            if part.startswith(b"bn1="):
                                val = part.split(b"=", 1)[1].decode()
                                carrier = TicketCarrier.QUERY.value
                                break
                # form body
                if val is None and body:
                    ctype = headers.get(b"content-type", b"").lower()
                    if b"application/x-www-form-urlencoded" in ctype:
                        for part in body.split(b"&"):
                            if part.startswith(b"bn1="):
                                val = part.split(b"=", 1)[1].decode()
                                carrier = TicketCarrier.BODY.value
                                break
                logger.info("carrier %s", carrier)
                if not val:
                    logger.warning("forbid reason=no_ticket")
                    _send_response(conn, c, 403, b"")
                    return
                ip = conn.getpeername()[0]
                logger.info("client_ip %s", ip)
                ok = self.ticket_verifier.parse_and_verify(val, ip)
                logger.info("ticket_ok %s", ok)
                if not ok:
                    logger.warning("forbid reason=bad_ticket")
                    _send_response(conn, c, 403, b"")
                    return
            try:
                cl_val = int(
                    headers.get(b"content-length", b"0").decode(errors="ignore") or "0"
                )
            except Exception:
                cl_val = 0
            logger.info("content_length %d body_len %d", cl_val, len(body))
            try:
                method = HttpMethod(method_bytes.decode(errors="ignore") or "GET")
            except Exception:
                method = HttpMethod.GET
            req_obj = RequestHead(
                method=method, path=path, headers=headers, content_length=len(body)
            )
            if not self.forward_path:
                umsg = UpstreamMessage(
                    method=req_obj.method, path=req_obj.path, body=body
                )
                payload = umsg.body
            else:
                if method == HttpMethod.POST:
                    umsg = UpstreamMessage(
                        method=req_obj.method,
                        path=req_obj.path,
                        body=b"POST " + path + b"\n\n" + body,
                    )
                else:
                    umsg = UpstreamMessage(
                        method=req_obj.method, path=req_obj.path, body=b"GET " + path
                    )
                payload = umsg.body
            cur = self.paths.maybe_switch() or self.paths.current()
            import time as _t

            _t0 = _t.perf_counter()
            try:
                if self.transport == "quic":
                    resp_body = roundtrip_with_udp_fallback(
                        cur.host,
                        cur.port,
                        self.client_priv,
                        self.server_pub,
                        1,
                        payload,
                        sleep_ms=lambda ms: None,
                    )
                else:
                    if self.up_client is None:
                        self.up_client = HtxTcpClientPersistent(
                            cur.host, cur.port, self.client_priv, self.server_pub
                        )
                    else:
                        self.up_client.rebind(cur.host, cur.port)
                    resp_body = self.up_client.roundtrip(payload)
                self.paths.mark_ok(cur.host, cur.port, (_t.perf_counter() - _t0) * 1000)
            except Exception:
                self.paths.mark_fail(cur.host, cur.port)
                raise
            logger.info("resp_len %d", len(resp_body))
            _send_response(conn, c, 200, resp_body)
        except Exception as e:
            logger.error("proxy_exception err=%r", e)
            try:
                _send_response(
                    conn, c if "c" in locals() else h11.Connection(h11.SERVER), 502, b""
                )
            except Exception:
                pass
        finally:
            conn.close()
            s.close()

    def serve_forever(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.bind((self.listen_host, self.listen_port))
        s.listen(64)
        while True:
            conn, addr = s.accept()
            try:
                try:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
                logger.info("conn addr=%s", addr)
                try:
                    method_bytes, path, headers, body, c = _read_request(conn)
                except Exception as e:
                    emsg = str(e).lower()
                    c = h11.Connection(h11.SERVER)
                    if (
                        "headers too large" in emsg
                        or "header too large" in emsg
                        or "headers too big" in emsg
                    ):
                        _send_response(conn, c, 431, b"")
                        conn.close()
                        continue
                    if "body too large" in emsg or "too large" in emsg:
                        _send_response(conn, c, 413, b"")
                        conn.close()
                        continue
                    _send_response(conn, c, 400, b"")
                    conn.close()
                    continue

                if self.ticket_verifier is not None and self.ticket_cookie_name:
                    carrier = None
                    val = None
                    # cookie
                    cv = headers.get(b"cookie")
                    if cv is not None:
                        parts = [p.strip() for p in cv.split(b";")]
                        for p in parts:
                            needle = self.ticket_cookie_name.encode() + b"="
                            if p.startswith(needle):
                                val = p.split(b"=", 1)[1].decode()
                                carrier = TicketCarrier.COOKIE.value
                                break
                    # query
                    if val is None:
                        q = path.split(b"?", 1)
                        if len(q) == 2:
                            for part in q[1].split(b"&"):
                                if part.startswith(b"bn1="):
                                    val = part.split(b"=", 1)[1].decode()
                                    carrier = TicketCarrier.QUERY.value
                                    break
                    # form body
                    if val is None and body:
                        ctype = headers.get(b"content-type", b"").lower()
                        if b"application/x-www-form-urlencoded" in ctype:
                            for part in body.split(b"&"):
                                if part.startswith(b"bn1="):
                                    val = part.split(b"=", 1)[1].decode()
                                    carrier = TicketCarrier.BODY.value
                                    break
                    logger.info("carrier %s", carrier)
                    if not val:
                        logger.warning("forbid reason=no_ticket")
                        _send_response(conn, c, 403, b"")
                        conn.close()
                        continue
                    ip = conn.getpeername()[0]
                    logger.info("client_ip %s", ip)
                    ok = self.ticket_verifier.parse_and_verify(val, ip)
                    logger.info("ticket_ok %s", ok)
                    if not ok:
                        logger.warning("forbid reason=bad_ticket")
                        _send_response(conn, c, 403, b"")
                        conn.close()
                        continue
                try:
                    cl_val = int(
                        headers.get(b"content-length", b"0").decode(errors="ignore")
                        or "0"
                    )
                except Exception:
                    cl_val = 0
                logger.info("content_length %d body_len %d", cl_val, len(body))

                if not self.forward_path:
                    payload = body
                else:
                    if method_bytes == b"POST":
                        payload = b"POST " + path + b"\n\n" + body
                    else:
                        payload = b"GET " + path
                cur = self.paths.maybe_switch() or self.paths.current()
                import time as _t

                _t0 = _t.perf_counter()
                try:
                    if self.transport == "quic":
                        resp_body = roundtrip_with_udp_fallback(
                            cur.host,
                            cur.port,
                            self.client_priv,
                            self.server_pub,
                            1,
                            payload,
                            sleep_ms=lambda ms: None,
                        )
                    else:
                        if self.up_client is None:
                            self.up_client = HtxTcpClientPersistent(
                                cur.host, cur.port, self.client_priv, self.server_pub
                            )
                        else:
                            self.up_client.rebind(cur.host, cur.port)
                        resp_body = self.up_client.roundtrip(payload)
                    self.paths.mark_ok(
                        cur.host, cur.port, (_t.perf_counter() - _t0) * 1000
                    )
                except Exception:
                    self.paths.mark_fail(cur.host, cur.port)
                    raise
                logger.info("resp_len %d", len(resp_body))
                _send_response(conn, c, 200, resp_body)
            except Exception as e:
                logger.error("proxy_exception err=%r", e)
                try:
                    _send_response(
                        conn,
                        c if "c" in locals() else h11.Connection(h11.SERVER),
                        502,
                        b"",
                    )
                except Exception:
                    pass
            finally:
                conn.close()
