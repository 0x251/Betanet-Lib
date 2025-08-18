import socket
from typing import Optional
import logging

from betanet.transport.tcp import HtxTcpClient, HtxTcpClientPersistent
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
        self.up_client: Optional[HtxTcpClientPersistent] = None

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
            raw = recv_until(conn, b"\r\n\r\n")
            head_end = raw.find(b"\r\n\r\n")
            head = raw[: head_end + 4]
            body = raw[head_end + 4 :]
            req_line = head.split(b"\r\n", 1)[0]
            logger.info("req_line %r", req_line)
            path = b"/"
            try:
                parts = req_line.split()
                if len(parts) >= 2:
                    path = parts[1]
                method_bytes = parts[0].upper() if parts else b"GET"
            except Exception:
                path = b"/"
                method_bytes = b"GET"
            cl = 0
            headers = {}
            for line in head.split(b"\r\n"):
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.strip()] = v.strip()
                if line.lower().startswith(b"content-length:"):
                    try:
                        cl = int(line.split(b":", 1)[1].strip() or b"0")
                    except Exception:
                        cl = 0
            break_needed = len(body) < cl
            if break_needed:
                body += recv_exact(conn, cl - len(body))
            
            if self.ticket_verifier is not None and self.ticket_cookie_name:
                carrier = None
                val = None
                
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"cookie:"):
                        cookie_line = line.split(b":", 1)[1].strip()
                        parts = [p.strip() for p in cookie_line.split(b";")]
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
                if val is None and cl > 0:
                    ctype = b""
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-type:"):
                            ctype = line.split(b":", 1)[1].strip().lower()
                            break
                    if b"application/x-www-form-urlencoded" in ctype:
                        for part in body.split(b"&"):
                            if part.startswith(b"bn1="):
                                val = part.split(b"=", 1)[1].decode()
                                carrier = TicketCarrier.BODY.value
                                break
                logger.info("carrier %s", carrier)
                if not val:
                    logger.warning("forbid reason=no_ticket")
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    return
                ip = conn.getpeername()[0]
                logger.info("client_ip %s", ip)
                ok = self.ticket_verifier.parse_and_verify(val, ip)
                logger.info("ticket_ok %s", ok)
                if not ok:
                    logger.warning("forbid reason=bad_ticket")
                    conn.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    return
            logger.info("content_length %d body_len %d", cl, len(body))
            try:
                method = HttpMethod(method_bytes.decode(errors="ignore") or "GET")
            except Exception:
                method = HttpMethod.GET
            req_obj = RequestHead(method=method, path=path, headers=headers, content_length=cl)
            if not self.forward_path:
                umsg = UpstreamMessage(method=req_obj.method, path=req_obj.path, body=body)
                payload = umsg.body
            else:
                if method == HttpMethod.POST:
                    umsg = UpstreamMessage(method=req_obj.method, path=req_obj.path, body=b"POST " + path + b"\n\n" + body)
                else:
                    umsg = UpstreamMessage(method=req_obj.method, path=req_obj.path, body=b"GET " + path)
                payload = umsg.body
            if self.up_client is None:
                self.up_client = HtxTcpClientPersistent(
                    self.upstream_host,
                    self.upstream_port,
                    self.client_priv,
                    self.server_pub,
                )
            resp_body = self.up_client.roundtrip(payload)
            logger.info("resp_len %d", len(resp_body))
            resp = (
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(resp_body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + resp_body
            )
            conn.sendall(resp)
        except Exception as e:
            logger.error("proxy_exception err=%r", e)
            try:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
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
                raw = recv_until(conn, b"\r\n\r\n")
                head_end = raw.find(b"\r\n\r\n")
                head = raw[: head_end + 4]
                body = raw[head_end + 4 :]
                req_line = head.split(b"\r\n", 1)[0]
                logger.info("req_line %r", req_line)
                path = b"/"
                try:
                    parts = req_line.split()
                    if len(parts) >= 2:
                        path = parts[1]
                except Exception:
                    path = b"/"
                cl = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            cl = int(line.split(b":", 1)[1].strip() or b"0")
                        except Exception:
                            cl = 0
                break_needed = len(body) < cl
                if break_needed:
                    body += recv_exact(conn, cl - len(body))
                
                if self.ticket_verifier is not None and self.ticket_cookie_name:
                    carrier = None
                    val = None
                    # cookie
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"cookie:"):
                            cookie_line = line.split(b":", 1)[1].strip()
                            parts = [p.strip() for p in cookie_line.split(b";")]
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
                    if val is None and cl > 0:
                        ctype = b""
                        for line in head.split(b"\r\n"):
                            if line.lower().startswith(b"content-type:"):
                                ctype = line.split(b":", 1)[1].strip().lower()
                                break
                        if b"application/x-www-form-urlencoded" in ctype:
                            for part in body.split(b"&"):
                                if part.startswith(b"bn1="):
                                    val = part.split(b"=", 1)[1].decode()
                                    carrier = TicketCarrier.BODY.value
                                    break
                    logger.info("carrier %s", carrier)
                    if not val:
                        logger.warning("forbid reason=no_ticket")
                        conn.sendall(
                            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
                        )
                        conn.close()
                        continue
                    ip = conn.getpeername()[0]
                    logger.info("client_ip %s", ip)
                    ok = self.ticket_verifier.parse_and_verify(val, ip)
                    logger.info("ticket_ok %s", ok)
                    if not ok:
                        logger.warning("forbid reason=bad_ticket")
                        conn.sendall(
                            b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
                        )
                        conn.close()
                        continue
                logger.info("content_length %d body_len %d", cl, len(body))
             
                if not self.forward_path:
                    payload = body
                else:
                    method = b"GET"
                    try:
                        parts = req_line.split()
                        if parts:
                            method = parts[0].upper()
                    except Exception:
                        method = b"GET"
                    if method == b"POST":
                        payload = b"POST " + path + b"\n\n" + body
                    else:
                        payload = b"GET " + path
                if self.up_client is None:
                    self.up_client = HtxTcpClientPersistent(
                        self.upstream_host,
                        self.upstream_port,
                        self.client_priv,
                        self.server_pub,
                    )
                resp_body = self.up_client.roundtrip(payload)
                logger.info("resp_len %d", len(resp_body))
                resp = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(resp_body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                    + resp_body
                )
                conn.sendall(resp)
            except Exception as e:
                logger.error("proxy_exception err=%r", e)
                try:
                    conn.sendall(
                        b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                    )
                except Exception:
                    pass
            finally:
                conn.close()
