import socket
import time
import logging
from importlib import import_module
from typing import Callable, Tuple

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM
from betanet.noise.xk import server_handshake_over_socket
from betanet.transport.upstream_adapter import AsgiAdapter

logger = logging.getLogger("betanet")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_varint(sock: socket.socket) -> bytes:
    first = recv_exact(sock, 1)
    prefix = first[0] >> 6
    if prefix == 0:
        return first
    if prefix == 1:
        rest = recv_exact(sock, 1)
        return first + rest
    if prefix == 2:
        rest = recv_exact(sock, 3)
        return first + rest
    if prefix == 3:
        rest = recv_exact(sock, 7)
        return first + rest
    raise ValueError("invalid varint")


def send_frame(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        sent = sock.send(view)
        view = view[sent:]


def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    length = int.from_bytes(hdr[:3], "big")
    typ = hdr[3]
    prefix = b""
    if typ in (0, 4):
        prefix = recv_varint(sock)
    ct = recv_exact(sock, length)
    return hdr + prefix + ct


async def _run_asgi(app: Callable, path: str, body: bytes = b"") -> Tuple[int, list[tuple[bytes, bytes]], bytes]:
    adapter = AsgiAdapter(app)
    status, headers, data = await adapter._run_asgi(path, body)
    return status, headers, data


class HtxAsgiServer:
    def __init__(self, host: str, port: int, static_private: bytes, app: Callable):
        self.host = host
        self.port = port
        self.static_private = static_private
        self.app = app
        self.adapter = AsgiAdapter(app)

    def serve_once(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(1)
        conn, addr = s.accept()
        try:
            k0 = server_handshake_over_socket(conn, self.static_private)
            sess = HtxSession(k0, is_client=False)
            while True:
                buf = recv_frame(conn)
                typ, sid, pt, off, out = sess.decrypt_frame(buf, 0)
                if typ == STREAM and sid is not None:
                    t0 = time.perf_counter()
                    body = self.adapter.handle(pt)
                    dt = (time.perf_counter() - t0) * 1000
                    logger.info("upstream_req time_ms=%.2f", dt)
         
                    reply = sess.encrypt_frame(STREAM, sid, body)
                    send_frame(conn, reply)
                    while (p := sess.pop_pending()) is not None:
                        send_frame(conn, p)
                if out:
                    send_frame(conn, out)
        except Exception:
            pass
        finally:
            conn.close()
            s.close()

    def serve_forever(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(64)
        try:
            while True:
                conn, addr = s.accept()
                try:
                    k0 = server_handshake_over_socket(conn, self.static_private)
                    sess = HtxSession(k0, is_client=False)
                    while True:
                        buf = recv_frame(conn)
                        typ, sid, pt, off, out = sess.decrypt_frame(buf, 0)
                        if typ == STREAM and sid is not None:
                            t0 = time.perf_counter()
                            body = self.adapter.handle(pt)
                            dt = (time.perf_counter() - t0) * 1000
                            logger.info("upstream_req time_ms=%.2f", dt)
                            reply = sess.encrypt_frame(STREAM, sid, body)
                            send_frame(conn, reply)
                            while (p := sess.pop_pending()) is not None:
                                send_frame(conn, p)
                        if out:
                            send_frame(conn, out)
                except Exception:
                    pass
                finally:
                    conn.close()
        finally:
            s.close()


def load_asgi_app(dotted: str) -> Callable:
    mod_path, attr = dotted.split(":", 1) if ":" in dotted else (dotted, "app")
    mod = import_module(mod_path)
    return getattr(mod, attr)
