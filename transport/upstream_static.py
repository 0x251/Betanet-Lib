import os
import socket
from typing import Optional

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM
from betanet.noise.xk import server_handshake_over_socket
from betanet.transport.upstream_adapter import StaticAdapter


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


class HtxStaticServer:
    def __init__(self, host: str, port: int, static_private: bytes, root: str):
        self.host = host
        self.port = port
        self.static_private = static_private
        self.root = root
        self.adapter = StaticAdapter(root)

    def _resolve_path(self, path: str) -> Optional[str]:
        if path.startswith("/"):
            path = path[1:]
        if path == "":
            path = "index.html"
        full = os.path.normpath(os.path.join(self.root, path))
        root_norm = os.path.normpath(self.root)
        if not full.startswith(root_norm):
            return None
        return full

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
                    data = self.adapter.handle(pt)
                    reply = sess.encrypt_frame(STREAM, sid, data)
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
                            data = self.adapter.handle(pt)
                            reply = sess.encrypt_frame(STREAM, sid, data)
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
