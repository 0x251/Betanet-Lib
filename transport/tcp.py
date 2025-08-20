import socket
from typing import Optional

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM, KEY_UPDATE
from betanet.transition import make_control_frame, AllowAllPathValidator
from betanet.transport.base import TransportServer, TransportClient
from betanet.noise.xk import client_handshake_over_socket, server_handshake_over_socket
from betanet.transport.upstream_adapter import EchoAdapter


# TODO: move to core.frames


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


class HtxTcpServer(TransportServer):
    def __init__(
        self, host: str, port: int, static_private: bytes, static_public: bytes
    ):
        self.host = host
        self.port = port
        self.static_private = static_private
        self.static_public = static_public
        self.sock: Optional[socket.socket] = None

    def serve_once(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        s.bind((self.host, self.port))
        s.listen(1)
        self.sock = s
        conn, addr = s.accept()
        try:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            k0 = server_handshake_over_socket(conn, self.static_private)
            sess = HtxSession(k0, is_client=False)
            try:
                cf = make_control_frame(sess, prev_as=0, next_as=0)
                send_frame(conn, cf)
            except Exception:
                pass
            adapter = EchoAdapter()
            while True:
                buf = recv_frame(conn)
                typ, sid, pt, off, out = sess.decrypt_frame(buf, 0)
                if typ == STREAM and sid is not None:
                    data = adapter.handle(pt)
                    reply = sess.encrypt_frame(STREAM, sid, data)
                    send_frame(conn, reply)
                    while (p := sess.pop_pending()) is not None:
                        send_frame(conn, p)
                if typ == KEY_UPDATE:
                    try:
                        cf = make_control_frame(sess, prev_as=0, next_as=0)
                        send_frame(conn, cf)
                    except Exception:
                        pass
                if out:
                    send_frame(conn, out)
        except Exception:
            pass
        finally:
            conn.close()
            s.close()


class HtxTcpClient(TransportClient):
    def __init__(
        self,
        host: str,
        port: int,
        initiator_static_private: bytes,
        responder_static_public: bytes,
    ):
        self.host = host
        self.port = port
        self.initiator_static_private = initiator_static_private
        self.responder_static_public = responder_static_public

    def roundtrip(self, stream_id: int, payload: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            k0 = client_handshake_over_socket(
                s, self.initiator_static_private, self.responder_static_public
            )
            sess = HtxSession(k0, is_client=True)
            buf = sess.encrypt_frame(STREAM, stream_id, payload)
            send_frame(s, buf)
            while (p := sess.pop_pending()) is not None:
                send_frame(s, p)
            resp = recv_frame(s)
            typ, sid, pt, off, out = sess.decrypt_frame(resp, 0)
            return pt


class HtxTcpClientPersistent:
    def __init__(
        self,
        host: str,
        port: int,
        initiator_static_private: bytes,
        responder_static_public: bytes,
    ):
        self.host = host
        self.port = port
        self.initiator_static_private = initiator_static_private
        self.responder_static_public = responder_static_public
        self.sock: Optional[socket.socket] = None
        self.sess: Optional[HtxSession] = None
        self.next_stream_id: int = 1

    def connect(self) -> None:
        if self.sock is not None:
            return
        s = socket.create_connection((self.host, self.port), timeout=5)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        k0 = client_handshake_over_socket(
            s, self.initiator_static_private, self.responder_static_public
        )
        self.sock = s
        self.sess = HtxSession(k0, is_client=True)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            finally:
                self.sock = None
                self.sess = None

    def roundtrip(self, payload: bytes) -> bytes:
        if self.sock is None or self.sess is None:
            self.connect()
        assert self.sock is not None and self.sess is not None
        sid = self.next_stream_id
        self.next_stream_id += 1
        buf = self.sess.encrypt_frame(STREAM, sid, payload)
        send_frame(self.sock, buf)
        while (p := self.sess.pop_pending()) is not None:
            send_frame(self.sock, p)
        resp = recv_frame(self.sock)
        typ, rsid, pt, off, out = self.sess.decrypt_frame(resp, 0)
        return pt or b""

    def rebind(self, host: str, port: int) -> None:
        if host == self.host and port == self.port:
            return
        self.close()
        self.host = host
        self.port = port


class HtxTcpClientPool:
    def __init__(
        self,
        host: str,
        port: int,
        initiator_static_private: bytes,
        responder_static_public: bytes,
        size: int = 4,
    ):
        self.host = host
        self.port = port
        self.initiator_static_private = initiator_static_private
        self.responder_static_public = responder_static_public
        self.clients: list[HtxTcpClientPersistent] = [
            HtxTcpClientPersistent(host, port, initiator_static_private, responder_static_public)
            for _ in range(max(1, size))
        ]
        self._idx = 0

    def rebind(self, host: str, port: int) -> None:
        if host == self.host and port == self.port:
            return
        self.host = host
        self.port = port
        for c in self.clients:
            c.rebind(host, port)

    def roundtrip(self, payload: bytes) -> bytes:
        cli = self.clients[self._idx % len(self.clients)]
        self._idx = (self._idx + 1) % len(self.clients)
        return cli.roundtrip(payload)
