import socket
import threading
from typing import Optional, Tuple, Dict, Any, Callable

from betanet.core.session12 import new_session12_from_k0
from betanet.core.frames12 import decode_frame12
from betanet.noise.xk import client_handshake_over_socket, server_handshake_over_socket
from betanet.l3.caps import (
    encode_cap_msg,
    decode_cap_msg,
    encode_sel_msg,
    decode_sel_msg,
    decide_selection,
)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    l3 = recv_exact(sock, 3)
    length = int.from_bytes(l3, "big")
    rest = recv_exact(sock, length)
    return l3 + rest


def send_bytes(sock: socket.socket, data: bytes) -> None:
    view = memoryview(data)
    while view:
        sent = sock.send(view)
        view = view[sent:]


class Tcp12Server:
    def __init__(self, host: str, port: int, static_private: bytes, server_caps: Optional[Dict[str, Any]] = None, handler: Optional[Callable[[bytes], bytes]] = None):
        self.host = host
        self.port = port
        self.static_private = static_private
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self.server_caps: Dict[str, Any] = server_caps or {
            "l2": ["betanet/htx/1.2.0"],
            "l3": ["betanet/mesh/1.2.0"],
            "l4": [],
            "l5": [],
        }
        self.selection: Optional[Dict[str, str]] = None
        self._handler = handler

    def serve_once(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(1)
        conn, addr = s.accept()
        try:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            k0 = server_handshake_over_socket(conn, self.static_private)
            sess = new_session12_from_k0(k0, is_client=False)
            # Capability exchange on StreamID=1
            try:
                buf = recv_frame(conn)
                t, sid, aad, pt, _ = sess.decrypt(buf, 0)
                if t == 0 and sid == 1:
                    _ = decode_cap_msg(pt)
                    out = sess.encrypt(0, 1, 0, encode_cap_msg(self.server_caps))
                    send_bytes(conn, out)
                    selbuf = recv_frame(conn)
                    t2, sid2, aad2, pt2, _ = sess.decrypt(selbuf, 0)
                    if t2 == 0 and sid2 == 1:
                        self.selection = decode_sel_msg(pt2)
            except Exception:
                pass
            while True:
                buf = recv_frame(conn)
                typ, sid, aad, pt, _ = sess.decrypt(buf, 0)
                if typ == 0 and sid > 0:
                    reply = pt
                    if self._handler is not None:
                        try:
                            reply = self._handler(pt)
                        except Exception:
                            reply = b""
                    out = sess.encrypt(0, sid, 0, reply)
                    send_bytes(conn, out)
                if typ == 4:
                    break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            finally:
                s.close()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            k0 = server_handshake_over_socket(conn, self.static_private)
            sess = new_session12_from_k0(k0, is_client=False)
            try:
                buf = recv_frame(conn)
                t, sid, aad, pt, _ = sess.decrypt(buf, 0)
                if t == 0 and sid == 1:
                    _ = decode_cap_msg(pt)
                    out = sess.encrypt(0, 1, 0, encode_cap_msg(self.server_caps))
                    send_bytes(conn, out)
                    selbuf = recv_frame(conn)
                    t2, sid2, aad2, pt2, _ = sess.decrypt(selbuf, 0)
                    if t2 == 0 and sid2 == 1:
                        self.selection = decode_sel_msg(pt2)
            except Exception:
                pass
            while True:
                buf = recv_frame(conn)
                typ, sid, aad, pt, _ = sess.decrypt(buf, 0)
                if typ == 0 and sid > 0:
                    reply = pt
                    if self._handler is not None:
                        try:
                            reply = self._handler(pt)
                        except Exception:
                            reply = b""
                    out = sess.encrypt(0, sid, 0, reply)
                    send_bytes(conn, out)
                if typ == 4:
                    break
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve_forever(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(128)
        self._sock = s
        try:
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
                t.start()
        finally:
            try:
                s.close()
            except Exception:
                pass


class Tcp12Client:
    def __init__(self, host: str, port: int, initiator_static_private: bytes, responder_static_public: bytes, client_caps: Optional[Dict[str, Any]] = None):
        self.host = host
        self.port = port
        self.initiator_static_private = initiator_static_private
        self.responder_static_public = responder_static_public
        self.client_caps: Dict[str, Any] = client_caps or {
            "l2": ["betanet/htx/1.2.0"],
            "l3": ["betanet/mesh/1.2.0"],
            "l4": [],
            "l5": [],
        }
        self.selection: Optional[Dict[str, str]] = None

    def roundtrip(self, stream_id: int, payload: bytes) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            k0 = client_handshake_over_socket(s, self.initiator_static_private, self.responder_static_public)
            sess = new_session12_from_k0(k0, is_client=True)
           
            try:
                cap = encode_cap_msg(self.client_caps)
                out0 = sess.encrypt(0, 1, 0, cap)
                send_bytes(s, out0)
                srv_msg = recv_frame(s)
                t, sid, aad, pt, _ = sess.decrypt(srv_msg, 0)
                if t == 0 and sid == 1:
                    srv_caps = decode_cap_msg(pt)
                    sel = decide_selection(self.client_caps, srv_caps)
                    self.selection = sel
                    sel_msg = encode_sel_msg(sel)
                    out1 = sess.encrypt(0, 1, 0, sel_msg)
                    send_bytes(s, out1)
            except Exception:
                pass
            out = sess.encrypt(0, stream_id, 0, payload)
            send_bytes(s, out)
            resp = recv_frame(s)
            typ, sid, aad, pt, _ = sess.decrypt(resp, 0)
            return pt

    def send_close(self, code: int, reason: bytes = b"") -> None:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            k0 = client_handshake_over_socket(s, self.initiator_static_private, self.responder_static_public)
            sess = new_session12_from_k0(k0, is_client=True)
            buf = sess.close(code, reason)
            send_bytes(s, buf)


class Tcp12ClientPersistent:
    def __init__(self, host: str, port: int, initiator_static_private: bytes, responder_static_public: bytes, client_caps: Optional[Dict[str, Any]] = None):
        self.host = host
        self.port = port
        self.initiator_static_private = initiator_static_private
        self.responder_static_public = responder_static_public
        self.client_caps: Dict[str, Any] = client_caps or {
            "l2": ["betanet/htx/1.2.0"],
            "l3": ["betanet/mesh/1.2.0"],
            "l4": [],
            "l5": [],
        }
        self.selection: Optional[Dict[str, str]] = None
        self.sock: Optional[socket.socket] = None
        self.sess = None
        self.next_stream_id = 1

    def connect(self) -> None:
        if self.sock is not None:
            return
        s = socket.create_connection((self.host, self.port), timeout=5)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass
        self.sock = s
        k0 = client_handshake_over_socket(s, self.initiator_static_private, self.responder_static_public)
        sess = new_session12_from_k0(k0, is_client=True)
        try:
            cap = encode_cap_msg(self.client_caps)
            out0 = sess.encrypt(0, 1, 0, cap)
            send_bytes(s, out0)
            srv_msg = recv_frame(s)
            t, sid, aad, pt, _ = sess.decrypt(srv_msg, 0)
            if t == 0 and sid == 1:
                srv_caps = decode_cap_msg(pt)
                sel = decide_selection(self.client_caps, srv_caps)
                self.selection = sel
                sel_msg = encode_sel_msg(sel)
                out1 = sess.encrypt(0, 1, 0, sel_msg)
                send_bytes(s, out1)
        except Exception:
            pass
        self.sess = sess

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
        out = self.sess.encrypt(0, sid, 0, payload)
        send_bytes(self.sock, out)
        while True:
            resp = recv_frame(self.sock)
            typ, rsid, aad, pt, _ = self.sess.decrypt(resp, 0)
            if typ == 1:
                continue
            if typ == 0 and rsid == sid:
                return pt

    def rebind(self, host: str, port: int) -> None:
        if host == self.host and port == self.port:
            return
        self.close()
        self.host = host
        self.port = port


