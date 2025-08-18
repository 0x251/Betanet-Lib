import socket
import time
from typing import Optional, Dict

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM
from betanet.noise.xk import client_handshake_over_socket, server_handshake_over_socket


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


class BitswapServerTcp:
    def __init__(self, host: str, port: int, static_private: bytes):
        self.host = host
        self.port = port
        self.static_private = static_private
        self.store: Dict[str, bytes] = {}

    def put_block(self, cid: str, data: bytes) -> None:
        self.store[cid] = data

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
                if typ == STREAM and sid is not None and pt.startswith(b"GET "):
                    cid = pt[4:].decode()
                    blk = self.store.get(cid, b"")
                    reply = sess.encrypt_frame(STREAM, sid, b"BLK " + blk)
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


class BitswapClientTcp:
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

    def fetch_block(self, cid: str, parallel_streams: int = 2) -> bytes:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            k0 = client_handshake_over_socket(
                s, self.initiator_static_private, self.responder_static_public
            )
            sess = HtxSession(k0, is_client=True)
            stream_ids = [i * 2 + 1 for i in range(parallel_streams)]
            for sid in stream_ids:
                b = sess.encrypt_frame(STREAM, sid, b"GET " + cid.encode())
                send_frame(s, b)
            while (p := sess.pop_pending()) is not None:
                send_frame(s, p)
            start = time.time()
            data: Optional[bytes] = None
            while True:
                resp = recv_frame(s)
                t, sid, pt, _, _ = sess.decrypt_frame(resp, 0)
                if t == STREAM and pt.startswith(b"BLK "):
                    data = pt[4:]
                    break
            dur = time.time() - start
            if data is None:
                raise RuntimeError("no block")
            mbs = len(data) / (1024 * 1024) / max(1e-6, dur)
            print(
                "bitswap_len=",
                len(data),
                "streams=",
                parallel_streams,
                "MBps=",
                round(mbs, 1),
            )
            return data
