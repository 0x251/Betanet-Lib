import socket
import os
import logging


from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def hkdf_from_hash(h: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"htx inner v1"
    ).derive(h)


def _create_noise(pq: bool) -> NoiseConnection:
    name_legacy = b"Noise_XK_25519_ChaChaPoly_SHA256"
    if pq:
        try:
            name_hybrid = b"Noise_XK_25519_Kyber768_ChaChaPoly_SHA256"
            return NoiseConnection.from_name(name_hybrid)
        except Exception:
            logging.getLogger("betanet").info("pq_unsupported_fallback")
    return NoiseConnection.from_name(name_legacy)


def client_handshake_over_socket(
    sock: socket.socket, initiator_static_private: bytes, responder_static_public: bytes
) -> bytes:
    pq = os.environ.get("BETANET_PQ", "0") == "1"
    n = _create_noise(pq)
    n.set_as_initiator()
    n.set_keypair_from_private_bytes(Keypair.STATIC, initiator_static_private)
    n.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, responder_static_public)
    n.start_handshake()
    msg1 = n.write_message(b"")
    send_prefixed(sock, msg1)
    msg2 = recv_prefixed(sock)
    n.read_message(msg2)
    msg3 = n.write_message(b"")
    send_prefixed(sock, msg3)
    h = n.get_handshake_hash()
    return hkdf_from_hash(h)


def server_handshake_over_socket(
    sock: socket.socket, responder_static_private: bytes
) -> bytes:
    pq = os.environ.get("BETANET_PQ", "0") == "1"
    n = _create_noise(pq)
    n.set_as_responder()
    n.set_keypair_from_private_bytes(Keypair.STATIC, responder_static_private)
    n.start_handshake()
    msg1 = recv_prefixed(sock)
    n.read_message(msg1)
    msg2 = n.write_message(b"")
    send_prefixed(sock, msg2)
    msg3 = recv_prefixed(sock)
    n.read_message(msg3)
    h = n.get_handshake_hash()
    return hkdf_from_hash(h)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf.extend(chunk)
    return bytes(buf)


def send_prefixed(sock: socket.socket, data: bytes) -> None:
    l = len(data).to_bytes(2, "big")
    sock.sendall(l + data)


def recv_prefixed(sock: socket.socket) -> bytes:
    l = int.from_bytes(recv_exact(sock, 2), "big")
    return recv_exact(sock, l)
