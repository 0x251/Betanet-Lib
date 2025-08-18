import asyncio
from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def hkdf_from_hash(h: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=b"htx inner v1"
    ).derive(h)


async def send_prefixed(writer: asyncio.StreamWriter, data: bytes) -> None:
    l = len(data).to_bytes(2, "big")
    writer.write(l + data)
    await writer.drain()


async def recv_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def recv_prefixed(reader: asyncio.StreamReader) -> bytes:
    l = int.from_bytes(await recv_exact(reader, 2), "big")
    return await recv_exact(reader, l)


async def client_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    initiator_static_private: bytes,
    responder_static_public: bytes,
) -> bytes:
    n = NoiseConnection.from_name(b"Noise_XK_25519_ChaChaPoly_SHA256")
    n.set_as_initiator()
    n.set_keypair_from_private_bytes(Keypair.STATIC, initiator_static_private)
    n.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, responder_static_public)
    n.start_handshake()
    msg1 = n.write_message(b"")
    await send_prefixed(writer, msg1)
    msg2 = await recv_prefixed(reader)
    n.read_message(msg2)
    msg3 = n.write_message(b"")
    await send_prefixed(writer, msg3)
    h = n.get_handshake_hash()
    return hkdf_from_hash(h)


async def server_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    responder_static_private: bytes,
) -> bytes:
    n = NoiseConnection.from_name(b"Noise_XK_25519_ChaChaPoly_SHA256")
    n.set_as_responder()
    n.set_keypair_from_private_bytes(Keypair.STATIC, responder_static_private)
    n.start_handshake()
    msg1 = await recv_prefixed(reader)
    n.read_message(msg1)
    msg2 = n.write_message(b"")
    await send_prefixed(writer, msg2)
    msg3 = await recv_prefixed(reader)
    n.read_message(msg3)
    h = n.get_handshake_hash()
    return hkdf_from_hash(h)
