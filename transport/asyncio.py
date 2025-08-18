import asyncio
from typing import Optional

from betanet.core.session import HtxSession
from betanet.core.frames import STREAM
from betanet.noise.xk_async import client_handshake, server_handshake


async def send(writer: asyncio.StreamWriter, data: bytes) -> None:
    writer.write(data)
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(4)
    length = int.from_bytes(hdr[:3], "big")
    typ = hdr[3]
    prefix = b""
    if typ in (0, 4):
        first = await reader.readexactly(1)
        pfx = first[0] >> 6
        if pfx == 1:
            first += await reader.readexactly(1)
        elif pfx == 2:
            first += await reader.readexactly(3)
        elif pfx == 3:
            first += await reader.readexactly(7)
        prefix = first
    ct = await reader.readexactly(length)
    return hdr + prefix + ct


class AsyncServer:
    def __init__(self, host: str, port: int, server_priv: bytes, server_pub: bytes):
        self.host = host
        self.port = port
        self.server_priv = server_priv
        self.server_pub = server_pub
        self.server: Optional[asyncio.base_events.Server] = None

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            k0 = await server_handshake(reader, writer, self.server_priv)
            sess = HtxSession(k0, is_client=False)
            while True:
                buf = await recv_frame(reader)
                typ, sid, pt, _, out = sess.decrypt_frame(buf, 0)
                if typ == STREAM and sid is not None:
                    reply = sess.encrypt_frame(STREAM, sid, pt)
                    await send(writer, reply)
                    while (p := sess.pop_pending()) is not None:
                        await send(writer, p)
                if out:
                    await send(writer, out)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        self.server = await asyncio.start_server(self.handle, self.host, self.port)
        return self.server


class AsyncClient:
    def __init__(self, host: str, port: int, client_priv: bytes, server_pub: bytes):
        self.host = host
        self.port = port
        self.client_priv = client_priv
        self.server_pub = server_pub

    async def roundtrip(self, stream_id: int, payload: bytes) -> bytes:
        reader, writer = await asyncio.open_connection(self.host, self.port)
        k0 = await client_handshake(reader, writer, self.client_priv, self.server_pub)
        sess = HtxSession(k0, is_client=True)
        buf = sess.encrypt_frame(STREAM, stream_id, payload)
        await send(writer, buf)
        while (p := sess.pop_pending()) is not None:
            await send(writer, p)
        resp = await recv_frame(reader)
        _, _, pt, _, _ = sess.decrypt_frame(resp, 0)
        writer.close()
        await writer.wait_closed()
        return pt
