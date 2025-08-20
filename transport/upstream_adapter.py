import os
import asyncio
from abc import ABC, abstractmethod
from typing import Callable, Tuple, Optional
from enum import Enum


class UpstreamAdapter(ABC):
	@abstractmethod
	def handle(self, payload: bytes) -> bytes:
		raise NotImplementedError


class UpstreamType(Enum):
	ECHO = "echo"
	ASGI = "asgi"
	STATIC = "static"


class EchoAdapter(UpstreamAdapter):
	def handle(self, payload: bytes) -> bytes:
		return payload


class AsgiAdapter(UpstreamAdapter):
	def __init__(self, app: Callable):
		self.app = app
		self.loop = asyncio.new_event_loop()

	async def _run_asgi(self, path: str, body: bytes = b"") -> Tuple[int, list[tuple[bytes, bytes]], bytes]:
		status: int = 500
		headers: list[tuple[bytes, bytes]] = []
		buf = bytearray()

		async def send(message):
			nonlocal status, headers, buf
			if message.get("type") == "http.response.start":
				status = int(message.get("status", 200))
				headers = list(message.get("headers", []))
			elif message.get("type") == "http.response.body":
				b = message.get("body", b"")
				if b:
					buf.extend(b)

		async def receive():
			return {"type": "http.request", "body": body, "more_body": False}

		scope = {"type": "http", "method": "GET", "path": path}
		await self.app(scope, receive, send)
		return status, headers, bytes(buf)

	def handle(self, payload: bytes) -> bytes:
		path = "/"
		body = b""
		if payload.startswith(b"GET "):
			try:
				path = payload[4:].decode(errors="ignore")
			except Exception:
				path = "/"
		elif payload.startswith(b"POST "):
			try:
				sep = payload.find(b"\n\n")
				if sep != -1:
					first = payload[:sep]
					path = first[5:].decode(errors="ignore")
					body = payload[sep + 2 :]
				else:
					path = payload[5:].decode(errors="ignore")
			except Exception:
				path = "/"
		status, headers, data = self.loop.run_until_complete(self._run_asgi(path, body))
		return data


class StaticAdapter(UpstreamAdapter):
	def __init__(self, root: str):
		self.root = root

	def _resolve(self, path: str) -> Optional[str]:
		if path.startswith("/"):
			path = path[1:]
		if path == "":
			path = "index.html"
		full = os.path.normpath(os.path.join(self.root, path))
		root_norm = os.path.normpath(self.root)
		if not full.startswith(root_norm):
			return None
		return full

	def handle(self, payload: bytes) -> bytes:
		if payload.startswith(b"GET "):
			try:
				req_path = payload[4:].decode(errors="ignore")
			except Exception:
				req_path = "/"
			resolved = self._resolve(req_path)
			if resolved and os.path.isfile(resolved):
				try:
					with open(resolved, "rb") as f:
						return f.read()
				except Exception:
					return b""
			return b""
		return payload


