from dataclasses import dataclass
from typing import Dict

from betanet.gateway.enums import HttpMethod


@dataclass
class RequestHead:
	method: HttpMethod
	path: bytes
	headers: Dict[bytes, bytes]
	content_length: int


@dataclass
class UpstreamMessage:
	method: HttpMethod
	path: bytes
	body: bytes


