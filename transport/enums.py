from enum import Enum


class TransportId(Enum):
	HTX = "/betanet/htx/1.1.0"
	HTX_QUIC = "/betanet/htxquic/1.1.0"


class MasqueOutcome(Enum):
	ATTEMPTED = "attempted"
	USED = "used"
	FALLBACK_TCP = "fallback_tcp"


