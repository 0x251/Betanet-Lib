from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from abc import ABC, abstractmethod


@dataclass
class AliasRecord:
	pk: bytes
	seq: int
	sig_b64: str
	exp: int
	payload_hash: bytes


def two_of_three_finalized(finality: Dict[str, bool]) -> bool:
	return sum(1 for v in finality.values() if v) >= 2


def monotonic_seq_ok(prev_seq: Optional[int], new_seq: int) -> bool:
	if prev_seq is None:
		return True
	return new_seq >= prev_seq


@dataclass
class QuorumCert:
	payload_hash: bytes
	epoch: int
	signers: List[str]
	weights: List[float]
	sigs: List[bytes]


def validate_quorum_cert(cert: QuorumCert, min_weight: float = 0.67) -> bool:
	if len(cert.signers) != len(cert.weights) or len(cert.signers) != len(cert.sigs):
		return False
	return sum(cert.weights) >= min_weight


@dataclass
class AliasState:
	pk: bytes
	seq: int
	payload_hash: bytes
	is_emergency: bool


def evaluate_record(prev: Optional[AliasState], rec: AliasRecord, finality: Dict[str, bool]) -> Tuple[Optional[AliasState], str]:
	if not monotonic_seq_ok(prev.seq if prev else None, rec.seq):
		return prev, "reject:non_monotonic"
	if two_of_three_finalized(finality):
		state = AliasState(pk=rec.pk, seq=rec.seq, payload_hash=rec.payload_hash, is_emergency=False)
		return state, "accept:finalized"
	return prev, "pending:await_finality"


def emergency_advance(prev: Optional[AliasState], rec: AliasRecord, cert: QuorumCert) -> Tuple[Optional[AliasState], str]:
	if not monotonic_seq_ok(prev.seq if prev else None, rec.seq):
		return prev, "reject:non_monotonic"
	if cert.payload_hash != rec.payload_hash:
		return prev, "reject:cert_payload_mismatch"
	if not validate_quorum_cert(cert):
		return prev, "reject:insufficient_quorum"
	state = AliasState(pk=rec.pk, seq=rec.seq, payload_hash=rec.payload_hash, is_emergency=True)
	return state, "accept:emergency"



class NamingPolicyBase(ABC):
	@abstractmethod
	def evaluate_record(self, prev: Optional[AliasState], rec: AliasRecord, finality: Dict[str, bool]) -> Tuple[Optional[AliasState], str]:
		raise NotImplementedError

	@abstractmethod
	def emergency_advance(self, prev: Optional[AliasState], rec: AliasRecord, cert: QuorumCert) -> Tuple[Optional[AliasState], str]:
		raise NotImplementedError


class NamingPolicy(NamingPolicyBase):
	def evaluate_record(self, prev: Optional[AliasState], rec: AliasRecord, finality: Dict[str, bool]) -> Tuple[Optional[AliasState], str]:
		return evaluate_record(prev, rec, finality)

	def emergency_advance(self, prev: Optional[AliasState], rec: AliasRecord, cert: QuorumCert) -> Tuple[Optional[AliasState], str]:
		return emergency_advance(prev, rec, cert)

