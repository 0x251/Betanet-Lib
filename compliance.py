import fnmatch
import time
from enum import Enum
from typing import Dict, Optional


class ComplianceProfile(Enum):
    MINIMAL = "MINIMAL"
    STANDARD = "STANDARD"
    EXTENDED = "EXTENDED"


def profile_flags(profile: "ComplianceProfile | str") -> Dict[str, bool]:
    name = profile.value if isinstance(profile, ComplianceProfile) else str(profile).upper().strip()
    if name == "MINIMAL":
        return {
            "allow_quic": False,
            "allow_l4": False,
            "allow_l5": False,
            "enforce_indistinguishability": False,
        }
    if name == "EXTENDED":
        return {
            "allow_quic": True,
            "allow_l4": True,
            "allow_l5": True,
            "enforce_indistinguishability": True,
        }
    return {
        "allow_quic": True,
        "allow_l4": True,
        "allow_l5": True,
        "enforce_indistinguishability": True,
    }


def active_profile() -> ComplianceProfile:
    import os
    val = os.environ.get("BETANET_PROFILE", "STANDARD").upper().strip()
    if val == "MINIMAL":
        return ComplianceProfile.MINIMAL
    if val == "EXTENDED":
        return ComplianceProfile.EXTENDED
    return ComplianceProfile.STANDARD


def _normalize_template_id(v: object) -> Optional[bytes]:
    if isinstance(v, (bytes, bytearray)) and len(v) == 32:
        return bytes(v)
    if isinstance(v, str) and len(v) == 64:
        try:
            b = bytes.fromhex(v)
            return b if len(b) == 32 else None
        except Exception:
            return None
    return None


def verify_front_origin_record(rec: Dict[str, object], host: str, now: Optional[int] = None) -> bool:
    tid = _normalize_template_id(rec.get("template_id"))
    pat = rec.get("host_pattern")
    prof = str(rec.get("profile", "")).upper().strip()
    exp = int(rec.get("expiry", 0) or 0)
    if tid is None:
        return False
    if not isinstance(pat, str) or not pat:
        return False
    if prof not in {"MINIMAL", "STANDARD", "EXTENDED"}:
        return False
    if now is None:
        now = int(time.time())
    if exp <= now:
        return False
    if not fnmatch.fnmatch(host, pat):
        return False
    return True


