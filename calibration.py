from dataclasses import dataclass
from typing import List, Dict, Tuple, Set


@dataclass
class OriginFingerprint:
    ja3: str
    alpn: List[str]
    extensions: List[int]
    grease: bool
    h2_settings: Dict[str, int]
    tolerant_settings: Set[str]
    zero_rtt_allowed: bool


def calibrate(sample: OriginFingerprint) -> OriginFingerprint:
    return sample


def verify(
    calibrated: OriginFingerprint, observed: OriginFingerprint
) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    if calibrated.alpn != observed.alpn:
        reasons.append("alpn_mismatch")
    if calibrated.extensions != observed.extensions:
        reasons.append("extension_order_mismatch")
    if calibrated.grease != observed.grease:
        reasons.append("grease_behavior_mismatch")
    if observed.zero_rtt_allowed:
        reasons.append("zero_rtt_not_allowed")
    keys_c = set(calibrated.h2_settings.keys())
    keys_o = set(observed.h2_settings.keys())
    if keys_c != keys_o:
        reasons.append("h2_settings_keys_mismatch")
    for k in keys_c & keys_o:
        cv = calibrated.h2_settings[k]
        ov = observed.h2_settings[k]
        if k in calibrated.tolerant_settings:
            low = int(cv - max(1, round(cv * 0.15)))
            high = int(cv + max(1, round(cv * 0.15)))
            if not (low <= ov <= high):
                reasons.append(f"h2_setting_out_of_tolerance:{k}")
        else:
            if ov != cv:
                reasons.append(f"h2_setting_mismatch:{k}")
    return (len(reasons) == 0), reasons
