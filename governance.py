import math
from typing import Dict, List, Tuple


def uptime_score(seconds_uptime: int) -> float:
    s = math.log2(1 + seconds_uptime / 86400)
    return min(s, 16.0)


def vote_weight_raw(seconds_uptime: int, total_ecash_staked_sat: int) -> float:
    us = uptime_score(seconds_uptime)
    stake_term = math.log10(total_ecash_staked_sat / 1000 + 1)
    return us + stake_term


def cap_weights_by_as(
    weights_by_as: Dict[str, float], cap_fraction: float
) -> Dict[str, float]:
    total = sum(weights_by_as.values())
    cap = total * cap_fraction
    out: Dict[str, float] = {}
    for k, v in weights_by_as.items():
        out[k] = min(v, cap)
    return out


def cap_weights_by_org(
    weights_by_org: Dict[str, float], cap_fraction: float
) -> Dict[str, float]:
    total = sum(weights_by_org.values())
    cap = total * cap_fraction
    out: Dict[str, float] = {}
    for k, v in weights_by_org.items():
        out[k] = min(v, cap)
    return out


def check_diversity(
    ack_weights_by_as: Dict[str, float],
    ack_weights_by_org: Dict[str, float],
    min_as_groups: int,
) -> Tuple[bool, Dict[str, float]]:
    total_ack = sum(ack_weights_by_as.values())
    by_as_ok = (
        all((w / total_ack) <= 0.20 + 1e-9 for w in ack_weights_by_as.values())
        if total_ack > 0
        else False
    )
    by_org_total = sum(ack_weights_by_org.values())
    by_org_ok = (
        all((w / by_org_total) <= 0.25 + 1e-9 for w in ack_weights_by_org.values())
        if by_org_total > 0
        else False
    )
    as_count_ok = (
        len([k for k, w in ack_weights_by_as.items() if w > 0]) >= min_as_groups
    )
    return (by_as_ok and by_org_ok and as_count_ok), {
        "ack_total": total_ack,
        "as_groups": float(len([k for k, w in ack_weights_by_as.items() if w > 0])),
    }


def check_quorum(
    ack_weights: Dict[str, float],
    active_weights: Dict[str, float],
    ack_by_as: Dict[str, float],
    ack_by_org: Dict[str, float],
    min_as_groups: int = 24,
) -> Tuple[bool, Dict[str, float]]:
    sum_ack = sum(ack_weights.values())
    sum_active = sum(active_weights.values())
    threshold = 0.67 * sum_active
    diversity_ok, div_stats = check_diversity(ack_by_as, ack_by_org, min_as_groups)
    ok = sum_ack >= threshold and diversity_ok
    return ok, {
        "sum_ack": sum_ack,
        "sum_active": sum_active,
        "threshold": threshold,
        "diversity_ok": 1.0 if diversity_ok else 0.0,
    }


def upgrade_delay_ready(window_days_ok: List[bool]) -> bool:
    if len(window_days_ok) < 7:
        return False
    return all(window_days_ok[-7:])
