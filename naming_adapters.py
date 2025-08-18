from typing import Dict, Tuple


def handshake_finalized(confirmations: int, seconds_since_last_reorg: int) -> bool:
    return confirmations >= 12 and seconds_since_last_reorg >= 3600


def filecoin_finalized(status: str) -> bool:
    return status.lower() == "finalized"


def l2_finalized(status: str) -> bool:
    return status.lower() == "finalized"


def combine_finality(
    hs_conf: int, hs_reorg_age_sec: int, fvm_status: str, l2_status: str
) -> Tuple[Dict[str, bool], bool]:
    hs = handshake_finalized(hs_conf, hs_reorg_age_sec)
    fvm = filecoin_finalized(fvm_status)
    l2 = l2_finalized(l2_status)
    m = {"handshake": hs, "filecoin": fvm, "l2": l2}
    ok = sum(1 for v in m.values() if v) >= 2
    return m, ok
