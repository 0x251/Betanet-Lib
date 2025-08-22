from typing import Dict, List
from betanet.core.detcbor import dumps as detcbor_dumps, loads as detcbor_loads


def encode_cap_msg(caps: Dict[str, object]) -> bytes:
    return detcbor_dumps(caps)


def decode_cap_msg(data: bytes) -> Dict[str, object]:
    obj = detcbor_loads(data)
    if not isinstance(obj, dict):
        return {}
    return obj


def select_decider(local_peer_id: bytes, remote_peer_id: bytes) -> bool:
    return local_peer_id < remote_peer_id


def _highest(mutual: List[str]) -> str:
    if not mutual:
        return ""
    return sorted(mutual)[-1]


def decide_selection(local_caps: Dict[str, object], remote_caps: Dict[str, object]) -> Dict[str, str]:
    sel: Dict[str, str] = {}
    for k in ("l2", "l3", "l4", "l5"):
        la = [str(x) for x in local_caps.get(k, [])]
        ra = [str(x) for x in remote_caps.get(k, [])]
        inter = [x for x in la if x in set(ra)]
        sel[k] = _highest(inter)
    return sel


def encode_sel_msg(selection: Dict[str, str]) -> bytes:
    return detcbor_dumps({
        "l2": str(selection.get("l2", "")),
        "l3": str(selection.get("l3", "")),
        "l4": str(selection.get("l4", "")),
        "l5": str(selection.get("l5", "")),
    })


def decode_sel_msg(data: bytes) -> Dict[str, str]:
    obj = detcbor_loads(data)
    if not isinstance(obj, dict):
        return {"l2": "", "l3": "", "l4": "", "l5": ""}
    out: Dict[str, str] = {}
    for k in ("l2", "l3", "l4", "l5"):
        v = obj.get(k, "")
        out[k] = str(v) if isinstance(v, (str, bytes)) else str(v)
    return out


def build_exporter_context(
    selection: Dict[str, str],
    caps_client: Dict[str, object],
    caps_server: Dict[str, object],
    template_id: bytes,
) -> Dict[str, object]:
    return {
        "l2": str(selection.get("l2", "")),
        "l3": str(selection.get("l3", "")),
        "l4": str(selection.get("l4", "")),
        "l5": str(selection.get("l5", "")),
        "caps_client": dict(caps_client),
        "caps_server": dict(caps_server),
        "template": bytes(template_id),
    }


