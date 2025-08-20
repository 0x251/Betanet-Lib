import json
import os
import logging
import socket
import ssl

from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Set, Optional, Protocol
from enum import Enum
from json import JSONDecodeError


@dataclass
class OriginFingerprint:
    tls_version: str
    cipher: str
    ja3: str
    alpn: List[str]
    extensions: List[int]
    grease: bool
    h2_settings: Dict[str, int]
    tolerant_settings: Set[str]
    zero_rtt_allowed: bool
    pop_hint: Optional[str] = None


calibration_counters: Dict[str, int] = {
    "accept": 0,
    "reject": 0,
}


def calibrate(sample: OriginFingerprint) -> OriginFingerprint:
    return sample


def verify(
    calibrated: OriginFingerprint, observed: OriginFingerprint
) -> Tuple[bool, List[str]]:
    logger = logging.getLogger("betanet")
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
    if (
        calibrated.pop_hint
        and observed.pop_hint
        and calibrated.pop_hint != observed.pop_hint
    ):
        reasons.append("pop_mismatch")
    ok = len(reasons) == 0
    if not ok:
        logger.info("calibration_mismatch fields=%s", ",".join(reasons))
        for r in reasons:
            calibration_counters[r] = calibration_counters.get(r, 0) + 1
        calibration_counters["reject"] = calibration_counters.get("reject", 0) + 1
    else:
        calibration_counters["accept"] = calibration_counters.get("accept", 0) + 1
    return ok, reasons


def _fp_dir() -> str:
    env = os.environ.get("BETANET_FP_DIR")
    if env:
        return env
    try:
        is_posix = os.name == "posix"
    except Exception:
        is_posix = False
    geteuid = getattr(os, "geteuid", None)
    if is_posix and callable(geteuid):
        try:
            if geteuid() == 0:
                return "/var/lib/betanet/fp"
        except Exception:
            pass

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return os.path.join(xdg, "betanet", "fp")

    return os.path.join(os.path.expanduser("~"), ".betanet", "fp")


def save_fingerprint(origin: str, pop: str, fp: OriginFingerprint) -> None:
    d = os.path.join(_fp_dir(), origin)
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, f"{pop}.json")
    payload = asdict(fp)
    ts = payload.get("tolerant_settings")
    if isinstance(ts, set):
        payload["tolerant_settings"] = sorted(ts)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.replace(tmp, p)


def load_fingerprint(origin: str, pop: str) -> Optional[OriginFingerprint]:
    p = os.path.join(_fp_dir(), origin, f"{pop}.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, JSONDecodeError):
        # Treat corrupt or partial files as missing
        return None
    ts = data.get("tolerant_settings")
    if isinstance(ts, list):
        data["tolerant_settings"] = set(ts)
    return OriginFingerprint(**data)


class CalibrationPolicy(Enum):
    REQUIRED = "required"
    DEV = "dev"


class FingerprintProvider(Protocol):
    def collect(self, origin: str, pop: str) -> OriginFingerprint: ...


class StaticFingerprintProvider:
    def __init__(self, fp: OriginFingerprint):
        self.fp = fp

    def collect(self, origin: str, pop: str) -> OriginFingerprint:
        return self.fp


class TLSFingerprintProvider:
    def __init__(self, alpn_offered: Optional[List[str]] = None):
        self.alpn_offered = alpn_offered or ["h2", "http/1.1"]

    def _read_exact(self, s: socket.socket, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf.extend(chunk)
        return bytes(buf)

    def _read_http2_settings(self, ssock: ssl.SSLSocket) -> Dict[str, int]:
        
        ssock.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        ssock.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        ssock.settimeout(3.0)
        settings: Dict[str, int] = {}
        id_to_name = {
            0x1: "HEADER_TABLE_SIZE",
            0x2: "ENABLE_PUSH",
            0x3: "MAX_CONCURRENT_STREAMS",
            0x4: "INITIAL_WINDOW_SIZE",
            0x5: "MAX_FRAME_SIZE",
            0x6: "MAX_HEADER_LIST_SIZE",
        }
        for _ in range(10):
            hdr = self._read_exact(ssock, 9)
            length = int.from_bytes(hdr[0:3], "big")
            ftype = hdr[3]
            flags = hdr[4]
            sid = int.from_bytes(hdr[5:9], "big") & 0x7FFFFFFF
            payload = self._read_exact(ssock, length) if length else b""
            if ftype == 0x4 and sid == 0 and (flags & 0x1) == 0:
                
                for i in range(0, len(payload), 6):
                    if i + 6 <= len(payload):
                        sid_code = int.from_bytes(payload[i : i + 2], "big")
                        val = int.from_bytes(payload[i + 2 : i + 6], "big")
                        name = id_to_name.get(sid_code, f"UNKNOWN_{sid_code}")
                        settings[name] = val
                break
        return settings

    def collect(self, origin: str, pop: str) -> OriginFingerprint:
        host, port = (origin.split(":", 1) + ["443"])[:2]
        port_i = int(port)
        ctx = ssl.create_default_context()
        try:
            ctx.set_alpn_protocols(self.alpn_offered)
        except Exception:
            pass
        with socket.create_connection((host, port_i), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.selected_alpn_protocol() or "http/1.1"
                ver = ssock.version() or "TLS-unknown"
                cipher = (ssock.cipher() or ("", "", 0))[0]
                h2 = {}
                if proto == "h2":
                    try:
                        h2 = self._read_http2_settings(ssock)
                    except Exception:
                        h2 = {}
                try:
                    srvname = ssock.server_hostname or host
                except Exception:
                    srvname = host
        
        tol = {"INITIAL_WINDOW_SIZE", "HEADER_TABLE_SIZE", "MAX_HEADER_LIST_SIZE"}
        return OriginFingerprint(
            tls_version=ver,
            cipher=cipher,
            ja3="unknown",
            alpn=[proto],
            extensions=[],
            grease=False,
            h2_settings=h2,
            tolerant_settings=tol,
            zero_rtt_allowed=False,
            pop_hint=srvname,
        )


def ensure_calibrated(
    origin: str, pop: str, provider: FingerprintProvider, policy: CalibrationPolicy
) -> OriginFingerprint:
    logger = logging.getLogger("betanet")
    attempts = 0
    while attempts < 3:
        attempts += 1
        baseline = load_fingerprint(origin, pop)
        observed = provider.collect(origin, pop)

        if baseline is None:
            save_fingerprint(origin, pop, observed)
            logger.info("calibration_saved origin=%s pop=%s", origin, pop)
            return observed
        ok, reasons = verify(baseline, observed)
        if ok:
            logger.info("calibration_ok origin=%s pop=%s", origin, pop)
            return baseline
        if "pop_mismatch" in reasons and observed.pop_hint:
            pop = observed.pop_hint
            logger.info("calibration_retry_pop origin=%s new_pop=%s", origin, pop)
            continue
        if policy == CalibrationPolicy.DEV:
            save_fingerprint(origin, pop, observed)
            logger.info("calibration_updated_dev origin=%s pop=%s", origin, pop)
            return observed
        break
    raise RuntimeError("calibration_failed")


def get_counters() -> Dict[str, int]:
    return dict(calibration_counters)
