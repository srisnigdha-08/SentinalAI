"""
SentinelAI Modular Threat Detection - Authentication Event Adapter Contract
Phase 10 Detector Recovery: E2 Structured Authentication Telemetry Adapter

Provides typed schema, sliding-window failure/stuffing tracking, bounded LRU memory,
and fail-safe degradation for authentication events (SSH, RDP, Web Login, Windows Event Logs).
"""

from __future__ import annotations
import math
import re
import time
import logging
from collections import OrderedDict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import threading
from pydantic import BaseModel, Field

from modular.base import BaseDetector
from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    EvidenceRecord,
    SimulatedMitigation,
    create_degraded_result,
    validate_finite_score
)

log = logging.getLogger("sentinel.modular.auth_event_adapter")


class AuthEventType(str, Enum):
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_LOCKOUT = "AUTH_LOCKOUT"
    SESSION_OPEN = "SESSION_OPEN"
    SESSION_CLOSE = "SESSION_CLOSE"


class AuthEvent(BaseModel):
    """Normalized structured authentication event contract."""
    event_type: AuthEventType
    timestamp: float = Field(..., description="Epoch seconds timestamp of auth event")
    src_ip: str = Field(..., min_length=1, description="Source IP initiating authentication")
    dst_ip: Optional[str] = Field(default=None, description="Target destination IP")
    dst_port: Optional[int] = Field(default=None, description="Target port (22, 3389, 443, etc.)")
    service: str = Field(default="auth", description="Service protocol (ssh, rdp, ftp, web_auth, pam)")
    user_identity: Optional[str] = Field(default=None, description="Targeted username or identity")
    failure_reason: Optional[str] = Field(default=None, description="Failure reason code or message")
    raw_message: Optional[str] = Field(default=None, description="Original raw event string")


# Regex patterns for syslog / auth.log SSH events
RE_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)",
    re.IGNORECASE
)
RE_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port (\d+)",
    re.IGNORECASE
)


def parse_auth_event(raw: Dict[str, Any]) -> Optional[AuthEvent]:
    """
    Parses heterogeneous authentication event formats into standard AuthEvent.
    Supports:
    1. Direct structured JSON/dict
    2. Linux auth.log / syslog strings
    3. Windows Security Event 4624 / 4625
    4. Cowrie SSH/Telnet honeypot events
    5. Netflow transport fallback (identifies SSH/auth port traffic)
    
    Returns None if payload cannot be validated or contains non-finite numbers.
    """
    if not isinstance(raw, dict):
        return None

    norm = {str(k).strip().lower().replace(" ", "_").replace("-", "_"): v for k, v in raw.items()}

    # 1. Direct typed event_type
    if "event_type" in norm:
        try:
            ev_str = str(norm["event_type"]).strip().upper()
            if ev_str in ("AUTH_SUCCESS", "SUCCESS", "LOGIN_SUCCESS"):
                etype = AuthEventType.AUTH_SUCCESS
            elif ev_str in ("AUTH_FAILURE", "FAILURE", "LOGIN_FAILED", "FAILED"):
                etype = AuthEventType.AUTH_FAILURE
            elif ev_str in ("AUTH_LOCKOUT", "LOCKOUT"):
                etype = AuthEventType.AUTH_LOCKOUT
            else:
                etype = AuthEventType(ev_str)

            ts_raw = norm.get("timestamp") or norm.get("ts") or time.time()
            ts = float(ts_raw)
            if not math.isfinite(ts) or ts <= 0:
                return None

            src = str(norm.get("src_ip") or norm.get("source_ip") or "0.0.0.0").strip()
            if not src:
                src = "0.0.0.0"

            dst_p = None
            if norm.get("dst_port") is not None:
                val = float(norm["dst_port"])
                if math.isfinite(val) and 0 <= val <= 65535:
                    dst_p = int(val)

            user = str(norm["user_identity"]).strip() if norm.get("user_identity") else (
                str(norm["username"]).strip() if norm.get("username") else (
                    str(norm["user"]).strip() if norm.get("user") else None
                )
            )

            return AuthEvent(
                event_type=etype,
                timestamp=ts,
                src_ip=src,
                dst_ip=str(norm.get("dst_ip")) if norm.get("dst_ip") else None,
                dst_port=dst_p,
                service=str(norm.get("service") or "auth"),
                user_identity=user,
                failure_reason=str(norm.get("failure_reason")) if norm.get("failure_reason") else None,
                raw_message=str(norm.get("raw_message")) if norm.get("raw_message") else None
            )
        except Exception:
            return None

    # 2. Syslog / auth.log message parsing
    msg = norm.get("message") or norm.get("log") or norm.get("raw_message")
    if msg and isinstance(msg, str):
        ts = float(norm.get("timestamp") or norm.get("ts") or time.time())
        if not math.isfinite(ts):
            return None

        m_fail = RE_SSH_FAILED.search(msg)
        if m_fail:
            user, src_ip, port = m_fail.groups()
            return AuthEvent(
                event_type=AuthEventType.AUTH_FAILURE,
                timestamp=ts,
                src_ip=src_ip,
                dst_port=int(port) if port.isdigit() else 22,
                service="ssh",
                user_identity=user,
                failure_reason="Failed password",
                raw_message=msg
            )

        m_acc = RE_SSH_ACCEPTED.search(msg)
        if m_acc:
            user, src_ip, port = m_acc.groups()
            return AuthEvent(
                event_type=AuthEventType.AUTH_SUCCESS,
                timestamp=ts,
                src_ip=src_ip,
                dst_port=int(port) if port.isdigit() else 22,
                service="ssh",
                user_identity=user,
                raw_message=msg
            )

    # 3. Windows Security Event 4624 / 4625
    event_id = norm.get("eventid") or norm.get("event_id")
    if event_id is not None:
        try:
            eid = int(event_id)
            ts = float(norm.get("timestamp") or norm.get("ts") or time.time())
            if not math.isfinite(ts):
                return None
            src_ip = str(norm.get("ipaddress") or norm.get("ip_address") or norm.get("src_ip") or "127.0.0.1").strip()
            user = str(norm.get("targetusername") or norm.get("target_user_name") or norm.get("username") or "").strip() or None

            if eid == 4625:
                return AuthEvent(
                    event_type=AuthEventType.AUTH_FAILURE,
                    timestamp=ts,
                    src_ip=src_ip,
                    service="windows_logon",
                    user_identity=user,
                    failure_reason=str(norm.get("status") or "0xC000006D"),
                    raw_message=f"Windows Event 4625 logon failure for {user} from {src_ip}"
                )
            elif eid == 4624:
                return AuthEvent(
                    event_type=AuthEventType.AUTH_SUCCESS,
                    timestamp=ts,
                    src_ip=src_ip,
                    service="windows_logon",
                    user_identity=user,
                    raw_message=f"Windows Event 4624 logon success for {user} from {src_ip}"
                )
        except Exception:
            return None

    # 4. Cowrie Honeypot event
    cowrie_id = norm.get("cowrie_eventid") or norm.get("eventid")
    if cowrie_id and isinstance(cowrie_id, str) and cowrie_id.startswith("cowrie."):
        try:
            ts = float(norm.get("timestamp") or norm.get("ts") or time.time())
            src_ip = str(norm.get("src_ip") or "0.0.0.0").strip()
            user = str(norm.get("username") or norm.get("user") or "").strip() or None
            if "failed" in cowrie_id:
                return AuthEvent(
                    event_type=AuthEventType.AUTH_FAILURE,
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_port=22,
                    service="ssh",
                    user_identity=user,
                    failure_reason="cowrie_login_failed"
                )
            elif "success" in cowrie_id:
                return AuthEvent(
                    event_type=AuthEventType.AUTH_SUCCESS,
                    timestamp=ts,
                    src_ip=src_ip,
                    dst_port=22,
                    service="ssh",
                    user_identity=user
                )
        except Exception:
            return None

    return None


class IPAuthRecord:
    """Sliding-window tracking of authentication events for a single source IP with deduplication."""
    def __init__(self, src_ip: str):
        self.src_ip = src_ip
        self.failure_timestamps: List[float] = []
        self.targeted_users: Dict[str, float] = {}  # username -> last_attempt_ts
        self.last_success_ts: Optional[float] = None
        self.last_seen_ts: float = 0.0
        self.recent_event_sigs: Set[str] = set()

    def record_failure(self, ts: float, user: Optional[str], event_sig: Optional[str] = None) -> bool:
        if event_sig and event_sig in self.recent_event_sigs:
            return False  # Duplicate event ignored
        if event_sig:
            if len(self.recent_event_sigs) > 500:
                self.recent_event_sigs.clear()
            self.recent_event_sigs.add(event_sig)
        self.last_seen_ts = max(self.last_seen_ts, ts)
        self.failure_timestamps.append(ts)
        if user:
            self.targeted_users[user] = ts
        return True

    def record_success(self, ts: float, user: Optional[str], event_sig: Optional[str] = None) -> bool:
        if event_sig and event_sig in self.recent_event_sigs:
            return False
        if event_sig:
            if len(self.recent_event_sigs) > 500:
                self.recent_event_sigs.clear()
            self.recent_event_sigs.add(event_sig)
        self.last_seen_ts = max(self.last_seen_ts, ts)
        self.last_success_ts = ts
        if user:
            self.targeted_users[user] = ts
        return True

    def prune_and_compute_metrics(self, current_ts: float, horizon_seconds: float = 600.0) -> Dict[str, Any]:
        effective_ts = max(current_ts, self.last_seen_ts)
        cutoff = effective_ts - horizon_seconds
        self.failure_timestamps = [t for t in self.failure_timestamps if t >= cutoff]
        self.failure_timestamps.sort()

        # Prune targeted users older than horizon
        self.targeted_users = {u: t for u, t in self.targeted_users.items() if t >= cutoff}

        failures_1m = sum(1 for t in self.failure_timestamps if t >= (effective_ts - 60.0))
        failures_5m = sum(1 for t in self.failure_timestamps if t >= (effective_ts - 300.0))

        # Recent unique usernames in last 5 minutes
        recent_users_5m = sum(1 for t in self.targeted_users.values() if t >= (effective_ts - 300.0))

        return {
            "failures_1m": failures_1m,
            "failures_5m": failures_5m,
            "total_window_failures": len(self.failure_timestamps),
            "unique_users_5m": recent_users_5m,
            "last_success_ts": self.last_success_ts,
            "last_seen_ts": self.last_seen_ts
        }


class AuthEventDetector(BaseDetector):
    """
    E2 Structured Authentication Event Adapter & Threat Detector.
    
    Ingests and normalizes authentication event telemetry.
    Detects:
    1. High-rate single-target SSH/RDP brute force (failures_1m >= threshold).
    2. Distributed or slow credential stuffing (unique users targeted from same IP >= threshold).
    3. Compromise after brute-force (AUTH_SUCCESS immediately following failure surge).
    
    Enforces bounded LRU state table, thread-safety, and fail-safe degradation on missing fields.
    """

    def __init__(
        self,
        detector_id: str = "auth_event_adapter",
        version: str = "1.0.0",
        warning_failures_5m: int = 5,
        critical_failures_1m: int = 10,
        critical_failures_5m: int = 20,
        credential_stuffing_users_threshold: int = 5,
        max_tracked_ips: int = 5000,
        ttl_seconds: float = 600.0
    ):
        super().__init__(detector_id=detector_id, version=version)
        self.warning_failures_5m = int(warning_failures_5m)
        self.critical_failures_1m = int(critical_failures_1m)
        self.critical_failures_5m = int(critical_failures_5m)
        self.credential_stuffing_users_threshold = int(credential_stuffing_users_threshold)
        self.max_tracked_ips = int(max_tracked_ips)
        self.ttl_seconds = float(ttl_seconds)

        self._lock = threading.RLock()
        self._ip_table: OrderedDict[str, IPAuthRecord] = OrderedDict()

    def health_check(self) -> DetectorStatus:
        with self._lock:
            if len(self._ip_table) > self.max_tracked_ips:
                return DetectorStatus.DEGRADED
            return DetectorStatus.HEALTHY

    def reset_state(self) -> None:
        with self._lock:
            self._ip_table.clear()

    def _get_or_create_record(self, src_ip: str, current_ts: float) -> IPAuthRecord:
        with self._lock:
            if src_ip in self._ip_table:
                rec = self._ip_table.pop(src_ip)
                self._ip_table[src_ip] = rec
                return rec

            # Evict LRU if capacity reached
            if len(self._ip_table) >= self.max_tracked_ips:
                self._ip_table.popitem(last=False)

            rec = IPAuthRecord(src_ip)
            self._ip_table[src_ip] = rec
            return rec

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        auth_event = parse_auth_event(telemetry)
        if auth_event is None:
            # Telemetry lacks required auth structures or contains invalid/non-finite fields
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason="Input telemetry lacks valid structured authentication event fields",
                correlation_id=correlation_id
            )

        event_sig = f"{auth_event.timestamp}:{auth_event.src_ip}:{auth_event.user_identity}:{auth_event.event_type.value}:{auth_event.raw_message or ''}"
        with self._lock:
            rec = self._get_or_create_record(auth_event.src_ip, auth_event.timestamp)
            if auth_event.event_type in (AuthEventType.AUTH_FAILURE, AuthEventType.AUTH_LOCKOUT):
                rec.record_failure(auth_event.timestamp, auth_event.user_identity, event_sig=event_sig)
            elif auth_event.event_type == AuthEventType.AUTH_SUCCESS:
                rec.record_success(auth_event.timestamp, auth_event.user_identity, event_sig=event_sig)

            metrics = rec.prune_and_compute_metrics(auth_event.timestamp, self.ttl_seconds)

        extracted = {
            "src_ip": auth_event.src_ip,
            "event_type": auth_event.event_type.value,
            "user_identity": auth_event.user_identity,
            "service": auth_event.service,
            "failures_1m": metrics["failures_1m"],
            "failures_5m": metrics["failures_5m"],
            "unique_users_5m": metrics["unique_users_5m"]
        }

        # 1. Credential Stuffing detection: single IP targeting many accounts
        if metrics["unique_users_5m"] >= self.credential_stuffing_users_threshold:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.SIMULATED_BLOCK,
                confidence=min(0.98, 0.85 + 0.02 * (metrics["unique_users_5m"] - self.credential_stuffing_users_threshold)),
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="CREDENTIAL_STUFFING_ATTACK_DETECTED",
                    summary=(
                        f"Credential stuffing detected from {auth_event.src_ip}: "
                        f"{metrics['unique_users_5m']} distinct accounts targeted within 5 minutes"
                    ),
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - CREDENTIAL STUFFING]"
                )
            )

        # 2. Compromise after brute-force surge: successful login following multiple failures
        if auth_event.event_type == AuthEventType.AUTH_SUCCESS and metrics["failures_5m"] >= self.warning_failures_5m:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.DETECTED,
                confidence=0.88,
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="SUSPECTED_BRUTE_FORCE_SUCCESSFUL_COMPROMISE",
                    summary=(
                        f"Account '{auth_event.user_identity}' successfully logged in from {auth_event.src_ip} "
                        f"immediately following {metrics['failures_5m']} auth failures within 5 minutes"
                    ),
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_RATE_LIMIT,
                    simulated=True,
                    watermark="[SIMULATED RATE LIMIT - SUSPECTED COMPROMISE]"
                )
            )

        # 3. Critical brute-force rate exceeded
        if metrics["failures_1m"] >= self.critical_failures_1m or metrics["failures_5m"] >= self.critical_failures_5m:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.SIMULATED_BLOCK,
                confidence=min(0.99, 0.88 + 0.01 * metrics["failures_1m"]),
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="RAPID_AUTHENTICATION_BRUTE_FORCE_CONFIRMED",
                    summary=(
                        f"Rapid authentication brute-force confirmed from {auth_event.src_ip} on {auth_event.service}: "
                        f"{metrics['failures_1m']} failures in 1m, {metrics['failures_5m']} in 5m"
                    ),
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - AUTH BRUTE FORCE]"
                )
            )

        # 4. Elevated failure surge (warning threshold)
        if metrics["failures_5m"] >= self.warning_failures_5m:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.DETECTED,
                confidence=round(0.70 + 0.15 * (metrics["failures_5m"] / self.critical_failures_5m), 4),
                severity=SeverityLevel.HIGH,
                evidence=EvidenceRecord(
                    trigger_rule="AUTHENTICATION_FAILURE_SURGE_DETECTED",
                    summary=(
                        f"Elevated authentication failures from {auth_event.src_ip} on {auth_event.service}: "
                        f"{metrics['failures_5m']} failures in 5m"
                    ),
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_RATE_LIMIT,
                    simulated=True,
                    watermark="[SIMULATED RATE LIMIT - AUTH SURGE]"
                )
            )

        # 5. Normal / isolated auth activity -> ALLOW
        conf = 0.02 if auth_event.event_type == AuthEventType.AUTH_SUCCESS else 0.15
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.ALLOW,
            confidence=conf,
            severity=SeverityLevel.INFORMATIONAL,
            evidence=EvidenceRecord(
                trigger_rule="BENIGN_AUTH_EVENT",
                summary=f"Authentication event {auth_event.event_type.value} within normal operating parameters",
                extracted_features=extracted
            ),
            mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
        )
