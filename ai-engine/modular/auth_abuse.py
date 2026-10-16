"""
SentinelAI Modular Threat Detection - E2 Stateful Auth-Abuse Detector Prototype
Phase 9E Prototype Implementation Milestone: Authentication Flood & Brute-Force Detection

Detects rapid credential stuffing, SSH/FTP brute force, and connection churn
using the bounded state table with exponential decay and frequency windowing.
"""

from __future__ import annotations
import math
import time
import logging
from typing import Any, Dict, Optional, Tuple

from modular.base import BaseDetector
from modular.state import BoundedConnectionStateTable
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

log = logging.getLogger("sentinel.modular.auth_abuse")

# Standard authentication service ports
AUTH_PORTS = {21, 22, 23, 3389, 8080, 8443}


class AuthAbuseDetector(BaseDetector):
    """
    E2 Stateful Authentication Abuse & Brute-Force Detector Prototype.
    
    Tracks connection attempt rates and decayed frequency per source IP targeting
    authentication ports (SSH: 22, FTP: 21, Telnet: 23, RDP: 3389).
    
    Operates strictly on protocol headers, connection frequencies, and state tables;
    strictly zero reliance on ground-truth label columns.
    """

    def __init__(
        self,
        detector_id: str = "auth_abuse",
        version: str = "1.0.0",
        warning_attempt_threshold: float = 5.0,
        critical_attempt_threshold: float = 15.0,
        decay_half_life_seconds: float = 30.0,
        state_table_capacity: int = 5000,
        default_ttl_seconds: float = 180.0
    ):
        super().__init__(detector_id=detector_id, version=version)
        self.warning_threshold = float(warning_attempt_threshold)
        self.critical_threshold = float(critical_attempt_threshold)
        self.state_table = BoundedConnectionStateTable(
            max_entries=state_table_capacity,
            default_ttl_seconds=default_ttl_seconds,
            decay_half_life_seconds=decay_half_life_seconds
        )

    def health_check(self) -> DetectorStatus:
        """Verifies state table responsiveness."""
        try:
            metrics = self.state_table.get_metrics()
            if metrics["current_entries"] > self.state_table.max_entries:
                return DetectorStatus.DEGRADED
            return DetectorStatus.HEALTHY
        except Exception as exc:
            log.error(f"AuthAbuseDetector health check failed: {exc}")
            return DetectorStatus.ERROR

    def reset_state(self) -> None:
        """Clears connection state table for test isolation."""
        self.state_table.clear()

    def _extract_telemetry(
        self, raw: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[int], Optional[float], Optional[float]]:
        """
        Extracts (src_ip, dst_port, flow_duration, timestamp).
        Returns None tuple if inputs are malformed or non-finite.
        """
        normalized = {str(k).strip().lower().replace(" ", "_").replace("-", "_"): v for k, v in raw.items()}

        # 1. Source IP
        src_ip = None
        for key in ("src_ip", "source_ip", "srcip", "source", "ip_src"):
            if key in normalized and normalized[key]:
                src_ip = str(normalized[key]).strip()
                break
        if not src_ip:
            src_ip = "0.0.0.0"

        # 2. Destination Port
        dst_port = None
        for key in ("dst_port", "destination_port", "dstport", "port"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0 or val > 65535:
                        return None, None, None, None
                    dst_port = int(val)
                    break
                except (ValueError, TypeError):
                    return None, None, None, None

        # 3. Flow Duration
        duration_s = None
        for key in ("flow_duration", "duration"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None
                    if val > 1_000_000:
                        duration_s = val / 1_000_000.0
                    else:
                        duration_s = val
                    break
                except (ValueError, TypeError):
                    return None, None, None, None

        # 4. Timestamp
        ts = None
        for key in ("timestamp", "ts", "epoch"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if math.isfinite(val) and val > 0:
                        ts = val
                        break
                except (ValueError, TypeError):
                    pass

        return src_ip, dst_port, duration_s, ts

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        now = time.time()
        src_ip, dst_port, duration_s, ts = self._extract_telemetry(telemetry)

        # Fail safe if inputs are invalid/non-finite
        if src_ip is None and dst_port is None:
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason="Invalid or non-finite connection parameters in telemetry",
                correlation_id=correlation_id
            )

        event_ts = ts if ts is not None else now

        # Only evaluate connections targeting known auth ports or with explicit auth flag
        is_auth_service = (dst_port in AUTH_PORTS) if dst_port is not None else False

        # If not an auth port, record nothing or return low-confidence ALLOW
        if not is_auth_service:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.ALLOW,
                confidence=0.01,
                severity=SeverityLevel.INFORMATIONAL,
                evidence=EvidenceRecord(
                    trigger_rule="NON_AUTH_PORT",
                    summary=f"Destination port {dst_port} is not a targeted authentication service",
                    extracted_features={"dst_port": dst_port, "src_ip": src_ip}
                ),
                mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
            )

        # Record attempt in state table
        entry = self.state_table.record_attempt(
            key=f"auth:{src_ip}:{dst_port}",
            current_time=event_ts,
            increment=1.0,
            metadata={"dst_port": dst_port, "last_duration": duration_s}
        )

        decayed_score = entry.decayed_score
        attempts = entry.attempt_count

        extracted = {
            "src_ip": src_ip,
            "dst_port": dst_port,
            "decayed_score": decayed_score,
            "total_attempts": attempts,
            "warning_threshold": self.warning_threshold,
            "critical_threshold": self.critical_threshold
        }

        if decayed_score < self.warning_threshold:
            decision = PolicyDecision.ALLOW
            confidence = round(min(0.30, decayed_score / self.warning_threshold * 0.30), 4)
            confidence = validate_finite_score(confidence)
            severity = SeverityLevel.INFORMATIONAL
            rule_id = "AUTH_ATTEMPTS_NORMAL"
            summary = f"Auth attempt rate normal ({decayed_score:.1f} / {self.warning_threshold})"
            mitigation = SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
        elif decayed_score < self.critical_threshold:
            decision = PolicyDecision.DETECTED
            ratio = (decayed_score - self.warning_threshold) / (self.critical_threshold - self.warning_threshold)
            confidence = round(0.65 + 0.20 * ratio, 4)
            confidence = validate_finite_score(confidence)
            severity = SeverityLevel.HIGH
            rule_id = "AUTH_BRUTEFORCE_WARNING_SURGE"
            summary = f"Auth attempt frequency elevated on port {dst_port} (score: {decayed_score:.1f})"
            mitigation = SimulatedMitigation(
                action=MitigationAction.SIMULATED_RATE_LIMIT,
                simulated=True,
                watermark="[SIMULATED RATE LIMIT - AUTH SURGE]"
            )
        else:
            decision = PolicyDecision.SIMULATED_BLOCK
            ratio = min(2.0, (decayed_score - self.critical_threshold) / self.critical_threshold)
            confidence = round(min(0.99, 0.85 + 0.10 * ratio), 4)
            confidence = validate_finite_score(confidence)
            severity = SeverityLevel.CRITICAL
            rule_id = "AUTH_BRUTEFORCE_ATTACK_CONFIRMED"
            summary = f"Persistent brute-force attack confirmed against port {dst_port} (score: {decayed_score:.1f})"
            mitigation = SimulatedMitigation(
                action=MitigationAction.SIMULATED_BLOCK,
                simulated=True,
                watermark="[SIMULATED BLOCK - AUTH BRUTE FORCE]"
            )

        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=decision,
            confidence=confidence,
            severity=severity,
            evidence=EvidenceRecord(
                trigger_rule=rule_id,
                summary=summary,
                extracted_features=extracted
            ),
            mitigation_recommendation=mitigation
        )
