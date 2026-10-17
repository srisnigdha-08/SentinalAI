"""
SentinelAI Modular Threat Detection - Candidate E5: Botnet C2 Periodicity Tracker Prototype
Phase 10C Implementation Milestone: Bounded Deterministic Periodicity Detection

Analyzes inter-arrival time consistency (Δt standard deviation and coefficient of variation)
for outbound network connections to detect periodic command-and-control (C2) beaconing,
including unidirectional failed-connection beacons (Ares C2 pattern).
"""

from __future__ import annotations
import math
import time
import logging
import threading
from collections import deque, OrderedDict
from typing import Any, Dict, List, Optional, Tuple, Union

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

log = logging.getLogger("sentinel.modular.periodicity")


def _normalize_key(key: str) -> str:
    """Normalize telemetry dict key for robust field lookup."""
    return key.strip().lower().replace(" ", "_").replace("-", "_").replace("/", "_")


class PeriodicityBuffer:
    """
    Sliding window buffer tracking inter-arrival times for a single (src_ip -> dst_ip) channel.
    Maintains up to `max_samples` connection timestamps within `horizon_seconds`.
    """
    def __init__(self, max_samples: int = 50, horizon_seconds: float = 3600.0):
        self.max_samples = max_samples
        self.horizon_seconds = horizon_seconds
        self.timestamps: deque[float] = deque()
        self.last_seen_ts: Optional[float] = None
        self.last_access: float = time.time()

    def add_event(self, ts: float) -> None:
        self.last_access = time.time()
        if self.last_seen_ts is None:
            self.last_seen_ts = ts
        else:
            self.last_seen_ts = max(self.last_seen_ts, ts)

        if self.timestamps and ts < self.timestamps[-1]:
            # Handle out-of-order jitter
            self.timestamps.append(ts)
            self.timestamps = deque(sorted(self.timestamps))
        else:
            self.timestamps.append(ts)

        self._prune(self.last_seen_ts)
        while len(self.timestamps) > self.max_samples:
            self.timestamps.popleft()

    def _prune(self, current_ts: float) -> None:
        cutoff = current_ts - self.horizon_seconds
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.popleft()

    def compute_periodicity(self, current_ts: float) -> Dict[str, Union[float, int, bool]]:
        """
        Computes inter-arrival intervals Δt, mean μ_Δt, standard deviation σ_Δt,
        and coefficient of variation CV = σ / μ.
        """
        self._prune(current_ts)
        n = len(self.timestamps)
        if n < 3:
            return {
                "event_count": n,
                "interval_count": max(0, n - 1),
                "mean_interval_s": 0.0,
                "std_interval_s": 0.0,
                "cv": 1.0,
                "min_interval_s": 0.0,
                "max_interval_s": 0.0,
                "is_periodic": False
            }

        intervals = [self.timestamps[i] - self.timestamps[i - 1] for i in range(1, n)]
        # Filter out negative or zero intervals (duplicate arrivals)
        positive_intervals = [dt for dt in intervals if dt > 0.0001]
        k = len(positive_intervals)
        if k < 2:
            return {
                "event_count": n,
                "interval_count": k,
                "mean_interval_s": 0.0,
                "std_interval_s": 0.0,
                "cv": 1.0,
                "min_interval_s": 0.0,
                "max_interval_s": 0.0,
                "is_periodic": False
            }

        mean_dt = sum(positive_intervals) / k
        variance = sum((dt - mean_dt) ** 2 for dt in positive_intervals) / max(1, k - 1)
        std_dt = math.sqrt(variance)
        cv = std_dt / max(0.001, mean_dt)

        # Periodic condition: meaningful interval (>= 2s to avoid tight loop floods) and low variance (CV <= 0.20)
        is_periodic = (k >= 3) and (mean_dt >= 2.0) and (cv <= 0.25)

        return {
            "event_count": n,
            "interval_count": k,
            "mean_interval_s": round(mean_dt, 3),
            "std_interval_s": round(std_dt, 3),
            "cv": round(cv, 4),
            "min_interval_s": round(min(positive_intervals), 3),
            "max_interval_s": round(max(positive_intervals), 3),
            "is_periodic": is_periodic
        }


class BotnetPeriodicityDetector(BaseDetector):
    """
    Candidate E5: Botnet C2 Periodicity Tracker Prototype.
    
    Tracks connection inter-arrival intervals per channel (src_ip -> dst_ip).
    Identifies deterministic C2 beaconing even when individual connections fail
    unidirectionally with zero return packets (e.g. Ares C2 beacons).
    """

    def __init__(
        self,
        detector_id: str = "botnet_periodicity",
        version: str = "1.0.0",
        min_intervals_for_alert: int = 4,
        strict_cv_threshold: float = 0.12,
        surge_cv_threshold: float = 0.25,
        min_beacon_interval_s: float = 2.0,
        max_beacon_interval_s: float = 600.0,
        max_channels: int = 5000,
        horizon_seconds: float = 3600.0
    ):
        super().__init__(detector_id=detector_id, version=version)
        self.min_intervals_for_alert = int(min_intervals_for_alert)
        self.strict_cv_threshold = float(strict_cv_threshold)
        self.surge_cv_threshold = float(surge_cv_threshold)
        self.min_beacon_interval_s = float(min_beacon_interval_s)
        self.max_beacon_interval_s = float(max_beacon_interval_s)
        self.max_channels = int(max_channels)
        self.horizon_seconds = float(horizon_seconds)

        self._lock = threading.RLock()
        self._channel_table: OrderedDict[str, PeriodicityBuffer] = OrderedDict()

    def health_check(self) -> DetectorStatus:
        with self._lock:
            if len(self._channel_table) > self.max_channels * 2:
                return DetectorStatus.DEGRADED
            return DetectorStatus.HEALTHY

    def reset_state(self) -> None:
        with self._lock:
            self._channel_table.clear()

    def _extract_fields(self, raw: Dict[str, Any]) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[float]]:
        normalized = {_normalize_key(str(k)): v for k, v in raw.items()}

        # 1. Source IP
        src_ip = None
        for key in ("src_ip", "source_ip", "srcip", "source", "ip_src"):
            if key in normalized and normalized[key]:
                src_ip = str(normalized[key]).strip()
                break

        # 2. Destination IP
        dst_ip = None
        for key in ("dst_ip", "destination_ip", "dstip", "destination", "ip_dst"):
            if key in normalized and normalized[key]:
                dst_ip = str(normalized[key]).strip()
                break

        # 3. Destination Port
        dst_port = None
        for key in ("dst_port", "destination_port", "dstport", "port"):
            if key in normalized and normalized[key] is not None:
                try:
                    p = int(normalized[key])
                    if 1 <= p <= 65535:
                        dst_port = p
                        break
                except (ValueError, TypeError):
                    pass

        # 4. Timestamp
        ts = None
        for key in ("timestamp", "flow_timestamp", "ts", "epoch", "time"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if math.isfinite(val) and val > 0:
                        ts = val
                        break
                except (ValueError, TypeError):
                    pass

        return src_ip, dst_ip, dst_port, ts

    def _get_or_create_channel(self, channel_key: str) -> PeriodicityBuffer:
        with self._lock:
            if channel_key in self._channel_table:
                buf = self._channel_table.pop(channel_key)
                self._channel_table[channel_key] = buf
                return buf

            if len(self._channel_table) >= self.max_channels:
                evicted_k, _ = self._channel_table.popitem(last=False)
                log.debug(f"Periodicity channel table full. Evicted LRU channel: {evicted_k}")

            buf = PeriodicityBuffer(max_samples=50, horizon_seconds=self.horizon_seconds)
            self._channel_table[channel_key] = buf
            return buf

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        src_ip, dst_ip, dst_port, ts = self._extract_fields(telemetry)

        # Fails safe if required addressing or timestamp is missing
        if not src_ip or not dst_ip or ts is None:
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason="Missing required src_ip, dst_ip, or timestamp for periodicity tracking",
                correlation_id=correlation_id
            )

        channel_key = f"{src_ip}->{dst_ip}:{dst_port}" if dst_port else f"{src_ip}->{dst_ip}"
        buf = self._get_or_create_channel(channel_key)
        buf.add_event(ts)
        effective_ts = max(ts, buf.last_seen_ts if buf.last_seen_ts is not None else ts)
        metrics = buf.compute_periodicity(effective_ts)

        k = int(metrics["interval_count"])
        cv = float(metrics["cv"])
        mean_dt = float(metrics["mean_interval_s"])
        std_dt = float(metrics["std_interval_s"])

        features_observed = {
            "channel": channel_key,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "metrics": metrics
        }

        # Policy decision logic
        if k >= self.min_intervals_for_alert and self.min_beacon_interval_s <= mean_dt <= self.max_beacon_interval_s:
            if cv <= self.strict_cv_threshold:
                # Highly deterministic periodic beaconing confirmed
                decision = PolicyDecision.SIMULATED_BLOCK
                confidence = min(0.92 + 0.05 * (1.0 - (cv / self.strict_cv_threshold)), 0.99)
                confidence = validate_finite_score(confidence)
                severity = SeverityLevel.CRITICAL
                rule_id = "PERIODIC_C2_BEACONING_CONFIRMED"
                summary = (
                    f"Deterministic periodic C2 beaconing detected from {src_ip} to {dst_ip} "
                    f"({k} intervals, mean Δt={mean_dt:.1f}s, σ={std_dt:.2f}s, CV={cv:.4f})"
                )
                mitigation = SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - PERIODIC C2 BEACON]"
                )
            elif cv <= self.surge_cv_threshold:
                # Suspected jittered periodic beaconing
                decision = PolicyDecision.DETECTED
                confidence = min(0.70 + 0.15 * (1.0 - (cv / self.surge_cv_threshold)), 0.85)
                confidence = validate_finite_score(confidence)
                severity = SeverityLevel.HIGH
                rule_id = "SUSPECTED_PERIODIC_BEACONING"
                summary = (
                    f"Suspected jittered periodic beaconing detected from {src_ip} to {dst_ip} "
                    f"({k} intervals, mean Δt={mean_dt:.1f}s, σ={std_dt:.2f}s, CV={cv:.4f})"
                )
                mitigation = SimulatedMitigation(
                    action=MitigationAction.SIMULATED_RATE_LIMIT,
                    simulated=True,
                    watermark="[SIMULATED RATE LIMIT - SUSPECTED BEACON]"
                )
            else:
                decision = PolicyDecision.ALLOW
                confidence = 0.05
                severity = SeverityLevel.INFORMATIONAL
                rule_id = "APERIODIC_TRAFFIC"
                summary = f"Outbound traffic is aperiodic (CV={cv:.2f} exceeds threshold)"
                mitigation = SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
        else:
            decision = PolicyDecision.ALLOW
            confidence = 0.05
            severity = SeverityLevel.INFORMATIONAL
            rule_id = "ACCUMULATING_SAMPLES"
            summary = f"Channel accumulating samples ({k} of {self.min_intervals_for_alert} required intervals)"
            mitigation = SimulatedMitigation(action=MitigationAction.NONE, simulated=True)

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
                extracted_features=features_observed
            ),
            mitigation_recommendation=mitigation
        )
