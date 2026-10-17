"""
SentinelAI Modular Threat Detection - B1 Volumetric Flood Detector Prototype
Phase 9D Prototype Implementation Milestone: Volumetric Flood Detection & Rate Analysis

Implements multi-window sliding rates (1s burst, 10s surge, 60s sustained), explicit PPS and BPS
calculations, thread-safe bounded per-source rate state, and fail-safe input validation.
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

log = logging.getLogger("sentinel.modular.volumetric")


def _normalize_key(key: str) -> str:
    """Normalize telemetry dict key for robust field lookup."""
    return key.strip().lower().replace(" ", "_").replace("-", "_").replace("/", "_")


class VolumetricWindowBuffer:
    """
    Sliding window buffer tracking packet and byte observations for a single source.
    Retains samples within a 60-second horizon.
    """
    def __init__(self, max_history_seconds: float = 60.0):
        self.max_history_seconds = max_history_seconds
        # Deque of (timestamp, packets, bytes)
        self.samples: deque[Tuple[float, float, float]] = deque()
        self.last_access: float = time.time()

    def add_sample(self, ts: float, packets: float, bytes_count: float) -> None:
        self.last_access = max(self.last_access, ts)
        if self.samples and ts < self.samples[-1][0]:
            # Handle out-of-order sample jitter
            self.samples.append((ts, packets, bytes_count))
            self.samples = deque(sorted(self.samples, key=lambda s: s[0]))
        else:
            self.samples.append((ts, packets, bytes_count))
        self._prune(ts)

    def _prune(self, current_ts: float) -> None:
        cutoff = current_ts - self.max_history_seconds
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    def calculate_rates(self, current_ts: float) -> Dict[str, float]:
        """
        Calculates PPS and BPS across standard 1s, 10s, and 60s windows.
        """
        self._prune(current_ts)
        if not self.samples:
            return {
                "burst_pps": 0.0, "burst_bps": 0.0,
                "surge_pps": 0.0, "surge_bps": 0.0,
                "sustained_pps": 0.0, "sustained_bps": 0.0
            }

        burst_cutoff = current_ts - 1.0
        surge_cutoff = current_ts - 10.0
        sustained_cutoff = current_ts - 60.0

        burst_pkts, burst_bytes = 0.0, 0.0
        surge_pkts, surge_bytes = 0.0, 0.0
        sustained_pkts, sustained_bytes = 0.0, 0.0

        for s_ts, s_pkts, s_bytes in self.samples:
            if s_ts >= burst_cutoff:
                burst_pkts += s_pkts
                burst_bytes += s_bytes
            if s_ts >= surge_cutoff:
                surge_pkts += s_pkts
                surge_bytes += s_bytes
            if s_ts >= sustained_cutoff:
                sustained_pkts += s_pkts
                sustained_bytes += s_bytes

        # Standard sliding window rates
        return {
            "burst_pps": burst_pkts / 1.0,
            "burst_bps": (burst_bytes * 8.0) / 1.0,
            "surge_pps": surge_pkts / 10.0,
            "surge_bps": (surge_bytes * 8.0) / 10.0,
            "sustained_pps": sustained_pkts / 60.0,
            "sustained_bps": (sustained_bytes * 8.0) / 60.0,
        }


class VolumetricFloodDetector(BaseDetector):
    """
    B1 Volumetric Flood Detector Prototype.
    
    Evaluates both instantaneous flow rates (from netflow/CICFlowMeter fields)
    and multi-window sliding rates (1s burst, 10s surge, 60s sustained) across
    a bounded per-source state table.
    
    Fails safe to INCOMPLETE or DEGRADED on missing, non-finite, or negative telemetry.
    """

    def __init__(
        self,
        detector_id: str = "volumetric_flood",
        version: str = "1.0.0",
        burst_pps_limit: float = 5000.0,
        surge_pps_limit: float = 2000.0,
        sustained_pps_limit: float = 800.0,
        burst_bps_limit: float = 50_000_000.0,     # 50 Mbps
        surge_bps_limit: float = 20_000_000.0,     # 20 Mbps
        sustained_bps_limit: float = 8_000_000.0,  # 8 Mbps
        instantaneous_pps_limit: float = 4000.0,
        instantaneous_bps_limit: float = 40_000_000.0,
        max_sources: int = 10000,
        source_ttl_seconds: float = 120.0
    ):
        super().__init__(detector_id=detector_id, version=version)
        self.burst_pps_limit = float(burst_pps_limit)
        self.surge_pps_limit = float(surge_pps_limit)
        self.sustained_pps_limit = float(sustained_pps_limit)
        self.burst_bps_limit = float(burst_bps_limit)
        self.surge_bps_limit = float(surge_bps_limit)
        self.sustained_bps_limit = float(sustained_bps_limit)
        self.instantaneous_pps_limit = float(instantaneous_pps_limit)
        self.instantaneous_bps_limit = float(instantaneous_bps_limit)

        self.max_sources = max_sources
        self.source_ttl_seconds = source_ttl_seconds

        self._lock = threading.RLock()
        self._source_table: OrderedDict[str, VolumetricWindowBuffer] = OrderedDict()

    def health_check(self) -> DetectorStatus:
        """Verifies detector internal health and memory limits."""
        with self._lock:
            if len(self._source_table) > self.max_sources * 2:
                return DetectorStatus.DEGRADED
            return DetectorStatus.HEALTHY

    def reset_state(self) -> None:
        """Clears all sliding window buffers for test isolation."""
        with self._lock:
            self._source_table.clear()

    def _extract_telemetry_fields(
        self, raw: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[float], Optional[float], Optional[float], Optional[float], Optional[float], Optional[float]]:
        """
        Extracts and validates essential flow metrics.
        Returns: (src_ip, packets, bytes_count, duration_s, flow_pps, flow_bps, timestamp)
        """
        normalized = {_normalize_key(str(k)): v for k, v in raw.items()}

        # 1. Source IP
        src_ip = None
        for key in ("src_ip", "source_ip", "srcip", "source", "ip_src"):
            if key in normalized and normalized[key]:
                src_ip = str(normalized[key]).strip()
                break
        if not src_ip:
            src_ip = "0.0.0.0"

        # 2. Packets
        packets = None
        for key in ("total_fwd_packets", "total_packets", "fwd_packets", "packets", "packet_count"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None, None, None, None
                    packets = val
                    break
                except (ValueError, TypeError):
                    return None, None, None, None, None, None, None

        # 3. Bytes
        bytes_count = None
        for key in ("total_length_of_fwd_packets", "total_bytes", "bytes", "byte_count", "flow_bytes"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None, None, None, None
                    bytes_count = val
                    break
                except (ValueError, TypeError):
                    return None, None, None, None, None, None, None

        # 4. Duration
        duration_s = None
        for key in ("flow_duration", "duration", "duration_ms", "duration_s"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None, None, None, None
                    # CICFlowMeter stores duration in microseconds
                    if "duration" in key and val > 1000.0 and val > 1_000_000:
                        duration_s = val / 1_000_000.0
                    else:
                        duration_s = val
                    break
                except (ValueError, TypeError):
                    return None, None, None, None, None, None, None

        # 5. Instantaneous Flow PPS / Flow BPS
        flow_pps = None
        for key in ("flow_packets_s", "flow_packet_s", "packets_per_sec", "flow_pps", "pps"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None, None, None, None
                    flow_pps = val
                    break
                except (ValueError, TypeError):
                    return None, None, None, None, None, None, None

        flow_bps = None
        for key in ("flow_bytes_s", "flow_byte_s", "bytes_per_sec", "flow_bps", "bps"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if not math.isfinite(val) or val < 0:
                        return None, None, None, None, None, None, None
                    # Convert bytes/s to bits/s for threshold comparison
                    flow_bps = val * 8.0
                    break
                except (ValueError, TypeError):
                    return None, None, None, None, None, None, None

        # Timestamp
        ts = None
        for key in ("timestamp", "flow_timestamp", "ts", "epoch"):
            if key in normalized and normalized[key] is not None:
                try:
                    val = float(normalized[key])
                    if math.isfinite(val) and val > 0:
                        ts = val
                        break
                except (ValueError, TypeError):
                    pass

        return src_ip, packets, bytes_count, duration_s, flow_pps, flow_bps, ts

    def _get_or_create_buffer(self, src_ip: str, now: float) -> VolumetricWindowBuffer:
        with self._lock:
            # Check if exists
            if src_ip in self._source_table:
                buf = self._source_table.pop(src_ip)
                self._source_table[src_ip] = buf
                return buf

            # LRU eviction if full
            if len(self._source_table) >= self.max_sources:
                # Evict oldest
                evicted_ip, _ = self._source_table.popitem(last=False)
                log.debug(f"Volumetric source table full. Evicted LRU source: {evicted_ip}")

            buf = VolumetricWindowBuffer(max_history_seconds=60.0)
            self._source_table[src_ip] = buf
            return buf

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        """
        Evaluates volumetric rates against multi-window thresholds.
        """
        now = time.time()
        (
            src_ip,
            packets,
            bytes_count,
            duration_s,
            flow_pps,
            flow_bps,
            ts
        ) = self._extract_telemetry_fields(telemetry)

        # Fail safe if core metrics could not be extracted or are invalid
        if packets is None and bytes_count is None and flow_pps is None and flow_bps is None:
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason="Missing or non-finite volumetric metrics in telemetry payload",
                correlation_id=correlation_id
            )

        event_ts = ts if ts is not None else now
        pkts_val = packets if packets is not None else 1.0
        bytes_val = bytes_count if bytes_count is not None else 64.0

        # Update sliding window state
        buf = self._get_or_create_buffer(src_ip, event_ts)
        buf.add_sample(event_ts, pkts_val, bytes_val)
        rates = buf.calculate_rates(event_ts)

        # Incorporate instantaneous flow rates if available
        inst_pps = flow_pps if flow_pps is not None else (pkts_val / max(0.001, duration_s or 1.0))
        inst_bps = flow_bps if flow_bps is not None else ((bytes_val * 8.0) / max(0.001, duration_s or 1.0))

        # Calculate violation ratios against configured thresholds
        ratios = {
            "burst_pps": rates["burst_pps"] / max(1.0, self.burst_pps_limit),
            "burst_bps": rates["burst_bps"] / max(1.0, self.burst_bps_limit),
            "surge_pps": rates["surge_pps"] / max(1.0, self.surge_pps_limit),
            "surge_bps": rates["surge_bps"] / max(1.0, self.surge_bps_limit),
            "sustained_pps": rates["sustained_pps"] / max(1.0, self.sustained_pps_limit),
            "sustained_bps": rates["sustained_bps"] / max(1.0, self.sustained_bps_limit),
            "instantaneous_pps": inst_pps / max(1.0, self.instantaneous_pps_limit),
            "instantaneous_bps": inst_bps / max(1.0, self.instantaneous_bps_limit),
        }

        max_metric, max_ratio = max(ratios.items(), key=lambda item: item[1])

        features_observed = {
            "src_ip": src_ip,
            "max_metric": max_metric,
            "max_ratio": round(max_ratio, 4),
            "rates": {k: round(v, 2) for k, v in rates.items()},
            "instantaneous": {"pps": round(inst_pps, 2), "bps": round(inst_bps, 2)},
        }

        # Policy decision logic
        if max_ratio < 1.0:
            # Baseline normal traffic
            decision = PolicyDecision.ALLOW
            confidence = 0.05
            severity = SeverityLevel.INFORMATIONAL
            rule_id = "VOLUMETRIC_NORMAL"
            summary = f"Volumetric rates within baseline (highest ratio: {max_metric}={max_ratio:.2f})"
            mitigation = SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
        elif max_ratio < 2.0:
            # Elevated surge / anomaly
            decision = PolicyDecision.DETECTED
            confidence = min(0.60 + 0.20 * (max_ratio - 1.0), 0.85)
            confidence = validate_finite_score(confidence)
            severity = SeverityLevel.HIGH
            rule_id = "VOLUMETRIC_SURGE_THRESHOLD_EXCEEDED"
            summary = f"Traffic rates exceeded surge threshold ({max_metric} ratio={max_ratio:.2f})"
            mitigation = SimulatedMitigation(
                action=MitigationAction.SIMULATED_RATE_LIMIT,
                simulated=True,
                watermark="[SIMULATED RATE LIMIT - VOLUMETRIC SURGE]"
            )
        else:
            # High-volume flood / DDoS attack
            decision = PolicyDecision.SIMULATED_BLOCK
            confidence = min(0.85 + 0.05 * (max_ratio - 2.0), 0.99)
            confidence = validate_finite_score(confidence)
            severity = SeverityLevel.CRITICAL
            rule_id = "VOLUMETRIC_FLOOD_ATTACK_DETECTED"
            summary = f"Volumetric flood attack confirmed ({max_metric} ratio={max_ratio:.2f})"
            mitigation = SimulatedMitigation(
                action=MitigationAction.SIMULATED_BLOCK,
                simulated=True,
                watermark="[SIMULATED BLOCK - VOLUMETRIC FLOOD]"
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
                extracted_features=features_observed
            ),
            mitigation_recommendation=mitigation
        )
