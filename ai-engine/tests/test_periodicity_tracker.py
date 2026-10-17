"""
Unit and Contract Test Suite for Candidate E5: Botnet C2 Periodicity Tracker Prototype
Tests inter-arrival calculation, coefficient of variation, deterministic beacon detection,
jitter tolerance, LRU channel eviction, horizon pruning, and fail-safe degradation.
"""

import math
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from modular.periodicity_tracker import BotnetPeriodicityDetector, PeriodicityBuffer
from modular.contracts import (
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    DetectorResult
)


class TestPeriodicityBuffer:
    def test_buffer_fewer_than_three_events(self):
        buf = PeriodicityBuffer(max_samples=50, horizon_seconds=3600.0)
        buf.add_event(100.0)
        buf.add_event(160.0)
        res = buf.compute_periodicity(160.0)
        assert res["is_periodic"] is False
        assert res["interval_count"] == 1

    def test_buffer_exact_periodic_intervals(self):
        buf = PeriodicityBuffer(max_samples=50, horizon_seconds=3600.0)
        # 5 events at exact 30s intervals: 100, 130, 160, 190, 220
        for i in range(5):
            buf.add_event(100.0 + (i * 30.0))
        res = buf.compute_periodicity(220.0)
        assert res["is_periodic"] is True
        assert res["interval_count"] == 4
        assert res["mean_interval_s"] == 30.0
        assert res["std_interval_s"] == 0.0
        assert res["cv"] == 0.0

    def test_buffer_prunes_past_horizon(self):
        buf = PeriodicityBuffer(max_samples=50, horizon_seconds=300.0)
        # Event 1 at t = 100.0
        buf.add_event(100.0)
        # Event 2 at t = 500.0 (400s later, Event 1 is > 300s old)
        buf.add_event(500.0)
        res = buf.compute_periodicity(500.0)
        assert len(buf.timestamps) == 1
        assert buf.timestamps[0] == 500.0


class TestBotnetPeriodicityDetector:
    @pytest.fixture
    def detector(self):
        return BotnetPeriodicityDetector(
            detector_id="botnet_periodicity_test",
            version="1.0.0-test",
            min_intervals_for_alert=4,
            strict_cv_threshold=0.10,
            surge_cv_threshold=0.25,
            min_beacon_interval_s=5.0,
            max_beacon_interval_s=300.0,
            max_channels=100
        )

    def test_health_check_healthy(self, detector):
        assert detector.health_check() == DetectorStatus.HEALTHY

    def test_single_event_returns_allow(self, detector):
        res = detector.evaluate({
            "src_ip": "192.168.1.50",
            "dst_ip": "198.51.100.5",
            "dst_port": 8080,
            "timestamp": 1000.0
        })
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.severity == SeverityLevel.INFORMATIONAL
        assert res.mitigation_recommendation.action == MitigationAction.NONE

    def test_deterministic_periodic_beaconing_triggers_simulated_block(self, detector):
        # 6 connections from infected host to C2 IP every 60 seconds
        src = "10.0.0.99"
        c2_ip = "203.0.113.88"
        base_t = 2000.0

        res = None
        for i in range(6):
            payload = {
                "src_ip": src,
                "dst_ip": c2_ip,
                "dst_port": 443,
                "total_fwd_packets": 2,
                "total_bwd_packets": 0,  # Unidirectional failed beacon!
                "timestamp": base_t + (i * 60.0)
            }
            res = detector.evaluate(payload)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.evidence.trigger_rule == "PERIODIC_C2_BEACONING_CONFIRMED"
        assert "[SIMULATED BLOCK - PERIODIC C2 BEACON]" in res.mitigation_recommendation.watermark
        assert res.confidence >= 0.90

    def test_jittered_periodic_beaconing_triggers_detected(self, detector):
        # Connections with moderate jitter (60s ± 8s: 60, 52, 68, 56, 64)
        src = "10.0.0.101"
        c2_ip = "203.0.113.99"
        intervals = [0.0, 60.0, 112.0, 180.0, 236.0, 300.0]

        res = None
        for dt in intervals:
            payload = {
                "src_ip": src,
                "dst_ip": c2_ip,
                "dst_port": 80,
                "timestamp": 5000.0 + dt
            }
            res = detector.evaluate(payload)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.DETECTED
        assert res.severity == SeverityLevel.HIGH
        assert res.evidence.trigger_rule == "SUSPECTED_PERIODIC_BEACONING"
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_RATE_LIMIT

    def test_random_aperiodic_traffic_returns_allow(self, detector):
        # Highly variable intervals: 2s, 150s, 12s, 400s, 5s (CV > 0.50)
        src = "10.0.0.102"
        dst_ip = "8.8.8.8"
        intervals = [0.0, 2.0, 152.0, 164.0, 564.0, 569.0]

        res = None
        for dt in intervals:
            payload = {
                "src_ip": src,
                "dst_ip": dst_ip,
                "dst_port": 53,
                "timestamp": 8000.0 + dt
            }
            res = detector.evaluate(payload)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.evidence.trigger_rule in ("APERIODIC_TRAFFIC", "ACCUMULATING_SAMPLES")

    def test_out_of_order_arrival_jitter(self, detector):
        # Timestamps arrive out of order: 100, 220, 160 (jitter)
        src = "10.0.0.105"
        dst = "192.0.2.1"
        detector.evaluate({"src_ip": src, "dst_ip": dst, "timestamp": 100.0})
        detector.evaluate({"src_ip": src, "dst_ip": dst, "timestamp": 220.0})
        detector.evaluate({"src_ip": src, "dst_ip": dst, "timestamp": 160.0})

        with detector._lock:
            buf = detector._channel_table[f"{src}->{dst}"]
            assert list(buf.timestamps) == [100.0, 160.0, 220.0]

    def test_lru_channel_eviction(self):
        det = BotnetPeriodicityDetector(max_channels=5)
        for i in range(10):
            det.evaluate({
                "src_ip": f"10.0.0.{i}",
                "dst_ip": "1.1.1.1",
                "timestamp": 1000.0 + i
            })
        with det._lock:
            assert len(det._channel_table) <= 5
            # Earliest channels 0 to 4 should be evicted
            assert "10.0.0.0->1.1.1.1" not in det._channel_table
            assert "10.0.0.9->1.1.1.1" in det._channel_table

    def test_missing_and_non_finite_inputs_fail_safe(self, detector):
        for bad_payload in [
            {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "timestamp": float("nan")},
            {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "timestamp": float("inf")},
            {"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "timestamp": -100.0},
            {"src_ip": "10.0.0.1"},  # missing dst_ip
            {"dst_ip": "1.1.1.1"},  # missing src_ip
            {}
        ]:
            res = detector.evaluate(bad_payload)
            assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
            assert res.decision == PolicyDecision.MONITOR
            assert res.confidence == 0.0
            assert res.mitigation_recommendation.action == MitigationAction.NONE
