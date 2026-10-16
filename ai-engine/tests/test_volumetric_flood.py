"""
Unit and Contract Test Suite for B1 Volumetric Flood Detector Prototype
Tests sliding rate calculation, multi-window thresholds, bounded state eviction,
thread safety, fail-safe degradation on non-finite/negative inputs, and orchestrator integration.
"""

import math
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from concurrent.futures import ThreadPoolExecutor

from modular.volumetric_flood import VolumetricFloodDetector, VolumetricWindowBuffer
from modular.contracts import (
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    DetectorResult
)
from modular.orchestrator import ModularOrchestrator


class TestVolumetricBuffer:
    def test_empty_buffer_rates_are_zero(self):
        buf = VolumetricWindowBuffer(max_history_seconds=60.0)
        rates = buf.calculate_rates(100.0)
        assert rates["burst_pps"] == 0.0
        assert rates["burst_bps"] == 0.0
        assert rates["surge_pps"] == 0.0
        assert rates["sustained_pps"] == 0.0

    def test_single_sample_window_rates(self):
        buf = VolumetricWindowBuffer(max_history_seconds=60.0)
        buf.add_sample(ts=10.0, packets=100.0, bytes_count=50000.0)
        rates = buf.calculate_rates(10.0)
        assert rates["burst_pps"] > 0.0
        assert rates["burst_bps"] > 0.0

    def test_buffer_pruning_after_horizon(self):
        buf = VolumetricWindowBuffer(max_history_seconds=60.0)
        buf.add_sample(ts=10.0, packets=100.0, bytes_count=1000.0)
        buf.add_sample(ts=20.0, packets=100.0, bytes_count=1000.0)
        # Advance clock to 75.0 (sample at 10.0 is > 60s old)
        rates = buf.calculate_rates(75.0)
        # Only sample at 20.0 remains in 60s sustained window
        assert len(buf.samples) == 1
        assert buf.samples[0][0] == 20.0


class TestVolumetricFloodDetector:
    @pytest.fixture
    def detector(self):
        # Configure sensitive thresholds for deterministic testing
        return VolumetricFloodDetector(
            detector_id="volumetric_flood_test",
            version="1.0.0-test",
            burst_pps_limit=100.0,
            surge_pps_limit=50.0,
            sustained_pps_limit=20.0,
            burst_bps_limit=100_000.0,
            surge_bps_limit=50_000.0,
            sustained_bps_limit=20_000.0,
            instantaneous_pps_limit=200.0,
            instantaneous_bps_limit=200_000.0,
            max_sources=100,
            source_ttl_seconds=30.0
        )

    def test_health_check_healthy(self, detector):
        assert detector.health_check() == DetectorStatus.HEALTHY

    def test_normal_traffic_within_limits_produces_allow(self, detector):
        telemetry = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "total_fwd_packets": 5,
            "total_length_of_fwd_packets": 200,
            "flow_duration": 1.0,
            "flow_packets_s": 5.0,
            "flow_bytes_s": 200.0,
            "timestamp": 1000.0
        }
        res = detector.evaluate(telemetry, correlation_id="test-allow-1")
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.severity == SeverityLevel.INFORMATIONAL
        assert res.mitigation_recommendation.action == MitigationAction.NONE
        assert res.mitigation_recommendation.simulated is True
        assert res.confidence <= 0.10

    def test_elevated_traffic_exceeding_threshold_produces_detected(self, detector):
        # burst_pps_limit is 100.0. 125 pps gives ratio 1.25 -> DETECTED
        telemetry = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "total_fwd_packets": 125,
            "total_length_of_fwd_packets": 10000,
            "flow_duration": 1.0,
            "flow_packets_s": 125.0,
            "flow_bytes_s": 10000.0,
            "timestamp": 1000.0
        }
        res = detector.evaluate(telemetry, correlation_id="test-detected-1")
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.DETECTED
        assert res.severity == SeverityLevel.HIGH
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_RATE_LIMIT
        assert res.mitigation_recommendation.simulated is True
        assert 0.60 <= res.confidence < 0.85

    def test_overwhelming_flood_produces_simulated_block(self, detector):
        # instantaneous_pps_limit is 200.0. 600 pps gives ratio 3.0 -> SIMULATED_BLOCK
        telemetry = {
            "src_ip": "10.10.10.10",
            "dst_ip": "10.0.0.1",
            "total_fwd_packets": 1500,
            "total_length_of_fwd_packets": 100000,
            "flow_duration": 1.0,
            "flow_packets_s": 1500.0,
            "flow_bytes_s": 100000.0,
            "timestamp": 1000.0
        }
        res = detector.evaluate(telemetry, correlation_id="test-block-1")
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert res.mitigation_recommendation.simulated is True
        assert res.confidence >= 0.85

    def test_non_finite_nan_input_fails_safe(self, detector):
        telemetry = {
            "src_ip": "192.168.1.50",
            "flow_packets_s": float("nan"),
            "total_fwd_packets": float("nan")
        }
        res = detector.evaluate(telemetry, correlation_id="test-nan")
        assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_non_finite_infinity_input_fails_safe(self, detector):
        telemetry = {
            "src_ip": "192.168.1.50",
            "flow_packets_s": float("inf"),
            "flow_bytes_s": 100.0
        }
        res = detector.evaluate(telemetry, correlation_id="test-inf")
        assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_negative_packets_fails_safe(self, detector):
        telemetry = {
            "src_ip": "192.168.1.50",
            "total_fwd_packets": -50,
            "flow_packets_s": -10.0
        }
        res = detector.evaluate(telemetry, correlation_id="test-neg")
        assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_missing_telemetry_fields_fails_safe(self, detector):
        telemetry = {
            "src_ip": "192.168.1.50"
            # Missing packets, bytes, flow_packets_s, flow_bytes_s
        }
        res = detector.evaluate(telemetry, correlation_id="test-missing")
        assert res.status == DetectorStatus.INCOMPLETE
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_multi_window_sliding_accumulation(self, detector):
        # Send 5 burst requests from same IP in short succession
        src = "172.16.0.99"
        base_t = 2000.0
        # Each request has 30 packets. In 0.5 seconds, 5 requests = 150 packets -> burst rate > 100 pps
        for i in range(5):
            tel = {
                "src_ip": src,
                "total_fwd_packets": 30,
                "total_length_of_fwd_packets": 1000,
                "timestamp": base_t + (i * 0.1)
            }
            res = detector.evaluate(tel, correlation_id=f"burst-{i}")

        # The last request should observe accumulated burst
        assert res.decision in (PolicyDecision.DETECTED, PolicyDecision.SIMULATED_BLOCK)
        assert res.evidence.extracted_features["rates"]["burst_pps"] >= 100.0

    def test_bounded_source_table_lru_eviction(self, detector):
        # max_sources is 100
        for i in range(150):
            tel = {
                "src_ip": f"10.0.0.{i}",
                "total_fwd_packets": 1,
                "total_length_of_fwd_packets": 50,
                "timestamp": 3000.0 + i
            }
            detector.evaluate(tel)

        with detector._lock:
            assert len(detector._source_table) <= 100
            # Oldest IPs (0 to 49) should have been evicted
            assert "10.0.0.0" not in detector._source_table
            assert "10.0.0.149" in detector._source_table

    def test_concurrency_thread_safety(self, detector):
        def worker(idx: int):
            for j in range(20):
                tel = {
                    "src_ip": f"192.168.{idx % 10}.{j}",
                    "total_fwd_packets": 5,
                    "total_length_of_fwd_packets": 200,
                    "timestamp": 4000.0 + (j * 0.1)
                }
                res = detector.evaluate(tel)
                assert isinstance(res, DetectorResult)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(worker, i) for i in range(16)]
            for fut in futs:
                fut.result()

    def test_orchestrator_integration(self, detector):
        orchestrator = ModularOrchestrator(max_threads=4)
        orchestrator.register_detector(detector)

        normal_telemetry = {
            "src_ip": "10.1.1.1",
            "total_fwd_packets": 2,
            "total_length_of_fwd_packets": 100,
            "flow_packets_s": 2.0,
            "flow_bytes_s": 100.0
        }
        res = orchestrator.evaluate_shadow(normal_telemetry, force_shadow=True)
        assert res.overall_decision == PolicyDecision.ALLOW
        assert "volumetric_flood_test" in res.detector_results
        assert res.detector_results["volumetric_flood_test"].status == DetectorStatus.HEALTHY

        flood_telemetry = {
            "src_ip": "10.2.2.2",
            "total_fwd_packets": 2000,
            "total_length_of_fwd_packets": 500000,
            "flow_packets_s": 2000.0,
            "flow_bytes_s": 500000.0
        }
        res_flood = orchestrator.evaluate_shadow(flood_telemetry, force_shadow=True)
        assert res_flood.overall_decision == PolicyDecision.SIMULATED_BLOCK
        assert res_flood.simulated_block is True
        assert res_flood.max_threat_confidence >= 0.85
        orchestrator.shutdown()
