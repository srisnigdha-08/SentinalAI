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


class TestDestinationTargetAggregator:
    def test_destination_buffer_unique_sources_and_rates(self):
        from modular.volumetric_flood import DestinationTargetBuffer
        buf = DestinationTargetBuffer(max_history_seconds=60.0)
        # 5 distinct sources arriving at ts=10.0
        for i in range(5):
            buf.add_sample(ts=10.0, packets=10.0, bytes_count=1000.0, src_ip=f"10.0.0.{i}")
        metrics = buf.calculate_metrics(10.0)
        assert metrics["burst_pps"] == 50.0
        assert metrics["unique_sources_10s"] == 5
        assert metrics["unique_sources_60s"] == 5

    def test_destination_buffer_jitter_out_of_order(self):
        from modular.volumetric_flood import DestinationTargetBuffer
        buf = DestinationTargetBuffer(max_history_seconds=60.0)
        buf.add_sample(ts=15.0, packets=10.0, bytes_count=500.0, src_ip="10.0.0.1")
        # Jitter: earlier timestamp arrives later
        buf.add_sample(ts=12.0, packets=10.0, bytes_count=500.0, src_ip="10.0.0.2")
        # Buffer remains sorted
        assert buf.samples[0][0] == 12.0
        assert buf.samples[1][0] == 15.0

    def test_distributed_ddos_multi_source_triggers_simulated_block(self):
        # Sensitive target limits: target_burst_pps=500, target_surge_pps=100, target_unique_sources=10
        det = VolumetricFloodDetector(
            burst_pps_limit=2000.0,
            surge_pps_limit=1000.0,
            target_burst_pps_limit=500.0,
            target_surge_pps_limit=100.0,
            target_unique_sources_limit=10,
            max_destinations=100
        )
        # 15 distinct sources each sending low rate (e.g. 100 packets, duration 0.1s)
        # Per source rate is 100 pps, below per-source burst_pps_limit of 2000.0
        # But aggregate hitting 192.168.1.100:80 is 1500 packets in 1 second!
        res = None
        for i in range(15):
            flow = {
                "src_ip": f"172.16.0.{i}",
                "dst_ip": "192.168.1.100",
                "dst_port": 80,
                "packets": 100,
                "bytes": 50000,
                "timestamp": 100.0 + (i * 0.05)
            }
            res = det.evaluate(flow)

        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.evidence.trigger_rule == "DISTRIBUTED_VOLUMETRIC_FLOOD_ATTACK_DETECTED"
        assert res.evidence.extracted_features["destination_aggregation"]["unique_sources_10s"] >= 10
        assert res.evidence.extracted_features["destination_aggregation"]["target"] == "192.168.1.100:80"

    def test_benign_multi_user_browsing_within_limits_produces_allow(self):
        det = VolumetricFloodDetector(
            target_surge_pps_limit=2000.0,
            target_unique_sources_limit=10
        )
        # 15 distinct sources each sending 1 packet to web server (total 15 pkts)
        res = None
        for i in range(15):
            flow = {
                "src_ip": f"198.51.100.{i}",
                "dst_ip": "192.168.1.100",
                "dst_port": 443,
                "packets": 1,
                "bytes": 100,
                "timestamp": 200.0 + (i * 0.1)
            }
            res = det.evaluate(flow)

        assert res.decision == PolicyDecision.ALLOW
        assert res.severity == SeverityLevel.INFORMATIONAL

    def test_destination_table_lru_eviction(self):
        det = VolumetricFloodDetector(max_destinations=10)
        # Add traffic to 20 distinct destination targets
        for i in range(20):
            flow = {
                "src_ip": "10.0.0.1",
                "dst_ip": f"192.168.2.{i}",
                "dst_port": 80,
                "packets": 5,
                "bytes": 500,
                "timestamp": 500.0 + i
            }
            det.evaluate(flow)

        with det._lock:
            assert len(det._destination_table) <= 10
            # Oldest targets (0 to 9) should have been evicted
            assert "192.168.2.0:80" not in det._destination_table
            assert "192.168.2.19:80" in det._destination_table

    def test_destination_key_missing_or_partial(self):
        det = VolumetricFloodDetector(max_destinations=10)
        # 1. Flow without dst_ip: destination aggregation skipped, normal source evaluation
        flow_no_dst = {
            "src_ip": "10.0.0.5",
            "packets": 10,
            "bytes": 1000,
            "timestamp": 100.0
        }
        res1 = det.evaluate(flow_no_dst)
        assert res1.status == DetectorStatus.HEALTHY
        assert "destination_aggregation" not in res1.evidence.extracted_features

        # 2. Flow with dst_ip but no dst_port: uses dst_ip as target key
        flow_no_port = {
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.10.1",
            "packets": 10,
            "bytes": 1000,
            "timestamp": 101.0
        }
        res2 = det.evaluate(flow_no_port)
        assert res2.status == DetectorStatus.HEALTHY
        assert res2.evidence.extracted_features["destination_aggregation"]["target"] == "192.168.10.1"

        # 3. Flow with out-of-range port: ignores port, uses dst_ip
        flow_bad_port = {
            "src_ip": "10.0.0.5",
            "dst_ip": "192.168.10.2",
            "dst_port": 99999,
            "packets": 10,
            "bytes": 1000,
            "timestamp": 102.0
        }
        res3 = det.evaluate(flow_bad_port)
        assert res3.status == DetectorStatus.HEALTHY
        assert res3.evidence.extracted_features["destination_aggregation"]["target"] == "192.168.10.2"

    def test_late_event_arriving_after_horizon_is_pruned_without_skewing_rates(self):
        """Validates that events arriving >60s prior to buffer horizon are pruned immediately."""
        buf = VolumetricWindowBuffer(max_history_seconds=60.0)
        # Baseline traffic at ts = 100.0
        buf.add_sample(ts=100.0, packets=10.0, bytes_count=1000.0)
        assert len(buf.samples) == 1

        # Late-arriving ancient sample from ts = 20.0 (80s in past relative to 100.0)
        # Even with massive packet count, it should be pruned immediately
        buf.add_sample(ts=20.0, packets=500_000.0, bytes_count=100_000_000.0)
        assert len(buf.samples) == 1
        assert buf.samples[0][0] == 100.0

        rates = buf.calculate_rates(100.0)
        assert rates["burst_pps"] == 10.0
        assert rates["sustained_pps"] == 10.0 / 60.0

    def test_destination_capacity_saturation_bound(self):
        """Validates that destination table is strictly bounded under extreme saturation."""
        det = VolumetricFloodDetector(max_destinations=2000)
        # Ingest traffic to 2500 unique destinations
        for i in range(2500):
            det.evaluate({
                "src_ip": "10.0.0.1",
                "dst_ip": f"172.16.{i // 256}.{i % 256}",
                "dst_port": 80,
                "packets": 1,
                "bytes": 64,
                "timestamp": 1000.0 + (i * 0.01)
            })

        with det._lock:
            assert len(det._destination_table) <= 2000
            assert det.health_check() == DetectorStatus.HEALTHY

    def test_result_semantics_and_mitigation_watermarks(self):
        """Validates that policy decisions strictly align with simulated mitigation watermarks."""
        detector = VolumetricFloodDetector(
            detector_id="volumetric_flood_test",
            version="1.0.0-test",
            burst_pps_limit=100.0,
            surge_pps_limit=50.0,
            sustained_pps_limit=20.0,
            burst_bps_limit=100_000.0,
            instantaneous_pps_limit=200.0,
            instantaneous_bps_limit=200_000.0
        )
        # 1. ALLOW -> NONE
        res_allow = detector.evaluate({
            "src_ip": "192.168.1.5",
            "packets": 1,
            "bytes": 64,
            "flow_duration": 1.0,
            "timestamp": 500.0
        })
        assert res_allow.decision == PolicyDecision.ALLOW
        assert res_allow.mitigation_recommendation.action == MitigationAction.NONE
        assert res_allow.mitigation_recommendation.simulated is True

        # 2. DETECTED -> SIMULATED_RATE_LIMIT
        res_surge = detector.evaluate({
            "src_ip": "192.168.1.6",
            "packets": 120,  # burst limit is 100
            "bytes": 5000,
            "flow_duration": 1.0,
            "flow_packets_s": 120.0,
            "timestamp": 501.0
        })
        assert res_surge.decision == PolicyDecision.DETECTED
        assert res_surge.mitigation_recommendation.action == MitigationAction.SIMULATED_RATE_LIMIT
        assert res_surge.mitigation_recommendation.simulated is True
        assert "[SIMULATED RATE LIMIT" in res_surge.mitigation_recommendation.watermark

        # 3. SIMULATED_BLOCK -> SIMULATED_BLOCK
        res_block = detector.evaluate({
            "src_ip": "192.168.1.7",
            "packets": 500,  # 5x burst limit
            "bytes": 500000,
            "flow_duration": 1.0,
            "flow_packets_s": 500.0,
            "timestamp": 502.0
        })
        assert res_block.decision == PolicyDecision.SIMULATED_BLOCK
        assert res_block.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert res_block.mitigation_recommendation.simulated is True
        assert "[SIMULATED BLOCK" in res_block.mitigation_recommendation.watermark


