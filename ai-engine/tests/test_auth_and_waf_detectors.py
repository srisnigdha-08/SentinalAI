"""
Unit and Integration Tests for E2 Auth-Abuse and E4 Layer 7 WAF Detectors
Validates detection accuracy, fail-safe degradation, zero label leakage, and orchestrator consensus.
"""

import math
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from modular.auth_abuse import AuthAbuseDetector
from modular.layer7_waf import Layer7WAFDetector
from modular.orchestrator import ModularOrchestrator
from modular.contracts import (
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction
)


class TestAuthAbuseDetector:
    @pytest.fixture
    def detector(self):
        return AuthAbuseDetector(
            detector_id="auth_abuse_test",
            version="1.0.0-test",
            warning_attempt_threshold=3.0,
            critical_attempt_threshold=6.0,
            decay_half_life_seconds=10.0
        )

    def test_health_check_healthy(self, detector):
        assert detector.health_check() == DetectorStatus.HEALTHY

    def test_non_auth_port_returns_allow(self, detector):
        tel = {"src_ip": "10.0.0.5", "dst_port": 80, "flow_duration": 0.5}
        res = detector.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.mitigation_recommendation.action == MitigationAction.NONE

    def test_single_ssh_attempt_returns_allow(self, detector):
        tel = {"src_ip": "192.168.1.10", "dst_port": 22, "flow_duration": 0.2, "timestamp": 1000.0}
        res = detector.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.confidence <= 0.30

    def test_repeated_ssh_attempts_trigger_surge_warning(self, detector):
        src = "192.168.1.100"
        # 4 rapid attempts exceed warning threshold (3.0)
        for i in range(4):
            tel = {"src_ip": src, "dst_port": 22, "timestamp": 2000.0 + (i * 0.5)}
            res = detector.evaluate(tel)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.DETECTED
        assert res.severity == SeverityLevel.HIGH
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_RATE_LIMIT

    def test_heavy_ssh_flood_triggers_simulated_block(self, detector):
        src = "192.168.1.200"
        # 8 rapid attempts exceed critical threshold (6.0)
        for i in range(8):
            tel = {"src_ip": src, "dst_port": 22, "timestamp": 3000.0 + (i * 0.2)}
            res = detector.evaluate(tel)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert res.confidence >= 0.85

    def test_invalid_telemetry_fails_safe(self, detector):
        tel = {"src_ip": "10.0.0.1", "dst_port": -1}
        res = detector.evaluate(tel)
        assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0


class TestLayer7WAFDetector:
    @pytest.fixture
    def waf(self):
        return Layer7WAFDetector(detector_id="layer7_waf_test", version="1.0.0-test")

    def test_health_check_healthy(self, waf):
        assert waf.health_check() == DetectorStatus.HEALTHY

    def test_benign_http_request_returns_allow(self, waf):
        tel = {
            "http_uri": "/products/catalog?category=electronics&page=2",
            "http_headers": "Host: example.com\r\nUser-Agent: Mozilla/5.0\r\n",
            "http_body": "{\"item\": 1234, \"quantity\": 1}"
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.confidence <= 0.10
        assert res.mitigation_recommendation.action == MitigationAction.NONE

    def test_sqli_attack_blocked(self, waf):
        tel = {
            "http_uri": "/login?user=admin' UNION SELECT null, username, password FROM users--",
            "http_headers": "Host: target.local\r\n"
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.confidence >= 0.85
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert "SQL_INJECTION" in res.evidence.trigger_rule

    def test_xss_attack_blocked(self, waf):
        tel = {
            "http_body": "<script>alert(document.cookie)</script>",
            "http_uri": "/comment/submit"
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert "CROSS_SITE_SCRIPTING" in res.evidence.trigger_rule

    def test_path_traversal_url_encoded_blocked(self, waf):
        tel = {
            "http_uri": "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert "PATH_TRAVERSAL" in res.evidence.trigger_rule

    def test_http_port_without_l7_buffers_degrades_safely(self, waf):
        # Transport-only netflow targeting port 80 without HTTP string fields
        tel = {
            "dst_port": 80,
            "flow_duration": 1.5,
            "total_fwd_packets": 10
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.INCOMPLETE
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_non_http_flow_returns_unsupported(self, waf):
        tel = {
            "dst_port": 53,
            "flow_duration": 0.01,
            "total_fwd_packets": 1
        }
        res = waf.evaluate(tel)
        assert res.status == DetectorStatus.UNSUPPORTED
        assert res.decision == PolicyDecision.MONITOR


class TestMultiDetectorOrchestratorIntegration:
    def test_multi_tier_consensus(self):
        orchestrator = ModularOrchestrator(max_threads=4)
        auth_det = AuthAbuseDetector(
            detector_id="auth_abuse",
            warning_attempt_threshold=2.0,
            critical_attempt_threshold=4.0
        )
        waf_det = Layer7WAFDetector(detector_id="layer7_waf")
        orchestrator.register_detector(auth_det)
        orchestrator.register_detector(waf_det)

        # 1. Clean request targeting web app
        clean_req = {
            "src_ip": "192.168.1.5",
            "dst_port": 80,
            "http_uri": "/index.html",
            "http_body": "hello world"
        }
        res = orchestrator.evaluate_shadow(clean_req, force_shadow=True)
        # auth_det returns ALLOW (port 80 is not auth), waf_det returns ALLOW
        assert res.overall_decision == PolicyDecision.ALLOW
        assert not res.simulated_block

        # 2. Web Attack request
        sqli_req = {
            "src_ip": "192.168.1.5",
            "dst_port": 80,
            "http_uri": "/users?id=1' OR '1'='1"
        }
        res_sqli = orchestrator.evaluate_shadow(sqli_req, force_shadow=True)
        assert res_sqli.overall_decision == PolicyDecision.SIMULATED_BLOCK
        assert res_sqli.simulated_block is True
        assert res_sqli.max_threat_confidence >= 0.85

        orchestrator.shutdown()
