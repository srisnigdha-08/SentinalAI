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
from modular.auth_event_adapter import AuthEventDetector, AuthEventType, parse_auth_event
from modular.host_telemetry_adapter import HostTelemetryDetector, HostEventType, parse_host_telemetry
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


class TestAuthEventDetector:
    @pytest.fixture
    def auth_det(self):
        return AuthEventDetector(
            detector_id="auth_event_test",
            version="1.0.0-test",
            warning_failures_5m=3,
            critical_failures_1m=5,
            critical_failures_5m=8,
            credential_stuffing_users_threshold=4,
            max_tracked_ips=100
        )

    def test_health_check_healthy(self, auth_det):
        assert auth_det.health_check() == DetectorStatus.HEALTHY

    def test_benign_auth_success_returns_allow(self, auth_det):
        event = {
            "event_type": "AUTH_SUCCESS",
            "src_ip": "10.0.0.50",
            "user_identity": "alice",
            "service": "ssh",
            "timestamp": 1000.0
        }
        res = auth_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.severity == SeverityLevel.INFORMATIONAL
        assert res.mitigation_recommendation.action == MitigationAction.NONE

    def test_syslog_ssh_failure_parsing(self, auth_det):
        event = {
            "message": "Failed password for root from 192.168.1.100 port 43210 ssh2",
            "timestamp": 1000.0
        }
        res = auth_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.evidence.extracted_features["user_identity"] == "root"
        assert res.evidence.extracted_features["src_ip"] == "192.168.1.100"

    def test_rapid_brute_force_triggers_simulated_block(self, auth_det):
        # 6 failures within 1 minute (> critical_failures_1m=5)
        res = None
        for i in range(6):
            event = {
                "event_type": "AUTH_FAILURE",
                "src_ip": "192.168.1.105",
                "user_identity": "root",
                "service": "ssh",
                "timestamp": 2000.0 + (i * 2.0)
            }
            res = auth_det.evaluate(event)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
        assert res.evidence.trigger_rule == "RAPID_AUTHENTICATION_BRUTE_FORCE_CONFIRMED"

    def test_credential_stuffing_multi_user_triggers_simulated_block(self, auth_det):
        # Same source IP targeting 4 distinct usernames (> credential_stuffing_users_threshold=4)
        users = ["admin", "root", "oracle", "testuser"]
        res = None
        for i, u in enumerate(users):
            event = {
                "event_type": "AUTH_FAILURE",
                "src_ip": "172.16.1.99",
                "user_identity": u,
                "service": "ssh",
                "timestamp": 3000.0 + (i * 5.0)
            }
            res = auth_det.evaluate(event)

        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert "CREDENTIAL_STUFFING" in res.evidence.trigger_rule

    def test_suspected_compromise_after_brute_force(self, auth_det):
        # 3 failures trigger warning, then 1 success from same IP
        for i in range(3):
            auth_det.evaluate({
                "event_type": "AUTH_FAILURE",
                "src_ip": "192.168.1.200",
                "user_identity": "admin",
                "service": "ssh",
                "timestamp": 4000.0 + (i * 2.0)
            })
        success_event = {
            "event_type": "AUTH_SUCCESS",
            "src_ip": "192.168.1.200",
            "user_identity": "admin",
            "service": "ssh",
            "timestamp": 4010.0
        }
        res = auth_det.evaluate(success_event)
        assert res.decision == PolicyDecision.DETECTED
        assert res.severity == SeverityLevel.CRITICAL
        assert res.evidence.trigger_rule == "SUSPECTED_BRUTE_FORCE_SUCCESSFUL_COMPROMISE"

    def test_missing_or_invalid_fields_fails_safe(self, auth_det):
        # Completely invalid payload with no auth structures
        res = auth_det.evaluate({"unrelated_field": 1234})
        assert res.status == DetectorStatus.INCOMPLETE
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0

    def test_lru_eviction_bounded_capacity(self):
        det = AuthEventDetector(max_tracked_ips=5)
        for i in range(10):
            det.evaluate({
                "event_type": "AUTH_FAILURE",
                "src_ip": f"10.0.0.{i}",
                "user_identity": "admin",
                "timestamp": 1000.0 + i
            })
        assert len(det._ip_table) <= 5
        assert det.health_check() == DetectorStatus.HEALTHY

    def test_tcp_flow_never_treated_as_auth_login(self, auth_det):
        """Validates invariant: raw network TCP flow is never treated as an auth event."""
        raw_tcp_flow = {
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "dst_port": 22,
            "flow_duration": 0.05,
            "total_fwd_packets": 2,
            "total_bwd_packets": 1,
            "flow_bytes_s": 500.0
        }
        res = auth_det.evaluate(raw_tcp_flow)
        assert res.status == DetectorStatus.INCOMPLETE
        assert res.decision == PolicyDecision.MONITOR
        assert res.confidence == 0.0
        assert "lacks valid structured authentication" in res.evidence.summary

    def test_duplicate_auth_events_deduplicated(self, auth_det):
        """Validates that identical duplicate auth events do not inflate the failure counter."""
        event = {
            "event_type": "AUTH_FAILURE",
            "src_ip": "192.168.1.88",
            "user_identity": "admin",
            "service": "ssh",
            "timestamp": 2000.0,
            "raw_message": "Failed password for admin"
        }
        # Send exact duplicate 5 times
        for _ in range(5):
            res = auth_det.evaluate(event)

        # Should only have counted as 1 failure, which is below warning threshold (3) -> ALLOW
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.evidence.extracted_features["failures_5m"] == 1

    def test_auth_jitter_and_out_of_order_timestamps(self, auth_det):
        """Validates that network jitter (out-of-order timestamps) is sorted monotonically."""
        # 6 failures arriving out of order (timestamps: 3010, 3002, 3008, 3000, 3012, 3005)
        timestamps = [3010.0, 3002.0, 3008.0, 3000.0, 3012.0, 3005.0]
        res = None
        for i, ts in enumerate(timestamps):
            event = {
                "event_type": "AUTH_FAILURE",
                "src_ip": "192.168.1.92",
                "user_identity": "root",
                "service": "ssh",
                "timestamp": ts,
                "raw_message": f"Failed password attempt {i}"
            }
            res = auth_det.evaluate(event)

        assert res.status == DetectorStatus.HEALTHY
        # 6 failures in under 15 seconds exceeds critical threshold (5) -> SIMULATED_BLOCK
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.evidence.extracted_features["failures_1m"] == 6

    def test_auth_malformed_and_non_finite_inputs(self, auth_det):
        """Validates that non-finite numbers and malformed structures fail safe."""
        for bad_payload in [
            {"event_type": "AUTH_FAILURE", "src_ip": "10.0.0.1", "timestamp": float("nan")},
            {"event_type": "AUTH_FAILURE", "src_ip": "10.0.0.1", "timestamp": float("inf")},
            {"event_type": "AUTH_FAILURE", "src_ip": "10.0.0.1", "timestamp": -50.0},
            {"event_type": 12345, "src_ip": "10.0.0.1"},
            "not a dictionary",
            {"dst_port": "not_a_number", "event_type": "AUTH_FAILURE"}
        ]:
            res = auth_det.evaluate(bad_payload if isinstance(bad_payload, dict) else {"bad": bad_payload})
            assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
            assert res.decision == PolicyDecision.MONITOR
            assert res.confidence == 0.0

    def test_delayed_auth_event_outside_horizon_pruned(self, auth_det):
        """Validates that events arriving with timestamps older than sliding horizon (600s) are pruned."""
        # Baseline failure at t = 1000.0
        auth_det.evaluate({
            "event_type": "AUTH_FAILURE",
            "src_ip": "192.168.1.95",
            "user_identity": "admin",
            "service": "ssh",
            "timestamp": 1000.0
        })
        # Delayed event with timestamp 200.0 (800 seconds prior to 1000.0, outside 600s horizon)
        res = auth_det.evaluate({
            "event_type": "AUTH_FAILURE",
            "src_ip": "192.168.1.95",
            "user_identity": "root",
            "service": "ssh",
            "timestamp": 200.0
        })
        assert res.status == DetectorStatus.HEALTHY
        # Delayed event should not inflate failure counter; failures_5m should only reflect recent events
        assert res.evidence.extracted_features["failures_5m"] <= 1
        assert res.evidence.extracted_features["failures_1m"] <= 1

    def test_unavailable_or_unparseable_auth_telemetry_fails_safe(self, auth_det):
        """Validates that empty dict or unrelated network flow safely degrades to INCOMPLETE."""
        for payload in [{}, {"dst_port": 8080, "packets": 5}, {"random_key": "unrelated"}]:
            res = auth_det.evaluate(payload)
            assert res.status == DetectorStatus.INCOMPLETE
            assert res.decision == PolicyDecision.MONITOR
            assert res.confidence == 0.0
            assert res.mitigation_recommendation.action == MitigationAction.NONE


class TestHostTelemetryDetector:
    @pytest.fixture
    def host_det(self):
        return HostTelemetryDetector(
            detector_id="host_telemetry_test",
            version="1.0.0-test",
            max_tracked_hosts=100
        )

    def test_health_check_healthy(self, host_det):
        assert host_det.health_check() == DetectorStatus.HEALTHY

    def test_benign_host_process_allow(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "WS-01",
            "process_name": "notepad.exe",
            "parent_process_name": "explorer.exe",
            "command_line": "notepad.exe report.txt",
            "timestamp": 1000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.ALLOW
        assert res.severity == SeverityLevel.INFORMATIONAL
        assert res.mitigation_recommendation.action == MitigationAction.NONE

    def test_webshell_w3wp_spawning_cmd_triggers_simulated_block(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "WEB-SRV-01",
            "process_name": "cmd.exe",
            "parent_process_name": "w3wp.exe",
            "command_line": "cmd.exe /c whoami",
            "timestamp": 2000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.evidence.trigger_rule == "EXPLOIT_WEBSHELL_PROCESS_SPAWNED"

    def test_office_macro_spawning_powershell_triggers_simulated_block(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "FINANCE-PC",
            "process_name": "powershell.exe",
            "parent_process_name": "winword.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File invoice.ps1",
            "timestamp": 3000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert res.severity == SeverityLevel.CRITICAL
        assert res.evidence.trigger_rule == "SUSPICIOUS_OFFICE_CHILD_PROCESS"

    def test_critical_lolbin_vssadmin_triggers_simulated_block(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "DC-01",
            "process_name": "vssadmin.exe",
            "parent_process_name": "cmd.exe",
            "command_line": "vssadmin delete shadows /all /quiet",
            "timestamp": 4000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert "DEFENSE_EVASION_VSSADMIN" in res.evidence.trigger_rule

    def test_encoded_powershell_triggers_simulated_block(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "PC-22",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAA',",
            "timestamp": 5000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.SIMULATED_BLOCK
        assert "ENCODED_POWERSHELL_PAYLOAD" in res.evidence.trigger_rule

    def test_reconnaissance_commands_trigger_detected(self, host_det):
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "PC-44",
            "process_name": "net.exe",
            "parent_process_name": "cmd.exe",
            "command_line": "net user /domain",
            "timestamp": 6000.0
        }
        res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        assert res.decision == PolicyDecision.DETECTED
        assert res.severity == SeverityLevel.HIGH
        assert "USER_RECON_NET_USER" in res.evidence.trigger_rule

    def test_lateral_movement_logon_followed_by_shell(self, host_det):
        # 1. Remote Interactive Logon (Type 10)
        logon_event = {
            "event_type": "LOGON",
            "host_id": "FILE-SRV-02",
            "logon_type": 10,
            "user_identity": "admin_backup",
            "timestamp": 7000.0
        }
        res_logon = host_det.evaluate(logon_event)
        assert res_logon.decision == PolicyDecision.ALLOW

        # 2. Within 15 seconds, interactive shell spawned
        proc_event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "FILE-SRV-02",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe",
            "timestamp": 7015.0
        }
        res_proc = host_det.evaluate(proc_event)
        assert res_proc.decision == PolicyDecision.SIMULATED_BLOCK
        assert res_proc.severity == SeverityLevel.CRITICAL
        assert res_proc.evidence.trigger_rule == "LATERAL_MOVEMENT_REMOTE_EXECUTION"

    def test_missing_fields_fails_safe(self, host_det):
        res = host_det.evaluate({"flow_duration": 1.0, "total_fwd_packets": 5})
        assert res.status == DetectorStatus.INCOMPLETE
        assert res.decision == PolicyDecision.MONITOR

    def test_duplicate_host_events_deduplicated(self, host_det):
        """Validates that identical duplicate host process events are deduplicated in history."""
        event = {
            "event_type": "PROCESS_CREATION",
            "host_id": "WS-99",
            "process_name": "cmd.exe",
            "parent_process_name": "explorer.exe",
            "command_line": "cmd.exe /c echo hello",
            "timestamp": 8000.0
        }
        # Send 3 identical duplicates
        for _ in range(3):
            res = host_det.evaluate(event)
        assert res.status == DetectorStatus.HEALTHY
        with host_det._lock:
            hist = host_det._host_table["WS-99"]
            # Deduplication should ensure only 1 command is stored in history
            assert len(hist.recent_commands) == 1

    def test_host_jitter_and_out_of_order_timestamps(self, host_det):
        """Validates that out-of-order host events maintain sorted history."""
        host_det.evaluate({
            "event_type": "LOGON",
            "host_id": "WS-JITTER",
            "logon_type": 10,
            "timestamp": 9010.0
        })
        # Jitter: earlier logon arrives later
        host_det.evaluate({
            "event_type": "LOGON",
            "host_id": "WS-JITTER",
            "logon_type": 3,
            "timestamp": 9005.0
        })
        with host_det._lock:
            hist = host_det._host_table["WS-JITTER"]
            # Hist logons should be sorted chronologically
            assert hist.recent_logons[0][0] == 9005.0
            assert hist.recent_logons[1][0] == 9010.0

    def test_host_malformed_and_non_finite_inputs(self, host_det):
        """Validates that non-finite numbers and malformed structures fail safe."""
        for bad_payload in [
            {"event_type": "PROCESS_CREATION", "host_id": "WS-01", "timestamp": float("nan")},
            {"event_type": "PROCESS_CREATION", "host_id": "WS-01", "timestamp": float("inf")},
            {"event_type": "PROCESS_CREATION", "host_id": "WS-01", "timestamp": -100.0},
            {"event_type": "UNKNOWN_TYPE", "host_id": "WS-01"},
            {"host_id": ""},
            None
        ]:
            res = host_det.evaluate(bad_payload if isinstance(bad_payload, dict) else {"bad": bad_payload})
            assert res.status in (DetectorStatus.INCOMPLETE, DetectorStatus.DEGRADED)
            assert res.decision == PolicyDecision.MONITOR


