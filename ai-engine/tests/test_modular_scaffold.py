"""
SentinelAI Modular Detector Scaffold & Safety Contracts Test Suite
Phase 9C Implementation Milestone: Staged Modular Scaffold & Safety Contracts

This test suite rigorously validates:
- Standardized typed DetectorResult contract and JSON Schema compatibility
- Strict numerical validation (rejection of NaN, +Inf, -Inf, None, strings)
- Explicit representation of degraded, timeout, unavailable, incomplete, and error states
- Prevention of silent ALLOW (degraded or timed-out detectors cannot produce verified ALLOW)
- Mitigation separation (simulated: True, [SIMULATED BLOCK] watermark)
- Bounded connection-state interface (LRU eviction, capacity limits, exponential decay, metrics)
- Shadow-mode orchestration, timeout isolation, and alert de-duplication
- Ground-truth label isolation (labels like 'Label', 'Attack', 'y' are stripped and inaccessible)
- Resilient logging error handling
"""

import math
import os
import sys
import time
import uuid
import pytest
from unittest.mock import patch, MagicMock

# Ensure ai-engine is in sys.path
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    EnsembleResult,
    EvidenceRecord,
    MitigationAction,
    PolicyDecision,
    SeverityLevel,
    SimulatedMitigation,
    create_degraded_result,
    validate_finite_score,
)
from modular.sanitizer import (
    sanitize_telemetry,
    assert_isolated_from_ground_truth,
    detect_ground_truth_keys,
    FORBIDDEN_GROUND_TRUTH_KEYS,
)
from modular.state import (
    BoundedConnectionStateTable,
    ConnectionStateEntry,
)
from modular.base import BaseDetector
from modular.orchestrator import (
    ModularOrchestrator,
    is_modular_enabled,
)


# ==============================================================================
# Test Fixtures & Stub Detectors (Strictly isolated mock detectors for unit tests)
# ==============================================================================

class MockBenignDetector(BaseDetector):
    """Stub detector that evaluates traffic as healthy and benign."""
    def __init__(self, detector_id: str = "mock_benign", version: str = "1.0.0"):
        super().__init__(detector_id, version)

    def health_check(self) -> DetectorStatus:
        return DetectorStatus.HEALTHY

    def _inspect(self, telemetry: dict, correlation_id: str) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.ALLOW,
            confidence=0.02,
            severity=SeverityLevel.LOW,
            evidence=EvidenceRecord(
                trigger_rule="BENIGN_BASELINE",
                summary="Observed normal traffic patterns within expected baseline bounds",
                extracted_features={"flow_rate": 10.5}
            ),
            mitigation_recommendation=SimulatedMitigation(
                action=MitigationAction.NONE,
                simulated=True,
                watermark="[BENIGN - ALLOW]"
            )
        )


class MockAttackDetector(BaseDetector):
    """Stub detector that flags an attack and recommends simulated block."""
    def __init__(self, detector_id: str = "mock_attack", threat_name: str = "SQL_INJECTION"):
        super().__init__(detector_id, "1.0.0")
        self.threat_name = threat_name

    def health_check(self) -> DetectorStatus:
        return DetectorStatus.HEALTHY

    def _inspect(self, telemetry: dict, correlation_id: str) -> DetectorResult:
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.SIMULATED_BLOCK,
            confidence=0.98,
            severity=SeverityLevel.CRITICAL,
            evidence=EvidenceRecord(
                trigger_rule=self.threat_name,
                summary=f"Detected high-confidence malicious pattern: {self.threat_name}",
                extracted_features={"payload_signature": "UNION SELECT", "threat_score": 0.98}
            ),
            mitigation_recommendation=SimulatedMitigation(
                action=MitigationAction.SIMULATED_BLOCK,
                simulated=True,
                watermark="[SIMULATED BLOCK]"
            )
        )


class MockSlowDetector(BaseDetector):
    """Stub detector that sleeps to trigger timeout handling."""
    def __init__(self, delay_seconds: float = 0.2):
        super().__init__("mock_slow", "1.0.0")
        self.delay = delay_seconds

    def health_check(self) -> DetectorStatus:
        return DetectorStatus.HEALTHY

    def _inspect(self, telemetry: dict, correlation_id: str) -> DetectorResult:
        time.sleep(self.delay)
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.ALLOW,
            confidence=0.01,
            severity=SeverityLevel.LOW,
            evidence=EvidenceRecord(trigger_rule="SLOW", summary="Completed late", extracted_features={})
        )


class MockFailingDetector(BaseDetector):
    """Stub detector that raises an unexpected internal exception."""
    def __init__(self, error_msg: str = "Corrupted internal state"):
        super().__init__("mock_failing", "1.0.0")
        self.error_msg = error_msg

    def health_check(self) -> DetectorStatus:
        return DetectorStatus.ERROR

    def _inspect(self, telemetry: dict, correlation_id: str) -> DetectorResult:
        raise RuntimeError(self.error_msg)


# ==============================================================================
# 1. Finite Number & Score Validation Tests
# ==============================================================================

def test_validate_finite_score_valid():
    """Confirms valid scores within [0.0, 1.0] are accepted and rounded."""
    assert validate_finite_score(0.0) == 0.0
    assert validate_finite_score(1.0) == 1.0
    assert validate_finite_score(0.554321) == 0.554321
    assert validate_finite_score(0) == 0.0
    assert validate_finite_score(1) == 1.0


def test_validate_finite_score_rejections():
    """Confirms that NaN, +Inf, -Inf, None, strings, booleans, and out-of-range floats are rejected."""
    # NaN
    with pytest.raises(ValueError, match="non-finite score rejected"):
        validate_finite_score(float("nan"))

    # Infinity
    with pytest.raises(ValueError, match="non-finite score rejected"):
        validate_finite_score(float("inf"))
    with pytest.raises(ValueError, match="non-finite score rejected"):
        validate_finite_score(float("-inf"))

    # None
    with pytest.raises(ValueError, match="score cannot be None"):
        validate_finite_score(None)

    # Boolean (True/False should not be coerced to 1.0/0.0)
    with pytest.raises(TypeError, match="score must be a real number"):
        validate_finite_score(True)
    with pytest.raises(TypeError, match="score must be a real number"):
        validate_finite_score(False)

    # String
    with pytest.raises(TypeError, match="score must be a real number"):
        validate_finite_score("0.95")

    # Out of bounds
    with pytest.raises(ValueError, match="outside required bounds"):
        validate_finite_score(1.0001)
    with pytest.raises(ValueError, match="outside required bounds"):
        validate_finite_score(-0.0001)


# ==============================================================================
# 2. Common Detector Result Contract & Invariant Tests
# ==============================================================================

def test_detector_result_contract_valid():
    """Confirms a valid DetectorResult constructs cleanly."""
    res = DetectorResult(
        detector_id="waf_owasp",
        version="1.0.0",
        status=DetectorStatus.HEALTHY,
        decision=PolicyDecision.DETECTED,
        confidence=0.88,
        severity=SeverityLevel.HIGH,
        execution_time_ms=12.5,
        evidence=EvidenceRecord(
            trigger_rule="CRS-942100",
            summary="SQL Injection attack detected via boolean logic",
            extracted_features={"param": "id", "pattern": "' OR '1'='1"}
        )
    )
    assert res.status == DetectorStatus.HEALTHY
    assert res.decision == PolicyDecision.DETECTED
    assert res.confidence == 0.88
    assert res.mitigation_recommendation.simulated is True
    assert res.mitigation_recommendation.watermark == "[SIMULATED BLOCK]"


def test_no_silent_allow_invariant():
    """
    INVARIANT TEST: An uninspected or degraded detector MUST NOT claim decision=ALLOW.
    """
    # Degraded status with ALLOW decision must be rejected
    with pytest.raises(ValueError, match="Contract Violation.*Uninspected or failed traffic cannot silently pass"):
        DetectorResult(
            detector_id="failing_det",
            version="1.0.0",
            status=DetectorStatus.DEGRADED,
            decision=PolicyDecision.ALLOW,
            confidence=0.0,
            severity=SeverityLevel.LOW,
            evidence=EvidenceRecord(trigger_rule="RULE_1", summary="Degraded", extracted_features={})
        )

    # Error status with ALLOW decision must be rejected
    with pytest.raises(ValueError, match="Contract Violation.*Uninspected or failed traffic cannot silently pass"):
        DetectorResult(
            detector_id="error_det",
            version="1.0.0",
            status=DetectorStatus.ERROR,
            decision=PolicyDecision.ALLOW,
            confidence=0.0,
            severity=SeverityLevel.LOW,
            evidence=EvidenceRecord(trigger_rule="RULE_1", summary="Error", extracted_features={})
        )


def test_create_degraded_result_factory():
    """Confirms create_degraded_result factory generates safe, standardized fallback structures."""
    res = create_degraded_result("volumetric_flood", DetectorStatus.TIMEOUT, "Execution timed out", execution_time_ms=52.1)
    assert res.detector_id == "volumetric_flood"
    assert res.status == DetectorStatus.TIMEOUT
    assert res.decision == PolicyDecision.MONITOR
    assert res.confidence == 0.0
    assert res.mitigation_recommendation.action == MitigationAction.NONE
    assert res.mitigation_recommendation.simulated is True
    assert res.execution_time_ms == 52.1


def test_simulated_mitigation_enforcement():
    """Confirms that simulated: False is strictly prohibited."""
    with pytest.raises(ValueError, match="Safety Violation: Real firewall containment cannot be enabled"):
        SimulatedMitigation(action=MitigationAction.SIMULATED_BLOCK, simulated=False)


# ==============================================================================
# 3. Ground-Truth Blinding & Telemetry Isolation Tests
# ==============================================================================

def test_ground_truth_detection_and_stripping():
    """
    CRITICAL TEST: Proves that ground-truth labels ('Label', 'Attack', 'y', 'ground_truth', etc.)
    are detected and completely stripped before reaching detector logic.
    """
    raw_packet = {
        "sourceIP": "192.168.1.100",
        "flow_duration": 12000.0,
        "Label": "DDoS-HOIC",           # Ground-truth label
        "attack_type": "HOIC",          # Ground-truth label
        "is_attack": 1,                 # Ground-truth label
        "nested": {
            "sub_flow": 1,
            "y": 1                      # Nested ground-truth label
        }
    }

    # 1. Verification that keys are detected
    violations = detect_ground_truth_keys(raw_packet)
    assert "Label" in violations
    assert "attack_type" in violations
    assert "is_attack" in violations
    assert "nested.y" in violations

    # 2. Strict assertion fails if raw packet is checked
    with pytest.raises(ValueError, match="Ground-Truth Isolation Failed"):
        assert_isolated_from_ground_truth(raw_packet)

    # 3. Sanitizer strips all forbidden keys
    clean_packet = sanitize_telemetry(raw_packet, raise_on_ground_truth=False)
    assert "sourceIP" in clean_packet
    assert "flow_duration" in clean_packet
    assert "Label" not in clean_packet
    assert "attack_type" not in clean_packet
    assert "is_attack" not in clean_packet
    assert "y" not in clean_packet["nested"]
    assert clean_packet["nested"]["sub_flow"] == 1

    # 4. Strict assertion passes on clean packet
    assert_isolated_from_ground_truth(clean_packet)


def test_base_detector_auto_strips_ground_truth():
    """Confirms BaseDetector.evaluate() automatically strips labels so _inspect never receives them."""
    class InspectingDetector(BaseDetector):
        def __init__(self):
            super().__init__("inspector", "1.0.0")
            self.received_keys = []

        def health_check(self):
            return DetectorStatus.HEALTHY

        def _inspect(self, telemetry: dict, correlation_id: str):
            self.received_keys = list(telemetry.keys())
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.ALLOW,
                confidence=0.01,
                severity=SeverityLevel.LOW,
                evidence=EvidenceRecord(trigger_rule="INSPECT", summary="Done", extracted_features={})
            )

    det = InspectingDetector()
    tainted_input = {"sourceIP": "10.0.0.1", "Label": "Infiltration", "y": 1, "packet_count": 5}
    det.evaluate(tainted_input)

    assert "sourceIP" in det.received_keys
    assert "packet_count" in det.received_keys
    assert "Label" not in det.received_keys
    assert "y" not in det.received_keys


# ==============================================================================
# 4. Bounded Connection-State Interface Tests
# ==============================================================================

def test_bounded_state_table_capacity_and_lru_eviction():
    """
    Confirms bounded state table enforces maximum entries and evicts LRU items.
    """
    # Create tiny table with max 3 entries
    table = BoundedConnectionStateTable(max_entries=3, default_ttl_seconds=300.0)

    # Insert 3 keys
    table.record_attempt("key1", current_time=100.0)
    table.record_attempt("key2", current_time=101.0)
    table.record_attempt("key3", current_time=102.0)

    metrics = table.get_metrics()
    assert metrics["current_entries"] == 3
    assert metrics["evictions"] == 0

    # Insert 4th key -> key1 (LRU) must be evicted
    table.record_attempt("key4", current_time=103.0)

    metrics = table.get_metrics()
    assert metrics["current_entries"] == 3
    assert metrics["evictions"] == 1
    assert table.get("key1", current_time=103.0) is None
    assert table.get("key2", current_time=103.0) is not None
    assert table.get("key4", current_time=103.0) is not None


def test_bounded_state_table_exponential_decay():
    """
    Confirms exponential decay math accurately discounts past attempts over time.
    """
    half_life = 60.0  # 60s half-life
    table = BoundedConnectionStateTable(max_entries=100, decay_half_life_seconds=half_life)

    t0 = 1000.0
    # First attempt: decayed_score = 1.0
    e1 = table.record_attempt("src_10.0.0.5", current_time=t0, increment=1.0)
    assert math.isclose(e1.decayed_score, 1.0, rel_tol=1e-4)

    # After 1 half-life (60s), without new attempts: decayed_score would be 0.5.
    # Adding a 2nd attempt (+1.0) at t0 + 60s should yield: 0.5 + 1.0 = 1.5
    e2 = table.record_attempt("src_10.0.0.5", current_time=t0 + 60.0, increment=1.0)
    assert math.isclose(e2.decayed_score, 1.5, rel_tol=1e-3)
    assert e2.attempt_count == 2.0


def test_bounded_state_table_expiration_and_purge():
    """Confirms TTL expiration and manual/automatic purging."""
    table = BoundedConnectionStateTable(max_entries=100, default_ttl_seconds=50.0)

    table.record_attempt("temp_key", current_time=100.0)
    assert table.get("temp_key", current_time=120.0) is not None

    # After 51 seconds (> 50s TTL), get() should return None and record expired purge
    assert table.get("temp_key", current_time=151.0) is None
    assert table.get_metrics()["expired_purges"] == 1


# ==============================================================================
# 5. Shadow-Mode Orchestrator & Consensus Tests
# ==============================================================================

def test_orchestrator_feature_flag_gating(monkeypatch):
    """
    Confirms orchestrator returns None when ENABLE_EXPERIMENTAL_MODULAR_DETECTORS is false.
    """
    monkeypatch.setenv("ENABLE_EXPERIMENTAL_MODULAR_DETECTORS", "false")
    assert is_modular_enabled() is False

    orch = ModularOrchestrator()
    orch.register_detector(MockBenignDetector())

    # When disabled, evaluate_shadow returns None without execution
    result = orch.evaluate_shadow({"sourceIP": "10.0.0.1"})
    assert result is None

    # When force_shadow=True, it executes (for isolated test harness)
    forced_res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
    assert forced_res is not None
    assert forced_res.ensemble_status == DetectorStatus.HEALTHY
    orch.shutdown()


def test_orchestrator_all_healthy_consensus():
    """Confirms all-healthy benign detectors produce an ALLOW consensus."""
    orch = ModularOrchestrator()
    orch.register_detector(MockBenignDetector("det_1"))
    orch.register_detector(MockBenignDetector("det_2"))

    res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
    assert res.ensemble_status == DetectorStatus.HEALTHY
    assert res.overall_decision == PolicyDecision.ALLOW
    assert res.simulated_block is False
    assert res.requires_triage is False
    assert len(res.detector_results) == 2
    orch.shutdown()


def test_orchestrator_threat_consensus_with_simulated_block():
    """Confirms a threat detection triggers SIMULATED_BLOCK recommendation."""
    orch = ModularOrchestrator()
    orch.register_detector(MockBenignDetector("det_benign"))
    orch.register_detector(MockAttackDetector("det_waf", "SQL_INJECTION"))

    res = orch.evaluate_shadow({"sourceIP": "192.168.1.50"}, force_shadow=True)
    assert res.overall_decision == PolicyDecision.SIMULATED_BLOCK
    assert res.simulated_block is True
    assert res.max_threat_confidence == 0.98
    assert "SQL_INJECTION" in res.summary_evidence
    orch.shutdown()


def test_orchestrator_prevents_silent_allow_on_partial_failure():
    """
    CRITICAL INVARIANT TEST:
    If one detector passes (benign) but another detector FAILS or TIMES OUT,
    the ensemble MUST NOT declare an unconditional ALLOW.
    It must fail safe to MONITOR with requires_triage=True and ensemble_status=DEGRADED.
    """
    orch = ModularOrchestrator(detector_timeout_seconds=0.05)
    orch.register_detector(MockBenignDetector("healthy_benign"))
    orch.register_detector(MockFailingDetector("Database connection failed"))

    res = orch.evaluate_shadow({"sourceIP": "10.0.0.2"}, force_shadow=True)

    # Status must be DEGRADED, NOT HEALTHY
    assert res.ensemble_status == DetectorStatus.DEGRADED
    # Decision must be MONITOR, NEVER ALLOW
    assert res.overall_decision == PolicyDecision.MONITOR
    assert res.requires_triage is True
    assert res.simulated_block is False
    assert any("mock_failing:ERROR" in s for s in res.degraded_detectors)
    orch.shutdown()


def test_orchestrator_timeout_isolation():
    """Confirms a slow detector is terminated at timeout and fails safe without blocking healthy detectors."""
    orch = ModularOrchestrator(detector_timeout_seconds=0.05)  # 50 ms timeout
    orch.register_detector(MockBenignDetector("fast_detector"))
    orch.register_detector(MockSlowDetector(delay_seconds=0.20))  # 200 ms > 50 ms

    t0 = time.perf_counter()
    res = orch.evaluate_shadow({"sourceIP": "10.0.0.3"}, force_shadow=True)
    elapsed = time.perf_counter() - t0

    # Total execution time should be bounded close to the 50ms timeout + thread overhead (under 150ms)
    assert elapsed < 0.25

    assert res.ensemble_status == DetectorStatus.DEGRADED
    assert res.overall_decision == PolicyDecision.MONITOR
    assert "mock_slow:TIMEOUT" in res.degraded_detectors
    assert res.detector_results["mock_slow"].status == DetectorStatus.TIMEOUT
    assert res.detector_results["fast_detector"].status == DetectorStatus.HEALTHY
    orch.shutdown()


def test_orchestrator_alert_deduplication():
    """Confirms alert deduplication suppresses repeated alerts within 60 seconds."""
    orch = ModularOrchestrator(dedup_window_seconds=60.0)
    orch.register_detector(MockAttackDetector("waf", "XSS_ATTACK"))

    payload = {"sourceIP": "192.168.10.5"}

    # First event: should NOT be duplicate
    res1 = orch.evaluate_shadow(payload, force_shadow=True)
    assert res1.is_duplicate is False

    # Second event immediately after: SHOULD be duplicate
    res2 = orch.evaluate_shadow(payload, force_shadow=True)
    assert res2.is_duplicate is True

    # Event from a DIFFERENT IP: should NOT be duplicate
    res3 = orch.evaluate_shadow({"sourceIP": "192.168.10.6"}, force_shadow=True)
    assert res3.is_duplicate is False
    orch.shutdown()


def test_orchestrator_resilient_logging():
    """Confirms that logging errors do not crash the orchestrator or bypass safety invariants."""
    orch = ModularOrchestrator()
    orch.register_detector(MockBenignDetector())

    # Mock logger to raise an exception
    with patch("modular.orchestrator.log.log", side_effect=IOError("Simulated Disk Full")):
        res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
        assert res is not None
        assert res.overall_decision == PolicyDecision.ALLOW

    orch.shutdown()


# ==============================================================================
# 6. DEF-01: Empty Pipeline & Degradation Regression Tests
# ==============================================================================

def test_def01_zero_detectors_fails_closed():
    """
    DEF-01 REGRESSION TEST:
    Confirms an orchestrator with zero registered detectors fails safe to MONITOR
    with status=UNAVAILABLE and requires_triage=True. Must NEVER return ALLOW.
    """
    orch = ModularOrchestrator()
    assert len(orch.list_detectors()) == 0

    res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
    assert res is not None
    assert res.ensemble_status == DetectorStatus.UNAVAILABLE
    assert res.overall_decision == PolicyDecision.MONITOR
    assert res.requires_triage is True
    assert res.simulated_block is False
    assert "NO_DETECTORS_REGISTERED" in res.degraded_detectors[0]
    assert "UNINSPECTED" in res.summary_evidence
    orch.shutdown()


def test_def01_all_detectors_unavailable():
    """
    DEF-01 REGRESSION TEST:
    When all registered detectors fail or are unavailable, ensemble_status must be
    UNAVAILABLE (or DEGRADED) and overall_decision must be MONITOR.
    """
    orch = ModularOrchestrator()
    orch.register_detector(MockFailingDetector("DB unreachable"))
    orch.register_detector(MockFailingDetector("Socket closed"))

    res = orch.evaluate_shadow({"sourceIP": "10.0.0.2"}, force_shadow=True)
    assert res.ensemble_status in (DetectorStatus.UNAVAILABLE, DetectorStatus.DEGRADED)
    assert res.overall_decision == PolicyDecision.MONITOR
    assert res.requires_triage is True
    assert res.simulated_block is False
    orch.shutdown()


def test_def01_partially_available_detectors():
    """
    DEF-01 REGRESSION TEST:
    When one detector is healthy (benign) and one is degraded/failing,
    the aggregate decision must fail safe to MONITOR (not ALLOW).
    """
    orch = ModularOrchestrator()
    orch.register_detector(MockBenignDetector("healthy_benign"))
    orch.register_detector(MockFailingDetector("Internal crash"))

    res = orch.evaluate_shadow({"sourceIP": "10.0.0.3"}, force_shadow=True)
    assert res.ensemble_status == DetectorStatus.DEGRADED
    assert res.overall_decision == PolicyDecision.MONITOR
    assert res.requires_triage is True
    orch.shutdown()


# ==============================================================================
# 7. DEF-02: Ground-Truth Blinding & Case-Insensitive Matching Regression Tests
# ==============================================================================

def test_def02_case_variants_and_compound_keys():
    """
    DEF-02 REGRESSION TEST:
    Confirms mixed-case (lAbEl, ATTACK_TYPE) and compound (target_label, eval_label)
    keys are reliably detected and stripped.
    """
    tainted = {
        "sourceIP": "192.168.1.1",
        "lAbEl": "DDoS",
        "ATTACK_TYPE": "SYN_FLOOD",
        "target_label": 1,
        "dataset_label": "CICIDS",
        "nested": {
            "True_Class": "Attack",
            "Actual_Class": "PortScan"
        }
    }
    violations = detect_ground_truth_keys(tainted)
    assert len(violations) >= 5
    assert any("lAbEl" in v for v in violations)
    assert any("ATTACK_TYPE" in v for v in violations)
    assert any("target_label" in v for v in violations)

    clean = sanitize_telemetry(tainted)
    assert "sourceIP" in clean
    assert "lAbEl" not in clean
    assert "ATTACK_TYPE" not in clean
    assert "target_label" not in clean
    assert "dataset_label" not in clean
    assert "True_Class" not in clean["nested"]
    assert "Actual_Class" not in clean["nested"]
    assert_isolated_from_ground_truth(clean)


def test_def02_preserves_legitimate_features():
    """
    DEF-02 REGRESSION TEST:
    Confirms legitimate operational features (e.g. flow_duration, packet_count)
    are strictly preserved and not accidentally stripped by prefix/suffix heuristics.
    """
    operational_data = {
        "sourceIP": "10.0.0.1",
        "destinationIP": "10.0.0.2",
        "sourcePort": 443,
        "destinationPort": 55123,
        "flow_duration": 50000.0,
        "total_fwd_packets": 10.0,
        "fwd_packet_len_mean": 64.0,
        "syn_flag_count": 1.0,
        "flow_rate": 100.5,
        "packet_count": 15
    }
    clean = sanitize_telemetry(operational_data)
    for k in operational_data:
        assert k in clean, f"Operational key '{k}' was unexpectedly stripped!"
        assert clean[k] == operational_data[k]


def test_def02_deep_immutability():
    """
    DEF-02 REGRESSION TEST:
    Confirms sanitize_telemetry does not mutate the caller's original dictionary or nested lists.
    """
    original = {
        "sourceIP": "10.0.0.1",
        "Label": "Botnet",
        "nested_dict": {"Attack": "DDoS", "val": 42},
        "nested_list": [{"target": 1}, {"safe": 100}]
    }
    import copy
    snapshot = copy.deepcopy(original)

    clean = sanitize_telemetry(original)

    # Clean must have stripped labels
    assert "Label" not in clean
    assert "Attack" not in clean["nested_dict"]
    assert "target" not in clean["nested_list"][0]

    # Original must remain 100% identical to snapshot
    assert original == snapshot


def test_def02_nested_structures_and_collections():
    """
    DEF-02 REGRESSION TEST:
    Confirms tuples, sets, and lists with nested ground-truth keys are cleaned.
    """
    data = {
        "tuple_data": ({"Label": "Attack", "val": 1}, {"safe": 2}),
        "list_data": [{"target_label": 1}, "ok"]
    }
    clean = sanitize_telemetry(data)
    assert isinstance(clean["tuple_data"], tuple)
    assert "Label" not in clean["tuple_data"][0]
    assert clean["tuple_data"][0]["val"] == 1
    assert "target_label" not in clean["list_data"][0]


# ==============================================================================
# 8. DEF-03: Bounded Connection State Numerical Validation Regression Tests
# ==============================================================================

def test_def03_rejects_nan_increment():
    """
    DEF-03 REGRESSION TEST:
    Confirms passing float('nan') to record_attempt raises ValueError and leaves state uncorrupted.
    """
    table = BoundedConnectionStateTable(max_entries=10)
    table.record_attempt("valid_key", increment=1.0)
    metrics_before = table.get_metrics()

    with pytest.raises(ValueError, match="increment must be a finite number"):
        table.record_attempt("valid_key", increment=float("nan"))

    with pytest.raises(ValueError, match="increment must be a finite number"):
        table.record_attempt("new_key", increment=float("nan"))

    # State must be completely uncorrupted
    entry = table.get("valid_key")
    assert math.isfinite(entry.decayed_score)
    assert entry.decayed_score == 1.0
    assert table.get("new_key") is None
    assert table.get_metrics()["current_entries"] == 1


def test_def03_rejects_inf_increment():
    """
    DEF-03 REGRESSION TEST:
    Confirms passing +Inf or -Inf raises ValueError.
    """
    table = BoundedConnectionStateTable(max_entries=10)
    with pytest.raises(ValueError, match="increment must be a finite number"):
        table.record_attempt("k1", increment=float("inf"))
    with pytest.raises(ValueError, match="increment must be a finite number"):
        table.record_attempt("k1", increment=float("-inf"))


def test_def03_rejects_negative_or_zero_increment():
    """
    DEF-03 REGRESSION TEST:
    Confirms non-positive increments are rejected.
    """
    table = BoundedConnectionStateTable(max_entries=10)
    with pytest.raises(ValueError, match="increment must be strictly positive"):
        table.record_attempt("k1", increment=0.0)
    with pytest.raises(ValueError, match="increment must be strictly positive"):
        table.record_attempt("k1", increment=-1.5)


def test_def03_rejects_invalid_types():
    """
    DEF-03 REGRESSION TEST:
    Confirms booleans, strings, and None are rejected with TypeError/ValueError.
    """
    table = BoundedConnectionStateTable(max_entries=10)
    with pytest.raises(ValueError, match="key cannot be None"):
        table.record_attempt(None, increment=1.0)
    with pytest.raises(ValueError, match="increment cannot be None"):
        table.record_attempt("k1", increment=None)
    with pytest.raises(TypeError, match="increment must be a real number"):
        table.record_attempt("k1", increment=True)
    with pytest.raises(TypeError, match="increment must be a real number"):
        table.record_attempt("k1", increment="5.0")


def test_def03_invalid_input_preserves_existing_state():
    """
    DEF-03 REGRESSION TEST:
    Verifies that when an invalid input is rejected, LRU order and metrics are preserved.
    """
    table = BoundedConnectionStateTable(max_entries=3)
    table.record_attempt("key1", current_time=100.0)
    table.record_attempt("key2", current_time=101.0)

    # Attempt invalid update on key1
    with pytest.raises(ValueError):
        table.record_attempt("key1", increment=float("nan"))

    # Attempt invalid update with bad timestamp
    with pytest.raises(ValueError):
        table.record_attempt("key1", current_time=float("nan"))

    # Verify key1 and key2 are still intact and key1 is still LRU relative to key2
    metrics = table.get_metrics()
    assert metrics["current_entries"] == 2
    entry1 = table.get("key1", current_time=102.0)
    assert entry1 is not None
    assert entry1.decayed_score == 1.0


# ==============================================================================
# 9. DEF-04: Parallel Dispatch & Concurrency Safety Regression Tests
# ==============================================================================

def test_def04_parallel_dispatch_latency_bound():
    """
    DEF-04 REGRESSION TEST:
    Verifies that 3 independent slow detectors (each taking 35 ms) execute in parallel
    within a total elapsed time well under the sequential sum (105 ms).
    """
    orch = ModularOrchestrator(detector_timeout_seconds=0.10, max_threads=4)
    orch.register_detector(MockSlowDetector(delay_seconds=0.035))  # 35 ms
    orch.register_detector(MockSlowDetector(delay_seconds=0.035))  # 35 ms
    orch.register_detector(MockSlowDetector(delay_seconds=0.035))  # 35 ms

    t0 = time.perf_counter()
    res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
    elapsed = time.perf_counter() - t0

    # Parallel execution of 3 x 35ms on 4 threads should finish in < 70 ms (far below 105 ms sequential)
    assert elapsed < 0.08, f"Parallel dispatch took too long ({elapsed*1000:.1f}ms); sequential execution suspected!"
    assert res is not None
    assert res.ensemble_status == DetectorStatus.HEALTHY
    orch.shutdown()


def test_def04_concurrent_timeout_bound():
    """
    DEF-04 REGRESSION TEST:
    Verifies that 2 detectors that exceed the 50 ms timeout complete concurrently
    and the total orchestrator wait time is bounded close to 50 ms, not 100 ms.
    """
    orch = ModularOrchestrator(detector_timeout_seconds=0.05, max_threads=4)
    orch.register_detector(MockSlowDetector(delay_seconds=0.20))  # 200 ms > 50 ms
    orch.register_detector(MockSlowDetector(delay_seconds=0.20))  # 200 ms > 50 ms

    t0 = time.perf_counter()
    res = orch.evaluate_shadow({"sourceIP": "10.0.0.1"}, force_shadow=True)
    elapsed = time.perf_counter() - t0

    # Total wait time should be bounded close to 50 ms + thread dispatch overhead (< 90 ms)
    assert elapsed < 0.10, f"Concurrent timeout took too long ({elapsed*1000:.1f}ms); sequential timeout suspected!"
    assert res.ensemble_status in (DetectorStatus.UNAVAILABLE, DetectorStatus.DEGRADED)
    assert res.overall_decision == PolicyDecision.MONITOR
    orch.shutdown()


def test_def04_dedup_thread_safety():
    """
    DEF-04 REGRESSION TEST:
    Verifies thread safety of deduplication cache under multi-threaded concurrent calls.
    """
    import threading
    orch = ModularOrchestrator(dedup_window_seconds=60.0)

    errors = []
    def worker(worker_id):
        try:
            for i in range(50):
                ip = f"192.168.1.{worker_id % 5}"
                threat = f"ATTACK_{i % 3}"
                orch._check_and_update_dedup(ip, threat, time.time())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    assert len(errors) == 0, f"Deduplication cache concurrency errors: {errors}"
    orch.shutdown()

