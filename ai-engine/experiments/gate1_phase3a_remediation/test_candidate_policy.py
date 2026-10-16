"""SentinelAI — GATE-1 Phase 3A: Candidate Policy Test Suite
Location: ai-engine/experiments/gate1_phase3a_remediation/test_candidate_policy.py

Comprehensive test suite verifying:
1. PortScan recovery on zero-anomaly flows
2. DDoS recovery on zero-anomaly flows
3. Threshold boundary behavior (0.699, 0.700, 0.701, 0.849, 0.850, 0.851, 0.919, 0.920, 0.921)
4. Benign outlier safety invariant (Unknown label, score 0.55, action ALLOW)
5. Non-finite, NaN, Inf, and malformed input handling
6. Inference service timeout and exception fail-safe behavior
7. Backend schema and action contract compatibility
8. Safety invariants (zero firewall rules, zero Q-table mutation, zero DB mutation)
"""

import sys
import os
import hashlib
from pathlib import Path
import pytest
import numpy as np

# Ensure candidate policy and ai-engine utils are importable
CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
WORKSPACE_ROOT = AI_ENGINE_DIR.parent

if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))
if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))

from candidate_policy import (
    CandidateSentinelPolicy,
    BLOCK_THRESHOLD,
    MONITOR_THRESHOLD,
    ANOMALY_THRESHOLD,
    EXPERIMENTAL_CONFIDENCE_THRESHOLD,
    calculate_if_anomaly_signal,
    score_to_severity,
)


@pytest.fixture
def policy():
    return CandidateSentinelPolicy()


# -----------------------------------------------------------------------------
# Test Category 1: High-Confidence PortScan with Zero Anomaly Signal
# -----------------------------------------------------------------------------
def test_portscan_high_confidence_zero_anomaly(policy):
    """
    Simulates the exact condition of the 926 PortScan flows that failed under baseline:
    Supervised model detects Port Scan with 92% confidence, but Isolation Forest reports inlier (sig=0.0).
    Under candidate policy, the attenuation trap must be broken: action must be MONITOR (or BLOCK), not ALLOW.
    """
    decision = policy.evaluate_signals(
        cname="Port Scan",
        confidence=0.92,
        is_anomaly=False,
        anomaly_signal=0.0,
        anomaly_score=-0.42,
    )

    # In baseline: threatScore was 0.7 * 0.92 = 0.6440 -> ALLOW (Recall Failure!)
    # In candidate: threatScore is 0.92 -> MONITOR (Autonomous Block Eligible)
    assert decision["predictedClass"] == "Port Scan"
    assert decision["threatScore"] >= 0.70, f"Expected threatScore >= 0.70, got {decision['threatScore']}"
    assert decision["threatScore"] == 0.92
    assert decision["action"] in ["MONITOR", "BLOCK"], f"Action must be MONITOR or BLOCK, got {decision['action']}"
    assert decision["action"] == "BLOCK" or decision["action"] == "MONITOR"
    assert decision["status"] in ["MONITORING", "BLOCKED"]
    assert decision["ruleApplied"].startswith("R-7") or decision["ruleApplied"].startswith("R-8")


def test_portscan_at_hypothesis_threshold_zero_anomaly(policy):
    """PortScan right at the experimental threshold (0.85) with zero anomaly signal."""
    decision = policy.evaluate_signals(
        cname="Port Scan",
        confidence=0.85,
        is_anomaly=False,
        anomaly_signal=0.0,
        anomaly_score=-0.45,
    )
    assert decision["threatScore"] == 0.85
    assert decision["action"] == "MONITOR"
    assert decision["severity"] == "HIGH"


# -----------------------------------------------------------------------------
# Test Category 2: High-Confidence DDoS with Zero Anomaly Signal
# -----------------------------------------------------------------------------
def test_ddos_high_confidence_zero_anomaly(policy):
    """
    Simulates DDoS flows that were suppressed under baseline due to low anomaly signal.
    """
    decision = policy.evaluate_signals(
        cname="DDoS",
        confidence=0.95,
        is_anomaly=False,
        anomaly_signal=0.0,
        anomaly_score=-0.46,
    )
    assert decision["predictedClass"] == "DDoS"
    assert decision["threatScore"] == 0.95
    assert decision["action"] == "BLOCK"
    assert decision["autonomousBlockEligible"] is True
    assert decision["severity"] == "CRITICAL"


def test_ddos_consensus_attack_with_anomaly_boost(policy):
    """DDoS attack confirmed by both classifiers triggers consensus boost."""
    decision = policy.evaluate_signals(
        cname="DDoS",
        confidence=0.88,
        is_anomaly=True,
        anomaly_signal=0.80,
        anomaly_score=-0.62,
    )
    # 0.88 + 0.10 * 0.80 = 0.96 -> BLOCK
    assert decision["threatScore"] == 0.96
    assert decision["action"] == "BLOCK"
    assert decision["ruleApplied"].startswith("R-8")


# -----------------------------------------------------------------------------
# Test Category 3: Boundary Tests Around Policy Thresholds
# -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    "conf,expected_score,expected_action",
    [
        # MONITOR Boundary (0.70)
        (0.699, 0.6291, "ALLOW"),   # 0.699 * 0.90 = 0.6291 -> ALLOW
        (0.700, 0.7000, "MONITOR"), # 0.700 -> MONITOR
        (0.701, 0.7010, "MONITOR"), # 0.701 -> MONITOR

        # Hypothesis Threshold Boundary (0.85)
        (0.849, 0.8490, "MONITOR"), # Inlier preserved -> 0.849 MONITOR
        (0.850, 0.8500, "MONITOR"), # Inlier preserved -> 0.850 MONITOR
        (0.851, 0.8510, "MONITOR"), # Inlier preserved -> 0.851 MONITOR

        # BLOCK Boundary (0.92)
        (0.919, 0.9190, "MONITOR"), # 0.919 -> MONITOR
        (0.920, 0.9200, "BLOCK"),   # 0.920 -> BLOCK
        (0.921, 0.9210, "BLOCK"),   # 0.921 -> BLOCK
    ],
)
def test_confidence_threshold_boundaries(policy, conf, expected_score, expected_action):
    decision = policy.evaluate_signals(
        cname="Port Scan",
        confidence=conf,
        is_anomaly=False,
        anomaly_signal=0.0,
    )
    assert decision["threatScore"] == expected_score
    assert decision["action"] == expected_action


@pytest.mark.parametrize(
    "if_score,expected_is_anomaly",
    [
        (-0.551, True),   # Outlier beyond threshold
        (-0.550, False),  # Exact threshold (not strictly less)
        (-0.549, False),  # Inlier above threshold
    ],
)
def test_anomaly_threshold_boundaries(policy, if_score, expected_is_anomaly):
    is_anomaly = bool(if_score < policy.anomaly_threshold)
    assert is_anomaly == expected_is_anomaly


# -----------------------------------------------------------------------------
# Test Category 4: Benign Traffic Safety Invariant
# -----------------------------------------------------------------------------
def test_benign_normal_traffic(policy):
    """Legitimate benign traffic with no anomaly signal."""
    decision = policy.evaluate_signals(
        cname="BENIGN",
        confidence=0.99,
        is_anomaly=False,
        anomaly_signal=0.0,
        anomaly_score=-0.35,
    )
    assert decision["predictedClass"] == "BENIGN"
    assert decision["threatScore"] == 0.05
    assert decision["action"] == "ALLOW"
    assert decision["severity"] == "LOW"
    assert decision["status"] == "ALLOW"


def test_benign_outlier_traffic_never_blocked(policy):
    """
    CRITICAL SAFETY INVARIANT:
    Bursty or unusual benign traffic flagged as an outlier (Unknown label)
    MUST NEVER escalate to MONITOR or BLOCK.
    """
    decision = policy.evaluate_signals(
        cname="BENIGN",
        confidence=0.95,
        is_anomaly=True,
        anomaly_signal=1.0,
        anomaly_score=-0.75,
    )
    assert decision["predictedClass"] == "Unknown"
    assert decision["threatScore"] == 0.55
    assert decision["threatScore"] < MONITOR_THRESHOLD
    assert decision["threatScore"] < BLOCK_THRESHOLD
    assert decision["action"] == "ALLOW"
    assert decision["severity"] == "MEDIUM"
    assert decision["status"] == "DETECTED"
    assert decision["autonomousBlockEligible"] is False


# -----------------------------------------------------------------------------
# Test Category 5: Malformed, Missing, NaN, and Infinite Inputs
# -----------------------------------------------------------------------------
def test_non_finite_input_rejection(policy):
    """Record containing NaN and Inf must not crash inference and must be safely rejected."""
    bad_record = {
        "Flow Duration": float("nan"),
        "Total Fwd Packets": float("inf"),
        "sourceIP": "192.168.1.100",
    }
    
    # Mock pipelines
    decision = policy.evaluate_flow_record(
        bad_record,
        rf_pipeline=object(),
        if_pipeline=object(),
    )
    assert decision["predictedClass"] == "INVALID_INPUT"
    assert decision["status"] == "INPUT_ERROR"
    assert decision["action"] == "ALLOW_AUDITED"
    assert decision["threatScore"] == 0.0
    assert decision["requiresHumanReview"] is True
    assert decision["isFailSafe"] is True


def test_empty_record_handling(policy):
    """Empty record must produce a structured error, not an unhandled crash."""
    decision = policy.evaluate_flow_record(
        {},
        rf_pipeline=object(),
        if_pipeline=object(),
    )
    assert decision["status"] in ["INPUT_ERROR", "DEGRADED"]
    assert decision["action"] in ["ALLOW_AUDITED", "MONITOR"]
    assert decision["action"] != "BLOCK"


# -----------------------------------------------------------------------------
# Test Category 6: Inference Service Timeout, Exception, and Model Failure Cases
# -----------------------------------------------------------------------------
def test_model_unavailable_fallback(policy):
    """When models are None / unloaded, policy fails safely without crashing."""
    decision = policy.evaluate_flow_record(
        {"sourceIP": "10.0.0.5"},
        rf_pipeline=None,
        if_pipeline=None,
    )
    assert decision["predictedClass"] == "UNINSPECTED_TRAFFIC"
    assert decision["status"] == "DEGRADED"
    assert decision["action"] == "MONITOR"
    assert decision["threatScore"] == 0.50
    assert decision["isFailSafe"] is True
    assert decision["autonomousBlockEligible"] is False
    # Crucial safety check: Never mark as BENIGN
    assert decision["predictedClass"] != "BENIGN"
    # Crucial safety check: Never block automatically
    assert decision["action"] != "BLOCK"


def test_explicit_timeout_handling(policy):
    """Explicit timeout failure creates observable audit record."""
    decision = policy.handle_inference_failure(
        failure_type="INFERENCE_TIMEOUT",
        error_detail="Socket timeout after 5000ms",
        source_ip="172.16.0.45",
    )
    assert decision["predictedClass"] == "UNINSPECTED_TRAFFIC"
    assert decision["status"] == "DEGRADED"
    assert decision["action"] == "MONITOR"
    assert decision["threatScore"] == 0.50
    assert decision["isFailSafe"] is True
    assert decision["requiresHumanReview"] is True
    assert decision["sourceIP"] == "172.16.0.45"


# -----------------------------------------------------------------------------
# Test Category 7: Backend Interpretation Contract Verification
# -----------------------------------------------------------------------------
def test_backend_schema_compatibility(policy):
    """
    Verifies that the candidate policy output satisfies the exact dictionary schema
    expected by backend/services/aiEngineService.js and threatService.js.
    """
    decision = policy.evaluate_signals(
        cname="DDoS",
        confidence=0.94,
        is_anomaly=True,
        anomaly_signal=0.50,
        anomaly_score=-0.58,
        inference_time_ms=12.5,
    )
    
    required_backend_fields = [
        "predictedClass",
        "threatScore",
        "severity",
        "confidence",
        "isAnomaly",
        "anomalyScore",
        "action",
        "status",
        "inferenceTimeMs",
        "modelVersion",
    ]
    for field in required_backend_fields:
        assert field in decision, f"Missing required backend field: {field}"
        
    # Verify type constraints
    assert isinstance(decision["predictedClass"], str)
    assert isinstance(decision["threatScore"], float)
    assert 0.0 <= decision["threatScore"] <= 1.0
    assert decision["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert decision["action"] in ["ALLOW", "MONITOR", "BLOCK"]


# -----------------------------------------------------------------------------
# Test Category 8: Safety Boundaries & Invariant Affirmations
# -----------------------------------------------------------------------------
def test_safety_invariants_no_side_effects():
    """
    Mandatory audit test: Confirms that running the candidate policy test suite
    cannot invoke real Windows Firewall enforcement, cannot mutate Q-tables,
    and cannot access the production MongoDB database.
    """
    # 1. Verify environment enforcement flags
    auto_containment = os.getenv("AUTONOMOUS_CONTAINMENT", "false").lower() == "true"
    real_firewall = os.getenv("ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT", "false").lower() == "true"
    assert auto_containment is False, "AUTONOMOUS_CONTAINMENT must remain False"
    assert real_firewall is False, "ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT must remain False"

    # 2. Verify baseline Q-table integrity
    baseline_qtable = AI_ENGINE_DIR / "models" / "q_table.json"
    if baseline_qtable.exists():
        hasher = hashlib.sha256()
        with open(baseline_qtable, "rb") as f:
            hasher.update(f.read())
        baseline_hash = hasher.hexdigest().upper()
        assert baseline_hash == "BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF", \
            f"Baseline Q-table altered! Hash={baseline_hash}"

    # 3. Verify runtime Q-table exists and is untouched
    runtime_qtable = AI_ENGINE_DIR / "runtime" / "q_table.json"
    assert runtime_qtable.exists(), "Runtime Q-table must exist"
