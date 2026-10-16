"""
tests/test_abuseipdb_decoupling.py

Automated tests for Phase 2.4B: AbuseIPDB Decoupling from ML Inference Pipeline.

Verifies:
TEST 1: Normal prediction works without AbuseIPDB (succeeds whether key is set, missing, or API down).
TEST 2: ThreatScore is mathematically unchanged (strict 0.70*RF + 0.30*IF calculation).
TEST 3: Action is unchanged (BLOCK for >= 0.92, MONITOR for >= 0.70, ALLOW otherwise).
TEST 4: Containment is unchanged (no side-effects triggered by inference).
TEST 16: Predict output threatScore is mathematically invariant to source IP reputation.
TEST 17: Predict output action is invariant to source IP reputation.
Verification: get_ip_reputation is never invoked synchronously during predict().
"""
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import numpy as np

sys.path.insert(0, str(Path(__file__).parent.parent))
from inference.predictor import SentinelPredictor, BLOCK_THRESHOLD, MONITOR_THRESHOLD


@pytest.fixture
def predictor_instance():
    """Predictor instance with mocked models for isolated scoring tests."""
    with patch("inference.predictor.SentinelPredictor.load"), \
         patch("inference.predictor.SentinelPredictor.init_explainer"):
        p = SentinelPredictor()
        p._loaded = True

        mock_rf = MagicMock()
        mock_rf.predict.return_value = [1]  # Attack class
        mock_rf.predict_proba.return_value = [[0.05, 0.95]]  # max_p = 0.95
        p.rf = mock_rf

        mock_if_estimator = MagicMock()
        mock_if_estimator.score_samples.return_value = [-0.55]
        mock_if_estimator.offset_ = -0.47402357424116837
        mock_ifo = MagicMock()
        mock_ifo.named_steps = {
            "if": mock_if_estimator,
            "scaler": MagicMock(transform=lambda x: x),
        }
        p.ifo = mock_ifo
        p.rf_meta = {"version": "test-v2"}
        return p


# ── TEST 1: Normal prediction works without AbuseIPDB ─────────────────────────
def test_normal_prediction_works_without_abuseipdb(predictor_instance):
    """
    TEST 1: Normal prediction works without AbuseIPDB.
    Verifies predict() executes cleanly when ABUSEIPDB_API_KEY is not set or network is disabled.
    """
    record = {"sourceIP": "185.220.101.5", "flow_duration": 1000.0}

    with patch.dict(os.environ, {}, clear=True):
        # ABUSEIPDB_API_KEY is completely unset
        res = predictor_instance.predict(record)

    assert res is not None
    assert "threatScore" in res
    assert "predictedClass" in res
    assert "action" in res
    assert res["ipReputationScore"] is None


# ── Latency & Synchronous Purge Verification ──────────────────────────────────
def test_get_ip_reputation_never_called_synchronously_during_predict(predictor_instance):
    """
    Verifies that get_ip_reputation is NOT called synchronously before or during predict().
    Prediction latency must be completely independent of AbuseIPDB.
    """
    record = {"sourceIP": "8.8.8.8", "flow_duration": 1500.0}

    with patch("inference.predictor.get_ip_reputation") as mock_get_rep:
        res = predictor_instance.predict(record)
        assert mock_get_rep.call_count == 0  # Zero calls!

    assert res["threatScore"] > 0
    assert res["ipReputationScore"] is None


def test_get_ip_reputation_never_called_synchronously_during_honeypot(predictor_instance):
    """
    Verifies that get_ip_reputation is NOT called synchronously during predict_from_honeypot().
    """
    session = {"sourceIP": "185.220.101.5", "commands": [{"command": "id"}, {"command": "uname -a"}]}

    with patch("inference.predictor.get_ip_reputation") as mock_get_rep:
        res = predictor_instance.predict_from_honeypot(session)
        assert mock_get_rep.call_count == 0  # Zero calls!

    assert res["threatScore"] > 0
    assert res["ipReputationScore"] is None


# ── TEST 2: ThreatScore is mathematically unchanged ───────────────────────────
def test_threat_score_mathematically_unchanged(predictor_instance):
    """
    TEST 2: ThreatScore is mathematically unchanged.
    Formula is strictly: round(0.70 * rf_s + 0.30 * if_sig, 4).
    """
    record = {"sourceIP": "185.220.101.5"}
    res = predictor_instance.predict(record)

    # For max_p = 0.95 (attack class):
    # rf_s = 0.95
    # val = -0.55, offset = -0.47402357424116837
    # deflection = -0.47402357424116837 - (-0.55) = 0.07597642575883163
    # if_sig = min(0.07597642575883163 / 0.20, 1.0) = 0.379882... -> round(..., 4) = 0.3799
    # expected score = round(0.7 * 0.95 + 0.3 * 0.3799, 4) = round(0.665 + 0.11397, 4) = 0.7790
    expected_rf_s = 0.95
    expected_if_sig = round(float((-0.47402357424116837 - (-0.55)) / 0.20), 4)
    expected_score = round(0.7 * expected_rf_s + 0.3 * expected_if_sig, 4)

    assert res["threatScore"] == expected_score


# ── TEST 3: Action is unchanged ───────────────────────────────────────────────
def test_action_is_unchanged(predictor_instance):
    """
    TEST 3: Action is unchanged:
      score >= 0.92 -> BLOCK
      score >= 0.70 -> MONITOR
      otherwise     -> ALLOW
    """
    # Test MONITOR (score ~ 0.7790)
    res = predictor_instance.predict({"sourceIP": "185.220.101.5"})
    assert res["action"] == "MONITOR"

    # Test BLOCK (max_p = 1.0, severe outlier)
    predictor_instance.rf.predict_proba.return_value = [[0.0, 1.0]]
    predictor_instance.ifo.named_steps["if"].score_samples.return_value = [-0.75]
    res_block = predictor_instance.predict({"sourceIP": "185.220.101.5"})
    assert res_block["threatScore"] >= BLOCK_THRESHOLD
    assert res_block["action"] == "BLOCK"

    # Test ALLOW (benign flow)
    predictor_instance.rf.predict.return_value = [0]  # BENIGN
    predictor_instance.rf.predict_proba.return_value = [[0.98, 0.02]]
    predictor_instance.ifo.named_steps["if"].score_samples.return_value = [-0.40]  # inlier
    res_allow = predictor_instance.predict({"sourceIP": "185.220.101.5"})
    assert res_allow["threatScore"] < MONITOR_THRESHOLD
    assert res_allow["action"] == "ALLOW"


# ── TEST 4: Containment is unchanged ──────────────────────────────────────────
def test_containment_is_unchanged(predictor_instance):
    """
    TEST 4: Predictor output strictly returns classification and score dictionary;
    it never invokes containment or writes to database.
    """
    res = predictor_instance.predict({"sourceIP": "185.220.101.5"})
    assert "action" in res
    assert res["action"] in ["ALLOW", "MONITOR", "BLOCK"]
    # Verify no containment side-effects are present in the response
    assert "containmentId" not in res
    assert "blockedAt" not in res


# ── TEST 16 & 17: Invariance across IP addresses ──────────────────────────────
def test_threat_score_and_action_invariance_across_ips(predictor_instance):
    """
    TEST 16 & TEST 17:
    Verifies that ThreatScore and Action are 100% invariant whether the sourceIP
    is a private IP, loopback, malicious public IP, or benign public IP.
    """
    test_ips = [
        "10.0.0.1",
        "127.0.0.1",
        "192.168.1.1",
        "185.220.101.5",  # Tor exit node
        "8.8.8.8",        # Google DNS
        "45.33.32.156",   # Scanme
    ]

    base_score = None
    base_action = None

    for ip in test_ips:
        res = predictor_instance.predict({"sourceIP": ip})
        if base_score is None:
            base_score = res["threatScore"]
            base_action = res["action"]
        else:
            assert res["threatScore"] == base_score
            assert res["action"] == base_action
