"""
SentinelAI - Phase 2.3C Replay Isolation Test Suite
Verifies TEST 1 through TEST 14 to prove complete isolation of /predict/eval
from production containment, persistence, and broadcasting pipelines.
"""
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

# Ensure test API key is configured before importing app
TEST_API_KEY = "test-sentinel-secret-key-12345"
os.environ["SENTINEL_KEY"] = TEST_API_KEY

with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    from inference.main import app

SAMPLE_BENIGN_RECORD = {
    "sourceIP": "192.168.10.101",
    "flow_duration": 1000.0,
    "total_fwd_packets": 2.0,
    "total_bwd_packets": 1.0,
    "total_len_fwd_packets": 120.0,
    "total_len_bwd_packets": 60.0,
    "syn_flag_count": 1.0
}

# A complete flow (every raw schema feature present): incomplete input is never allowed to BLOCK (M2).
from utils.features import FEATURE_NAMES as _FEATURES
SAMPLE_ATTACK_RECORD = {
    **{f: 0.0 for f in _FEATURES if f not in ("payload_entropy", "time_of_day_sin", "time_of_day_cos")},
    "sourceIP": "192.168.10.102",
    "flow_duration": 50000.0,
    "total_fwd_packets": 5000.0,
    "total_bwd_packets": 0.0,
    "total_len_fwd_packets": 300000.0,
    "total_len_bwd_packets": 0.0,
    "flow_packets_per_sec": 100000.0,
    "syn_flag_count": 5000.0
}

MOCK_BENIGN_RESULT = {
    "predictedClass": "BENIGN",
    "threatScore": 0.08,
    "severity": "LOW",
    "confidence": 0.99,
    "isAnomaly": False,
    "anomalyScore": -0.42,
    "classProbabilities": {"BENIGN": 0.99, "DDoS": 0.01},
    "inferenceTimeMs": 3.2,
    "action": "ALLOW",
    "modelVersion": "rf_cicids_v2.0",
    "featureImportance": [],
    "ipReputationScore": None
}

MOCK_BLOCK_RESULT = {
    "predictedClass": "DDoS",
    "threatScore": 0.9650,
    "severity": "CRITICAL",
    "confidence": 0.99,
    "isAnomaly": False,
    "anomalyScore": -0.41,
    "classProbabilities": {"BENIGN": 0.01, "DDoS": 0.99},
    "inferenceTimeMs": 4.1,
    "action": "BLOCK",
    "modelVersion": "rf_cicids_v2.0",
    "featureImportance": [],
    "ipReputationScore": None
}

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

# ─────────────────────────────────────────────────────────────────────────────
# TEST 1: Normal /predict behavior remains unchanged
# ─────────────────────────────────────────────────────────────────────────────
def test_test1_normal_predict_behavior_unchanged(client):
    """Verifies that production /predict continues to invoke _upd and _notify."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT) as mock_pred, \
         patch("inference.main._upd") as mock_upd, \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["sourceIP"] == SAMPLE_ATTACK_RECORD["sourceIP"]
        assert data["result"]["action"] == "BLOCK"
        
        # In production /predict: _upd and _notify MUST be invoked
        mock_pred.assert_called_once()
        mock_upd.assert_called_once_with(MOCK_BLOCK_RESULT)
        mock_notify.assert_called_once()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 2: /predict and /predict/eval produce equivalent model inference results
# ─────────────────────────────────────────────────────────────────────────────
def test_test2_inference_model_parity(client):
    """
    Submitting the exact same feature vector to /predict and /predict/eval
    returns the identical underlying model result dictionary.
    """
    with patch("inference.main.predictor.predict", return_value=MOCK_BENIGN_RESULT), \
         patch("inference.main._notify"):
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp_prod = client.post("/predict", json=SAMPLE_BENIGN_RECORD, headers=headers)
        resp_eval = client.post("/predict/eval", json=SAMPLE_BENIGN_RECORD, headers=headers)
        
        assert resp_prod.status_code == 200
        assert resp_eval.status_code == 200
        
        prod_json = resp_prod.json()
        eval_json = resp_eval.json()
        
        # The ML result dictionary must be 100% identical
        assert prod_json["result"] == eval_json["result"]
        assert prod_json["sourceIP"] == eval_json["sourceIP"]
        
        # Expected outer wrapper differences:
        # 1. eval_json contains 'evaluation': True to explicitly identify isolated context
        # 2. timestamps will differ by execution microseconds
        assert eval_json["evaluation"] is True
        assert "evaluation" not in prod_json

# ─────────────────────────────────────────────────────────────────────────────
# TEST 3: Evaluation may return action = BLOCK without executing containment
# ─────────────────────────────────────────────────────────────────────────────
def test_test3_eval_returns_block_without_containment(client):
    """
    Evaluation can return action: 'BLOCK' reflecting true model prediction,
    while guaranteeing that background notifications and containment are bypassed.
    """
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify, \
         patch("inference.main._upd") as mock_upd:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        data = resp.json()
        assert data["result"]["action"] == "BLOCK"
        assert data["result"]["threatScore"] >= 0.92
        
        # ABSOLUTE SAFETY ASSERTIONS:
        # Zero notifications, zero stats pollution
        mock_notify.assert_not_called()
        mock_upd.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 4: Evaluation creates zero ThreatLog documents
# ─────────────────────────────────────────────────────────────────────────────
def test_test4_eval_creates_zero_threat_logs(client):
    """
    Proves that /predict/eval never contacts backend:5000/api/ai/predictions,
    guaranteeing zero ThreatLog records are created in MongoDB.
    """
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify, \
         patch("httpx.AsyncClient.post") as mock_http_post:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_notify.assert_not_called()
        mock_http_post.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 5: Evaluation creates zero Alert documents
# ─────────────────────────────────────────────────────────────────────────────
def test_test5_eval_creates_zero_alerts(client):
    """Verifies that no alert creation triggers occur from /predict/eval."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_notify.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 6: Evaluation creates zero BlockedIP documents
# ─────────────────────────────────────────────────────────────────────────────
def test_test6_eval_creates_zero_blocked_ips(client):
    """Verifies that no BlockedIP upsert triggers occur from /predict/eval."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_notify.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 7: Evaluation performs zero containment calls
# ─────────────────────────────────────────────────────────────────────────────
def test_test7_eval_performs_zero_containment_calls(client):
    """Mock/spy on containment boundary proving 0 containment calls during evaluation."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_notify.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 8: Evaluation emits zero production Socket.IO events
# ─────────────────────────────────────────────────────────────────────────────
def test_test8_eval_emits_zero_socket_events(client):
    """Verifies zero event emissions because notification is never triggered."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_notify.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 9: Production /predict retains notification/containment behavior
# ─────────────────────────────────────────────────────────────────────────────
def test_test9_production_predict_retains_behavior(client):
    """Verifies that /predict continues normal notification for scores >= 0.70."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._upd") as mock_upd, \
         patch("inference.main._notify") as mock_notify:
        
        headers = {"X-API-Key": TEST_API_KEY}
        resp = client.post("/predict", json=SAMPLE_ATTACK_RECORD, headers=headers)
        
        assert resp.status_code == 200
        mock_upd.assert_called_once()
        mock_notify.assert_called_once()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 10: Unauthenticated evaluation requests are rejected
# ─────────────────────────────────────────────────────────────────────────────
def test_test10_unauthenticated_eval_rejected(client):
    """Rejects missing or invalid API keys on /predict/eval."""
    # Missing key -> 401
    resp_no_key = client.post("/predict/eval", json=SAMPLE_BENIGN_RECORD)
    assert resp_no_key.status_code == 401
    
    # Invalid key -> 403
    resp_bad_key = client.post("/predict/eval", json=SAMPLE_BENIGN_RECORD, headers={"X-API-Key": "wrong-secret"})
    assert resp_bad_key.status_code == 403

# ─────────────────────────────────────────────────────────────────────────────
# TEST 11: Invalid evaluation input is rejected without side effects
# ─────────────────────────────────────────────────────────────────────────────
def test_test11_invalid_eval_input_rejected_safely(client):
    """Malformed payloads return 422 without triggering notifications."""
    with patch("inference.main._notify") as mock_notify, \
         patch("inference.main._upd") as mock_upd:
        
        headers = {"X-API-Key": TEST_API_KEY}
        # Send invalid type for numerical field
        resp = client.post("/predict/eval", json={"flow_duration": "not-a-number"}, headers=headers)
        
        assert resp.status_code == 422
        mock_notify.assert_not_called()
        mock_upd.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 12: Repeated evaluation requests remain side-effect free
# ─────────────────────────────────────────────────────────────────────────────
def test_test12_repeated_eval_requests_side_effect_free(client):
    """Executes 25 sequential evaluation calls, asserting zero side effects across all calls."""
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify, \
         patch("inference.main._upd") as mock_upd:
        
        headers = {"X-API-Key": TEST_API_KEY}
        for _ in range(25):
            resp = client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
            assert resp.status_code == 200
            
        mock_notify.assert_not_called()
        mock_upd.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 13: Evaluation failures do not create partial production telemetry
# ─────────────────────────────────────────────────────────────────────────────
def test_test13_eval_internal_failure_atomicity(client):
    """If inference throws an unexpected error, no side effects occur."""
    with patch("inference.main.predictor.predict", side_effect=RuntimeError("Model error")), \
         patch("inference.main._notify") as mock_notify, \
         patch("inference.main._upd") as mock_upd:
        
        headers = {"X-API-Key": TEST_API_KEY}
        with pytest.raises(RuntimeError):
            client.post("/predict/eval", json=SAMPLE_ATTACK_RECORD, headers=headers)
            
        mock_notify.assert_not_called()
        mock_upd.assert_not_called()

# ─────────────────────────────────────────────────────────────────────────────
# TEST 14: No query/body/header parameter on /predict can disable notification
# ─────────────────────────────────────────────────────────────────────────────
def test_test14_no_bypass_parameter_on_production_predict(client):
    """
    Verifies that /predict does NOT accept or honor parameters like notify=false,
    dryRun=true, or X-Sentinel-Mode to suppress production notifications.
    """
    with patch("inference.main.predictor.predict", return_value=MOCK_BLOCK_RESULT), \
         patch("inference.main._notify") as mock_notify:
        
        headers = {
            "X-API-Key": TEST_API_KEY,
            "X-Sentinel-Mode": "evaluation",
            "X-Sentinel-Simulation": "true"
        }
        # Attempt to pass query parameters to suppress notification
        resp = client.post(
            "/predict?notify=false&dryRun=true&mode=evaluation",
            json={**SAMPLE_ATTACK_RECORD, "notify": False, "dryRun": True},
            headers=headers
        )
        
        assert resp.status_code == 200
        # Production /predict MUST still invoke _notify despite suppression attempts
        mock_notify.assert_called_once()
