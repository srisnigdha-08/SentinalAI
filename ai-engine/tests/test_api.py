import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

# Setup environment variable before importing the FastAPI application
os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"

# Mock predictor load so startup event runs without throwing or loading files
with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    from inference.main import app

@pytest.fixture(autouse=True)
def mock_predictor_methods():
    with patch("inference.predictor.SentinelPredictor.predict") as mock_predict, \
         patch("inference.predictor.SentinelPredictor.predict_from_honeypot") as mock_predict_honeypot, \
         patch("inference.predictor.SentinelPredictor.get_model_info") as mock_get_info, \
         patch("inference.predictor.SentinelPredictor._loaded", new_callable=PropertyMock, return_value=True, create=True):

        mock_predict.return_value = {
            "threatScore": 0.85,
            "predictedClass": "Port Scan",
            "action": "MONITOR",
            "severity": "HIGH",
            "classProbabilities": {},
            "inferenceTimeMs": 2.5
        }
        mock_predict_honeypot.return_value = {
            "threatScore": 0.95,
            "predictedClass": "Brute Force",
            "action": "BLOCK"
        }
        mock_get_info.return_value = {
            "version": "test-v1",
            "metrics": {"accuracy": 0.99}
        }
        yield

@pytest.fixture
def client():
    # Disable background notifications to Node.js backend
    with patch("inference.main._notify") as mock_notify:
        with TestClient(app) as c:
            yield c

# ── Health Endpoint ───────────────────────────────────────────────────────────

def test_health_public(client):
    """Liveness check must be public and omit sensitive metrics."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data
    # Verify sensitive model info is not leaked
    assert "avgScore" not in data
    assert "onlineModelHoldoutAccuracy" not in data
    assert "modelsLoaded" not in data

# ── Model Info Endpoint ───────────────────────────────────────────────────────

def test_model_info_no_key(client):
    response = client.get("/model/info")
    assert response.status_code == 401

def test_model_info_invalid_key(client):
    response = client.get("/model/info", headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 403

def test_model_info_valid_key(client):
    response = client.get("/model/info", headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    assert response.json()["version"] == "test-v1"

# ── Model Stats Endpoint ──────────────────────────────────────────────────────

def test_model_stats_no_key(client):
    response = client.get("/model/stats")
    assert response.status_code == 401

def test_model_stats_valid_key(client):
    response = client.get("/model/stats", headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200

# ── Predict Endpoint ──────────────────────────────────────────────────────────

def test_predict_no_key(client):
    response = client.post("/predict", json={"sourceIP": "192.168.1.1"})
    assert response.status_code == 401

def test_predict_invalid_key(client):
    response = client.post("/predict", json={"sourceIP": "192.168.1.1"}, headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 403

def test_predict_valid_key(client):
    payload = {
        "sourceIP": "192.168.1.100",
        "flow_duration": 1200.0,
        "total_fwd_packets": 2.0
    }
    response = client.post("/predict", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["result"]["predictedClass"] == "Port Scan"

# ── Predict Batch Endpoint ────────────────────────────────────────────────────

def test_predict_batch_no_key(client):
    response = client.post("/predict/batch", json=[{"sourceIP": "192.168.1.1"}])
    assert response.status_code == 401

def test_predict_batch_valid_key(client):
    payload = [
        {"sourceIP": "192.168.1.100"},
        {"sourceIP": "192.168.1.101"}
    ]
    response = client.post("/predict/batch", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["total"] == 2

# ── Predict Honeypot Endpoint ─────────────────────────────────────────────────

def test_predict_honeypot_no_key(client):
    response = client.post("/predict/honeypot", json={})
    assert response.status_code == 401

def test_predict_honeypot_valid_key(client):
    payload = {
        "sessionId": "session-1",
        "sourceIP": "192.168.1.5",
        "commands": [{"command": "whoami"}]
    }
    response = client.post("/predict/honeypot", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    assert response.json()["success"] is True

# ── Removed Learn Update Endpoint (404 Negative Tests) ─────────────────────────

def test_learn_update_no_key(client):
    """Removed legacy endpoint must return 404 regardless of authentication."""
    response = client.post("/learn/update", json={})
    assert response.status_code == 404

def test_learn_update_invalid_key(client):
    """Removed legacy endpoint must return 404."""
    response = client.post("/learn/update", json={}, headers={"X-API-Key": "wrong-key"})
    assert response.status_code == 404

def test_learn_update_valid_key_valid_payload(client):
    """Removed legacy endpoint must return 404 even with valid API key and payload."""
    payload = {
        "rawFeatures": {"flow_duration": 1500.0, "sourceIP": "192.168.1.1"},
        "actualClass": "BENIGN"
    }
    response = client.post("/learn/update", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 404

def test_learn_update_valid_key_invalid_payload(client):
    """Removed legacy endpoint must return 404."""
    payload = {
        "rawFeatures": {"flow_duration": 1500.0}
    }
    response = client.post("/learn/update", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 404

# ── Shadow Auth Telemetry Endpoint ────────────────────────────────────────────

def test_predict_auth_shadow_no_key(client):
    response = client.post("/predict/auth/shadow", json={"event_type": "AUTH_FAILURE"})
    assert response.status_code == 401

def test_predict_auth_shadow_disabled_by_default(client):
    payload = {"event_type": "AUTH_FAILURE", "src_ip": "192.168.1.100"}
    response = client.post("/predict/auth/shadow", json=payload, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["shadow_enabled"] is False
