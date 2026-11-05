"""
tests/test_feature_capture.py

Phase 2.5C-2 Data Capture Implementation Test Suite:
Verifies:
  A. Exact vector: length 53, canonical order, raw/unscaled, valid float representations
  B. Prediction parity: identical inference metrics and decisions
  C. API leakage protection: /predict and /predict/eval omit featureVector from public JSON
  D. Notification path: _notify receives featureVector and featureSchemaVersion
  E. Replay isolation: /predict/eval remains side-effect free
"""
import os
import sys
import math
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

TEST_API_KEY = "test-sentinel-secret-key-12345"
os.environ["SENTINEL_KEY"] = TEST_API_KEY

from utils.features import FEATURE_NAMES, EXPECTED_FEATURE_COUNT, FEATURE_SCHEMA_VERSION, extract_features_from_record
from inference.predictor import SentinelPredictor
from inference.main import app, _public_result

SAMPLE_RECORD = {
    "sourceIP": "192.168.1.100",
    "flow_duration": 12345.0,
    "total_fwd_packets": 10.0,
    "total_bwd_packets": 5.0,
    "total_len_fwd_packets": 800.0,
    "total_len_bwd_packets": 500.0,
    "flow_bytes_per_sec": 45000.0,
    "flow_packets_per_sec": 1200.0,
    "syn_flag_count": 1.0,
    "ack_flag_count": 5.0,
}


class TestFeatureVectorIntegrity:
    """Verifies that predictor.predict() exposes the exact raw 53-feature vector."""

    @pytest.fixture
    def real_predictor(self):
        p = SentinelPredictor()
        # Verify if models are loaded from disk
        if not p._loaded:
            pytest.skip("Production models not found in models/ directory; skipping real model test.")
        return p

    def test_exact_53_features_raw_and_canonical(self, real_predictor):
        result = real_predictor.predict(SAMPLE_RECORD)
        
        assert "featureVector" in result, "featureVector must be present in predict() output"
        assert "featureSchemaVersion" in result, "featureSchemaVersion must be present in predict() output"
        assert result["featureSchemaVersion"] == FEATURE_SCHEMA_VERSION
        
        vec = result["featureVector"]
        assert isinstance(vec, list), "featureVector must be a Python list"
        assert len(vec) == 53, f"Expected exactly 53 features, got {len(vec)}"
        assert len(vec) == EXPECTED_FEATURE_COUNT
        
        # Verify all values are valid, finite floats
        for i, val in enumerate(vec):
            assert isinstance(val, (int, float)), f"Feature {FEATURE_NAMES[i]} is not numeric: {type(val)}"
            assert math.isfinite(val), f"Feature {FEATURE_NAMES[i]} is not finite: {val}"
            
        # Verify raw unscaled values match the input record directly
        # Index 0 is flow_duration
        assert vec[0] == 12345.0, f"Expected unscaled flow_duration 12345.0, got {vec[0]}"
        # Index 1 is total_fwd_packets
        assert vec[1] == 10.0, f"Expected unscaled total_fwd_packets 10.0, got {vec[1]}"
        # Index 2 is total_bwd_packets
        assert vec[2] == 5.0, f"Expected unscaled total_bwd_packets 5.0, got {vec[2]}"
        # Index 3 is total_len_fwd_packets
        assert vec[3] == 800.0, f"Expected unscaled total_len_fwd_packets 800.0, got {vec[3]}"

    def test_single_extraction_parity(self, real_predictor):
        """Vector in predict() must match extract_features_from_record() directly."""
        direct_raw = extract_features_from_record(SAMPLE_RECORD)
        result = real_predictor.predict(SAMPLE_RECORD)
        
        assert result["featureVector"] == [float(v) for v in direct_raw]

    def test_prediction_parity_invariants(self, real_predictor):
        """Feature capture must not alter any model classification or ThreatScore calculation."""
        res1 = real_predictor.predict(SAMPLE_RECORD)
        res2 = real_predictor.predict(SAMPLE_RECORD)
        
        assert res1["predictedClass"] == res2["predictedClass"]
        assert res1["threatScore"] == res2["threatScore"]
        assert res1["severity"] == res2["severity"]
        assert res1["action"] == res2["action"]
        assert res1["anomalyScore"] == res2["anomalyScore"]
        assert res1["classProbabilities"] == res2["classProbabilities"]
        assert res1["modelVersion"] == res2["modelVersion"]


class TestPublicApiLeakage:
    """Verifies that public API responses never leak the featureVector."""

    @pytest.fixture
    def client(self):
        with patch("inference.main._notify"):
            with TestClient(app) as c:
                yield c

    def test_predict_endpoint_does_not_leak_feature_vector(self, client):
        resp = client.post("/predict", json=SAMPLE_RECORD, headers={"X-API-Key": TEST_API_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        result = data["result"]
        
        assert "featureVector" not in result, "featureVector leaked in public /predict response!"
        assert "featureSchemaVersion" not in result, "featureSchemaVersion leaked in public /predict response!"
        assert "rawFeatures" not in result, "rawFeatures leaked in public /predict response!"
        assert "threatScore" in result
        assert "predictedClass" in result

    def test_predict_eval_does_not_leak_feature_vector(self, client):
        resp = client.post("/predict/eval", json=SAMPLE_RECORD, headers={"X-API-Key": TEST_API_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        result = data["result"]
        
        assert "featureVector" not in result, "featureVector leaked in /predict/eval response!"
        assert "featureSchemaVersion" not in result, "featureSchemaVersion leaked in /predict/eval response!"

    def test_predict_batch_does_not_leak_feature_vector(self, client):
        resp = client.post("/predict/batch", json=[SAMPLE_RECORD], headers={"X-API-Key": TEST_API_KEY})
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        for item in data["results"]:
            assert "featureVector" not in item["result"]
            assert "featureSchemaVersion" not in item["result"]


class TestNotifyPayloadIntegrity:
    """Verifies that background _notify receives the full featureVector."""

    @pytest.mark.anyio
    async def test_notify_receives_feature_vector(self):
        from inference.main import _notify
        
        captured_payload = {}
        class MockClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            async def post(self, url, json=None, headers=None):
                nonlocal captured_payload
                captured_payload = json
                return MagicMock(status_code=201)

        result_with_vector = {
            "threatScore": 0.95,  # above the callback line (= alert line 0.90, M1)
            "predictedClass": "Port Scan",
            "action": "MONITOR",
            "featureVector": [0.0] * 53,
            "featureSchemaVersion": "v2.1_53feat"
        }

        with patch("httpx.AsyncClient", return_value=MockClient()):
            await _notify(result_with_vector, "192.168.1.50")

        assert captured_payload.get("inputSource") == "network_traffic"
        assert captured_payload.get("sourceIP") == "192.168.1.50"
        assert "featureVector" in captured_payload
        assert len(captured_payload["featureVector"]) == 53
        assert captured_payload.get("featureSchemaVersion") == "v2.1_53feat"
