"""In-process validation/operational regressions; models mocked, no live telemetry."""
import json
import os
from unittest.mock import Mock, patch
import pytest
from fastapi.testclient import TestClient
os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from inference.main import app


@pytest.fixture
def validation_client():
    with patch("inference.main.SentinelPredictor") as factory:
        factory.return_value._loaded = True
        factory.return_value.predict.return_value = {"predictedClass": "BENIGN", "threatScore": 0.1, "action": "ALLOW"}
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, factory.return_value


@pytest.mark.parametrize("payload", [
    '{"flow_duration":NaN}', '{"flow_duration":Infinity}', '{"flow_duration":-Infinity}',
    '{"flow_duration":"not-numeric-private-input"}', '{"flow_duration":[1,2]}',
    '{"flow_duration":', '{"sourceIP":{"password":"private-input"}}',
])
def test_invalid_input_returns_sanitized_422_without_inference(validation_client, payload):
    client, predictor = validation_client
    response = client.post("/predict/eval", content=payload, headers={"Content-Type": "application/json", "X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 422
    result = response.json()
    json.dumps(result, allow_nan=False)
    assert "private-input" not in response.text
    assert all("input" not in item and "ctx" not in item for item in result["detail"])
    predictor.predict.assert_not_called()


def test_missing_optional_features_preserve_preprocessing_defaults(validation_client):
    client, predictor = validation_client
    response = client.post("/predict/eval", json={}, headers={"X-API-Key": "test-sentinel-secret-key-12345"})
    assert response.status_code == 200
    assert predictor.predict.call_args.args[0]["flow_duration"] == 1000.0


def test_prediction_only_shutdown_never_initializes_or_saves_learning_state(monkeypatch):
    from inference import deception
    monkeypatch.setattr(deception, "_scorer", None)
    assert deception.save_scorer() is False
    assert deception._scorer is None
    scorer = Mock()
    monkeypatch.setattr(deception, "_scorer", scorer)
    assert deception.save_scorer() is True
    scorer.learner.save.assert_called_once()
