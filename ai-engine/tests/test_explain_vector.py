"""
On-demand per-threat explanation (POST /explain/vector, SentinelPredictor.explain_vector).

The backend sends back the feature vector the engine produced for a prediction; the engine must reproduce that
prediction exactly (same class, score, confidence, model version) and explain it, without recording anything.
"""
import json
import os
import sys
from pathlib import Path
from unittest.mock import PropertyMock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")

from inference.predictor import SentinelPredictor  # noqa: E402
from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION  # noqa: E402

GOLDEN = Path(__file__).resolve().parent.parent / "models" / "golden_set.json"


@pytest.fixture(scope="module")
def real_predictor():
    p = SentinelPredictor()
    if not p._loaded or p.explainer is None:
        pytest.skip("served models or SHAP explainer not available")
    return p


@pytest.fixture(scope="module")
def stored_vectors(real_predictor):
    """featureVector exactly as /predict/internal returns it (and the backend stores it), for the golden rows."""
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["vectors"]
    out = []
    for v in golden:
        r = real_predictor.predict(dict(zip(FEATURE_NAMES, v)))
        out.append((r["featureVector"], r))
    return out


def test_explaining_a_stored_vector_reproduces_the_prediction(real_predictor, stored_vectors):
    for vector, original in stored_vectors:
        e = real_predictor.explain_vector(vector)
        assert e["predictedClass"] == original["predictedClass"]
        assert e["threatScore"] == original["threatScore"]
        assert e["confidence"] == original["confidence"]
        assert e["modelVersion"] == original["modelVersion"]
        assert e["featureSchemaVersion"] == FEATURE_SCHEMA_VERSION


def test_contributions_cover_every_feature_with_its_value_and_are_ranked(real_predictor, stored_vectors):
    vector, _ = stored_vectors[0]
    e = real_predictor.explain_vector(vector)
    c = e["contributions"]
    assert len(c) == len(FEATURE_NAMES) and {x["feature"] for x in c} == set(FEATURE_NAMES)
    mags = [abs(x["contribution"]) for x in c]
    assert mags == sorted(mags, reverse=True)
    by_name = dict(zip(FEATURE_NAMES, vector))
    assert all(x["value"] == pytest.approx(by_name[x["feature"]]) for x in c)


def test_contributions_add_up_to_the_classifier_margin(real_predictor, stored_vectors):
    """SHAP additivity: base value + sum of contributions = the booster's raw margin for the explained class."""
    vector, _ = stored_vectors[0]
    e = real_predictor.explain_vector(vector)
    if e["baseValue"] is None:
        pytest.skip("explainer exposes no expected value")
    xgb = real_predictor.clf.named_steps["xgb"]
    booster = getattr(xgb, "model_", xgb)
    Xs = real_predictor.clf.named_steps["scaler"].transform(np.asarray(vector, dtype=float).reshape(1, -1))
    margin = np.asarray(booster.predict(Xs, output_margin=True), dtype=float).reshape(-1)
    cls_pos = int(np.argmax(real_predictor.rf.predict_proba(np.asarray(vector, dtype=float).reshape(1, -1))[0]))
    expected = margin[cls_pos] if margin.size > 1 else margin[0]
    assert e["baseValue"] + sum(x["contribution"] for x in e["contributions"]) == pytest.approx(expected, abs=1e-3)


@pytest.mark.parametrize("bad", [[1.0] * 52, [1.0] * 54, [float("nan")] + [1.0] * 52, [float("inf")] + [1.0] * 52])
def test_malformed_vectors_are_rejected(real_predictor, bad):
    with pytest.raises(ValueError):
        real_predictor.explain_vector(bad)


# ── endpoint (mocked predictor; no model files needed) ──────────────────────────────────────────────────────────
with patch("inference.predictor.SentinelPredictor.load"), patch("inference.predictor.SentinelPredictor.init_explainer"):
    from inference import main as engine_main  # noqa: E402

KEY = os.environ["SENTINEL_KEY"]
RESULT = {"predictedClass": "DDoS", "explainedClass": "DDoS", "threatScore": 0.97, "confidence": 0.97,
          "classProbabilities": {"DDoS": 0.97}, "isAnomaly": False, "modelVersion": "xgb_cicids_v1",
          "featureSchemaVersion": FEATURE_SCHEMA_VERSION, "baseValue": 0.1, "units": "x",
          "contributions": [{"feature": "flow_duration", "contribution": 1.2, "value": 3.0}]}


@pytest.fixture
def client():
    with patch("inference.predictor.SentinelPredictor._loaded", new_callable=PropertyMock, return_value=True, create=True), \
         patch("inference.predictor.SentinelPredictor.explain_vector", return_value=dict(RESULT)) as ev, \
         patch("inference.main._notify"):
        with TestClient(engine_main.app) as c:
            c.explain_mock = ev
            yield c


def _body(**over):
    return {"featureVector": [0.0] * len(FEATURE_NAMES), "featureSchemaVersion": FEATURE_SCHEMA_VERSION, **over}


def test_endpoint_requires_the_service_key(client):
    assert client.post("/explain/vector", json=_body()).status_code == 401
    assert client.post("/explain/vector", json=_body(), headers={"X-API-Key": "wrong"}).status_code == 403


def test_endpoint_returns_the_explanation_and_records_nothing(client):
    before = dict(engine_main.stats)
    r = client.post("/explain/vector", json=_body(), headers={"X-API-Key": KEY})
    assert r.status_code == 200 and r.json()["result"]["predictedClass"] == "DDoS"
    assert engine_main.stats["total"] == before["total"]  # no stats / drift update


def test_endpoint_refuses_another_feature_schema(client):
    r = client.post("/explain/vector", json=_body(featureSchemaVersion="v1_old"), headers={"X-API-Key": KEY})
    assert r.status_code == 409
    client.explain_mock.assert_not_called()


def test_endpoint_maps_malformed_vectors_to_422(client):
    client.explain_mock.side_effect = ValueError("featureVector must have 53 values, got 3")
    r = client.post("/explain/vector", json=_body(featureVector=[1.0, 2.0, 3.0]), headers={"X-API-Key": KEY})
    assert r.status_code == 422


def test_endpoint_reports_an_unavailable_explainer_without_a_5xx(client):
    """A 5xx would count towards the backend's AI circuit breaker and could stall threat scoring."""
    client.explain_mock.return_value = {**RESULT, "contributions": []}
    r = client.post("/explain/vector", json=_body(), headers={"X-API-Key": KEY})
    assert r.status_code == 200 and r.json()["result"]["explainerAvailable"] is False
