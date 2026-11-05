"""Low-priority AI engine fixes: L1, L2, L4, L6, L8, L9, L11, L12 (L5 is in test_predictor.py)."""
import argparse
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from fastapi.testclient import TestClient  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from inference import main  # noqa: E402
from inference import predictor as pred_mod  # noqa: E402
from training import train as T  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402
from tests.test_medium_fixes import _load, _register, _write_models  # noqa: E402

ENGINE = Path(__file__).resolve().parent.parent
H = {"X-API-Key": os.environ["SENTINEL_KEY"]}


# ── L1 / L2 ───────────────────────────────────────────────────────────────────────────────────────────
def test_shadow_errors_do_not_echo_exception_text(monkeypatch):
    shadow = MagicMock()
    shadow.evaluate.side_effect = ValueError("password=hunter2 from raw_message")
    monkeypatch.setattr(main, "predictor", MagicMock(shadow_e2=shadow))
    body = TestClient(main.app).post("/predict/auth/shadow", headers=H, json={"raw_message": "x"}).json()
    assert body == {"success": False, "error": "shadow evaluation failed"}


@pytest.mark.parametrize("field,value", [("raw_message", "x" * 5000), ("user_identity", "u" * 300),
                                         ("dst_port", 70000), ("timestamp", float("nan"))])
def test_auth_telemetry_is_bounded(field, value):
    with pytest.raises(ValidationError):
        main.AuthTelemetryRecord(**{field: value})


def test_auth_telemetry_optional_fields_default_to_none():
    rec = main.AuthTelemetryRecord()
    assert rec.dst_ip is None and rec.user_identity is None and rec.timestamp is None


# ── L4 ────────────────────────────────────────────────────────────────────────────────────────────────
class VectorPredictor:
    _loaded = True

    def predict(self, record, explain=False):
        return {"predictedClass": "BENIGN", "threatScore": 0.1, "action": "ALLOW", "inferenceTimeMs": 1.0,
                "featureVector": [float(record.get("flow_duration", 0))] + [0.0] * (len(FEATURE_NAMES) - 1)}


@pytest.fixture
def counted(monkeypatch):
    monkeypatch.setattr(main, "predictor", VectorPredictor())
    monkeypatch.setattr(main, "_SEEN_DELIVERIES", main.OrderedDict())
    calls = []
    monkeypatch.setattr(main, "_upd_unlocked", lambda r: calls.append(r["featureVector"][0]))
    return calls


def test_retried_internal_call_is_counted_once(counted):
    client = TestClient(main.app)
    headers = {**H, "X-Request-Id": "retry-test-0001"}
    for _ in range(3):  # backend withRetry: same request id, same payload
        assert client.post("/predict/internal", headers=headers, json={"flow_duration": 5}).status_code == 200
    assert counted == [5.0]


def test_distinct_flows_in_one_request_are_all_counted(counted):
    client = TestClient(main.app)
    headers = {**H, "X-Request-Id": "batch-loop-0001"}
    for d in (1, 2, 3):
        client.post("/predict/internal", headers=headers, json={"flow_duration": d})
    assert counted == [1.0, 2.0, 3.0]


def test_calls_without_a_request_id_are_independent(counted):
    client = TestClient(main.app)
    for _ in range(2):
        client.post("/predict/internal", headers=H, json={"flow_duration": 7})
    assert counted == [7.0, 7.0]  # the engine generates a fresh id per request


# ── L6 / L9 ───────────────────────────────────────────────────────────────────────────────────────────
def test_training_no_longer_imports_the_unused_log_transform():
    assert not hasattr(T, "log_transform_features")


@pytest.mark.skipif(not (ENGINE.parent / "models" / "sgd_classifier_cicids.pkl").exists(), reason="archive absent")
def test_archived_sgd_artifact_still_unpickles():
    import joblib
    assert type(joblib.load(ENGINE.parent / "models" / "sgd_classifier_cicids.pkl")).__name__ == "Pipeline"


def test_requirements_are_fully_pinned():
    lines = [l.strip() for l in (ENGINE / "requirements.txt").read_text().splitlines() if l.strip() and not l.startswith("#")]
    assert all("==" in l for l in lines), [l for l in lines if "==" not in l]
    assert any(l.startswith("scipy==") for l in lines)


# ── L8 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_tuning_baseline_is_the_untuned_recipe_on_the_same_split(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(T.RF_PARAMS, "n_estimators", 5)
    monkeypatch.setitem(T.IF_PARAMS, "n_estimators", 5)

    class QuickSearch:  # stands in for RandomizedSearchCV: one fit, no grid
        def __init__(self, pipe, **kw):
            self.pipe = pipe

        def fit(self, X, y):
            self.best_estimator_ = self.pipe.fit(X, y)
            self.best_params_ = {}
            return self

    monkeypatch.setattr(T, "RandomizedSearchCV", QuickSearch)
    T.train(argparse.Namespace(data=None, synthetic=True, rows=1500, model_dir=str(tmp_path), model="rf", cv=False,
                               tune=True, smote=False, version="tune1"))
    out = capsys.readouterr().out
    assert "Baseline (untuned, same split)" in out
    assert "0.8468" not in out and "default baseline metrics" not in out


# ── L11 ───────────────────────────────────────────────────────────────────────────────────────────────
def test_external_registry_pin_must_match(tmp_path, monkeypatch):
    _write_models(tmp_path)
    _register(tmp_path)
    good = pred_mod.file_sha256(tmp_path / "registry.json")
    monkeypatch.setenv("MODEL_REGISTRY_SHA256", "0" * 64)
    assert not _load(tmp_path)._loaded
    monkeypatch.setenv("MODEL_REGISTRY_SHA256", good.upper())
    p = _load(tmp_path)
    assert p._loaded and p.registry["registryPinned"] is True
    monkeypatch.delenv("MODEL_REGISTRY_SHA256")
    assert _load(tmp_path).registry["registryPinned"] is False


# ── L12 ───────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.skipif(not (ENGINE / "models" / "registry.json").exists(), reason="registered models not present")
def test_batch_scoring_is_one_forest_pass_and_matches_single_scoring():
    p = pred_mod.SentinelPredictor(model_dir=str(ENGINE / "models"))
    if not p._loaded:
        pytest.skip("registered models did not load")
    rng = np.random.default_rng(0)
    records = [dict(zip(FEATURE_NAMES[:43], rng.lognormal(3, 2, 43))) for _ in range(25)]
    with patch.object(p.rf, "predict_proba", wraps=p.rf.predict_proba) as proba:
        many = p.predict_many(records)
    assert proba.call_count == 1 and len(many) == 25
    for rec, got in zip(records, many):
        one = p.predict(rec)
        for key in ("predictedClass", "threatScore", "action", "anomalyScore", "classProbabilities", "featureVector"):
            assert got[key] == one[key], key


def test_batch_route_calls_predict_many_once(monkeypatch):
    calls = []

    class Batch:
        _loaded = True

        def predict_many(self, records, explain=False):
            calls.append(len(records))
            return [{"predictedClass": "BENIGN", "threatScore": 0.1, "action": "ALLOW", "inferenceTimeMs": 1.0,
                     "featureVector": None} for _ in records]

    monkeypatch.setattr(main, "predictor", Batch())
    body = TestClient(main.app).post("/predict/batch", headers=H, json=[{"flow_duration": i} for i in range(7)]).json()
    assert calls == [7] and body["total"] == 7
