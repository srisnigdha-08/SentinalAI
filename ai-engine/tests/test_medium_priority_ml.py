"""Medium-priority AI engine fixes: M1, M2, M5, M7, M8, M9 (M4 is in test_medium_fixes.py)."""
import argparse
import os
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from fastapi.testclient import TestClient  # noqa: E402

from inference import main  # noqa: E402
from inference import predictor as pred_mod  # noqa: E402
from monitoring import drift  # noqa: E402
from training import train as T  # noqa: E402
from utils.features import FEATURE_NAMES, prepare_features  # noqa: E402

H = {"X-API-Key": os.environ["SENTINEL_KEY"]}


# ── M1 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_severity_follows_the_operating_lines():
    b, m = pred_mod.BLOCK_THRESHOLD, pred_mod.MONITOR_THRESHOLD
    assert pred_mod.score_to_severity(b) == "CRITICAL"
    assert pred_mod.score_to_severity(m) == "HIGH"
    assert pred_mod.score_to_severity((m + pred_mod.SEVERITY_MEDIUM) / 2) == "MEDIUM"
    assert pred_mod.score_to_severity(0.1) == "LOW"


def test_engine_threat_counter_defaults_to_the_alert_line():
    if os.getenv("SCORE_THRESHOLD"):
        pytest.skip("SCORE_THRESHOLD overridden in this environment")
    assert main.THRESHOLD == pred_mod.MONITOR_THRESHOLD


# ── M2 ────────────────────────────────────────────────────────────────────────────────────────────────
class FixedPredictor:
    _loaded = True

    def __init__(self, action="BLOCK", score=0.99):
        self.action, self.score = action, score

    def predict(self, record, explain=False):
        return {"predictedClass": "DDoS", "threatScore": self.score, "action": self.action, "inferenceTimeMs": 1.0,
                "featureVector": None}


def _full_record():
    return {f: 1.0 for f in FEATURE_NAMES if f not in ("payload_entropy", "time_of_day_sin", "time_of_day_cos")}


def test_incomplete_input_never_blocks(monkeypatch):
    monkeypatch.setattr(main, "predictor", FixedPredictor())
    r = TestClient(main.app).post("/predict/internal", headers=H, json={"flow_duration": 5}).json()["result"]
    assert r["incompleteInput"] is True and r["action"] == "MONITOR" and r["actionCappedReason"] == "incomplete_input"
    assert len(r["defaultedFeatures"]) > main.MAX_DEFAULTED_FEATURES


def test_complete_input_keeps_its_action(monkeypatch):
    monkeypatch.setattr(main, "predictor", FixedPredictor())
    r = TestClient(main.app).post("/predict/internal", headers=H, json=_full_record()).json()["result"]
    assert r["incompleteInput"] is False and r["action"] == "BLOCK" and r["defaultedFeatures"] == []


def test_csv_named_features_count_as_sent(monkeypatch):
    monkeypatch.setattr(main, "predictor", FixedPredictor())
    rec = _full_record()
    rec.pop("init_win_bytes_forward")
    rec["Init_Win_bytes_forward"] = 8192
    r = TestClient(main.app).post("/predict/eval", headers=H, json=rec).json()["result"]
    assert "init_win_bytes_forward" not in r["defaultedFeatures"]


def test_features_outside_the_record_model_are_counted_when_missing(monkeypatch):
    monkeypatch.setattr(main, "predictor", FixedPredictor(action="ALLOW", score=0.1))
    rec = _full_record()
    for f in ("active_mean", "idle_std"):
        rec.pop(f)
    r = TestClient(main.app).post("/predict/eval", headers=H, json=rec).json()["result"]
    assert set(r["defaultedFeatures"]) == {"active_mean", "idle_std"} and r["incompleteInput"] is False


# ── M5 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_unmapped_label_raises_instead_of_becoming_benign():
    df = pd.DataFrame({"Flow Duration": [1, 2], "Label": ["BENIGN", "Web Attack – Brute Force"]})
    with pytest.raises(ValueError, match="unmapped label"):
        prepare_features(df)


def test_known_labels_still_map():
    df = pd.DataFrame({"Flow Duration": [1, 2], "Label": ["BENIGN", "PortScan"]})
    _, y = prepare_features(df)
    assert y.tolist() == [0, 3]


# ── M7 ────────────────────────────────────────────────────────────────────────────────────────────────
def _reference(n=4000, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.lognormal(3, 1, (n, len(FEATURE_NAMES)))
    X[:, FEATURE_NAMES.index("time_of_day_sin")] = 0.0
    return X, drift.benign_reference(X)


def test_psi_is_small_for_the_same_distribution_and_large_for_a_shift():
    X, ref = _reference()
    j = 0
    same = np.bincount(drift._bin_index(_reference(seed=1)[0][:, j], ref["edges"][j]), minlength=len(ref["edges"][j]) + 1)
    assert drift.psi(ref["fractions"][j], same / same.sum()) < 0.05
    shifted = np.bincount(drift._bin_index(X[:, j] * 10, ref["edges"][j]), minlength=len(ref["edges"][j]) + 1)
    assert drift.psi(ref["fractions"][j], shifted / shifted.sum()) > drift.PSI_LIMIT


def test_psi_report_uses_only_benign_predicted_flows_and_skips_constant_features():
    X, ref = _reference()
    m = drift.DriftMonitor(window=1000, min_samples=100)
    for v in _reference(n=300, seed=2)[0]:
        m.record(v, "BENIGN")
    for v in X[:300] * 50:  # wildly different, but predicted as attacks: must not count
        m.record(v, "DDoS")
    rep = m.report_psi(ref, FEATURE_NAMES)
    assert rep["method"] == "psi_benign_quantiles" and rep["benign_samples"] == 300 and rep["status"] == "ok"
    assert "time_of_day_sin" not in {r["feature"] for r in rep["top_shifts"]}
    assert rep["informative_features"] == len(FEATURE_NAMES) - 1
    m2 = drift.DriftMonitor(window=1000, min_samples=100)
    for v in _reference(n=300, seed=3)[0] * 20:
        m2.record(v, "BENIGN")
    assert m2.report_psi(ref, FEATURE_NAMES)["status"] == "drift"


def test_drift_endpoint_prefers_the_benign_reference(monkeypatch):
    _, ref = _reference()
    p = MagicMock(_loaded=True, rf_meta={"drift_reference": ref}, registry={"classifier": "x.pkl"})
    monkeypatch.setattr(main, "predictor", p)
    monkeypatch.setattr(main, "drift_monitor", drift.DriftMonitor(window=100, min_samples=5))
    for v in _reference(n=50, seed=4)[0]:
        main.drift_monitor.record(v, "BENIGN")
    body = TestClient(main.app).get("/model/drift", headers=H).json()
    assert body["method"] == "psi_benign_quantiles" and body["status"] in ("ok", "drift")


# ── M8 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_smote_strategy_targets_only_the_thin_classes():
    y = np.array([0] * 50 + [6] * 10 + [7] * 5000)
    assert T.smote_strategy(y) == {7: 5001, 6: 1500}


def test_cross_validation_runs_on_the_training_split_with_the_recipe(tmp_path, monkeypatch, capsys):
    monkeypatch.setitem(T.RF_PARAMS, "n_estimators", 5)
    monkeypatch.setitem(T.IF_PARAMS, "n_estimators", 5)
    seen = []
    real = T.RandomForestClassifier.fit

    def spy(self, X, y, *a, **k):
        seen.append(len(y))
        return real(self, X, y, *a, **k)

    monkeypatch.setattr(T.RandomForestClassifier, "fit", spy)
    T.train(argparse.Namespace(data=None, synthetic=True, rows=1500, model_dir=str(tmp_path), model="rf", cv=True,
                               tune=False, smote=False, version="cv1"))
    out = capsys.readouterr().out
    assert "training split only" in out
    final, folds = seen[0], seen[1:6]
    assert len(folds) == 5 and all(f < final for f in folds)  # 4/5 of the training split, never the full data


# ── M9 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_reload_requires_the_admin_key_when_configured(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_KEY", "admin-secret-for-tests")
    client = TestClient(main.app)
    assert client.post("/model/reload", headers=H).status_code == 403
    assert client.post("/model/reload", headers={**H, "X-Admin-Key": "wrong"}).status_code == 403
    with patch.object(main, "SentinelPredictor") as cls:
        cls.return_value = MagicMock(_loaded=True, registry={}, get_model_info=lambda: {})
        r = client.post("/model/reload", headers={**H, "X-Admin-Key": "admin-secret-for-tests"})
    assert r.status_code == 200


def test_reload_without_an_admin_key_configured_accepts_the_service_key(monkeypatch):
    monkeypatch.setattr(main, "ADMIN_KEY", None)
    with patch.object(main, "SentinelPredictor") as cls:
        cls.return_value = MagicMock(_loaded=True, registry={}, get_model_info=lambda: {})
        assert TestClient(main.app).post("/model/reload", headers=H).status_code == 200
    assert TestClient(main.app).post("/model/reload").status_code == 401
