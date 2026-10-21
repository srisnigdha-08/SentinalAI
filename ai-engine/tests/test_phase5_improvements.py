"""Phase 5 improvements: U3 history, P5 golden set, P4 metrics, U5 global SHAP, U6 UCB1, U7 calibration, M-5 XGB."""
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import joblib
import numpy as np
import pytest

os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from fastapi.testclient import TestClient  # noqa: E402
from sklearn.ensemble import IsolationForest, RandomForestClassifier  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

from evaluation import day_holdout_eval as ev  # noqa: E402
from inference import main  # noqa: E402
from inference import model_checks as mc  # noqa: E402
from inference.predictor import SentinelPredictor, file_sha256  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402

ENGINE = Path(__file__).resolve().parent.parent
H = {"X-API-Key": os.environ["SENTINEL_KEY"]}


def _tiny_models(model_dir: Path, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.lognormal(3, 1, (300, len(FEATURE_NAMES)))
    y = (X[:, 0] > np.median(X[:, 0])).astype(int) * 3  # BENIGN (0) vs Port Scan (3)
    clf = Pipeline([("scaler", StandardScaler()), ("rf", RandomForestClassifier(n_estimators=5, random_state=seed))]).fit(X, y)
    ifo = Pipeline([("scaler", StandardScaler()), ("if", IsolationForest(n_estimators=5, random_state=seed))]).fit(X[y == 0])
    joblib.dump(clf, model_dir / "clf_t.pkl")
    joblib.dump(ifo, model_dir / "if_t.pkl")
    return clf, ifo


def _register(model_dir: Path, note="test"):
    subprocess.run([sys.executable, str(ENGINE / "training" / "register_model.py"), "--model-dir", str(model_dir),
                    "--classifier", "clf_t.pkl", "--anomaly", "if_t.pkl", "--note", note],
                   check=True, capture_output=True, text=True)


# ── P5 golden set + U3 history ─────────────────────────────────────────────────────────────────────────
def test_registration_writes_golden_set_and_history_and_the_engine_verifies_it(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_UNREGISTERED_MODELS", raising=False)
    _tiny_models(tmp_path)
    _register(tmp_path, note="first")
    reg = json.loads((tmp_path / "registry.json").read_text())
    assert reg["golden"]["file"] == mc.GOLDEN_FILE and reg["golden"]["rows"] == mc.GOLDEN_ROWS
    p = SentinelPredictor(model_dir=str(tmp_path))
    assert p._loaded and "golden rows reproduced" in p.registry["goldenCheck"]
    hist = mc.read_history(tmp_path)
    assert len(hist) == 1 and hist[0]["note"] == "first" and hist[0]["classifier"]["file"] == "clf_t.pkl"
    _register(tmp_path, note="second")
    assert [h["note"] for h in mc.read_history(tmp_path)] == ["first", "second"]
    assert [h["note"] for h in p.get_model_info()["lineage"]][-1:] in (["first"], ["second"])


def test_engine_refuses_when_the_golden_outputs_do_not_reproduce(tmp_path, monkeypatch):
    monkeypatch.delenv("ALLOW_UNREGISTERED_MODELS", raising=False)
    _tiny_models(tmp_path)
    _register(tmp_path)
    golden = json.loads((tmp_path / mc.GOLDEN_FILE).read_text())
    golden["expected"]["if_scores"][0] += 0.01  # as if the environment computed differently
    (tmp_path / mc.GOLDEN_FILE).write_text(json.dumps(golden))
    # the file hash no longer matches the registry -> refused
    assert not SentinelPredictor(model_dir=str(tmp_path))._loaded
    # and even with a re-pinned hash the outputs themselves are rejected
    reg = json.loads((tmp_path / "registry.json").read_text())
    reg["golden"]["sha256"] = file_sha256(tmp_path / mc.GOLDEN_FILE)
    (tmp_path / "registry.json").write_text(json.dumps(reg))
    assert not SentinelPredictor(model_dir=str(tmp_path))._loaded


def test_verify_golden_detects_a_different_model(tmp_path):
    clf, ifo = _tiny_models(tmp_path, seed=0)
    golden = mc.build_golden(clf, ifo, len(FEATURE_NAMES))
    assert mc.verify_golden(clf, ifo, golden)[0]
    other_clf, other_ifo = _tiny_models(tmp_path, seed=1)
    assert not mc.verify_golden(other_clf, other_ifo, golden)[0]


@pytest.mark.skipif(not (ENGINE / "models" / "registry.json").exists(), reason="registered models not present")
def test_shipped_registry_has_a_golden_set_and_history():
    reg = json.loads((ENGINE / "models" / "registry.json").read_text())
    assert reg.get("golden", {}).get("file") == mc.GOLDEN_FILE
    assert len(mc.read_history(ENGINE / "models", last=100)) >= 3


# ── P4 metrics ─────────────────────────────────────────────────────────────────────────────────────────
def test_metrics_export_actions_and_a_threat_score_histogram(monkeypatch):
    monkeypatch.setattr(main, "stats", {**main.stats, "actions": main.defaultdict(int),
                                        "score_buckets": main.defaultdict(int), "score_sum": 0.0, "incomplete": 0,
                                        "classes": main.defaultdict(int), "total": 0, "threats": 0, "blocked": 0,
                                        "time_sum_ms": 0.0})
    for score, action in ((0.05, "ALLOW"), (0.95, "BLOCK"), (0.91, "MONITOR")):
        main._upd_unlocked({"predictedClass": "DDoS", "threatScore": score, "action": action, "featureVector": None,
                            "incompleteInput": action == "MONITOR"})
    monkeypatch.setenv("METRICS_TOKEN", "metrics-test-token")
    body = TestClient(main.app).get("/metrics", headers={"Authorization": "Bearer metrics-test-token"}).text
    assert 'sentinel_ai_actions_total{action="BLOCK"} 1' in body
    assert 'sentinel_ai_threat_score_bucket{le="0.1"} 1' in body
    assert 'sentinel_ai_threat_score_bucket{le="0.92"} 2' in body
    assert 'sentinel_ai_threat_score_bucket{le="+Inf"} 3' in body
    assert "sentinel_ai_incomplete_input_total 1" in body


# ── U5 global SHAP ─────────────────────────────────────────────────────────────────────────────────────
def test_global_explanation_aggregates_recent_flows_by_class(monkeypatch):
    stub = MagicMock(_loaded=True, explainer=object())
    stub._classify_many.return_value = (np.array([0, 3, 3]), None, np.array([0, 1, 1]))
    contrib = np.zeros((3, len(FEATURE_NAMES)))
    contrib[:, 5] = [1.0, 3.0, 5.0]
    contrib[1:, 7] = 2.0
    stub.shap_for_classes.return_value = contrib
    monkeypatch.setattr(main, "predictor", stub)
    monitor = main.DriftMonitor(window=10, min_samples=1)
    for _ in range(3):
        monitor.record(np.ones(len(FEATURE_NAMES)), "x")
    monkeypatch.setattr(main, "drift_monitor", monitor)
    body = TestClient(main.app).get("/model/explain/global", headers=H).json()
    assert body["samples"] == 3 and body["overall"][0]["feature"] == FEATURE_NAMES[5]
    assert body["by_class"]["Port Scan"]["samples"] == 2 and body["by_class"]["BENIGN"]["samples"] == 1
    assert body["by_class"]["Port Scan"]["top"][0] == {"feature": FEATURE_NAMES[5], "mean_abs_shap": 4.0}


def test_global_explanation_requires_an_explainer(monkeypatch):
    monkeypatch.setattr(main, "predictor", MagicMock(_loaded=True, explainer=None))
    assert TestClient(main.app).get("/model/explain/global", headers=H).status_code == 501


# ── U6 UCB1 ────────────────────────────────────────────────────────────────────────────────────────────
def test_ucb1_tries_every_persona_then_prefers_the_best(tmp_path, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "100000")
    learner = ds.DeceptionQLearner(q_table_path=str(tmp_path / "q.json"))
    learner.policy = "ucb1"
    seen = []
    servable = ds.servable_profiles()  # windows_srv is never recommended (H5): Cowrie cannot serve it
    for _ in range(len(servable)):
        a = learner.choose_action("ubuntu_22")
        seen.append(a)
        learner.update("ubuntu_22", a, 18.0 if a == "centos_7" else 1.0, a)
    assert sorted(seen) == sorted(servable)  # each servable persona once before any repeat
    for _ in range(200):
        a = learner.choose_action("ubuntu_22")
        learner.update("ubuntu_22", a, 18.0 if a == "centos_7" else 1.0, a)
    assert learner.greedy_action("ubuntu_22") == "centos_7"
    pulls = {a: st["n"] for a, st in learner.arm_stats.items()}
    assert max(pulls, key=pulls.get) == "centos_7" and pulls["centos_7"] > sum(pulls.values()) / 2  # exploitation dominates
    assert all(learner.arm_stats[a]["n"] >= 2 for a in servable)  # but nothing servable is abandoned
    assert learner.arm_stats["windows_srv"]["n"] == 0


def test_arm_statistics_persist_and_are_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("Q_SAVE_EVERY", "1")
    path = tmp_path / "q.json"
    learner = ds.DeceptionQLearner(q_table_path=str(path))
    learner.update("ubuntu_22", "aws_ec2", 20.0, "aws_ec2")
    reloaded = ds.DeceptionQLearner(q_table_path=str(path))
    assert reloaded.arm_stats["aws_ec2"] == {"n": 1, "mean": 1.0}
    stats = reloaded.get_stats()
    assert stats["policy"] in ds.POLICIES and stats["armStats"]["aws_ec2"]["n"] == 1


# ── U7 calibration ─────────────────────────────────────────────────────────────────────────────────────
def test_calibration_report_separates_calibrated_from_overconfident():
    rng = np.random.default_rng(0)
    p = rng.random(20000)
    y = rng.random(20000) < p  # calibrated by construction
    good = ev.calibration_report(p, y)
    bad = ev.calibration_report(np.where(p > 0.5, 0.99, 0.01), y)
    assert good["ece"] < 0.02 < bad["ece"] and good["brier"] < bad["brier"]
    assert sum(r["n"] for r in good["reliability"]) == 20000


# ── M-5 XGBoost in the honest evaluator ────────────────────────────────────────────────────────────────
def test_encoded_xgb_keeps_original_labels_when_classes_are_missing():
    rng = np.random.default_rng(0)
    X = rng.random((120, 4))
    y = np.repeat([0, 3, 8], 40)  # a leave-one-day-out fold can lack classes in between
    m = ev.EncodedXGB(n_estimators=5, max_depth=2, random_state=0).fit(X, y)
    assert m.classes_.tolist() == [0, 3, 8]
    assert m.predict_proba(X).shape == (120, 3) and set(m.predict(X)) <= {0, 3, 8}
