"""Improvement round: drift monitoring, hot model reload, deception recommendation, metrics and request ids,
retraining (sample loading, gate, promotion) and the sniffer's live-detection mapping."""
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"

with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    from inference import main

from monitoring.drift import DriftMonitor  # noqa: E402
from training import retrain_from_samples as retrain  # noqa: E402
from utils.features import FEATURE_NAMES, FEATURE_SCHEMA_VERSION  # noqa: E402

KEY = {"X-API-Key": "test-sentinel-secret-key-12345"}


# ── Drift ─────────────────────────────────────────────────────────────────────
def test_drift_reports_insufficient_data_then_ok_then_drift():
    rng = np.random.default_rng(0)
    mean, var = np.zeros(5), np.ones(5)
    names = [f"f{i}" for i in range(5)]
    m = DriftMonitor(window=500, min_samples=100)
    for v in rng.normal(0, 1, (50, 5)):
        m.record(v)
    assert m.report(mean, var, names)["status"] == "insufficient_data"
    for v in rng.normal(0, 1, (300, 5)):
        m.record(v, "BENIGN")
    ok = m.report(mean, var, names)
    assert ok["status"] == "ok" and ok["drifted_features"] == [] and ok["recent_class_mix"]["BENIGN"] == 300
    for v in rng.normal(3, 1, (500, 5)):  # shifted by 3 sd
        m.record(v, "DDoS")
    drift = m.report(mean, var, names)
    assert drift["status"] == "drift" and set(drift["drifted_features"]) == set(names)
    assert drift["top_shifts"][0]["mean_shift_sd"] > 2


def test_zero_variance_features_are_ignored_and_bad_vectors_dropped():
    m = DriftMonitor(window=200, min_samples=10)
    for _ in range(20):
        m.record([0.0, 5.0])  # second feature constant in training (var 0) but 5 live
    m.record([float("nan"), 1.0])
    report = m.report([0.0, 0.0], [1.0, 0.0], ["a", "b"])
    assert report["samples"] == 20 and report["informative_features"] == 1 and "b" not in report["drifted_features"]


def _fake_predictor(loaded=True, registry=None):
    p = MagicMock()
    p._loaded = loaded
    p.registry = registry or {"classifier": "rf_x.pkl"}
    scaler = MagicMock(mean_=np.zeros(len(FEATURE_NAMES)), var_=np.ones(len(FEATURE_NAMES)))
    p.clf.named_steps = {"scaler": scaler}
    p.get_model_info.return_value = {"registry": p.registry, "thresholds": {"monitor": 0.90}}
    return p


def test_drift_endpoint_requires_key_and_reports(monkeypatch):
    monkeypatch.setattr(main, "predictor", _fake_predictor())
    monkeypatch.setattr(main, "drift_monitor", DriftMonitor(window=100, min_samples=5))
    rng = np.random.default_rng(1)
    for _ in range(100):  # drawn from the reference distribution N(0, 1)
        main.drift_monitor.record(rng.normal(0, 1, len(FEATURE_NAMES)), "BENIGN")
    client = TestClient(main.app)
    assert client.get("/model/drift").status_code == 401
    body = client.get("/model/drift", headers=KEY).json()
    assert body["status"] == "ok" and body["model"] == "rf_x.pkl" and body["samples"] == 100


# ── Hot reload ────────────────────────────────────────────────────────────────
def test_reload_swaps_only_a_verified_predictor(monkeypatch):
    old = _fake_predictor(registry={"classifier": "old.pkl"})
    monkeypatch.setattr(main, "predictor", old)
    client = TestClient(main.app)

    with patch.object(main, "SentinelPredictor", return_value=_fake_predictor(loaded=False)):
        r = client.post("/model/reload", headers=KEY)
    assert r.status_code == 409 and main.predictor is old  # failed load keeps serving the old model

    new = _fake_predictor(registry={"classifier": "new.pkl"})
    with patch.object(main, "SentinelPredictor", return_value=new):
        r = client.post("/model/reload", headers=KEY)
    assert r.status_code == 200 and main.predictor is new
    assert r.json()["previous"]["registry"]["classifier"] == "old.pkl"


# ── Deception recommendation ──────────────────────────────────────────────────
def test_recommendation_uses_the_learner_and_validates_profile(monkeypatch, tmp_path):
    from inference import deception
    monkeypatch.setattr(deception, "_scorer", None)
    monkeypatch.setenv("DEFAULT_RUNTIME_Q_TABLE_PATH", str(tmp_path / "q.json"))
    client = TestClient(main.app)
    assert client.get("/deception/recommendation", params={"current": "nope"}, headers=KEY).status_code == 422
    body = client.get("/deception/recommendation", params={"current": "centos_7"}, headers=KEY).json()
    assert body["current"] == "centos_7"
    assert body["nextProfile"] in ("ubuntu_22", "debian_11", "centos_7", "windows_srv", "aws_ec2", "raspberry_pi")
    assert isinstance(body["explored"], bool)


# ── Metrics and request ids ───────────────────────────────────────────────────
def test_metrics_require_token_when_configured(monkeypatch):
    monkeypatch.setattr(main, "predictor", _fake_predictor())
    client = TestClient(main.app)
    monkeypatch.setenv("METRICS_TOKEN", "scrape-token-123")
    assert client.get("/metrics").status_code == 403
    r = client.get("/metrics", headers={"Authorization": "Bearer scrape-token-123"})
    assert r.status_code == 200 and "sentinel_ai_model_loaded 1" in r.text
    monkeypatch.delenv("METRICS_TOKEN")
    assert client.get("/metrics").status_code == 403  # TestClient is not loopback


def test_request_id_is_echoed_or_generated():
    client = TestClient(main.app)
    assert client.get("/health", headers={"X-Request-Id": "abc12345-req"}).headers["x-request-id"] == "abc12345-req"
    generated = client.get("/health", headers={"X-Request-Id": "bad id with spaces"}).headers["x-request-id"]
    assert generated != "bad id with spaces" and len(generated) == 32


# ── Retraining ────────────────────────────────────────────────────────────────
def test_load_samples_keeps_only_valid_schema_rows(tmp_path):
    good = {"label": "DDoS", "featureVector": [1.0] * len(FEATURE_NAMES), "featureSchemaVersion": FEATURE_SCHEMA_VERSION}
    rows = [good, {**good, "label": "NotAClass"}, {**good, "featureSchemaVersion": "v1"},
            {**good, "featureVector": [1.0] * 5}, {**good, "featureVector": [float("inf")] * len(FEATURE_NAMES)}]
    path = tmp_path / "s.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows))
    df = retrain.load_samples(path)
    assert len(df) == 1 and df.iloc[0]["target"] == "DDoS" and df.iloc[0]["file"] == "analyst_samples"


def _metrics(f1, fpr):
    return {"f1_macro": f1, "score_rules": {"current": {"threat_raised": {"benign_fpr": fpr}}}}


def test_gate_blocks_regressions():
    assert retrain.gate(_metrics(0.80, 0.0005), _metrics(0.80, 0.0005))["passed"]
    assert not retrain.gate(_metrics(0.78, 0.0005), _metrics(0.80, 0.0005))["passed"]  # macro F1 drop > 0.005
    assert not retrain.gate(_metrics(0.85, 0.002), _metrics(0.80, 0.0005))["passed"]  # more false alerts than baseline
    # An unchanged recipe passes even when the absolute 0.1 % target is out of reach (U1 dry run)
    same = retrain.gate(_metrics(0.77, 0.0016), _metrics(0.77, 0.0016))
    assert same["passed"] and same["meets_alert_fpr_target"] is False
    assert retrain.gate(_metrics(0.80, 0.0017), _metrics(0.80, 0.0016))["passed"]  # within the tolerance


def test_promote_writes_new_files_and_repins_registry(tmp_path):
    out, models = tmp_path / "cand", tmp_path / "models"
    out.mkdir(); models.mkdir()
    # Real (tiny) models: promotion scores the golden set with them (P5)
    from tests.test_phase5_improvements import _tiny_models
    _tiny_models(out)
    (out / "clf_t.pkl").rename(out / "rf_classifier.pkl")
    (out / "if_t.pkl").rename(out / "isolation_forest.pkl")
    (models / "registry.json").write_text('{"previous": true}')
    report = {"trained_at": "t", "analyst_samples": 3,
              "candidate": {"accuracy": 0.9, "f1_weighted": 0.9, "f1_macro": 0.8}}
    reg = retrain.promote(out, models, "retrained_test", report)
    assert reg["classifier"]["file"] == "rf_classifier_retrained_test.pkl"
    assert json.loads((models / "registry.json").read_text())["anomaly"]["file"] == "isolation_forest_retrained_test.pkl"
    assert json.loads((out / "registry.previous.json").read_text()) == {"previous": True}  # rollback copy
    assert reg["golden"]["file"] == "golden_set.json" and (models / "golden_set.json").exists()
    assert "retrain_from_samples.py --promote" in (models / "registry_history.jsonl").read_text()
    with pytest.raises(SystemExit):
        retrain.promote(out, models, "retrained_test", report)  # never overwrites


# ── Sniffer mapping ───────────────────────────────────────────────────────────
def test_cicflowmeter_row_maps_to_detection_payload():
    spec = importlib.util.spec_from_file_location("flow_mapping", ENGINE.parent / "honeypot/sniffer/flow_mapping.py")
    fm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fm)
    row = {"src_ip": "198.51.100.4", "dst_ip": "10.0.0.5", "timestamp": "2026-10-21 10:00:00",
           "flow_duration": "1200", "tot_fwd_pkts": "3", "syn_flag_cnt": "1", "init_fwd_win_byts": "29200",
           "flow_byts_s": "inf", "unrelated": "x"}
    payload = fm.to_detection_payload(row)
    assert payload["sourceIP"] == "198.51.100.4" and payload["destinationIP"] == "10.0.0.5"
    assert payload["timestamp"].startswith("2026-10-21T10:00:00")
    assert payload["total_fwd_packets"] == 3.0 and payload["init_win_bytes_forward"] == 29200.0
    assert "flow_bytes_per_sec" not in payload and "unrelated" not in payload  # non-finite / unknown dropped
    assert fm.to_detection_payload({"flow_duration": "1"}) is None
