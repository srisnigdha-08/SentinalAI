"""H2 (class provenance), H4 (CSV-named fields), H5 (anomaly review action)."""
import os
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from fastapi.testclient import TestClient  # noqa: E402

from inference import main  # noqa: E402
from inference import predictor as pred_mod  # noqa: E402
from inference.predictor import ANOMALY_THRESHOLD, IF_ANOMALY_SPAN, REVIEW_MIN_SIGNAL, SentinelPredictor  # noqa: E402
from utils.features import (  # noqa: E402
    FEATURE_NAMES, LABEL_MAP, LABEL_SOURCES, MIN_TRAINING_ROWS, RAW_LABEL_TO_TARGET, extract_features_from_record)

H = {"X-API-Key": os.environ["SENTINEL_KEY"]}


# ── H4 ────────────────────────────────────────────────────────────────────────────────────────────────
class Capture:
    _loaded = True

    def __init__(self):
        self.payloads = []

    def predict(self, record, explain=False):
        self.payloads.append(record)
        return {"predictedClass": "BENIGN", "threatScore": 0.1, "action": "ALLOW", "inferenceTimeMs": 1.0,
                "featureVector": None}

    def predict_many(self, records, explain=False):
        return [self.predict(r, explain) for r in records]


@pytest.fixture
def capture(monkeypatch):
    cap = Capture()
    monkeypatch.setattr(main, "predictor", cap)
    return cap


def test_csv_named_fields_reach_the_feature_vector(capture):
    r = TestClient(main.app).post("/predict/eval", headers=H, json={"Flow Duration": 24, "Total Fwd Packets": 3})
    assert r.status_code == 200
    vec = extract_features_from_record(capture.payloads[0])
    assert vec[FEATURE_NAMES.index("flow_duration")] == 24.0
    assert vec[FEATURE_NAMES.index("total_fwd_packets")] == 3.0
    defaulted = r.json()["result"]["defaultedFeatures"]
    assert "flow_duration" not in defaulted and "total_fwd_packets" not in defaulted
    assert "total_bwd_packets" in defaulted  # genuinely missing fields are still reported


def test_schema_name_wins_when_both_are_sent(capture):
    TestClient(main.app).post("/predict/internal", headers=H, json={"flow_duration": 7, "Flow Duration": 24})
    assert extract_features_from_record(capture.payloads[0])[FEATURE_NAMES.index("flow_duration")] == 7.0


def test_unsent_fields_keep_their_defaults(capture):
    TestClient(main.app).post("/predict/eval", headers=H, json={})
    assert capture.payloads[0]["flow_duration"] == 1000.0


@pytest.mark.parametrize("value", ["NaN", "Infinity", "bad"])
def test_non_finite_csv_named_value_is_rejected(capture, value):
    r = TestClient(main.app).post("/predict/eval", headers=H, json={"Flow Bytes/s": value})
    assert r.status_code == 422 and not capture.payloads


def test_batch_uses_aliases_too(capture):
    TestClient(main.app).post("/predict/batch", headers=H, json=[{"Flow Duration": 5}, {"flow_duration": 6}])
    got = [extract_features_from_record(p)[FEATURE_NAMES.index("flow_duration")] for p in capture.payloads]
    assert got == [5.0, 6.0]


# ── H5 ────────────────────────────────────────────────────────────────────────────────────────────────
def _predictor(proba, if_score):
    with patch.object(SentinelPredictor, "load"):
        p = SentinelPredictor()
    p._loaded = True
    p.rf = MagicMock(classes_=np.arange(len(proba)))
    p.rf.predict_proba.return_value = [proba]
    est = MagicMock()
    est.score_samples.return_value = [if_score]
    p.ifo = MagicMock(named_steps={"scaler": MagicMock(transform=lambda x: x), "if": est})
    return p


def _if_score_for_signal(sig):
    return ANOMALY_THRESHOLD - sig * IF_ANOMALY_SPAN


def test_strong_anomaly_classified_benign_goes_to_review_not_alert():
    r = _predictor([0.95, 0.05], _if_score_for_signal(min(1.0, REVIEW_MIN_SIGNAL + 0.1))).predict({})
    assert r["predictedClass"] == "Unknown" and r["action"] == "REVIEW"
    assert r["threatScore"] < pred_mod.MONITOR_THRESHOLD


def test_weak_anomaly_is_labelled_unknown_but_allowed():
    r = _predictor([0.95, 0.05], _if_score_for_signal(REVIEW_MIN_SIGNAL / 2)).predict({})
    assert r["predictedClass"] == "Unknown" and r["action"] == "ALLOW"


def test_inlier_benign_is_allowed_and_attacks_never_become_review():
    assert _predictor([0.95, 0.05], -0.40).predict({})["action"] == "ALLOW"
    attack = _predictor([0.02, 0.98], _if_score_for_signal(1.0)).predict({})
    assert attack["predictedClass"] != "Unknown" and attack["action"] == "BLOCK"


def test_review_level_is_published():
    assert _predictor([1.0, 0.0], -0.4).get_model_info()["thresholds"]["reviewMinAnomalySignal"] == REVIEW_MIN_SIGNAL


# ── H2 ────────────────────────────────────────────────────────────────────────────────────────────────
def test_every_class_and_raw_label_has_a_documented_source():
    assert set(LABEL_SOURCES) == set(LABEL_MAP)
    for target, raw in ((RAW_LABEL_TO_TARGET[k], k) for k in RAW_LABEL_TO_TARGET):
        assert raw in LABEL_SOURCES[target]["cicids"]
    assert LABEL_SOURCES["Data Exfiltration"]["cicids"] == []


def test_class_provenance_flags_classes_with_too_little_training_data():
    p = _predictor([0.5, 0.5, 0.0], -0.4)
    p.rf_meta = {"class_counts": {"train": {"BENIGN": 5000, "SSH Brute Force": MIN_TRAINING_ROWS - 1}}}
    prov = p.class_provenance()
    assert prov["BENIGN"]["sufficientTrainingData"] is True
    assert prov["SSH Brute Force"]["sufficientTrainingData"] is False
    assert prov["SQL Injection"]["trainingRows"] is None and prov["SQL Injection"]["sufficientTrainingData"] is None
    assert prov["SSH Brute Force"]["cicids"] == ["SSH-Patator"]


def test_prediction_of_a_low_data_class_is_flagged():
    p = _predictor([0.01, 0.01, 0.98], -0.4)
    p._low_data_classes = {"SQL Injection"}
    r = p.predict({})
    assert r["predictedClass"] == "SQL Injection" and r["lowTrainingDataClass"] is True


@pytest.mark.skipif(not (pred_mod.Path(__file__).resolve().parent.parent / "models" / "registry.json").exists(),
                    reason="registered models not present")
def test_served_model_marks_its_tiny_classes():
    p = SentinelPredictor(model_dir=str(pred_mod.Path(__file__).resolve().parent.parent / "models"))
    if not p._loaded:
        pytest.skip("registered models did not load")
    low = {n for n, v in p.class_provenance().items() if v["sufficientTrainingData"] is False}
    assert {"SQL Injection", "RCE Attempt", "Lateral Movement"} <= low
    assert "BENIGN" not in low and "DDoS" not in low


def test_isolation_forest_report_counts_the_review_queue():
    from evaluation.day_holdout_eval import isolation_forest_report
    y = np.array([0, 0, 0, 1, 1, 1])
    cls = np.array([0, 0, 0, 0, 1, 0])          # two attacks missed by the classifier
    sig = np.array([0.0, 0.7, 0.2, 0.9, 1.0, 0.0])
    rep = isolation_forest_report(y, cls, sig, review_level=0.5)
    assert rep["flag_rate_benign"] == pytest.approx(2 / 3) and rep["flag_rate_attack"] == pytest.approx(2 / 3)
    assert rep["review_queue_size"] == 2 and rep["review_rate_benign"] == pytest.approx(1 / 3)
    assert rep["attacks_missed_by_classifier"] == 2 and rep["missed_attacks_sent_to_review"] == 1
    assert rep["review_queue_attack_share"] == pytest.approx(0.5)
