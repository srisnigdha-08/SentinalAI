"""Rank 8: network-flow model reliability, on the frozen production model (read-only).

Class support and unmodelled classes, time-of-day extraction (valid / missing / invalid / time zones / boundaries /
feature order), proof that time-of-day values cannot change a prediction (golden vectors and full records), the
golden set still reproduced, canonical XGBoost naming with legacy fields kept, and the reproducible, cached
reference global SHAP summary. The model directory is hashed before and after: nothing in it changes.
"""
import hashlib
import json
import math
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from inference.model_checks import golden_outputs, verify_golden  # noqa: E402
from inference.predictor import SentinelPredictor  # noqa: E402
from utils.features import (FEATURE_NAMES, FEATURE_SCHEMA_VERSION, LABEL_MAP, compute_time_of_day,  # noqa: E402
                            extract_features_from_record)

MODELS = ENGINE / "models"
GOLDEN = json.loads((MODELS / "golden_set.json").read_text(encoding="utf-8"))
SIN, COS = FEATURE_NAMES.index("time_of_day_sin"), FEATURE_NAMES.index("time_of_day_cos")


def _models_hash():
    h = hashlib.sha256()
    for p in sorted(MODELS.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(MODELS).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


MODELS_BEFORE = _models_hash()


@pytest.fixture(autouse=True, scope="module")
def models_unchanged():
    yield
    assert _models_hash() == MODELS_BEFORE


@pytest.fixture(scope="module")
def real():
    p = SentinelPredictor(model_dir=str(MODELS))
    if not p._loaded:
        pytest.skip("served model not available")
    return p


# ── schema and golden set ────────────────────────────────────────────────────────────────────────────────────────
def test_feature_order_and_schema_are_unchanged():
    assert len(FEATURE_NAMES) == 53 and FEATURE_SCHEMA_VERSION == "v2.1_53feat"
    assert (SIN, COS) == (51, 52)
    meta = json.loads((MODELS / "xgb_classifier_xgb_cicids_v1_meta.json").read_text(encoding="utf-8"))
    assert meta["feature_names"] == FEATURE_NAMES and meta["n_features"] == 53


def test_the_golden_set_is_still_reproduced(real):
    ok, msg = verify_golden(real.clf, real.ifo, GOLDEN)
    assert ok, msg


# ── class support / Data Exfiltration ────────────────────────────────────────────────────────────────────────────
def test_class_support_covers_every_label_with_real_counts(real):
    s = real.class_support()
    assert set(s) == set(LABEL_MAP)
    meta = real.rf_meta["class_counts"]
    for name, v in s.items():
        assert v["trainingRows"] == meta["train"].get(name, 0) and v["testRows"] == meta["test"].get(name, 0)
    assert {n for n, v in s.items() if v["status"] == "low_support"} == {"SQL Injection", "RCE Attempt", "Lateral Movement"}
    assert all(v["trainingRows"] < v["minimumTrainingRows"] for v in s.values() if v["status"] == "low_support")


def test_data_exfiltration_is_unmodeled_and_never_predicted(real):
    s = real.class_support()["Data Exfiltration"]
    assert s == {**s, "status": "unmodeled", "canBePredicted": False, "trainingRows": 0, "labelIndex": 10}
    assert LABEL_MAP["Data Exfiltration"] not in set(int(c) for c in real.clf.classes_)
    X = np.asarray(GOLDEN["vectors"], dtype=float)
    rng = np.random.default_rng(0)
    probe = np.vstack([X, np.abs(rng.normal(0, 5, (500, X.shape[1]))) * np.abs(X).max(axis=0)])
    assert real.clf.predict_proba(probe).shape[1] == 10
    assert LABEL_MAP["Data Exfiltration"] not in set(int(c) for c in real.clf.predict(probe))
    info = real.get_model_info()
    assert info["unmodeledClasses"] == ["Data Exfiltration"]


# ── naming (XGBoost) with backward compatibility ────────────────────────────────────────────────────────────────
def test_canonical_names_and_legacy_fields(real):
    info = real.get_model_info()
    assert info["classifierType"] == "xgboost" and real.model_type == "xgboost"
    assert info["classifierVersion"] == info["rfVersion"] == "xgb_cicids_v1"
    assert info["classifierMetrics"] == info["rfMetrics"]
    assert info["legacyFieldNames"] == {"rfVersion": "classifierVersion", "rfMetrics": "classifierMetrics"}
    assert real.classifier_meta is real.rf_meta and real.rf is real.clf
    assert real.registry["classifier"] == "xgb_classifier_xgb_cicids_v1.pkl"  # artifact name unchanged


# ── time of day ──────────────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ts,expected", [
    ("2026-11-18T00:00:00Z", (0.0, 1.0)),
    ("2026-11-18T06:00:00Z", (1.0, 0.0)),
    ("2026-11-18T12:00:00Z", (0.0, -1.0)),
    ("2026-11-18T18:00:00Z", (-1.0, 0.0)),
    ("2026-11-18T05:30:00+05:30", (0.0, 1.0)),       # 00:00 UTC
    ("2026-11-18T00:00:00", (0.0, 1.0)),              # naive -> UTC
    (0, (0.0, 1.0)), (21600, (1.0, 0.0)),             # epoch seconds, UTC
])
def test_valid_timestamps_and_time_zones(ts, expected):
    s, c = compute_time_of_day(ts)
    assert math.isclose(s, expected[0], abs_tol=1e-9) and math.isclose(c, expected[1], abs_tol=1e-9)


def test_boundary_just_before_midnight():
    s, c = compute_time_of_day("2026-11-18T23:59:59Z")
    assert s < 0 and c > 0.9999 and math.isclose(s * s + c * c, 1.0, abs_tol=1e-9)


@pytest.mark.parametrize("bad", [None, "", "not a time", "2026-13-45T99:99:99Z", float("nan"), float("inf"), 1e30, [], {}])
def test_missing_or_invalid_timestamps_keep_the_trained_default(bad):
    assert compute_time_of_day(bad) == (0.0, 0.0)


def test_extraction_places_time_of_day_at_its_fixed_positions():
    base = {n: 1.0 for n in FEATURE_NAMES}
    v0 = extract_features_from_record(dict(base))
    v1 = extract_features_from_record({**base, "timestamp": "2026-11-18T06:00:00Z"})
    v0, v1 = np.ravel(v0), np.ravel(v1)
    assert len(v0) == len(v1) == 53
    assert (v0[SIN], v0[COS]) == (0.0, 0.0) and math.isclose(v1[SIN], 1.0, abs_tol=1e-9)
    assert np.array_equal(np.delete(v0, [SIN, COS]), np.delete(v1, [SIN, COS]))


def test_model_facts_say_time_of_day_cannot_influence_predictions(real):
    lim = real.feature_limitations()
    for f in ("time_of_day_sin", "time_of_day_cos"):
        assert lim[f]["trainingValueConstant"] is True and lim[f]["importance"] == 0.0
        assert lim[f]["influencesPredictions"] is False


@pytest.mark.parametrize("hour", [0, 3, 6, 9, 12, 15, 18, 21, 23.99])
def test_time_of_day_values_never_change_a_golden_prediction(real, hour):
    X = np.asarray(GOLDEN["vectors"], dtype=float)
    want = golden_outputs(real.clf, real.ifo, X)
    theta = 2 * math.pi * hour / 24
    Xt = X.copy()
    Xt[:, SIN], Xt[:, COS] = math.sin(theta), math.cos(theta)
    got = golden_outputs(real.clf, real.ifo, Xt)
    assert got["classes"] == want["classes"]
    assert np.allclose(got["proba"], want["proba"], atol=0, rtol=0)


def test_time_of_day_never_changes_a_full_record_prediction(real):
    for vec in GOLDEN["vectors"][:10]:
        record = dict(zip(FEATURE_NAMES, vec))
        a = real.predict(dict(record))
        b = real.predict({**record, "timestamp": "2026-11-18T14:37:00Z"})
        assert (a["predictedClass"], a["threatScore"]) == (b["predictedClass"], b["threatScore"])


# ── reference global SHAP (reproducible, cached, invalidated on change) ─────────────────────────────────────────
@pytest.fixture
def engine(real, monkeypatch):
    os.environ.setdefault("SENTINEL_KEY", "test-sentinel-secret-key-12345")  # same dummy key as the other engine tests
    with patch("inference.predictor.SentinelPredictor.load"), patch("inference.predictor.SentinelPredictor.init_explainer"), \
         patch("joblib.load", return_value=MagicMock()):
        import inference.main as main
    if real.explainer is None:
        pytest.skip("SHAP explainer not available")
    monkeypatch.setattr(main, "predictor", real)
    return main


def test_reference_summary_is_deterministic_cached_and_traceable(engine, tmp_path):
    a = engine.reference_global_shap(tmp_path / "a")
    b = engine.reference_global_shap(tmp_path / "a")
    c = engine.reference_global_shap(tmp_path / "c")
    assert a["cache"] == "miss" and b["cache"] == "hit" and c["cache"] == "miss"
    for k in ("overall", "by_class", "samples"):
        assert a[k] == b[k] == c[k]
    p = a["provenance"]
    pinned = json.loads((MODELS / "registry.json").read_text(encoding="utf-8"))
    assert p["modelSha256"] == engine.predictor.registry["classifierSha256"] == pinned["classifier"]["sha256"]
    assert p["featureSchemaVersion"] == FEATURE_SCHEMA_VERSION
    assert p["sample"]["sha256"] == pinned["golden"]["sha256"] and p["sample"]["rows"] == 20
    assert p["persisted"] is True and p["shapConfig"]["explainer"] == "shap.TreeExplainer" and p["generatedAt"]
    files = list((tmp_path / "a").glob("global_shap_*.json"))
    assert len(files) == 1 and p["cacheKey"] in files[0].name
    assert a["scope"] == "reference" and len(a["overall"]) == 10


def test_a_model_or_schema_change_invalidates_the_cached_summary(engine, tmp_path, monkeypatch):
    first = engine.reference_global_shap(tmp_path)
    reg = dict(engine.predictor.registry)
    reg["classifierSha256"] = "0" * 64
    monkeypatch.setattr(engine.predictor, "registry", reg)
    second = engine.reference_global_shap(tmp_path)
    assert second["cache"] == "miss" and second["provenance"]["cacheKey"] != first["provenance"]["cacheKey"]
    monkeypatch.setattr(engine, "FEATURE_SCHEMA_VERSION", "other-schema")
    third = engine.reference_global_shap(tmp_path)
    assert third["provenance"]["cacheKey"] not in (first["provenance"]["cacheKey"], second["provenance"]["cacheKey"])


def test_a_golden_set_that_does_not_match_the_registry_is_refused(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(engine, "_pinned_golden", lambda: {"file": "golden_set.json", "rows": 20, "sha256": "f" * 64})
    with pytest.raises(Exception) as e:
        engine.reference_global_shap(tmp_path)
    assert getattr(e.value, "status_code", None) == 409


def test_the_recent_view_says_it_is_not_persisted(engine):
    out = engine.model_explain_global(scope="recent")
    assert out["scope"] == "recent" and out["provenance"]["persisted"] is False
    with pytest.raises(Exception) as e:
        engine.model_explain_global(scope="bogus")
    assert getattr(e.value, "status_code", None) == 422


def test_predictions_report_the_classifier_type(real):
    out = real.predict(dict(zip(FEATURE_NAMES, GOLDEN["vectors"][0])))
    assert out["modelType"] == "xgboost" and out["modelVersion"] == "xgb_cicids_v1"
