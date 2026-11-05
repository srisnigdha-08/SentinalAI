"""
PERF-001: single-threaded per-request inference (SentinelPredictor._set_inference_threads).

The served models were saved with n_jobs=-1, so every one-row request started all-core thread pools; under
concurrent requests that oversubscribed the CPU. The predictor now runs each model call single-threaded by default
(INFERENCE_N_JOBS overrides it). These tests pin the setting and that it never changes a prediction.
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from inference.predictor import SentinelPredictor  # noqa: E402
from utils.features import FEATURE_NAMES  # noqa: E402

MODELS = Path(__file__).resolve().parent.parent / "models"


def _load(monkeypatch, value=None):
    if value is None:
        monkeypatch.delenv("INFERENCE_N_JOBS", raising=False)
    else:
        monkeypatch.setenv("INFERENCE_N_JOBS", value)
    p = SentinelPredictor(model_dir=str(MODELS))
    if not p._loaded:
        pytest.skip("served models not available")
    return p


def _thread_settings(p):
    xgb = p.clf.named_steps["xgb"]
    xgb = getattr(xgb, "model_", xgb)
    nthread = json.loads(xgb.get_booster().save_config())["learner"]["generic_param"]["nthread"]
    return xgb.get_params()["n_jobs"], p.ifo.named_steps["if"].n_jobs, int(nthread)


def test_models_run_single_threaded_by_default_and_golden_check_passes(monkeypatch):
    p = _load(monkeypatch)
    assert _thread_settings(p) == (1, 1, 1)
    assert p.inference_n_jobs == 1
    assert "golden rows reproduced" in p.registry.get("goldenCheck", "")  # checked after the setting is applied


def test_inference_n_jobs_overrides_the_default(monkeypatch):
    p = _load(monkeypatch, "-1")
    xgb_jobs, if_jobs, _ = _thread_settings(p)
    assert (xgb_jobs, if_jobs) == (-1, -1)


def test_thread_setting_never_changes_a_prediction(monkeypatch):
    golden = json.loads((MODELS / "golden_set.json").read_text(encoding="utf-8"))["vectors"]
    records = [dict(zip(FEATURE_NAMES, v)) for v in golden]
    single = _load(monkeypatch, "1")
    a = [(r["predictedClass"], r["threatScore"], r["confidence"], r["anomalyScore"]) for r in single.predict_many(records)]
    multi = _load(monkeypatch, "-1")
    b = [(r["predictedClass"], r["threatScore"], r["confidence"], r["anomalyScore"]) for r in multi.predict_many(records)]
    assert a == b


def test_concurrent_requests_match_sequential_results(monkeypatch):
    """The engine serves requests from a thread pool; single-threaded models must stay safe to share across it."""
    from concurrent.futures import ThreadPoolExecutor

    golden = json.loads((MODELS / "golden_set.json").read_text(encoding="utf-8"))["vectors"]
    p = _load(monkeypatch)
    if p.explainer is None:
        pytest.skip("SHAP explainer not available")
    vectors = [p.predict(dict(zip(FEATURE_NAMES, v)))["featureVector"] for v in golden]

    def run(vec):
        e = p.explain_vector(vec)
        return e["predictedClass"], e["threatScore"], e["baseValue"], [(c["feature"], c["contribution"]) for c in e["contributions"]]

    sequential = [run(v) for v in vectors]
    with ThreadPoolExecutor(max_workers=8) as pool:
        concurrent = list(pool.map(run, vectors * 8))
    assert concurrent == sequential * 8


def test_thread_setting_never_changes_an_explanation(monkeypatch):
    golden = json.loads((MODELS / "golden_set.json").read_text(encoding="utf-8"))["vectors"]

    def explain_all(value):
        p = _load(monkeypatch, value)
        if p.explainer is None:
            pytest.skip("SHAP explainer not available")
        vecs = [p.predict(dict(zip(FEATURE_NAMES, v)))["featureVector"] for v in golden]
        return [(e["baseValue"], [(c["feature"], round(c["contribution"], 9)) for c in e["contributions"]])
                for e in map(p.explain_vector, vecs)]

    assert explain_all("1") == explain_all("-1")
