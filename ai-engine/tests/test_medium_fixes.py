"""Medium-priority fixes in the AI engine:
M5  Q-table saves merge concurrent writers (other workers/processes) instead of losing their updates.
M9  prepare_features can fail on unexpectedly missing schema columns instead of silently zero-filling.
M11 models/registry.json pins model files by SHA-256; a mismatch makes inference unavailable."""
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import joblib
import pandas as pd
import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from rl_engine.deception_scorer import DeceptionQLearner  # noqa: E402
from utils.features import FEATURE_NAMES, prepare_features  # noqa: E402
from inference import predictor as pred_mod  # noqa: E402


# ── M5 ────────────────────────────────────────────────────────────────────────
def test_two_learners_on_one_file_keep_every_update(tmp_path):
    path = tmp_path / "q.json"
    a, b = DeceptionQLearner(q_table_path=str(path)), DeceptionQLearner(q_table_path=str(path))
    for _ in range(5):
        a.update("centos_7", "centos_7", 2.0, "centos_7")   # saves each episode
        b.update("centos_7", "debian_11", 4.0, "debian_11")
    saved = json.loads(path.read_text())
    assert saved["episode_count"] == 10
    assert saved["q_table"]["centos_7"]["centos_7"] > 0 and saved["q_table"]["centos_7"]["debian_11"] > 0
    assert saved["total_reward"] == pytest.approx(30.0)
    assert not (tmp_path / "q.json.lock").exists()


WORKER = r'''
import sys
sys.path.insert(0, sys.argv[1])
from rl_engine.deception_scorer import DeceptionQLearner
learner = DeceptionQLearner(q_table_path=sys.argv[2])
for _ in range(int(sys.argv[3])):
    learner.update("centos_7", sys.argv[4], 1.0, sys.argv[4])
'''


def test_separate_processes_do_not_lose_each_others_learning(tmp_path):
    path = tmp_path / "q.json"
    env = {"SENTINEL_TEST_MODE": "1", "SYSTEMROOT": __import__("os").environ.get("SYSTEMROOT", "")}
    procs = [subprocess.Popen([sys.executable, "-I", "-c", WORKER, str(ENGINE), str(path), "25", action], env=env)
             for action in ("centos_7", "ubuntu_22")]
    assert [p.wait(timeout=120) for p in procs] == [0, 0]
    saved = json.loads(path.read_text())
    assert saved["episode_count"] == 50  # last-writer-wins would leave 25


def test_unreadable_table_is_reported_not_silently_ignored(tmp_path, caplog):
    path = tmp_path / "q.json"
    path.write_text("{not json")
    with caplog.at_level("WARNING"):
        learner = DeceptionQLearner(q_table_path=str(path))
    assert learner.episode_count == 0
    assert "could not be read" in caplog.text


# ── M9 ────────────────────────────────────────────────────────────────────────
def _frame(columns):
    return pd.DataFrame({**{c: [1.0, 2.0] for c in columns}, "Label": ["BENIGN", "DDoS"]})


def test_strict_mode_rejects_unexpectedly_missing_columns():
    present = [f for f in FEATURE_NAMES if f not in ("flow_duration", "syn_flag_count", "time_of_day_sin", "time_of_day_cos")]
    with pytest.raises(ValueError, match="flow_duration, syn_flag_count"):
        prepare_features(_frame(present), max_missing=0)


def test_time_features_and_derived_entropy_are_expected_absent():
    present = [f for f in FEATURE_NAMES if f not in ("time_of_day_sin", "time_of_day_cos", "payload_entropy")]
    X, _ = prepare_features(_frame(present), max_missing=0)  # does not raise
    assert X.shape == (2, len(FEATURE_NAMES))


def test_lenient_mode_still_zero_fills_but_warns(caplog):
    with caplog.at_level("WARNING"):
        X, _ = prepare_features(pd.DataFrame({"Label": ["BENIGN"]}))
    assert X.shape == (1, len(FEATURE_NAMES)) and (X == 0).all()
    assert "zero-filled" in caplog.text


# ── M11 ───────────────────────────────────────────────────────────────────────
class TinyModel:
    """Stand-in estimator: picklable, reports the right feature count."""
    n_features_in_ = len(FEATURE_NAMES)


def _write_models(model_dir: Path):
    joblib.dump(TinyModel(), model_dir / "clf_a.pkl")
    joblib.dump(TinyModel(), model_dir / "rf_classifier_cicids_v2.pkl")  # would win the legacy first-match order
    joblib.dump(TinyModel(), model_dir / "if_a.pkl")


def _register(model_dir: Path, **override):
    reg = {
        "classifier": {"file": "clf_a.pkl", "type": "rf", "sha256": pred_mod.file_sha256(model_dir / "clf_a.pkl")},
        "anomaly": {"file": "if_a.pkl", "sha256": pred_mod.file_sha256(model_dir / "if_a.pkl")},
    }
    reg["classifier"].update(override)
    (model_dir / "registry.json").write_text(json.dumps(reg))


def _load(model_dir):
    with patch.object(pred_mod.SentinelPredictor, "init_explainer"), \
         patch.object(pred_mod.SentinelPredictor, "_init_shadow_detectors"):
        return pred_mod.SentinelPredictor(model_dir=str(model_dir))


def test_registry_pins_the_exact_files(tmp_path):
    _write_models(tmp_path)
    _register(tmp_path)
    p = _load(tmp_path)
    assert p._loaded
    assert p.registry["classifier"] == "clf_a.pkl" and p.registry["verified"] is True
    assert p.get_model_info()["registry"]["anomaly"] == "if_a.pkl"


def test_hash_mismatch_makes_inference_unavailable(tmp_path, caplog):
    _write_models(tmp_path)
    _register(tmp_path, sha256="0" * 64)
    with caplog.at_level("ERROR"):
        p = _load(tmp_path)
    assert not p._loaded
    assert "hash mismatch" in caplog.text


def test_registry_rejects_paths_outside_model_dir(tmp_path, caplog):
    _write_models(tmp_path)
    _register(tmp_path, file="../clf_a.pkl")
    with caplog.at_level("ERROR"):
        p = _load(tmp_path)
    assert not p._loaded and "registry invalid" in caplog.text


def test_shipped_registry_matches_shipped_models():
    reg = pred_mod.load_registry(ENGINE / "models")
    assert reg is not None, "ai-engine/models/registry.json is missing"
    for role in ("classifier", "anomaly"):
        assert pred_mod.file_sha256(ENGINE / "models" / reg[role]["file"]) == reg[role]["sha256"]
    assert reg["classifier"]["file"] == "rf_classifier_cicids_v2.pkl"
