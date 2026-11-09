"""L2: reconnaissance intent matches whole words only. L4: one classifier pass per prediction, reused by SHAP."""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

ENGINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ENGINE))
from inference import predictor as pred_mod  # noqa: E402


@pytest.fixture
def parser(monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-low-fixes-key")
    spec = importlib.util.spec_from_file_location("parser_low", ENGINE.parent / "honeypot/parsers/log_parser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("cmd,intent", [
    ("id", "RECONNAISSANCE"), ("uname -a", "RECONNAISSANCE"), ("whoami;ls", "RECONNAISSANCE"),
    ("ls hidden", "UNKNOWN"), ("cd android", "UNKNOWN"), ("echo valid", "UNKNOWN"),
])
def test_recon_intent_is_whole_word(parser, cmd, intent):
    assert parser.classify_intent(cmd) == intent


class CountingForest:
    """predict_proba-only estimator with real classes_, counting forest passes."""
    def __init__(self):
        self.classes_ = np.array([0, 4])
        self.proba_calls = 0
        self.named_steps = {"scaler": MagicMock(transform=lambda X: X), "rf": MagicMock()}

    def predict_proba(self, X):
        self.proba_calls += 1
        return np.array([[0.1, 0.9]])

    def predict(self, X):  # must not be needed
        raise AssertionError("predict() should not be called; predict_proba already has the answer")


def test_single_forest_pass_and_shap_reuses_it():
    with patch.object(pred_mod.SentinelPredictor, "load"):
        p = pred_mod.SentinelPredictor()
    p._loaded = True
    p.rf = p.clf = CountingForest()
    ifo = MagicMock()
    ifo.named_steps = {"if": MagicMock(score_samples=lambda X: np.array([-0.40])), "scaler": MagicMock(transform=lambda X: X)}
    p.ifo = ifo
    p.explainer = MagicMock(shap_values=lambda X: np.zeros((1, X.shape[1], 2)))

    res = p.predict({"flow_duration": 10.0}, explain=True)

    assert res["predictedClass"] == "DDoS"
    assert p.rf.proba_calls == 1  # previously predict + predict_proba, plus another predict for SHAP
    assert len(res["featureImportance"]) == 5
