"""Inference runs off the event loop with locked shared state; Q-learning persists across restarts."""
import inspect
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"

with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    from inference import main
    from inference import deception

from rl_engine import deception_scorer
from rl_engine.deception_scorer import DeceptionQLearner

HEADERS = {"X-API-Key": "test-sentinel-secret-key-12345"}
TEST_MODE_VARS = ("PYTEST_CURRENT_TEST", "SENTINEL_TEST_MODE", "SENTINEL_DIAGNOSTIC", "SENTINEL_ENV", "NODE_ENV")


def test_cpu_bound_endpoints_are_sync_so_fastapi_uses_the_threadpool():
    for handler in (main.predict, main.predict_internal, main.predict_eval, main.predict_batch,
                    main.predict_honeypot, main.predict_honeypot_internal, main.deception_score):
        assert not inspect.iscoroutinefunction(handler), handler.__name__
    # Liveness/readiness stay async and never wait behind inference.
    assert inspect.iscoroutinefunction(main.health)
    assert inspect.iscoroutinefunction(main.ready)


def test_concurrent_deception_updates_are_not_lost(monkeypatch):
    monkeypatch.setattr(deception, "_scorer", None)
    client = TestClient(main.app)  # no context manager: skip model-loading lifespan
    session = {"sessionId": "s", "sourceIP": "203.0.113.4", "durationSeconds": 60,
               "commands": [], "deceptionProfile": "centos_7"}
    start = client.post("/deception/score", json=session, headers=HEADERS).json()["result"]["learnerStats"]["episodeCount"]

    def call(_):
        return client.post("/deception/score", json=session, headers=HEADERS).status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(call, range(40)))

    assert codes == [200] * 40
    assert deception.get_scorer().learner.episode_count == start + 40


def test_service_default_q_table_path_is_stable_and_outside_repo(monkeypatch, tmp_path):
    for var in TEST_MODE_VARS + ("DEFAULT_RUNTIME_Q_TABLE_PATH", "SENTINEL_ALLOW_REPO_RUNTIME_WRITE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    # Detection also keys off "pytest" in sys.modules; simulate a normal service process.
    monkeypatch.setattr(deception_scorer, "is_test_or_diagnostic_mode", lambda: False)

    first = deception_scorer.get_default_runtime_path()
    monkeypatch.setattr(os, "getpid", lambda: 424242)  # a restarted process
    second = deception_scorer.get_default_runtime_path()

    assert first == second == (tmp_path / "SentinelAI" / "runtime" / "q_table.json").resolve()
    repo = Path(__file__).resolve().parent.parent
    assert repo not in first.parents


def test_test_mode_still_uses_process_isolated_temp(monkeypatch):
    monkeypatch.delenv("DEFAULT_RUNTIME_Q_TABLE_PATH", raising=False)
    monkeypatch.delenv("SENTINEL_ALLOW_REPO_RUNTIME_WRITE", raising=False)
    monkeypatch.setenv("SENTINEL_TEST_MODE", "1")
    assert "sentinelai_isolated_runtime_" in str(deception_scorer.get_default_runtime_path())


def test_every_episode_is_persisted_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("Q_SAVE_EVERY", raising=False)
    path = tmp_path / "q.json"
    learner = DeceptionQLearner(q_table_path=str(path))
    learner.update("centos_7", "centos_7", 5.0, "centos_7")
    assert json.loads(path.read_text())["episode_count"] == 1

    # A restarted learner resumes from the saved state instead of the seed.
    resumed = DeceptionQLearner(q_table_path=str(path))
    assert resumed.episode_count == 1
    assert resumed.q_table["centos_7"]["centos_7"] == pytest.approx(0.5)


def test_previous_profile_from_backend_is_used_as_state(tmp_path):
    scorer = deception_scorer.SessionScorer(q_table_path=str(tmp_path / "q.json"))
    res = scorer.process_session({"sessionId": "x", "durationSeconds": 120, "commands": [],
                                  "deceptionProfile": "debian_11", "previousProfile": "centos_7"})
    assert res["prevProfile"] == "centos_7"
    assert res["activeProfile"] == "debian_11"
    assert scorer.learner.q_table["centos_7"]["debian_11"] > 0
