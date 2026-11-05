"""
/deception/score and /deception/recommendation when the Q-learner cannot start or fails mid-update.

Regression (2026-10-22): a failing get_scorer() surfaced as a bare "Internal Server Error". The backend logged
only "status code 500", every honeypot session was stored with qDeceptionScore 0, and the cause was visible
nowhere but the engine's own console. The endpoints must now name the cause and report it in /model/info.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"

with patch("inference.predictor.SentinelPredictor.load"), \
     patch("inference.predictor.SentinelPredictor.init_explainer"), \
     patch("joblib.load", return_value=MagicMock()):
    import inference.main as main

HEADERS = {"X-API-Key": "test-sentinel-secret-key-12345"}
SESSION = {"sessionId": "s1", "sourceIP": "203.0.113.5", "durationSeconds": 3, "loginSucceeded": True,
           "commands": [{"command": "whoami", "intent": "RECONNAISSANCE"}], "deceptionProfile": "ubuntu_22"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(main, "_deception_error", None)
    with patch("inference.main._notify"), \
         patch("inference.predictor.SentinelPredictor.get_model_info", return_value={"version": "test"}), \
         TestClient(main.app) as c:
        yield c


def test_scorer_init_failure_is_a_reasoned_503(client, monkeypatch):
    def boom():
        raise PermissionError("Scorer initialization targeting repository runtime rejected")
    monkeypatch.setattr(main, "get_scorer", boom)

    r = client.post("/deception/score", json=SESSION, headers=HEADERS)
    assert r.status_code == 503
    detail = r.json()["detail"]
    assert detail["error"] == "DECEPTION_SCORER_UNAVAILABLE"
    assert detail["reason"].startswith("PermissionError: Scorer initialization")

    rec = client.get("/deception/recommendation?current=ubuntu_22", headers=HEADERS)
    assert rec.status_code == 503 and rec.json()["detail"]["error"] == "DECEPTION_SCORER_UNAVAILABLE"

    status = client.get("/model/info", headers=HEADERS).json()["deception"]
    assert status["initialized"] is False
    assert status["lastError"].startswith("PermissionError")


def test_failure_inside_scoring_names_the_exception(client, monkeypatch):
    scorer = MagicMock()
    scorer.process_session.side_effect = OSError("disk full")
    monkeypatch.setattr(main, "get_scorer", lambda: scorer)

    r = client.post("/deception/score", json=SESSION, headers=HEADERS)
    assert r.status_code == 500
    assert r.json()["detail"] == {"error": "DECEPTION_SCORING_FAILED", "reason": "OSError: disk full"}


def test_recovery_clears_the_reported_error(client, monkeypatch, tmp_path):
    def boom():
        raise PermissionError("denied")
    monkeypatch.setattr(main, "get_scorer", boom)
    assert client.post("/deception/score", json=SESSION, headers=HEADERS).status_code == 503

    scorer = MagicMock()
    scorer.process_session.return_value = {"deceptionScore": 12.0, "nextProfile": "ubuntu_22",
                                           "recommendationApplied": False}
    scorer.learner.q_table_path = str(tmp_path / "q_table.json")
    monkeypatch.setattr(main, "get_scorer", lambda: scorer)
    monkeypatch.setattr(main.deception, "_scorer", scorer)

    r = client.post("/deception/score", json=SESSION, headers=HEADERS)
    assert r.status_code == 200 and r.json()["result"]["recommendationApplied"] is False
    status = client.get("/model/info", headers=HEADERS).json()["deception"]
    assert status == {"initialized": True, "qTablePath": str(tmp_path / "q_table.json"), "lastError": None}
