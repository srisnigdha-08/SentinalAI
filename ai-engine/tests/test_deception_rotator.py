"""honeypot/deception_rotator.py applies the recommended persona: rewrites cowrie.cfg, restarts Cowrie
(without a shell) and records the served persona; it records nothing when the restart fails."""
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

HONEYPOT = Path(__file__).resolve().parents[2] / "honeypot"


@pytest.fixture
def rotator(monkeypatch):
    monkeypatch.syspath_prepend(str(HONEYPOT))
    spec = importlib.util.spec_from_file_location("deception_rotator", HONEYPOT / "deception_rotator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _client(active, nxt, record_status=200, active_sessions=None):
    client = MagicMock(RECOMMENDATION="/api/honeypot/deception/recommendation", PROFILE="/api/honeypot/deception/profile")
    rec = MagicMock(status_code=200)
    rec.json.return_value = {"data": {"activeProfile": active, "nextProfile": nxt, "explored": True,
                                      **({} if active_sessions is None else {"activeSessions": active_sessions})}}
    put = MagicMock(status_code=record_status)
    client.call.side_effect = lambda method, path, **kw: rec if method == "GET" else put
    return client


def test_switches_restarts_and_records(rotator, tmp_path, monkeypatch):
    cfg = tmp_path / "cowrie.cfg"
    ran = []
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: ran.append(args) or MagicMock(returncode=0))
    client = _client("centos_7", "debian_11")
    result = rotator.rotate_once(client, cfg, "systemctl restart cowrie", dry_run=False)
    assert result == {"changed": True, "active": "debian_11", "previous": "centos_7"}
    assert "debian" in cfg.read_text().lower()
    assert ran == [["systemctl", "restart", "cowrie"]]  # argv list, no shell
    client.call.assert_any_call("PUT", "/api/honeypot/deception/profile", json={"profile": "debian_11"})


def test_same_persona_or_dry_run_changes_nothing(rotator, tmp_path):
    cfg = tmp_path / "cowrie.cfg"
    assert rotator.rotate_once(_client("centos_7", "centos_7"), cfg, "", dry_run=False)["changed"] is False
    dry = rotator.rotate_once(_client("centos_7", "aws_ec2"), cfg, "", dry_run=True)
    assert dry == {"changed": False, "active": "centos_7", "would_switch_to": "aws_ec2"}
    assert not cfg.exists()


def test_failed_restart_does_not_record_the_persona(rotator, tmp_path, monkeypatch):
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: MagicMock(returncode=1, stderr="denied"))
    client = _client("centos_7", "ubuntu_22")
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is False and "restart failed" in result["error"]
    assert all(c.args[0] == "GET" for c in client.call.call_args_list)


def test_failed_restart_restores_the_served_cfg_and_retries(rotator, tmp_path, monkeypatch):
    cfg = tmp_path / "cowrie.cfg"
    rotator.switch_profile.CFG_PATH = cfg
    rotator.switch_profile.generate_config("centos_7")
    original = cfg.read_text()
    outcomes, seen = iter([1, 0]), []

    def run(args, **kw):
        seen.append(rotator.served_persona(cfg))  # persona on disk at each restart attempt
        return MagicMock(returncode=next(outcomes), stderr="busy")

    monkeypatch.setattr(rotator.subprocess, "run", run)
    client = _client("centos_7", "ubuntu_22")
    result = rotator.rotate_once(client, cfg, "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is False and result["restored"] is True and result["recovered"] is True
    assert seen == ["ubuntu_22", "centos_7"]  # tried the new persona, then restarted with the restored one
    assert cfg.read_text() == original
    assert all(c.args[0] == "GET" for c in client.call.call_args_list)


def test_machine_client_uses_only_the_honeypot_key_on_scoped_paths(rotator, monkeypatch, tmp_path):
    # C3: no admin login on the honeypot host; the rotator talks to /api/honeypot/ingest/deception/*.
    calls = []

    def fake_request(self, method, url, **kw):
        calls.append((method, url, kw.get("headers"), kw.get("json")))
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": {"activeProfile": "centos_7", "nextProfile": "debian_11", "explored": False}}
        return resp

    monkeypatch.setattr(rotator.requests.Session, "request", fake_request)
    monkeypatch.setattr(rotator, "run_restart", lambda cmd: True)
    client = rotator.MachineClient("http://127.0.0.1:5000/", "hp-key")
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "", dry_run=False)
    assert result == {"changed": True, "active": "debian_11", "previous": "centos_7"}
    assert [(m, u) for m, u, _, _ in calls] == [
        ("GET", "http://127.0.0.1:5000/api/honeypot/ingest/deception/recommendation"),
        ("PUT", "http://127.0.0.1:5000/api/honeypot/ingest/deception/profile"),
    ]
    assert all(h == {"X-API-Key": "hp-key"} for _, _, h, _ in calls)
    assert calls[1][3] == {"profile": "debian_11"}


def test_switch_waits_while_attackers_are_connected_unless_forced(rotator, tmp_path, monkeypatch):
    """M7: a switch restarts Cowrie and would drop the live sessions."""
    ran = []
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: ran.append(args) or MagicMock(returncode=0))
    cfg = tmp_path / "cowrie.cfg"
    busy = _client("centos_7", "debian_11", active_sessions=2)
    result = rotator.rotate_once(busy, cfg, "systemctl restart cowrie", dry_run=False)
    assert result == {"changed": False, "active": "centos_7", "deferred": "debian_11", "activeSessions": 2}
    assert not ran and not cfg.exists()
    forced = rotator.rotate_once(busy, cfg, "systemctl restart cowrie", dry_run=False, force=True)
    assert forced["changed"] is True and ran
    idle = rotator.rotate_once(_client("debian_11", "ubuntu_22", active_sessions=0), cfg, "", dry_run=False)
    assert idle["changed"] is True


def test_unservable_recommendation_is_skipped_not_fatal(rotator, tmp_path):
    result = rotator.rotate_once(_client("centos_7", "windows_srv"), tmp_path / "cowrie.cfg", "", dry_run=False)
    assert result["changed"] is False and "not servable" in result["error"]
    assert not (tmp_path / "cowrie.cfg").exists()


def test_records_the_persona_cowrie_serves_before_deciding(rotator, tmp_path):
    # Regression: on an empty database the backend assumes centos_7. If the recommendation was also centos_7,
    # the rotator "kept" centos_7 while Cowrie really served ubuntu_22, and nothing was ever corrected.
    cfg = tmp_path / "cowrie.cfg"
    cfg.write_text("# Generated by honeypot/switch_profile.py (ubuntu_22). Edit the template there, not this file.\n")
    responses = [{"activeProfile": "centos_7", "nextProfile": "centos_7"},
                 {"activeProfile": "ubuntu_22", "nextProfile": "ubuntu_22"}]
    client = MagicMock(RECOMMENDATION="/rec", PROFILE="/profile")
    calls = []

    def call(method, path, **kw):
        calls.append((method, path, kw.get("json")))
        if method == "PUT":
            return MagicMock(status_code=200)
        r = MagicMock(status_code=200)
        r.json.return_value = {"data": responses.pop(0)}
        return r
    client.call.side_effect = call

    result = rotator.rotate_once(client, cfg, "", dry_run=False)
    assert calls[1] == ("PUT", "/profile", {"profile": "ubuntu_22"})
    assert result == {"changed": False, "active": "ubuntu_22"}


def test_served_persona_ignores_hand_written_configs(rotator, tmp_path):
    cfg = tmp_path / "cowrie.cfg"
    assert rotator.served_persona(cfg) is None
    cfg.write_text("[honeypot]\nhostname = svr04\n")
    assert rotator.served_persona(cfg) is None
    cfg.write_text("# Generated by honeypot/switch_profile.py (not_a_persona).\n")
    assert rotator.served_persona(cfg) is None


# ── RL-001: the rotator applies, keeps or fails exactly the decision it was given ──────────────────────────────
def _decision_client(active, nxt, decision_id="decision-1"):
    client = _client(active, nxt)
    client.DECISION_FAIL = "/api/honeypot/ingest/deception/decision/{}/fail"
    client.call.return_value = None
    rec = client.call.side_effect("GET", client.RECOMMENDATION)
    rec.json.return_value["data"]["decisionId"] = decision_id
    return client


def test_switch_records_the_applied_decision_id(rotator, tmp_path, monkeypatch):
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: MagicMock(returncode=0))
    client = _decision_client("centos_7", "debian_11")
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is True and result["decisionId"] == "decision-1"
    client.call.assert_any_call("PUT", client.PROFILE, json={"profile": "debian_11", "decisionId": "decision-1"})


def test_keep_decision_is_acknowledged_so_the_next_rotation_draws_anew(rotator, tmp_path):
    client = _decision_client("centos_7", "centos_7")
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "", dry_run=False)
    assert result == {"changed": False, "active": "centos_7", "decisionId": "decision-1"}
    client.call.assert_any_call("PUT", client.PROFILE, json={"profile": "centos_7", "decisionId": "decision-1"})


def test_failed_restart_marks_the_decision_failed_and_records_no_persona(rotator, tmp_path, monkeypatch):
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: MagicMock(returncode=1, stderr="denied"))
    client = _decision_client("centos_7", "ubuntu_22")
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is False
    calls = [c for c in client.call.call_args_list if c.args[0] != "GET"]
    assert len(calls) == 1 and calls[0].args[:2] == ("POST", "/api/honeypot/ingest/deception/decision/decision-1/fail")
    assert "restart failed" in calls[0].kwargs["json"]["reason"]


def test_deferred_switch_leaves_the_decision_pending(rotator, tmp_path):
    client = _client("centos_7", "aws_ec2", active_sessions=3)
    client.call.side_effect("GET", client.RECOMMENDATION).json.return_value["data"]["decisionId"] = "decision-1"
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "", dry_run=False)
    assert result["deferred"] == "aws_ec2"
    assert all(c.args[0] == "GET" for c in client.call.call_args_list)
