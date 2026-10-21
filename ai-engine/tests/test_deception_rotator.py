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


def _client(active, nxt, record_status=200):
    client = MagicMock()
    rec = MagicMock(status_code=200)
    rec.json.return_value = {"data": {"activeProfile": active, "nextProfile": nxt, "explored": True}}
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
