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


@pytest.fixture(autouse=True)
def built_personas(rotator, tmp_path, monkeypatch):
    """A built persona filesystem for every Linux persona, and a Cowrie that answers with the new banner
    (individual tests override either)."""
    fs = tmp_path / "personas"
    fs.mkdir()
    for p in rotator.switch_profile.PROFILES:
        (fs / f"{p}.pickle").write_bytes(b"x")
    monkeypatch.setenv("COWRIE_PERSONA_FS", str(fs))
    monkeypatch.delenv("COWRIE_PERSONA_HONEYFS", raising=False)
    monkeypatch.setattr(rotator, "verify_served", lambda cfg, persona, addr=None, timeout=30.0: None)
    monkeypatch.setattr(rotator, "open_watch", lambda address: None)
    return fs


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
    result = rotator.rotate_once(client, tmp_path / "cowrie.cfg", "systemctl restart cowrie", dry_run=False)
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
    idle = rotator.rotate_once(_client("debian_11", "ubuntu_22", active_sessions=0), cfg, "systemctl restart cowrie", dry_run=False)
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


# ── A persona is recorded only when Cowrie really serves it ─────────────────────────────────────────────────────
def _restart_ok(rotator, monkeypatch):
    ran = []
    monkeypatch.setattr(rotator.subprocess, "run", lambda args, **kw: ran.append(args) or MagicMock(returncode=0))
    return ran


def test_without_restart_command_nothing_is_switched_or_recorded(rotator, tmp_path, monkeypatch):
    # Regression: run_restart("") returned True, so the backend recorded a persona Cowrie never served.
    ran = _restart_ok(rotator, monkeypatch)
    cfg = tmp_path / "cowrie.cfg"
    client = _decision_client("centos_7", "debian_11")
    result = rotator.rotate_once(client, cfg, "", dry_run=False)
    assert result["changed"] is False and "restart-cmd" in result["error"]
    assert not cfg.exists() and not ran
    writes = [c for c in client.call.call_args_list if c.args[0] != "GET"]
    assert [c.args[:2] for c in writes] == [("POST", "/api/honeypot/ingest/deception/decision/decision-1/fail")]


@pytest.mark.parametrize("setup, reason", [
    (lambda fs, mp: mp.delenv("COWRIE_PERSONA_FS"), "COWRIE_PERSONA_FS"),
    (lambda fs, mp: (fs / "debian_11.pickle").unlink(), "does not exist"),
])
def test_missing_persona_filesystem_refuses_the_switch(rotator, tmp_path, monkeypatch, built_personas, setup, reason):
    # Without it Cowrie serves its stock tree (user "phil") under the new hostname, or refuses every login.
    ran = _restart_ok(rotator, monkeypatch)
    setup(built_personas, monkeypatch)
    cfg = tmp_path / "cowrie.cfg"
    client = _decision_client("centos_7", "debian_11")
    result = rotator.rotate_once(client, cfg, "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is False and reason in result["error"]
    assert not cfg.exists() and not ran
    assert not any(c.args[0] == "PUT" for c in client.call.call_args_list)


def test_relative_persona_filesystem_resolves_against_the_cowrie_home(rotator, tmp_path, monkeypatch):
    home = tmp_path / "cowrie"
    (home / "etc").mkdir(parents=True)
    (home / "personas").mkdir()
    (home / "personas" / "aws_ec2.pickle").write_bytes(b"x")
    monkeypatch.setenv("COWRIE_PERSONA_FS", "personas")
    assert rotator.persona_fs_problem(home / "etc" / "cowrie.cfg", "aws_ec2") is None
    assert "does not exist" in rotator.persona_fs_problem(home / "etc" / "cowrie.cfg", "ubuntu_22")


def test_wrong_banner_after_restart_restores_the_cfg_and_fails_the_decision(rotator, tmp_path, monkeypatch):
    ran = _restart_ok(rotator, monkeypatch)
    monkeypatch.setattr(rotator, "verify_served", lambda cfg, persona, addr=None, timeout=30.0: "Cowrie serves banner None")
    cfg = tmp_path / "cowrie.cfg"
    rotator.switch_profile.CFG_PATH = cfg
    rotator.switch_profile.generate_config("centos_7")
    original = cfg.read_text()
    client = _decision_client("centos_7", "raspberry_pi")
    result = rotator.rotate_once(client, cfg, "systemctl restart cowrie", dry_run=False)
    assert result["changed"] is False and result["restored"] is True and "banner" in result["error"]
    assert cfg.read_text() == original and len(ran) == 2  # new persona, then the restored one
    writes = [c for c in client.call.call_args_list if c.args[0] != "GET"]
    assert len(writes) == 1 and writes[0].args[0] == "POST" and "banner" in writes[0].kwargs["json"]["reason"]


def test_no_verify_skips_the_banner_check(rotator, tmp_path, monkeypatch):
    _restart_ok(rotator, monkeypatch)
    monkeypatch.setattr(rotator, "verify_served", lambda *a, **k: pytest.fail("verify_served must not run"))
    result = rotator.rotate_once(_client("centos_7", "debian_11"), tmp_path / "cowrie.cfg", "systemctl restart cowrie",
                                 dry_run=False, verify=False)
    assert result["changed"] is True and result["verified"] is False  # never silently reported as checked


class _banner_server:
    """Fake SSH server: sends `banner` and keeps each connection open until restart() closes them all."""

    def __init__(self, banner):
        import socket, threading
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(8)
        self._held, self._banner = [], banner
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            conn.sendall((self._banner + "\r\n").encode())
            self._held.append(conn)

    def getsockname(self):
        return self._srv.getsockname()

    def restart(self):
        while self._held:
            self._held.pop().close()

    def close(self):
        self._srv.close()


def test_verify_served_reads_the_real_banner(rotator, tmp_path, monkeypatch):
    # The real check (the autouse stub is replaced by the module's own function).
    spec = importlib.util.spec_from_file_location("rot_real", HONEYPOT / "deception_rotator.py")
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    cfg = tmp_path / "cowrie.cfg"
    real.switch_profile.CFG_PATH = cfg
    monkeypatch.setenv("COWRIE_LISTEN_ADDR", "127.0.0.1")
    real.switch_profile.generate_config("raspberry_pi")
    assert real.listen_address(cfg) == ("127.0.0.1", 2222)
    srv = _banner_server("SSH-2.0-OpenSSH_8.4p1 Raspbian")
    try:
        addr = srv.getsockname()
        assert real.verify_served(cfg, "raspberry_pi", addr, timeout_s=2) is None
        assert "expected 'SSH-2.0-OpenSSH_8.9p1" in real.verify_served(cfg, "ubuntu_22", addr, timeout_s=2)
    finally:
        srv.restart()
        srv.close()
    assert "None" in real.verify_served(cfg, "raspberry_pi", addr, timeout_s=0)  # nothing listening any more


def test_wildcard_listen_is_probed_on_loopback(rotator, tmp_path):
    cfg = tmp_path / "cowrie.cfg"
    cfg.write_text("[ssh]\nlisten_endpoints     = tcp:2222:interface=0.0.0.0\n")
    assert rotator.listen_address(cfg) == ("127.0.0.1", 2222)
    cfg.write_text("[ssh]\n")
    assert rotator.listen_address(cfg) is None


def _real_rotator():
    spec = importlib.util.spec_from_file_location("rot_real2", HONEYPOT / "deception_rotator.py")
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    return real


@pytest.mark.parametrize("really_restarts, applied", [(False, False), (True, True)])
def test_shared_banner_switch_needs_proof_of_restart(tmp_path, monkeypatch, built_personas, really_restarts, applied):
    """centos_7 and aws_ec2 both send SSH-2.0-OpenSSH_7.4: the banner check passes even if Cowrie never restarted.
    The pre-restart watch connection must have been dropped for the switch to count."""
    real = _real_rotator()
    assert real.switch_profile.PROFILES["centos_7"]["banner"] == real.switch_profile.PROFILES["aws_ec2"]["banner"]
    srv = _banner_server("SSH-2.0-OpenSSH_7.4")
    addr = srv.getsockname()

    def run(args, **kw):
        if really_restarts:
            srv.restart()
        return MagicMock(returncode=0)
    monkeypatch.setattr(real.subprocess, "run", run)
    cfg = tmp_path / "cowrie.cfg"
    real.switch_profile.CFG_PATH = cfg
    real.switch_profile.generate_config("centos_7")
    original = cfg.read_text()
    client = _decision_client("centos_7", "aws_ec2")
    try:
        result = real.rotate_once(client, cfg, "systemctl restart cowrie", dry_run=False, verify_addr=addr, verify_timeout=2)
    finally:
        srv.restart()
        srv.close()
    assert result["changed"] is applied
    puts = [c for c in client.call.call_args_list if c.args[0] == "PUT"]
    if applied:
        assert puts[-1].kwargs["json"] == {"profile": "aws_ec2", "decisionId": "decision-1"}
    else:
        assert "not restarted" in result["error"] and not puts and cfg.read_text() == original


def test_watch_without_a_running_cowrie_falls_back_to_the_banner(tmp_path):
    real = _real_rotator()
    srv = _banner_server("SSH-2.0-OpenSSH_7.4")
    addr = srv.getsockname()
    srv.restart()
    srv.close()
    assert real.open_watch(addr) is None and real.open_watch(None) is None
