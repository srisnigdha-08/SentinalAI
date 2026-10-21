"""
Cowrie parser failure scenarios (docs/HONEYPOT_STUDY_GUIDE.md 3.5): parser restart, log rotation, partial
lines, backend outage, lost session state and duplicate delivery. Offline: deliveries go to a fake _send.
"""
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def parser(monkeypatch, tmp_path):
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-reliability-key")
    module = _load("cowrie_parser_reliability", ROOT / "honeypot/parsers/log_parser.py")
    monkeypatch.setattr(module, "STATE_DIR", tmp_path / "state")
    module.sent = []
    module.backend = "up"

    def fake_send(ep, data, retries=0):
        if module.backend == "down":
            return "transient"
        if module.backend == "reject":
            return "rejected"
        module.sent.append((ep, data))
        return "ok"

    monkeypatch.setattr(module, "_send", fake_send)
    return module


def restart(parser):
    """What a parser process restart loses: everything in memory."""
    parser._sessions.clear()
    parser._spool.clear()


def line(eventid, session="s1", **fields):
    event = {"eventid": eventid, "session": session, "src_ip": "192.0.2.7",
             "timestamp": f"2026-10-21T10:00:{len(fields):02d}.{abs(hash(str(fields))) % 999999:06d}Z", **fields}
    return (json.dumps(event) + "\n").encode()


def commands_sent(parser):
    return [d["command"] for ep, d in parser.sent if ep == "/honeypot/ingest/command"]


def test_restart_resumes_from_saved_offset_with_session_state(parser, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(line("cowrie.session.connect") + line("cowrie.login.success", username="root", password="x")
                    + line("cowrie.command.input", input="id"))
    with open(log, "rb") as f:
        parser.read_lines(f, 0, log.stat().st_ino)
    restart(parser)
    with open(log, "ab") as f:  # written while the parser was down
        f.write(line("cowrie.command.input", input="uname -a") + line("cowrie.session.closed", duration=5))

    pos = parser.resume_position(log, parser.load_state())
    assert "s1" in parser._sessions  # credentials and commands survived the restart
    with open(log, "rb") as f:
        parser.read_lines(f, pos, log.stat().st_ino)

    assert commands_sent(parser) == ["id", "uname -a"]
    close = [d for ep, d in parser.sent if ep == "/honeypot/ingest/close"][0]
    assert close["credentials"][0]["username"] == "root" and len(close["commands"]) == 2


def test_first_start_without_state_begins_at_end_unless_from_start(parser, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(line("cowrie.session.connect"))
    assert parser.resume_position(log, None) == log.stat().st_size
    assert parser.resume_position(log, None, from_start=True) == 0


def test_partial_line_is_not_consumed_until_complete(parser, tmp_path):
    log = tmp_path / "cowrie.json"
    full = line("cowrie.session.connect") + line("cowrie.command.input", input="whoami")
    log.write_bytes(full[:-10])  # Cowrie is mid-write
    ino = log.stat().st_ino
    with open(log, "rb") as f:
        pos = parser.read_lines(f, 0, ino)
    assert commands_sent(parser) == [] and pos == len(line("cowrie.session.connect"))
    log.write_bytes(full)
    with open(log, "rb") as f:
        parser.read_lines(f, pos, ino)
    assert commands_sent(parser) == ["whoami"]


def test_rotation_while_stopped_finishes_the_rotated_file_first(parser, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_bytes(line("cowrie.session.connect"))
    with open(log, "rb") as f:
        parser.read_lines(f, 0, log.stat().st_ino)
    restart(parser)
    with open(log, "ab") as f:
        f.write(line("cowrie.command.input", input="before-rotation"))
    log.rename(tmp_path / "cowrie.json.2026-10-21")  # Cowrie's daily rotation
    log.write_bytes(line("cowrie.command.input", input="after-rotation"))

    pos = parser.resume_position(log, parser.load_state())
    assert pos == 0
    with open(log, "rb") as f:
        parser.read_lines(f, pos, log.stat().st_ino)
    assert commands_sent(parser) == ["before-rotation", "after-rotation"]


def test_backend_outage_spools_in_order_and_survives_restart(parser):
    parser.on_connect({"session": "s1", "src_ip": "192.0.2.7"})
    parser.backend = "down"
    parser.on_cmd({"session": "s1", "input": "id", "timestamp": "t1"})  # opens the session, then the command
    parser.on_cmd({"session": "s1", "input": "ls", "timestamp": "t2"})
    assert parser.sent == [] and len(parser._spool) == 3
    restart(parser)
    parser.load_spool()
    assert [item["ep"] for item in parser._spool] == ["/honeypot/ingest", "/honeypot/ingest/command", "/honeypot/ingest/command"]

    parser.backend = "up"
    parser.flush_spool(force=True)
    assert [ep for ep, _ in parser.sent] == ["/honeypot/ingest", "/honeypot/ingest/command", "/honeypot/ingest/command"]
    assert commands_sent(parser) == ["id", "ls"]
    assert parser._spool == [] and parser._spool_path().read_text() == ""


def test_new_events_queue_behind_spooled_ones(parser):
    parser.on_connect({"session": "s1", "src_ip": "192.0.2.7"})
    parser.backend = "down"
    parser.on_cmd({"session": "s1", "input": "id"})
    parser.backend = "up"
    parser._spool_next_try = float("inf")  # retry not due yet: the next event must not overtake the queue
    parser.on_cmd({"session": "s1", "input": "ls"})
    assert parser.sent == [] and len(parser._spool) == 3
    parser.flush_spool(force=True)
    assert commands_sent(parser) == ["id", "ls"]


def test_rejected_event_is_not_spooled(parser):
    parser.backend = "reject"
    assert parser.post("/honeypot/ingest", {"eventType": "SESSION_OPENED"}) is False
    assert parser._spool == []


def test_lost_session_state_is_rebuilt_from_the_event(parser):
    parser.on_cmd({"session": "s9", "src_ip": "192.0.2.9", "input": "id", "timestamp": "t"})
    assert [ep for ep, _ in parser.sent] == ["/honeypot/ingest", "/honeypot/ingest/command"]
    assert parser.sent[0][1]["sourceIP"] == "192.0.2.9"


def test_events_carry_ids_matching_the_output_plugin(parser, monkeypatch):
    cowrie = types.ModuleType("cowrie")
    core = types.ModuleType("cowrie.core")
    core.output = types.SimpleNamespace(Output=object)
    config = types.ModuleType("cowrie.core.config")
    config.CowrieConfig = types.SimpleNamespace(get=lambda *a, **k: "")
    for name, mod in (("cowrie", cowrie), ("cowrie.core", core), ("cowrie.core.config", config)):
        monkeypatch.setitem(sys.modules, name, mod)
    plugin = _load("cowrie_output_ids", ROOT / "honeypot/cowrie/sentinel_output.py")

    event = {"eventid": "cowrie.command.input", "session": "s1", "src_ip": "192.0.2.7",
             "timestamp": "2026-10-21T10:00:00.123456Z", "input": "id"}
    parser.on_cmd(event)
    sent_id = parser.sent[-1][1]["eventId"]
    assert sent_id == parser.event_id(event, "id") == plugin.event_id(event, "id")
    assert parser.event_id({**event, "timestamp": "2026-10-21T10:00:00.123457Z"}, "id") != sent_id
    assert parser.event_id({k: v for k, v in event.items() if k != "timestamp"}, "id") is None
