"""
Cowrie events the parser used to drop and the guide's Phase 5 fixes (docs/COWRIE_COMPLETE_GUIDE.md):
M1 cowrie.command.failed, M3 file uploads and port-forward requests, M4 no passwords at rest, L2 lag clamp.
Offline: deliveries go to a fake _send.
"""
import importlib.util
import json
import time
from datetime import datetime, timezone
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
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-events-key")
    monkeypatch.delenv("COWRIE_PERSONA", raising=False)
    module = _load("cowrie_parser_events", ROOT / "honeypot/parsers/log_parser.py")
    monkeypatch.setattr(module, "STATE_DIR", tmp_path / "state")
    module.COWRIE_CFG = None
    module.sent = []
    module.backend = "up"

    def fake_send(ep, data, retries=0):
        if module.backend == "down":
            return "transient"
        module.sent.append((ep, data))
        return "ok"

    monkeypatch.setattr(module, "_send", fake_send)
    return module


def ev(parser, eventid, n=0, **fields):
    event = {"eventid": eventid, "session": "s1", "src_ip": "192.0.2.7",
             "timestamp": f"2026-10-22T06:31:{n:02d}.000001Z", **fields}
    parser.process(json.dumps(event))


def opened(parser):
    ev(parser, "cowrie.session.connect", 0)
    ev(parser, "cowrie.client.kex", 1, hassh="ab" * 16)


def ingest(parser, event_type):
    return [d for ep, d in parser.sent if ep == "/honeypot/ingest" and d.get("eventType") == event_type]


def test_command_failed_is_delivered_as_command_failed_with_its_own_event_id(parser):
    opened(parser)
    ev(parser, "cowrie.command.input", 2, input="notarealcommand")
    ev(parser, "cowrie.command.failed", 3, input="notarealcommand ")
    [failed] = ingest(parser, "COMMAND_FAILED")
    assert failed["command"] == "notarealcommand" and failed["sourceIP"] == "192.0.2.7"
    [command] = [d for ep, d in parser.sent if ep == "/honeypot/ingest/command"]
    assert len(failed["eventId"]) == 32 and failed["eventId"] != command["eventId"]


def test_upload_is_delivered_with_its_hash(parser):
    opened(parser)
    sha = "c" * 64
    ev(parser, "cowrie.session.file_upload", 2, filename="x.sh", outfile="var/lib/cowrie/downloads/" + sha, shasum=sha)
    [upload] = ingest(parser, "FILE_UPLOAD")
    assert upload["filename"] == "x.sh" and upload["sha256"] == sha and len(upload["eventId"]) == 32


def test_upload_with_a_malformed_hash_is_sent_without_it(parser):
    opened(parser)
    ev(parser, "cowrie.session.file_upload", 2, filename="x.sh", shasum="not-a-hash")
    [upload] = ingest(parser, "FILE_UPLOAD")
    assert "sha256" not in upload


def test_port_forward_request_is_delivered_and_bad_ports_are_ignored(parser):
    opened(parser)
    ev(parser, "cowrie.direct-tcpip.request", 2, dst_ip="203.0.113.9", dst_port=25, orig_ip="127.0.0.1", orig_port=0)
    ev(parser, "cowrie.direct-tcpip.request", 3, dst_ip="203.0.113.9", dst_port="smtp")
    ev(parser, "cowrie.direct-tcpip.request", 4, dst_ip="203.0.113.9", dst_port=70000)
    [tunnel] = ingest(parser, "TUNNEL_REQUEST")
    assert tunnel["dstIP"] == "203.0.113.9" and tunnel["dstPort"] == 25


def test_passwords_never_reach_state_spool_or_backend(parser):
    secret = "hunter2-plaintext"
    opened(parser)
    ev(parser, "cowrie.login.failed", 2, username="root", password=secret)
    ev(parser, "cowrie.login.success", 3, username="root", password=secret)
    parser.save_state(1, 0)
    parser.backend = "down"
    ev(parser, "cowrie.session.closed", 4, duration_ms=4000)
    state = (parser.STATE_DIR / "state.json").read_text(encoding="utf-8")
    spool = (parser.STATE_DIR / "spool.jsonl").read_text(encoding="utf-8")
    assert secret not in state and secret not in spool
    parser.backend = "up"
    parser.flush_spool(force=True)
    [close] = [d for ep, d in parser.sent if ep == "/honeypot/ingest/close"]
    assert close["credentials"] == [{"username": "root", "success": False}, {"username": "root", "success": True}]
    assert secret not in json.dumps(parser.sent)


def test_future_timestamps_do_not_drive_lag_negative(parser):
    now = time.time()
    future = datetime.fromtimestamp(now + 3600, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    recent = datetime.fromtimestamp(now - 10, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    parser.process(json.dumps({"eventid": "cowrie.client.size", "session": "s9", "timestamp": recent}))
    parser.process(json.dumps({"eventid": "cowrie.totally.unknown", "session": "s9", "timestamp": future}))
    lag = [line for line in parser.metrics_text(now).splitlines() if line.startswith("cowrie_parser_lag_seconds ")]
    assert float(lag[0].split()[1]) == pytest.approx(10, abs=1)
