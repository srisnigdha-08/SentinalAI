"""Phase 5 parser additions: delivery metrics and exporter, JSON logs, client version and TTY-recording capture,
canary reads, and the edge cases from 5.4 (unknown eventid, malformed JSON, truncation)."""
import importlib.util
import json
import logging
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def parser(monkeypatch, tmp_path):
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-observability-key")
    spec = importlib.util.spec_from_file_location("cowrie_parser_obs", ROOT / "honeypot/parsers/log_parser.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "STATE_DIR", tmp_path / "state")
    module.sent, module.backend = [], "up"

    def fake_send(ep, data, retries=0):
        if module.backend != "up":
            return module.backend
        module.sent.append((ep, data))
        return "ok"

    monkeypatch.setattr(module, "_send", fake_send)
    return module


def ev(eventid, **f):
    return json.dumps({"eventid": eventid, "session": "o1", "src_ip": "192.0.2.5",
                       "timestamp": "2026-10-21T10:00:00.000001Z", **f})


def test_metrics_count_reads_deliveries_rejections_and_spooling(parser):
    parser.process(ev("cowrie.session.connect"))
    parser.process(ev("cowrie.command.input", input="id"))          # open + command delivered
    parser.backend = "rejected"
    parser.process(ev("cowrie.command.input", input="ls"))          # rejected (4xx)
    parser.backend = "transient"
    parser.process(ev("cowrie.command.input", input="uname"))       # queued
    m = parser.METRICS
    assert m == {"read": 4, "posted": 2, "rejected": 1, "spooled": 1}
    text = parser.metrics_text(now=parser._cowrie_time("2026-10-21T10:00:30.000001Z"))
    assert "cowrie_parser_events_posted_total 2" in text and "cowrie_parser_spool_depth 1" in text
    assert "cowrie_parser_lag_seconds 30.0" in text


def test_metrics_exporter_serves_prometheus_text_on_loopback(parser):
    server = parser.start_metrics_server(0)
    try:
        port = server.server_address[1]
        assert server.server_address[0] == "127.0.0.1"
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()
        assert "# TYPE cowrie_parser_events_read_total counter" in body
        assert "cowrie_parser_lag_seconds NaN" in body  # nothing processed yet
    finally:
        server.shutdown()


def test_json_log_format(parser):
    record = logging.LogRecord("sentinel.parser", logging.WARNING, __file__, 1, "queued %s", ("/x",), None)
    out = json.loads(parser._JsonFormatter().format(record))
    assert out["level"] == "warning" and out["msg"] == "queued /x" and out["ts"].endswith("Z")


def test_unknown_eventid_and_malformed_json_are_counted_and_skipped(parser, caplog):
    parser.process(ev("cowrie.direct-tcpip.request", dst_ip="10.0.0.1"))
    with caplog.at_level(logging.ERROR):
        parser.process('{"eventid": "cowrie.command.input", "session": ')
    assert parser.METRICS["read"] == 2 and parser.sent == []
    assert "JSONDecodeError" in caplog.text


def test_client_version_and_tty_recording_reach_the_backend(parser):
    parser.process(ev("cowrie.session.connect"))
    parser.process(ev("cowrie.client.version", version="SSH-2.0-libssh_0.9.6"))
    parser.process(ev("cowrie.client.kex", hassh="ab" * 16))
    kex = [d for ep, d in parser.sent if d.get("eventType") == "CLIENT_KEX"][0]
    assert kex["clientVersion"] == "SSH-2.0-libssh_0.9.6"
    parser.process(ev("cowrie.log.closed", ttylog="var/lib/cowrie/tty/" + "c" * 64, size=1982, shasum="c" * 64))
    parser.process(ev("cowrie.session.closed", duration_ms=4200))
    close = [d for ep, d in parser.sent if ep == "/honeypot/ingest/close"][0]
    assert close["ttylog"] == {"sha256": "c" * 64, "size": 1982, "path": "var/lib/cowrie/tty/" + "c" * 64}
    assert close["durationSeconds"] == 4


@pytest.mark.parametrize("cmd", ["cat ~/.aws/credentials", "cat /root/.ssh/id_rsa", "less .git-credentials"])
def test_canary_reads_are_credential_harvesting(parser, cmd):
    assert parser.classify_intent(cmd) == "CREDENTIAL_HARVEST"


def test_truncated_log_since_last_run_is_read_from_the_start(parser, tmp_path):
    log = tmp_path / "cowrie.json"
    log.write_text(ev("cowrie.session.connect") + "\n")
    state = {"ino": log.stat().st_ino, "pos": 10_000, "sessions": {}}
    assert parser.resume_position(log, state) == 0
