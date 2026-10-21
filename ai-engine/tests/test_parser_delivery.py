"""M12: Cowrie parser delivery retries transient failures, keeps Cowrie's start time, and closes sessions
it lost track of after a restart. Offline: requests.post is replaced, no telemetry leaves the process."""
import importlib.util
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests


@pytest.fixture
def parser(monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-delivery-key")
    source = Path(__file__).resolve().parents[2] / "honeypot/parsers/log_parser.py"
    spec = importlib.util.spec_from_file_location("cowrie_parser_delivery", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.time, "sleep", lambda s: None)  # no real backoff waits
    return module


def response(status):
    return Mock(status_code=status)


def test_transient_failures_are_retried_then_delivered(parser, monkeypatch):
    calls = Mock(side_effect=[requests.ConnectionError(), response(503), response(201)])
    monkeypatch.setattr(parser.requests, "post", calls)
    assert parser.post("/honeypot/ingest", {"eventType": "SESSION_OPENED"}) is True
    assert calls.call_count == 3


def test_client_errors_are_not_retried(parser, monkeypatch):
    calls = Mock(return_value=response(400))
    monkeypatch.setattr(parser.requests, "post", calls)
    assert parser.post("/honeypot/ingest", {}) is False
    assert calls.call_count == 1


def test_exhausted_retries_queue_the_event_for_redelivery(parser, monkeypatch):
    # After the configured retries a transient failure is no longer dropped: it is spooled to disk
    # (accepted, so post() returns True) and redelivered in order later (test_cowrie_parser_reliability.py).
    calls = Mock(side_effect=requests.Timeout())
    monkeypatch.setattr(parser.requests, "post", calls)
    assert parser.post("/honeypot/ingest/command", {"sessionId": "s1"}) is True
    assert calls.call_count == parser.POST_RETRIES + 1
    assert parser._spool == [{"ep": "/honeypot/ingest/command", "data": {"sessionId": "s1"}}]
    assert parser._spool_path().parent == parser.STATE_DIR and "cowrie-parser-state" in str(parser.STATE_DIR)


def test_session_open_carries_cowrie_timestamp(parser, monkeypatch):
    sent = Mock(return_value=True)
    monkeypatch.setattr(parser, "post", sent)
    parser.on_connect({"session": "s1", "src_ip": "192.0.2.10", "src_port": 2222, "timestamp": "2017-07-07T13:30:00.123Z"})
    parser.on_cmd({"session": "s1", "input": "id"})
    endpoint, body = sent.call_args_list[0].args
    assert endpoint == "/honeypot/ingest" and body["eventType"] == "SESSION_OPENED"
    assert body["startTime"] == "2017-07-07T13:30:00.123Z"


@pytest.mark.parametrize("event,seconds", [
    ({"duration_ms": 10019}, 10),         # current Cowrie (milliseconds)
    ({"duration": 42.7}, 42),             # older Cowrie (seconds)
    ({"duration_ms": 900, "duration": 99}, 0),  # duration_ms wins when both are present
    ({}, 0),
])
def test_close_duration_from_both_cowrie_formats(parser, monkeypatch, event, seconds):
    sent = Mock(return_value=True)
    monkeypatch.setattr(parser, "post", sent)
    parser.on_connect({"session": "d1", "src_ip": "192.0.2.12"})
    parser._sessions["d1"]["openedPosted"] = True
    parser.on_closed({"session": "d1", **event})
    assert sent.call_args.args[1]["durationSeconds"] == seconds


def test_close_without_parser_state_is_still_delivered(parser, monkeypatch):
    sent = Mock(return_value=True)
    monkeypatch.setattr(parser, "post", sent)
    parser.on_closed({"session": "lost-after-restart", "src_ip": "192.0.2.11", "duration": 42.7})
    sent.assert_called_once_with("/honeypot/ingest/close",
                                 {"sessionId": "lost-after-restart", "sourceIP": "192.0.2.11", "durationSeconds": 42})
    # Without a source IP the backend would reject it, so nothing is sent.
    sent.reset_mock()
    parser.on_closed({"session": "no-ip"})
    sent.assert_not_called()
