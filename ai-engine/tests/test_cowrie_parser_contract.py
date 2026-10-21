"""Offline parser contract checks; no real telemetry is produced."""
import importlib.util
import logging
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.fixture
def parser(monkeypatch):
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-contract-key")
    source = Path(__file__).resolve().parents[2] / "honeypot/parsers/log_parser.py"
    spec = importlib.util.spec_from_file_location("cowrie_parser_contract", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "post", Mock(return_value=True))
    module.on_connect({"session": "contract-session", "src_ip": "192.0.2.10", "src_port": 12345})
    return module


def test_failed_open_is_not_acknowledged_and_next_event_retries(parser):
    parser.post.side_effect = [False, True]
    event = {"session": "contract-session", "username": "test-user", "password": "test-credential"}
    parser.on_login_failed(event)
    assert parser._sessions["contract-session"]["openedPosted"] is False
    assert parser._sessions["contract-session"]["credentials"] == []
    parser.on_login_failed(event)
    assert parser._sessions["contract-session"]["openedPosted"] is True
    assert len(parser._sessions["contract-session"]["credentials"]) == 1
    assert parser.post.call_count == 2


@pytest.mark.parametrize("handler,event", [
    ("on_cmd", {"input": "id"}),
    ("on_download", {"url": "https://example.invalid/file"}),
    ("on_kex", {"hassh": "contract-hassh"}),
])
def test_dependent_event_is_not_sent_when_open_fails(parser, handler, event):
    parser.post.return_value = False
    getattr(parser, handler)({"session": "contract-session", **event})
    assert parser.post.call_count == 1
    assert parser.post.call_args.args[0] == "/honeypot/ingest"


def test_login_logging_omits_credentials(parser, caplog):
    with caplog.at_level(logging.INFO):
        parser.on_login_ok({"session": "contract-session", "username": "private-user", "password": "private-password"})
    assert "Login SUCCESS" in caplog.text
    assert "private-user" not in caplog.text
    assert "private-password" not in caplog.text
    # Preserve original event data for the existing ingestion contract.
    assert parser._sessions["contract-session"]["credentials"][0]["password"] == "private-password"


def test_command_and_download_logs_omit_sensitive_payload_but_ingestion_preserves_it(parser, caplog):
    secret = "offline-private-command-credential"
    command = f"curl -H 'Authorization: Bearer {secret}' https://example.invalid"
    url = f"https://user:{secret}@example.invalid/file"
    with caplog.at_level(logging.INFO):
        parser.on_cmd({"session": "contract-session", "input": command})
        parser.on_download({"session": "contract-session", "url": url})
    assert secret not in caplog.text
    assert command not in caplog.text
    assert url not in caplog.text
    assert parser._sessions["contract-session"]["commands"][0]["command"] == command
    assert parser.post.call_args.args[1]["url"] == url


def test_malformed_event_exception_does_not_echo_sensitive_values(parser, caplog):
    import json
    parser._sessions["contract-session"]["openedPosted"] = True
    with caplog.at_level(logging.ERROR):
        parser.process(json.dumps({"eventid": "cowrie.session.closed", "session": "contract-session", "duration": "offline-private-credential"}))
    assert "offline-private-credential" not in caplog.text
    assert "ValueError" in caplog.text


def test_failed_close_is_not_logged_as_success_and_preserves_state_for_explicit_retry(parser, caplog):
    parser._sessions['contract-session']['openedPosted'] = True
    parser.post.side_effect = [False, True]
    with caplog.at_level(logging.INFO):
        parser.on_closed({'session': 'contract-session', 'duration': 60})
    assert 'contract-session' in parser._sessions
    assert 'Session closed:' not in caplog.text
    parser.on_closed({'session': 'contract-session', 'duration': 60})
    assert 'contract-session' not in parser._sessions
