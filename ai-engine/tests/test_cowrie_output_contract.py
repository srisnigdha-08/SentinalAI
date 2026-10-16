"""Offline dictionary-event dispatch only. Does not instantiate or contact Cowrie."""
import importlib.util
import logging
import sys
import types
from pathlib import Path
from unittest.mock import Mock
import pytest


@pytest.fixture
def plugin(monkeypatch):
    cowrie = types.ModuleType('cowrie')
    core = types.ModuleType('cowrie.core')
    core.output = types.SimpleNamespace(Output=object)
    config = types.ModuleType('cowrie.core.config')
    config.CowrieConfig = types.SimpleNamespace(get=lambda section, key, fallback='': 'offline-key' if key == 'api_key' else fallback)
    monkeypatch.setitem(sys.modules, 'cowrie', cowrie)
    monkeypatch.setitem(sys.modules, 'cowrie.core', core)
    monkeypatch.setitem(sys.modules, 'cowrie.core.config', config)
    spec = importlib.util.spec_from_file_location('cowrie_output_offline', Path(__file__).resolve().parents[2] / 'honeypot/cowrie/sentinel_output.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    monkeypatch.setattr(module.requests, 'post', Mock(return_value=Mock(raise_for_status=Mock())))
    instance = module.Output(); instance.start()
    return module, instance


def test_normalized_event_dispatch_keeps_credentials_private_until_supported_close(plugin, caplog):
    module, instance = plugin
    with caplog.at_level(logging.INFO):
        instance.write({'eventid': 'cowrie.session.connect', 'session': 'offline', 'src_ip': '192.0.2.10', 'src_port': 12345})
        instance.write({'eventid': 'cowrie.login.failed', 'session': 'offline', 'username': 'private-user', 'password': 'private-captured-password'})
        instance.write({'eventid': 'cowrie.command.input', 'session': 'offline', 'input': 'id'})
        instance.write({'eventid': 'cowrie.session.closed', 'session': 'offline'})
    events = [call.kwargs['json'] for call in module.requests.post.call_args_list]
    assert [event['eventType'] for event in events] == ['SESSION_OPENED', 'COMMAND_INPUT', 'SESSION_CLOSED']
    assert events[-1]['credentials'][0]['password'] == 'private-captured-password'
    assert 'private-captured-password' not in caplog.text
    assert 'offline' not in instance.sessions


def test_sessions_are_instance_local_and_unknown_events_do_not_post(plugin):
    module, first = plugin
    second = module.Output(); second.start()
    first.write({'eventid': 'cowrie.session.connect', 'session': 'offline', 'src_ip': '192.0.2.10'})
    module.requests.post.reset_mock()
    first.write({'eventid': 'unknown', 'session': 'offline'})
    first.write({'eventid': 'cowrie.command.input', 'session': 'unknown', 'input': 'id'})
    assert 'offline' not in second.sessions
    module.requests.post.assert_not_called()


def test_failed_close_retains_local_state_and_error_log_omits_payload(plugin, caplog):
    module, instance = plugin
    instance.write({'eventid': 'cowrie.session.connect', 'session': 'offline', 'src_ip': '192.0.2.10'})
    module.requests.post.side_effect = RuntimeError('private-captured-password')
    with caplog.at_level(logging.WARNING):
        instance.write({'eventid': 'cowrie.session.closed', 'session': 'offline'})
    assert 'offline' in instance.sessions
    assert 'RuntimeError' in caplog.text
    assert 'private-captured-password' not in caplog.text


def test_missing_key_fails_plugin_startup(plugin):
    module, instance = plugin
    module.CowrieConfig.get = lambda section, key, fallback='': fallback
    with pytest.raises(ValueError, match='internal API key'):
        instance.start()
