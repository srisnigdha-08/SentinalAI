"""Offline tests of honeypot/cowrie/sentinelblocker.py with stand-in Cowrie factories; Cowrie is not needed."""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "honeypot/cowrie/sentinelblocker.py"


class FakeFactory:
    def buildProtocol(self, addr):
        return "protocol"


@pytest.fixture
def blocker(monkeypatch):
    ssh, telnet = type("SSH", (FakeFactory,), {}), type("Telnet", (FakeFactory,), {})
    modules = {
        "cowrie": types.ModuleType("cowrie"),
        "cowrie.core": types.SimpleNamespace(output=types.SimpleNamespace(Output=object)),
        "cowrie.ssh": types.ModuleType("cowrie.ssh"),
        "cowrie.ssh.factory": types.SimpleNamespace(CowrieSSHFactory=ssh),
        "cowrie.telnet": types.ModuleType("cowrie.telnet"),
        "cowrie.telnet.factory": types.SimpleNamespace(HoneyPotTelnetFactory=telnet),
    }
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.setenv("HONEYPOT_API_KEY", "offline-blocker-key")
    spec = importlib.util.spec_from_file_location("sentinelblocker_offline", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.threading, "Thread", Mock())  # no background loop during tests
    monkeypatch.setattr(module.requests, "get", Mock())
    plugin = module.Output()
    plugin.start()
    return module, plugin, ssh, telnet


def deny_list(module, ips, status=200):
    module.requests.get.return_value = Mock(status_code=status, json=Mock(return_value={"data": {"blockedIPs": ips}}))


def test_blocked_ip_is_refused_on_ssh_and_telnet(blocker):
    module, plugin, ssh, telnet = blocker
    deny_list(module, ["203.0.113.9"])
    assert plugin.sync_once() is True
    addr = types.SimpleNamespace(host="203.0.113.9")
    assert ssh().buildProtocol(addr) is None
    assert telnet().buildProtocol(addr) is None
    assert ssh().buildProtocol(types.SimpleNamespace(host="198.51.100.1")) == "protocol"
    assert module.requests.get.call_args.kwargs["headers"] == {"X-API-Key": "offline-blocker-key"}


def test_connections_never_start_threads_or_requests(blocker):
    module, plugin, ssh, _ = blocker
    assert module.threading.Thread.call_count == 1  # only the sync thread, created by start()
    module.requests.get.reset_mock()
    for i in range(200):  # a flood of new source IPs
        ssh().buildProtocol(types.SimpleNamespace(host=f"198.51.100.{i % 250}"))
    assert module.threading.Thread.call_count == 1
    assert module.requests.get.call_count == 0


def test_unblocking_takes_effect_on_next_sync(blocker):
    module, plugin, ssh, _ = blocker
    addr = types.SimpleNamespace(host="203.0.113.9")
    deny_list(module, ["203.0.113.9"]); plugin.sync_once()
    deny_list(module, []); plugin.sync_once()
    assert ssh().buildProtocol(addr) == "protocol"


@pytest.mark.parametrize("failure", ["status", "exception", "bad-shape"])
def test_backend_failure_keeps_the_previous_list(blocker, failure):
    module, plugin, ssh, _ = blocker
    deny_list(module, ["203.0.113.9"]); plugin.sync_once()
    if failure == "status":
        deny_list(module, [], status=503)
    elif failure == "exception":
        module.requests.get.side_effect = ConnectionError("backend down")
    else:
        module.requests.get.return_value = Mock(status_code=200, json=Mock(return_value={"data": {}}))
    assert plugin.sync_once() is False
    assert ssh().buildProtocol(types.SimpleNamespace(host="203.0.113.9")) is None


def test_without_key_nothing_is_requested(blocker, monkeypatch):
    module, plugin, _, _ = blocker
    plugin.api_key = ""
    module.requests.get.reset_mock()
    assert plugin.sync_once() is False
    module.requests.get.assert_not_called()
