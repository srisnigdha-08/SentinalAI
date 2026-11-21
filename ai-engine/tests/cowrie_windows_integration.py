"""Rank 7: the simulated Windows shell inside the REAL Cowrie protocol, in-process (stdlib unittest).

Run with Cowrie's own interpreter from the Cowrie checkout (it needs Cowrie and Twisted importable):

    cd <cowrie>; <cowrie-env>/bin/python <sentinelai>/ai-engine/tests/cowrie_windows_integration.py <sentinelai>/honeypot

Uses Cowrie's own test doubles (cowrie.test.fake_server / fake_transport / eventcapture): a real
HoneyPotInteractiveProtocol / HoneyPotExecProtocol object driven through a fake transport. No listener is opened,
the running honeypot is not touched, nothing is written to Cowrie's var/ directory, and process/socket creation is
patched to fail for the duration. Not collected by pytest on the engine host (no Cowrie there).
"""
import json
import os
import socket
import subprocess
import sys
import unittest

HONEYPOT = sys.argv.pop(1) if len(sys.argv) > 1 else os.environ.get("SENTINEL_HONEYPOT", "")
sys.path.insert(0, HONEYPOT)
os.environ.setdefault("COWRIE_HONEYPOT_DATA_PATH", "data")
os.environ.setdefault("COWRIE_SHELL_FILESYSTEM", "src/cowrie/data/fs.pickle")

import cowrie  # noqa: E402
from cowrie.shell import honeypot, protocol  # noqa: E402
from cowrie.test.eventcapture import capture_events, events_of  # noqa: E402
from cowrie.test.fake_server import FakeAvatar, FakeServer  # noqa: E402
from cowrie.test.fake_transport import FakeTransport  # noqa: E402

from windows_persona import cowrie_hook  # noqa: E402
from windows_persona.cowrie_shell import WindowsCowrieShell  # noqa: E402

PROMPT = b"C:\\Users\\Administrator>"
CALLS = []


def _forbid(name):
    def f(*a, **k):
        CALLS.append(name)
        raise AssertionError(f"{name} called")
    return f


class WindowsShellInCowrie(unittest.TestCase):
    def setUp(self):
        self.assertEqual(cowrie_hook.install(honeypot, enabled=True, persona="windows_srv", allow_experimental=True), "INSTALLED")
        self.proto = protocol.HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        self.tr = FakeTransport("", "31337")
        # Cowrie's own connection setup (before any attacker input) is Cowrie's behaviour, not the simulator's: the
        # process/socket guards and the event capture start once the session exists, and cover every line typed.
        self.proto.makeConnection(self.tr)
        self.events = capture_events(self.proto)
        self.patches = [(subprocess, "Popen"), (subprocess, "run"), (os, "system"), (os, "popen"), (socket, "socket"),
                        (socket, "create_connection")]
        self.saved = [(m, n, getattr(m, n)) for m, n in self.patches]
        for m, n in self.patches:
            setattr(m, n, _forbid(f"{m.__name__}.{n}"))

    def tearDown(self):
        for m, n, f in self.saved:
            setattr(m, n, f)
        self.proto.connectionLost()
        cowrie_hook.uninstall(honeypot)

    def run_line(self, line):
        self.tr.clear()
        self.proto.lineReceived(line.encode() + b"\n")
        return self.tr.value()

    def test_session_starts_with_the_windows_shell_and_prompt(self):
        self.assertIsInstance(self.proto.cmdstack[0], WindowsCowrieShell)
        self.assertTrue(self.tr.value().endswith(PROMPT))

    def test_commands_answer_from_the_simulator(self):
        self.assertEqual(self.run_line("whoami"), b"win-srv19-dc01\\administrator\r\n" + PROMPT)
        self.assertIn(b"Microsoft Windows Server 2019 Datacenter", self.run_line("systeminfo"))
        self.assertIn(b"IPv4 Address. . . . . . . . . . . : 10.20.30.15", self.run_line("ipconfig"))
        self.assertIn(b"Directory of C:\\Users\\Administrator", self.run_line("dir"))
        self.assertTrue(self.run_line("cd Desktop").endswith(b"C:\\Users\\Administrator\\Desktop>"))
        self.assertIn(b"rotate svc_billing password", self.run_line("type notes.txt"))

    def test_linux_commands_and_injection_never_reach_cowrie_or_the_host(self):
        for line in ["uname -a", "cat /etc/passwd", "whoami; id", "whoami && cat /etc/shadow", "$(id)", "`id`",
                     "echo x | sh", "ls -la /", "wget http://example.test/x"]:
            out = self.run_line(line)
            self.assertNotIn(b"root:", out)
            self.assertNotIn(b"Linux", out)
            self.assertTrue(out.endswith(PROMPT), (line, out))
        self.assertEqual(CALLS, [])

    def test_cowrie_events_feed_the_existing_pipeline(self):
        self.run_line("whoami")
        self.run_line("frobnicate --x")
        inputs = [e["input"] for e in events_of(self.events, "cowrie.command.input")]
        self.assertIn("whoami", inputs)
        self.assertIn("frobnicate --x", inputs)
        self.assertEqual([e["input"] for e in events_of(self.events, "cowrie.command.failed")], ["frobnicate --x"])
        sim = events_of(self.events, "sentinel.windows.command")
        self.assertTrue(all(e["simulated"] is True and e["persona"] == "windows_srv" for e in sim))
        self.assertEqual(sim[0]["intent"], "RECONNAISSANCE")

    def test_exit_ends_the_session(self):
        self.run_line("exit")
        self.assertTrue(self.proto._process_ended)


class ExecChannelAndRollback(unittest.TestCase):
    def test_exec_channel_runs_one_simulated_command(self):
        cowrie_hook.install(honeypot, enabled=True, persona="windows_srv", allow_experimental=True)
        try:
            proto = protocol.HoneyPotExecProtocol(FakeAvatar(FakeServer()), b"hostname")
            tr = FakeTransport("", "31337")
            proto.makeConnection(tr)
            self.assertIn(b"WIN-SRV19-DC01", tr.value())
            proto.connectionLost()
        finally:
            cowrie_hook.uninstall(honeypot)

    def test_disabled_or_wrong_persona_leaves_the_linux_shell(self):
        for kw in ({"enabled": False, "persona": "windows_srv", "allow_experimental": True},
                   {"enabled": True, "persona": "ubuntu_22", "allow_experimental": True},
                   {"enabled": True, "persona": "windows_srv", "allow_experimental": False}):
            self.assertNotEqual(cowrie_hook.install(honeypot, **kw), "INSTALLED")
            self.assertEqual(honeypot.HoneyPotShell.__module__, "cowrie.shell.honeypot")

    def test_uninstall_restores_cowries_own_shell(self):
        cowrie_hook.install(honeypot, enabled=True, persona="windows_srv", allow_experimental=True)
        self.assertTrue(cowrie_hook.uninstall(honeypot))
        proto = protocol.HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        tr = FakeTransport("", "31337")
        proto.makeConnection(tr)
        self.assertNotIsInstance(proto.cmdstack[0], WindowsCowrieShell)
        proto.connectionLost()


if __name__ == "__main__":
    version = getattr(cowrie, "__version__", None)
    try:
        from cowrie._version import __version__ as version  # noqa: F811
    except ImportError:
        pass
    result = unittest.main(exit=False, verbosity=2).result
    print(json.dumps({"cowrieVersion": version, "testsRun": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "forbiddenCalls": CALLS}))
    sys.exit(0 if result.wasSuccessful() and not CALLS else 1)
