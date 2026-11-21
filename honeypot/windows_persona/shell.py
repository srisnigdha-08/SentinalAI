"""Windows-style command simulator for the windows_srv persona (Rank 7).

A pure function of its own state: every command an attacker types is parsed here and answered from an explicit
allowlist with fictional output. Nothing is ever executed on the host. This module imports no process, network
or host-filesystem facility (no os, subprocess, socket, pathlib, open, eval or exec); networking commands print
simulated results, and file operations go to the session's own VirtualFS.

Supported syntax: cmd-style `&`, `&&`, `||`, `|`, `^` escapes, `%VAR%` expansion from the simulated environment,
and `>`, `>>`, `2>`, `<` redirection into/out of the virtual filesystem only. PowerShell mode supports `;` and `|`.
Anything else (command substitution, scripts, unknown programs) is inert text that produces a Windows-style error.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import persona
from .telemetry import attack_techniques, category_of, classify_windows_intent
from .vfs import VfsError, VirtualFS

MAX_LINE = 8191
MAX_OUTPUT = 64 * 1024
MAX_SEGMENTS = 32
MAX_DEPTH = 3
# Rank 8: hard per-line event budget, shared by every nested cmd /c, cmd /k and powershell -c/-enc of that line. When
# it is used up, nothing further on the line runs; Result.limits says why. Same reference value as MAX_SEGMENTS.
MAX_EVENTS_PER_LINE = 32
# Rank 8: at most this many redirections per statement (cmd creates every target, only the last gets the output).
MAX_REDIRECTIONS = 8
ESCAPED = {">": "\ue001", "<": "\ue002"}
UNESCAPE = str.maketrans({v: k for k, v in ESCAPED.items()})

NOT_RECOGNISED_CMD = "'{0}' is not recognized as an internal or external command,\noperable program or batch file."
NOT_RECOGNISED_PS = ("{0} : The term '{0}' is not recognized as the name of a cmdlet, function, script file, or operable "
                     "program. Check the spelling of the name, or if a path was included, verify that the path is correct "
                     "and try again.\nAt line:1 char:1\n+ {0}\n+ {1}\n    + CategoryInfo          : ObjectNotFound: "
                     "({0}:String) [], CommandNotFoundException\n    + FullyQualifiedErrorId : CommandNotFoundException")


@dataclass
class Result:
    output: str = ""
    exit_code: int = 0
    clear: bool = False
    exit_session: bool = False
    events: list = field(default_factory=list)
    limits: list = field(default_factory=list)  # Rank 8: e.g. ["EVENT_LIMIT"] when a line hit a hard limit
    budget: object = field(default=None, repr=False, compare=False)

    @property
    def failed(self) -> bool:
        return any(not e["recognised"] for e in self.events)


class _Budget:
    """Work done for one input line, across all nesting levels."""
    __slots__ = ("events",)

    def __init__(self):
        self.events = 0


@dataclass
class _Out:
    text: str = ""
    code: int = 0
    recognised: bool = True
    name: str = ""


def _q(s):
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] == '"' else s


class WindowsShell:
    """One simulated session. `clock` is injectable for deterministic tests."""

    def __init__(self, vfs: VirtualFS | None = None, clock=None):
        self.vfs = vfs or VirtualFS()
        self.ident = persona.IDENTITY
        self.net = persona.NETWORK
        self.cwd = self.ident["home"]
        self.mode = "cmd"
        self.ps_from_cmd = False
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.env = {
            "ALLUSERSPROFILE": "C:\\ProgramData", "APPDATA": "C:\\Users\\Administrator\\AppData\\Roaming",
            "COMPUTERNAME": self.ident["hostname"], "ComSpec": "C:\\Windows\\system32\\cmd.exe",
            "HOMEDRIVE": "C:", "HOMEPATH": "\\Users\\Administrator",
            "LOCALAPPDATA": "C:\\Users\\Administrator\\AppData\\Local", "NUMBER_OF_PROCESSORS": "2", "OS": "Windows_NT",
            "PATH": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\;C:\\Windows\\System32\\OpenSSH\\",
            "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC", "PROCESSOR_ARCHITECTURE": "AMD64",
            "PROMPT": "$P$G", "ProgramData": "C:\\ProgramData", "ProgramFiles": "C:\\Program Files",
            "PUBLIC": "C:\\Users\\Public", "SystemDrive": "C:", "SystemRoot": "C:\\Windows",
            "TEMP": "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp", "TMP": "C:\\Users\\ADMINI~1\\AppData\\Local\\Temp",
            "USERDOMAIN": self.ident["hostname"], "USERNAME": self.ident["username"],
            "USERPROFILE": self.ident["home"], "windir": "C:\\Windows",
        }

    # ── prompt ──────────────────────────────────────────────────────────────────────────────────────────────────
    def prompt(self) -> str:
        return f"PS {self.cwd}> " if self.mode == "ps" else f"{self.cwd}>"

    # ── entry point ─────────────────────────────────────────────────────────────────────────────────────────────
    def execute(self, line: str, _depth=0, _budget=None) -> Result:
        res = Result(budget=_budget if _budget is not None else _Budget())
        text = str(line or "").replace("\r", "").replace("\n", " ")
        if not text.strip():
            return res
        if len(text) > MAX_LINE:
            res.output, res.exit_code = "The command line is too long.", 1
            self._add_event(res, self._event(text[:256], "", False, 1))
            return res
        mode = self.mode
        try:
            pieces = self._split(text, mode)
        except ValueError as e:
            res.output, res.exit_code = str(e), 1
            self._add_event(res, self._event(text[:256], "syntax-error", True, 1))
            return res
        outputs, last = [], 0
        for i, (op, pipeline) in enumerate(pieces[:MAX_SEGMENTS]):
            if op == "&&" and last != 0 or op == "||" and last == 0:
                continue
            stdin = None
            for j, seg in enumerate(pipeline):
                if res.budget.events >= MAX_EVENTS_PER_LINE:
                    self._limit(res, "EVENT_LIMIT")
                    break
                o = self._run_segment(seg, stdin, res, _depth)
                if o is None:  # cls / exit handled
                    break
                stdin = o.text
                last = o.code
                self._add_event(res, self._event(seg, o.name, o.recognised, o.code))
                if j == len(pipeline) - 1 and o.text:
                    outputs.append(o.text)
            if res.exit_session or "EVENT_LIMIT" in res.limits:
                break
        if len(pieces) > MAX_SEGMENTS:
            self._limit(res, "STATEMENT_LIMIT")
        out = "\n".join(t.rstrip("\n") for t in outputs if t is not None)
        if len(out) > MAX_OUTPUT:
            self._limit(res, "OUTPUT_LIMIT")
        res.output = out[:MAX_OUTPUT]
        res.exit_code = 1 if "EVENT_LIMIT" in res.limits and last == 0 else last
        return res

    @staticmethod
    def _limit(res, name):
        if name not in res.limits:
            res.limits.append(name)

    def _add_event(self, res, ev):
        """Record an event if the line's budget allows it (the budget is shared with nested shells)."""
        if res.budget.events >= MAX_EVENTS_PER_LINE:
            self._limit(res, "EVENT_LIMIT")
            return False
        res.budget.events += 1
        res.events.append(ev)
        return True

    def _child(self, mode):
        """A nested shell (cmd /c, cmd /k, powershell -c/-enc). It shares only the session's virtual disk and its
        identity; the environment is a copy and the working directory its own, so nothing it changes reaches this
        shell unless the caller adopts it on purpose (cmd /k)."""
        child = WindowsShell(vfs=self.vfs, clock=self.clock)
        child.env = dict(self.env)
        child.cwd = self.cwd
        child.mode = mode
        return child

    def _run_child(self, child, script, res, depth):
        r = child.execute(script, depth + 1, _budget=res.budget)
        res.events.extend(r.events)  # already counted in the shared budget
        for name in r.limits:
            self._limit(res, name)
        return r

    # ── parsing ─────────────────────────────────────────────────────────────────────────────────────────────────
    def _split(self, text, mode):
        """[(operator_before, [pipeline segments])]. Operators inside double quotes or ^-escaped are literal."""
        if mode == "cmd":
            text = self._expand(text)
        pieces, cur, segs, op = [], [], [], "&"
        i, inq = 0, False
        while i < len(text):
            ch = text[i]
            if mode == "cmd" and ch == "^" and not inq and i + 1 < len(text):
                cur.append(ESCAPED.get(text[i + 1], text[i + 1])); i += 2; continue
            if ch == '"':
                inq = not inq; cur.append(ch); i += 1; continue
            if not inq:
                two = text[i:i + 2]
                if two in ("&&", "||"):
                    if mode == "ps":
                        raise ValueError(f"At line:1 char:{i + 1}\n+ {text}\nThe token '{two}' is not a valid statement separator in this version.")
                    segs.append("".join(cur).strip()); pieces.append((op, segs)); segs, cur, op = [], [], two; i += 2; continue
                if ch == "|":
                    segs.append("".join(cur).strip()); cur = []; i += 1; continue
                if (ch == "&" and mode == "cmd") or (ch == ";" and mode == "ps"):
                    segs.append("".join(cur).strip()); pieces.append((op, segs)); segs, cur, op = [], [], "&"; i += 1; continue
            cur.append(ch); i += 1
        segs.append("".join(cur).strip())
        pieces.append((op, segs))
        out = []
        for op, pipeline in pieces:
            if any(s == "" for s in pipeline) and len(pipeline) > 1:
                raise ValueError("The syntax of the command is incorrect." if mode == "cmd" else
                                 "An empty pipe element is not allowed.")
            pipeline = [s for s in pipeline if s]
            if pipeline:
                out.append((op, pipeline))
        return out

    def _expand(self, text):
        low = {k.lower(): v for k, v in self.env.items()}
        return re.sub(r"%([A-Za-z_][A-Za-z0-9_()]*)%", lambda m: low.get(m.group(1).lower(), m.group(0)), text)

    @staticmethod
    def _tokens(seg):
        # Rank 8: an unterminated quote runs to the end of the segment (cmd behaviour); it used to be dropped, and a
        # segment made only of quote characters produced no token at all and crashed the shell.
        return re.findall(r'"[^"]*"?|[^\s"]+', seg)

    def _redirections(self, seg):
        """Strip redirections; return (segment, [(fd, mode, target)], stdin_file)."""
        reds, stdin_file = [], None
        pat = re.compile(r'(?<![\w^])(\d?)(>>|>)(&\d)?\s*("[^"]*"|[^\s"<>]+)?|<\s*("[^"]*"|[^\s"<>]+)')
        def repl(m):
            nonlocal stdin_file
            if m.group(5) is not None:
                stdin_file = _q(m.group(5))
            elif m.group(3):
                pass  # 2>&1: merge, nothing to do
            else:
                reds.append((m.group(1) or "1", m.group(2), _q(m.group(4) or "")))
            return " "
        # redirection characters inside quotes are literal
        parts = re.split(r'("[^"]*")', seg)
        rebuilt = "".join(p if p.startswith('"') else pat.sub(repl, p) for p in parts)
        return rebuilt.strip(), reds, stdin_file

    # ── execution of one segment ────────────────────────────────────────────────────────────────────────────────
    def _run_segment(self, seg, stdin, res, depth):
        seg, reds, stdin_file = self._redirections(seg)
        seg = seg.translate(UNESCAPE)
        for fd, how, target in reds:
            if target == "":
                return _Out("The syntax of the command is incorrect.", 1, True, "")
        if len(reds) > MAX_REDIRECTIONS:
            self._limit(res, "REDIRECTION_LIMIT")
            return _Out("The syntax of the command is incorrect.", 1, True, "")
        if stdin_file is not None:
            try:
                stdin = self.vfs.read(stdin_file, self.cwd)
            except VfsError as e:
                return _Out(str(e), 1, True, "")
        if not seg:
            return _Out("", 0, True, "")
        toks = self._tokens(seg)
        if not toks:
            return _Out("The syntax of the command is incorrect.", 1, True, "")
        name, args = self._name(toks[0]), toks[1:]
        m = re.match(r"^(cd|chdir|dir)([.\\].*)$", name)  # cmd quirks: cd.. cd\ dir\
        if m and self.mode == "cmd":
            name, args = m.group(1), [m.group(2)] + args
        o = self._dispatch(name, args, seg, stdin, res, depth)
        if o is None:
            return None
        o.name = o.name or name
        stdout = o.text
        # cmd semantics for repeated redirection of one handle: every target is opened (created / truncated by >),
        # and only the last one receives the output. stderr redirections go to nul or a file and carry nothing here.
        out_targets = [(how, target) for fd, how, target in reds if fd == "1"]
        for k, (how, target) in enumerate(out_targets):
            last_one = k == len(out_targets) - 1
            stdout = ""
            if target.lower() == "nul":
                continue
            try:
                text = ((o.text + "\n") if o.text else "") if last_one else ""
                self.vfs.write(target, self.cwd, text, append=(how == ">>" or not last_one))
            except VfsError as e:
                return _Out(str(e), 1, o.recognised, o.name)
        for fd, how, target in reds:
            if fd != "1" and target.lower() != "nul":
                try:
                    self.vfs.write(target, self.cwd, "", append=True)
                except VfsError as e:
                    return _Out(str(e), 1, o.recognised, o.name)
        o.text = stdout
        return o

    def _name(self, tok):
        t = _q(tok)
        if "\\" in t or "/" in t:
            # a full path to a program: only names under the simulated filesystem resolve
            try:
                parts, node = self.vfs.resolve(t if t.lower().endswith((".exe", ".com")) else t + ".exe", self.cwd)
            except VfsError:
                return t.lower()
            if node is None or node.is_dir:
                return t.lower()
            t = parts[-1]
        t = t.lower()
        for ext in (".exe", ".com"):
            if t.endswith(ext):
                t = t[: -len(ext)]
        return t

    def _dispatch(self, name, args, seg, stdin, res, depth):
        if self.mode == "ps":
            fn = PS_COMMANDS.get(name) or PS_COMMANDS.get(PS_ALIASES.get(name, ""))
            if fn is None:
                fn = NATIVE.get(name)
            if fn is None:
                if name in ("exit",):
                    return self._ps_exit(res)
                if seg.lstrip().startswith("$"):
                    return self._ps_variable(seg)
                return _Out(NOT_RECOGNISED_PS.format(_q(self._tokens(seg)[0]), "~" * len(_q(self._tokens(seg)[0]))), 1, False)
        else:
            fn = CMD_COMMANDS.get(name) or NATIVE.get(name)
            if fn is None:
                if "\\" in name or "/" in name:
                    return _Out("The system cannot find the path specified.", 1, False)
                return _Out(NOT_RECOGNISED_CMD.format(_q(self._tokens(seg)[0])), 9009, False)
        return fn(self, args, stdin=stdin, res=res, depth=depth, seg=seg)

    def _event(self, seg, name, recognised, code):
        seg = seg.translate(UNESCAPE)
        return {"command": seg, "name": name, "mode": self.mode, "recognised": recognised, "exitCode": code,
                "category": category_of(name) if recognised else "unrecognised",
                "intent": classify_windows_intent(seg), "attack": attack_techniques(seg), "simulated": True}

    # ── helpers ─────────────────────────────────────────────────────────────────────────────────────────────────
    @staticmethod
    def _flags(args):
        return {a.lower() for a in args if a.startswith("/") or a.startswith("-")}, [_q(a) for a in args if not (a.startswith("/") or (a.startswith("-") and len(a) > 1))]

    def _ps_exit(self, res):
        if self.ps_from_cmd:
            self.mode, self.ps_from_cmd = "cmd", False
            return _Out("", 0, True, "exit")
        res.exit_session = True
        return None

    def _ps_variable(self, seg):
        m = re.match(r"^\$env:([A-Za-z_][\w()]*)\s*$", seg.strip(), re.I)
        if m:
            low = {k.lower(): v for k, v in self.env.items()}
            return _Out(low.get(m.group(1).lower(), ""), 0, True, "$env")
        if seg.strip().lower() == "$psversiontable":
            return _Out(PSVERSION, 0, True, "$psversiontable")
        # assignments and other expressions are accepted and ignored (never evaluated)
        return _Out("", 0, True, "$expr")


# ── command implementations ─────────────────────────────────────────────────────────────────────────────────────
def _psdate(mtime):
    d, t, ampm = mtime.split()
    mm, dd, yyyy = d.split("/")
    hh, mi = t.split(":")
    return f"{int(mm)}/{int(dd)}/{yyyy}".rjust(10) + f" {int(hh)}:{mi} {ampm}".rjust(9)


def c_dir(sh, args, **_):
    flags, rest = sh._flags(args)
    show_hidden = any(f.startswith("/a") for f in flags)
    bare = "/b" in flags
    target = rest[0] if rest else "."
    pattern = None
    if any(ch in target for ch in "*?"):
        head, _, tail = target.replace("/", "\\").rpartition("\\")
        target, pattern = (head + "\\" if head else "."), tail
    try:
        path, node, items = sh.vfs.listdir(target, sh.cwd, show_hidden)
    except VfsError as e:
        return _Out(str(e) if str(e) != "File Not Found" else "File Not Found", 1)
    if pattern:
        rx = re.compile("^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$", re.I)
        items = [i for i in items if rx.match(i.name)]
        if not items:
            return _Out(" Volume in drive C has no label.\n Volume Serial Number is 6A3F-2B91\n\n Directory of " + path + "\n\nFile Not Found", 1)
    if bare:
        return _Out("\n".join(i.name for i in items))
    lines = [" Volume in drive C has no label.", " Volume Serial Number is 6A3F-2B91", "", f" Directory of {path}", ""]
    nd = nf = total = 0
    if path.upper() != "C:\\" and node and node.is_dir and not pattern:
        lines += [f"{node.mtime}    <DIR>          .", f"{node.mtime}    <DIR>          .."]
        nd += 2
    for i in items:
        if i.is_dir:
            lines.append(f"{i.mtime}    <DIR>          {i.name}"); nd += 1
        else:
            lines.append(f"{i.mtime} {i.size:>17,} {i.name}"); nf += 1; total += i.size
    lines.append(f"{nf:>16} File(s) {total:>14,} bytes")
    lines.append(f"{nd:>16} Dir(s)  {sh.vfs.free_bytes():,} bytes free")
    return _Out("\n".join(lines))


def c_cd(sh, args, **_):
    flags, rest = sh._flags(args)
    if not rest:
        return _Out(sh.cwd)
    target = " ".join(rest) if sh.mode == "cmd" else rest[0]
    try:
        sh.cwd = sh.vfs.chdir(target, sh.cwd)
    except VfsError as e:
        if sh.mode == "ps":
            return _Out(f"Set-Location : Cannot find path '{target}' because it does not exist.", 1)
        return _Out(str(e), 1)
    return _Out("")


def c_type(sh, args, stdin=None, **_):
    _, rest = sh._flags(args)
    if not rest:
        if sh.mode == "ps" and stdin:
            return _Out(stdin)
        return _Out("The syntax of the command is incorrect.", 1)
    out, code = [], 0
    for f in rest:
        try:
            out.append(sh.vfs.read(f, sh.cwd))
        except VfsError as e:
            code = 1
            msg = str(e)
            if sh.mode == "ps" and "being used" not in msg and "denied" not in msg:
                msg = "Cannot find path '" + f + "' because it does not exist."
            out.append(("Get-Content : " + msg) if sh.mode == "ps" else msg)
    return _Out("\n".join(o.rstrip("\n") for o in out), code)


def c_more(sh, args, stdin=None, **kw):
    _, rest = sh._flags(args)
    if not rest and stdin is not None:
        return _Out(stdin)
    return c_type(sh, args, **kw)


def c_echo(sh, args, seg="", **_):
    # Rank 8: cmd's echo prints the rest of the statement as typed (spacing and quotes kept), not re-joined tokens.
    m = re.match(r'^\s*(?:"[^"]*"|\S+?)(?:\.exe)?[\s.](.*)$', seg or "", re.S) if sh.mode == "cmd" and args else None
    raw = m.group(1) if m else " ".join(args)
    if sh.mode == "cmd":
        if not args:
            return _Out("ECHO is on.")
        if raw.lower() in ("on", "off"):
            return _Out("")
    return _Out("\n".join(_q(a) for a in args) if sh.mode == "ps" else raw)


def c_set(sh, args, **_):
    raw = " ".join(args)
    if "=" in raw and not raw.startswith("/"):
        k, v = raw.split("=", 1)
        if k.strip() and len(sh.env) < 128 and len(v) < 1024:
            sh.env[k.strip()] = v
        return _Out("")
    items = sorted(sh.env.items(), key=lambda kv: kv[0].lower())
    if raw:
        items = [kv for kv in items if kv[0].lower().startswith(raw.lower())]
        if not items:
            return _Out(f"Environment variable {raw} not defined", 1)
    return _Out("\n".join(f"{k}={v}" for k, v in items))


def c_cls(sh, args, res=None, **_):
    res.clear = True
    return _Out("")


def c_whoami(sh, args, **_):
    flags, _ = sh._flags(args)
    user = f"{sh.ident['hostname'].lower()}\\{sh.ident['username'].lower()}"
    if not flags:
        return _Out(user)
    sid = "S-1-5-21-3623811015-3361044348-30300820-500"  # fictional domain identifier, RID 500 = Administrator
    parts = []
    if "/all" in flags or "/user" in flags:
        parts.append(f"\nUSER INFORMATION\n----------------\n\nUser Name                  SID\n========================== {'=' * len(sid)}\n{user:<26} {sid}")
    if "/all" in flags or "/groups" in flags:
        parts.append("\nGROUP INFORMATION\n-----------------\n\nGroup Name                           Type             SID          Attributes\n"
                     "==================================== ================ ============ ==================================================\n"
                     "Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group\n"
                     "BUILTIN\\Administrators               Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner\n"
                     "BUILTIN\\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group\n"
                     "NT AUTHORITY\\NETWORK                 Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group\n"
                     "Mandatory Label\\High Mandatory Level Label            S-1-16-12288")
    if "/all" in flags or "/priv" in flags:
        parts.append("\nPRIVILEGES INFORMATION\n----------------------\n\nPrivilege Name                Description                          State\n"
                     "============================= ==================================== =======\n"
                     "SeShutdownPrivilege           Shut down the system                 Disabled\n"
                     "SeChangeNotifyPrivilege       Bypass traverse checking             Enabled\n"
                     "SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled\n"
                     "SeTimeZonePrivilege           Change the time zone                 Disabled")
    if not parts:
        return _Out(f"ERROR: Invalid argument/option - '{sorted(flags)[0]}'.\nType \"WHOAMI /?\" for usage.", 1)
    return _Out("\n".join(parts))


def c_hostname(sh, args, **_):
    return _Out(sh.ident["hostname"])


def c_ver(sh, args, **_):
    return _Out("\n" + sh.ident["ver_string"])


def c_systeminfo(sh, args, **_):
    i, n = sh.ident, sh.net
    hot = "\n".join(f"                           [{k:02d}]: {h}" for k, h in enumerate(i["hotfixes"], 1))
    return _Out(f"""
Host Name:                 {i['hostname']}
OS Name:                   {i['os_name']}
OS Version:                {i['os_version']} N/A Build {i['os_build']}
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          {i['registered_owner']}
Registered Organization:   {i['registered_organization']}
Product ID:                {i['product_id']}
Original Install Date:     {i['install_date']}
System Boot Time:          {i['boot_time']}
System Manufacturer:       {i['manufacturer']}
System Model:              {i['model']}
System Type:               {i['system_type']}
Processor(s):              1 Processor(s) Installed.
                           [01]: {i['processor']}
BIOS Version:              {i['bios']}
Windows Directory:         C:\\Windows
System Directory:          C:\\Windows\\system32
Boot Device:               \\Device\\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 {i['time_zone']}
Total Physical Memory:     {i['memory_mb']:,} MB
Available Physical Memory: {i['available_mb']:,} MB
Domain:                    {i['domain']}
Logon Server:              \\\\{i['hostname']}
Hotfix(s):                 {len(i['hotfixes'])} Hotfix(s) Installed.
{hot}
Network Card(s):           1 NIC(s) Installed.
                           [01]: {n['description']}
                                 Connection Name: {n['adapter']}
                                 DHCP Enabled:    {n['dhcp']}
                                 IP address(es)
                                 [01]: {n['ipv4']}
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.""")


def c_ipconfig(sh, args, **_):
    flags, _ = sh._flags(args)
    n = sh.net
    if "/all" in flags:
        return _Out(f"""
Windows IP Configuration

   Host Name . . . . . . . . . . . . : {sh.ident['hostname']}
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter {n['adapter']}:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : {n['description']}
   Physical Address. . . . . . . . . : {n['mac']}
   DHCP Enabled. . . . . . . . . . . : {n['dhcp']}
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : {n['ipv6_link_local']}(Preferred)
   IPv4 Address. . . . . . . . . . . : {n['ipv4']}(Preferred)
   Subnet Mask . . . . . . . . . . . : {n['mask']}
   Default Gateway . . . . . . . . . : {n['gateway']}
   DNS Servers . . . . . . . . . . . : {n['dns'][0]}
                                       {n['dns'][1]}
   NetBIOS over Tcpip. . . . . . . . : Enabled""")
    if flags and not flags <= {"/all"}:
        if flags & {"/flushdns"}:
            return _Out("\nWindows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.")
        if flags & {"/displaydns", "/release", "/renew", "/registerdns"}:
            return _Out("\nWindows IP Configuration\n\nThe requested operation requires elevation.", 1)
        return _Out(f"\nError: unrecognized or incomplete command line.\n\nUSAGE:\n    ipconfig [/allcompartments] [/? | /all | /renew [adapter] | /release [adapter] | /flushdns | /displaydns]", 1)
    return _Out(f"""
Windows IP Configuration


Ethernet adapter {n['adapter']}:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : {n['ipv6_link_local']}
   IPv4 Address. . . . . . . . . . . : {n['ipv4']}
   Subnet Mask . . . . . . . . . . . : {n['mask']}
   Default Gateway . . . . . . . . . : {n['gateway']}""")


KNOWN_HOSTS = {"localhost": "127.0.0.1", "127.0.0.1": "127.0.0.1", "dc01": "10.20.30.10", "dc01.corp.local": "10.20.30.10",
               "sql01": "10.20.30.22", "sql01.corp.local": "10.20.30.22", "10.20.30.1": "10.20.30.1",
               "10.20.30.10": "10.20.30.10", "10.20.30.11": "10.20.30.11", "10.20.30.22": "10.20.30.22"}


def c_ping(sh, args, **_):
    """Simulated ICMP: no packet is sent. Fictional neighbours answer; everything else times out."""
    count, target, it = 4, None, iter(args)
    for a in it:
        if a.lower() in ("-n", "/n"):
            try:
                count = max(1, min(int(next(it, "4")), 10))
            except ValueError:
                return _Out(f"Bad value for option -n, valid range is from 1 to 4294967295.", 1)
        elif a.lower() in ("-l", "-w", "-i", "/l", "/w", "/i"):
            next(it, None)
        elif not a.startswith(("-", "/")):
            target = _q(a)
    if not target:
        return _Out("\nUsage: ping [-t] [-a] [-n count] [-l size] [-f] [-i TTL] [-v TOS]\n            [-r count] [-s count] [[-j host-list] | [-k host-list]]\n            [-w timeout] [-R] [-S srcaddr] [-c compartment] [-p]\n            [-4] [-6] target_name", 1)
    low = target.lower()
    own = {sh.ident["hostname"].lower(), sh.net["ipv4"]}
    ip = "127.0.0.1" if low in own and low != sh.net["ipv4"] else (sh.net["ipv4"] if low in own else KNOWN_HOSTS.get(low))
    is_ip = re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", target) is not None
    if ip is None and not is_ip:
        return _Out(f"Ping request could not find host {target}. Please check the name and try again.", 1)
    shown = f"{target} [{ip}]" if ip and ip != target else target
    lines = [f"\nPinging {shown} with 32 bytes of data:"]
    if ip:
        t = "<1ms" if ip in ("127.0.0.1", sh.net["ipv4"]) else "=1ms"
        lines += [f"Reply from {ip}: bytes=32 time{t} TTL=128"] * count
        lines += [f"\nPing statistics for {ip}:", f"    Packets: Sent = {count}, Received = {count}, Lost = 0 (0% loss),",
                  "Approximate round trip times in milli-seconds:", f"    Minimum = {0 if t == '<1ms' else 1}ms, Maximum = {0 if t == '<1ms' else 1}ms, Average = {0 if t == '<1ms' else 1}ms"]
        return _Out("\n".join(lines))
    lines += ["Request timed out."] * count
    lines += [f"\nPing statistics for {target}:", f"    Packets: Sent = {count}, Received = 0, Lost = {count} (100% loss),"]
    return _Out("\n".join(lines), 1)


NETSTAT_ROWS = [("TCP", "0.0.0.0:22", "0.0.0.0:0", "LISTENING", 2804), ("TCP", "0.0.0.0:80", "0.0.0.0:0", "LISTENING", 4),
                ("TCP", "0.0.0.0:135", "0.0.0.0:0", "LISTENING", 884), ("TCP", "0.0.0.0:443", "0.0.0.0:0", "LISTENING", 4),
                ("TCP", "0.0.0.0:445", "0.0.0.0:0", "LISTENING", 4), ("TCP", "0.0.0.0:3389", "0.0.0.0:0", "LISTENING", 1052),
                ("TCP", "0.0.0.0:5985", "0.0.0.0:0", "LISTENING", 4), ("TCP", "0.0.0.0:47001", "0.0.0.0:0", "LISTENING", 4),
                ("TCP", "10.20.30.15:139", "0.0.0.0:0", "LISTENING", 4),
                ("TCP", "10.20.30.15:49712", "10.20.30.22:1433", "ESTABLISHED", 3120),
                ("UDP", "0.0.0.0:123", "*:*", "", 1180), ("UDP", "0.0.0.0:500", "*:*", "", 2604)]


def c_netstat(sh, args, **_):
    flags = "".join(a.lower().lstrip("-/") for a in args)
    show_pid = "o" in flags
    rows = NETSTAT_ROWS if "a" in flags else [r for r in NETSTAT_ROWS if r[3] == "ESTABLISHED"]
    head = "\nActive Connections\n\n  Proto  Local Address          Foreign Address        State" + ("           PID" if show_pid else "")
    body = [f"  {p:<6} {la:<22} {fa:<22} {st:<15}" + (f" {pid}" if show_pid else "") for p, la, fa, st, pid in rows]
    return _Out("\n".join([head] + [b.rstrip() for b in body]))


PROCESSES = [("System Idle Process", 0, "Services", 0, "8 K"), ("System", 4, "Services", 0, "140 K"),
             ("Registry", 88, "Services", 0, "33,412 K"), ("smss.exe", 296, "Services", 0, "1,128 K"),
             ("csrss.exe", 400, "Services", 0, "4,904 K"), ("wininit.exe", 476, "Services", 0, "6,236 K"),
             ("services.exe", 616, "Services", 0, "9,580 K"), ("lsass.exe", 632, "Services", 0, "18,044 K"),
             ("svchost.exe", 884, "Services", 0, "22,600 K"), ("svchost.exe", 1052, "Services", 0, "12,916 K"),
             ("svchost.exe", 1180, "Services", 0, "9,072 K"), ("spoolsv.exe", 2052, "Services", 0, "15,340 K"),
             ("sshd.exe", 2804, "Services", 0, "6,812 K"), ("MsMpEng.exe", 2860, "Services", 0, "121,504 K"),
             ("w3wp.exe", 3120, "Services", 0, "64,224 K"), ("sqlwriter.exe", 3212, "Services", 0, "7,080 K"),
             ("cmd.exe", 4412, "Services", 0, "4,316 K"), ("conhost.exe", 4420, "Services", 0, "11,208 K")]
SERVICES = [("LanmanServer", "Server", "RUNNING", "share process"), ("sshd", "OpenSSH SSH Server", "RUNNING", "own process"),
            ("W3SVC", "World Wide Web Publishing Service", "RUNNING", "share process"),
            ("WinDefend", "Microsoft Defender Antivirus Service", "RUNNING", "own process"),
            ("WinRM", "Windows Remote Management (WS-Management)", "RUNNING", "share process"),
            ("TermService", "Remote Desktop Services", "RUNNING", "share process"),
            ("Spooler", "Print Spooler", "RUNNING", "own process"), ("EventLog", "Windows Event Log", "RUNNING", "share process"),
            ("Dnscache", "DNS Client", "RUNNING", "share process"), ("wuauserv", "Windows Update", "STOPPED", "share process")]


def c_tasklist(sh, args, **_):
    flags, _ = sh._flags(args)
    if "/svc" in flags:
        svc = {884: "RpcEptMapper, RpcSs", 1052: "TermService", 2804: "sshd", 2860: "WinDefend", 2052: "Spooler"}
        lines = ["", "Image Name                     PID Services", "========================= ======== ============================================"]
        lines += [f"{n:<25} {pid:>8} {svc.get(pid, 'N/A')}" for n, pid, *_ in PROCESSES]
        return _Out("\n".join(lines))
    lines = ["", "Image Name                     PID Session Name        Session#    Mem Usage",
             "========================= ======== ================ =========== ============"]
    lines += [f"{n:<25} {pid:>8} {s:<16} {num:>11} {mem:>12}" for n, pid, s, num, mem in PROCESSES]
    return _Out("\n".join(lines))


def _svc_block(name, display, state):
    code = "4  RUNNING" if state == "RUNNING" else "1  STOPPED"
    return (f"\nSERVICE_NAME: {name}\nDISPLAY_NAME: {display}\n        TYPE               : 20  WIN32_SHARE_PROCESS\n"
            f"        STATE              : {code}\n        WIN32_EXIT_CODE    : 0  (0x0)\n        SERVICE_EXIT_CODE  : 0  (0x0)\n"
            f"        CHECKPOINT         : 0x0\n        WAIT_HINT          : 0x0")


def c_sc(sh, args, **_):
    if not args:
        return _Out("DESCRIPTION:\n        SC is a command line program used for communicating with the\n        Service Control Manager and services.\nUSAGE:\n        sc <server> [command] [service name] <option1> <option2>...", 1)
    sub = args[0].lower()
    if sub in ("query", "queryex"):
        if len(args) > 1:
            want = _q(args[1]).lower()
            for n, d, s, _ in SERVICES:
                if n.lower() == want:
                    return _Out(_svc_block(n, d, s))
            return _Out("[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.", 1060)
        return _Out("\n".join(_svc_block(n, d, s) for n, d, s, _ in SERVICES if s == "RUNNING"))
    if sub in ("create", "config", "delete", "start", "stop", "failure", "sdset"):
        return _Out(f"[SC] OpenSCManager FAILED 5:\n\nAccess is denied.", 5)
    return _Out(f"ERROR:  Unrecognized command\n\nDESCRIPTION:\n        SC is a command line program used for communicating with the\n        Service Control Manager and services.", 1)


USERS = [("Administrator", "Built-in account for administering the computer/domain", "Yes"),
         ("DefaultAccount", "A user account managed by the system.", "No"),
         ("Guest", "Built-in account for guest access to the computer/domain", "No"),
         ("svc_backup", "Backup service account", "Yes"), ("WDAGUtilityAccount", "A user account managed and used by the system for Windows Defender Application Guard scenarios.", "No")]


def c_net(sh, args, **_):
    if not args:
        return _Out("The syntax of this command is:\n\nNET\n    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\n      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |\n      STATISTICS | STOP | TIME | USE | USER | VIEW ]", 1)
    sub, rest = args[0].lower(), args[1:]
    host = sh.ident["hostname"]
    if sub in ("user", "users"):
        if any(a.lower() in ("/add", "/delete", "/del") for a in rest) or (len(rest) >= 2 and not rest[1].startswith("/")):
            return _Out("System error 5 has occurred.\n\nAccess is denied.", 2)
        if rest:
            want = _q(rest[0]).lower()
            for n, c, active in USERS:
                if n.lower() == want:
                    return _Out(f"User name                    {n}\nFull Name\nComment                      {c}\nUser's comment\n"
                                f"Country/region code          000 (System Default)\nAccount active               {active}\n"
                                f"Account expires              Never\n\nPassword last set            3/14/2024 9:52:11 AM\n"
                                f"Password expires             Never\nPassword changeable          3/14/2024 9:52:11 AM\n"
                                f"Password required            Yes\nUser may change password     Yes\n\nWorkstations allowed         All\n"
                                f"Logon script\nUser profile\nHome directory\nLast logon                   11/14/2026 8:02:41 AM\n\n"
                                f"Logon hours allowed          All\n\nLocal Group Memberships      *{'Administrators' if n in ('Administrator', 'svc_backup') else 'Users'}\n"
                                f"Global Group memberships     *None\nThe command completed successfully.")
            return _Out("The user name could not be found.\n\nMore help is available by typing NET HELPMSG 2221.", 2)
        names = [u[0] for u in USERS]
        rows = [" ".join(f"{n:<25}" for n in names[i:i + 3]).rstrip() for i in range(0, len(names), 3)]
        return _Out(f"\nUser accounts for \\\\{host}\n\n{'-' * 79}\n" + "\n".join(rows) + "\nThe command completed successfully.")
    if sub == "localgroup":
        if any(a.lower() in ("/add", "/delete", "/del") for a in rest):
            return _Out("System error 5 has occurred.\n\nAccess is denied.", 2)
        if rest and _q(rest[0]).lower() == "administrators":
            return _Out("Alias name     Administrators\nComment        Administrators have complete and unrestricted access to the computer/domain\n\n"
                        f"Members\n\n{'-' * 79}\nAdministrator\nsvc_backup\nThe command completed successfully.")
        if rest:
            return _Out("The specified local group does not exist.\n\nMore help is available by typing NET HELPMSG 3780.", 2)
        groups = ["Access Control Assistance Operators", "Administrators", "Backup Operators", "Guests", "IIS_IUSRS",
                  "Remote Desktop Users", "Remote Management Users", "Users"]
        return _Out(f"\nAliases for \\\\{host}\n\n{'-' * 79}\n" + "\n".join("*" + g for g in groups) + "\nThe command completed successfully.")
    if sub == "share":
        return _Out("\nShare name   Resource                        Remark\n\n" + "-" * 79 +
                    "\nC$           C:\\                             Default share\nIPC$                                         Remote IPC\n"
                    "ADMIN$       C:\\Windows                      Remote Admin\nwwwroot      C:\\inetpub\\wwwroot\nThe command completed successfully.")
    if sub == "view":
        return _Out("System error 6118 has occurred.\n\nThe list of servers for this workgroup is not currently available", 2)
    if sub == "accounts":
        return _Out("Force user logoff how long after time expires?:       Never\nMinimum password age (days):                          0\n"
                    "Maximum password age (days):                          42\nMinimum password length:                              0\n"
                    "Length of password history maintained:                None\nLockout threshold:                                    Never\n"
                    "Computer role:                                        SERVER\nThe command completed successfully.")
    if sub == "start":
        return _Out("These Windows services are started:\n\n" + "\n".join("   " + d for _, d, s, _ in SERVICES if s == "RUNNING") + "\n\nThe command completed successfully.")
    if sub in ("use", "session"):
        return _Out("There are no entries in the list.")
    return _Out("The syntax of this command is:\n\nNET\n    [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP |\n      HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START |\n      STATISTICS | STOP | TIME | USE | USER | VIEW ]", 1)


def c_mkdir(sh, args, **_):
    _, rest = sh._flags(args)
    if not rest:
        return _Out("The syntax of the command is incorrect.", 1)
    for d in rest:
        try:
            sh.vfs.mkdir(d, sh.cwd)
        except VfsError as e:
            return _Out(str(e), 1)
    return _Out("")


def c_del(sh, args, **_):
    _, rest = sh._flags(args)
    if not rest:
        return _Out("The syntax of the command is incorrect.", 1)
    out = []
    for f in rest:
        try:
            sh.vfs.delete(f, sh.cwd)
        except VfsError as e:
            out.append(str(e) if "Could Not Find" in str(e) else f"{f}\n{e}")
    return _Out("\n".join(out), 1 if out else 0)


def c_findstr(sh, args, stdin=None, **_):
    flags, rest = sh._flags(args)
    if not rest:
        return _Out("FINDSTR: Bad command line", 2)
    needle, files = rest[0], rest[1:]
    texts = []
    if files:
        for f in files:
            try:
                texts.append(sh.vfs.read(f, sh.cwd))
            except VfsError:
                return _Out(f"FINDSTR: Cannot open {f}", 1)
    else:
        texts.append(stdin or "")
    ci = "/i" in flags
    hits = [ln for t in texts for ln in t.splitlines() if (needle.lower() in ln.lower() if ci else needle in ln)]
    return _Out("\n".join(hits), 0 if hits else 1)


def c_certutil(sh, args, **_):
    low = [a.lower() for a in args]
    if any(a in ("-urlcache", "/urlcache") for a in low):
        url = next((a for a in args if a.lower().startswith(("http://", "https://"))), "")
        return _Out(f"****  Online  ****\nCertUtil: -URLCache command FAILED: 0x80072ee7 (WinHttp: 12007 ERROR_INTERNET_NAME_NOT_RESOLVED)\n"
                    f"CertUtil: The server name or address could not be resolved", 1) if url else _Out("CertUtil: -URLCache command FAILED: 0x80070057 (WIN32: 87 ERROR_INVALID_PARAMETER)", 1)
    if not args:
        return _Out("CertUtil: -dump command completed successfully.")
    return _Out(f"CertUtil: Unknown arg: {args[0]}\nCertUtil: The parameter is incorrect.", 1)


def c_date(sh, args, **_):
    now = sh.clock()
    if not any(a.lower() == "/t" for a in args):
        return _Out(f"The current date is: {now:%a %m/%d/%Y}\nEnter the new date: (mm-dd-yy) \nA required privilege is not held by the client.", 1)
    return _Out(f"{now:%a %m/%d/%Y}")


def c_time(sh, args, **_):
    now = sh.clock()
    if not any(a.lower() == "/t" for a in args):
        return _Out(f"The current time is: {now:%H:%M:%S}.00\nEnter the new time: \nA required privilege is not held by the client.", 1)
    return _Out(f"{now:%I:%M %p}")


HELP = {"CD": "Displays the name of or changes the current directory.", "CLS": "Clears the screen.",
        "DATE": "Displays or sets the date.", "DEL": "Deletes one or more files.",
        "DIR": "Displays a list of files and subdirectories in a directory.", "ECHO": "Displays messages, or turns command echoing on or off.",
        "EXIT": "Quits the CMD.EXE program (command interpreter).", "FINDSTR": "Searches for strings in files.",
        "MKDIR": "Creates a directory.", "MORE": "Displays output one screen at a time.", "SC": "Displays or configures services (background processes).",
        "SET": "Displays, sets, or removes Windows environment variables.", "SYSTEMINFO": "Displays machine specific properties and configuration.",
        "TASKLIST": "Displays all currently running tasks including services.", "TIME": "Displays or sets the system time.",
        "TYPE": "Displays the contents of a text file.", "VER": "Displays the Windows version."}


def c_help(sh, args, **_):
    return _Out("For more information on a specific command, type HELP command-name\n" +
                "\n".join(f"{k:<15}{v}" for k, v in HELP.items()) +
                "\n\nFor more information on tools see the command-line reference in the online help.")


def c_exit(sh, args, res=None, **_):
    res.exit_session = True
    return None


_CMD_SWITCH = re.compile(r'^\s*(?:"[^"]*"|\S+?)\s*/([ck])(?=\s|"|$)\s*(.*)$', re.I | re.S)


def cmd_command_line(seg: str):
    r"""(switch, command text) of `cmd /c ...` / `cmd /k ...` taken from the raw statement, or None.

    Rank 8 (F3): the text after the switch is used as typed (not re-joined tokens), and quotes follow cmd.exe's
    documented rule (cmd /?): when it starts with a quote, the leading quote and the LAST quote on the line are
    removed and everything else is kept, so `cmd /c "whoami & hostname"` runs both commands and
    `cmd /c ""C:\Program Files\x.exe" a"` keeps the inner quotes. Bounded: the statement is already <= MAX_LINE.
    """
    m = _CMD_SWITCH.match(seg or "")
    if not m:
        return None
    text = m.group(2).strip()
    if text.startswith('"'):
        last = text.rfind('"')
        text = text[1:last] + text[last + 1:] if last > 0 else text[1:]
    return m.group(1).lower(), text


def c_cmd(sh, args, res=None, depth=0, seg="", **_):
    parsed = cmd_command_line(seg) if args and args[0].lower().startswith(("/c", "/k")) else None
    if parsed:
        switch, text = parsed
        if depth >= MAX_DEPTH:
            sh._limit(res, "DEPTH_LIMIT")
            return _Out("", 0)
        if not text.strip():
            return _Out("", 0)
        # Rank 8 (F4): an isolated child shell (own environment copy and working directory, shared virtual disk).
        child = sh._child("cmd")
        r = sh._run_child(child, text, res, depth)
        if switch == "k":
            # cmd /k leaves the new shell open: its working directory and environment are what the session sees.
            sh.cwd, sh.env = child.cwd, child.env
        return _Out(r.output, r.exit_code)
    return _Out(f"{sh.ident['ver_string']}\n(c) 2018 Microsoft Corporation. All rights reserved.")


def c_powershell(sh, args, res=None, depth=0, **_):
    low = [a.lower() for a in args]
    script, i = None, 0
    while i < len(low):
        a = low[i]
        if a in ("-c", "-command", "/c", "/command"):
            script = " ".join(_q(x) for x in args[i + 1:]); break
        if a in ("-e", "-enc", "-ec", "-encodedcommand"):
            raw = args[i + 1] if i + 1 < len(args) else ""
            try:
                script = base64.b64decode(raw, validate=True).decode("utf-16-le")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                return _Out("Cannot process the command because the value specified with -EncodedCommand is not properly encoded. The value must be Base64 encoded.", 1)
            break
        if a in ("-file", "-f"):
            return _Out(f"The argument '{args[i + 1] if i + 1 < len(args) else ''}' to the -File parameter does not exist. Provide the path to an existing '.ps1' file as an argument to the -File parameter.", 1)
        if a in ("-executionpolicy", "-ep", "-windowstyle", "-w"):
            i += 2; continue
        i += 1
    if script is None:
        if sh.mode == "ps":
            return _Out("")
        sh.mode, sh.ps_from_cmd = "ps", True
        return _Out("Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n")
    if depth >= MAX_DEPTH:
        sh._limit(res, "DEPTH_LIMIT")
        return _Out("", 0)
    # Rank 8 (F4): powershell -c / -enc runs in an isolated child (it never changes this shell's state).
    r = sh._run_child(sh._child("ps"), script, res, depth)
    return _Out(r.output, r.exit_code)


# ── PowerShell cmdlets ──────────────────────────────────────────────────────────────────────────────────────────
PSVERSION = """
Name                           Value
----                           -----
PSVersion                      5.1.17763.5329
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.17763.5329
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1"""


def p_gci(sh, args, **_):
    _, rest = sh._flags(args)
    force = any(a.lower() in ("-force", "-fo") for a in args)
    target = rest[0] if rest else "."
    try:
        path, node, items = sh.vfs.listdir(target, sh.cwd, force)
    except VfsError:
        return _Out(f"Get-ChildItem : Cannot find path '{target}' because it does not exist.", 1)
    lines = ["", f"    Directory: {path}", "", "", "Mode                 LastWriteTime         Length Name", "----                 -------------         ------ ----"]
    for i in items:
        mode = ("d" if i.is_dir else "-") + ("-" if i.is_dir else "a") + "-" + ("h" if i.hidden else "-") + ("s" if i.sysfile else "-") + "-"
        lines.append(f"{mode:<13}{_psdate(i.mtime):>22} {'' if i.is_dir else i.size:>14} {i.name}")
    return _Out("\n".join(lines))


def p_location(sh, args, **_):
    return _Out(f"\nPath\n----\n{sh.cwd}")


def p_set_location(sh, args, **kw):
    return c_cd(sh, args, **kw)


def p_get_content(sh, args, **kw):
    return c_type(sh, [a for a in args if a.lower() not in ("-path", "-raw")], **kw)


def p_get_process(sh, args, **_):
    lines = ["", "Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName", "-------  ------    -----      -----     ------     --  -- -----------"]
    for n, pid, _s, si, mem in PROCESSES:
        ws = int(mem.split()[0].replace(",", ""))
        lines.append(f"{(pid * 7) % 900 + 80:>7} {ws // 1000 + 8:>7} {ws // 2:>8} {ws:>10} {round(pid / 977, 2):>10} {pid:>6} {si:>3} {n.removesuffix('.exe')}")
    return _Out("\n".join(lines))


def p_get_service(sh, args, **_):
    lines = ["", "Status   Name               DisplayName", "------   ----               -----------"]
    lines += [f"{s.title():<8} {n:<18} {d}" for n, d, s, _ in SERVICES]
    return _Out("\n".join(lines))


def p_computer_info(sh, args, **_):
    i = sh.ident
    return _Out(f"""
WindowsBuildLabEx                                       : 17763.1.amd64fre.rs5_release.180914-1434
WindowsCurrentVersion                                   : 6.3
WindowsEditionId                                        : ServerDatacenter
WindowsInstallationType                                 : Server
WindowsProductName                                      : Windows Server 2019 Datacenter
WindowsRegisteredOwner                                  : {i['registered_owner']}
WindowsSystemRoot                                       : C:\\Windows
WindowsVersion                                          : 1809
BiosManufacturer                                        : Microsoft Corporation
CsDNSHostName                                           : {i['hostname']}
CsDomain                                                : {i['domain']}
CsManufacturer                                          : {i['manufacturer']}
CsModel                                                 : {i['model']}
CsName                                                  : {i['hostname']}
CsNumberOfLogicalProcessors                             : 2
CsTotalPhysicalMemory                                   : {i['memory_mb'] * 1048576}
OsName                                                  : {i['os_name']}
OsVersion                                               : {i['os_version']}
OsBuildNumber                                           : {i['os_build']}
OsArchitecture                                          : 64-bit
OsLanguage                                              : en-US
TimeZone                                                : {i['time_zone']}
LogonServer                                             : \\\\{i['hostname']}""")


def p_local_user(sh, args, **_):
    lines = ["", "Name               Enabled Description", "----               ------- -----------"]
    lines += [f"{n:<18} {('True' if a == 'Yes' else 'False'):<7} {c}" for n, c, a in USERS]
    return _Out("\n".join(lines))


def p_netip(sh, args, **_):
    n = sh.net
    return _Out(f"\nIPAddress         : {n['ipv4']}\nInterfaceIndex    : 6\nInterfaceAlias    : {n['adapter']}\nAddressFamily     : IPv4\n"
                f"Type              : Unicast\nPrefixLength      : 24\nPrefixOrigin      : Manual\nSuffixOrigin      : Manual\nAddressState      : Preferred")


def p_iwr(sh, args, **_):
    return _Out("Invoke-WebRequest : Unable to connect to the remote server\nAt line:1 char:1\n+ " + " ".join(args)[:60] +
                "\n    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebException\n"
                "    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand", 1)


def p_passthru(sh, args, stdin=None, **_):
    return _Out(stdin or "")


def p_select_string(sh, args, stdin=None, **_):
    _, rest = sh._flags(args)
    pat = _q(rest[0]) if rest else ""
    return _Out("\n".join(ln for ln in (stdin or "").splitlines() if pat.lower() in ln.lower()))


def p_select_object(sh, args, stdin=None, **_):
    low = [a.lower() for a in args]
    for flag in ("-first", "-last"):
        if flag in low and low.index(flag) + 1 < len(args):
            try:
                n = max(0, int(args[low.index(flag) + 1]))
            except ValueError:
                break
            lines = (stdin or "").splitlines()
            # tables: keep the header (up to the ---- underline) and count objects (rows), not lines
            sep = next((k for k, ln in enumerate(lines) if ln.startswith("---")), -1)
            head, rows = lines[:sep + 1], [ln for ln in lines[sep + 1:] if ln.strip()]
            rows = rows[:n] if flag == "-first" else rows[-n:] if n else []
            return _Out("\n".join(head + rows))
    return _Out(stdin or "")


def p_clear(sh, args, res=None, **_):
    res.clear = True
    return _Out("")


CMD_COMMANDS = {
    "dir": c_dir, "cd": c_cd, "chdir": c_cd, "type": c_type, "more": c_more, "echo": c_echo, "set": c_set,
    "cls": c_cls, "mkdir": c_mkdir, "md": c_mkdir, "del": c_del, "erase": c_del, "date": c_date, "time": c_time,
    "help": c_help, "exit": c_exit, "ver": c_ver,
}
# Programs available from both cmd and PowerShell (they are .exe files on a real system).
NATIVE = {
    "whoami": c_whoami, "hostname": c_hostname, "systeminfo": c_systeminfo, "ipconfig": c_ipconfig, "ping": c_ping,
    "netstat": c_netstat, "tasklist": c_tasklist, "net": c_net, "net1": c_net, "findstr": c_findstr, "find": c_findstr,
    "certutil": c_certutil, "cmd": c_cmd, "powershell": c_powershell, "sc": c_sc,
}
PS_COMMANDS = {
    "get-childitem": p_gci, "get-location": p_location, "set-location": p_set_location, "get-content": p_get_content,
    "get-process": p_get_process, "get-service": p_get_service, "get-computerinfo": p_computer_info,
    "get-localuser": p_local_user, "get-netipaddress": p_netip, "invoke-webrequest": p_iwr, "clear-host": p_clear,
    "write-output": c_echo, "write-host": c_echo, "select-string": p_select_string, "select-object": p_select_object,
    "format-table": p_passthru, "format-list": p_passthru, "out-string": p_passthru, "out-host": p_passthru,
    "where-object": p_passthru, "sort-object": p_passthru, "mkdir": c_mkdir, "remove-item": c_del,
}
# PowerShell aliases. "sc" is Set-Content in PowerShell (not sc.exe), so it is not routed to the service tool there.
PS_ALIASES = {
    "dir": "get-childitem", "ls": "get-childitem", "gci": "get-childitem", "pwd": "get-location", "gl": "get-location",  # secret-scan: allow (PowerShell alias pwd = Get-Location, not a password)
    "cd": "set-location", "chdir": "set-location", "sl": "set-location", "cat": "get-content", "type": "get-content",
    "gc": "get-content", "ps": "get-process", "gps": "get-process", "gsv": "get-service", "cls": "clear-host",
    "clear": "clear-host", "echo": "write-output", "iwr": "invoke-webrequest", "curl": "invoke-webrequest",
    "wget": "invoke-webrequest", "sls": "select-string", "select": "select-object", "ft": "format-table",
    "fl": "format-list", "where": "where-object", "?": "where-object", "sort": "sort-object", "rm": "remove-item",
    "del": "remove-item", "more": "out-host",
}
NATIVE_PS_SHADOWED = {"sc"}


def _ps_dispatch_fix():
    # In PowerShell `sc` is Set-Content: writing is not simulated, so it fails like a missing -Value.
    def p_set_content(sh, args, **_):
        return _Out("Set-Content : A positional parameter cannot be found that accepts argument.", 1)
    PS_COMMANDS["set-content"] = p_set_content
    PS_ALIASES["sc"] = "set-content"


_ps_dispatch_fix()


def supported_commands() -> dict:
    """The allowlist, for documentation and evidence."""
    return {"cmd": sorted(CMD_COMMANDS), "native": sorted(NATIVE), "powershell": sorted(PS_COMMANDS),
            "powershell_aliases": dict(sorted(PS_ALIASES.items()))}
