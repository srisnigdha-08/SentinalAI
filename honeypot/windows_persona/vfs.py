"""Isolated, in-memory Windows-style filesystem for the simulated Windows persona.

There is no host filesystem behind it: this module imports nothing that can touch disk (no os, pathlib, open or
io). Every path an attacker types is parsed into components and resolved against an in-memory tree; ".." stops at
C:\\ as Windows does, other drives, UNC paths, device names, alternate data streams and control characters are
rejected. Each shell session gets its own copy, so one session's writes never reach another.
"""
from __future__ import annotations

import copy
import re

DRIVE = "C:"
MAX_PATH = 260
MAX_FILE_BYTES = 64 * 1024
MAX_CREATED_NODES = 256
# Rank 8: aggregate cap on what one session can store (bytes held in files it created or modified). Well inside the
# ~16 MiB theoretical ceiling of 256 nodes x 64 KB; the per-file and per-node limits above are unchanged.
MAX_SESSION_BYTES = 1024 * 1024
RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_BAD_CHARS = re.compile(r'[\x00-\x1f<>"|?*]')


class VfsError(Exception):
    """A Windows-style error message (the text cmd.exe would print)."""


class Node:
    __slots__ = ("name", "is_dir", "content", "children", "hidden", "sysfile", "locked", "mtime", "size_hint")

    def __init__(self, name, is_dir, content="", hidden=False, sysfile=False, locked=False, mtime="03/14/2024  09:41 AM",
                 size_hint=None):
        self.name = name
        self.is_dir = is_dir
        self.content = content
        self.children: dict[str, Node] = {} if is_dir else {}
        self.hidden = hidden
        self.sysfile = sysfile
        self.locked = locked      # readable "in use" files such as the SAM hive: type fails
        self.mtime = mtime
        self.size_hint = size_hint  # binaries: a believable size without carrying content

    @property
    def size(self) -> int:
        return self.size_hint if self.size_hint is not None else len(self.content.encode("utf-8"))


def _d(name, *children, hidden=False, sysfile=False, mtime="03/14/2024  09:41 AM"):
    n = Node(name, True, hidden=hidden, sysfile=sysfile, mtime=mtime)
    for c in children:
        n.children[c.name.lower()] = c
    return n


def _f(name, content="", **kw):
    return Node(name, False, content=content, **kw)


def _bin(name, size, mtime="09/15/2018  09:28 AM"):
    return Node(name, False, content="MZ\x90", size_hint=size, mtime=mtime)


HOSTS = """# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# localhost name resolution is handled within DNS itself.
#\t127.0.0.1       localhost
#\t::1             localhost
10.20.30.10     dc01.corp.local
10.20.30.22     sql01.corp.local
"""

WEB_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="Billing" connectionString="Server=sql01.corp.local;Database=Billing;User Id=svc_billing;Password=Winter2024!Billing;" providerName="System.Data.SqlClient" />
  </connectionStrings>
  <system.web>
    <compilation debug="false" targetFramework="4.8" />
  </system.web>
</configuration>
"""

UNATTEND = """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <AdministratorPassword>
          <Value>UABhAHMAcwB3ADAAcgBkACEAMgAwADEAOQA=</Value>
          <PlainText>false</PlainText>
        </AdministratorPassword>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"""

NOTES = """TODO before go-live
- rotate svc_billing password (still the one from the web.config)
- move nightly backup job to \\\\fs01\\backups
- disable old admin share once DFS is ready
"""


def _tree() -> Node:
    """The template tree (fictional content). Copied per session by VirtualFS."""
    return _d("C:",
        _d("$Recycle.Bin", hidden=True, sysfile=True),
        _d("inetpub",
           _d("logs", _d("LogFiles")),
           _d("wwwroot",
              _f("iisstart.htm", "<!DOCTYPE html>\n<html><head><title>IIS Windows Server</title></head>\n<body><img src=\"iisstart.png\" alt=\"IIS\"></body></html>\n"),
              _bin("iisstart.png", 99710),
              _f("web.config", WEB_CONFIG))),
        _d("PerfLogs"),
        _d("Program Files",
           _d("Common Files"),
           _d("internet explorer"),
           _d("Microsoft SQL Server", _d("Client SDK")),
           _d("OpenSSH", _bin("sshd.exe", 1033728), _bin("ssh.exe", 913408)),
           _d("Windows Defender", _bin("MpCmdRun.exe", 600296)),
           _d("WindowsPowerShell", _d("Modules"))),
        _d("Program Files (x86)", _d("Common Files"), _d("Microsoft.NET")),
        _d("ProgramData",
           _d("Microsoft", _d("Windows", _d("Start Menu"))),
           _d("ssh",
              _f("sshd_config", "# This is the sshd server system-wide configuration file.\nPort 22\nPasswordAuthentication yes\nMatch Group administrators\n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n"),
              _f("administrators_authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM0ckPq2v1Z6rN3hFakeKeyOnlyForHoneypotX9 admin@jumpbox\n")),
           hidden=True),
        _d("Temp",
           _f("setup.log", "[2024-03-14 09:58:12] Installing IIS role... OK\n[2024-03-14 10:02:40] Installing SQL client tools... OK\n"),
           _f("install_notes.txt", "Server staged by build script v2.3. Do not delete C:\\Temp until audit.\n")),
        _d("Users",
           _d("Administrator",
              _d("AppData", _d("Local"), _d("Roaming"), hidden=True),
              _d("Contacts"),
              _d("Desktop", _f("notes.txt", NOTES), _f("desktop.ini", "[.ShellClassInfo]\n", hidden=True, sysfile=True)),
              _d("Documents", _f("backup_plan.txt", "Nightly: robocopy D:\\Data \\\\fs01\\backups /MIR\nWeekly: full VSS snapshot\n")),
              _d("Downloads"),
              _d("Favorites"),
              _d("Links"),
              _d("Music"),
              _d("Pictures"),
              _d("Videos"),
              _f("NTUSER.DAT", "", hidden=True, sysfile=True, locked=True, size_hint=2359296)),
           _d("Default", hidden=True),
           _d("Public", _d("Desktop"), _d("Documents"), _d("Downloads"))),
        _d("Windows",
           _d("Logs", _d("CBS", _f("CBS.log", "2026-11-02 06:13:01, Info  CBS  Session: 31094381_1872 initialized.\n"))),
           _d("Panther", _f("unattend.xml", UNATTEND)),
           _d("System32",
              _d("config", _f("SAM", "", locked=True, size_hint=65536, sysfile=True),
                 _f("SYSTEM", "", locked=True, size_hint=17039360, sysfile=True),
                 _f("SECURITY", "", locked=True, size_hint=65536, sysfile=True)),
              _d("drivers", _d("etc", _f("hosts", HOSTS), _f("networks", "loopback  127\n"), _f("services", "echo  7/tcp\nftp  21/tcp\nssh  22/tcp\nhttp  80/tcp\n"))),
              _d("WindowsPowerShell", _d("v1.0", _bin("powershell.exe", 448000))),
              _bin("cmd.exe", 280576), _bin("whoami.exe", 79360), _bin("hostname.exe", 14848),
              _bin("ipconfig.exe", 33792), _bin("netstat.exe", 41472), _bin("PING.EXE", 22016),
              _bin("systeminfo.exe", 98304), _bin("tasklist.exe", 92672), _bin("sc.exe", 69632),
              _bin("net.exe", 59904), _bin("certutil.exe", 1554432), _bin("findstr.exe", 36352)),
           _d("Temp"),
           _f("win.ini", "; for 16-bit app support\n[fonts]\n[extensions]\n[mci extensions]\n[files]\n[Mail]\nMAPI=1\n"),
           _f("system.ini", "; for 16-bit app support\n[386Enh]\nwoafont=dosapp.fon\n"),
           _bin("explorer.exe", 4720640), _bin("notepad.exe", 254464), _bin("regedit.exe", 358400)),
    )


_TEMPLATE = _tree()


class VirtualFS:
    def __init__(self):
        self.root = copy.deepcopy(_TEMPLATE)
        self.created = 0
        self._usage = {}  # node -> bytes this session stored in it

    @property
    def bytes_used(self) -> int:
        return sum(self._usage.values())

    # ── path handling ───────────────────────────────────────────────────────────────────────────────────────────
    def parts(self, path: str, cwd: str) -> list[str]:
        """Validated components (without the drive) of `path` resolved against `cwd`. Raises VfsError."""
        if not isinstance(path, str):
            raise VfsError("The filename, directory name, or volume label syntax is incorrect.")
        p = path.strip()
        if len(p) > MAX_PATH:
            raise VfsError("The filename or extension is too long.")
        p = p.replace("/", "\\")
        if p.startswith("\\\\"):
            raise VfsError("The network path was not found.")
        drive = re.match(r"^([A-Za-z]):", p)
        if drive:
            if drive.group(1).upper() != "C":
                raise VfsError("The system cannot find the drive specified.")
            p = p[2:]  # "C:\x" is absolute; "C:x" and "C:" are relative to the current directory on C:
        if p.startswith("\\"):
            base = []
        else:
            base = self._cwd_parts(cwd)
        out = list(base)
        for comp in p.split("\\"):
            comp = comp.rstrip(" .") if comp not in (".", "..") else comp
            if comp in ("", "."):
                continue
            if comp == "..":
                if out:
                    out.pop()
                continue
            if _BAD_CHARS.search(comp) or ":" in comp:
                raise VfsError("The filename, directory name, or volume label syntax is incorrect.")
            if comp.split(".")[0].lower() in RESERVED:
                raise VfsError("The system cannot find the path specified.")
            out.append(comp)
        return out

    def _cwd_parts(self, cwd: str) -> list[str]:
        """The shell's current directory is always an absolute C:\\ path it produced itself."""
        if not cwd or not cwd[:3].upper() == "C:\\":
            return []
        return [c for c in cwd[3:].split("\\") if c]

    def node(self, parts: list[str]) -> Node | None:
        n = self.root
        for comp in parts:
            if not n.is_dir:
                return None
            n = n.children.get(comp.lower())
            if n is None:
                return None
        return n

    def display(self, parts: list[str]) -> str:
        """Canonical case of an existing path (Windows shows stored case, not typed case)."""
        n, names = self.root, []
        for comp in parts:
            n = n.children.get(comp.lower()) if n and n.is_dir else None
            names.append(n.name if n else comp)
        return "C:\\" + "\\".join(names)

    def resolve(self, path: str, cwd: str) -> tuple[list[str], Node | None]:
        parts = self.parts(path, cwd)
        return parts, self.node(parts)

    # ── operations used by the shell ────────────────────────────────────────────────────────────────────────────
    def chdir(self, path: str, cwd: str) -> str:
        parts, n = self.resolve(path, cwd)
        if n is None:
            raise VfsError("The system cannot find the path specified.")
        if not n.is_dir:
            raise VfsError("The directory name is invalid.")
        return self.display(parts)

    def read(self, path: str, cwd: str) -> str:
        parts, n = self.resolve(path, cwd)
        if n is None:
            raise VfsError("The system cannot find the file specified.")
        if n.is_dir:
            raise VfsError("Access is denied.")
        if n.locked:
            raise VfsError("The process cannot access the file because it is being used by another process.")
        return n.content

    def listdir(self, path: str, cwd: str, show_hidden=False) -> tuple[str, Node, list[Node]]:
        parts, n = self.resolve(path, cwd)
        if n is None:
            raise VfsError("File Not Found")
        if not n.is_dir:
            return self.display(parts[:-1]), self.node(parts[:-1]), [n]
        items = sorted(n.children.values(), key=lambda c: c.name.lower())
        if not show_hidden:
            items = [c for c in items if not c.hidden]
        return self.display(parts), n, items

    def write(self, path: str, cwd: str, text: str, append=False):
        parts, n = self.resolve(path, cwd)
        if not parts:
            raise VfsError("Access is denied.")
        parent = self.node(parts[:-1])
        if parent is None or not parent.is_dir:
            raise VfsError("The system cannot find the path specified.")
        if n is not None and (n.is_dir or n.sysfile or n.locked or self._protected(parts)):
            raise VfsError("Access is denied.")
        if n is None and self._protected(parts):
            raise VfsError("Access is denied.")
        new = (n.content if (n and append) else "") + text
        size = len(new.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            raise VfsError("There is not enough space on the disk.")
        if self.bytes_used - self._usage.get(n, 0) + size > MAX_SESSION_BYTES:
            raise VfsError("There is not enough space on the disk.")
        if n is None:
            self._count()
            n = Node(parts[-1], False, mtime="11/14/2026  10:00 AM")
            parent.children[parts[-1].lower()] = n
        n.content, n.size_hint = new, None
        self._usage[n] = size

    def mkdir(self, path: str, cwd: str):
        parts, n = self.resolve(path, cwd)
        if n is not None:
            raise VfsError(f"A subdirectory or file {path} already exists.")
        if self._protected(parts):
            raise VfsError("Access is denied.")
        cur = self.root
        for comp in parts:
            nxt = cur.children.get(comp.lower())
            if nxt is None:
                self._count()
                nxt = Node(comp, True, mtime="11/14/2026  10:00 AM")
                cur.children[comp.lower()] = nxt
            elif not nxt.is_dir:
                raise VfsError("The system cannot find the path specified.")
            cur = nxt

    def delete(self, path: str, cwd: str):
        parts, n = self.resolve(path, cwd)
        if n is None:
            raise VfsError(f"Could Not Find {self.display(parts)}")
        if n.is_dir:
            raise VfsError("Access is denied.")
        if n.sysfile or n.locked or self._protected(parts):
            raise VfsError("Access is denied.")
        del self.node(parts[:-1]).children[parts[-1].lower()]
        self._usage.pop(n, None)

    def _protected(self, parts):
        # Writes are allowed only under the user's profile and C:\Temp, as a non-elevated session would see it.
        low = [p.lower() for p in parts]
        return not (low[:2] == ["users", "administrator"] or low[:1] == ["temp"])

    def _count(self):
        if self.created >= MAX_CREATED_NODES:
            raise VfsError("There is not enough space on the disk.")
        self.created += 1

    def free_bytes(self) -> int:
        return 41_237_172_224 - self.created * 4096 - self.bytes_used
