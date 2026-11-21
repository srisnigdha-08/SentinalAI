"""Intent and MITRE ATT&CK classification of Windows-style commands (Rank 7).

Same intent vocabulary as the Linux rules (honeypot/parsers/log_parser.classify_intent and the backend's
classifyIntent): CREDENTIAL_HARVEST, MALWARE_DOWNLOAD, PRIVILEGE_ESCALATION, PERSISTENCE, REVERSE_SHELL,
RECONNAISSANCE, DESTRUCTION, UNKNOWN. These rules are applied only to sessions served by the simulated Windows
persona, so Linux sessions are classified exactly as before. backend/utils/windowsPersona.js mirrors them (a test
keeps both in step). Classification describes what was *attempted*; the simulator executed nothing.
"""
from __future__ import annotations

import base64
import binascii
import re

_S = r"(?:^|[;&|(]\s*)(?:cmd(?:\.exe)?\s+/c\s+|powershell(?:\.exe)?\s+(?:-\w+\s+)*)?"


def _c(names):
    return re.compile(_S + r"(?:" + names + r")(?:\.exe)?(?=\s|$|[;&|)])", re.I)


# Rank 8 (F5): PowerShell's encoded-command flag. Required: a powershell invocation and an explicit -enc /
# -EncodedCommand (any unambiguous prefix from -enc on, or the -ec alias). A bare "-e" or a long word after any
# "-e" no longer counts. Mirrored in backend/utils/windowsPersona.js (encodedPowerShell).
ENCODED_PS = re.compile(r"(?:^|[\s;&|(\"'])powershell(?:\.exe)?\b[^;&|]*?\s[-/](?:ec|enc(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)"
                        r"\s+[\"']?([A-Za-z0-9+/=]{8,})", re.I)
REVERSE_SHELL_PAYLOAD = re.compile(r"tcpclient|invoke-powershelltcp|\$\w+\.getstream\(\)", re.I)
MAX_DECODED = 16 * 1024


# Ordered: the first matching intent wins (same precedence as the Linux rules).
INTENT_RULES = [
    ("CREDENTIAL_HARVEST", re.compile(r"\\config\\(sam|system|security)\b|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)"
                                      r"|unattend\.xml|web\.config|administrators_authorized_keys|mimikatz|sekurlsa"
                                      r"|ntds\.dit|cmdkey\s+/list|vaultcmd", re.I)),
    ("MALWARE_DOWNLOAD", re.compile(r"certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+/transfer"
                                    r"|invoke-webrequest|\biwr\b|downloadstring|downloadfile|start-bitstransfer"
                                    r"|(curl|wget)(\.exe)?\s+https?://", re.I)),
    ("PRIVILEGE_ESCALATION", re.compile(r"net\s+localgroup\s+administrators\s+\S+\s+/add|runas\s+/user"
                                        r"|whoami\s+/priv.*sedebug|takeown\s+/f|icacls\s+.*/grant", re.I)),
    ("PERSISTENCE", re.compile(r"schtasks(\.exe)?\s+/create|sc(\.exe)?\s+create|reg(\.exe)?\s+add\s+\S*\\run\b"
                               r"|new-service|register-scheduledtask|net\s+user\s+\S+\s+\S*\s*/add|new-localuser", re.I)),
    # Rank 8 (F5): plain reverse-shell indicators only. An encoded PowerShell command is never a reverse shell by
    # itself: classify_windows_intent requires an explicit -enc/-EncodedCommand AND a reverse-shell indicator inside.
    ("REVERSE_SHELL", re.compile(r"nc(at)?(\.exe)?\s+.*-e\s+cmd|system\.net\.sockets\.tcpclient|invoke-powershelltcp", re.I)),
    ("RECONNAISSANCE", _c(r"whoami|hostname|ver|systeminfo|ipconfig|netstat|tasklist|net\s+(user|localgroup|share|view|accounts)"
                          r"|sc\s+query|get-computerinfo|get-process|get-service|get-localuser|get-netipaddress"
                          r"|nltest|arp|route\s+print|query\s+user|quser|wmic")),
    # Rank 8: clearing event logs is defense impairment (T1685.005), not destruction; it keeps its technique only.
    ("DESTRUCTION", re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete"
                               r"|del\s+.*(/s|/q).*(/s|/q)|rd\s+/s\s+/q\s+c:\\|format\s+[a-z]:|cipher\s+/w"
                               r"|remove-item\s+.*-recurse.*-force", re.I)),
]

# ATT&CK Enterprise v20.1 (verified 2026-11-16). backend/utils/attackTechniques.js is the master table; a test keeps
# both equal. In v20 Defense Evasion is split into Stealth and Defense Impairment; Clear Windows Event Logs is
# T1685.005 (formerly T1070.001).
TECHNIQUES = {
    "T1082": ("System Information Discovery", ["Discovery"]),
    "T1033": ("System Owner/User Discovery", ["Discovery"]),
    "T1016": ("System Network Configuration Discovery", ["Discovery"]),
    "T1049": ("System Network Connections Discovery", ["Discovery"]),
    "T1057": ("Process Discovery", ["Discovery"]),
    "T1007": ("System Service Discovery", ["Discovery"]),
    "T1087.001": ("Local Account", ["Discovery"]),
    "T1069.001": ("Local Groups", ["Discovery"]),
    "T1135": ("Network Share Discovery", ["Discovery"]),
    "T1018": ("Remote System Discovery", ["Discovery"]),
    "T1083": ("File and Directory Discovery", ["Discovery"]),
    "T1003.001": ("LSASS Memory", ["Credential Access"]),
    "T1003.002": ("Security Account Manager", ["Credential Access"]),
    "T1003.003": ("NTDS", ["Credential Access"]),
    "T1552.001": ("Credentials In Files", ["Credential Access"]),
    "T1555.004": ("Windows Credential Manager", ["Credential Access"]),
    "T1105": ("Ingress Tool Transfer", ["Command and Control"]),
    "T1095": ("Non-Application Layer Protocol", ["Command and Control"]),
    "T1059.001": ("PowerShell", ["Execution"]),
    "T1059.003": ("Windows Command Shell", ["Execution"]),
    "T1027": ("Obfuscated Files or Information", ["Stealth"]),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1543.003": ("Windows Service", ["Persistence", "Privilege Escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"]),
    "T1136.001": ("Local Account", ["Persistence"]),
    "T1098": ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1222.001": ("Windows Permissions", ["Defense Impairment"]),
    "T1490": ("Inhibit System Recovery", ["Impact"]),
    "T1485": ("Data Destruction", ["Impact"]),
    "T1685.005": ("Clear Windows Event Logs", ["Defense Impairment"]),
}

# (pattern, technique id) pairs, all that match are reported. Same rules and order as
# backend/utils/windowsPersona.js WINDOWS_COMMAND_TECHNIQUES.
ATTACK_RULES = [
    (_c(r"systeminfo|ver|hostname|get-computerinfo|wmic\s+os"), "T1082"),
    (_c(r"whoami|query\s+user|quser"), "T1033"),
    (_c(r"ipconfig|route\s+print|arp|get-netipaddress"), "T1016"),
    (_c(r"netstat"), "T1049"),
    (_c(r"tasklist|get-process|ps|gps"), "T1057"),
    (_c(r"sc\s+query|get-service|gsv|net\s+start"), "T1007"),
    (_c(r"net\s+user|get-localuser|net\s+accounts"), "T1087.001"),
    (_c(r"net\s+localgroup|get-localgroup"), "T1069.001"),
    (_c(r"net\s+share|net\s+view"), "T1135"),
    (_c(r"ping|nltest"), "T1018"),
    (_c(r"dir|tree|get-childitem|gci|ls"), "T1083"),
    (re.compile(r"\\config\\(sam|system|security)\b|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)", re.I), "T1003.002"),
    (re.compile(r"mimikatz|sekurlsa", re.I), "T1003.001"),
    (re.compile(r"ntds\.dit", re.I), "T1003.003"),
    (re.compile(r"unattend\.xml|web\.config|administrators_authorized_keys", re.I), "T1552.001"),
    (re.compile(r"cmdkey(\.exe)?\s+/list|vaultcmd", re.I), "T1555.004"),
    (re.compile(r"certutil(\.exe)?\s+.*-urlcache|bitsadmin(\.exe)?\s+/transfer|invoke-webrequest|\biwr\b|downloadstring"
                r"|downloadfile|start-bitstransfer", re.I), "T1105"),
    (re.compile(r"(^|[\s;&|(])powershell(\.exe)?\b|invoke-expression|\biex\b", re.I), "T1059.001"),
    (re.compile(r"(^|[\s;&|(])cmd(\.exe)?\s+/[ck]\b", re.I), "T1059.003"),
    (ENCODED_PS, "T1027"),
    (re.compile(r"system\.net\.sockets\.tcpclient|tcpclient\(|invoke-powershelltcp", re.I), "T1095"),
    (re.compile(r"schtasks(\.exe)?\s+/create|register-scheduledtask", re.I), "T1053.005"),
    (re.compile(r"sc(\.exe)?\s+create|new-service", re.I), "T1543.003"),
    (re.compile(r"reg(\.exe)?\s+add\s+\S*\\run\b", re.I), "T1547.001"),
    (re.compile(r"net\s+user\s+\S+\s+\S*\s*/add|new-localuser", re.I), "T1136.001"),
    (re.compile(r"net\s+localgroup\s+administrators\s+\S+\s+/add", re.I), "T1098"),
    (re.compile(r"icacls\s+.*/grant|takeown\s+/f", re.I), "T1222.001"),
    (re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete", re.I), "T1490"),
    (re.compile(r"del\s+.*(/s|/q).*(/s|/q)|rd\s+/s\s+/q\s+c:\\|format\s+[a-z]:|cipher\s+/w"
                r"|remove-item\s+.*-recurse.*-force", re.I), "T1485"),
    (re.compile(r"wevtutil(\.exe)?\s+cl|clear-eventlog", re.I), "T1685.005"),
]


def encoded_powershell(command: str):
    """The decoded script of `powershell -enc <base64>`, or None (no explicit flag, or not valid Base64/UTF-16LE)."""
    m = ENCODED_PS.search(str(command or ""))
    if not m:
        return None
    raw = m.group(1)
    if len(raw) % 4 or len(raw) > 4 * MAX_DECODED:
        return None
    try:
        return base64.b64decode(raw, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def classify_windows_intent(command: str, _depth: int = 0) -> str:
    text = str(command or "")
    decoded = encoded_powershell(text) if _depth == 0 else None
    for intent, pattern in INTENT_RULES:
        if intent == "REVERSE_SHELL" and decoded is not None and REVERSE_SHELL_PAYLOAD.search(decoded):
            return intent
        if pattern.search(text):
            return intent
    # A benign encoded command is classified by what it decodes to (never as a reverse shell by itself).
    if decoded is not None:
        return classify_windows_intent(decoded, _depth + 1)
    return "UNKNOWN"


def attack_techniques(command: str) -> list[dict]:
    text, out, seen = str(command or ""), [], set()
    for pattern, tid in ATTACK_RULES:
        if tid not in seen and pattern.search(text):
            seen.add(tid)
            name, tactics = TECHNIQUES[tid]
            out.append({"id": tid, "name": name, "tactics": list(tactics)})
    return out


CATEGORIES = {
    "filesystem": {"dir", "cd", "chdir", "type", "more", "mkdir", "md", "del", "erase", "tree", "get-childitem",
                   "get-content", "get-location", "set-location", "findstr", "find"},
    "system_info": {"whoami", "hostname", "ver", "systeminfo", "get-computerinfo", "set"},
    "network": {"ipconfig", "ping", "netstat", "get-netipaddress"},
    "process_service": {"tasklist", "sc", "get-process", "get-service"},
    "account": {"net", "get-localuser"},
    "transfer": {"certutil", "invoke-webrequest", "bitsadmin", "curl", "wget"},
    "shell": {"cls", "clear-host", "echo", "write-output", "powershell", "cmd", "exit", "help"},
}


def category_of(name: str) -> str:
    n = (name or "").lower()
    for cat, names in CATEGORIES.items():
        if n in names:
            return cat
    return "unrecognised"
