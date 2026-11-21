"""
Honeypot-SESSION feature contract (docs/SESSION_ML.md). Separate from the network-flow contract (utils.features,
53 features, xgb_cicids_v1): no name, vector or model is shared.

Schema "session_v2": every feature of "session_v1" with the same definition, plus authentication, command-category,
sequence and persona groups. Deterministic: the same session always gives the same vector, in FEATURE_NAMES order.

Safety:
  * Commands are only read as text. Nothing is executed, evaluated, passed to a shell or written anywhere.
  * Inputs are bounded (MAX_COMMANDS commands, MAX_COMMAND_CHARS characters each); the rest is ignored and counted.
  * Malformed input never raises: a non-dict session, a non-list command list, non-dict items, non-numeric or
    negative numbers are counted in the quality report and contribute 0. Every feature value is a finite float.
  * Usernames and passwords are never part of a feature or of the quality report; only their counts are.
Only fields that exist in the backend's Cowrie session payload are read (backend/services/honeypotService.js):
sessionId, durationSeconds, loginSucceeded, failedLogins, credentials[].username/success (when sent), commands[].
command/intent/timestamp, iocCount, deceptionProfile.
"""
import math
import re
import statistics as st
from datetime import datetime
from typing import Dict, List, Tuple

SCHEMA_VERSION = "session_v2"
MAX_COMMANDS = 5000
MAX_COMMAND_CHARS = 4096
INTENTS = ("RECONNAISSANCE", "CREDENTIAL_HARVEST", "MALWARE_DOWNLOAD", "PERSISTENCE", "PRIVILEGE_ESCALATION",
           "REVERSE_SHELL")
# The five personas Cowrie can genuinely serve. windows_srv is unsupported (docs/PERSONAS.md) and maps to unknown.
SERVABLE_PERSONAS = ("ubuntu_22", "debian_11", "centos_7", "aws_ec2", "raspberry_pi")

_FP = re.compile(r"\b(systemd-detect-virt|virt-what|dmidecode|imvirt)\b|/proc/1/cgroup|\.dockerenv")
_DOWNLOAD = re.compile(r"\b(wget|curl|tftp|ftpget)\b")
_EXEC_DOWNLOADED = re.compile(r"chmod \+x|\./")
_SEGMENT_SPLIT = re.compile(r"\|\||&&|[;|&\n]")

# Command categories: program names (first word of each ;/&&/|| segment, path stripped) and a few path markers.
# A category is an OBSERVATION of what a command touches, not proof of intent.
CATEGORIES: Dict[str, Tuple[frozenset, Tuple[str, ...]]] = {
    "recon_system": (frozenset({"uname", "hostname", "hostnamectl", "lscpu", "uptime", "free", "df", "dmesg",
                                "lsb_release", "nproc", "lsmod", "arch"}),
                     ("/proc/cpuinfo", "/proc/meminfo", "/etc/os-release", "/etc/issue", "/proc/version")),
    "recon_user": (frozenset({"whoami", "id", "w", "who", "last", "lastlog", "groups", "users", "finger"}),
                   ("/etc/passwd", "/etc/group")),
    "recon_network": (frozenset({"ifconfig", "ip", "netstat", "ss", "arp", "route", "iwconfig", "nmcli"}),
                      ("/etc/resolv.conf", "/etc/hosts", "/proc/net/")),
    "recon_filesystem": (frozenset({"ls", "find", "pwd", "du", "locate", "tree", "stat", "file"}), ()),
    "credential_access": (frozenset(), ("/etc/shadow", ".ssh/id_", ".bash_history", "/etc/gshadow")),
    "privilege_escalation": (frozenset({"sudo", "su", "pkexec", "doas"}), ("/etc/sudoers", "u+s", "4755")),
    "persistence": (frozenset({"crontab", "useradd", "adduser", "usermod", "chpasswd"}),
                    ("authorized_keys", "/etc/cron", "/etc/rc.local", "/etc/init.d", ".bashrc", ".profile",
                     "systemctl enable", "/etc/systemd/system")),
    "file_modification": (frozenset({"rm", "mv", "cp", "touch", "chmod", "chown", "chattr", "mkdir", "tee", "dd",
                                     "truncate", "shred"}), (" > ", ">>", "sed -i")),
    "upload": (frozenset({"scp", "sftp", "ftpput", "rsync"}), ("--upload-file", "curl -t ")),
    "network_tools": (frozenset({"nc", "ncat", "netcat", "nmap", "ssh", "telnet", "socat", "ping", "masscan",
                                 "tcpdump"}), ()),
    "shell_execution": (frozenset({"sh", "bash", "dash", "zsh", "busybox", "python", "python3", "perl", "php",
                                   "ruby", "eval", "exec", "nohup", "source"}), ("./", "base64 -d", "| sh", "|sh")),
}
CATEGORY_NAMES = tuple(CATEGORIES)

V1_NAMES = (
    "n_commands", "unique_command_ratio", "distinct_programs", "bigram_diversity", "duration_seconds",
    "login_succeeded", "failed_logins", "gap_mean_s", "gap_median_s", "gap_std_s", "max_command_length",
    "pipes_and_redirects", "downloads", "executes_downloaded", "fingerprint_commands", "ioc_count",
) + tuple(f"intent_{i.lower()}" for i in INTENTS)
V2_ADDED = (
    ("login_attempts", "distinct_usernames")
    + tuple(f"cmd_{c}" for c in CATEGORY_NAMES)
    + ("category_diversity", "event_count", "events_per_minute", "timestamp_coverage", "recon_before_download")
    + tuple(f"persona_{p}" for p in SERVABLE_PERSONAS) + ("persona_unknown",)
)
# Fixed, versioned order: a model artifact must list exactly these names to be loadable.
FEATURE_NAMES: Tuple[str, ...] = V1_NAMES + V2_ADDED

# Human-readable contract (docs/SESSION_ML.md is generated from the same definitions).
FEATURE_SPEC: Dict[str, dict] = {}


def _spec(name, group, definition, missing="0"):
    FEATURE_SPEC[name] = {"group": group, "type": "float", "definition": definition, "missing": missing}


_spec("n_commands", "commands", "number of commands (bounded to MAX_COMMANDS)")
_spec("unique_command_ratio", "commands", "distinct command strings / commands; 0 with no commands")
_spec("distinct_programs", "commands", "distinct first words of the commands")
_spec("bigram_diversity", "sequence", "distinct consecutive first-word pairs / (commands - 1)")
_spec("duration_seconds", "session", "session duration in seconds; negative or non-numeric -> 0")
_spec("login_succeeded", "authentication", "1 if a login succeeded, else 0")
_spec("failed_logins", "authentication", "failed logins (max of failedLogins and failed credentials[] entries)")
_spec("gap_mean_s", "sequence", "mean seconds between consecutive timestamped commands")
_spec("gap_median_s", "sequence", "median seconds between consecutive timestamped commands")
_spec("gap_std_s", "sequence", "population std of those gaps (needs 2+ gaps)")
_spec("max_command_length", "commands", "longest command, in characters (after truncation)")
_spec("pipes_and_redirects", "commands", "count of | and > characters across commands")
_spec("downloads", "file_and_network", "commands invoking wget / curl / tftp / ftpget")
_spec("executes_downloaded", "execution", "1 if any command matches 'chmod +x' or './'")
_spec("fingerprint_commands", "reconnaissance", "commands probing for a VM / honeypot (systemd-detect-virt, ...)")
_spec("ioc_count", "file_and_network", "indicator count reported for the session (iocCount)")
for _i in INTENTS:
    _spec(f"intent_{_i.lower()}", "intent", f"commands the existing command-intent classifier tagged {_i}")
_spec("login_attempts", "authentication", "credentials[] entries, or loginSucceeded + failed_logins when absent")
_spec("distinct_usernames", "authentication", "distinct usernames tried (the names themselves are never output)")
for _c in CATEGORY_NAMES:
    _spec(f"cmd_{_c}", "command_category", f"commands with a segment in category {_c} (observation, not intent)")
_spec("category_diversity", "command_category", "categories observed / number of categories")
_spec("event_count", "session", "login attempts + commands")
_spec("events_per_minute", "session", "event_count / (duration / 60); 0 when duration is 0")
_spec("timestamp_coverage", "session", "commands with a valid timestamp / commands; 0 with no commands")
_spec("recon_before_download", "sequence", "1 if a reconnaissance-category command precedes the first download")
for _p in SERVABLE_PERSONAS:
    _spec(f"persona_{_p}", "persona", f"1 if the served persona was {_p}")
_spec("persona_unknown", "persona", "1 if the persona is missing, unsupported (windows_srv) or unrecognised")
assert tuple(FEATURE_SPEC) == FEATURE_NAMES


def _ts(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v) if math.isfinite(v) else None
    if isinstance(v, datetime):
        return v.timestamp()
    if isinstance(v, str) and v:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _num(v, quality, field):
    """A finite, non-negative number, else 0 (and the field is reported as invalid when it was present)."""
    if v is None or v == "":
        return 0.0
    if isinstance(v, bool):
        return float(v)
    try:
        x = float(v)
    except (TypeError, ValueError):
        quality["invalidNumbers"].append(field)
        return 0.0
    if not math.isfinite(x) or x < 0:
        quality["invalidNumbers"].append(field)
        return 0.0
    return x


def _program(segment: str) -> str:
    words = segment.strip().split()
    while words and (words[0] in ("sudo", "nohup", "env", "busybox", "timeout") or "=" in words[0]) and len(words) > 1:
        if words[0] == "sudo":
            return "sudo"
        words = words[1:]
    return words[0].rsplit("/", 1)[-1].lower() if words else ""


def command_categories(text: str) -> List[str]:
    """Categories one command touches (sorted, unique). Pure text inspection; nothing is executed."""
    low = f" {text.lower()} "
    progs = {_program(s) for s in _SEGMENT_SPLIT.split(text)} - {""}
    found = []
    for name, (programs, markers) in CATEGORIES.items():
        if progs & programs or any(m in low for m in markers):
            found.append(name)
    return found


def extract(session) -> Tuple[Dict[str, float], dict]:
    """(features, quality). features has exactly FEATURE_NAMES; quality describes what was missing or ignored."""
    quality = {"schemaVersion": SCHEMA_VERSION, "malformedCommands": 0, "truncatedCommands": 0,
               "ignoredCommands": 0, "invalidNumbers": [], "missingDuration": False, "notADict": False}
    if not isinstance(session, dict):
        quality["notADict"] = True
        session = {}
    raw = session.get("commands")
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        quality["malformedCommands"] += 1
        raw = []
    if len(raw) > MAX_COMMANDS:
        quality["ignoredCommands"] = len(raw) - MAX_COMMANDS
        raw = raw[:MAX_COMMANDS]
    texts, times, intents = [], [], []
    for c in raw:
        if isinstance(c, str):
            c = {"command": c}
        if not isinstance(c, dict):
            quality["malformedCommands"] += 1
            continue
        t = c.get("command")
        t = "" if t is None else str(t)
        if len(t) > MAX_COMMAND_CHARS:
            quality["truncatedCommands"] += 1
            t = t[:MAX_COMMAND_CHARS]
        texts.append(t)
        times.append(_ts(c.get("timestamp")))
        intents.append(c.get("intent") if isinstance(c.get("intent"), str) else None)

    valid_times = [x for x in times if x is not None]
    gaps = [b - a for a, b in zip(valid_times, valid_times[1:]) if b >= a]
    first_words = [t.strip().split()[0] if t.strip() else "" for t in texts]
    bigrams = set(zip(first_words, first_words[1:]))
    if session.get("durationSeconds") in (None, ""):
        quality["missingDuration"] = True
    duration = _num(session.get("durationSeconds"), quality, "durationSeconds")

    creds = session.get("credentials")
    creds = [c for c in creds if isinstance(c, dict)] if isinstance(creds, list) else []
    failed_from_creds = sum(1 for c in creds if not c.get("success"))
    failed = max(_num(session.get("failedLogins"), quality, "failedLogins"), float(failed_from_creds))
    login_ok = bool(session.get("loginSucceeded")) or any(bool(c.get("success")) for c in creds)
    attempts = float(len(creds)) if creds else failed + float(login_ok)
    usernames = {str(c.get("username")) for c in creds if c.get("username") not in (None, "")}

    per_cmd = [command_categories(t) for t in texts]
    cat_counts = {c: float(sum(c in cats for cats in per_cmd)) for c in CATEGORY_NAMES}
    is_download = [bool(_DOWNLOAD.search(t)) for t in texts]
    first_dl = is_download.index(True) if any(is_download) else None
    recon = {"recon_system", "recon_user", "recon_network", "recon_filesystem"}
    recon_before = first_dl is not None and any(recon & set(cats) for cats in per_cmd[:first_dl])
    persona = session.get("deceptionProfile")
    persona = persona if persona in SERVABLE_PERSONAS else None
    n = len(texts)
    events = attempts + n

    f = {
        "n_commands": float(n),
        "unique_command_ratio": len(set(texts)) / n if n else 0.0,
        "distinct_programs": float(len(set(first_words) - {""})),
        "bigram_diversity": len(bigrams) / max(1, len(first_words) - 1),
        "duration_seconds": duration,
        "login_succeeded": float(login_ok),
        "failed_logins": failed,
        "gap_mean_s": st.mean(gaps) if gaps else 0.0,
        "gap_median_s": st.median(gaps) if gaps else 0.0,
        "gap_std_s": st.pstdev(gaps) if len(gaps) > 1 else 0.0,
        "max_command_length": float(max((len(t) for t in texts), default=0)),
        "pipes_and_redirects": float(sum(t.count("|") + t.count(">") for t in texts)),
        "downloads": float(sum(is_download)),
        "executes_downloaded": float(any(_EXEC_DOWNLOADED.search(t) for t in texts)),
        "fingerprint_commands": float(sum(bool(_FP.search(t)) for t in texts)),
        "ioc_count": _num(session.get("iocCount"), quality, "iocCount"),
    }
    for i in INTENTS:
        f[f"intent_{i.lower()}"] = float(sum(x == i for x in intents))
    f["login_attempts"] = attempts
    f["distinct_usernames"] = float(len(usernames))
    for c in CATEGORY_NAMES:
        f[f"cmd_{c}"] = cat_counts[c]
    f["category_diversity"] = sum(v > 0 for v in cat_counts.values()) / len(CATEGORY_NAMES)
    f["event_count"] = events
    f["events_per_minute"] = events / (duration / 60.0) if duration > 0 else 0.0
    f["timestamp_coverage"] = len(valid_times) / n if n else 0.0
    f["recon_before_download"] = float(recon_before)
    for p in SERVABLE_PERSONAS:
        f[f"persona_{p}"] = float(persona == p)
    f["persona_unknown"] = float(persona is None)
    # Every value finite (statistics on huge timestamps could overflow in principle)
    f = {k: (float(v) if isinstance(v, (int, float)) and math.isfinite(v) else 0.0) for k, v in f.items()}
    return {k: f[k] for k in FEATURE_NAMES}, quality


def vector(session) -> List[float]:
    feats, _ = extract(session)
    return [feats[k] for k in FEATURE_NAMES]


# Behavioural reason codes: what was observed, in neutral terms. They describe the session and are shown next to any
# prediction; they are not a verdict and are produced whether or not a model is available.
def reason_codes(features: Dict[str, float]) -> List[str]:
    codes = []
    if features.get("failed_logins", 0) >= 3:
        codes.append("REPEATED_FAILED_LOGINS")
    if features.get("login_succeeded"):
        codes.append("LOGIN_SUCCEEDED")
    if features.get("n_commands", 0) == 0:
        codes.append("NO_COMMANDS")
    for c in CATEGORY_NAMES:
        if features.get(f"cmd_{c}", 0) > 0:
            codes.append(f"OBSERVED_{c.upper()}")
    if features.get("downloads", 0) > 0:
        codes.append("DOWNLOAD_ATTEMPT")
    if features.get("executes_downloaded"):
        codes.append("EXECUTION_MARKER")
    if features.get("recon_before_download"):
        codes.append("RECON_BEFORE_DOWNLOAD")
    if features.get("fingerprint_commands", 0) > 0:
        codes.append("HONEYPOT_FINGERPRINTING")
    if features.get("persona_unknown"):
        codes.append("PERSONA_UNKNOWN")
    return codes
