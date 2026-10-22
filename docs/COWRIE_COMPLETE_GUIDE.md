# Cowrie in SentinelAI: complete guide, live verification, audit and viva prep

Written 2026-10-22 on branch `db-fixes` (working tree, uncommitted changes included).

**How to read the labels**

- **[Cowrie]**: general Cowrie behaviour, true for any Cowrie install.
- **[Ours]**: specific to SentinelAI, with the file and line that proves it.
- **[Live 2026-10-22]**: I observed it today on your machine (procedure in Phase 4).
- **NOT FOUND**: I searched and it does not exist. It is not a guess.

Related docs: `docs/HONEYPOT_STUDY_GUIDE.md` is the earlier audit, and `docs/HONEYPOT_LIVE_EVIDENCE.md` is the 2026-10-21 live run. This guide re-verifies both and adds new findings (marked **NEW**).

---

# PHASE 1: Cowrie fundamentals

## 1.1 What Cowrie is

[Cowrie] Cowrie is an open-source SSH and Telnet honeypot written in Python. It listens like an SSH server and accepts logins from a configurable list. It then gives the attacker a shell that looks like Linux, but it is **emulated**: no attacker command ever runs on the real operating system. Every keystroke, login attempt, command and download is recorded as a structured event.

**Interaction levels**

| Level | What the attacker gets | Examples | Risk | Intelligence |
|---|---|---|---|---|
| Low | A port that answers a banner or handshake, with no shell | honeyd, simple port listeners | Very low | Scans and credentials only |
| **Medium** | A **simulated** shell: commands are parsed and answered by Python code from a fake filesystem | **Cowrie** (shell mode), Kippo | Low: nothing executes | Credentials, commands, download URLs, TTY replays |
| High | A real OS, usually a VM | Real VMs, Cowrie *proxy* mode | High: real code runs | Everything, including real malware behaviour |

**Why Cowrie suits SentinelAI.** SSH brute force is the most common internet attack, and Cowrie's JSON events feed a parser directly. Medium interaction means a student project can collect real attacker behaviour without hosting a machine attackers can take over. Cowrie is also the standard tool here: widely used, maintained, and cited in the literature.

## 1.2 Architecture [Cowrie]

```
             Twisted reactor (one event loop, single-threaded, asynchronous)
   ┌────────────────────────────────────────────────────────────────────┐
   │  SSH transport (twisted.conch)      Telnet transport (optional)    │
   │   - key exchange, HASSH, banner      - disabled by default         │
   │   - auth via checkers -> UserDB                                     │
   │                 │                                                   │
   │          Session / Avatar                                           │
   │                 │                                                   │
   │   Shell emulation (cowrie.shell)  ──or──  Proxy (backend pool/VM)   │
   │    - HoneyPotShell: parses lines, pipes, ;, &&                      │
   │    - command modules (cowrie.commands.*: ls, cat, wget, uname...)   │
   │    - txtcmds: fixed text outputs for simple commands                │
   │    - fake filesystem: fs.pickle (tree + metadata, now also contents)│
   │                 │                                                   │
   │   Event bus: log.msg(eventid=...) ──> output plugins                │
   │      jsonlog, textlog, mongodb, elasticsearch, splunk, custom...    │
   └────────────────────────────────────────────────────────────────────┘
```

- **Twisted**: an asynchronous networking framework. One reactor thread serves every connection, so anything that blocks (a slow HTTP call inside a plugin, for example) freezes the whole honeypot. This is why your blocker plugin polls in a background thread (see 2.4).
- **SSH transport**: Cowrie uses Twisted Conch. It offers a configurable server version string (`[ssh] version`), host keys generated on first start, and records the client's version string and **HASSH** (an MD5 fingerprint of the client's key-exchange algorithm lists that identifies the client software).
- **Telnet**: a separate factory, off by default (`[telnet] enabled = false` in `cowrie.cfg.dist`).
- **Authentication**: `auth_class = UserDB` checks `etc/userdb.txt`, one `user:uid:password` per line. Cowrie's syntax also allows `*` (any password) and `!pass` (refuse this password). The alternative, `AuthRandom`, accepts a login after a random number of attempts.
- **Emulated shell**: `HoneyPotShell` tokenises the input line and looks up each program in the command registry (`src/cowrie/commands/*.py`). An unknown program prints `-bash: X: command not found` and logs `cowrie.command.failed`.
- **Fake filesystem**: `fs.pickle` is a pickled tree of nodes (name, type, uid, gid, size, mode, ctime, children, target, contents). Older Cowrie read file contents from a separate `honeyfs/` directory. Current Cowrie keeps them inside the pickle, and your `build_honeyfs.py` handles both layouts. The attacker can create, delete and "modify" files, but only in memory for that session.
- **txtcmds**: a directory of files whose content is printed as the output of a simple command (e.g. `txtcmds/usr/bin/lscpu`).
- **Output plugins**: every event goes to every enabled `[output_<name>]`. Cowrie imports the plugin module as `cowrie.output.<section name after "output_", up to the next underscore>`. That rule is why your plugin had to be renamed `sentinelblocker` (see 2.4).
- **Proxy / backend pool mode** (`[honeypot] backend = proxy`): Cowrie relays the session to a real SSH server, optionally from a pool of QEMU VMs it starts and recycles. That is high interaction.

## 1.3 Lifecycle of one connection [Cowrie]

1. TCP connect to the listen endpoint → `cowrie.session.connect` (src_ip, src_port, session id: 12 hex characters).
2. Version exchange → `cowrie.client.version` (e.g. `SSH-2.0-paramiko_5.1.0`).
3. Key exchange → `cowrie.client.kex` (hassh, algorithm lists).
4. Each password attempt → `cowrie.login.failed` or `cowrie.login.success` (username, password **in plain text**).
5. PTY request → `cowrie.client.size`. Session parameters → `cowrie.session.params`. On an interactive shell Cowrie starts a **TTY log**.
6. The MOTD and prompt are printed. Each line typed → `cowrie.command.input`, plus `cowrie.command.failed` if the command is unknown.
7. `wget`/`curl` → Cowrie really fetches the URL (if reachable and allowed), stores it under `downloads/<sha256>` and logs `cowrie.session.file_download` (url, outfile, shasum). Uploads over SFTP/SCP → `cowrie.session.file_upload`.
8. Port-forward requests → `cowrie.direct-tcpip.request` (refused when `forwarding = false`).
9. Exit → `cowrie.log.closed` (ttylog path, size, shasum, duration_ms), then `cowrie.session.closed` (duration_ms; older Cowrie wrote `duration` in seconds).

---

# PHASE 2: Your Cowrie setup

## 2.1 Every Cowrie-related file

| File | Role |
|---|---|
| `honeypot/cowrie/cowrie.cfg` | The config Cowrie reads (generated by `switch_profile.py`; line 1 says so) |
| `honeypot/cowrie/userdb.txt` | Accepted credentials (13 lines) |
| `honeypot/cowrie/sentinelblocker.py` | Custom output plugin: refuses connections from SentinelAI-blocked IPs |
| `honeypot/cowrie/sentinel_output.py` | Alternative output plugin that POSTs events directly. **Not enabled** (README line "not enabled ... on purpose") |
| `honeypot/switch_profile.py` | Writes `cowrie.cfg` for one of 6 personas (lines 20-69) |
| `honeypot/build_honeyfs.py` | Builds one `fs.pickle` per persona (os-release, issue, hostname, motd, canary credentials) |
| `honeypot/deception_rotator.py` | Applies the Q-learner's recommended persona: rewrites cfg, restarts Cowrie, records the persona |
| `honeypot/parsers/log_parser.py` | **The ingest path**: tails `cowrie.json` and POSTs to the backend |
| `honeypot/parsers/Dockerfile` | Parser image (python:3.12-slim, uid 10001) |
| `honeypot/docker-compose.honeypot.yml` | Hardened Cowrie + parser stack. **Untested** (its own line 3) |
| `honeypot/docker/egress-rules.sh` | iptables: the honeypot bridge may reach only the backend port. **Untested** |
| `honeypot/redirect-ssh-port.sh` | iptables REDIRECT 22 → 2222. **Untested** |
| `honeypot/collectors/session_collector.js` | Backend-side handlers that turn events into MongoDB documents |
| `honeypot/sniffer/` | Packet-flow capture for the ML dataset (not Cowrie) |
| `backend/routes/honeypotIngest.js` | `/api/honeypot/ingest/*` (honeypot API key only) |
| `backend/services/honeypotService.js` | Atomic session updates, closure analysis, Q-learner call, auto-block |
| `backend/models/HoneypotSession.js` | MongoDB schema |
| `ai-engine/inference/predictor.py:529` + `ai-engine/utils/features.py:383` | Rule classification of sessions |
| `ai-engine/rl_engine/deception_scorer.py` | Q-learning persona recommender |
| `frontend/src/pages/HoneypotAnalytics.jsx` | Dashboard page |
| Cowrie install (outside the repo) | WSL Ubuntu: `~/sentinelai-cowrie-test/cowrie` |

## 2.2 Version and install method

- **Install: git clone + Python venv inside WSL Ubuntu** (not Docker, not pip-from-PyPI). [Live 2026-10-22]
  - Path `/home/srisnigdha/sentinelai-cowrie-test/cowrie`, venv `../env`.
  - Git commit **`c7773f4`** (2026-10-15). pip metadata reports `cowrie 3.1.3`; treat the commit as the authoritative version.
  - **Twisted 26.4.0, Python 3.14.4, paramiko 5.1.0.**
- It runs as your normal user `srisnigdha`, **not root** (`ls -la` of `var/` shows owner `srisnigdha`).
- The Docker path (`honeypot/docker-compose.honeypot.yml:29`) uses `cowrie/cowrie:latest`. That tag is **unpinned**, and the stack has **never been run** (no Docker on this machine; `docker` is not installed).

## 2.3 cowrie.cfg, section by section

Repo file `honeypot/cowrie/cowrie.cfg` is currently the **centos_7** persona. The deployed WSL copy is **ubuntu_22**, written by the rotator during yesterday's closed-loop test, and also sets `filesystem = personas/ubuntu_22.pickle`.

| Key | Value (repo) | Line | Default? / Comment |
|---|---|---|---|
| `[honeypot] hostname` | `centos-web-gateway` | 3 | Changed from Cowrie's default `svr04` ✔ |
| `log_path` | `var/log/cowrie` | 4 | Default |
| `interactive_timeout` | 180 s | 5 | Default is 180 (explicit only) |
| `auth_class` | `UserDB` | 6 | Default |
| `download_path` | `${honeypot:state_path}/downloads` → `var/lib/cowrie/downloads` | 7 | Default |
| `download_limit_size` | 10485760 (10 MB) | 8 | Changed (Cowrie's default is no limit) ✔ |
| `[shell] kernel_version / build / platform / OS` | CentOS 7 3.10.0-1160 | 11-14 | Changed ✔ |
| `[shell] filesystem` | not set in repo cfg → **stock fs.pickle** | — | Set only when `COWRIE_PERSONA_FS` is used (`switch_profile.py:89`). The deployed WSL copy sets it |
| `[ssh] version` | `SSH-2.0-OpenSSH_7.4` | 17 | Changed (Cowrie's default mimics an old Debian OpenSSH) ✔ |
| `listen_endpoints` | `tcp:2222:interface=0.0.0.0` | 18 | Default port 2222. **There is no 2223** (that is the Telnet default, and Telnet is off) |
| `forwarding` | `false` | 20 | Changed (default is true) ✔ |
| `[telnet]` | **NOT FOUND** → disabled (Cowrie default) | — | [Live] only 2222 listens |
| `[output_jsonlog]` | enabled, `var/log/cowrie/cowrie.json` | 22-24 | Default |
| `[output_textlog]` | enabled, `cowrie.log` | 26-28 | Default is disabled in recent `.dist`. Duplicates the JSON log |
| `[output_pcap]` | disabled | 30-32 | — |
| `[output_sentinelblocker]` | enabled | 37-38 | Ours |
| TTY logging (`ttylog`) | **not set** → enabled by default, `var/lib/cowrie/tty/` | — | [Live] 6 recordings present |
| `[output_mongodb]`, `[output_sentinel]` | **NOT FOUND** (not enabled) | — | MongoDB is fed by the parser, not by Cowrie |
| `[backend_pool]` / `backend = proxy` | **NOT FOUND** | — | **Shell emulation only** |
| `sensor_name` | not set → the host name (`snigdha`) appears in every JSON event | — | Only in logs, not visible to attackers |

## 2.4 Customisations

| Customisation | Exists? | Evidence |
|---|---|---|
| Hostname, kernel strings, SSH banner per persona | Yes, 6 personas | `switch_profile.py:20-69` |
| Custom userdb | Yes | `userdb.txt:1-13`: root with toor/password/123456/admin/Admin123/P@ssw0rd; admin with admin/password; ubuntu, pi, user, test |
| Per-persona fs.pickle (os-release, issue, issue.net, hostname, /proc/version, motd, user rename, canary creds) | Code yes; **deployed copy is stale (NEW)** | `build_honeyfs.py:69-117`. The WSL pickles were built 2026-10-21 18:24 UTC, *before* the Phase 5 commit `a5856b7` that added motd and canaries. [Live] `/root/.aws/credentials` is **missing** in the deployed `ubuntu_22.pickle`, and the login MOTD reads "Debian GNU/Linux" |
| Custom txtcmds | **NOT FOUND** | — |
| Custom command modules (`src/cowrie/commands/*`) | **NOT FOUND** | — |
| Custom banner / MOTD | MOTD via pickle only (stale, see above); no pre-auth banner | — |
| Custom output plugin | `sentinelblocker.py` (deny-list enforcement) | Monkey-patches `CowrieSSHFactory.buildProtocol` (lines 77-85) and the Telnet factory (87-95). Returning `None` makes Twisted drop the connection. The deny-list is pulled every 2 s (`SYNC_INTERVAL`, line 22) from `GET /api/honeypot/ingest/check-block` in a daemon thread (51-75), so the reactor never blocks. [Live] Cowrie logs `Loaded output engine: sentinelblocker` |

## 2.5 Output: where things go and how SentinelAI consumes them

| Data | Location [Live] | Consumed by |
|---|---|---|
| JSON events | `var/log/cowrie/cowrie.json` (rotated daily to `cowrie.json.YYYY-MM-DD`) | `log_parser.py --live` tails it |
| Text log | `var/log/cowrie/cowrie.log` | Humans only |
| TTY recordings | `var/lib/cowrie/tty/<sha256>` | Only the **reference** (sha256, size, path) reaches MongoDB (`log_parser.py:349-354`); replay happens on the honeypot host with `playlog` |
| Downloads | `var/lib/cowrie/downloads/<sha256>` (empty: no real download ever happened) | URL and sha256 are sent; the file itself is never sent |
| Host keys | `var/lib/cowrie/ssh_host_*_key` | — |

**Consumption mechanism.** SentinelAI uses one ingest path: a **file-tailing parser** (`honeypot/parsers/log_parser.py`) that POSTs JSON to the backend with the `X-API-Key: HONEYPOT_API_KEY` header. It does not use a Cowrie output plugin, a MongoDB plugin or a message queue.

## 2.6 Event IDs

Handled by the parser (`log_parser.py:394`, the `HANDLERS` dict):

| eventid | Handler | What is sent |
|---|---|---|
| `cowrie.session.connect` | `on_connect` (262) | Nothing yet: kept in memory until the first auth/kex event |
| `cowrie.client.version` | `on_client_version` (342) | Stored and sent with the next kex |
| `cowrie.client.kex` | `on_kex` (329) | **Triggers SESSION_OPENED**, then `CLIENT_KEX` (hassh, clientVersion) |
| `cowrie.login.failed` / `.success` | (276) / (282) | Buffered; sent in the close payload |
| `cowrie.command.input` | `on_cmd` (293) | `POST /honeypot/ingest/command` with intent, IOCs and eventId |
| `cowrie.session.file_download` | `on_download` (313) | `POST /honeypot/ingest/download` (url, sha256, filename) |
| `cowrie.log.closed` | `on_log_closed` (349) | TTY reference, sent with the close |
| `cowrie.session.closed` | `on_closed` (365) | `POST /honeypot/ingest/close` (duration from `duration_ms`, credentials, hassh, ttylog) |

**Arrive but are ignored** (silently, by `process()` line 404): `cowrie.command.failed` **(NEW: the backend accepts `COMMAND_FAILED` at `honeypotIngest.js:246`, but nothing sends it, so every command is stored `success: true`, including `notarealcommand` [Live])**, `cowrie.client.size`, `cowrie.session.params`, `cowrie.session.file_upload` (SFTP/SCP uploads are lost), `cowrie.direct-tcpip.request/.data`, `cowrie.client.fingerprint` (public-key auth attempts), `cowrie.client.var`, `cowrie.login.*` beyond the above, and anything unknown.

## 2.7 Simulated / seeded "Cowrie" data

| Generator | What it makes | Labelled? |
|---|---|---|
| `log_parser.py --demo` (lines 519-533) | Fake sessions `demo-xxxxxxxx` from 4 fixed IPs, fixed commands and fixed HASSH, through the **real** ingest API | Yes: `demo-` prefix; the Q-learner skips them (`honeypotService.js:593-599`); the UI shows a badge (`HoneypotAnalytics.jsx:25,178`) |
| `backend/utils/seed.js` (`npm run seed`) | `demo-seed-*` sessions inserted straight into MongoDB | Same prefix. Refused in production without `--force` (lines 5-9) |
| `frontend/e2e/global-setup.js` | `cowrie-sess-101` etc. for Playwright tests | Test DB only, **not** prefixed `demo-` |
| `ai-engine/models/q_table.json` | Q-table **seed of 12,087 synthetic episodes** | Stamped `synthetic warm start` (`inference/deception.py:116`); `DECEPTION_COLD_START=1` starts empty |
| Not affected | The aggregates in `getFullAnalytics` (`honeypotService.js:623`) **include** demo sessions in the KPIs (minor) | — |

Nothing in the live path fabricates events: everything in Phase 4 came from Cowrie's own log.

---

# PHASE 3: How Cowrie connects to SentinelAI

## 3.1 One real session (sequence diagram)

Session `d8de51f91d42`, today. Times are from Cowrie's JSON and the parser log.

```
Attacker (paramiko)   Cowrie (WSL :2222)           log_parser.py (Windows)        Backend :5000 (Express)               AI engine :8000      MongoDB          Socket.IO → React
      │ TCP SYN ──────────►│ session.connect 06:31:20.917
      │ version/kex ──────►│ client.version, client.kex ─(tail 0.5s)─►│ on_kex: POST /ingest SESSION_OPENED ─►│ onSessionOpened (collector:24)
      │                    │                              │            │  HoneypotSession.create(servedProfile) ──────────────────►│
      │                    │                              │            │  ThreatLog 'SSH Brute Force' 0.75 (or shared per IP/60min) ─►│ emitNewThreat, honeypot_session_opened ─►
      │                    │                              │ POST /ingest CLIENT_KEX ────────────►│ onClientKex: hassh, clientVersion ────────────────────►│
      │ root/123456 ──────►│ login.success (UserDB)       │ buffered (credentials)
      │ "whoami" ─────────►│ command.input ──────────────►│ classify_intent → POST /ingest/command (eventId) ─►│ recordSessionActivity (atomic pipeline update):
      │◄── "root" (emulated)                              │            │  commands[], IOCs, MITRE, deceptionScore, engagement ───►│ honeypot_command ─►
      │ ... 8 more commands │                             │            │  canary / high-value alerts (alertOnce)
      │ exit ─────────────►│ log.closed (tty sha), session.closed duration_ms=11879
      │                    │                              │ POST /ingest/close (creds, hassh, ttylog) ─►│ closeSession (claim → analyseClosure):
      │                    │                              │            │  redact passwords ───────────────────────────────────────►│
      │                    │                              │            │  POST predictHoneypotSession ─────────►│ rules: "RCE Attempt" 0.99
      │                    │                              │            │  storePrediction, reclassify ThreatLog → CRITICAL ───────►│ threat_updated ─►
      │                    │                              │            │  auto-block? (autoBlockEnabled setting + thresholds + cap/approve)
      │                    │                              │            │  POST deception score ───────────────►│ Q-update (state=prev persona, action=served) → 50.2, next=ubuntu_22
      │                    │                              │            │  session.save, campaign clustering ──────────────────────►│ honeypot_session_closed ─►
```

Measured today: Cowrie event → parser POST took about 1 s per command (parser log 12:01:22.004 vs Cowrie 06:31:21.981 UTC). Yesterday's matched-latency table gives 144-490 ms, median 320 ms.

## 3.2 The code that reads Cowrie output

- Tailing: `log_parser.py:474-513` (`tail`). It polls every 0.5 s, reads complete lines only (`read_lines`, 421-437), saves the byte offset and inode after **every** line (`save_state`, 418), detects rotation by inode change (494-502), and handles truncation (503-505).
- Dispatch: `process()` at 396-408. JSON parse → `HANDLERS[eventid]`. Exceptions are logged by type only, so attacker data is never echoed into the logs.
- Delivery: `post()` at 194-214. Retries with backoff on connection errors, 429 and 5xx; a 4xx is final. Failed deliveries go to a durable spool (`spool.jsonl`) and are replayed in order.
- Idempotency: `event_id()` at 216-227 is sha256(session|eventid|timestamp|payload)[:32]. The backend guards with `ingestEventIds: {$ne: eventId}` (`honeypotService.js:176`).

## 3.3 Field mapping: Cowrie JSON → MongoDB `honeypotsessions`

| Cowrie field (event) | Parser payload | Mongo field (`HoneypotSession.js`) |
|---|---|---|
| `session` | `sessionId` | `sessionId` (unique) |
| `src_ip` (connect) | `sourceIP` | `sourceIP` |
| `src_port` | `sourcePort` | `sourcePort` |
| `timestamp` (connect) | `startTime` | `startTime` (rejected if more than 5 min in the future: `collector:22`) |
| constant | `honeypotNode: SSH-COWRIE-01`, `protocol: SSH` | `honeypotNode`, `protocol` |
| `version` (client.version) | `clientVersion` | `clientVersion` (≤256 chars) |
| `hassh` (client.kex) | `hassh` | `hassh` |
| `username`, `password` (login.*) | `credentials[]` | `credentials[]`: username ≤100 chars, password **always `***REDACTED***`** (`redact.js:227-233`), success |
| `input` (command.input) | `command`, `intent`, `iocs`, `eventId` | `commands[]{command, timestamp, intent, success:true, output:''}`, `commandCount`, `iocExtracted.{ips,urls,hashes}`, `filesAccessed`, `mitreTechniques`, `ingestEventIds` (hidden) |
| `url`, `shasum`, `outfile` (file_download) | `url`, `sha256`, `filename` | `iocExtracted.urls`, `iocExtracted.hashes`, `malwareDownloaded`, `downloadCount` |
| `ttylog`, `size`, `shasum` (log.closed) | `ttylog{sha256,size,path}` | `ttylog` |
| `duration_ms` (session.closed) | `durationSeconds` (int) | `durationSeconds` |
| derived by backend | — | `deceptionScore = min(100, 3·cmds + 10·sensitiveFiles + 8·urls + 15·downloads)`, `engagementLevel`, `aiClassification`, `aiThreatScore`, `aiClassificationMethod: honeypot_rules`, `qDeceptionScore`, `recommendedProfile`, `servedProfile`, `linkedThreatLog` |

## 3.4 Does SentinelAI change Cowrie at runtime?

| Lever | Changes Cowrie? | Proof |
|---|---|---|
| Deny-list (blocked IPs refused) | **Yes, automatically**, within about 2 s | `sentinelblocker.py:77-97`; check-block route `honeypotIngest.js:67-86` |
| Persona (hostname, banner, kernel, filesystem) | **Yes, but only if you run `deception_rotator.py`** (separate process, never started automatically). It rewrites `cowrie.cfg` and restarts Cowrie (`deception_rotator.py:96-115`) | Demonstrated once on 2026-10-21 (`HONEYPOT_LIVE_EVIDENCE.md`, "Closed deception loop"); today the deployed cfg is still ubuntu_22 because of that run |
| Q-learner itself | **No**: it returns a recommendation | `deception_scorer.py:426`: "nothing here reconfigures Cowrie"; `recommendationApplied: False` |
| Fake files, credentials, responses at runtime | **No**: canaries are planted at build time (static); no txtcmds or command modules are generated | — |
| userdb | **No** | — |
| Timing jitter, port selection | **NOT FOUND** | — |

**Verdict for the viva:** the scorer *adapts deception* at the persona level, and only when the optional rotator is running. Each switch means a Cowrie restart, which drops live sessions. Everything finer-grained stops at a score.

**NEW integrity bug proven today:** the backend does not learn from Cowrie which persona is being served. `servedProfile` comes from a `SystemSetting` recorded by the rotator or an admin. If that is absent it falls back to `centos_7` (`honeypotService.js:17-24`). In today's run Cowrie served **ubuntu_22** (hostname `ubuntu-prod-srv`, Ubuntu `os-release`), yet all 9 sessions were credited `servedProfile: centos_7`. Any persona change made by hand (`switch_profile.py` without the PUT) or against a fresh database therefore **trains the Q-learner on the wrong action**.

---

# PHASE 4: Is it working? (verified today)

## 4.1 What I ran (all against your own machine)

- Cowrie: WSL `~/sentinelai-cowrie-test/cowrie`, started as your user.
- AI engine: `uvicorn inference.main:app --port 8000`, with `Q_TABLE_PATH` pointed at a **scratch copy**, so your real Q-table was not touched.
- Backend: `node server.js` with `MONGO_URI=mongodb://127.0.0.1:27017/sentinel-cowrie-verify-20261022` (an **isolated DB**; `sentinel-db` was not touched).
- Parser: Windows, reading `//wsl.localhost/Ubuntu/.../cowrie.json`, with state in the scratchpad.
- The blocker's backend URL pointed at an unused port (WSL NAT cannot reach the Windows backend), so blocking was **not** retested today.

## 4.2 Commands to reproduce

```bash
# WSL: start Cowrie
cd ~/sentinelai-cowrie-test/cowrie && export PATH=~/sentinelai-cowrie-test/env/bin:$PATH
export HONEYPOT_API_KEY=<key> SENTINEL_API_URL=http://127.0.0.1:5000/api
cowrie start && cowrie status
ss -ltn | grep 2222
grep -E "Loaded output engine|Ready to accept" var/log/cowrie/cowrie.log | tail
```

Expected (seen today):

```
cowrie is running (PID: 428).
LISTEN 0 50 0.0.0.0:2222
[cowrie.core.output#info] Loaded output engine: jsonlog / textlog / sentinelblocker
[cowrie.ssh.factory.CowrieSSHFactory#info] Ready to accept SSH connections
```

```bash
# client (any terminal)
ssh -p 2222 root@127.0.0.1        # password 123456 (userdb.txt:4) -> shell
ssh -p 2222 root@127.0.0.1        # wrong password -> "Permission denied"
# Telnet: not enabled, nothing listens on 2223
tail -f var/log/cowrie/cowrie.json | jq -c '{eventid,session,input,username}'
playlog var/lib/cowrie/tty/<sha256>   # replay a session
```

## 4.3 Results, step by step

| Step | Cowrie JSON line (real, password masked) | In MongoDB? |
|---|---|---|
| Wrong password | `{"eventid":"cowrie.login.failed","username":"root","password":"<masked>","session":"615576732df9",...}` | ✔ session `615576732df9`, credentials `[{root, ***REDACTED***, false}]`, class **SSH Brute Force 0.90** |
| Burst of 5 failed logins (admin/guess0-4) | 5 × `cowrie.login.failed`, one per connection | ✔ 5 sessions, all `SSH Brute Force 0.90`, all sharing **one** ThreatLog (per-IP window, `collector:13`) |
| Valid login root/123456 | `cowrie.login.success` | ✔ `success: true`, `***REDACTED***` |
| `whoami` | `{"input":"whoami","eventid":"cowrie.command.input",...}` → output `root` | ✔ intent RECONNAISSANCE, MITRE T1033 |
| `uname -a` | → `Linux ubuntu-prod-srv 5.15.0-91-generic #101-Ubuntu ...` | ✔ T1082 |
| `ls /` | → standard root directories | ✔ (intent UNKNOWN) |
| `cat /etc/passwd` | → Cowrie's passwd | ✔ CREDENTIAL_HARVEST, `filesAccessed: ["/etc/passwd"]`, T1003 / T1003.008 |
| `ps` | → **only `-bash` and `ps`** | ✔ T1057 |
| `wget http://127.0.0.1:8081/test.sh` | `command.input` only. Cowrie printed *"unable to resolve host address '127.0.0.1'"* and **no** `file_download` event | ✔ MALWARE_DOWNLOAD intent, URL in IOCs, T1105, alert **"High-Value: MALWARE_DOWNLOAD" (CRITICAL)**, although nothing was downloaded |
| `notarealcommand` | `command.input` **and** `{"eventid":"cowrie.command.failed","input":"notarealcommand ",...}` | ⚠ stored as `success: true` (command.failed ignored) |
| `exit` | `cowrie.log.closed` (ttylog sha `85f0b33a…`, 2280 bytes), `cowrie.session.closed` `duration_ms: 11879` | ✔ `durationSeconds: 11`, `ttylog` stored, status `closed`, closure `complete` |
| Whole session | — | `RCE Attempt 0.99` (because `wget` ∈ `RCE_TOOLS`, `features.py:352`), `deceptionScore 45`, engagement `medium`, `qDeceptionScore 50.2`, `recommendedProfile ubuntu_22`, `servedProfile centos_7` ✘ (should be ubuntu_22) |
| ThreatLog | — | 1 doc, `RCE Attempt`, CRITICAL, 0.99, `MONITORING` (auto-block setting off, so no block) |
| AI predictions | — | 7 docs (one per closed session), `modelType: rules` |
| `playlog` | — | ✔ replays the MOTD, prompt and all commands with their output |

Event counts in today's JSON: connect 7, version 7, kex 7, login.failed 6, login.success 1, command.input 9, command.failed 1, log.closed 1, session.closed 7. Every session reached MongoDB exactly once.

**Dashboard.** Not opened in a browser today. Code path: `socketManager.emitHoneypotEvent` sends `honeypot_session_opened` / `honeypot_command` / `honeypot_session_closed` / `malware_download` to the admin and analyst rooms, and a redacted copy to viewers (`socketManager.js:319-324`). `HoneypotAnalytics.jsx:82-84` reloads on those events; `useRealTimeFeed.js:43-48` shows them in the live feed. Earlier captured WebSocket frames in `scratch/evidence/` do not contain honeypot events, so **dashboard rendering of Cowrie events is Untested** in captured evidence.

## 4.4 Robustness (all tested today unless marked)

| Scenario | Result | Lost? | Duplicated? |
|---|---|---|---|
| Malformed JSON line appended to `cowrie.json` | Parser logged `Error processing log event (JSONDecodeError)`, advanced past it, continued | No | No |
| Unknown eventid (`cowrie.totally.unknown`) | Silently ignored | — | — |
| Cowrie restart (`cowrie restart`) | Next session `61cc6bce6759` ingested normally (same file, appended) | No | No |
| Backend down during a session | 6 deliveries spooled to disk (`spool_depth 6`); after restart "Delivered 6 queued events"; session `a3949279ed14` present once with 3 commands | No | No |
| Parser down mid-session | Tested 2026-10-21 (session `ca364abd2bae` ingested after restart) | No | No |
| Log rotation | Tested 2026-10-21 (Linux rename semantics) | No | No |
| Rotated file deleted while the parser is stopped | Code: warns "its unread lines are lost" (`log_parser.py:470-471`) | **Yes** (by design) | — |
| Spool over 50,000 | Oldest dropped (`log_parser.py:152-156`) | Yes (bounded) | — |
| `lag_seconds` metric | Trusts event timestamps: my injected future-dated line made it −382 s | — | — |

## 4.5 Verdict table

| Component | Status | Evidence | File |
|---|---|---|---|
| Cowrie install (git c7773f4, venv, non-root) | **Working** | [Live] `cowrie status`, port 2222 | WSL `~/sentinelai-cowrie-test` |
| SSH listener / banner / hostname / kernel persona | **Working** | [Live] `uname -a`, prompt | `cowrie.cfg:3,11-18` |
| Telnet | **Not Implemented** (disabled) | No `[telnet]` | — |
| UserDB auth | **Working** | [Live] 123456 accepted, 6 wrong rejected | `userdb.txt` |
| `forwarding = false` | **Working** | 2026-10-21 run | `cowrie.cfg:20` |
| Persona fs.pickle (os-release, user) | **Working** | [Live] Ubuntu `os-release` | `build_honeyfs.py` |
| Canary files and per-distro MOTD on the deployed honeypot | **Broken (stale deployment)** | [Live] canary missing, Debian MOTD | WSL `personas/*.pickle` |
| JSON logging, TTY logging, playlog | **Working** | [Live] | Cowrie |
| Blocker plugin loads | **Working** | [Live] "Loaded output engine: sentinelblocker" | `sentinelblocker.py` |
| Blocker enforcing against the real backend | **Partially** (tested against a stub on 10-21; the WSL→Windows hop was never run) | Evidence doc | — |
| Parser tail / dispatch / idempotency | **Working** | [Live] 9 sessions once each | `log_parser.py` |
| Parser restart, rotation, backend outage, malformed lines | **Working** | [Live] and 10-21 | `log_parser.py` |
| `cowrie.command.failed` handling | **Broken** (ignored; success always true) | [Live] | `log_parser.py:394` |
| File downloads end to end | **Untested** (Cowrie refuses local targets; no internet) | [Live] | `log_parser.py:313` |
| SFTP/SCP uploads | **Not Implemented** | not in HANDLERS | — |
| Backend ingest auth (honeypot key, 401) | **Working** | [Live] 401 on a wrong key | `honeypotIngest.js:38-44` |
| Credential redaction | **Working** | [Live] `***REDACTED***` | `redact.js:227` |
| Rule classification | **Working** (but coarse, see Phase 5) | [Live] | `features.py:383` |
| MITRE mapping | **Working** | [Live] 7 techniques | `mitreMapping.js:119` |
| Q-learner scoring | **Working** | [Live] 50.2, next ubuntu_22 | `deception_scorer.py` |
| `servedProfile` correctness | **Broken** when the setting is not recorded | [Live] centos_7 vs real ubuntu_22 | `honeypotService.js:17-24` |
| Rotator (closed loop) | **Partially**: works, opt-in, demonstrated once | 10-21 evidence | `deception_rotator.py` |
| Socket.IO → dashboard | **Untested** today (code present) | — | `socketManager.js:319` |
| Docker honeypot stack, egress rules, port-22 redirect | **Untested** | No Docker | `docker-compose.honeypot.yml` |
| Demo/seed sessions | **Mocked** (labelled `demo-`) | — | `log_parser.py:519`, `seed.js:134` |
| GeoIP for honeypot sessions | **Not Implemented** (`geoLocation` is never filled by the parser) | — | collector:24 |

---

# PHASE 5: Issues audit

### Status of every Phase 5 issue (working tree, 2026-10-22)

"Live" means re-tested today against the WSL Cowrie: an isolated instance on 127.0.0.1:2299 with its own log, using the deployed config, personas and userdb, feeding the test backend and database. Test counts: full backend suite 1126 passed (13 skipped, as before); full AI-engine suite 565 passed.

| # | Issue | Status | Evidence / what changed |
|---|---|---|---|
| C1 | Wrong persona credited | **Fixed** | Parser reads the persona from `cowrie.cfg`. Live: credited `ubuntu_22` |
| H1 | Stale persona pickles | **Fixed** | Rebuilt twice; live: Ubuntu MOTD, canary alert |
| H2 | wget "unable to resolve" for a bare IP | **Not fixed** | Cowrie's own anti-SSRF guard, which applies only to private/loopback targets (`wget.py:274-281`). Public URLs are fetched normally. Fixing it needs a custom `wget` module |
| H2 | `ps` shows only 2 processes | **Withdrawn (my finding was wrong)** | Real `ps` with no options lists only the processes on your terminal (the shell and `ps`). Not a tell |
| H2 | Debian MOTD on other personas | **Fixed** | See H1 |
| H2 | `[4l`/`[4h` escape codes | **Not fixed** | Comes from Cowrie's terminal code; no config option exists |
| H2 | Textbook userdb | **Fixed** | `userdb.txt` is root-only. Removed: toor, password, `admin` with uid 0, and per-distro users that could log in on the wrong persona. Live: `pi/raspberry` refused |
| H2 | Docker used the stock fs.pickle | **Fixed (untested)** | Compose mounts `./personas`; the repo `cowrie.cfg` points at them. No Docker here to run it |
| H2 | `windows_srv` persona | **Fixed** | `switch_profile.py` refuses it (exit 2) without `--allow-unservable`; the rotator skips it |
| H2 | SSH algorithm list / server HASSH | **Not fixable** in shell mode | Inherent to Twisted Conch; proxy mode is the only answer |
| H2 | No `lsb_release`, uniform timing | **Partially** | `lsb_release` added for Ubuntu/Debian/Raspbian via per-persona txtcmds. Live: `lsb_release -a` prints Ubuntu 22.04.3 LTS. CentOS and Amazon Linux rightly lack it. No timing jitter |
| H2 | Host private keys 0644 | **Fixed (WSL install)** | `chmod 600` applied |
| H3 | Isolation | **Partially** | Image pinned to `cowrie/cowrie:sha-c7773f4@sha256:69e3…515c`. `COWRIE_LISTEN_ADDR`: the deployed WSL config now listens on 127.0.0.1. Hardened systemd unit `honeypot/cowrie.service` (its `twistd -n` command verified live). **Still open:** the Docker stack and egress rules have never run (no Docker/root), and the WSL install has full outbound internet |
| H4 | One failed login = brute force | **Fixed** | Brute force needs ≥5 failures from the source within the threat window; fewer is "SSH Intrusion Attempt" 0.75. Live: 4 × Intrusion Attempt, then Brute Force from the 5th |
| H5 | Paper overclaims | **Not fixed here** | The paper's source is not in this repo; corrected wording is below |
| M1 | `command.failed` ignored | **Fixed** | Live: `notarealcommand` stored `success: false`, command count unchanged |
| M2 | CRITICAL alert for a download attempt | **Fixed** | Intent alerts are HIGH; CRITICAL only for a real `file_download`. Live: HIGH |
| M3 | Uploads and port-forwards dropped | **Uploads fixed; port-forwards partially** | Live: SFTP upload stored with sha256, CRITICAL alert. The port-forward handler is built and tested offline, but Cowrie does not log the request at all when `forwarding = false` (verified live), so with our config it never fires |
| M4 | Plaintext passwords at rest | **Partially** | Parser state, spool and the alternative plugin no longer keep passwords (live: none in `state.json`). Cowrie's own `cowrie.json` still has them (Cowrie cannot mask): `var/` set to 700 on WSL, and `retention.sh` prunes it |
| M5 | Disk growth | **Fixed (needs scheduling)** | `honeypot/retention.sh` (logs 30 d, TTY 90 d, downloads 30 d; tested on aged files); `output_textlog` off. Not added to cron: that is your call |
| M6 | Coarse classifier | **Fixed** | Logged in with no commands → "SSH Intrusion Attempt" (not Port Scan). A download that is never run stays below the block line. Live: `wget` alone → RCE Attempt 0.91 |
| M7 | Persona switch drops live sessions | **Fixed** | The recommendation now includes `activeSessions`; the rotator waits while it is > 0 (`--force` overrides) |
| M8 | Demo sessions in KPIs | **Fixed** | Every analytics query excludes `demo-*` (test) |
| L1 | Host name as sensor | **Fixed** | Live: `"sensor": "sentinel-hp-01"` |
| L2 | Lag trusts future timestamps | **Fixed** | Timestamps more than 5 min ahead are ignored (test) |
| L3 | Stale `twistd.pid` | **Fixed (template)** | `honeypot/cowrie.service`. Not installed (needs sudo/systemd) |
| L4 | `sentinel_output.py` | **No change needed** | Still disabled; it now also drops passwords |
| L5 | Hard-coded node port | **Fixed** | `HONEYPOT_SSH_PORT` (test) |
| L6 | Timezones | **No change needed** | — |

Two things changed under the Cowrie instance that was running in WSL during this work (PID 1193, started with `cowrie start` at 07:38 UTC, not by me): its `userdb.txt` and persona files were replaced, and its `cowrie.cfg` was regenerated. It reads the new config only when restarted. Backups: `etc/userdb.txt.bak-20261022`, `etc/cowrie.cfg.bak-20261022`, `personas.bak-20261022/`.

**H5: corrected wording for the paper**
- Containers: "The frontend, backend and AI engine run under Docker Compose. A hardened Compose file for the honeypot is provided but has not yet been deployed; the evaluated honeypot ran natively under WSL."
- Profile: "Cowrie serves one of five Linux personas (the shipped default is CentOS 7)."
- Adaptation: "An optional rotator applies the Q-learner's recommended persona by rewriting Cowrie's configuration and restarting it when no attacker session is open; this was demonstrated once and is not enabled by default."
- Downloads: "The parser ingests Cowrie download and upload events; uploads were verified, while real downloads were not exercised because the honeypot has no outbound access by design."
- Tests: "Automated tests cover the parser, ingestion, collector, rules and Q-learner."

### Status after the C1 / H1 fixes (working tree, 2026-10-22, live-verified)

- **C1 FIXED.**
  - The parser reads the persona from the header `switch_profile.py` writes on line 1 of `cowrie.cfg`. It finds `<cowrie>/etc/cowrie.cfg` next to the log by default, or uses `COWRIE_CFG`; `COWRIE_PERSONA` overrides both.
  - It captures the persona at `cowrie.session.connect` and sends it as `servedProfile` with SESSION_OPENED (`log_parser.py`: `served_persona`, `on_connect`, `ensure_session_opened`).
  - A config rewritten *after* the session started is not trusted, and an unknown persona is omitted.
  - The backend accepts only the six personas (`honeypotIngest.js`, shared list `backend/utils/deceptionProfiles.js`). The collector credits the reported persona over the recorded setting and logs a warning on a mismatch (`session_collector.js`: `servedProfileFor`).
  - The Docker parser mounts `cowrie.cfg` read-only.
  - Tests: `ai-engine/tests/test_cowrie_persona.py` (22, including a contract test over all six `switch_profile` outputs), `honeypotAuditFixes.test.js` (2), `honeypotIngestContract.test.js` (1). Results: honeypot backend suites 461/461, Cowrie Python suites 66/66.
  - Live check: same conditions as the morning failure (no recorded setting, Cowrie serving ubuntu_22). Session `01287b9f85fe` was credited **`servedProfile: ubuntu_22`**, and the backend warned "Cowrie serves ubuntu_22 but the recorded active profile is centos_7".
- **H1 FIXED.**
  - Rebuilt the five persona pickles in WSL from the current `build_honeyfs.py`. The old ones are in `personas.bak-20261022/`. `personas/BUILD_INFO` and `BUILD_SHA256SUMS` record the build.
  - Live check: the login MOTD now reads "Welcome to Ubuntu 22.04.3 LTS", and `/root/.aws/credentials` exists. Reading it raised a **CRITICAL "Canary file read"** alert.
- The verdict-table rows "Canary files and per-distro MOTD" and "`servedProfile` correctness" below are now **Working**. Their original wording is kept as the record of what was found.

## Critical

**C1. Persona attribution can be wrong, so the Q-learner learns from mislabelled data (NEW).**
- Where: `honeypotService.js:17-24`, `session_collector.js:20,24`.
- Why it matters: the "self-evolving" claim rests on reward → correct action. Today 9/9 sessions were credited to the wrong persona.
- Fix: make Cowrie's own state the source of truth. Give the parser the persona (it runs next to `cowrie.cfg`) and send it with SESSION_OPENED:
  ```python
  # log_parser.py
  PERSONA = os.getenv("COWRIE_PERSONA") or _persona_from_cfg(os.getenv("COWRIE_CFG", "/opt/cowrie/etc/cowrie.cfg"))
  def _persona_from_cfg(path):
      import configparser
      first = Path(path).read_text().splitlines()[0]  # "# Generated by honeypot/switch_profile.py (ubuntu_22)."
      m = re.search(r"\((\w+)\)", first); return m.group(1) if m else None
  # in ensure_session_opened payload:  "servedProfile": PERSONA,
  ```
  Then the collector uses `data.servedProfile` when it is one of `DECEPTION_PROFILES`, and the SystemSetting only as a fallback. Also make `switch_profile.py` print a loud warning when the PUT was not made.

## High

**H1. The deployed honeypot is out of sync with the repo: stale persona pickles (NEW).**
- Where: WSL `personas/*.pickle` (built 2026-10-21 18:24 UTC) vs `build_honeyfs.py` at `a5856b7`.
- Why: canary alerts cannot fire on the live honeypot, and the login MOTD says Debian on an Ubuntu/CentOS persona (an instant inconsistency).
- Fix: rebuild with `python build_honeyfs.py --fs-pickle src/cowrie/data/fs.pickle --out personas`, restart, and add a build hash, e.g. write `/etc/.build` or log the pickle sha at startup, so drift is detectable.

**H2. Fingerprints an attacker can use to spot Cowrie** [Live where marked]:

| Tell | Where | Fix |
|---|---|---|
| `wget http://<IP>` → "unable to resolve host address '<IP>'" (real wget never resolves an IP literal) [Live] | Cowrie's wget plus local-target refusal | Allow downloads to the sinkhole only, or add a custom `wget` module that prints a realistic "Connection refused" |
| `ps` shows only `-bash` and `ps` [Live] | Cowrie default | `txtcmds` or a custom `ps` with sshd, cron, systemd, nginx and similar |
| Stock Debian MOTD on non-Debian personas [Live] | stale pickle (H1) | Rebuild |
| `[4l` / `[4h` insert-mode escape codes around output [Live] | Cowrie terminal handling | Known Cowrie tell; cannot be fixed by config. Admit it |
| Accepting `root/123456`, `root/password`, `admin/admin` (Cowrie-style weak creds); every attempt rejected the same way | `userdb.txt` | Accept a few, add `!` refusals, and consider `AuthRandom` |
| Stock `fs.pickle` in the Docker stack (persona mount commented out): user `phil`, empty `os-release` while the hostname says CentOS | `docker-compose.honeypot.yml:53-55` | Uncomment the persona volume and set `[shell] filesystem` |
| `windows_srv` persona: Windows banner over a Linux shell | `switch_profile.py:45-52` | Already excluded from recommendations (`deception_scorer.py:87`); remove it from `switch_profile` too, or refuse it there |
| SSH algorithm list and HASSH-server of Twisted Conch differ from OpenSSH 7.4/8.9 | Cowrie | Known and unfixable in shell mode; proxy mode is the real answer |
| Uniform, instant command latency; no `lsb_release`, `apt`, `systemctl` realism | Cowrie | `txtcmds`, small random delays (custom module) |
| Host private keys mode 0644 [Live] | `var/lib/cowrie/ssh_host_*_key` | `chmod 600` (local only, not visible to attackers) |

**H3. Docker isolation is designed but unproven; the WSL deployment has no isolation.**
- Where: `docker-compose.honeypot.yml:29-61`, `egress-rules.sh`.
- The design is good: read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, mem 512m, cpus 0.5, pids 256, noexec tmpfs for downloads, bind 127.0.0.1 by default, a bridge with egress limited to the backend.
- Problems: never run; image `cowrie/cowrie:latest` unpinned (line 29); in-container paths are unverified (lines 3-4). The WSL install that actually runs has **full outbound internet**, shares the kernel with your laptop and listens on `0.0.0.0:2222`. That is acceptable for localhost tests only.
- Fix: before any exposure, run the compose stack on a Linux VM/VPS, pin a digest, apply `egress-rules.sh`, then verify with `docker exec … python -c "import socket;socket.create_connection(('1.1.1.1',80),3)"` (it must fail).

**H4. A single failed login is classified "SSH Brute Force" at 0.90 = the ALERT threshold** (`features.py:394-395`, `predictor.py:91`, `predictor.py:28`). [Live] 6 single-attempt sessions all scored 0.90, so every internet scanner becomes a monitored threat.
- Fix: require N failures (e.g. ≥5 across the IP's window, or `credentialCount ≥ 3`) for brute force, and score single failures as Port Scan / low.

**H5. Paper vs code gaps (overclaims).**

| Paper says | Reality |
|---|---|
| "All four services (… honeypot) are containerised and orchestrated via Docker Compose" (paper ~l.1068, l.1078) | Main `docker-compose.yml:7` explicitly excludes the honeypot. The honeypot compose is **untested** |
| "The Cowrie configuration supplied … is a fixed Ubuntu-oriented profile" (~l.1121) | Repo cfg is **CentOS 7**; there are 6 personas |
| "no runtime mechanism changes the active Cowrie configuration" (~l.1122, l.1033) | **Understates**: the optional rotator does it (demonstrated once). Reword, don't hide it |
| "parser captures … file downloads" (~l.1116) | Code exists; **never exercised** with a real download |
| Proposed: timing jitter, port selection, artifact planting, pool of nodes (~l.599-618) | Only static canary planting exists; one node. Keep it as "proposed" |
| "No equivalent automated test suite … for honeypot" (~l.1150) | Outdated: there are about 20 honeypot test files (`ai-engine/tests/test_cowrie_*`, `backend/tests/honeypot*`) |
| "Increase engagement ≥40%" (objective, ~l.426) | No experiment measured it. Must stay an objective |

## Medium

- **M1. `cowrie.command.failed` ignored** → `success` is always true and unknown-command analytics are impossible. Fix: add `"cowrie.command.failed": on_cmd_failed` posting `eventType: COMMAND_FAILED`, already accepted at `honeypotIngest.js:246`. Then make the collector set `success:false` (currently hard-coded true at `collector:27`).
- **M2. "High-Value: MALWARE_DOWNLOAD" alert from intent alone** (`collector:27`). [Live] it fired for a wget that failed. Fix: alert CRITICAL only on `cowrie.session.file_download`; keep the intent as HIGH.
- **M3. Uploads and port-forward attempts dropped** (`cowrie.session.file_upload`, `cowrie.direct-tcpip.*`). Add handlers; they are strong signals.
- **M4. Plain-text passwords at rest on the honeypot host**: `cowrie.json` (both `password` and `message` fields), `cowrie.log`, and the parser `state.json`/`spool.jsonl` (`log_parser.py:46-49`; `chmod 600` is a no-op on Windows, `log_parser.py:144`). Fix: restrict the directories, set retention on Cowrie logs, and hash passwords in parser state.
- **M5. Disk growth**: Cowrie rotates daily but never deletes. TTY logs and downloads are unbounded on the WSL install (the Docker tmpfs caps downloads at 256 MB). Fix: a `logrotate`/cron job such as `find var/log/cowrie -name 'cowrie.json.*' -mtime +30 -delete`, the same for `tty/`. Disable `output_textlog` (it duplicates the JSON).
- **M6. Rule classifier is coarse.** `wget` alone ⇒ "RCE Attempt 0.93+", which is ≥ BLOCK 0.92 (`predictor.py:22`). With `autoBlockEnabled` on, any logged-in `wget` auto-blocks (subject to the cap and approve mode). Also, a logged-in session with zero commands is labelled "Port Scan" (`features.py:396-397`), which is semantically wrong.
- **M7. Persona switch requires a Cowrie restart**, which drops active attacker sessions; the rotator default interval is 60 min (`deception_rotator.py:125`). Document it, and rotate only when `activeSessions == 0`.
- **M8. KPIs include demo sessions** (`honeypotService.js:623-705`). Add `sessionId: {$not: /^demo-/}` to the `$match`.

## Low

- **L1.** `sensor` = host name (`snigdha`) in every event: set `[honeypot] sensor_name = sentinel-hp-01`.
- **L2.** Parser `lag_seconds` trusts attacker-reachable timestamps. Clamp to now.
- **L3.** `twistd.pid` left stale after an unclean stop (seen today). Use a supervisor (systemd user unit) instead.
- **L4.** `sentinel_output.py` (if ever enabled) keeps sessions in memory with no spool. Keep it disabled.
- **L5.** `getNodeStatus` hard-codes port 2222 (`honeypotService.js:761`).
- **L6.** Timezones: Cowrie writes UTC `Z`; the parser converts correctly (`log_parser.py:60-64`); the backend clamps future times (`collector:22`). This is fine; just state "all times UTC" in the viva.

## Ingestion / XSS security (checked, OK)

- Every attacker string goes through validation: sessionId ≤128, command ≤2048, URL ≤2048, eventId hex-only, clientVersion ≤256 (`honeypotIngest.js:183-215`). The update pipeline uses `$literal`, so `$`-prefixed attacker strings cannot be evaluated as MongoDB expressions (`honeypotService.js:157-159`). Passwords are redacted before storage.
- Frontend: **no `dangerouslySetInnerHTML` / `innerHTML` anywhere in `frontend/src`** (grep), so React escapes commands and usernames as text. Viewers get redacted commands and IPs (`redact.js:90-149`).
- Ingest requires `HONEYPOT_API_KEY`; the AI engine's key is refused; optional source binding via `HONEYPOT_ALLOWED_SOURCES`. **Set it** when the honeypot is remote.

---

# PHASE 6: Improvements

| # | Item | Effort | Impact | Files |
|---|---|---|---|---|
| **Quick wins (< 1 h)** |
| Q1 | Rebuild and redeploy persona pickles (fixes canaries and MOTD) | 10 min | High | WSL `personas/` |
| Q2 | `sensor_name`, disable `output_textlog`, `chmod 600` host keys | 10 min | Low | `switch_profile.py` template |
| Q3 | userdb realism: drop the most Cowrie-typical pairs, add `!` refusals | 15 min | Medium | `userdb.txt` |
| Q4 | Retention cron for `cowrie.json.*`, `tty/`, `downloads/` | 20 min | Medium | new `honeypot/retention.sh` |
| Q5 | Handle `cowrie.command.failed` → `success:false` | 30 min | Medium | `log_parser.py`, `session_collector.js` |
| Q6 | Exclude `demo-` from KPIs | 10 min | Low | `honeypotService.js` |
| **Must-fix before demo/viva** |
| M1 | Persona sent by the parser (C1 fix) | 1-2 h | **Critical** | `log_parser.py`, `session_collector.js`, tests |
| M2 | Brute-force threshold (H4) and download-only CRITICAL alert (M2) | 1 h | High | `features.py`, `session_collector.js` |
| M3 | Honest labelling: badge `demo-*` (done), state "rules not ML" (done in `HoneypotAnalytics.jsx:20-23`), and **fix the paper rows in H5** | 1 h | High | `paper_text` / report |
| M4 | Isolation: for the demo, keep Cowrie bound to localhost/LAN; never expose the WSL install publicly. For public exposure, use the Docker stack on a Linux VM with egress rules | 2-4 h (needs Docker) | High | compose, `egress-rules.sh` |
| M5 | Run the blocker against the real backend (mirrored WSL networking) | 30 min | Medium | `.wslconfig` |
| **Upgrades** |
| U1 | MITRE ATT&CK mapping | **Done** | — | `mitreMapping.js` |
| U2 | Credential/command analytics and attacker profiles by HASSH | **Done** (`GET /api/honeypot/attackers`) | — | `honeypotService.js:722` |
| U3 | Session replay in the dashboard: ship the TTY file (it is small) or convert it to asciinema JSON and render it with `asciinema-player` | 1 day | High (viva wow) | parser, new route, frontend |
| U4 | GeoIP for honeypot sessions (MaxMind GeoLite2 lookup in the collector; the schema already has `geoLocation`) | 3 h | Medium | `session_collector.js` |
| U5 | AbuseIPDB | **Done** (background, needs key) | — | `threatIntelService` |
| U6 | VirusTotal hash lookup on `file_download` sha256 (only after real downloads work through a sinkhole) | 3 h | Medium | collector, new service |
| U7 | Dynamic deception beyond personas: per-session canary filenames, rotating fake credentials in `/root/.bash_history`; Q-actions extended to "plant artifact X" | 1-2 weeks | High (research) | `build_honeyfs.py`, scorer |
| U8 | Proxy mode to a disposable VM (Cowrie `backend_pool`) for high interaction | 1 week + infrastructure | High | new cfg, VM images |
| U9 | Export closed sessions as a labelled dataset (rule class as weak label) for supervised retraining | 2-3 days | Medium | new export script |
| **Production-readiness** |
| P1 | Pin `cowrie/cowrie@sha256:…` | 15 min | High | compose:29 |
| P2 | Health checks: compose `healthcheck` (`nc -z localhost 2222`); heartbeat already exists (`honeypotHeartbeat.js`, metric `sentinel_honeypot_heartbeat_age_seconds`) | 30 min | Medium | compose |
| P3 | Monitoring: parser Prometheus metrics exist (`--metrics-port`); add alerts on spool depth > 0 for 5 min | 1 h | Medium | ops |
| P4 | Parser unit tests with real Cowrie JSON: **exist** (`ai-engine/tests/test_cowrie_parser*.py`, 6 files). Add today's 9-event session as a golden fixture | 30 min | Medium | tests |

---

# PHASE 7: Viva prep

## 7.1 Fifteen likely questions

1. **Why Cowrie?** It is the de-facto open-source SSH honeypot, it writes structured JSON for every event, it is medium-interaction (safe), it is maintained, and it is cited in the literature. Writing my own SSH emulator would be weaker and riskier.

2. **What does "medium interaction" mean?** The attacker gets a convincing shell, but every command is answered by Python code reading a fake filesystem. Nothing the attacker types executes on a real OS. Low interaction gives only a banner; high interaction gives a real VM.

3. **How does Cowrie fake a shell?** Twisted's SSH server hands the session to `HoneyPotShell`, which parses the line and dispatches each program to a Python command class (`ls`, `cat`, `uname`…). Those classes read a pickled filesystem tree and config strings (hostname, kernel). Unknown programs return "command not found". Changes the attacker makes exist only in memory.

4. **What exactly do you collect?** Source IP and port, SSH client version and HASSH, every username/password attempt (passwords redacted before MongoDB), every command, download URLs and hashes, session duration, and a TTY recording reference I can replay with `playlog`.

5. **How does Cowrie data reach your system?** A parser tails `cowrie.json`, keeps its byte offset and inode on disk, and POSTs each event to the backend with a dedicated honeypot API key. Each event has a deterministic id, so replays never duplicate. If the backend is down, events go to an on-disk spool. I tested restart, rotation, malformed lines and a backend outage: nothing was lost or duplicated.

6. **How do attackers detect honeypots?** SSH banner/algorithm mismatches, default hostname `svr04`, the default user `phil`, empty `os-release`, a too-short process list, weird `wget` errors, terminal escape quirks, uniform timing, and accepting trivial passwords. My counters: six consistent personas (banner, kernel, hostname, os-release, users) and fingerprint-command detection that *penalises* the persona in the reward. I can also name what I cannot hide: `ps`, the `[4l` escapes and Twisted's SSH algorithm list. The honest fix for those is proxy mode.

7. **Does your AI really adapt the honeypot?** A tabular Q-learner scores each closed session (duration, commands, intents, login, IOCs, minus a penalty for fingerprinting commands) and recommends the next persona. An optional rotator applies it by rewriting the Cowrie config and restarting Cowrie; I demonstrated that loop once. It is opt-in, it changes only the persona, and the seed table is synthetic. I also found that persona attribution must come from the honeypot itself; that is my fix list item #1.

8. **Why Q-learning and not PPO as in your design?** The realised action space is 5 servable personas and the state is the previous persona, so the problem is close to a bandit. Tabular Q-learning (with a UCB1 option) is appropriate. PPO pays off only with a richer action space (jitter, artifacts), which is future work.

9. **Is the session classification machine learning?** No, and I say so in the UI. Cowrie gives no packet flows, so the CICIDS-trained model doesn't apply. Sessions are classified by transparent rules (login outcome, programs run, IOC count) and mapped to MITRE ATT&CK.

10. **How is the honeypot contained?** The live test runs as an unprivileged user, on localhost, with SSH forwarding disabled and a 10 MB download cap. The production design is a Docker container with a read-only rootfs, all capabilities dropped, no-new-privileges, CPU/memory/PID limits, a noexec tmpfs for downloads, and iptables egress limited to the ingest port. That stack is written but not yet run, because I had no Docker host. So I demonstrate on localhost only.

11. **What if an attacker attacks SentinelAI through the honeypot data?** Input is validated and length-capped, Mongo updates use `$literal`, the honeypot key is scoped to ingest routes only and can be source-bound, React escapes all text, and nothing uses `dangerouslySetInnerHTML`.

12. **What happens to malware downloads?** Cowrie stores them by SHA-256 under a 10 MB cap; Docker adds a noexec 256 MB tmpfs. SentinelAI receives only URL and hash. I did not test real downloads, because that needs outbound internet, which I deliberately do not allow.

13. **Can the honeypot block attackers?** Yes. A custom Cowrie plugin pulls SentinelAI's deny-list every 2 seconds in a background thread and refuses new connections from listed IPs. Honeypot-originated auto-blocks are capped per hour and can require analyst approval.

14. **Ethics and law?** A honeypot on my own infrastructure is passive; I don't attack back. Captured credentials are redacted before storage. Raw logs stay on the honeypot host with restricted access and retention. The honeypot is prevented from being used to attack third parties (no forwarding; egress rules). Collected data is personal data under GDPR / India's DPDP Act and needs a stated purpose and retention. Entrapment does not apply: I don't induce the crime.

15. **What is simulated in your demo?** `demo-` sessions from the parser's demo mode or the seed script, which are badged and excluded from learning, and the Q-table's synthetic warm start (12,087 episodes, labelled). Everything in my live evidence came from real Cowrie sessions against my own machine.

## 7.2 Two-minute explanation (memorise)

> "SentinelAI uses Cowrie, a medium-interaction SSH honeypot built on Python Twisted. When an attacker connects on port 2222, Cowrie presents a believable server, a CentOS or Ubuntu persona with a matching banner, kernel and filesystem, and accepts weak passwords from a user database. After login the attacker gets an emulated shell: commands like `uname` or `cat /etc/passwd` are answered by Python code from a fake filesystem, so nothing really executes.
>
> Cowrie writes every step as a JSON event: connect, client fingerprint, each login attempt, each command, downloads and the session close, plus a TTY recording. My parser tails that log, remembers its position on disk, gives every event a deterministic id and posts it to the Node backend with a dedicated API key. If the backend is down it queues events on disk, so nothing is lost or duplicated. I tested restarts, rotation and outages.
>
> The backend stores the session in MongoDB with redacted passwords, extracts IOCs, maps commands to MITRE ATT&CK, and pushes live updates to the dashboard over Socket.IO. When the session closes, the AI engine classifies it with transparent rules and a Q-learning agent scores how engaging the persona was, penalising fingerprinting commands, and recommends the next persona. An optional rotator can apply that recommendation to Cowrie, which I demonstrated once. A custom Cowrie plugin enforces SentinelAI's deny-list inside the honeypot.
>
> What it doesn't do yet: real malware downloads, high-interaction proxy mode, and a tested Docker isolation stack. Those are my next steps."

## 7.3 Wording: implemented vs simulated vs future

| Say | Don't say |
|---|---|
| "Implemented and live-tested: Cowrie SSH honeypot, persona configs, JSON ingestion with exactly-once delivery, redaction, rule classification, MITRE mapping, Q-learning recommendation, deny-list plugin." | "Fully autonomous adaptive honeypot." |
| "Implemented, demonstrated once, opt-in: the rotator that applies the recommended persona." | "The AI reconfigures the honeypot in real time." |
| "Rule-based session classification." | "ML classifies honeypot sessions." |
| "The Q-table starts from a labelled synthetic warm start and is updated by real sessions." | "Trained on real attacker data." |
| "Docker isolation designed and written, not yet executed." | "Containerised and isolated." |
| "Download capture supported by Cowrie; not exercised (no outbound access by design)." | "We capture and analyse malware." |
| "Future work: proxy/high interaction, dynamic artifacts, timing jitter, PPO, GeoIP, VirusTotal, retraining dataset, measuring the ≥40% engagement objective." | Any of these in the present tense. |

---

## Appendix: today's live artifacts

- Isolated database `sentinel-cowrie-verify-20261022` (9 sessions, 1 threat, 1 alert, 7 predictions). Drop it when done: `mongosh --eval 'db.getSiblingDB("sentinel-cowrie-verify-20261022").dropDatabase()'`.
- WSL `cowrie.json` now contains two lines I injected for the robustness test (one malformed, one `cowrie.totally.unknown`) and the test sessions of 2026-10-22 06:31-06:34 UTC.
- Cowrie, parser, backend and AI engine were stopped afterwards (port 2222 closed). Your runtime Q-table was not touched (a scratch copy was used).
