# SentinelAI Honeypot: Study Guide, Verification and Audit

Audited on 2026-10-21 against branch `db-fixes` (commit `f991412`). Every claim cites a file. Anything not in the
repository is marked **NOT FOUND**. Line numbers are for this commit.

---

## How to read this

| Label | Meaning |
|---|---|
| **Working** | Code exists and I executed tests or saw real data that prove it. |
| **Partially** | Works with caveats that matter for a viva. |
| **Untested** | Code exists; nothing in this audit ran it end to end. |
| **Mocked** | A simulation or synthetic generator stands in for the real thing. |
| **Not Implemented** | Described somewhere (paper, enum, docs) but no code does it. |

What I actually ran during this audit:

- `pytest` on the 8 AI-engine honeypot/Q-learning suites: **75 passed** (`ai-engine/tests/test_cowrie_*`, `test_deception_*`, `test_honeypot_rules.py`, `test_q_learning_h6.py`, `test_q_table_safety.py`).
- `jest` on the 8 backend honeypot suites: **63 passed** (`backend/tests/cowrieIngest.test.js`, `honeypot*.test.js`, `deceptionProfile.test.js`, `mediumHoneypot.test.js`). These mock MongoDB.
- Read-only queries against the local MongoDB (`sentinel-db` on 127.0.0.1:27017).
- A search of Windows and the WSL `Ubuntu` distro for a Cowrie install: **none found**.
- The real rule classifier and reward function run on the Phase 3 test-plan sessions (results in Phase 3).

Nothing was started against the network and no data was changed.

> **Update, same day: quick wins fixed (uncommitted).** The findings below describe the audited commit; these are
> now resolved in the working tree: Cowrie config sections (H5 partly, L1, L2), classifier substrings and duration
> rule (H2, rules now `honeypot_rules_v2`), dashboard refetch storm (M3), mislabelled note (M8), and demo sessions
> training the Q-learner (H4 partly). Each one is marked **FIXED** where it appears below. The legacy plaintext
> credentials (C1) were redacted later the same day, after a backup.

---

# PHASE 1: Map of the honeypot system

## 1.1 Every honeypot file

### Cowrie configuration (`honeypot/cowrie/`)

| File | What it is | Notes |
|---|---|---|
| `honeypot/cowrie/cowrie.cfg` | Cowrie config: hostname `centos-web-gateway`, port 2222, banner `SSH-2.0-OpenSSH_7.4`, JSON log on, blocker plugin on | Several keys are in sections Cowrie ignores (see 4.2). |
| `honeypot/cowrie/userdb.txt` | 13 accepted logins (`root:0:root`, `root:0:123456`, `pi:1000:raspberry`, …) | Format `user:uid:password` is valid for Cowrie's UserDB. |
| `honeypot/cowrie/sentinelblocker.py` (was `sentinel_blocker.py`) | Cowrie output plugin that monkey-patches the SSH/Telnet factories to refuse connections from blocked IPs | Enabled by `[output_sentinelblocker]`. Under its old name it **never loaded** (see 3.6 status). |
| `honeypot/cowrie/sentinel_output.py` | Alternative output plugin that POSTs events straight to the backend | **Deliberately not enabled** (would double-ingest with the parser; `honeypot/README.md:21-23`). |
| `fs.pickle` (fake filesystem) | **NOT FOUND**: Cowrie's default filesystem would be used. |
| `honeyfs/` (fake file contents like `/etc/passwd`, `/etc/os-release`) | **NOT FOUND**: Cowrie defaults would be used. |
| `txtcmds/` (canned command output) | **NOT FOUND**. |

### Ingestion and helpers (`honeypot/`)

| File | Role |
|---|---|
| `honeypot/parsers/log_parser.py` | **The real ingest path.** Tails `cowrie.json`, maps eventids to backend HTTP calls. Also has `--file` (replay) and `--demo` (fake sessions). |
| `honeypot/collectors/session_collector.js` | Runs **inside the backend process** (required by `backend/routes/honeypotIngest.js:56-64`). Writes sessions, threats, alerts, emits sockets. |
| `honeypot/switch_profile.py` | Rewrites `cowrie.cfg` for one of 6 personas. Never restarts Cowrie. |
| `honeypot/deception_rotator.py` | Optional loop: asks the backend for the Q-learner's recommended persona, rewrites `cowrie.cfg`, runs a restart command, records the persona. |
| `honeypot/sniffer/sniffer.py`, `flow_mapping.py` | Optional Scapy + cicflowmeter packet capture; builds `flows.csv` and can POST flows to `/api/honeypot/ingest/flow`. Not part of the Cowrie event path. |
| `honeypot/README.md` | States that no honeypot, parser, sniffer or simulated feed starts automatically. |

### Backend (Node/Express)

| File | Role |
|---|---|
| `backend/routes/honeypotIngest.js` | Machine-to-machine API (`X-API-Key`): `POST /api/honeypot/ingest`, `/command`, `/download`, `/close`, `/flow`, `/match-session`, `GET /check-block`. |
| `backend/routes/honeypot.js` | Dashboard API (JWT): `/status`, `/analytics`, `/nodes`, `/sessions`, `/sessions/:id`, `/sessions/:id/close`, `/deception/profile` (GET/PUT), `/deception/recommendation`. |
| `backend/controllers/honeypotController.js` | Handlers for the dashboard API, with role-based redaction. |
| `backend/services/honeypotService.js` | Core logic: atomic activity updates, session closure, AI call, auto-block decision, Q-learner call, analytics. |
| `backend/services/honeypotSweepService.js` | Every 15 min closes sessions inactive for 6 h (lost close events). Started in `backend/server.js:288`. |
| `backend/models/HoneypotSession.js` | The MongoDB schema. |
| `backend/services/aiEngineService.js:223-237, 313-320` | HTTP client to the AI engine for honeypot classify, deception score and recommendation. |
| `backend/services/containmentService.js:829` | `executeAutoBlock`, shared with the network-flow path. |
| `backend/services/containment/adapterFactory.js` | Chooses Mock vs Windows Firewall adapter. |
| `backend/websocket/socketManager.js:319-350` | `emitHoneypotEvent`. |
| `backend/utils/redact.js:90, 227` | Viewer redaction; password redaction at ingest. |
| `backend/utils/seed.js` | **Synthetic** seed: wipes collections and inserts 40 fake sessions (`sess-…`). |
| `backend/services/retentionService.js` | Archive-then-delete retention, **disabled by default**, manual only. |

### AI engine (Python/FastAPI)

| File | Role |
|---|---|
| `ai-engine/inference/main.py:436, 476, 482` | `POST /predict/honeypot/internal`, `POST /deception/score`, `GET /deception/recommendation`. |
| `ai-engine/inference/predictor.py:88-96, 529-575` | `predict_from_honeypot`: **rule-based** score, not ML. |
| `ai-engine/utils/features.py:347-369` | `classify_honeypot_session`: the keyword rules. |
| `ai-engine/rl_engine/deception_scorer.py` | The tabular Q-learner (`DeceptionQLearner`, `SessionScorer`, `calc_reward`). |
| `ai-engine/inference/deception.py` | Singleton scorer and Q-table path guard (never writes `models/q_table.json`). |
| `ai-engine/models/q_table.json` | Shipped seed Q-table (12,087 episodes; see 4.6). |
| `ai-engine/runtime/q_table.json` | Runtime copy; currently a test artefact (99 episodes, all zeros). |

### Frontend (React)

| File | Role |
|---|---|
| `frontend/src/pages/HoneypotAnalytics.jsx` | Honeypot page: KPIs, session list, top commands, daily volume, Adaptive Deception panel, nodes. |
| `frontend/src/services/api.js:44-54` | `honeypotAPI` client. |
| `frontend/src/hooks/useSocket.js`, `context/SocketContext.jsx` | Socket.IO connection. |

### Docker / deployment

| Item | Finding |
|---|---|
| Cowrie Dockerfile / compose service | **NOT FOUND**, now or in git history. `docker-compose.yml:7-9` says the honeypot "runs on a separate host by design and is not part of this stack". |
| Backend port | `docker-compose.yml:75-76` publishes 5000 "so honeypot hosts post to /api/honeypot/ingest". Natively the backend binds **127.0.0.1** (`backend/server.js:297`). |

## 1.2 How Cowrie is installed and run

- **In this repo: not at all.** No install script, no container, no systemd unit. `docs/NATIVE_DEVELOPMENT.md:114-121` says Cowrie "requires a separately managed Linux host" and "has not been validated on this Windows host".
- **On this machine: not installed.** Searched Windows `PATH` and the WSL `Ubuntu` filesystem (depth 5); no `cowrie` directory, binary, or `cowrie.json`. WSL Ubuntu exists (currently stopped), so Phase 3 uses it.
- **Historically it did run once.** Local MongoDB holds session `9b21e8e00dd7` (Cowrie-style 12-hex id) from `172.18.0.1`, a Docker bridge gateway address, created 2026-09-11. So Cowrie ran in some Docker network that is not in the repository.
- **Port:** `listen_endpoints = tcp:2222` (`cowrie.cfg:4`). No Telnet port configured (Telnet is off by default in Cowrie). No 22→2222 redirect: **NOT FOUND**.
- **How traffic reaches it:** nothing in the repo routes or redirects traffic to Cowrie. Attackers (or you) connect directly to port 2222. The paper's "redirecting suspected attacker traffic to decoy nodes" is **NOT FOUND** (see 4.8).

## 1.3 Where Cowrie logs and how SentinelAI picks them up

```
Cowrie ──writes──► var/log/cowrie/cowrie.json   (one JSON object per line; cowrie.cfg:17-19)
                   var/log/cowrie/cowrie.log    (text; cowrie.cfg:21-23)
log_parser.py --live ──polls every 0.5 s──► reads new lines ──HTTP POST + X-API-Key──► backend /api/honeypot/ingest*
```

- **Mechanism: file tail by polling** (`log_parser.py:202-242`, `POLL_INTERVAL = 0.5` at line 26). Not a webhook, not a queue, not a DB plugin.
- It **starts at the end of the file** (`log_parser.py:215`, `seek(0, 2)`): lines written while the parser was down are never read.
- Rotation is detected by inode change or file shrink (`log_parser.py:223`).
- Alternative push path (`sentinel_output.py`) exists but is disabled.
- The blocker plugin is a **pull** in the other direction: Cowrie polls `GET /api/honeypot/ingest/check-block` every 2 s (`sentinelblocker.py`, `sync_once`).

## 1.4 Mocked or simulated parts

| Generator | Where | What it does |
|---|---|---|
| Parser demo mode | `log_parser.py:248-262` (`--demo`) | Invents sessions `demo-xxxxxxxx` from 4 hard-coded public IPs and 10 canned commands, then **posts them through the real backend path**, so they hit MongoDB, the dashboard **and the live Q-learner**. |
| Backend seed | `backend/utils/seed.js:93, 124-154` | `deleteMany` on 7 collections, then 40 fake closed sessions `sess-…`. Blocked only when `NODE_ENV=production` (line 3-5). |
| Mock AI engine | `scratch/mock_ai_engine.js` | Scratch utility; no honeypot endpoints. |
| Mock containment | `backend/services/containment/MockContainmentAdapter.js` | **Default** enforcement adapter. |
| Seed Q-table | `ai-engine/models/q_table.json` | 12,087 episodes whose recent rewards repeat exactly `10.63, 10.63, 19.73, …`, a pattern from scripted or replayed sessions, not attackers. |

**What is in your MongoDB today:** 8 honeypot sessions. 7 are `demo-*` (parser demo mode, 2026-09-23). 1 is a real Cowrie session from your own testing (above). **There is no real attacker data.**

---

# PHASE 2: How it works, from scratch

## 2.1 Theory

**What a honeypot is.** A system with no production purpose, built to be attacked. Because no legitimate user should ever touch it, *every* interaction is suspicious. That gives near-zero false positives and lets you observe attacker tools, credentials and commands.

**Interaction levels.**

| Level | What the attacker gets | Risk | Example |
|---|---|---|---|
| Low | A port that answers and logs; maybe a banner | Very low | honeyd, OpenCanary port listeners |
| **Medium** | An *emulated* service: a fake shell that parses commands and returns scripted output; no real OS underneath | Low–moderate | **Cowrie** (SSH/Telnet), Dionaea (SMB/HTTP malware capture) |
| High | A real OS or real service the attacker truly controls | High: real pivot risk, needs strong containment | A real VM with monitoring |

**Where Cowrie fits.** Cowrie is a medium-interaction SSH/Telnet honeypot written in Python on Twisted. It implements the SSH protocol for real, accepts the logins you list in `userdb.txt`, then gives a *fake* shell: commands like `ls`, `cat`, `uname` are re-implemented in Python against a pickled fake filesystem. Nothing the attacker types executes on the host. Notable exception: Cowrie's `wget`/`curl` emulation **really downloads** the URL and stores the file (by SHA-256) in `download_path` (`cowrie.cfg:12`). It logs every step as JSON events (`cowrie.session.connect`, `cowrie.login.failed`, `cowrie.login.success`, `cowrie.command.input`, `cowrie.session.file_download`, `cowrie.client.kex`, `cowrie.session.closed`, …).

**Why deception helps defence.**
1. High-fidelity alerts (no legitimate traffic).
2. Threat intelligence: credentials tried, tools, malware URLs/hashes, client fingerprints (HASSH).
3. Attacker time wasted on a decoy is time not spent on real assets.
4. Adaptive deception: if you change what the decoy looks like based on what keeps attackers engaged, you learn longer sessions and more intelligence, and you make fingerprinting harder.

## 2.2 One attacker session, end to end

```
Attacker            Cowrie (Linux host)       log_parser.py           Backend (Express)                 AI engine (FastAPI)        MongoDB            Dashboard
   |  TCP :2222  ───────►|                         |                         |                                   |                          |                  |
   |                     | blocker: is IP blocked? (in-memory set, synced every 2 s from GET /check-block) |       |                          |                  |
   |                     | cowrie.session.connect ─► on_connect: remember in _sessions (no HTTP yet)           |                          |                  |
   |  SSH kex  ─────────►| cowrie.client.kex ──────► on_kex → ensure_session_opened ─► POST /ingest SESSION_OPENED ──► collector.onSessionOpened |
   |                     |                         |                         |   HoneypotSession.create ───────────────────────────────►|                  |
   |                     |                         |                         |   ThreatLog.create(HIGH, 0.75, "SSH Brute Force") ───────►|                  |
   |                     |                         |                         |   emit new_threat, honeypot_session_opened ─────────────────────────────────►|
   |                     |                         |                         ◄── POST /ingest CLIENT_KEX (hassh) ──┤                          |                  |
   |  root/123456 ──────►| cowrie.login.failed ────► on_login_failed: append to local credentials (no HTTP)     |                          |                  |
   |  root/toor ────────►| cowrie.login.success ───► on_login_ok: append (no HTTP)                             |                          |                  |
   |  uname -a ─────────►| cowrie.command.input ───► on_cmd: classify_intent, extract_iocs ─► POST /ingest/command                        |                  |
   |                     |                         |                         |   classifyIntent again (server-side, caller's value ignored)                 |                  |
   |                     |                         |                         |   recordSessionActivity: one atomic $set pipeline ─────►|  commands, IOCs,  |
   |                     |                         |                         |     (rule deceptionScore, engagementLevel, MITRE ids)    |  deceptionScore  |
   |                     |                         |                         |   intent ∈ {MALWARE_DOWNLOAD, REVERSE_SHELL, PERSISTENCE} → Alert CRITICAL  |                  |
   |                     |                         |                         |   emit honeypot_command, live_feed_event ──────────────────────────────────►| page refetches
   |  wget http://x ────►| cowrie.session.file_download ► on_download ─► POST /ingest/download ─► Alert CRITICAL, emit malware_download    |                  |
   |  exit ─────────────►| cowrie.session.closed ──► on_closed ─► POST /ingest/close {duration, credentials, hassh}                       |                  |
   |                     |                         |                         |   redact passwords → "***REDACTED***"                    |                  |
   |                     |                         |                         |   closeSession: claim (closureAnalysisState=processing)  |                  |
   |                     |                         |                         |   POST /predict/honeypot/internal ─►| rules → class + threatScore           |
   |                     |                         |                         |   store AIPrediction; update ThreatLog severity/status   |                  |
   |                     |                         |                         |   if autoBlockEnabled && score ≥ 0.92 → executeAutoBlock ─► BlockedIP (+ adapter)
   |                     |                         |                         |   POST /deception/score ───────────►| calc_reward → Q update → save Q-table |
   |                     |                         |                         |                                     | choose next persona (recommendation)  |
   |                     |                         |                         |   save qDeceptionScore, recommendedProfile; campaign clustering            |
   |                     |                         |                         |   emit honeypot_session_closed, threat_updated ────────────────────────────►|
   | next connection ───►| blocker refuses if IP now in BlockedIP (≤ 2 s later)                                |                          |                  |
```

### Step by step, with the code

1. **Connect.** Cowrie accepts TCP on 2222. `sentinelblocker.py` (`patch_ssh`) wraps `CowrieSSHFactory.buildProtocol`; if `is_ip_blocked(ip)` (line 95) the factory returns `None` and Twisted drops the connection. Cowrie logs `cowrie.session.connect` with `session`, `src_ip`, `src_port`.
2. **Parser sees the line.** `tail()` reads it, `process()` (`log_parser.py:193-200`) does `json.loads` and dispatches by `eventid` through `HANDLERS` (line 191). `on_connect` (line 93) only stores state in memory. *Design point:* a bare port-scan connection with no SSH activity is never sent (line 187-188), which keeps scanner noise out.
3. **First SSH activity opens the session in the backend.** Any of kex/login/command calls `ensure_session_opened` (line 71), which POSTs `SESSION_OPENED` with Cowrie's own timestamp.
   - Backend: `internalAuth` checks the key (`honeypotIngest.js:9-14`), `telemetryError` validates `sessionId` (string ≤128) and `sourceIP` (lines 66-80).
   - `onSessionOpened` (`session_collector.js:12`) is idempotent on `sessionId`, creates the `HoneypotSession` **and a `ThreatLog` with fixed severity HIGH, score 0.75, note `[SESSION_OPEN_HEURISTIC]`**, then emits `new_threat` and `honeypot_session_opened`.
4. **Logins.** `cowrie.login.failed/success` are buffered by the parser (`log_parser.py:107-118`) and only sent at close. The backend never sees a brute-force burst as it happens.
5. **Commands.** `on_cmd` (line 120) classifies intent with regexes (lines 43-53) and extracts IOCs (IPs, URLs, hashes, sensitive files; lines 34-41), then POSTs `/ingest/command`.
   - Backend re-derives intent server-side (`honeypotIngest.js:305-307`).
   - `honeypotService.recordSessionActivity` (`honeypotService.js:112-164`) is **one atomic MongoDB update pipeline**: append command, union IOCs and MITRE techniques, recompute `deceptionScore = min(100, 3·commands + 10·sensitiveFiles + 8·urls + 15·downloads)` and `engagementLevel`. Every attacker string goes through `$literal`, so `$where`-style operator injection is stored as text.
   - High-value intents create a CRITICAL `Alert` (`session_collector.js:15`).
6. **File download.** `on_download` → `/ingest/download` → URL/hash recorded, `downloadCount+1`, CRITICAL alert, `malware_download` socket event (`session_collector.js:16`). The file itself stays on the Cowrie host.
7. **Close.** `on_closed` (`log_parser.py:163`) POSTs duration, the buffered credentials and HASSH. Passwords are replaced by `***REDACTED***` (`honeypotIngest.js:120-122`, `redact.js:227-234`, again in `honeypotService.js:231`).
8. **Closure analysis** (`honeypotService.closeSession`, line 189): a compare-and-set on `closureAnalysisState` guarantees one analysis per session; a failed attempt is parked as `failed` for human review, never retried automatically (lines 194-205).
9. **Classification** (`analyseClosure`, line 223) calls `POST /predict/honeypot/internal`. In the AI engine, `predict_from_honeypot` (`predictor.py:529`) **does not use RF/XGBoost/IF**. It uses `classify_honeypot_session` (`features.py:347-369`):
   - login failed → `SSH Brute Force` (0.90)
   - logged in, 0 commands → `Port Scan` (0.75)
   - IOC ≥ 3, or a program in `scp ftp sftp rsync tar zip nc ncat netcat` → `Data Exfiltration` (0.95)
   - a program in `ssh telnet ping nmap arp route smbclient mount` → `Lateral Movement` (0.90)
   - a program in `wget curl chmod python python3 perl bash sh gcc`, or a local executable (`./x`, `/tmp/x`) → `RCE Attempt` (0.93)
   - "Program" means the first word of each command segment (split on `; & |`, backticks, `$(`), path stripped, `sudo`/`busybox`/`nohup` skipped (`features.py` `command_programs`). **FIXED:** v1 matched raw substrings and treated any session over 120 s as exfiltration.
   - else `BENIGN` (0.40); non-benign adds +0.01 per command, capped 0.99 (`predictor.py:88-96, 539-543`).
   The code says why: Cowrie gives no packet flow features, and the CICIDS model scored every synthesised session BENIGN (`predictor.py:530-533`).
10. **Decision.** Thresholds come from the engine: alert 0.90, block 0.92 (`predictor.py:22, 28`). The `ThreatLog` from step 3 is updated with the class, score, severity and status (`honeypotService.js:307-373`). Blocking is described in 2.4.
11. **Q-learner** (`finishClosure`, line 418) → `POST /deception/score` (not retried, because it mutates the Q-table: `aiEngineService.js:23`). Result stored as `qDeceptionScore` and `recommendedProfile`. Then campaign clustering.
12. **Dashboard.** `honeypot_session_closed` + `threat_updated` reach admin/analyst rooms in full and viewers redacted (`socketManager.js:319-350`). `HoneypotAnalytics.jsx:64-70` refetches analytics, sessions and nodes on each event.

> **Two different "deception scores".** `deceptionScore` (0–100) is the backend's rule formula in step 5. `qDeceptionScore` is `min(reward × 5, 100)` from the Q-learner (`deception_scorer.py:401`). The dashboard's "Avg deception" KPI uses the first (`honeypotService.js:462, 504`). Say this clearly in a viva.

## 2.3 The Q-learning deception scorer

Code: `ai-engine/rl_engine/deception_scorer.py`.

| Element | Exactly what the code does |
|---|---|
| **States** | The 6 personas: `ubuntu_22, debian_11, centos_7, windows_srv, aws_ec2, raspberry_pi` (line 73-81). The state for a session is **the persona served in the previous session** (`previousProfile`, looked up in `honeypotService.js:37-48, 239`). Attacker behaviour is **not** part of the state. |
| **Actions** | The same 6 personas: "which persona was served during this session". |
| **What an action actually changes** | Only via `switch_profile.generate_config` (`switch_profile.py:72-117`): `hostname`, `kernel_version`, `kernel_build_string`, `hardware_platform` and the SSH `version` banner in `cowrie.cfg`. The `os`, `prompt` and `ports` fields in `deception_scorer.PROFILES` are **never applied** anywhere. Fake filesystem, files, command output, timing: **unchanged**. |
| **Reward** (`calc_reward`, lines 103-113) | `2·ln(1 + duration/60)` + `0.3·#commands` + intent bonuses (`MALWARE_DOWNLOAD` 3.0, `REVERSE_SHELL` 2.5, `PERSISTENCE` 2.0, `CREDENTIAL_HARVEST`/`PRIVILEGE_ESCALATION` 1.5) + `0.5·iocCount` + 2.0 if login succeeded − 5.0 if any fingerprinting command (`systemd-detect-virt`, `/proc/1/cgroup`, `cowrie`, `dmidecode`, …), clipped to [−10, 20]. So "engagement" = longer, busier, more malicious sessions. |
| **Update rule** (`_td_update`, lines 209-218) | `Q(s,a) ← Q(s,a) + α [r + γ·maxₐ′ Q(s′,a′) − Q(s,a)]` with α = 0.1, γ = 0.9, and **s′ = a** (the persona just served becomes the next state; `process_session` line 398). |
| **Policy** (`choose_action`, line 347) | ε-greedy, ε = 0.2 / (1 + 0.01·episodes), floored at 0.05 (lines 117, 325-326). Optional UCB1 bandit via `DECEPTION_POLICY=ucb1` (line 128). The code itself notes the problem is "close to a multi-armed bandit" (lines 123-126). |
| **Persistence** | JSON file, atomic write (temp file + `os.replace` + `fsync`, lines 296-321), cross-process lock file (lines 149-176), merge of concurrent writers (lines 220-239). Path: `Q_TABLE_PATH` (Docker: `/data/q_table.json` on a volume), otherwise `%LOCALAPPDATA%\SentinelAI\runtime\q_table.json`. Writes to `models/` are always refused (lines 254-266). The file is seeded once from `models/q_table.json` (`inference/deception.py:90-96`). |
| **Concurrency** | FastAPI handler holds `_scorer_lock` (`main.py:478`). |

### Does its decision change Cowrie? The proof

- `SessionScorer.process_session` returns `"recommendationApplied": False` (line 401) and its docstring says "nothing here reconfigures Cowrie" (line 382).
- The backend stores the recommendation only as a field (`honeypotService.js:422`) and credits the reward to the persona **recorded** as active, not the recommended one (lines 236-251).
- The only code that turns a recommendation into a Cowrie change is `honeypot/deception_rotator.py`, which must be started by hand with admin credentials, rewrites the file, and needs `--restart-cmd` to restart Cowrie (lines 66-96). It is unit-tested (`test_deception_rotator.py`) but **was never run against a live Cowrie** (none exists here).
- Even when applied, the change is cosmetic (hostname/kernel/banner), and some of those keys are in sections Cowrie ignores (4.2).

**Verdict:** by default it is a **score and a recommendation**. The loop *can* be closed with the rotator, but that is **Untested** live and changes only surface strings.

## 2.4 Link to the firewall adapter

Path (`honeypotService.js:300-373` → `containmentService.js:829-940`):

1. `shouldBlock = threatScore ≥ blockThreshold (0.92) AND SystemSetting autoBlockEnabled === true` (`honeypotService.js:300-305`). **`autoBlockEnabled` defaults to false** (no setting → `false`, line 302). Your DB has no such setting and 0 blocked IPs.
2. Because every session already has the `ThreatLog` from session-open, the normal branch is `executeAutoBlock` (line 350).
3. `checkTargetSafety` refuses loopback, 0.0.0.0, broadcast, multicast, link-local and anything in `CONTAINMENT_PROTECTED_TARGETS` (`containmentPolicyService.js:11-24, 340`). **Private ranges (10/8, 172.16/12, 192.168/16) are not protected unless you list them.**
4. Upsert into `BlockedIP`, then `requestContainment` through the adapter.
5. Adapter (`adapterFactory.js:18-47`): **Mock** by default; `WindowsFirewallAdapter` only when `CONTAINMENT_BACKEND=windows-firewall` **and** `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true` **and** not `NODE_ENV=test`/`CONTAINMENT_DRY_RUN`.
6. Enforcement that actually affects the attacker: the Cowrie blocker plugin pulls the `BlockedIP` list every 2 s and refuses **new** connections. An open session is not killed.

Facts to know:
- With default settings a honeypot event **cannot** block anything.
- A Windows Firewall rule on the SentinelAI host does **not** protect a separate Linux Cowrie host. It blocks that IP from reaching the Windows machine.
- Brute force alone scores 0.90: it reaches the **alert** line but never the **block** line (0.92).
- Blocking a honeypot attacker ends the intelligence you are collecting. Justify it as "stop a confirmed attacker reaching real assets", not as honeypot hygiene.

## 2.5 MongoDB

| Collection | Honeypot use | Schema / file |
|---|---|---|
| `honeypotsessions` | One document per Cowrie session. Embeds `credentials[]` (password redacted), `commands[]` (`command, timestamp, output, success, intent`), `iocExtracted{ips,urls,hashes}`, `filesAccessed`, `malwareDownloaded`, `downloadCount`, `hassh`, scores, `servedProfile`, `recommendedProfile`, `mitreTechniques`, closure state | `backend/models/HoneypotSession.js:13-63` |
| `threatlogs` | One per session (created at open, updated at close) | `backend/models/ThreatLog.js` |
| `alerts` | High-value command, download, auto-block alerts (TTL index on `expiresAt`) | `backend/models/Alert.js:48` |
| `aipredictions` | One per closed session, `modelType: 'rules'` | `honeypotService.js:275-290` |
| `blockedips` | Deny-list the blocker plugin reads | `backend/models/BlockedIP.js` |
| `systemsettings` | `deceptionActiveProfile`, `autoBlockEnabled` | `honeypotService.js:17-35, 300-302` |
| `campaigns` | Sessions clustered by shared commands | `campaignService.clusterSession` |

Separate collections for commands, credentials or IPs: **NOT FOUND**. They are embedded arrays.

Indexes declared (`HoneypotSession.js:64-70`): `sessionId` unique, `{sourceIP, createdAt}`, `{honeypotNode, status}`, `{createdAt}`, `{hassh}`, `{linkedThreatLog}`, `{commands.command, createdAt}`. **In your live DB the `commands.command` index is missing** (it was declared after the collection's indexes were built). No TTL on honeypot sessions.

## 2.6 What the dashboard shows and which socket events carry it

Page `frontend/src/pages/HoneypotAnalytics.jsx`: KPIs (sessions today, unique IPs, avg duration, avg rule deception score, avg commands), attacker session list (id, IP, country code, node, duration, first 5 commands, MITRE badges), top 10 commands (7 days), daily volume, **Adaptive Deception** panel (served persona; Q-learner recommendation for admin/analyst only), node list.

| Socket event | Emitted from | Payload | Rooms |
|---|---|---|---|
| `honeypot_session_opened` | `session_collector.js:12` | sessionId, sourceIP, node | admin/analyst full; viewer masked IP |
| `honeypot_command` | `session_collector.js:15` | sessionId, IP, command, intent, deceptionScore | viewer gets `[REDACTED_COMMAND]` |
| `malware_download` | `session_collector.js:16` | IP, url, sha256 | |
| `honeypot_session_closed` | `session_collector.js:17` | duration, deceptionScore | |
| `live_feed_event` (`type: 'honeypot'`) | `socketManager.js:332-349` | one-line message | |
| `new_threat`, `threat_updated`, `ip_blocked`, `new_alert` | collector / honeypotService / containmentService | threat/alert docs | |

The page listens to the first three and **refetches all three REST endpoints on every event** (`HoneypotAnalytics.jsx:64-70`). It does not render the socket payload directly.

`/api/honeypot/nodes` hard-codes one node `SSH-COWRIE-01` on port 2222 and calls it "active" if it had a session today (`honeypotService.js:525-538`). That is **not a health check**: there is no Cowrie heartbeat.

---

# PHASE 3: Is it working? A verification plan

## 3.1 What I could and couldn't verify

Cowrie is not installed, so **no live session was run in this audit**. Everything below is a plan for you to run on your own machine, with the expected outcome computed from the real code.

## 3.2 Start everything, in order

**0. Prerequisites (one time).**

- WSL2 networking: the backend binds `127.0.0.1` (`server.js:297`). Easiest: turn on mirrored networking so WSL and Windows share `localhost`. Put this in `%UserProfile%\.wslconfig`, then run `wsl --shutdown`:
  ```ini
  [wsl2]
  networkingMode=mirrored
  ```
- Generate a honeypot key and put it in `backend/.env` as `HONEYPOT_API_KEY=` (32 hex bytes, e.g. `python -c "import secrets;print(secrets.token_hex(32))"`).

**1. Install Cowrie in WSL Ubuntu** (official method, as a non-root user):

```bash
sudo apt-get update && sudo apt-get install -y git python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal jq
sudo adduser --disabled-password --gecos "" cowrie
sudo su - cowrie
git clone https://github.com/cowrie/cowrie && cd cowrie
python3 -m venv cowrie-env && source cowrie-env/bin/activate
python -m pip install --upgrade pip && python -m pip install -e . requests
```

**2. Install SentinelAI's Cowrie files** (paths relative to `~/cowrie`; repo mounted at `/mnt/c/Users/srisn/Desktop/Projects/sentinelai-complete`):

```bash
R=/mnt/c/Users/srisn/Desktop/Projects/sentinelai-complete/honeypot
cp $R/cowrie/cowrie.cfg etc/cowrie.cfg          # fix sections first: see 4.2 / 5.1
cp $R/cowrie/userdb.txt etc/userdb.txt
cp $R/cowrie/sentinelblocker.py src/cowrie/output/sentinelblocker.py
```

**3. Start the SentinelAI services (Windows, separate terminals).** MongoDB is already running on 27017.

```bash
cd ai-engine && .venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ../backend/.env
```
```bash
cd backend && npm start
```
```bash
cd frontend && npm run dev -- --host 127.0.0.1
```

**4. Start Cowrie (WSL, user `cowrie`).** The blocker reads the key from the environment:

```bash
export HONEYPOT_API_KEY=<same key> SENTINEL_API_URL=http://127.0.0.1:5000/api
cowrie start            # older checkouts: bin/cowrie start
tail -f var/log/cowrie/cowrie.log    # expect "[SentinelAI] Non-blocking blocker plugin loaded"
```

**5. Start the parser (WSL).**

```bash
export HONEYPOT_API_KEY=<same key> SENTINEL_API=http://127.0.0.1:5000/api
python /mnt/c/Users/srisn/Desktop/Projects/sentinelai-complete/honeypot/parsers/log_parser.py --live --log ~/cowrie/var/log/cowrie/cowrie.json
```

**6. Optional.** `python honeypot/deception_rotator.py --once --dry-run --origin http://127.0.0.1:5173` (needs an admin login in env; dry run changes nothing).

## 3.3 Safe local test plan (only your machine)

All traffic goes to `127.0.0.1:2222`. Because the source IP is loopback, **auto-block is always refused** (`containmentPolicyService.js:12`), so you cannot lock yourself out.

For the `wget` step, serve a harmless file locally first:

```bash
mkdir -p /tmp/dummy && echo 'echo hello' > /tmp/dummy/test.sh && python3 -m http.server 8081 --bind 127.0.0.1 --directory /tmp/dummy
```

**Correction (verified on a live Cowrie, 2026-10-22):** current Cowrie refuses to download from any address that is not globally routable (`src/cowrie/core/network.py`, SSRF protection). A local URL is therefore never fetched: step 3 produces `cowrie.command.input` but no `cowrie.session.file_download`, no download alerts and `downloadCount: 0`. Seeing a real download needs a public URL, which means outbound internet from the honeypot; only do that on an isolated host. The download ingest path itself is covered by the replayed-log test (3.6).

| # | Do | Cowrie JSON (`jq -c 'select(.session=="<id>")' cowrie.json`) | Parser log | Backend log | MongoDB | AI / Q-table | Dashboard |
|---|---|---|---|---|---|---|---|
| 1 | `ssh -p 2222 root@127.0.0.1`, password `123456` | `cowrie.session.connect`, `cowrie.client.kex`, `cowrie.login.success` | `SSH session opening acknowledged` | `[Collector] Opened: <id>` | new `honeypotsessions` doc `status: active`; new `threatlogs` HIGH 0.75 | none yet | session appears; live feed line |
| 2 | `whoami`, `uname -a`, `ls`, `cat /etc/passwd` | 4× `cowrie.command.input` | `Command [RECONNAISSANCE]…`, `[CREDENTIAL_HARVEST]` | 4 POST `/command` 200 | `commands[]` grows; `filesAccessed: ["/etc/passwd"]`; `deceptionScore` 3→6→9→22 | none | commands column, MITRE badges |
| 3 | `wget http://127.0.0.1:8081/test.sh` | `cowrie.command.input`, `cowrie.session.file_download` (`url`, `shasum`, `outfile`) | `FILE DOWNLOAD` | Alert "High-Value: MALWARE_DOWNLOAD", Alert "Malware Downloaded" | `iocExtracted.urls`, `malwareDownloaded`, `downloadCount: 1` | none | 2 CRITICAL alerts in the bell |
| 4 | `exit` | `cowrie.session.closed` (`duration_ms` on current Cowrie, `duration` on older) | `Session closed: <id>` | `[HP] AI classified … RCE Attempt (0.98)`, `[HP] Q-learner scored …` | `status: closed`, `closureAnalysisState: complete`, `aiClassification`, `qDeceptionScore`, `recommendedProfile`, `servedProfile: centos_7`; credentials with `***REDACTED***` | Q-table `episode_count +1`, `saved_at` updated | `honeypot_session_closed`, threat updated |
| 5 | Brute force: `for i in $(seq 1 20); do sshpass -p wrong$i ssh -o StrictHostKeyChecking=no -p 2222 root@127.0.0.1 true; done` | 20× connect + several `login.failed` per connection + closed | 20 open/close pairs | 20 sessions opened/closed | 20 sessions, each `SSH Brute Force` 0.90, status MONITORING | 20 Q updates with reward ≈ 0.3 | 20 new HIGH threats |

Expected numbers, computed by running the real `classify_honeypot_session` and `calc_reward`:

| Session | Class | Threat score | Reward | qDeceptionScore |
|---|---|---|---|---|
| Brute force, no login | SSH Brute Force | 0.90 (alert, not block) | 0.31 | 1.5 |
| Login + 4 harmless commands, 60 s | **BENIGN** | 0.40 | 6.09 | 30.4 |
| Same, but stay > 120 s | BENIGN (v1 said Data Exfiltration 0.99) | 0.40 | 7.21 | 36.0 |
| + local `wget`, 60 s | RCE Attempt | 0.98 | 9.89 | 49.4 |
| Single command `sync` | BENIGN (v1 said Data Exfiltration 0.96, `"nc"` inside `sync`) | 0.40 | 3.11 | 15.6 |
| `cat /proc/1/cgroup` | BENIGN | 0.40 | −1.31 | −6.6 |

Useful commands to see the evidence:

```bash
jq -c 'select(.eventid|test("login|command|download|closed")) | {t:.timestamp,e:.eventid,s:.session,i:.input}' ~/cowrie/var/log/cowrie/cowrie.json | tail
```
```bash
python -c "import json,os;d=json.load(open(os.path.join(os.environ['LOCALAPPDATA'],'SentinelAI','runtime','q_table.json')));print(d['episode_count'],d['saved_at'],d['reward_history'][-5:])"
```

## 3.4 Measuring latency (attack → dashboard)

The backend stamps each command with **ingest time** (`session_collector.js:15`, `timestamp: new Date()`), while Cowrie's JSON has the **event time**. The difference is ingestion latency:

```bash
mongosh sentinel-db --quiet --eval 'db.honeypotsessions.findOne({sessionId:"<id>"},{commands:1}).commands.forEach(c=>print(c.timestamp.toISOString(), c.command))'
```

Compare with the `timestamp` of the matching `cowrie.command.input` lines. Socket push adds a few ms. The page then does 3 REST calls; measure those in the browser DevTools Network tab. Expected from the design: 0–500 ms polling wait + HTTP/DB time, so **under ~1 s for commands**. Session close is slower: two AI calls plus a Q-table fsync. This is an estimate until you measure it.

## 3.5 Failure scenarios (from the code)

| Scenario | What happens | Lost? | Duplicated? |
|---|---|---|---|
| **Parser restarts** mid-session | Restarts at **end of file** (`log_parser.py:215`); in-memory `_sessions` gone. Later commands for the open session are ignored (`sid not in _sessions`, line 123). The close is still delivered without state (lines 167-173). | **Yes**: events during downtime and later commands of open sessions | No |
| **Cowrie restarts** | Open SSH sessions drop; Cowrie logs their close. Fine if the parser is running. The rotator also restarts Cowrie, so a persona switch drops live attackers. | No | No |
| **Log rotation** (Cowrie rotates daily by renaming `cowrie.json`) | Inode change detected (line 223) → reopen new file at offset 0. Lines written to the old file after the last poll and before the rename are not read. | Small window | No |
| **Partial line** (poll mid-write) | `readline()` returns half a JSON line → parse error logged (line 199) → offset advanced → line gone. | Yes, rare | No |
| **Backend down** | `post()` retries 3× with 0.5/1/2 s backoff (lines 55-69), then gives up. Command/download results are not checked (lines 130, 146). Only close keeps local state for a later retry that never comes. | **Yes** after ~3.5 s | No |
| **MongoDB down** | Backend returns 5xx → same as above. Closure analysis claimed but failing → `failed`, needs manual review. | Yes | No |
| **AI engine down** | Classification skipped, session still closed and saved. Q-learner not updated. The sweeper does not retry analysis. | Classification/Q update | No |
| **Replay with `--file` of an already-ingested log** | Session open is idempotent, but commands are appended again (`$concatArrays`, no event id) | No | **Yes: commands** |
| **Both plugin and parser enabled** | Every event twice (`honeypot/README.md:21-23`) | No | **Yes** |
| **Close event never arrives** | Sweeper closes after 6 h of inactivity, measuring duration to last activity (`honeypotSweepService.js:24-50`) | No | No |

### Status after the reliability fixes (working tree, 2026-10-21)

The table above describes the audited commit. Tests for each row: `ai-engine/tests/test_cowrie_parser_reliability.py` (9), `backend/tests/mediumHoneypot.test.js` (3 new, real in-memory MongoDB), `backend/tests/honeypotService.test.js` (3 new), `backend/tests/cowrieIngest.test.js` (4 new). None of it has been run against a live Cowrie.

| Scenario | Status | How | What is still not covered |
|---|---|---|---|
| Parser restarts | **FIXED** | `state.json` in `PARSER_STATE_DIR` holds inode, byte offset and open sessions, saved after every line; restart resumes there (`resume_position`). A session with no saved state is rebuilt from the event's `src_ip` (`_session_for`). | The very first start (no state) still begins at the end of the log unless `--from-start`. A crash between processing a line and saving state replays that one line (commands/downloads de-duplicated; a login could be recorded twice). |
| Cowrie restarts | No fix needed | — | The rotator's restart still drops live attacker sessions. |
| Log rotation | **FIXED** | The open handle reads the renamed file to its end before switching; after downtime the rotated file is found by inode and finished first. | If the rotated file was deleted or compressed while the parser was down, its unread lines are lost (logged as a warning). |
| Partial line | **FIXED** | `read_lines` never advances past a line without `\n`; it is read on the next poll. | — |
| Backend down | **FIXED** (parser path) | Transient failures (connection error, timeout, 429, 5xx) go to a durable `spool.jsonl`, replayed in order every 5 s; new events queue behind it; 4xx is still final. | Spool capped at 50,000 events (oldest dropped, logged). The disabled `sentinel_output.py` plugin has no spool. |
| MongoDB down | **FIXED** for delivery (same spool) | — | A closure that fails *during* analysis is still parked as `failed` for manual review: deliberate, so containment side effects are never repeated automatically. |
| AI engine down | **FIXED** | Closure sets `aiAnalysisPending` / `deceptionScoringPending`; the sweep retries only the pending step (`retryDeferredAnalysis`), at least 5 min apart, at most 5 times (`HONEYPOT_ANALYSIS_RETRY_MINUTES`, `HONEYPOT_ANALYSIS_MAX_RETRIES`). | After the last attempt the session stays flagged (visible, not analysed). The sweep runs every 15 min, so the first retry is up to ~15 min later. |
| Replay of an ingested log | **FIXED** | Each command/download carries `eventId` = hash of Cowrie's session, eventid, microsecond timestamp and payload; the backend's atomic update skips an id it has applied and raises no second alert or broadcast. | Demo-mode events have no timestamp, so no id (they are synthetic anyway). |
| Plugin and parser both enabled | **FIXED** for duplicates | The plugin computes the same `eventId`; session open/close were already idempotent. | Still not recommended: two delivery paths, only one with a spool. |
| Close event never arrives | Already handled | Sweep (unchanged). | — |

## 3.6 Verdict table

| Component | Status | Evidence | File |
|---|---|---|---|
| Cowrie install / runtime | **Untested** (not installed here); ran once historically in Docker | Search found nothing; session `9b21e8e00dd7` from 172.18.0.1 | none in repo |
| Cowrie Docker/compose | **Not Implemented** | not in repo or history | `docker-compose.yml:7-9` |
| `cowrie.cfg` | Untested live; sections **FIXED** | keys moved to `[ssh]`/`[shell]`, dead keys removed, `forwarding = false`, download size limit; generated from `switch_profile.py` | `honeypot/cowrie/cowrie.cfg` |
| `userdb.txt` | Working format; Untested live | 13 valid entries | `honeypot/cowrie/userdb.txt` |
| Custom fs / honeyfs / txtcmds | **Not Implemented** | NOT FOUND | — |
| JSON log → parser tail | Unit-tested, untested live; restart/rotation/outage/duplicate losses **FIXED** (3.5) | parser contract + reliability tests | `honeypot/parsers/log_parser.py` |
| Direct output plugin | Implemented, **disabled** | contract test passes | `honeypot/cowrie/sentinel_output.py` |
| Blocker plugin | **Untested** live | needs running Cowrie | `honeypot/cowrie/sentinelblocker.py` (then `sentinel_blocker.py`) |
| Backend ingest + validation | **Working** (tests) | 63 jest pass (mocked DB) | `backend/routes/honeypotIngest.js` |
| Atomic session updates / MongoDB writes | **Working** | tests + 8 real docs in DB | `backend/services/honeypotService.js:112` |
| Credential redaction | **Working** for new data; **legacy plaintext present** | session `9b21e8e00dd7`: 3,383 credential rows, all plaintext | `backend/utils/redact.js:227` |
| Session classification | **Working, rule-based, not ML**; substring false positives **FIXED** (v2) | regression tests in `test_honeypot_rules.py` | `ai-engine/utils/features.py` `classify_honeypot_session` |
| Q-learner math + persistence | **Working** (tests) | `test_q_learning_h6.py`, `test_q_table_safety.py`, `test_deception_credit_assignment.py` | `ai-engine/rl_engine/deception_scorer.py` |
| Q-learner trained on real attackers | **Mocked** | seed table 12,087 synthetic-pattern episodes; DB has 0 attacker sessions | `ai-engine/models/q_table.json` |
| Deception adaptation applied to Cowrie | **Partially / Untested** (optional rotator, cosmetic keys only) | `recommendationApplied: False` | `honeypot/deception_rotator.py` |
| Auto-block from honeypot | Implemented, **off by default** | `autoBlockEnabled` absent; 0 blocked IPs | `honeypotService.js:300-373` |
| Real firewall enforcement | **Mocked** by default; real path double-gated | adapter factory | `backend/services/containment/adapterFactory.js` |
| Socket events | **Working** (tests) | `websocket.test.js`, `socketRoomDelivery.test.js` exist | `backend/websocket/socketManager.js:319` |
| Dashboard page | Implemented; **Untested** live in this audit | — | `frontend/src/pages/HoneypotAnalytics.jsx` |
| Demo/seed generators | **Mocked** | 7 `demo-*` sessions in DB | `log_parser.py:248`, `backend/utils/seed.js` |
| Honeypot → model retraining | **Not Implemented** | no training script reads honeypot data | — |
| GeoIP enrichment | **Not Implemented** | `geoLocation` always `{}` from parser | `session_collector.js:12` |
| HTTP/FTP/SMTP decoys | **Not Implemented** | enum only; comment confirms | `HoneypotSession.js:29`, `honeypotService.js:527-529` |
| Retention | Implemented, **disabled by default**, manual | — | `backend/services/retentionService.js:1-17` |

### Status after the verdict-table fixes (working tree, 2026-10-21)

**Live end-to-end run (no Cowrie).** WSL's networking failed to start on this machine (`E_UNEXPECTED`, fallen back to no network) and sudo needs a password, so Cowrie could not be installed. Instead the real parser tailed a Cowrie-format JSON log written with live timestamps, feeding the real backend, AI engine, MongoDB and dashboard. It used an isolated database (`sentinel-honeypot-verify`), a scratch Q-table and a test admin; `sentinel-db` and the real Q-tables were not touched. Results: 19/19 pipeline checks passed, plus:
- a backend outage: 4 events queued on disk, all delivered in order after restart
- the dashboard refreshing live
- a 6-event burst causing exactly 1 reload
- a DEMO badge, with the Q-table unchanged by a demo session

Per-command ingest latency, Cowrie event to MongoDB: **64–887 ms**. What this does **not** cover is Cowrie itself: SSH, the fake shell, its log writer and the blocker plugin inside a running Cowrie.

| Component | Now | What changed / evidence | Still open |
|---|---|---|---|
| Cowrie install / runtime | **Untested** (blocked) | — | Needs working WSL networking or a Linux host; then run section 3.3. |
| Cowrie Docker/compose | **Implemented, untested** | `honeypot/docker-compose.honeypot.yml` (non-root, read-only, no capabilities, CPU/memory/pids limits, own bridge), `honeypot/parsers/Dockerfile`, `honeypot/docker/egress-rules.sh` (bridge may reach only the ingest port) | Docker not available here; image paths and that the image has `requests` must be checked. |
| `cowrie.cfg` / `userdb.txt` | Untested live | — | Needs Cowrie. |
| Custom fs / honeyfs / txtcmds | **Partially implemented** | `honeypot/build_honeyfs.py`: one honeyfs per Linux persona (no `phil`, distro user, matching os-release/issue/hostname/proc/version); opt-in `COWRIE_PERSONA_HONEYFS` in `switch_profile.py`; 4 tests | `fs.pickle` unchanged (`ls /home` still shows phil); no txtcmds; windows_srv has none. |
| JSON log → parser tail | **Working** (live tail, no Cowrie) | E2E: ordering, redaction, partial line, duplicate, outage spool | Rotation not exercised live (Windows cannot rename an open file; covered by unit tests). |
| Direct output plugin | Disabled by design | — | — |
| Blocker plugin | **Unit-tested**, bug fixed | Each connection from an IP not yet cached started a thread + HTTP request (flood → unbounded threads); now an in-memory lookup of the list synced every 2 s. 7 tests with stand-in Cowrie factories | Not run inside a real Cowrie. |
| Backend ingest, MongoDB writes, socket events | **Working** (live) | E2E | — |
| Credential redaction | Working for new data (live); **legacy session FIXED** | E2E: stored as `***REDACTED***`; 2026-10-21: all 3,383 entries of `9b21e8e00dd7` redacted after a full backup (`backups/sentinel-db-2026-10-21T18-13-22-733Z`, git-ignored) | The 14 fake passwords in the 7 `demo-*` sessions were redacted too: no plaintext password remains in `honeypotsessions`. The backup keeps the original plaintext: delete it once no longer needed. |
| Session classification | Working (live, v2 rules) | E2E: RCE Attempt 0.98, brute force 0.90 | Rule-based by design. |
| Q-learner trained on real attackers | **Labelled honestly** (still synthetic seed) | Runtime table records `seed_provenance`; stats and dashboard say "N updates from scored sessions; 12087 inherited from a synthetic warm start, not attacker data"; `DECEPTION_COLD_START=1` starts empty; 4 tests; E2E shows 8 session updates | Only real attacker traffic can change this. |
| Deception adaptation applied to Cowrie | Partially (now can change file contents) | honeyfs personas above | Rotator still needs admin credentials (C3) and restarts Cowrie. |
| Auto-block / real firewall | Off / mock by design | E2E: 0 blocks | Design choice, not a defect. |
| Dashboard page | **Working** (live) | Logged in, honeypot page renders, live refresh, provenance line, DEMO badge, no console errors | — |
| Demo/seed generators | Synthetic, now **labelled** | DEMO badge; demo sessions skip the Q-learner (E2E: episodes unchanged) | Seed `sess-*` sessions are not badged. |
| Honeypot → retraining, HTTP/FTP/SMTP decoys | **Not implemented** | — | Multi-day features (section 5.3). |
| GeoIP enrichment | **Not implemented** | — | No data source: no GeoLite2 database, no `ABUSEIPDB_API_KEY`. |
| Retention | Disabled by default (design) | — | Turning on automatic deletion is a policy decision. |

### Status after the live Cowrie run (working tree, 2026-10-22)

WSL networking came back, so real Cowrie (git `c7773f4`, 2026-10-15; Twisted 26.4.0, Python 3.14) was installed in a user venv at `~/sentinelai-cowrie-test` in WSL Ubuntu. No sudo was used and nothing was installed system-wide; delete that folder to remove it.

It ran with this repo's `cowrie.cfg`, `userdb.txt`, blocker plugin and persona filesystems. Real SSH sessions from paramiko then flowed through Cowrie's own JSON log to the parser (on Windows, over `\\wsl.localhost`, where inodes match Linux), backend, AI engine and MongoDB. That used the isolated test database again; `sentinel-db` was not touched.

WSL cannot reach the Windows backend in NAT mode, and opening a firewall path was not an option, so the blocker read its deny-list from a stub at 127.0.0.1:5099. That stub is the only stand-in in this run.

**Bugs the live run found (all fixed):**
1. **The blocker plugin could never load.** Cowrie loads `[output_X]` as module `cowrie.output.<section.split("_")[1]>`, so `[output_sentinel_blocker]` asked for `sentinel` and failed with an ImportError. Every block was unenforced on the honeypot. Renamed to `sentinelblocker` (`honeypot/cowrie/sentinelblocker.py`, `[output_sentinelblocker]`), with a regression test applying Cowrie's rule to our config (`tests/test_cowrie_config_contract.py`).
2. **Every session had duration 0.** Current Cowrie writes `duration_ms`; the parser read only `duration`. It now reads both (`session_duration_seconds`, 4 tests). Duration feeds the Q-learner's reward.
3. **The honeyfs builder assumed a honeyfs directory that current Cowrie no longer ships.** File contents now live inside `fs.pickle`. `build_honeyfs.py --fs-pickle` writes one complete pickle per persona (`[shell] filesystem`, via `COWRIE_PERSONA_FS`), which also renames `/home/phil`. Symlinks are resolved from the tree root, as Cowrie does. The directory mode stays for older Cowrie.
4. **Stock Cowrie's `/etc/os-release` is empty** (a fingerprint in itself); the persona pickles fill it.
5. `max_sessions` is not read by Cowrie (dead key, removed). `interactive_timeout` is read.

**Verified live:**

| Check | Result |
|---|---|
| Our config loads; keys in the sections Cowrie reads | Yes (checked against Cowrie's `cowrie.cfg.dist`) |
| Persona consistency (centos_7) | Banner `OpenSSH_7.4`, hostname, kernel `3.10.0-1160.el7`, CentOS `os-release`, `/home/centos`, no `phil` |
| `userdb.txt` | `root/123456` accepted; wrong passwords rejected (5/5) |
| `forwarding = false` | direct-tcpip channel refused |
| Blocker plugin inside Cowrie | Loaded; blocked IP refused within one sync; allowed again after unblock |
| Pipeline from real Cowrie events | 11 sessions, each once: commands, redacted credentials, HASSH, rule class, Q-learner score, `servedProfile` |
| Parser restart | Session written while the parser was down was ingested after restart (3 commands, duration 7 s) |
| Log rotation (Linux semantics) | Log renamed while the parser held it open; sessions before and after both ingested once, no duplicates |
| Closed deception loop | Recommendation `ubuntu_22` → rotator (honeypot key only) rewrote config, Cowrie restarted (supervisor) → attacker sees Ubuntu banner, hostname, kernel, `os-release`, `/home/ubuntu` → backend recorded `ubuntu_22`, audit actor `honeypot-rotator` → next session credited `servedProfile: ubuntu_22` |
| `wget` | Refused by Cowrie for local targets (by design, see 3.3) |

**C3 fixed:** the rotator uses `HONEYPOT_API_KEY` on `GET /api/honeypot/ingest/deception/recommendation` and `PUT /api/honeypot/ingest/deception/profile`. These accept only the honeypot key (not `SENTINEL_KEY`, not a user token) and only the six persona names, and every write is audited as `honeypot-rotator`. 7 backend tests, 1 rotator test and role-matrix entries cover them. The admin-login path remains as a deprecated fallback.

**Rows still open:**
- **Docker stack:** untested; no Docker here.
- **Blocker against the real backend:** the backend side (`check-block`) is unit-tested, but the WSL↔Windows hop wasn't run.
- **Real downloads:** need outbound internet.
- **Persona fidelity:** windows_srv has no filesystem; no txtcmds; command output such as `lsb_release` and the package list is still Cowrie's default.
- **Seed `sess-*` sessions:** not badged.
- **Not implemented:** retraining, multi-protocol decoys, GeoIP.
- **By design:** retention, auto-block and the firewall are off or mock by default.

---

# PHASE 4: Issues audit

## Critical

**C1. [FIXED 2026-10-21: session `9b21e8e00dd7` (3,383 entries) and 7 `demo-*` sessions (14 fake entries) redacted after a backup; 0 plaintext left] Plaintext captured passwords still in MongoDB.**
- *Where:* local `sentinel-db.honeypotsessions`, session `9b21e8e00dd7` (3,383 rows, none redacted). Written before redaction existed.
- *Why it matters:* the code and paper say passwords are redacted. Your own database contradicts that, and an examiner or demo could show it.
- *Fix:* read `scratch/scrub_honeypot_credentials.mjs`, back up (`scratch/backup_sentinel_db.mjs`), run the scrub, then re-query. Equivalent one-off:
  ```js
  db.honeypotsessions.updateMany({ 'credentials.password': { $ne: '***REDACTED***' } },
    [{ $set: { credentials: { $map: { input: '$credentials', in: { username: '$$this.username', password: '***REDACTED***', success: '$$this.success' } } } } }])
  ```
  Also delete or restrict raw `cowrie.json` on the honeypot host: it always holds plaintext.

**C2. No honeypot isolation exists in the repository.**
- *Where:* no Cowrie container, network policy, egress rule or resource limit anywhere (`docker-compose.yml:7-9` defers it to "a separate host").
- *Why it matters:* Cowrie emulates the shell, but `wget`/`curl` make **real outbound requests**, downloads land on disk, and SSH `direct-tcpip` forwarding can turn the honeypot into a proxy. Check `[ssh] forwarding` in your Cowrie version's `cowrie.cfg.dist`; it defaults to enabled in common releases. The same host also holds `HONEYPOT_API_KEY` and, if you run the rotator, **an admin password** (C3).
- *Fix (see 5.2):* run Cowrie in its own container or VM on an isolated network, as non-root, read-only image, `cap_drop: ALL`, CPU/memory/pids limits, egress denied except to the backend ingest port, `forwarding = false`, `download_limit_size` set.

**C3. [FIXED 2026-10-22: rotator uses HONEYPOT_API_KEY on two honeypot-only endpoints; verified live] The rotator puts SentinelAI admin credentials on the honeypot host.**
- *Where:* `honeypot/deception_rotator.py:14-19, 112-115` needs an admin account with `settings:write`, while `honeypot/README.md:18` says the honeypot host should hold only `HONEYPOT_API_KEY`.
- *Why it matters:* the honeypot is the machine you *expect* to be attacked. Anyone who escapes Cowrie gets a dashboard admin login: a pivot from decoy to defence platform.
- *Fix:* add a machine-key endpoint scoped to deception only, e.g. `PUT /api/honeypot/ingest/deception/profile` behind `internalAuth` that only accepts the 6 profile names, and change the rotator to use `HONEYPOT_API_KEY`. Or run the rotator on the SentinelAI host and push only the config file.

## High

**H1. [FIXED: state file, rotation drain, partial-line check, durable spool; see 3.5] Ingestion loses events silently.** `log_parser.py:215` (seek to end), 123 (post-restart commands dropped), 130/146 (result ignored), 231-236 (partial lines), 55-69 (give up after ~3.5 s).
- *Fix:* persist `(inode, offset)` to a state file after each acknowledged line; on start resume from it; only advance past a line once it ends with `\n`; spool failed POSTs to a local JSONL queue and retry. Sketch:
  ```python
  STATE = Path(os.getenv("PARSER_STATE", "parser_state.json"))
  def load_state(): return json.loads(STATE.read_text()) if STATE.exists() else {}
  def save_state(ino, pos): STATE.write_text(json.dumps({"ino": ino, "pos": pos}))
  # in tail(): if saved ino == current ino: seek(saved pos) else seek(0)
  # in the read loop: if not line.endswith("\n"): break   # wait for the rest
  ```
  Or replace the tailer with a proven shipper (Filebeat/Fluent Bit/Vector), or Cowrie's own output plugin plus a local disk queue.

**H2. [FIXED: whole program names, duration rule removed, `honeypot_rules_v2`] Rule classifier false positives can trigger blocks.** `features.py:363-368` uses raw substrings: `nc` matches `sync`, `function`, `rsync`; `sh` matches `ssh`, `bash`, `shadow`, `.sh`; `tar` matches `start`; any logged-in session over 120 s becomes Data Exfiltration (0.95+). With `autoBlockEnabled` on, these exceed the 0.92 block line.
- *Fix:* tokenise and match whole commands, and drop duration as an exfiltration signal:
  ```python
  import shlex
  def _tools(cmds):
      out = set()
      for c in cmds:
          for part in re.split(r"[;&|]+", str(c.get("command", ""))):
              try: toks = shlex.split(part)
              except ValueError: toks = part.split()
              if toks: out.add(os.path.basename(toks[0]).lower())
      return out
  EXFIL = {"scp","sftp","ftp","rsync","tar","zip","nc","netcat","ncat"}
  ```
  Add tests for `sync`, `history`, `start`, and long idle sessions.

**H3. A leaked `HONEYPOT_API_KEY` can make SentinelAI block arbitrary IPs and pollute the Q-table.** `honeypotIngest.js:9-14` accepts any well-formed `sourceIP`. `/close` with fake commands drives `analyseClosure` → `executeAutoBlock` (if enabled) and `/deception/score`. Private IPs are not protected by default (`containmentPolicyService.js:11-17`).
- *Fix:* bind the key to the honeypot host's IP (check `req.ip`); set `CONTAINMENT_PROTECTED_TARGETS` to your LAN and gateway; require human approval for honeypot-originated blocks; rotate the key; keep the 20,000/15 min service rate limit (`server.js:91-98`) but alert on bursts.

**H4. [PARTLY FIXED: `demo-*` sessions no longer reach `/deception/score` (`honeypotService.finishClosure`); the seed table is unchanged] Shipped Q-table and demo sessions misrepresent "learning from attackers".** `ai-engine/models/q_table.json` has 12,087 episodes with repeating rewards. `log_parser.py --demo` posts through the real path, so demo sessions update the live Q-table.
- *Fix:* reset to a zero table (or label the seed "synthetic warm-start" in the paper); skip Q updates for `sessionId` starting `demo-`, `sess-` or `test-` in `honeypotService.finishClosure`:
  ```js
  const SYNTHETIC = /^(demo|sess|test)-/i
  const decRes = SYNTHETIC.test(session.sessionId) ? null : await aiSvc.getDeceptionScore(payload)
  ```

**H5. [PARTLY FIXED: keys now in `[shell]`/`[ssh]`; personas are still cosmetic] Personas are cosmetic and partly not applied.** `switch_profile.py:80-117` writes `kernel_*`/`hardware_platform` and `listen_endpoints` under `[honeypot]`; in Cowrie 2.x these live under `[shell]` and `[ssh]` (verify against your Cowrie's `cowrie.cfg.dist`). `windows_srv` advertises a Windows OpenSSH banner over a Linux bash shell. The default fake filesystem (and its tell-tale files) is the same for all six personas.
- *Fix:* move keys to the right sections; drop `windows_srv` or make it a separate honeypot; give each persona its own `honeyfs` (`/etc/os-release`, `/etc/issue`, `/proc/version`) and `txtcmds/` (`uname`, `lsb_release`), and point `[shell] filesystem` at a per-persona pickle made with Cowrie's `createfs`.

## Medium

**M1. Every connection creates a HIGH ThreatLog before analysis.** `session_collector.js:12` writes a fixed `HIGH, 0.75, "SSH Brute Force"`. A bot hitting you 1,000 times/day produces 1,000 HIGH threats. *Fix:* create the ThreatLog at close (or with severity `LOW`/status `DETECTED`, then raise), and aggregate by IP per hour.

**M2. Per-command CRITICAL alerts with no de-duplication.** `session_collector.js:15-16`. *Fix:* one alert per `(sessionId, intent)`: check for an existing alert, or use a unique key.

**M3. [FIXED: events coalesced into at most one reload per 1.5 s] Dashboard refetch storm.** `HoneypotAnalytics.jsx:64-70` makes 3 REST calls per socket event per open browser. A 200-command session = 600 calls per tab, and the per-IP limit is 1,000 / 15 min (`server.js:85-89`). *Fix:* debounce:
  ```js
  const t = useRef(); const reload = () => { clearTimeout(t.current); t.current = setTimeout(load, 1500) }
  const unsubOpen = on('honeypot_session_opened', reload) // same for the others
  ```

**M4. Unbounded arrays → 16 MB document limit.** `credentials` (3,383 already), `commands` (no count cap; each ≤ 2,048 chars). *Fix:* `$slice` the arrays in `recordSessionActivity` (keep the last N, count the rest), or move commands to their own collection keyed by `(sessionId, seq)`.

**M5. No retention or TTL for honeypot data.** `retentionService.js` is opt-in and manual. *Fix:* schedule it weekly with `RETENTION_ENABLED=true`, or add a TTL to raw commands if you split them out. Keep aggregates.

**M6. [FIXED: eventId, see 3.5] Duplicate commands on replay; no event id.** `$concatArrays` in `honeypotService.js:123`. *Fix:* send Cowrie's `(session, timestamp, input)` hash as `eventId` and add `{ $not: { $in: [eventId, '$eventIds'] } }` guarding, or a separate collection with a unique index.

**M7. Q-learner state ignores the attacker; credit can be misattributed.** State = previous persona only. `servedProfile` is read at **close** time (`honeypotService.js:238`), so a session that spans a persona switch is credited to the new persona. *Fix:* stamp `servedProfile` at session open in `onSessionOpened`; describe the method as a contextual bandit.

**M8. [FIXED: new marker `[HONEYPOT_RULES_RECLASSIFIED]`; the UI shows "Rule-reclassified" for both new and legacy markers] Mislabelled provenance note.** `honeypotService.js:335-339` rewrites the ThreatLog note to `[RF_IF_RECLASSIFIED] RF/IF inference replaced …`, but honeypot classification is rules (`predictor.py:529-575`). *Fix:* use `[HONEYPOT_RULES_RECLASSIFIED]`.

**M9. Missing index in live DB; sweeper query not indexed.** `commands.command+createdAt` is not built. Sweeper filters `{status, updatedAt}` (`honeypotSweepService.js:27`). *Fix:* `HoneypotSession.syncIndexes()` once; add `HoneypotSessionSchema.index({ status: 1, updatedAt: 1 })`.

**M10. Downloaded malware stored with no handling policy.** `download_path` on the Cowrie host (`cowrie.cfg:12`), no size limit, no quarantine, no hashing pipeline beyond Cowrie's `shasum`. *Fix:* `download_limit_size = 10485760`, a separate non-executable volume (`noexec`), hash-only forwarding, optional VirusTotal hash lookup (never upload without consent).

## Low

**L1. [FIXED]** `cowrie.cfg:29-31` `[userdb]` section and `auth_class_parameters` (line 11) are ignored by Cowrie's UserDB. Remove them to avoid confusion.
**L2. [FIXED: PCAP off in both]** `switch_profile.py:105` enables PCAP output while the shipped `cowrie.cfg:26` disables it: inconsistent and fills disk.
**L3.** `qDeceptionScore` can be negative (e.g. −6.6 for a fingerprinting session): `deception_scorer.py:401` clamps only the top. Clamp at 0 or document it.
**L4.** `/api/honeypot/nodes` reports "active" based on sessions, not liveness (`honeypotService.js:536`). Add a Cowrie heartbeat (e.g. the blocker's 2 s poll updates `lastSeen`).
**L5.** Seed sessions `sess-…` are not excluded by retention/demo filters (only `demo-`), so seeded data looks real (`seed.js:133`, `retentionService.js:45`).
**L6.** Default persona fallback differs: backend `centos_7` (`honeypotService.js:23`), Q-learner `ubuntu_22` (`deception_scorer.py:385`), schema default `ubuntu_22` (`HoneypotSession.js:57`).
**L7.** Port 2222 with no 22 redirect: internet bots mostly hit 22. Use `iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222` (and move real SSH elsewhere).
**L8.** `internalAuth` also accepts `SENTINEL_KEY` on honeypot routes (`honeypotIngest.js:12`), which widens the AI engine key's powers.

## Security checks that passed

- **NoSQL injection:** attacker strings are wrapped in `$literal` in the update pipeline (`honeypotService.js:102-104`); `sessionId`/`sourceIP` are type- and format-checked.
- **XSS:** no `dangerouslySetInnerHTML`/`innerHTML` anywhere in `frontend/src` (grep). React escapes `{c.command}` text. Toasts take plain strings.
- **Viewer privacy:** commands, IPs, credentials redacted for viewers (`redact.js:90-120`; `socketManager.js:322-347`).
- **Q-table integrity:** atomic write, lock, merge, and refusal to write the shipped model (`deception_scorer.py:241-323`).
- **Closure idempotency:** compare-and-set claim prevents double analysis and double blocks (`honeypotService.js:189-221`).

## Paper vs code

| Paper claim (`paper_text.txt`) | Code reality |
|---|---|
| "validated end-to-end … Q-learning agent recommends adaptive honeypot profiles based on **live attacker engagement**" (l.29-34) | No real attacker sessions in DB; seed Q-table is synthetic-pattern. Say "validated with local test sessions". |
| MDP state "encodes … commands issued, tools used, probing patterns, interaction duration, fingerprinting attempt count, current configuration" (l.~628) | State = previous persona only. Behaviour appears only in the **reward**. |
| Actions: "OS profile switching, service banner rotation, timing jitter injection, artifact planting" | Hostname/kernel/banner strings only. Jitter and artefacts **NOT FOUND**. |
| "recommendation is not automatically applied" (l.~650) | Still true by default, but `deception_rotator.py` now exists. Mention it as optional and not live-validated. |
| Adaptive Honeypot Engine "redirecting suspected attacker traffic to decoy nodes" (l.~449) | **NOT FOUND**. |
| "feeding interaction logs back to the Detection Engine for retraining" (l.~450) | **NOT FOUND**. |
| "pool of honeypot nodes" | One node, SSH only. |
| Objective "≥40% engagement vs static baseline" (l.~426) | No experiment or measurement **found**. Present it as a target, not a result. |
| ε-greedy with decaying ε | Correct, with a 0.05 floor (`deception_scorer.py:117, 325`). |

---

# PHASE 5: Improvements

## 5.1 Quick wins (under 1 hour each)

| Change | Effort | Impact | Files |
|---|---|---|---|
| Scrub legacy plaintext credentials (C1) | 15 min | Critical honesty/privacy | DB only; `scratch/scrub_honeypot_credentials.mjs` |
| Fix `cowrie.cfg` sections: `[ssh] listen_endpoints`, `[shell] kernel_version/kernel_build_string/hardware_platform/operating_system`, remove `[userdb]` and `auth_class_parameters`, add `[ssh] forwarding = false`, `[honeypot] download_limit_size = 10485760` | 30 min | High (personas take effect, less pivot) | `honeypot/cowrie/cowrie.cfg`, `honeypot/switch_profile.py` |
| Customise fingerprints: hostname per persona (done), add `honeyfs/etc/os-release`, `/etc/issue`, `/etc/motd`; remove the default `phil` user from `/etc/passwd` in honeyfs | 45 min | High against fingerprinting | new `honeypot/cowrie/honeyfs/…` |
| `syncIndexes()`, add `{status, updatedAt}` index | 10 min | Medium | `backend/models/HoneypotSession.js` |
| Debounce dashboard refetch (M3) | 15 min | Medium | `frontend/src/pages/HoneypotAnalytics.jsx` |
| Fix `[RF_IF_RECLASSIFIED]` label (M8) | 5 min | Viva honesty | `backend/services/honeypotService.js:335-339` |
| Skip Q updates for synthetic sessions (H4) | 15 min | High honesty | `backend/services/honeypotService.js:418` |
| Clamp `qDeceptionScore` ≥ 0 (L3) | 5 min | Low | `ai-engine/rl_engine/deception_scorer.py:401` |
| Escape output: already safe (React); add a test rendering `<img src=x onerror=alert(1)>` as a command | 20 min | Evidence for viva | `frontend/tests/` |

## 5.2 Must-fix before demo/viva

1. **Isolation (C2).** Half a day. Run Cowrie in Docker on WSL with a dedicated network:
   ```yaml
   # honeypot/docker-compose.honeypot.yml (new)
   services:
     cowrie:
       image: cowrie/cowrie:latest        # pin an exact tag/digest
       user: "999:999"
       read_only: true
       cap_drop: [ALL]
       security_opt: ["no-new-privileges:true"]
       pids_limit: 200
       mem_limit: 512m
       cpus: 0.5
       ports: ["127.0.0.1:2222:2222"]     # local demo only
       volumes:
         - ./cowrie/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
         - ./cowrie/userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
         - ./cowrie/sentinelblocker.py:/cowrie/cowrie-git/src/cowrie/output/sentinelblocker.py:ro
         - cowrie-var:/cowrie/cowrie-git/var
       environment: [HONEYPOT_API_KEY, SENTINEL_API_URL]
       networks: [honeynet]
   networks:
     honeynet: { internal: true }   # no internet egress; add a single allowed route to the backend
   volumes: { cowrie-var: {} }
   ```
   Check paths against the image's documentation; they differ between versions. `internal: true` blocks egress entirely, including to the backend, so either put the parser in the same network with a second network to the backend, or add a host firewall rule allowing only `backend:5000`.
2. **Reliable ingestion (H1).** 2–4 h: offset persistence, newline check, local retry spool, metrics (events read / posted / failed). Add parser tests for restart, rotation and partial lines.
3. **Remove admin creds from the honeypot host (C3).** 1–2 h.
4. **Fix classifier substrings (H2)** and add regression tests. 1 h.
5. **Honest labelling.** 1 h: in the paper and UI say "rule-based session classification", "Q-learning recommender; optional rotator applies cosmetic persona changes (not validated live)", "synthetic warm-start Q-table", "Mock containment by default".
6. **Run the Phase 3 test plan once and keep the evidence** (JSON lines, Mongo docs, Q-table before/after, screenshots, latency numbers).

## 5.3 Upgrades

| Upgrade | Effort | Impact | Files |
|---|---|---|---|
| **More protocols**: Dionaea (SMB/HTTP/FTP malware capture), or T-Pot for many sensors; a new parser per sensor posting to the same ingest API with a `honeypotNode` from the existing enum | 2–5 days | High coverage | new `honeypot/parsers/dionaea_parser.py`; `HoneypotSession.js` enum; `honeypotService.getNodeStatus` |
| **Session replay**: enable Cowrie TTY logs (`cowrie.log.closed` gives `ttylog` path); store path/hash; play with Cowrie's `playlog`, or convert to asciinema for the dashboard | 1–2 days | High for analysts | collector, new endpoint, new React player |
| **Attacker profiling**: group by HASSH, client version (`cowrie.client.version`), credential lists, command n-grams; extend `campaignService` | 2–3 days | High | `backend/services/campaignService.js` |
| **MITRE ATT&CK**: already maps intents (`backend/utils/mitreMapping.js`); extend to per-command techniques (T1059.004, T1105, T1053.003, T1082, T1003.008) with tests | 1 day | Medium (viva-friendly) | `mitreMapping.js` |
| **Threat intel**: offline GeoLite2 for `geoLocation` at ingest; AbuseIPDB lookup via the existing `threatIntelService` for honeypot threats (currently only threats created by `aiService.storePrediction` are enriched, `aiService.js:203-215`) | 1 day | Medium | `session_collector.js`, `threatIntelService.js` |
| **Supervised retraining from honeypot data**: export closed sessions (features: commands, intents, duration, login, IOC counts) with labels confirmed by analyst triage; train a session classifier to replace the keyword rules; evaluate on a time-split holdout | 1–2 weeks | High, academically strong | new `ai-engine/training/train_session_classifier.py`, `predictor.predict_from_honeypot` |
| **Dynamic deception**: per-persona `honeyfs`/`txtcmds`/fs pickles; rotate without dropping sessions by running two Cowrie instances and switching the port redirect; a richer action space (planted credentials files, fake `.aws/credentials` canaries) | 1–2 weeks | High: makes "adaptive" real | `switch_profile.py`, `deception_rotator.py`, new honeyfs trees |
| **Proper RL framing**: contextual bandit with context = early-session features (client version, HASSH, first commands), or keep UCB1 (already implemented: `DECEPTION_POLICY=ucb1`) and run an A/B experiment vs a static persona to test the 40% objective | 1 week + data collection time | High for the paper | `deception_scorer.py`, an experiment script |
| **Malware sandbox**: forward only hashes; optional local CAPE/Cuckoo VM or a VirusTotal hash lookup; never execute on the Cowrie host | 1 week | Medium | new service |

## 5.4 Production-readiness

| Item | Effort | Files |
|---|---|---|
| Honeypot compose file (5.2) plus parser container with a state volume | 1 day | `honeypot/docker-compose.honeypot.yml`, `honeypot/parsers/Dockerfile` |
| Monitoring: parser exports `events_read_total`, `events_posted_total`, `events_failed_total`, `lag_seconds`; Prometheus alert when Cowrie heartbeat is stale > 2 min | 1 day | `log_parser.py`, `deployment/prometheus/alerts.yml` |
| Structured JSON logs in the parser (`LOG_FORMAT=json`, already used by the backend) | 2 h | `log_parser.py` |
| Parser tests: rotation, truncation, partial lines, restart with saved offset, unknown eventid, malformed JSON, backend 5xx/429 | 1 day | `ai-engine/tests/test_cowrie_parser*.py` |
| Alerting on honeypot-originated block requests (human approval) | 1 day | `honeypotService.js`, containment policy |

---

# PHASE 6: Viva prep

## 6.1 Likely questions with honest answers

**1. Why Cowrie?**
It is the standard open-source medium-interaction SSH/Telnet honeypot. It implements real SSH, so bots and humans interact normally, while the shell is emulated, so nothing executes on the host. It logs structured JSON events we can parse, and SSH brute force is the most common attack on internet-facing Linux hosts.

**2. What interaction level is it, and why that level?**
Medium. Low interaction would only show connection attempts and passwords. High interaction gives real command execution, which needs heavy containment we could not justify for a student project. Medium gives command-level intelligence at low risk.

**3. How is the attacker contained?**
Honest answer: by Cowrie's design. The shell is emulated in Python, Cowrie refuses to run as root, and the only enforcement we add is the blocker plugin refusing blocked IPs. Network isolation (container, no egress, resource limits) is documented as a deployment requirement ("separate host") and is not yet automated in the repository. I'd add a hardened container with no internet egress before any public exposure.

**4. Can an attacker escape or pivot?**
Not through the emulated shell. The real risks are Cowrie software vulnerabilities, outbound `wget`/`curl` fetches, SSH port forwarding, and secrets stored on the honeypot host. We store only an ingest API key there, never database credentials. The optional rotator needs admin credentials, which I identified as a risk and would replace with a scoped key.

**5. How do Cowrie events reach SentinelAI?**
Cowrie writes one JSON line per event. A Python parser tails the file every 0.5 s, maps event ids to REST calls with an API key, and the backend validates them, stores them in MongoDB with atomic updates, and pushes Socket.IO events to the dashboard.

**6. Is the honeypot verdict produced by your machine-learning model?**
No. Cowrie sessions have no packet-flow features, and our CICIDS-trained model labelled synthetic sessions benign, so the honeypot path uses transparent rules over login outcome, command keywords, IOCs and duration. It is labelled `modelType: rules` in the database. The ML models handle network flows.

**7. What is "adaptive" about the deception?**
A tabular Q-learner treats each OS persona as an action. After each session it computes a reward from engagement (duration, commands, malicious intents, IOCs, successful login) minus a penalty for fingerprinting commands, updates Q-values, and recommends the next persona. By default that recommendation is shown, not applied. An optional rotator can apply it by rewriting the Cowrie config and restarting. Today a persona changes hostname, kernel strings and banner only.

**8. Why Q-learning and not PPO or DQN?**
The action space is six discrete personas and the state is the previous persona, a 6×6 table. Tabular Q-learning is interpretable, sample-efficient and needs no neural network. Since the state carries little information, the problem is close to a multi-armed bandit, so we also implemented UCB1 as an alternative policy.

**9. What does the Q-learner's state contain?**
Only the persona served in the previous session. Attacker behaviour enters through the reward, not the state. Adding attacker context would make it a contextual bandit; that is future work.

**10. How do you stop reward hacking?**
The reward is clipped to [−10, 20], duration is log-scaled, fingerprinting is penalised, stale sessions are closed by a sweeper that measures duration to last activity, and the Q-update endpoint is never retried. Remaining weaknesses: a bot can inflate commands up to the cap, and demo sessions currently update the table; I'd exclude them.

**11. Has the Q-learner learned from real attackers?**
No. It has been tested with unit tests and local sessions. The shipped table is a warm start from scripted sessions. Measuring the 40% engagement objective needs a real exposure period and an A/B comparison against a static persona.

**12. Can a honeypot event block an IP?**
Yes, if an administrator enables auto-block and the session's score reaches 0.92. The IP goes on SentinelAI's deny-list, which the Cowrie plugin enforces for new connections within about 2 s. The firewall adapter is a mock by default; a real Windows Firewall rule needs two explicit environment flags. Loopback and protected ranges can never be blocked.

**13. How do you protect captured data and the dashboard?**
Passwords are redacted at ingest; viewers see masked IPs and redacted commands; attacker strings are stored with `$literal` so they cannot act as MongoDB operators; React escapes all output and there is no raw HTML rendering. One legacy record from before redaction must be scrubbed. *(Do it first, so this answer is true.)*

**14. Legal and ethical concerns?**
A honeypot is your own system, so monitoring it is generally lawful, but: (a) logging credentials and IPs is personal data under GDPR / India's DPDP Act 2023, so minimise and retain briefly, which is why we redact passwords; (b) you must not let it attack third parties (downstream liability), hence egress control; (c) entrapment does not apply to passive decoys; (d) get written permission from whoever owns the network or cloud account; (e) handle captured malware as hazardous material. For this project it only runs locally.

**15. What happens if parts fail?**
Closure analysis is claimed atomically, so a session is analysed once; failures are parked for review. A sweeper closes abandoned sessions. Known gap: if the parser or backend is down, events are lost because the parser starts at the end of the log and has no local spool. The fix is offset persistence and a retry queue.

**16. How do you know the honeypot isn't trivially fingerprinted?**
We changed the hostname and banner and penalise fingerprinting commands in the reward, but the default Cowrie filesystem is unchanged, so a skilled attacker could detect it. Custom honeyfs and command outputs per persona are the next step.

## 6.2 Two-minute explanation (memorise)

> SentinelAI's deception layer is built on Cowrie, a medium-interaction SSH honeypot. Cowrie speaks real SSH on port 2222 and accepts a list of weak passwords, but the shell is emulated in Python, so nothing an attacker types runs on the host. Every action — connection, login attempt, command, download, disconnect — is written as a JSON event.
>
> A Python parser tails that log and sends each event to our Express backend with an API key. The backend validates the input, redacts passwords, and records the session in MongoDB with a single atomic update per event, extracting IOCs such as URLs and sensitive files and mapping commands to MITRE ATT&CK techniques. It pushes Socket.IO events so the dashboard updates live.
>
> When a session closes, the backend asks the FastAPI engine for a verdict. Cowrie has no network-flow features, so this verdict comes from transparent rules, not the Random Forest. It is stored as a rule-based prediction and can raise alerts or, if an administrator has enabled auto-block, add the IP to a deny-list that our Cowrie plugin enforces within about two seconds. Firewall enforcement is a safe mock by default.
>
> The adaptive part is a tabular Q-learning agent. Each OS persona — Ubuntu, CentOS, Raspberry Pi and so on — is an action. The reward measures engagement: duration, command count, malicious intents, IOCs and a successful login, minus a penalty when the attacker runs honeypot-detection commands. After each session the agent updates its Q-table and recommends the next persona with an epsilon-greedy policy. By default that is a recommendation; an optional rotator script can apply it by rewriting Cowrie's configuration. What I have validated is the pipeline and the learner with tests and local sessions. Learning from real attackers and proving the engagement gain are the next steps.

## 6.3 Wording: implemented vs mocked vs future

**Say "implemented and tested":**
- Cowrie configuration, user database and a connection-blocking output plugin.
- JSON log parser that maps seven Cowrie event types to an authenticated ingest API.
- Validated, atomic MongoDB persistence with IOC extraction, MITRE mapping and password redaction.
- Rule-based session classification served by the AI engine.
- Tabular Q-learning recommender with ε-greedy (and UCB1) policies, bounded reward, fingerprint penalty and safe persistence.
- Real-time dashboard events with role-based redaction.
- Optional auto-block through the shared containment service (off by default).

**Say "simulated / mock":**
- Firewall enforcement uses a mock adapter by default; real Windows Firewall rules are behind two explicit safety flags.
- Demo mode and the seed script generate synthetic sessions for UI testing.
- The shipped Q-table is a synthetic warm start, not learned from attackers.

**Say "implemented but not validated live":**
- Applying the Q-learner's recommendation (the deception rotator) and the Cowrie blocker plugin.

**Say "future work":**
- Isolated honeypot deployment (container/VM, no egress) in the repository.
- Personas that change the fake filesystem and command output, not just strings.
- Attacker-aware state (contextual bandit) and an A/B test of the 40% engagement target.
- Feeding honeypot sessions into model retraining.
- Extra protocols (HTTP/SMB via Dionaea or T-Pot), session replay, GeoIP enrichment, malware sandboxing.

**Never say:** "the honeypot is classified by the Random Forest", "the system automatically reconfigures Cowrie", "learned from live attackers", "traffic is redirected to decoys", "multiple honeypot nodes", "honeypot data retrains the model".
