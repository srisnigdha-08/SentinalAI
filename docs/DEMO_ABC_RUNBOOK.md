# Demo A / B / C operator runbook (verified 2026-11-02)

The authoritative short procedure for the three demonstrations:
- **Demo A — Honeypot Intelligence**
- **Demo B — AI Threat Detection**
- **Demo C — Autonomous Incident Response**

Talk track, examiner questions and the full honesty table: [`THREAT_DEMO_RUNBOOK.md`](THREAT_DEMO_RUNBOOK.md). RBAC and
session walkthrough: [`DEMO_RUNBOOK.md`](DEMO_RUNBOOK.md).

**What is real and what is not** (say it once, early):
- **Real:** the Cowrie SSH honeypot in WSL and its sessions; the XGBoost + Isolation Forest inference;
  MongoDB persistence; Socket.IO updates; the honeypot's own refusal of deny-listed IPs.
- **Replayed:** network flows. They are **recorded CICIDS2017 flow records** sent to the engine, not live packet
  capture.
- **Simulated:** the firewall. Containment runs through the **mock adapter**. **No host-firewall rule is created**,
  and the Windows Firewall adapter is disabled and has never been run live.
- **Learned, but unproven:** persona choice. A tabular Q-learning recommender picks the persona and the rotator
  applies it. Whether it keeps attackers engaged longer than a fixed persona has **not** been measured.
- **Model accuracy:** 98.97 % on a de-duplicated random split. Detection of attack days and tools it never saw is
  poor: 3–51 % recall (`README.md`, `audit/ML_EVAL_PLAN.md`).

## 0. Evidence that this procedure works (2026-11-02)

| Check | Result | Evidence |
|---|---|---|
| Integration harness with live WSL Cowrie (Demos A, A-live, B, C, auth, outage) | **41 passed, 0 failed** (2026-11-02); **42 passed, 0 failed** with the per-threat explanation check (2026-11-03) | `scripts/integration/runs/20261102_145846`, `20261102_191411` |
| Same on MongoDB with `--auth` as least-privilege `sentinel_app` | **35 passed, 0 failed** | `scripts/integration/runs/20261102_150153` |
| Browser E2E: Chromium, Firefox, WebKit | 167 passed, 1 failed (known intermittent Firefox E2E-002; 40/40 when repeated alone) | `frontend/playwright-report` |
| Single-flow inference, idle machine | p95 **35 ms**; with SHAP p95 **47 ms**; engine ready in 4.6–6.1 s, 272 MB | `scripts/perf/engine_latency.py` |
| Per-threat explanation (batch 11, 2026-11-03) | engine `/explain/vector` p50 26 ms / p95 48 ms, 20/20 reproduced; end to end through the backend 90 ms on a replayed threat | `scripts/perf/engine_latency.py`; integration run `20261102_191411` (42/42) |

Not run, so not claimed: Docker Compose (Docker is not installed), nginx/TLS, real firewall enforcement.

## 1. Start (Windows PowerShell, repository root)

Prerequisites:
- MongoDB service running: `Get-Service MongoDB` shows **Running**;
- WSL Ubuntu with Cowrie in `~/sentinelai-cowrie-test/cowrie`;
- `backend/.env` present;
- `ai-engine/.venv`, `backend/node_modules` and `frontend/node_modules` installed.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-demo.ps1
```

This opens four windows: the engine on :8000, the backend on :5000 using the **`sentinel-demo`** database, the
frontend on :3000 and the Cowrie log parser. `sentinel-db` is never written to. The demo uses its own Q-table in
`%USERPROFILE%\.sentinelai\demo\`. Expected: three lines ending in `UP`.

In WSL (from the repository directory, e.g. `cd /mnt/c/Users/<you>/Desktop/Projects/sentinelai-complete`):

```bash
bash scripts/demo/cowrie-demo-mode.sh on       # Cowrie listens on the WSL IP; the blocker reaches the backend
bash scripts/demo/cowrie-demo-mode.sh status   # expect: threads 2, check-block HTTP 200
```

Back in PowerShell, open a "demo console" and load the addresses (no secrets in this file):

```powershell
. $env:USERPROFILE\.sentinelai\demo\demo-env.ps1   # sets SENTINEL_HONEYPOT_IP and SENTINEL_BACKEND_URL
```

Open **http://localhost:3000/login** and sign in with a demo account. Passwords are on your cue card, never in a
document.

Before Demo C (all on the **Settings** page, as admin):
1. Turn **Auto-block ON**.
2. In the blocked-IP list, **Unblock IP** the Windows host's WSL-side address if a rehearsal left it deny-listed.
   Otherwise the first SSH connection is refused.

## 2. Demo A — Honeypot Intelligence

**Optional, lab hygiene:** in WSL, back up the persona so you can restore it afterwards:
`cp ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg.pre-demo`.

| # | Do | Expect / point at |
|---|---|---|
| 1 | Services are up (§1) | Dashboard live dot connected |
| 2 | Demo console: `ssh -p 2222 root@$env:SENTINEL_HONEYPOT_IP` and log in with the lab credentials from Cowrie's `etc/userdb.txt` | Ubuntu banner; you are in a **fake** shell |
| 3 | Safe commands: `uname -a`, `whoami`, `cat /etc/passwd`, `ls /tmp`, `exit` | Cowrie returns fabricated output; nothing executes on a real host |
| 4 | **Honeypot** page | The session appears live with its commands (socket events `honeypot_session_opened`, `honeypot_command`, `honeypot_session_closed`) |
| 5 | Open the closed session | MITRE techniques, e.g. T1082 (`uname`), T1033 (`whoami`), T1003 / T1003.008 (`/etc/passwd`); rule-based classification (`honeypot_rules`, not the network model) |
| 6 | Same view | Threat score and deception score, plus the Q-learner score |
| 7 | **Honeypot → Adaptive Deception** panel (analyst/admin) | "Serving persona", the learner's recommendation and **"Decision …xxxxxxxx (already pending/just drawn)"**. REFRESH shows the **same** decision: it is drawn once per served persona and kept until applied or expired. Read-only DB view: `mongosh --quiet mongodb://127.0.0.1:27017/sentinel-demo --eval "db.deceptiondecisions.find({},{_id:0,decisionId:1,state:1,action:1,status:1,appliedProfile:1}).sort({createdAt:-1}).limit(3)"` |
| 8 | WSL: `bash scripts/demo/cowrie-demo-mode.sh rotate --once` | Rewrites `cowrie.cfg` for the decided persona, restarts Cowrie and records the persona with the decision id. It waits if attacker sessions are still open; `--force` overrides |
| 9 | Repeat step 7's `mongosh` query, then SSH in again (step 2) | The decision is `APPLIED`, and `appliedProfile` equals `action`. The new session shows that persona's hostname (e.g. `debian-prod-01`) and is credited to it |
| 10 | Dashboard | "Serving persona" equals the applied persona; the new session lists it |

If the decision's action equals the served persona, the rotator records a **keep** (no restart). That is a valid
outcome; say so.

**Restore the lab** (optional):
1. `cp …/cowrie.cfg.pre-demo …/cowrie.cfg`
2. `bash scripts/demo/cowrie-demo-mode.sh restart`
3. Record the persona as admin with `PUT /api/honeypot/deception/profile {"profile":"<original>"}`, or let the next
   rotation record it.
4. After the demo, run `bash scripts/demo/cowrie-demo-mode.sh off` to return Cowrie to 127.0.0.1.

## 3. Demo B — AI Threat Detection (recorded-flow replay)

| # | Do | Expect / point at |
|---|---|---|
| 1 | `Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/ready` | 200: models loaded |
| 2 | Same window as the engine log | At startup: model sha256 verified against `models/registry.json` and the 20-row golden set reproduced (`xgb_cicids_v1`, XGBoost + Isolation Forest) |
| 3 | Demo console: `cd ai-engine`, then `.\.venv\Scripts\python.exe demo\replay_cicids.py --target backend --rows 10 --delay 0.5 --backend-url $env:SENTINEL_BACKEND_URL --email <analyst email>`. The password is prompted, or comes from `$env:SENTINEL_DEMO_PASSWORD`, and is never shown | Ten **recorded CICIDS2017 Friday** flows are sent one by one |
| 4 | Replay output / engine log | The engine validates every record against its 53-feature schema: malformed values get 422. A record with many defaulted features is marked incomplete and can raise a threat but is never auto-blocked |
| 5 | **Threat Logs** | Every non-BENIGN prediction at or above the **0.90 alert line** becomes a ThreatLog |
| 6 | Threat row | Severity from the score: **CRITICAL** at or above the 0.92 block line, **HIGH** from 0.90; attack type; AI confidence |
| 7 | **Dashboard** | Live feed and counters update without reload (`new_threat`, `ai_prediction`) |
| 8 | **Threat Logs → Explain** on a replayed threat (analyst/admin) | The per-threat SHAP explanation: predicted class, confidence, threat score, model version and a red/blue bar chart of the strongest feature contributions. It is computed from the feature vector stored with **that** prediction and shown only if re-scoring reproduces the same class, score and model version; otherwise the panel states the reason. Say: "contributions explain the XGBoost classifier, in log-odds units; the threat score also includes the anomaly detector, which SHAP does not break down." **AI Analytics** shows the global view |
| 9 | Alerts bell | One alert per HIGH or CRITICAL threat |
| 10 | Admin: **Settings → audit log** (latest 20) | Sign-ins and analyst actions are recorded |

Say: "These are recorded flows from a public dataset replayed through the live engine, not live capture. On a
de-duplicated random split the model scores 98.97 %, but on attack days it never saw recall drops to 3–51 %, so it
is not a detector of novel attacks."

## 4. Demo C — Autonomous Incident Response (simulated enforcement)

| # | Do | Expect / point at |
|---|---|---|
| 1 | Auto-block ON (§1). Run Demo B's replay, or attack Cowrie from Windows | A flow at or above **0.92** becomes a high-risk threat |
| 2 | **Threat Logs** row / **Settings** containment status | The policy is evaluated before any action |
| 3 | Protected targets | Loopback, link-local and `CONTAINMENT_PROTECTED_TARGETS` are **refused** (`AUTO_BLOCK_REFUSED` note); never contained |
| 4 | Score between 0.90 and 0.92 | Threat stored, **not** blocked (unit-tested; replay rarely produces such a score) |
| 5 | Score at or above 0.92, unprotected | Containment record created (`requestedBy: AI Auto-Block`) |
| 6 | Containment details | `enforcementBackend: mock`, status `ACTIVE`. **The mock adapter records a simulated rule; no firewall changes.** The honeypot's deny-list is the only real enforcement: Cowrie refuses that IP on the next connection |
| 7 | Dashboard / **Settings** blocked-IP list | IP listed as blocked; `ip_blocked` event |
| 8 | Admin: **Settings → audit log** | `CONTAINMENT_REQUESTED` → `CONTAINMENT_ACTIVE` |
| 9 | **Settings → Unblock IP** (operator rollback; the API equivalent is `POST /api/containment/actions/:id/rollback`) | Containment action `ROLLED_BACK`, deny-list row removed, `ip_unblocked` event |
| 10 | Threat row | Restored to its pre-block status; a TTL action also rolls back by itself on expiry (reconciliation) |

**Outage:** stop the engine window. The next flow is kept as `DEGRADED` (MEDIUM, never blocked), an "AI Engine
UNAVAILABLE" alert appears, the backend's `/health` returns 503, and the dashboard keeps working. Restart the engine
window to recover.

Never say "the firewall blocked the attacker". Say: "the containment decision and record are real; enforcement is
simulated by a mock adapter, and the honeypot refuses the deny-listed IP".

## 5. Stop, reset and recover

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\stop-demo.ps1     # closes the four demo windows
```

```bash
bash scripts/demo/cowrie-demo-mode.sh off                                # WSL: Cowrie back on 127.0.0.1
```

`scripts\demo\reset-demo-db.ps1` deletes demo activity in `sentinel-demo`: threats, alerts, AI predictions,
blocked IPs, containment actions, honeypot sessions and campaigns. It keeps users, login sessions and settings. Run
it only when you mean to. Never reset `sentinel-db`.

| Symptom | Cause | Fix |
|---|---|---|
| `start-demo.ps1`: "Port … in use" | Previous run still open | `stop-demo.ps1` (add `-Force` for foreign processes) |
| Engine `NOT RESPONDING` | venv missing or model verification failed | Read the engine window; models must match `registry.json` |
| SSH refused at once | Your IP is still deny-listed from a rehearsal | Settings → Unblock IP |
| `status`: check-block not 200 | Backend not reachable from WSL | Restart with `start-demo.ps1` (binds the WSL-visible address) |
| No session on the dashboard | Parser window stopped, or Cowrie on 127.0.0.1 | Check the parser window; `cowrie-demo-mode.sh on` |
| Persona rotation "waiting" | Attacker sessions still open | Exit the SSH sessions, or `rotate --once --force` |
| Recommendation "unavailable" | Engine down | Restart the engine window |
| Auto-block never fires | Off, or target protected or loopback | Settings → Auto-block ON; attack the WSL IP, not 127.0.0.1 |

## 6. Automated re-check before a viva (about 5 minutes; throwaway database)

```powershell
node scripts/integration/run_integration.cjs --cowrie
```

Expect `42 passed, 0 failed`. It restores `cowrie.cfg` and Cowrie's running state itself.
