# Final demonstration script (rehearsed 2026-11-03)

The presenter's script for Demo A, B and C in one sequence, with the real terminal output captured in the batch 15
rehearsal. [`DEMO_ABC_RUNBOOK.md`](DEMO_ABC_RUNBOOK.md) remains the short reference; this document adds what to say,
what the examiner should see, and how to recover.

**How it was rehearsed.** Same scripts, same machine, same Cowrie install; only the database differed
(`start-demo.ps1 -DemoDb sentinel-rehearsal`, three throwaway accounts) so the real `sentinel-demo` data and your
demo passwords were never touched. Afterwards the demo Q-table, parser state and `cowrie.cfg` were restored exactly
and the rehearsal database was dropped. Your demo uses the default `sentinel-demo` and your own accounts.

**Say once, at the start:** network flows are **recorded CICIDS2017 flows replayed** through the live engine, not live
capture; host-firewall enforcement is **simulated** by a mock adapter (the honeypot's own deny-list is real); the
persona learner's benefit is **not measured**; the model is strong on its own dataset and **weak on unseen attack
days**.

| Capability | Status in the demo |
|---|---|
| Cowrie SSH honeypot, sessions, commands, MITRE mapping | **Real** (live SSH into WSL) |
| XGBoost + Isolation Forest inference, storage, alerts, SHAP | **Real** computation on **replayed** recorded flows |
| Q-learning persona choice and rotation | **Real mechanism**, **effect unmeasured** (warm-started from a synthetic seed table) |
| Containment policy, state machine, audit, rollback | **Real** |
| Host firewall rule | **Simulated** (mock adapter) |
| Honeypot refusing a deny-listed IP | **Real** |

## 0. Ten minutes before (pre-presentation checklist)

| # | Check | Command (PowerShell, repository root unless noted) | Expected |
|---|---|---|---|
| 1 | MongoDB running | `Get-Service MongoDB` | `Running` |
| 2 | Demo ports free | `Get-NetTCPConnection -State Listen -LocalPort 8000,5000,3000 -ErrorAction SilentlyContinue` | no output |
| 3 | Models verified | `ai-engine\.venv\Scripts\python ai-engine\training\register_model.py --check` | `classifier … OK`, `anomaly … OK`, `golden … OK` |
| 4 | Dataset present (Demo B) | `Test-Path ai-engine\datasets\cicids2017\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `True` |
| 5 | Real firewall off | `Select-String -Path backend\.env -Pattern 'ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true','CONTAINMENT_BACKEND=windows'` | no output |
| 6 | Demo DB is the isolated one | (start-demo prints it) | `Demo database : sentinel-demo (sentinel-db untouched)` |
| 7 | Accounts | sign in once as analyst and admin | dashboard opens; passwords only on your cue card |
| 8 | Optional full self-test (~5 min, throwaway DB) | `node scripts/integration/run_integration.cjs --cowrie` | `42 passed, 0 failed` |
| 9 | Optional backup of the demo DB | `$env:MONGO_URI='mongodb://127.0.0.1:27017/sentinel-demo'; node scratch/backup_sentinel_db.mjs` | `=== BACKUP COMPLETE ===` (folder under `backups/`, git-ignored; contains password hashes — keep it local) |

Close heavy apps first: on this 8 GB laptop browser tabs stalled under memory pressure (TEST-008).

## 1. Start (≈ 1 minute)

**PowerShell (repository root):**

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\start-demo.ps1
```

Expected (rehearsal, 37 s):

```
Waiting for services (up to 90 s)...
AI engine  http://127.0.0.1:8000/ready        UP
Backend    http://172.29.32.1:5000/health     UP
Frontend   http://localhost:3000              UP

Demo database : sentinel-demo   (sentinel-db untouched)
Q-table       : C:\Users\<you>\.sentinelai\demo\q_table.json
Honeypot (WSL): 172.29.32.17    Windows host as seen from WSL: 172.29.32.1
```

(The WSL addresses can differ after a reboot; the script finds them each time.)

**WSL (repository directory):**

```bash
cp ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg.pre-demo
bash scripts/demo/cowrie-demo-mode.sh on
```

Expected:

```
Demo mode ON: Cowrie listens on 172.29.32.17:2222
cowrie      : cowrie is running (PID: …).
threads     : 2  (2 = blocker sync thread alive)
check-block : HTTP 200  (200 = the blocker can read the deny-list)
```

**Demo console (new PowerShell window):** `. $env:USERPROFILE\.sentinelai\demo\demo-env.ps1`

Open http://localhost:3000/login, sign in as an **analyst**. Point at the status bar: *Detection services connected,
Honeypot: 1 active, AI Engine: Running*. (Screenshot: [`02-dashboard-analyst.png`](presentation/screenshots/02-dashboard-analyst.png).)

## 2. Demo A — Honeypot Intelligence (≈ 5 minutes)

| Step | Do | Expected (rehearsal) | Examiner should see | Explain |
|---|---|---|---|---|
| A1 | Demo console: `ssh -p 2222 root@$env:SENTINEL_HONEYPOT_IP`, password from Cowrie's `etc/userdb.txt` (lab credential) | prompt `root@ubuntu-prod-srv:~#` | a convincing Ubuntu server | Cowrie is a medium-interaction honeypot: it emulates SSH and a shell; nothing runs on a real host |
| A2 | `uname -a`, `whoami`, `cat /etc/passwd`, `ls /tmp`, `exit` | `Linux ubuntu-prod-srv 5.15.0-91-generic … x86_64`, `root`, a fake passwd file | fabricated output | the persona (kernel, hostname, banner) is configured, not real |
| A3 | Dashboard → **Honeypot** | the session appears with its commands; *LIVE* badge | live update without reload | parser → `/api/honeypot/ingest` → Socket.IO `honeypot_*` events |
| A4 | Open the session | MITRE **T1082** (uname), **T1033** (whoami), **T1003 / T1003.008** (/etc/passwd), **T1595** | ATT&CK techniques per command | rule-based mapping (`honeypot_rules`), not the network model; session threat score 0.40 → a LOW ThreatLog |
| A5 | Same view | deception score (≈ 25), Q-learner score (≈ 26), engagement *medium* | engagement scoring | reward = duration, commands, intent bonuses, IOCs, login; minus a fingerprinting penalty |
| A6 | **Honeypot → Adaptive Deception** (analyst) | *Serving persona: ubuntu_22*; recommendation e.g. **centos_7**, decision id `…`; REFRESH shows the same decision | one decision per served persona | tabular Q-learning, ε-greedy; provenance shows it was warm-started from a **synthetic** seed table |
| A7 | WSL: `bash scripts/demo/cowrie-demo-mode.sh rotate --once` | `Rotation result: {'changed': True, 'active': 'centos_7', 'previous': 'ubuntu_22', 'decisionId': '…'}`, `persona now: centos_7` | the decision is applied | rotator rewrites `cowrie.cfg` from a template, restarts Cowrie, records `APPLIED` |
| A8 | SSH again, `hostname`, `uname -r` | `centos-web-gateway`, `3.10.0-1160.el7.x86_64` | a different-looking server | the next session is credited to `centos_7` (rehearsal: session `1f9de…` served by centos_7) |

If the decision equals the current persona the rotator records a **keep** (no restart): that is valid; say so.

## 3. Demo B — AI Threat Detection (≈ 5 minutes)

**Demo console:**

```powershell
cd ai-engine
.\.venv\Scripts\python.exe demo\replay_cicids.py --target backend --rows 10 --delay 0.5 --backend-url $env:SENTINEL_BACKEND_URL --email <analyst email>
```

(Password is prompted; nothing is echoed. Or set `$env:SENTINEL_DEMO_PASSWORD` beforehand.)

Expected (rehearsal):

```
SentinelAI -- CICIDS2017 Real Attack Replay Demonstration
  * Dataset Source:   …\Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
[1/2] Curating balanced sample of recorded CICIDS2017 flows...
[2/2] Replaying recorded flows through SentinelAI (not live capture)...
Flow #01 | Client IP: 198.51.100.2 | …   Model Prediction: BENIGN  Threat: 0.0001 | ALLOW  …  [MATCH] Latency: 143.4ms
Flow #02 | Client IP: 198.51.100.3 | …   Model Prediction: DDoS    Threat: 1.0000 | BLOCK  …  [MATCH] Latency: 9.9ms
…  (10/10 correct; DDoS 0.9997–1.0, BENIGN ≤ 0.0004; 3–10 ms after the first call)
```

| Step | Show | Examiner should see | Explain |
|---|---|---|---|
| B1 | the replay output | prediction first, ground truth revealed after | flows come from a public dataset; source addresses are replaced by documentation-range IPs (198.51.100.x) |
| B2 | **Threat Logs** | 5 new **CRITICAL** DDoS rows | non-BENIGN at ≥ 0.90 → ThreatLog; ≥ 0.92 → CRITICAL |
| B3 | Alert bell | 5 CRITICAL alerts | one alert per HIGH/CRITICAL threat |
| B4 | Dashboard live feed | each threat once, without reload | Socket.IO `new_threat`, per-role rooms |
| B5 | Threat Logs → **Explain** on a DDoS row | *Predicted class DDoS, confidence 100 %, model xgb_cicids_v1, "reproduced from the features stored with this prediction"*; bars led by `init_win_bytes_backward` (+3.66) | SHAP for **that** stored prediction | stored 53-feature vector re-scored; refused if class/score/model differ; contributions are log-odds and add up to the margin (base 0.246 + Σ = 8.26 in the rehearsal); covers the classifier, not the anomaly term |
| B6 | (optional) sign in as **viewer** | no Explain button; IPs shown as `198.51.100.xxx` | redaction | viewer API and socket payloads are redacted on the server (rehearsal: viewer explanation request → 403) |

Say: *"98.97 % accuracy on a de-duplicated random split; 3–51 % recall on attack days it never saw — it is not a
detector of novel attacks."*

## 4. Demo C — Autonomous Incident Response (≈ 5 minutes)

| Step | Do | Expected (rehearsal) | Explain |
|---|---|---|---|
| C1 | Admin → **Settings → AI Auto-Blocking ON** | *ACTIVE / ON*; audit `SETTINGS_CHANGED` | off by default; one flow ≥ 0.92 is enough (no correlation) |
| C2 | Re-run the replay with `--rows 4` | the 2 DDoS sources are contained | containment policy runs before any action |
| C3 | **Settings** | *Active Enforcement Adapter: MockContainmentAdapter (In-Memory Simulation)*; blocklist rows *Triggered by AI Engine*, reason `AI Engine auto-block (score = 1)` | **simulated** rule; no host firewall change |
| C4 | Threat Logs / dashboard queue | rows **BLOCKED** | every open detection of that address is marked |
| C5 | Settings → Manual enforcement: `127.0.0.1` → ENFORCE IP BLOCK | refused: *"Target 127.0.0.1 matches protected network infrastructure or loopback address"* (403) | protected targets: loopback, link-local, local services, `CONTAINMENT_PROTECTED_TARGETS` |
| C6 | Manual block of the **Windows host's WSL address** (`172.29.32.1` in the rehearsal), then SSH as in A1 | SSH fails at once (*connection forcibly closed*) | the **one real enforcement**: Cowrie's blocker reads the deny-list |
| C7 | Settings → **Unblock IP** on it, SSH again | `ROLLED_BACK`; SSH works | operator rollback; audit `IP_UNBLOCKED_MANUAL` |
| C8 | Unblock the auto-blocked replay IPs | rows back to their previous status (e.g. MONITORING) | containment `ROLLED_BACK`, deny-list cleared, `ip_unblocked` event |
| C9 | Containment audit trail | backend window (or `backend\logs\sentinel*.log`): `[AUDIT] CONTAINMENT_REQUESTED → CONTAINMENT_ACTIVE`, `ALREADY_ACTIVE_HIT` for a repeat detection | these structured lines are in the backend log; **Settings → audit log** shows sign-ins, settings changes and manual block/unblock |
| C10 | **Outage:** close the "SentinelAI-demo: AI engine" window, replay `--rows 2` | flows stored as **DEGRADED / MEDIUM, never blocked** (even with auto-block on); alert *"AI Engine UNAVAILABLE"*; backend `/health` → 503; dashboard keeps working | fail-safe: no blocking without a model decision |
| C11 | `powershell -ExecutionPolicy Bypass -File scripts\demo\restart-engine.ps1` | `AI engine … UP` in ≈ 11 s; backend `/health` 200 without a restart; next replay scored normally | circuit breaker closes by itself |
| C12 | Settings → Auto-Blocking **OFF** | | leave the demo as you found it |

Never say "the firewall blocked the attacker". Say: *"the containment decision, state machine and audit are real;
the host-firewall action is simulated by a mock adapter; the honeypot refuses the deny-listed address."*

## 5. If something fails during the presentation

| Symptom | Recovery (≈ time) |
|---|---|
| Engine window closed / engine not responding | `scripts\demo\restart-engine.ps1` (≈ 11 s; backend recovers by itself) |
| Backend, frontend or parser window died | `scripts\demo\stop-demo.ps1` then `scripts\demo\start-demo.ps1` (≈ 40–60 s); dashboards reconnect by themselves |
| MongoDB stopped | `Start-Service MongoDB` (may need an elevated PowerShell); API answers 503 meanwhile; recovers within seconds |
| SSH refused at once | your WSL-side address is deny-listed: Settings → Unblock IP |
| `check-block` not 200 / no honeypot sessions | WSL: `bash scripts/demo/cowrie-demo-mode.sh on`; restart the demo if the WSL address changed |
| Live feed or dashboard stale | it reconnects and catches up by itself; otherwise reload the page |
| Rotation "waiting" | close your SSH sessions, or `rotate --once --force` |
| Replay: "Set SENTINEL_DEMO_PASSWORD or run interactively" | run it in an interactive window, or set the variable first |
| Login fails | caps lock / wrong account; sign in with the other prepared account of the same role (have two per role on the cue card) |

## 6. Afterwards (cleanup and restoration)

1. Settings: Auto-Blocking OFF; unblock anything still listed.
2. `powershell -ExecutionPolicy Bypass -File scripts\demo\stop-demo.ps1` (expect four "Stopped demo window" lines).
3. WSL: `cp ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg.pre-demo ~/sentinelai-cowrie-test/cowrie/etc/cowrie.cfg`,
   then `bash scripts/demo/cowrie-demo-mode.sh off` (Cowrie back on 127.0.0.1 only).
4. Optional: `scripts\demo\reset-demo-db.ps1` to clear demo activity (keeps users and settings; refuses `sentinel-db`).
5. Confirm ports are free: `Get-NetTCPConnection -State Listen -LocalPort 8000,5000,3000 -ErrorAction SilentlyContinue`.

## 7. Rehearsal evidence (2026-11-03)

| Demo | Result |
|---|---|
| Start | three services UP in 37 s; Cowrie demo mode on, blocker thread alive, check-block 200; registry check OK |
| A | real SSH from Windows; session stored with 5 ATT&CK techniques, deception score 25; decision `ubuntu_22 → centos_7` drawn, applied by `rotate --once` (`APPLIED`, `appliedProfile: centos_7`); next session saw `centos-web-gateway` and was credited to centos_7 |
| B | 10/10 replayed flows correct; 5 CRITICAL threats and 5 alerts; explanation reproduced, 53 contributions, additivity holds; viewer refused (403) |
| C | auto-block contained both DDoS sources via the mock adapter (`ACTIVE`); loopback refused (403); deny-listing the Windows host made Cowrie drop SSH, unblock restored it; outage → DEGRADED, alert, `/health` 503; `restart-engine.ps1` recovered in 11 s |
| Found and fixed | CONT-001: unblocking an address detected more than once left the other detections `BLOCKED` (fixed, tested); replay script said "live network traffic" (corrected); runbook pointed at the wrong place for containment audit lines (corrected); no single-service engine restart existed (`restart-engine.ps1` added) |
| Restored | `sentinel-demo` untouched (240 threats, 8 users); demo Q-table and parser state restored; `cowrie.cfg` hash `91349e56…`, Cowrie stopped; rehearsal DB dropped; model hashes unchanged |
