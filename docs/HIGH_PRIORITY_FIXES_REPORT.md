# High-Priority and Critical Fixes Report (H1–H7, C1, C2, C3)

Date: 2026-10-21 · Branch: `db-fixes` · Status: **uncommitted** working-tree changes.
Source of the issue list: `docs/BACKEND_STUDY_GUIDE.md` → Phase 4 "High" and "Critical". H1–H7 are
below; C1 (independent re-evaluation) and C2 (demo driver through `/api/ai/analyze`) are in their own
section near the end, together with a new critical finding (C3) that C1 uncovered.

## Summary

| ID | Issue | Fix | Verified by |
|---|---|---|---|
| H1 | Windows firewall adapter ran `netsh` through a shell (`exec`) and accepted any string of IP characters | `execFile` with an argument array (no shell), real IP/CIDR validation, locale-safer `verifyRule` | `tests/firewallExecFile.test.js` (5) + existing firewall safety suites |
| H2 | AI outage → one SYSTEM_HEALTH alert per analysed flow (alert flood) | Alert raised once per cooldown window (default 5 min, `DEGRADED_ALERT_COOLDOWN_MS`); every degraded flow is still recorded | `tests/aiDegradedMode.test.js` (2) + existing regression suite |
| H3 | Block-threshold lookup re-tried with a 10 s timeout on every call during an outage | Back-off on failure (cache window applies to failures too), 1.5 s fetch timeout | `tests/aiDegradedMode.test.js` (2) |
| H4 | CPU-bound RF/IF/SHAP ran inside `async def` handlers, blocking the event loop | Inference endpoints are plain `def` (FastAPI threadpool); stats and Q-learner guarded by locks | `tests/test_high_priority_fixes.py` (sync-handler check + 40 concurrent Q updates, none lost) |
| H5 | Q-learner always received `centos_7` as its action → only one Q cell ever changed | Served persona recorded in `SystemSetting` via new admin API, stamped on each session (`servedProfile`); previous session's persona sent as state | `tests/deceptionProfile.test.js` (4), role matrix (+2 routes), Python state test |
| H6 | Q-table written to a per-PID temp dir → learning lost on every restart; saved only every 10 episodes | Service runs persist to a stable per-user path outside the repo; save every episode (`Q_SAVE_EVERY`) | `tests/test_high_priority_fixes.py` (path stable across PIDs; resume after restart) |
| H7 | `ai-engine/.env` never loaded (no `load_dotenv`) | `main.py` loads `ai-engine/.env` (no override of already-set vars; skipped under pytest) | Live: engine started with `SENTINEL_KEY` unset in the shell → read from `.env`, `/ready` ok, 401 without key |

## Details

### H1 — Firewall adapter command execution
File: `backend/services/containment/WindowsFirewallAdapter.js`
- `child_process.exec` (shell) → `execFile('netsh', args, { timeout, windowsHide: true })`. Each value
  (`name=…`, `remoteip=…`) is one argv element, so shell metacharacters cannot start another command
  even if validation regressed.
- `_sanitizeTarget` keeps the character allow-list (same error message, existing tests unchanged) and
  now also requires `net.isIP()` on the address and a numeric prefix ≤ 32 (IPv4) / ≤ 128 (IPv6).
  Rejected now: `:::`, `999.1.1.1`, `1.2.3.4/99`, `1.2.3.4/24/8`, `/24`.
- `verifyRule` reads the `Enabled:` line instead of `stdout.includes('Yes')` (which matched e.g.
  "Edge traversal: Yes"); non-English output falls back to "exists".
- The runner is injectable (`options.runNetsh`) so tests assert the exact argv with no OS call.
- Unchanged: gates (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`, `NODE_ENV=test`, `CONTAINMENT_DRY_RUN`),
  rule namespace, mock default. The real adapter has still **never run against a live host**.

### H2 — Degraded-mode alert flood
File: `backend/services/aiService.js`
- Each degraded flow still creates its `AIPrediction` and `DEGRADED` `ThreatLog` (audit trail, held in
  MONITOR, never blocked) and still emits `new_threat` / `ai_prediction`.
- Only the SYSTEM_HEALTH alert is de-duplicated: one per `DEGRADED_ALERT_COOLDOWN_MS` (default 300000).
- `resetDegradedAlertCooldown()` exported for tests.

### H3 — Threshold lookup back-off
File: `backend/services/aiEngineService.js`
- `lastFetchedTime` is set before the fetch, so a failure is cached for 60 s like a success.
- The threshold fetch uses its own 1.5 s timeout instead of the 10 s default.
- Worst case per analysed flow during an outage drops from ~20 s (predict + threshold) to the 10 s
  predict timeout, and threshold fetches drop to one per minute.

### H4 — Inference off the event loop
File: `ai-engine/inference/main.py`
- `predict`, `predict_internal`, `predict_eval`, `predict_batch`, `predict_honeypot`,
  `predict_honeypot_internal`, `deception_score`, `predict_auth_shadow` are now `def`; FastAPI runs them
  in its threadpool. `/health`, `/ready`, `/model/*` stay `async` and answer while inference runs.
- `_stats_lock` guards the in-memory counters; `_scorer_lock` guards Q-learner updates and the shutdown
  flush. Test: 40 concurrent `/deception/score` calls → exactly +40 episodes.
- Still single-process: with `uvicorn --workers > 1` each worker would hold its own Q-table (keep 1).

### H5 — Q-learning credited to the persona actually served
Files: `backend/services/honeypotService.js`, `backend/routes/honeypot.js`, `backend/models/HoneypotSession.js`,
`honeypot/switch_profile.py`, `backend/tests/roleMatrix.test.js`
- New endpoints:
  - `GET /api/honeypot/deception/profile` (any signed-in role) → `{ profile, source: setting|env|default, profiles }`
  - `PUT /api/honeypot/deception/profile` (`settings:write`, i.e. admin) body `{ "profile": "debian_11" }` →
    validated against the six personas, stored in `SystemSetting.deceptionActiveProfile`, audit-logged.
- On closure each session is stamped with `servedProfile` (setting → `DECEPTION_ACTIVE_PROFILE` → `centos_7`),
  sent to the learner as `deceptionProfile` (action); the most recent earlier session's `servedProfile`
  is sent as `previousProfile` (state). A failed lookup falls back to the learner's in-memory state.
- `switch_profile.py` now prints the PUT call to make after restarting Cowrie.
- Honest limit: recommendations are still **not applied automatically**. Learning is now correct
  across operator-applied switches; adapting by itself is still future work (Phase 5 F3).

### H6 — Q-table survives restarts
Files: `ai-engine/rl_engine/deception_scorer.py`, `ai-engine/.env.example`
- `get_default_runtime_path()` for a normal service run (not test/diagnostic, no repo-write flag) is now
  `%LOCALAPPDATA%\SentinelAI\runtime\q_table.json` (`~/.local/share/SentinelAI/...` elsewhere): stable
  across restarts, outside the repository, seeded once from `models/q_table.json`.
- Unchanged: tests/diagnostics → per-PID temp; `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1` → `ai-engine/runtime/`;
  `Q_TABLE_PATH` / `DEFAULT_RUNTIME_Q_TABLE_PATH` overrides; writes into `models/` are always refused.
- Saves every episode by default (atomic temp + fsync + replace); `Q_SAVE_EVERY` to tune.

### H7 — AI engine reads its `.env`
File: `ai-engine/inference/main.py`
- `load_dotenv(ai-engine/.env, override=False)` before `SENTINEL_KEY` is checked. Variables already in
  the environment win. Not loaded when pytest is imported, so a developer `.env` cannot change tests.
- Start command no longer needs `--env-file`:
  `cd ai-engine && .venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000`

## Test results

| Suite | Before | After |
|---|---|---|
| Backend Jest (`npx jest --runInBand --ci`) | 54 passed / 4 skipped suites; 948 passed, 13 skipped | **57 passed / 4 skipped suites; 969 passed, 13 skipped, 0 failed** |
| AI engine pytest (`.venv`, Python 3.11.9) | 335 passed | **341** after H1–H7; **352** after C1/C2; **356 passed, 0 failed** after C3 |
| ESLint on touched backend files (line endings ignored) | — | 0 errors; 1 warning that was already there (`aiEngineService.js:52` unused `io`) |
| Live: AI engine with `SENTINEL_KEY` unset in shell | failed to start (RuntimeError) | started from `.env`, loaded `rf_classifier_cicids_v2.pkl`, `/ready` ok, `/model/info` 401 without key |

New tests: `backend/tests/firewallExecFile.test.js` (5), `backend/tests/aiDegradedMode.test.js` (4),
`backend/tests/deceptionProfile.test.js` (4), `ai-engine/tests/test_high_priority_fixes.py` (6); role
matrix extended with the 2 new routes (viewer/analyst/admin/no-token expectations).

The 4 skipped backend suites need a real MongoDB (`AUTH_TEST_MONGO_URI`), same as before. The full
backend was not started against your real `sentinel-db`, and Cowrie was not run.

Lint note: on this Windows checkout (`core.autocrlf=true`) every file, including untouched ones,
reports prettier `Delete ␍` errors; CI on Linux checks out LF. Other remaining prettier errors in
`aiService.js` (lines 67, 69, 107) and `roleMatrix.test.js` (one-line matrix entries) were already there.

## Behaviour changes to know about
- New Mongo field `HoneypotSession.servedProfile` (null on old sessions; no migration needed).
- New SystemSetting key `deceptionActiveProfile` (absent ⇒ env/default, same as before).
- New env vars: `DEGRADED_ALERT_COOLDOWN_MS` (backend), `Q_SAVE_EVERY` (AI engine).
- After the first service run, learning state lives in `%LOCALAPPDATA%\SentinelAI\runtime\q_table.json`.
  Delete that file to restart learning from the seed.

## Critical items C1 and C2 (added in the same working tree)

### C2 — demo driver through `/api/ai/analyze`
File: `ai-engine/demo/replay_cicids.py` (+ `ai-engine/tests/test_replay_targets.py`, 6 tests)
- New `--target backend` mode: CSRF handshake + login (`--email` or `SENTINEL_DEMO_EMAIL`; password from
  `SENTINEL_DEMO_PASSWORD` or a hidden prompt, never a CLI argument or log line), checks the account is
  admin/analyst, warns if auto-block is on, then posts each real CICIDS2017 row to `/api/ai/analyze`.
  One re-login on 401 (15-minute access tokens).
- Source addresses are RFC 5737 TEST-NET-2 (`198.51.100.0/24`), so an enabled auto-block can never
  deny-list a real host. Ground-truth labels are still never sent.
- Default `--target engine` behaves exactly as before (side-effect-free `/predict/eval`).
- **Verified end to end** on a disposable stack (real backend on in-memory MongoDB, real AI engine,
  Socket.IO client as the dashboard): 8 Friday-DDoS-file flows, 8/8 classified correctly, 8 predictions
  stored, 3 threats created, and the listener received `ai_prediction`, `new_threat`, `new_alert` and
  `critical_alert` live. Your real `sentinel-db` was not used.

Demo command (backend, AI engine and dashboard running):
```
cd ai-engine
.venv/Scripts/python.exe demo/replay_cicids.py --target backend --email <analyst or admin email> --rows 20 --delay 1.5
```

### C1 — day-held-out re-evaluation
Files: `ai-engine/evaluation/day_holdout_eval.py` (+ `ai-engine/tests/test_day_holdout_eval.py`, 5 tests),
results in `ai-engine/experiments/c1_day_holdout_eval/`, write-up in `docs/C1_EVALUATION_PLAN_AND_RESULTS.md`.
Ran on all 2,827,876 cleaned CICIDS2017 rows with the production recipe (14 min):

| Protocol | Accuracy | Macro F1 | Attack detection (classifier) | Attack detection (threat raised) |
|---|---|---|---|---|
| Random 80/20 (as reported) | 0.9869 | 0.8778 | 99.7 % | 23.2 % |
| Chronological per class | 0.9757 | 0.7390 | 93.9 % | 29.4 % |
| Leave-one-day-out (Tue/Wed/Thu/Fri) | 0.59–0.94 | 0.19–0.29 | 0.03–7.7 % | 0.0–0.2 % |

The reported number reproduces under a random split. Under an independent split macro F1 drops to 0.74,
and the model does not generalise to attack days it was not trained on.

### C3 — threat score suppressed correct detections (fixed: option 1)
`threatScore = 0.7·confidence + 0.3·anomaly` kept a correctly classified attack below the 0.70 threat
line unless the anomaly detector also fired (only 20–29 % of attacks raised a threat; reproduced live:
a correctly classified DDoS flow scored 0.6999 → ALLOW).
Fix: `inference/predictor.py::combine_threat_score` — `max(rf_s, blend)` for attack classes, BENIGN
unchanged; used by flow and honeypot scoring and by the C1 script. Tests: `tests/test_predictor.py`
(+4), `tests/test_abuseipdb_decoupling.py` and `tests/test_day_holdout_eval.py` updated to the new formula.

Measured on the chronological split (full re-run):

| | Threat raised (≥ 0.70) detection / benign FPR | Block line (≥ 0.92) detection / benign FPR |
|---|---|---|
| Before | 29.4 % / 0.029 % | 5.0 % / 0.000 % |
| After | **89.7 % / 0.496 %** | **86.5 % / 0.046 %** |
| After, threat line 0.85 (sweep, not applied) | 87.8 % / 0.073 % | — |

Detection target met; the < 0.1 % benign **alert** FPR target is not met at the current 0.70 line (it is
at the block line). See `docs/C1_EVALUATION_PLAN_AND_RESULTS.md` §5 for the full table and sweep.
Behaviour change: with auto-block enabled, confidently classified attacks (≥ 0.92) are now deny-listed,
including honeypot sessions the rules classify as attacks; auto-block is still off by default.

## Not done in this change
- Raising the alert threshold to ≈ 0.85 (would meet the alert-FPR target; needs validation-split confirmation and a backend change).
- Updating README/paper metric claims to the C1 wording.
- Medium/Low items (M1–M13, L1–L15) from the study guide.
- Live verification of the real firewall adapter (needs an isolated Windows VM).
