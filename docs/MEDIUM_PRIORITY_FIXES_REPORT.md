# Medium-Priority Fixes Report (M1–M13)

Date: 2026-10-21 · Branch `db-fixes` · **Uncommitted.** Issue list: `docs/BACKEND_STUDY_GUIDE.md`, Phase 4 "Medium".

| ID | Problem | Fix | Files | Verified by |
|---|---|---|---|---|
| M1 | Two concurrent containment requests for one target could both create rules | `targetLock` field + unique sparse index; it is held while an action is in flight or enforced and released on FAILED/REJECTED/ROLLED_BACK; the loser gets the winner's action back | `models/ContainmentAction.js`, `services/containmentService.js` | `tests/mediumContainment.test.js` (real DB: 5 parallel requests → 1 action) |
| M2 | Read-modify-save on honeypot sessions lost concurrent commands/scores | One atomic pipeline update (`recordSessionActivity`); attacker strings go through `$literal`; MITRE merged with `$setUnion`; `downloadCount` keeps the +15 download bonus | `services/honeypotService.js`, `honeypot/collectors/session_collector.js`, `models/HoneypotSession.js` | `tests/mediumHoneypot.test.js` (25 parallel commands all kept; `$commands` stored as text) |
| M3 | Prediction and threat writes not atomic | Threat id chosen first, prediction stored already linked; failed threat write unlinks the prediction | `services/aiService.js` | `tests/mediumBackend.test.js` |
| M4 | `request_stats` unthrottled; every socket packet re-read the session | Per-socket 5 s snapshot cache; packet auth reused for 5 s (revocation still disconnects via rooms; 15 s recheck kept) | `websocket/socketManager.js`, `websocket/auth.js` | `tests/mediumBackend.test.js` (10 requests → 3 counts) |
| M5 | Several engine workers overwrote each other's Q-table | Exclusive lock file + merge-on-save: foreign writes are reloaded and pending TD updates replayed; unreadable table now logged | `ai-engine/rl_engine/deception_scorer.py` | `tests/test_medium_fixes.py` (2 real processes × 25 → 50 episodes) |
| M6 | Analytics/clustering scanned whole collections | Honeypot analytics bounded to 7 days; AI stats to `ANALYTICS_WINDOW_DAYS` (30) with O(1) total; clustering loads only same-hassh/shared-command candidates (indexed) and their campaigns | `services/honeypotService.js`, `services/aiService.js`, `services/campaignService.js`, models (indexes) | `tests/campaignService.test.js` (rewritten on real DB, query plan IXSCAN), `tests/mediumHoneypot.test.js` |
| M7 | Auto-block deny-list and firewall adapter were separate systems | Auto-block also files a `ContainmentAction` via `requestContainment` (analyst-rights system requester, expiring, idempotent per threat); alert text states what enforced it; failure keeps the deny-list | `services/containmentService.js` | `tests/mediumContainment.test.js` |
| M8 | Honeypot "AI" class looked like real ML; card said "RL reward" | UI shows "(rule-based)" with tooltip; card relabelled; `aiClassificationMethod` stored | `frontend/src/pages/Campaigns.jsx`, `HoneypotAnalytics.jsx`, backend model/service | review |
| M9 | Missing training columns silently zero-filled | `prepare_features(..., max_missing=0)` raises on unexpected gaps (time features/entropy exempt); always logs | `ai-engine/utils/features.py`, `training/train.py`, `evaluation/day_holdout_eval.py` | `tests/test_medium_fixes.py` |
| M10 | `isAnomaly` (−0.55) and anomaly signal (offset ≈ −0.474) disagreed on 2.8 % of benign flows | One boundary (−0.55) for both via shared `anomaly_signal()`; measured on the chronological split: detection/benign FPR unchanged at 0.70/0.85/0.92 (unifying at offset_ instead would raise "Unknown" on benign from 2.0 % to 4.7 %) | `ai-engine/inference/predictor.py`, eval script | `tests/test_predictor.py` (updated + agreement test) |
| M11 | Any stray `.pkl` could become the live model | `models/registry.json` pins classifier + IF by SHA-256; mismatch/missing/invalid → inference unavailable; `training/register_model.py` (`--check`) | `ai-engine/inference/predictor.py`, `ai-engine/models/registry.json`, `training/register_model.py` | `tests/test_medium_fixes.py` |
| M12 | Parser lost sessions on restart, no retry, backend used ingest time | Retries with backoff for transient errors (not 4xx); Cowrie start time forwarded and used; close delivered even without parser state; backend sweep closes stale active sessions (duration to last activity) | `honeypot/parsers/log_parser.py`, collector, `services/honeypotSweepService.js`, `server.js` | `ai-engine/tests/test_parser_delivery.py`, `tests/mediumHoneypot.test.js` |
| M13 | 10 000 req/15 min per IP; valid API keys bypassed limits entirely | Default 1000 per IP; service keys get their own per-key budget (`RATE_LIMIT_MACHINE_MAX`, 20 000) | `server.js`, `.env.example` | `tests/rateLimit.test.js` (+1) |

L1 (unused `exec` import in the collector) was removed along the way.

## New settings (`backend/.env.example`)
`RATE_LIMIT_MAX=1000`, `RATE_LIMIT_MACHINE_MAX=20000`, `ANALYTICS_WINDOW_DAYS=30`, `HONEYPOT_STALE_SESSION_HOURS=6`,
`DEGRADED_ALERT_COOLDOWN_MS=300000`. If your own `backend/.env` still sets `RATE_LIMIT_MAX=10000`, that value wins.

## Behaviour changes to know
- With auto-block on, each auto-block now also creates an expiring (1 h) ContainmentAction through the configured adapter (mock by default; real firewall only behind its existing two gates).
- Honeypot analytics and AI-stat charts now cover a window (7 / 30 days), not all history; verified accuracy stays all-time.
- Campaign matching only considers sessions from the last 7 days.
- New indexes are built on next start: `ContainmentAction.targetLock`, `Campaign.sessions`, `HoneypotSession.commands.command`, `AIPrediction.verified`.

## Test status
- First full run after the medium fixes: backend 988 passed / **1 failed** (`threatSecurityRemediation.test.js`,
  OBS-01 linking — it still expected the pre-M3 `pred.save()`), AI engine 372 passed, frontend 36 passed + build OK.
- C1 re-run with the M10 boundary: chronological split unchanged — accuracy 0.9757, macro F1 0.739, detection
  89.7 %, benign alert FPR 0.496 % (`ai-engine/experiments/c1_day_holdout_eval/results.json` refreshed).
- The OBS-01 test was then updated to the M3 invariant; after that and the low-priority round, all suites are
  green: backend 992 passed / 13 skipped, AI engine 379 passed, frontend 36 passed + build
  (see `docs/LOW_PRIORITY_FIXES_REPORT.md`). Lint on touched backend files: 0 errors.
