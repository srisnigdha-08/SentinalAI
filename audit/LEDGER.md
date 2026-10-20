# Audit Ledger — SentinelAI evidence-driven audit (v2)

Started: 2026-10-20. Auditor: Claude (read-only on project; writes only under `audit/`).

## Status
| Stage | State |
|---|---|
| 1 Inventory | DONE |
| 2 Critical flows | DONE — see STAGE2_FLOWS.md |
| Fix batch 1 (user-requested) | APPLIED + VERIFIED (Jest 948 pass, pytest 335 pass, frontend 36 pass + build) — see FIXES.md |
| 3 Claims vs reality | next |
| 4 Security | not started |
| 5 ML validity | not started |
| 6 Tests | not started |
| 7 Ops/docs | not started |

## Repo state at audit start
- Root: `C:\Users\srisn\Desktop\Projects\sentinelai-complete`, branch `db-fixes` (19 commits ahead of `main`; `origin/main` = `796fc56`, 9 commits total on main; 28 commits on db-fixes).
- Uncommitted: 28 modified files, 3 staged deletions, 7 untracked paths (Playwright E2E suite, ErrorBoundary/Modal, `scripts/start-test-backend.cjs`, `.github/workflows/e2e.yml`, `frontend/tests/e2eSafety.test.mjs`). Includes containment safety-lock changes in `adapterFactory.js` / `WindowsFirewallAdapter.js`.

## Files / flows inspected (Stage 1)
- `backend/package.json`, `backend/server.js` (diff only), `backend/config/validateEnv.js`
- `backend/services/containment/WindowsFirewallAdapter.js:40-90`, `adapterFactory.js` (diff)
- `backend/utils/seed.js`, `backend/utils/clean.js`, `backend/trigger_block.js`
- `ai-engine/inference/main.py:1-70,260-285`, `ai-engine/inference/predictor.py:1-140`, `ai-engine/training/train.py` (grep), `ai-engine/utils/features.py` (grep)
- all `*meta.json` in `models/` and `ai-engine/models/` (parsed with python, read-only)
- `honeypot/**` (grep for network/OS calls)
- `frontend/package.json`, `frontend/playwright.config.js`, `frontend/e2e/global-setup.js`, `frontend/tests/e2eSafety.test.mjs`
- `.github/workflows/ci.yml`, `.github/workflows/e2e.yml`
- `README.md` (run steps, metrics), `paper_text.txt` (header)
- env files: key names + value classification only (no values printed)

## Commands run (all read-only)
- `git status/log/diff/branch/ls-files/show/grep/merge-base/check-ignore`
- `ls`, `sha256sum` on model files, `sed/grep/cat` on source
- `python -c` reading meta JSON files (no writes)
- shell comparisons of env values vs Git history (printed match flags / lengths only)
- A `du -sh` over aux dirs timed out (backgrounded); not needed.

## Files / flows inspected (Stage 2)
- backend: routes/honeypotIngest.js, routes/aiEngine.js, routes/containment.js (auth lines), routes/auth.js (routes),
  services/honeypotService.js, aiEngineService.js, aiService.js:1-200, threatService.js:60-170,
  containmentService.js (44-320, 475-610, 783-852), containmentPolicyService.js (patterns, role checks),
  containment/MockContainmentAdapter.js, adapterFactory.js, middleware/auth.js, websocket/auth.js,
  websocket/socketManager.js, utils/securityEventBus.js (head + publisher search), controllers/authController.js (grep)
- honeypot: collectors/session_collector.js, cowrie/sentinel_output.py, cowrie/cowrie.cfg, cowrie/sentinel_blocker.py
  (outline), parsers/log_parser.py (outline), sniffer/sniffer.py, switch_profile.py (header)
- ai-engine: inference/main.py (71-260), predictor.py (298-428), utils/features.py (318-400), inference/deception.py,
  rl_engine/deception_scorer.py, models/q_table.json (read)
- frontend: context/SocketContext.jsx, socket listener census, ContainmentConfirmModal.jsx, ThreatLogs.jsx:105-125,
  Dashboard.jsx:230-240, services/api.js
- docs (prior-report): DATABASE_GUIDE.md, DATABASE_HEALTH_REPORT.md, ENROLLMENT_POLICY_20261015.md,
  final-closure/known-limitations-and-release-gates.md

## Findings so far (IDs)
Stage 1: SEC-001, OPS-001, TEST-001, TEST-002, ML-001, ML-002, DOC-001, CFG-001, HYG-001, CI-001
Stage 2: CORE-001, CORE-002, CORE-003, CORE-004, SEC-002, F1-001, CORE-005, CORE-006, CORE-007, ML-003, SEC-003, DOC-002

## Leads for later stages
- Firewall adapter: `containmentId` interpolated unsanitised into netsh `description=` (WindowsFirewallAdapter.js:84). Check where containmentId comes from (Stage 4).
- `honeypot/parsers/log_parser.py` authenticates with SENTINEL_KEY; `trigger_block.js` / `sentinel_output.py` hit `/api/honeypot/ingest` with X-API-Key. Which key does ingest accept? (F1)
- `honeypot/rl_engine/deception_scorer.py` differs from `ai-engine/rl_engine/deception_scorer.py`; and `ai-engine/inference/deception.py` exists — which is live? (F3)
- `honeypot/collectors/session_collector.js` required by `backend/routes/honeypotIngest.js`; collector auto-creates CRITICAL alerts with attacker command text (stored-XSS check, Stage 4).
- Test-only `/api/test/emit-socket` (server.js, uncommitted) is unauthenticated, gated by NODE_ENV=test && ALLOW_TEST_ROUTES=true.
- Time-of-day features present in all saved models — determine what the "leakage fix" actually was (Stage 5). Experiments dir has later candidate models (`gate1_phase13_shift_and_leakage/candidate_rf_multicorpus_v3.pkl`) not on the runtime load path.
- `paper_text.txt` is the implementation paper ("SentinelAI: An Adaptive Cyber Defence Platform…"); `IMPLIMENTATION.pdf` presumably same. Survey paper not found in repo.
- No Dockerfile/compose tracked although many docs describe Docker (removed per docs/DOCKER_REMOVAL_*).

## Open questions for user
- Was `db-fixes` (or any branch other than main) ever pushed? Local tracking refs show only `origin/main`; can't confirm without network.

## Stage 2 leads carried forward
- Stage 3: seed.js (150 synthetic threats), demo-* sessions, Landing/AIAnalytics static numbers, getNodeStatus nodes.
- Stage 4: WindowsFirewallAdapter.js:84 raw containmentId in description (containmentId source = ContainmentAction
  model default — check it is server-generated UUID); session_collector Alert.message includes raw attacker command
  (React escapes; no dangerouslySetInnerHTML found in frontend/src); log_parser posts with SENTINEL_KEY so the
  honeypot box holds the AI-engine key too.
- Stage 5: honeypot synthetic features (CORE-002); time-of-day; sniffer labels flows with rule output (circular labels).

## Next step
Await user reply to Stage 2, then Stage 3 (claims matrix).
