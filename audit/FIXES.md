# Fix batch 1 — Stage 1 & 2 findings (2026-10-21)

The user asked for the Stage 1 and 2 fixes to be applied, which lifts the audit's read-only rule for these edits.
Backup of all pre-existing uncommitted work (taken before any edit): `audit/backup/`
(`pre-fix-unstaged.patch`, `pre-fix-staged.patch`, `pre-fix-untracked.tar` + list). Nothing was committed.

## Fixed in code

| Finding | Change | Files |
|---|---|---|
| CORE-001 (blocks never reach a firewall; UI claims success) | Legacy auto/manual block paths now run the containment safety check first. A refused auto-block reverts the threat (status, autonomousAction) and records nothing. Alerts and toasts now say "added to deny-list (honeypot deny-list only; no host firewall rule)" or "Simulated containment recorded (mock adapter…)", driven by the returned `enforcementBackend`. | `backend/services/containmentService.js`, `backend/services/honeypotService.js`, `frontend/src/utils/containmentLabels.js` (new), `frontend/src/pages/{Dashboard,ThreatLogs,Settings}.jsx`, `frontend/src/hooks/useRealTimeAlerts.js`, `frontend/e2e/{dashboard,settings,threat-logs}.spec.js` |
| CORE-001 (no protection for own hosts) | New `CONTAINMENT_PROTECTED_TARGETS` (IPv4 hosts/CIDRs, overlap-checked) in the policy; `checkTargetSafety()` exported for legacy paths. RFC1918 is **not** protected by default because tests and lab attackers use private ranges. Set the variable for your demo LAN. | `backend/services/containmentPolicyService.js`, `backend/.env.example`, test `backend/tests/containmentProtectedTargets.test.js` (new) |
| SEC-002 (fabricated predictions) | `POST /api/ai/predictions` accepts only `SENTINEL_KEY` (honeypot key → 403; user JWTs → 401). Fields are whitelisted, so `verified`, `actualClass`, `generatedThreat`, `inputSource` and the like can't be set. `/honeypot/ingest/command` now derives `intent`/`isMalware` server-side. | `backend/routes/aiEngine.js`, `backend/routes/honeypotIngest.js`, `backend/tests/internalAuth.test.js`, `backend/tests/roleMatrix.test.js` |
| SEC-002 (key separation) | Parser/sniffer prefer `HONEYPOT_API_KEY`; they fall back to `SENTINEL_KEY` with a warning. | `honeypot/parsers/log_parser.py`, `honeypot/sniffer/sniffer.py` |
| SEC-003 | Constant-time key comparison helper. | `backend/utils/apiKeys.js` (new) |
| CORE-002 (honeypot "ML") | The honeypot result now carries `classificationMethod: "rule_profile_synthetic_flow"`, and the stored `modelVersion` gets a `+rule_profile_synthetic_flow` suffix (visible in AI Analytics). The method is documented in code. **Scoring unchanged.** | `ai-engine/inference/predictor.py`, `backend/services/honeypotService.js` |
| CORE-004 (Q-learning) | The reward now goes to the profile active during the session (action), from the previously active profile (state). The backend sends the actually served persona (`DECEPTION_ACTIVE_PROFILE`, default `centos_7` = cowrie.cfg) instead of an unset recommendation. Output adds `activeProfile` and `recommendationApplied: false`. Persistence flag documented. | `ai-engine/rl_engine/deception_scorer.py`, `backend/services/honeypotService.js`, `ai-engine/.env.example`, test `ai-engine/tests/test_deception_credit_assignment.py` (new) |
| CORE-006 (duplicate socket delivery) | Redacted copies go to viewer rooms only, no longer to `all`/`threat_subscribers`, which privileged sockets also join. | `backend/websocket/socketManager.js`, test `backend/tests/socketRoomDelivery.test.js` (new) |
| CORE-007 (fake nodes) | Node status lists only `SSH-COWRIE-01`. | `backend/services/honeypotService.js`, `frontend/e2e/README.md` |
| ML-002 (CWD-dependent model) | A relative `MODEL_DIR` resolves against `ai-engine/`, not the shell CWD. | `ai-engine/inference/main.py`, `ai-engine/inference/deception.py`, `ai-engine/.env.example` |
| ML-003 (silent defaults) | `/predict`, `/predict/internal`, `/predict/eval` return `defaultedFeatures` (fields the caller omitted). Not rejected, to keep replay/readiness scripts working. | `ai-engine/inference/main.py` |
| OPS-001 (seed/clean wipe DB) | Both scripts refuse to run unless `--confirm=<database-name>` matches `MONGO_URI`. | `backend/utils/destructiveGuard.js` (new), `backend/utils/seed.js`, `backend/utils/clean.js`, test `backend/tests/destructiveGuard.test.js` (new) |
| TEST-001 (E2E hits real backend) | Backend `reuseExistingServer: false`. | `frontend/playwright.config.js` |
| TEST-002 (E2E CI can't boot) | CI env sets `HONEYPOT_API_KEY`, `SENTINEL_KEY` (test values). | `.github/workflows/e2e.yml` |
| CI-001 | Frontend job runs `npm test`. `validateTestDatabaseName` moved to `frontend/e2e/dbGuard.js` so the unit test doesn't need backend `node_modules`. | `.github/workflows/ci.yml`, `frontend/e2e/{dbGuard.js,global-setup.js}`, `frontend/tests/e2eSafety.test.mjs` |
| DOC-001 | README AI-engine step: `--host 127.0.0.1 --env-file .env`. | `README.md` |
| DOC-002 | Enrollment doc now states forced first-login change is implemented. | `docs/ENROLLMENT_POLICY_20261015.md` |
| CFG-001 | `ADMIN_INITIAL_PASSWORD` placeholder rejected outside test. | `backend/config/validateEnv.js`, `backend/tests/secretsValidation.test.js` |
| Stage-4 lead | `containmentId` sanitised before interpolation into the netsh `description=`. | `backend/services/containment/WindowsFirewallAdapter.js` |

## Not fixed — needs the user, a decision, or a later stage

| Finding | Why not done here | What to do |
|---|---|---|
| SEC-001 leaked honeypot key | Rotating it changes your local `.env` files and the honeypot host config. History rewrite is destructive. | Generate a new key, put it in `backend/.env`, `deployment/.env.demo` and the honeypot host. Don't push `db-fixes` until the key is rotated. |
| CORE-001 full fix (route all blocks through the adapter) | Larger refactor touching ~30 containment tests. The honest-labelling fix removes the false claim now. | Separate batch: make `executeAutoBlock`/`blockThreat` call `requestContainment`. |
| CORE-003 no live traffic feed / F1-001 Cowrie not live | Infrastructure (Linux/WSL Cowrie) or wording. | Stage 3 wording list; optionally a WSL Cowrie run. |
| CORE-004 apply recommendations | Needs a Cowrie restart mechanism in a lab. | Keep "recommendation only" wording. |
| CORE-005 dead event bus | Wire-or-delete is a design decision. | Decide; then remove the phase-7 reliability claim or route emits through the bus. |
| ML-001 time-of-day features in all models | Retraining. | Stage 5 (will ask before running training). |
| HYG-001 stale models / .bak files | Deleting tracked files. | Confirm, then remove or move to an archive branch. |
| Plaintext historical credentials in sentinel-db (prior-report) | Writes to your real DB. | Run `scratch/scrub_honeypot_credentials.mjs --apply` yourself after a backup. |

## Verification status (ran 2026-10-21, user-approved)
- Backend Jest (`NODE_ENV=test`, `AUTH_TEST_MONGO_URI` unset): **54 suites passed, 4 skipped; 948 tests passed, 13 skipped, 0 failed.**
  The first run aborted: my new `socketRoomDelivery.test.js` passed a mock `io` without `engine`, and the health
  interval started by `socketManager.init()` crashed the process. Fixed in the test (mock `engine`, `stopHealthBroadcast`); full re-run is green.
- AI engine pytest: **335 passed** (incl. 3 new credit-assignment tests). Warning: experiment pickles were saved with
  scikit-learn 1.7.2 but the venv has 1.4.0 (Stage 5 item).
- Frontend: `npm test` **36/36 passed**; `npm run build` succeeded (covers the edited JSX pages).
- Not run: Playwright E2E (needs a local `sentinelai_test` MongoDB and starts servers), real-firewall VM harness, Cowrie.

---

# Fix batch 2 — the "Not fixed" rows (2026-10-22, at `a5856b7` + working tree; nothing committed)

| Row | Outcome | What was done |
|---|---|---|
| SEC-001 leaked honeypot key | **PARTLY FIXED** | Rotated `HONEYPOT_API_KEY` to a new 64-hex value in `backend/.env` and `deployment/.env.demo` (no local file holds the old value). Removed the hard-coded key **and three verify-account passwords** from the tracked `scratch/run_all_verify.ps1`; the script now refuses to run unless they are set in the shell. **Not done:** the honeypot host's env (not reachable from here); Git-history purge (needs a force-push of a shared branch); the account passwords: a read-only check showed the leaked passwords still work for `admin@sentinel.io`, `arjun@sentinel.io`, `priya@sentinel.io` and `sara@sentinel.io`. |
| CORE-001 manual blocks via adapter | **FIXED** | `enforceManualBlock` / `releaseManualBlock` in `containmentService.js`; the Block button, block-ip and unblock-ip now go through policy → adapter → ContainmentAction after the deny-list write and audit succeed. `requestContainment(syncLegacyState)` and `rollbackContainment(releaseLegacyState)` options keep the manual paths' own BlockedIP/ThreatLog semantics. Manual adapter rules get the 30-day policy maximum, not the 1-hour default. Responses carry `enforcement`; the Dashboard toast reports it (`manualBlockOutcome`). Test: `backend/tests/manualBlockEnforcement.test.js`. |
| CORE-003 / F1-001 wording | **FIXED (README + UI)** | README (served model, replay input, rule-based honeypot classification, containment, MITRE scope, latency), `Landing.jsx` (hero text; terminal relabelled "Illustrative output (not live)" with accurate lines), `Features.jsx`, `About.jsx`. **Paper not edited:** only the PDF and its text extraction are in the repo. |
| CORE-003 / F1-001 live Cowrie run | **NOT FIXED** | Needs a Linux/WSL host running Cowrie. |
| CORE-004 apply recommendations | **CODE DONE, NOT VALIDATED** | `honeypot/deception_rotator.py` (added by `a6de7f1`) applies personas; a live run needs Cowrie. |
| CORE-005 event bus | **ALREADY FIXED** | `socketManager.js:110-120` records every delivery; `securityEventBus.js:766-772` persists to the outbox store. |
| ML-001 time-of-day | **WITHDRAWN** | Features are constant zero in training and have 0.0 importance; nothing to fix. |
| HYG-001 stale models | **KEPT BY DESIGN** | Every non-served file is referenced by tests, the legacy loader, `verify_protected_hashes.py` or `docs/PRESERVED_ASSETS_SHA256.json`, or is a rollback target in `registry_history.jsonl`; `ai-engine/models/README.md` documents which files are served. Deleting would break tests and the protected-hash check. |
| Plaintext credentials in sentinel-db | **ALREADY FIXED** | Fresh backup `backups/sentinel-db-2026-10-22T05-55-35-492Z` (git-ignored), then a dry run: 0 unredacted credentials in 8 sessions, so no write was needed. Older pre-scrub backups in `backups/` still contain plaintext passwords. |
| (found while testing) | **FIXED** | `honeypotService.test.js`: `setImmediate` enrichment (added in `a5856b7`) ran after Jest teardown and made `npm test` exit 1 even with all tests passing; the suite now drains it in `afterAll`. |

## Verification (ran 2026-10-22)
- Backend Jest: **71 suites passed, 4 skipped; 1114 passed, 13 skipped, 0 failed; exit 0.** The first run failed one
  test (TEST 8 in `containmentPolicy.test.js` timed out on the new unmocked `ContainmentAction` lookup); stubbed like the
  suite's existing `requestContainment` stub. ESLint clean on all changed backend files (my edit had changed
  `threatController.js` line endings; restored with `eslint --fix`, formatting only).
- Frontend: `npm test` **49/49 passed**; `npm run build` succeeded.
- AI engine: no code changed in this batch; not re-run.

## Also in the working tree (after batch 2, uncommitted)
- `honeypot/deception_rotator.py`: `served_persona()` reads the persona from switch_profile's `cowrie.cfg` header and,
  before deciding, records it with the backend when it differs (a fresh database assumes `centos_7`, so the rotator
  could "keep" a persona Cowrie was not serving). Tests: two new cases in `ai-engine/tests/test_deception_rotator.py`.
- `ai-engine/inference/main.py`: `GET /` service index (links to `/health`, `/ready`, `/docs`).
- `ai-engine/demo/replay_cicids.py`: `--backend-url` defaults to `SENTINEL_BACKEND_URL`.
- `scripts/demo/` (start/stop/reset-demo-db PowerShell, `cowrie-demo-mode.sh`): demo stack on a separate
  `sentinel-demo` database and Q-table, mock containment only. `.gitattributes` forces LF on `*.sh` for WSL.

## Re-verification at HEAD `56981a3` + working tree (ran 2026-11-01) — closes TEST-004
- Backend Jest: **71 suites passed, 4 skipped; 1128 passed, 13 skipped, 0 failed; exit 0.**
- AI engine pytest: **594 passed**, 0 failed (6 InconsistentVersionWarnings: experiment pickles from scikit-learn 1.7.2, DEP-001).
- Frontend: `npm test` **49/49 passed**; `npm run build` succeeded.
- Still not run: Playwright E2E, real-firewall VM harness, live Cowrie (F1-001 / CORE-004).
