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
