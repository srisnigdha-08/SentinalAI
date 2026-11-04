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

---

# Fix batch 3 — baseline breakers and remaining P2/P3 rows (2026-11-01, at `a4f606d`; nothing committed)

Baseline at `a4f606d` before any edit (this machine, Windows 11, `core.autocrlf=true`):
- Backend Jest: 71 suites passed, 4 skipped; **1128 passed**, 13 skipped, 0 failed; exit 0.
- Backend ESLint: **exit 1, 11,918 errors.** 11,914 are `Delete ␍` (CRLF checkout vs prettier's LF default). Linting the
  committed (LF) blobs via `git show HEAD:<file> | eslint --stdin` leaves **4 real errors in 3 files**
  (`services/honeypotService.js`, `tests/deceptionProfile.test.js`, `tests/reviewQueue.test.js`), so the CI lint step
  fails at HEAD as well.
- AI engine pytest: **1 failed, 593 passed** — `test_separate_processes_do_not_lose_each_others_learning`
  (`PermissionError: [WinError 5]` from `os.replace` in `DeceptionQLearner.save`). Intermittent: 2 of 14 reruns failed.
- Frontend: `npm test` 49/49 passed.

| ID | Outcome | What was done |
|---|---|---|
| TEST-005 (new) Q-table save fails on Windows under concurrency | **FIXED** | Root cause: a learner's constructor `_load()` reads the table without the lock, and Windows refuses `os.replace` onto a file another process has open; a just-unlinked `.lock` is also "delete pending" and `O_EXCL` creation raises `PermissionError`. `save()` now retries the replace briefly (`_replace_with_retry`, ≤ 4.75 s total), and `_exclusive_lock` treats `PermissionError` as busy until its deadline, then re-raises it. POSIX behaviour unchanged. Test: `test_save_retries_a_replace_blocked_by_an_open_reader`. The two-process test passed 15/15 reruns after the fix. Files: `ai-engine/rl_engine/deception_scorer.py`, `ai-engine/tests/test_medium_fixes.py`. |
| CI-002 (new) backend lint red | **FIXED** | `eslint --fix` on the 3 files (formatting only; `git diff -w` reviewed). `backend/.prettierrc` gets `"endOfLine": "auto"` so a Windows checkout lints the same as CI; git still stores LF. `npx eslint .` → exit 0. |
| OPS-002 compose publishes the plain-HTTP API on all interfaces | **FIXED (not run: no Docker here)** | `docker-compose.yml` backend and dashboard ports bind `${BACKEND_BIND_ADDRESS:-127.0.0.1}` / `${DASHBOARD_BIND_ADDRESS:-127.0.0.1}`. A honeypot on another host needs `BACKEND_BIND_ADDRESS` set to the lab-network IP for that run (documented in the file and `deployment/.env.compose.example`). YAML parsed with PyYAML; `docker compose config` not run. |
| OPS-004 collector session cache unbounded | **FIXED** | `honeypot/collectors/session_collector.js`: the sessionId → _id cache is capped at 10,000 entries (oldest evicted; a miss falls back to `findOne`). Test in `backend/tests/honeypotCollectorContract.test.js`. |
| SEC-005 helmet CSP disabled | **FIXED** | `backend/server.js`: helmet's default CSP (`default-src 'self'`, `script-src 'self'`, `object-src 'none'`, `frame-ancestors 'self'`) minus `upgrade-insecure-requests` (would break `/api/docs` over plain HTTP). Test in `backend/tests/authHardening.test.js` checks the header and that the dev Swagger page has no inline scripts and its init script loads. The dashboard's own CSP (nginx / Vite) is unchanged and still absent. |
| EVT-001 `ip_unblocked` has no UI listener | **FIXED** | `frontend/src/hooks/useRealTimeAlerts.js` toasts on `ip_unblocked` (manual unblock, rollback, TTL expiry). `critical_alert` is a duplicate of the CRITICAL `new_alert` toast already shown, so it stays unlistened. Verified by build + unit tests only; not exercised in a browser. |

Still open (unchanged by this batch): SEC-001 remainder (honeypot-host key, history purge, the four leaked account
passwords still valid), live Cowrie run (F1-001 / CORE-004), ML-004 LODO for the served XGB, ML-005 clean-commit
retrain, RET-001 first promotion, TEST-003 cross-service E2E, OPS-003 Mongo auth in compose, DEP-001 dependency
refresh, dashboard CSP, paper wording.

## Verification after batch 3 (ran 2026-11-01)
- Backend Jest: 71 suites passed, 4 skipped; **1130 passed** (+2 new), 13 skipped, 0 failed; exit 0.
- Backend ESLint (`npx eslint .` on the Windows checkout): **exit 0** (was exit 1, 11,918 errors).
- AI engine pytest: **595 passed** (+1 new), 0 failed; exit 0 (was 1 failed).
- Frontend: `npm test` 49/49 passed; `npm run build` succeeded.
- Not run: Playwright E2E, `docker compose config` (no Docker on this machine), live Cowrie, real-firewall VM harness.

---

# Fix batch 4 — integration validation and closure (2026-11-01, at `6883308`; nothing committed)

Start state: clean tree at `6883308`, 7 commits ahead of `origin/db-fixes`, no other sessions' changes; all batch 1-3
fixes present (suites green at the end of batch 3).

| ID | Final status | What was done / found |
|---|---|---|
| SEC-001 | **PARTIALLY RESOLVED / REQUIRES APPROVAL** | Read-only check (`SEC001_REMEDIATION.md`): repo is **public**, leaking commits `315700c`/`a7fa029` are on GitHub; the old key is in no local env file and nowhere on the WSL honeypot host, and is refused; **the leaked passwords still work for 4 accounts in sentinel-db and 5 in sentinel-demo** (session count wrong here: 114 unrevoked sessions in sentinel-db, see the 2026-11-02 correction in SEC001_REMEDIATION.md). Plan written; passwords and history purge need you. |
| TEST-003 cross-service E2E | **RESOLVED (local)** | `scripts/integration/run_integration.cjs` (+ README): real engine + backend + MongoDB, workflows A-D and resilience, 25/25. Not in GitHub CI: the CICIDS CSVs are git-ignored. |
| F1-001 live Cowrie / CORE-004 apply recommendations | **RESOLVED (verified once, lab)** | `--cowrie` + `scripts/integration/cowrie_lab.sh`: real SSH sessions against WSL Cowrie on 127.0.0.1, rotator switched `ubuntu_22` → `raspberry_pi`, hostname change seen over SSH, second session credited to the new persona, Q-table updated (episode_count 3); original cfg and state restored (hash check). |
| ROT-001 (new) rotator left a rewritten cfg after a failed restart | **RESOLVED** | `honeypot/deception_rotator.py`: restores the previous `cowrie.cfg` and retries the restart; result reports `restored`/`recovered`. Test in `test_deception_rotator.py`. |
| CORE-008 (new) block failed for INVESTIGATING/CONTAINED threats | **RESOLVED** | `backend/models/ThreatLog.js` enum; `tests/blockFromTriageStatus.test.js` (fails before, passes after). Found by the Firefox/WebKit E2E runs. |
| UI-001 (new) modal state carried across opens | **RESOLVED** | `key` on both containment modals and the triage modal; triage form initialised at mount (`TriageModal.jsx`, `ThreatLogs.jsx`, `Settings.jsx`). |
| E2E-001 (new) three broken/racy E2E tests | **RESOLVED** | landing label (stale since 347af80), seeded-user restore after the password-change spec, row-render wait in threat-logs. Full suite 163/177 → 177/177. |
| E2E-002 (new) Firefox triage note intermittently empty | **DEFERRED** | 2 of 8 Firefox repeats; absent in the final full run. Cause unknown; trace procedure in FINDINGS. |
| RL-001 (new) stored recommendation ≠ applied persona | **DEFERRED (design)** | Seen live; documented. |
| ML-004 / ML-005 / RET-001 | **REQUIRES APPROVAL** | `audit/ML_EVAL_PLAN.md`: provenance verified (all 8 dataset sha256 match), per-day class table (7 of 10 classes occur on one day only; Data Exfiltration has 0 samples), protocols P1-P5, metrics, promotion and rollback criteria. No training run. |
| OPS-003 MongoDB auth | **PARTIALLY RESOLVED** | Compose: root user + `mongo-init.js` on first start, backend as `sentinel_app`; `mongo-init.js` takes `SENTINEL_DB_NAME`. Verified the role at runtime (`run_with_mongo_auth.cjs`, 24/24, no authorization errors). Compose itself not run (no Docker); existing volumes need mongo-init run once by hand (documented in compose). |
| Dashboard CSP | **RESOLVED (preview), nginx not run** | `frontend/csp.js` → `vite preview` headers and the same string in `nginx.conf` (+ nosniff, Referrer-Policy); `tests/csp.test.mjs`. Browser check on the production build: 11 pages, 0 violations, fonts and socket OK. |
| DEP-001 | **VERIFIED EXISTING / DEFERRED** | Installed versions equal the pins; served models load with no version warning (registry sklearn 1.4.0 = venv). Warnings come only from experiment pickles (sklearn 1.7.2) loaded by tests. Pin refresh deferred (needs network + regression run). |
| Compose validation | **BLOCKED** | Docker not installed; YAML parses, `docker compose config` not run. |
| WebSocket auth | **VERIFIED EXISTING** | JWT socket connects, bad token refused (harness). Reconnection after a server restart not tested. |
| Service startup / health | **VERIFIED EXISTING** | `/health` is readiness (Mongo + engine + revocation): 503 while the engine is down, API keeps serving. |
| Test/dev isolation | **VERIFIED** | harness: generated DB, secrets, empty dotenv; E2E: `sentinelai_test` guard; auth run: throwaway mongod. The developer databases were not written. |

Also: `.gitignore` ignores `scripts/integration/runs/`; `.claude/launch.json` (local preview servers for the CSP check)
is new and untracked.

## Verification after batch 4 (ran 2026-11-01)
- Backend Jest: 72 suites passed, 4 skipped; **1133 passed**, 13 skipped, 0 failed; exit 0. ESLint: exit 0.
- AI engine pytest: **596 passed**, 0 failed.
- Frontend: `npm test` **52/52**; `npm run build` OK.
- Playwright E2E, Chromium + Firefox + WebKit: **177/177 passed** (13.8 min); 163/177 at the start of the batch.
- Integration: `run_integration.cjs` **25/25**; `--cowrie` **30/30** (before the resilience check existed);
  `run_with_mongo_auth.cjs` **24/24** (before the resilience check existed).
- Not run: Docker Compose, real firewall adapter / VM harness, nginx, auto-block end to end, ML protocols P1-P5.

---

# Fix batch 5 — SEC-001 verification, P5, RL-001 decisions, E2E stability (2026-11-02, at `ff90941`; nothing committed)

| ID | Final status | What was done / found |
|---|---|---|
| SEC-001 | **REQUIRES USER ACTION** | Re-checked: the 3 leaked passwords still open 9 account records (4 in sentinel-db, 5 in sentinel-demo); the old honeypot key is in no env file and refused. Corrected session count (checker bug: `userId` → `user`): 114 unrevoked rows in sentinel-db. Session invalidation verified on the running backend (7 requirements, `SEC001_REMEDIATION.md` § Sessions). Account-by-account checklist with exact steps. |
| AUTH-001 (new) no way to change your own password in the UI | **RESOLVED** | `/change-password` redirected everyone not flagged `mustChangePassword`. Route opened to all signed-in users; page wording/cancel differ for forced vs voluntary; sidebar "CHANGE PASSWORD". E2E test (3 browsers). Files: `frontend/src/App.jsx`, `pages/ChangePassword.jsx`, `components/Sidebar.jsx`, `e2e/password-change.spec.js`. |
| SCAN-001 (new) secret scanner gaps | **RESOLVED** | Commit-range scanning (`--range`, CI over every pushed commit, `fetch-depth: 0`), reviewed-history baseline, length-only output (was 2+2 characters), exact-path allowlist, reason-required marker, `*_KEY` names, all URI schemes, backup files, whole-word test values. 9 tests incl. a throwaway-repo range scan. History values bcrypt-checked: only the 3 known passwords open anything. Files: `scripts/security/*`, `.github/workflows/ci.yml`, `.githooks/pre-commit`. |
| ML-004 plan | **RESOLVED (plan)** | `ML_EVAL_PLAN.md` corrected: 8 files ≠ 5 calendar days; `--rows 20000` is unused for real data; identical-boundary rule; per-day class table. |
| P5 | **VERIFIED** | `ai-engine/evaluation/p5_served_model_eval.py`; split reconstruction equals the meta exactly (re-verified after the loader change); accuracy 0.9897, macro F1 0.8738, weighted F1 0.9907; benign FPR 0.230 % at the alert line; full results in `ML_EVAL_PLAN.md` §5 and `ai-engine/experiments/p5_served_eval_20261102/`. |
| P3/P4/P4f | **REQUIRES APPROVAL (prepared)** | `ai-engine/evaluation/xgb_holdout_eval.py` plan mode: frozen manifests (sha256 in `experiments/xgb_holdout_20261102/plan.json`; manifests git-ignored), fold tables with classes absent from training, per-fold label re-encoding, `--run` refuses without `--approved`. 4 unit tests. Nothing trained. |
| RL-001 | **PARTIALLY RESOLVED** | Persisted decisions (`DeceptionDecision`): drawn once per served persona, reused by every caller (6 concurrent requests → 1 decision), applied/acknowledged/failed by id with compare-and-set, superseded on persona change or TTL. Rotator sends `decisionId`, acknowledges keeps, fails on restart failure. Live lab: applied persona `debian_11` = APPLIED decision's action. Not changed (needs your decision): closure-time draws still stored as `session.recommendedProfile`; no minimum-evidence rule; engine RNG not seeded. `RL001_DESIGN.md` § Implemented. |
| E2E-002 | **PARTIALLY RESOLVED** | Root cause of the Firefox stall found: the lazy route chunk (`/src/pages/Dashboard.jsx`) served on demand by the Vite dev server never completed after login in Firefox. `server.warmup` for `src/pages` and `src/components`: isolated repeats 5/10 and 6/10 failing → 0/10 and 0/15; full suite 7.8 min (was 13.8). Rejected hypothesis (tested, reverted): Socket.IO long-polling starving connections (websocket-first: still 6/10). Residual: the empty-triage-note failure, 1 in 39 Firefox runs of the spec; cause unknown. |
| WS-001 reconnection | **VERIFIED** | After a backend restart the socket reconnects (5.6 s), authenticates with its token, receives events exactly once (no duplicate after re-subscription); logout disconnects the user's socket server-side. |
| C-auto autonomous response | **VERIFIED (mock adapter)** | Auto-block contained 3/3 unprotected high-score flows, refused 1/1 in `CONTAINMENT_PROTECTED_TARGETS` (recorded on the threat), no second action on repeated detections, audit lines present, operator rollback → ROLLED_BACK + deny-list cleared + threat restored + `ip_unblocked`; engine outage → DEGRADED, never blocked; TTL expiry earlier in the run. |
| Demo naming | **RESOLVED** | Demo A — Honeypot Intelligence, Demo B — AI Threat Detection, Demo C — Autonomous Incident Response in README, runbooks, readiness report, harness. |
| Deployment | **BLOCKED (tools)** | Docker and nginx not installed: compose start, nginx CSP and TLS not executed. Static: compose YAML parses; every `${VAR:?}` is in `.env.compose.example`. |

## Verification after batch 5 (ran 2026-11-02)
- Backend Jest: 73 suites passed, 4 skipped; **1147 passed**, 13 skipped, 0 failed. ESLint: exit 0.
- AI engine pytest: **604 passed**, 0 failed.
- Frontend: `npm test` 52/52; `npm run build` OK.
- Playwright E2E, Chromium + Firefox + WebKit: **180/180** (7.8 min).
- Secret scan: 9/9 tests; tree 0 findings; history 0 new (25 reviewed in the baseline).
- Integration: `run_integration.cjs --cowrie` **41/41**; `run_with_mongo_auth.cjs` **35/35** (no authorization errors).
- Not run: Docker Compose, nginx, real firewall adapter, P3/P4 training.

---

# Batch 6 — cross-day ML validation, weakness analysis, RL review (2026-11-02, at `c44f0c8`; nothing committed)

| ID | Final status | What was done |
|---|---|---|
| SEC-001 | **REQUIRES USER ACTION** | Read-only re-check: the leaked passwords still open the same 9 account records; no change since the last check. Checklist and verified session behaviour unchanged (`SEC001_REMEDIATION.md`). |
| ML-004 / P3+P4 | **RESOLVED (measured)** | Six approved evaluation fits (P3 + 5 day folds), frozen manifests verified against `plan.json`, train/test disjoint asserted, scaler fitted on training rows only, no tuning; nothing saved; `models/` untouched. Results `ML_EVAL_PLAN.md` §5c → ML-007. |
| ML-007 (new) | **OPEN (finding)** | No cross-day/cross-tool generalisation (see FINDINGS). |
| ML-008 (new) | **REQUIRES APPROVAL** (retrain) | Taxonomy root cause of XSS/Credential Stuffing confusion. |
| Threat-line trade-off | **VERIFIED** | Descriptive sweep on the P5 test split with the served scoring path (`evaluation/p5_threshold_sweep.py`, `experiments/p5_served_eval_20261102/threshold_sweep.json`): 0.10 % FPR only at 0.999 (recall 86.2 %). No threshold changed. |
| RL review | **VERIFIED / DOCUMENTED** | `RL001_DESIGN.md` review: reward measures engagement, not defence; 20 sessions in total in the two databases (7 synthetic, 12 self-generated) so no effectiveness evidence exists; A/B design with fixed-persona and random baselines. No policy change. |
| E2E-002 | **DEFERRED** | 0/45 failures in further Firefox repeats; diagnostic pre-save assertions added. |
| DOC-003 (new) | **RESOLVED** | README: cross-day XGB table; false "multi-event correlation" claim corrected. |
| Deployment | **BLOCKED (tools)** | `audit/DEPLOYMENT_VALIDATION.md`: what was checked here and the exact Docker/nginx procedure (not run). |

Files: `ai-engine/evaluation/xgb_holdout_eval.py` (metrics, CIs, collisions, manifest verification, versions),
`ai-engine/evaluation/p5_threshold_sweep.py` (new), `ai-engine/tests/test_xgb_holdout_eval.py`,
`ai-engine/experiments/xgb_holdout_20261102/results.json`, `ai-engine/experiments/p5_served_eval_20261102/threshold_sweep.json`,
`frontend/e2e/threat-logs.spec.js`, `README.md`, `audit/*`.

## Verification (2026-11-02)
- Evaluator unit tests 4/4; P3/P4 run exit 0 (six fits, 3.7–11.2 s each); threshold sweep reproduces P5 at 0.90/0.92.
- Playwright threat-logs spec: Firefox 45/45 (×15), Chromium + WebKit 6/6. Secret scan: tree 0 findings.
- Not re-run (no code change in those areas since batch 5's green run): backend Jest, full pytest, full E2E, integration.

---

# Batch 7 — generalisation root causes and plans (2026-11-02, at `c73efa0`; nothing committed)

| ID | Final status | What was done |
|---|---|---|
| SEC-001 | **REQUIRES USER ACTION** | Re-checked: 9 records still accept the leaked passwords. |
| Model integrity | **VERIFIED** | classifier, anomaly and golden-set sha256 equal `registry.json`. |
| Full-hybrid P3/P4 | **REQUIRES APPROVAL (implemented, not run)** | `xgb_holdout_eval.py --with-if --approved-if`: IF on benign training rows only, served combination, Unknown/REVIEW, reproduction check `--expect` (stops if a refit differs). 2 new tests (6/6). |
| ML-009 root cause | **VERIFIED** | `evaluation/shift_analysis.py` (no fitting) → tool fingerprints, not benign drift. |
| Improvement options | **DOCUMENTED** | `ML_GENERALIZATION_PLAN.md` §3: 8 ranked options with hypothesis, cost, data, success criteria, failure modes. |
| CSE-CIC-IDS2018 | **DOCUMENTED** | availability, terms (citation required), schema, labels, quality, touched vs untouched days, sizes from the public bucket listing; Experiments A/B with acceptance criteria. Nothing downloaded. |
| DOC-004 | **RESOLVED** | Deployment procedure no longer exposes passwords or suggests deleting a volume. |
| RL defaults | **DOCUMENTED (needs approval)** | rename per-session field, min 5 real sessions, 24 h dwell, fixed/random baselines; demo override. |

## Verification (2026-11-02)
- `pytest tests/test_xgb_holdout_eval.py`: 6/6. Shift analysis exit 0. Model hashes match. Secret scan: tree 0 findings.
- Firefox threat-logs spec ×30: 90/90 passed (8.0 min). Since the warmup fix: 1 empty-note failure in 174 runs, 0 in the last 135; E2E-002 stays DEFERRED (not reproducible).
- Full-hybrid P3/P4 (follow-up, approved) — **VERIFIED (measured)**: 6 reproduction-checked XGBoost re-fits + 6 benign-only IF fits; hybrid recall at 0.90 equals classifier-only (P3 12.14 %, P4 0.2–10.4 %); the IF adds review signal on Wednesday DoS (46 % "Unknown"), not alerts. `ML_EVAL_PLAN.md` §5c-2.

---

# Batch 8 — controlled development protocol and infrastructure (2026-11-02, at `f831af5`; nothing committed, nothing trained)

| Item | Status | What |
|---|---|---|
| SEC-001 | **REQUIRES USER ACTION** | unchanged (9 records). |
| Baseline | **VERIFIED** | git, model/registry hashes, Q-table hash, frozen manifests, P5/P3/P4/hybrid metrics. |
| Protected external test | **RESOLVED (enforced)** | `evaluation/protected_data.py`: 16/20/22/28-02-2018 cannot be read by development code; tested. |
| Feature ablation | **PREPARED** | `evaluation/feature_sets.py` variants A–E (stateless, row-wise; tested for no cross-split dependence). |
| Taxonomy | **PREPARED** | `evaluation/taxonomies.py` T0 (deployed), T1 (split Credential Stuffing), T2 (families), TB (binary); every raw label of both corpora mapped; unknown labels raise; T0 equals the deployed LABEL_MAP. |
| Development runner | **PREPARED (plan run only)** | `evaluation/dev_experiments.py`: 2017 + 2018-dev pools with identical preprocessing (DATA-002 avoided), D17/D18 folds, 7 frozen candidates, multiclass and two-stage architectures, metrics incl. PR-AUC, Brier, per-family, latency, model size; `--run` needs `--approved`. Plan run: `experiments/dev_20261102/plan.json`. |
| Protocol | **PRE-REGISTERED** | `audit/ML_DEV_PROTOCOL.md` v1: matrix, folds, selection rule, acceptance, resources, first-batch approval. |

## Verification (2026-11-02)
- `pytest tests/test_dev_experiments.py`: 13/13. Plan run exit 0 (73 s pool build). `models/`, `runtime/` unchanged.
- Batch 1 (approved) — C0, C1, C2 on D17 + D18: all manifests equal the plan; **no candidate eligible under §7**
  (C1/C2 raise benign FPR 2–10×); recall gains 3.5–6 points. Served model unchanged. `ML_DEV_RESULTS.md`.
- Batch 3 (approved) — C4 multi-dataset: D18 recall 11.1 → 32.3 % (2018 botnet 0 → 61 %, web 0 → 61 %) but benign FPR
  6.45 % mean / 24.3 % on 21-02 → **not eligible**. Nothing goes to the external test; served model unchanged.

---

# Batch 9 — protocol v2 preparation (2026-11-02, at `3b1f349`; nothing committed, nothing trained)

| Item | Status | What |
|---|---|---|
| SEC-001 | **REQUIRES USER ACTION** | unchanged (9 records). |
| 21-02 FP root cause | **PARTLY RESOLVED** | homogeneous out-of-distribution benign pattern confirmed (DATA-004); row-level cause needs predictions (v2 batch). |
| Pipeline integrity | **VERIFIED** | `evaluation/pipeline_integrity.py` (ML-014). |
| Reporting | **ADDED** | `evaluation/dev_summary.py`: macro + pooled + worst fold + without-homogeneous-fold view (ML-013). |
| Protocol v2 | **PRE-REGISTERED** | `audit/ML_DEV_PROTOCOL_V2.md`; C4A/C4B frozen in `dev_experiments.py`; `--dump-predictions` (needs `--run --approved`). v2 plan manifests equal batch 3's. |

## Verification
- `pytest tests/test_dev_protocol_v2.py tests/test_dev_experiments.py tests/test_xgb_holdout_eval.py`: 24/24.
- `models/`, `runtime/` unchanged; protected days not on disk and not read.
- v2 batch 1 (approved), C4/C4-A/C4-B: manifests equal the plan; C4 reproduces batch 3 exactly; models/runtime
  unchanged. **No candidate eligible** (ML-015); C4-A/B best so far (D18 recall 53.2 %, FPR 1.58 %). Nothing
  promoted; no thresholds changed. Row-level analysis in `evaluation/fp_rows_v2.py` (ML-016).
- 2017-Thursday FP analysis (model-free): DATA-005; `evaluation/thursday_fp_2017.py`; 1 new test (19/19 in the v2 + dev suites).
- Label verification plan for DATA-005 pre-registered (`audit/LABEL_VERIFICATION_PLAN.md`); read-only checker `evaluation/verify_labels_2017.py` + 2 tests (not run: needs the GeneratedLabelledFlows file).
- DATA-005 label check run (approved by the owner; mirror download): **VERIFIED**. Checker comparison bug (48 vs 48.0) fixed before the verdict; +1 test (9/9).
- Protocol v3 pre-registered (`audit/ML_DEV_PROTOCOL_V3.md`): frozen verified correction list (sha256 c4e3f1c1…), `--labels corrected_v3`, candidate C4AI; plan runs only (manifests unchanged); +4 tests (32/32).
- v3 runs (approved): manifests equal plan; models/runtime unchanged. **C4-A-I (corrected labels) eligible and selected** (ML-017); recall instability and per-family cost recorded (ML-018). `evaluation/v3_report.py` (+1 test, 33/33). External test not run.
- Operating line pre-registered then computed (`audit/OPERATING_LINE_V3.md`, `evaluation/operating_line.py`, +1 test): C4-A-I 0.915614, C0 0.974834 (ML-019). External test not run.
- v3 stability check (approved): `--train-subsample/--subsample-seed` (+1 test), `evaluation/stability_report.py`; eligibility and lines robust, deployment criterion predicted to fail (ML-020).

---

# Batch 10 — engineering validation and demo readiness (2026-11-02, at `6672b26`; nothing committed)

| Item | Status | What |
|---|---|---|
| UI-002 Adaptive Deception wording | **FIXED** | Panel text, REFRESH button and a decision line (`decisionStatusSummary`: id, "already pending / just drawn", reused until applied or expired). `frontend/src/utils/modelHealth.js`, `pages/HoneypotAnalytics.jsx`; unit test. |
| TEST-006 below-block-line branch | **FIXED (coverage)** | `backend/tests/containmentPolicy.test.js` TEST 5b. |
| XAI-001 per-flow SHAP not in pipeline | **DOCUMENTED** | README (2 places), runbooks corrected; next work. |
| E2E-002 Firefox triage note | **DEFERRED** | 1 failure in the full 3-browser run (167/168); 40/40 when repeated alone with traces; the screenshot shows the status kept (no remount) and the note empty; no cause found in code; no speculative change. About 2 failures in ~380 Firefox executions overall. |
| Demo runbook | **ADDED** | `docs/DEMO_ABC_RUNBOOK.md` (verified operator procedure, A/B/C steps, outage, recovery); stale reality-matrix rows in `THREAT_DEMO_RUNBOOK.md` updated with today's evidence. |
| Performance probe | **ADDED** | `scripts/perf/engine_latency.py` (idle machine): p95 35 ms, 47 ms with SHAP; ready 4.6–6.1 s; 272 MB. |
| SEC-001 | **OPEN (risk accepted by the owner)** | out of scope this batch; unchanged. |

## Verification (2026-11-02)
- Backend Jest 1,148 passed / 13 skipped (73 suites + 4 skipped); after TEST 5b the containment suite is 25/25. Backend ESLint clean.
- AI engine pytest 636 passed. Frontend unit 53/53. Frontend production build OK. Frontend has no ESLint configuration (not run).
- Playwright Chromium/Firefox/WebKit: 167 passed, 1 failed (E2E-002); affected specs after the UI change: 42/42.
- Integration with live Cowrie: 41/41 (`runs/20261102_145846`); MongoDB `--auth` least privilege: 35/35 (`runs/20261102_150153`).
- Registry: classifier, anomaly and golden-set hashes verified; `models/`, `runtime/` unchanged.
- Not run: Docker Compose, nginx/TLS, real firewall adapter.

---

# Batch 11 — per-threat SHAP, frontend reliability (2026-11-03, at `4bd562c`; nothing committed)

| Item | Status | What |
|---|---|---|
| XAI-001 per-threat SHAP | **FIXED** | Engine `SentinelPredictor.explain_vector` + `POST /explain/vector` (key-gated, side-effect free; explainer missing → 200 `explainerAvailable:false`, so the backend's circuit breaker is never tripped by explanations). Backend `services/threatExplanationService.js`, `GET /api/threats/:id/explanation` (analyst/admin; reason codes NO_LINKED_PREDICTION, PREDICTION_MISSING, NOT_A_FLOW, NO_STORED_VECTOR, SCHEMA_MISMATCH, MODEL_VERSION_MISMATCH, NOT_REPRODUCED, ENGINE_UNAVAILABLE, EXPLAINER_UNAVAILABLE). Frontend `ExplanationModal.jsx` (bar chart, guidance), `utils/threatExplanation.js`, Explain button on Threat Logs for threats with a prediction. No new storage; scoring unchanged. |
| UI-003 Threat Logs stale-response race | **FIXED** | Request sequence guard in `pages/ThreatLogs.jsx`; `e2e/threat-logs-race.spec.js` failed before, passes after (3 browsers). |
| LINT-001 frontend lint | **FIXED** | `frontend/eslint.config.js`, `npm run lint`, CI step; dead code removed in 9 files; 0 errors. |
| E2E-002 | **OPEN** | focus-steal hypothesis refuted by experiment; no code change. |
| SEC-001 | **OPEN (risk accepted by the owner)** | out of scope. |

## Verification (2026-11-03)
- AI engine pytest 648 passed (12 new in `tests/test_explain_vector.py`, real served model: 20/20 reproduced, SHAP additivity).
- Backend Jest 1,176 passed / 13 skipped (`threatExplanation.test.js` 24 new; role matrix +1 route). Backend ESLint clean.
- Frontend unit 56/56 (3 new); lint 0 errors / 13 warnings; production build OK.
- Integration with live Cowrie 42/42 (`runs/20261102_191411`), including the per-threat explanation on a replayed threat (90 ms end to end).
- Engine latency (idle): `/explain/vector` p50 26 ms / p95 48 ms; `/predict/internal` p95 33 ms (unchanged).
- `models/`, `runtime/` unchanged; registry hashes verified.

---

# Batch 12 — GitHub Actions failures (2026-11-03, at `596adcd`; nothing committed)

| Item | Status | What |
|---|---|---|
| CI-001 backend Jest | **FIXED** | `backend/tests/retentionPolicy.test.js`: package-managed MongoDB binary. |
| CI-001 AI pytest | **FIXED** | `test_q_table_safety.py` (state-based protected-file checks), `test_gate1_ml_remediation.py`, `experiments/gate1_phase3a_remediation/test_candidate_policy.py`, `test_model_evaluation.py`. |
| CI-001 MongoDB suites | **FIXED** | `.github/workflows/ci.yml` env (JWT secrets, CLIENT_URL); `backend/tests/authBrowser.test.js` (evidence folder, browser lookup). |
| CI timeouts | **ADDED** | `timeout-minutes` on all 7 jobs. |
| TEST-007 | **FIXED** | `frontend/e2e/auth.spec.js` now exercises 401 → refresh → retry. |
| REPRO-001 | **FIXED** | `.gitattributes` for hash-pinned model JSON. |
| Frontend lint | **0 warnings** | Reviewed intentional effects annotated; dead E2E import/variable removed; fixture arguments kept. |

## Verification (2026-11-03)
- Linux, pristine `596adcd` + patch, env read from the patched ci.yml: Backend lint 0 / Jest 1,176 passed + 13 skipped;
  pytest 646 passed + 2 skipped (runtime file still absent after the run); frontend lint 0 problems, unit and build OK;
  MongoDB suites 13/13 (MongoDB 8.2.6 locally; CI uses 7), no hang.
- Windows: Jest 1,176 / 13 skipped, ESLint clean, pytest 648, registry check OK, frontend unit 56/56, build OK,
  E2E auth 33/33 and dashboard/threat-logs/race/explanation 30/30 on three browsers.
- Not verifiable locally: MongoDB 7 service and the runner's Chrome. The CI run after an approved push is the check.

---

# Batch 13 — performance, resilience, stability (2026-11-03, at `94dc068`; nothing committed)

| Item | Status | What |
|---|---|---|
| PERF-001 engine thread oversubscription | **FIXED** | `ai-engine/inference/predictor.py` `_set_inference_threads`; `tests/test_inference_threads.py` (3). |
| WS-001 dashboard not reconnecting after server disconnect | **FIXED** | `frontend/src/context/SocketContext.jsx`, `utils/socketReconnect.js`; unit test (2) and `e2e/realtime.spec.js`. |
| UI-004 duplicate React keys | **FIXED** | `frontend/src/pages/ThreatLogs.jsx`; check in `e2e/explanation.spec.js`. |
| Probes | **ADDED** | `scripts/perf/load_resilience.cjs` (15 checks), `db_query_scale.cjs`, `njobs_breakdown.py`, engine concurrency mode; `e2e/page-performance.spec.js`. |
| Docs | **ADDED** | `docs/PERFORMANCE_AND_RESILIENCE.md`. |
| WS-001 follow-up: retry refused handshakes while MongoDB is down | **FIXED** | found in the finalization review; `socketReconnect.js` also retries "Authentication service unavailable"; harness outage now held past the first retries; revoked/expired-session check; 2 more E2E tests. |
| PERF-001 re-measurement | **DOCUMENTED** | CPU reduction reproduced; throughput gain load-dependent (see FINDINGS, docs §2). |
| E2E-002 | **OPEN** | not seen in this batch's runs; no change. |
| TEST-008 | **OPEN (environment)** | Firefox login stall traced to a frozen content process under memory pressure; see FINDINGS. |
| TEST-009 | **OPEN** | unhandled cancelled-fetch rejections in alert/containment pollers (WebKit smoke, pre-existing). |

## Verification (2026-11-03)
- Backend Jest 1,176 passed / 13 skipped; ESLint clean. AI pytest 651 passed. Registry check OK.
- Frontend unit 58/58; lint 0 problems; build OK.
- Integration harness (A, B, C, D, outage) 36/36. Load/resilience harness 14/14. Page performance spec 18/18 (3 browsers × 3).
- Playwright full run 189/192 under heavy background load (TEST-008); realtime 12/12, explanation + perf 15/15 when run alone.

## Finalization verification (2026-11-03; other apps using ~20-50 % CPU, 0.7-0.9 GB of 7.7 GB free)
- Backend Jest 1,176 passed / 13 skipped (74 suites, 4 skipped); ESLint clean. AI pytest 653 passed. Registry and golden check OK.
- Frontend unit 59/59; lint clean; build OK. Secret-scan tests 9/9; tree scan 0 findings.
- Load/resilience harness 15/15 (full levels). Realtime spec 54/54 (3 repeats × 3 browsers).
- Playwright full run: 209 passed, 1 failed (TEST-009, WebKit smoke, pre-existing), 10.8 min.
- Models, registry (5f76c136) and runtime Q-table (08209e99) unchanged.
- `models/`, `runtime/` unchanged; registry hashes verified.

---

# Batch 14 — final validation and handover (2026-11-03, from `7902115`; nothing committed)

| Item | Status | What |
|---|---|---|
| WS-002 Live Feed duplicates, missed threats, recovery race, merged detections, ordering | **FIXED** | `frontend/src/hooks/useRealTimeFeed.js`, `src/utils/liveFeedSync.js`; `e2e/live-feed.spec.js` (5 tests, real backend), `tests/liveFeedSync.test.mjs` (6) |
| TEST-009 WebKit navigation-cancellation reports | **FIXED (test)** | root cause established (not the pollers); `e2e/fixtures/navigationErrors.js`; smoke spec updated + rapid-navigation test; negative controls `e2e/page-errors.spec.js` (4 tests); `tests/navigationErrors.test.mjs` (5) |
| SETUP-001 README omitted required secrets and the seed | **FIXED (docs)** | README steps 1, 3, 4, 5 |
| SETUP-002 Windows path length; machine-specific links | **DOCUMENTED / FIXED** | README step 1; `HANDOFF.md` links made relative |
| SETUP-003 undocumented optional variables | **DOCUMENTED** | `docs/FINAL_PROJECT_GUIDE.md` §7 |
| Final documentation | **ADDED** | `docs/FINAL_PROJECT_GUIDE.md`, `docs/VIVA_GUIDE.md` |
| E2E-002 | **OPEN (not reproduced)** | Firefox x10, 30/30 |
| TEST-008 | **OPEN (environment)** | none in this batch's runs |

## Verification (2026-11-03; other apps using ~25 % CPU, 0.9 GB of 7.7 GB free)
- Clean clone (short path) → `npm ci` x2 → production build → Python 3.11 venv → registry check → throwaway MongoDB
  7.0.45 → `seed` (refused without `--confirm`, then OK) → engine, backend, `vite preview` up in ~65 s → login (CSRF)
  → `/auth/me` → analyze a golden vector → threat list: all 200; 0 errors in service logs; everything removed after.
- Integration harness with live WSL Cowrie: **42 passed, 0 failed** (`scripts/integration/runs/20261103_061910`);
  `cowrie.cfg` hash and stopped state restored exactly.
- `start-demo.ps1` (three UP in 61 s), `cowrie-demo-mode.sh on` (check-block HTTP 200, blocker thread alive) / `off`,
  `stop-demo.ps1` (four windows closed, ports free); Cowrie restored to its exact prior state.
- Backend Jest 1,176 passed / 13 skipped (74 suites, 4 skipped); ESLint clean. AI pytest 653 passed. Registry and
  golden set OK. Frontend unit 70/70; lint clean; build OK. Secret scan 0 findings (scanner tests 9/9).
- Playwright full run (Chromium, Firefox, WebKit + device projects): **240 passed, 0 failed, 0 skipped** (12.7 min).
- Models, registry (`5f76c136`), runtime Q-table (`08209e99`) and seed Q-table (`bf9b46a1`) unchanged.

---

# Batch 15 — final demonstration, presentation and handover (2026-11-03, from `f806459`; nothing committed)

| Item | Status | What |
|---|---|---|
| CONT-001 unblock left repeat detections BLOCKED | **FIXED** | `backend/services/containmentService.js`; `backend/tests/unblockRepeatDetections.test.js` (2, real MongoDB); `tests/containmentPolicy.test.js` stub + TEST 14 mock |
| OPS-004 backup dropped index options | **FIXED** | `scratch/backup_sentinel_db.mjs`, `scratch/restore_sentinel_db.mjs` |
| DOC-002 runbook/replay inaccuracies; engine recovery | **FIXED** | `docs/DEMO_ABC_RUNBOOK.md`, `ai-engine/demo/replay_cicids.py`, `scripts/demo/restart-engine.ps1` |
| Presenter script, metrics, presentation, viva bank, deployment/backup plan | **ADDED** | `docs/DEMO_REHEARSAL_SCRIPT.md`, `docs/PROJECT_METRICS.md`, `docs/PRESENTATION_CONTENT.md`, `docs/VIVA_GUIDE.md` (Part 2, 61 questions), `docs/DEPLOYMENT_AND_BACKUP_PLAN.md`, `docs/FINAL_PROJECT_GUIDE.md` §1, §15–16 |
| Screenshots from the rehearsal | **ADDED** | `docs/presentation/screenshots/` (10) |

## Rehearsal (isolated database `sentinel-rehearsal`, real scripts, Cowrie and engine)
- A: real SSH from Windows → session with T1082/T1033/T1003/T1003.008/T1595 → decision ubuntu_22 → centos_7 APPLIED →
  next session on `centos-web-gateway`, credited to centos_7.
- B: replay 10/10 correct; 5 CRITICAL threats + 5 alerts; explanation reproduced, 53 contributions, additivity holds;
  viewer 403.
- C: auto-block → 2 mock containments ACTIVE; loopback refused 403; Cowrie dropped SSH from a deny-listed host and
  accepted it after rollback; engine outage → DEGRADED, alert, `/health` 503 → `restart-engine.ps1` 11 s.
- Restored: `sentinel-demo` unchanged (240 threats, 8 users), demo Q-table and parser state restored (parser advanced
  past the 3 rehearsal sessions so they are never ingested into `sentinel-demo`), `cowrie.cfg` hash `91349e56…`,
  Cowrie stopped, rehearsal database dropped, models and Q-tables unchanged.

## Verification
- Backend Jest 1,178 passed / 13 skipped (75 suites, 4 skipped); ESLint clean. AI pytest 653 passed. Registry OK.
- Frontend unit 70/70; lint clean; build OK. Secret scan 0 findings (scanner tests 9/9). Hashes unchanged.
- Playwright full run (backend changed): **235 passed, 5 failed** in 21.7 min with 0.6–0.7 GB of 7.7 GB free. The 5:
  WebKit landing + smoke (2) "Failed to load resource: Could not resolve hostname" for the external Google Fonts
  stylesheet — DNS failing on this machine at that time (same session saw intermittent getaddrinfo failures); Firefox
  auth (3) page.goto /login timeouts at 20 s (TEST-008). Re-runs of exactly those specs: WebKit landing + smoke 6/6
  (DNS resolving again); Firefox auth 10/11 then 22/22 over 2 repeats. No failure touched containment or unblock.
