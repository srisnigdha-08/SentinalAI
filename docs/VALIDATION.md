# Validation and deployment status

Updated 2026-10-14 (Asia/Calcutta). Work began 2026-10-13.
**Docker is postponed by the owner. All prepared deployment configuration has
been removed. Native application development and testing continue; full
integration acceptance is still pending. No Docker operations are authorized.**

## Protection and backup

The repository had no .git directory. Before edits, the entire project was copied
to C:\Users\srisn\Desktop\Projects\sentinelai-backup-20261013-8962d597:
38,360 files, 2,093,870,770 bytes. Every source/copy pair passed SHA-256 comparison.
The separate backup was not overwritten.

After changes, 46 model, dataset, original environment, log and Cowrie configuration
files still matched that backup. See PRESERVED_ASSETS_SHA256.json. No protected
Docker disk, original backup, recovered MongoDB candidate or BuildKit cache.db
was opened, moved, repaired or modified by this task. No Docker/WSL reset,
unregistration, prune, volume deletion or MongoDB recovery start was performed.
The owner's recovery SHA-256 was recorded without accessing that file.

## Native results

| Check | Actual result |
| --- | --- |
| Python runtime | 3.11.9 |
| Node runtime | 24.14.0 |
| Python dependency consistency | pip check passed |
| Installed npm dependencies | Both package trees resolved without missing dependencies |
| Python unit/API/model tests | 104 passed, 2 warnings |
| Python syntax | 26 AI/honeypot source and test files parsed successfully |
| Actual RF / Isolation Forest | Loaded; both expect 53 features |
| SHAP | Real RF explanation produced 5 finite feature contributions |
| Scoring policy | Formula and ALLOW/MONITOR/BLOCK tests passed; thresholds unchanged |
| Backend | 203 tests passed across 17 suites |
| Backend lint | Passed: 0 errors, 17 unused-variable warnings |
| Frontend build | Vite production build passed (946 modules) |
| Browser smoke | Login error, corrupted local auth recovery, dashboard unavailable state, threat-log error state passed; no page exceptions |
| Native AI HTTP | Started temporary Uvicorn service, passed readiness/auth/evaluation checks, then stopped it |

Real dataset HTTP samples (evaluation only; no production alerts or database writes):

| Dataset label | Predicted class | ThreatScore | Decision |
| --- | --- | --- | --- |
| BENIGN | BENIGN | 0.0664 | ALLOW |
| DDoS | DDoS | 0.7000 | MONITOR |

These two samples are a smoke test, not an accuracy benchmark. No BLOCK decision
was forced for presentation purposes. BLOCK behavior is covered by unit tests.
Evaluation left model statistics unchanged. Model version: rf_cicids_v2.0.

Initial test attempts exposed sandbox limitations: Jest could not resolve its
temporary cache directory (EPERM), and sandboxed Python tests stalled. The suites
passed when run with approved execution outside the sandbox. No database or
Docker access was added to those tests. Lint also exposed existing formatting
errors; the project formatter corrected them without changing their logic.
The two Python warnings are dependency deprecations, not failed tests.

## Application corrections

- Missing or broken models now fail explicitly rather than returning random or
  invented benign predictions. Readiness requires loaded models.
- Non-finite feature inputs are rejected; model dimension/order metadata is checked.
- SHAP, RF/IF artifacts, model priorities, feature order and scoring thresholds remain.
- Separate authenticated internal inference routes let backend-owned persistence
  avoid duplicate callbacks; production /predict cannot suppress notifications.
  Internal vectors are persisted but omitted from public backend results.
- Q-learning writes use a separate runtime location initialized from the shipped
  q_table.json; ordinary prediction/startup/shutdown does not overwrite that artifact.
- Live simulation HTTP routes and websocket demo startup were removed.
- MongoDB connection is required before the backend starts listening; readiness
  reports unavailable dependencies. Native binding defaults to loopback and
  proxy trust is explicit.
- Password-change checks are enforced for access, refresh and socket authentication.
  Runtime logs redact credentials/secrets; 500 responses omit internal details.
- Overlapping Socket.IO rooms receive each threat/alert once.
- Frontend widgets share one connection owner; corrupt stored auth is recovered.
  Dashboard and threat-log requests expose errors/retry, and AI offline status is
  truthful. Unimplemented exports no longer announce fake success.
- Old deployment files and Docker-specific tests were removed. Requirements and
  removal reasons are recorded in ARCHITECTURE.md. Native startup instructions are provided. Source models, datasets and original credentials remain.
- CI uses Node 24, installs the Socket.IO test dependency, and includes frontend build.

## Native follow-up results (2026-10-14)

- Honeypot session filters now use the model's active/closed/analysed statuses.
- A threat created by AI prediction persistence is linked back to its honeypot
  session. Session closure does not repeat containment or alerts already handled
  by prediction storage.
- Reclassification preserves an existing BLOCKED status and does not reissue
  containment for that threat. Score thresholds and model semantics are unchanged.
- Missing inference timing remains null; a measured zero remains zero.
- Six regression cases were added. All 203 backend tests across 17 suites passed.
  Lint completed with no errors and 17 existing unused-variable warnings.
- UI copy no longer advertises Docker deployment or host-wide enforcement;
  honeypot blocking explicitly requires a connected Cowrie blocker plugin.
  The frontend production build passed again (946 modules).
- All 46 entries in PRESERVED_ASSETS_SHA256.json were rehashed and matched.
  No protected Docker/recovery paths were accessed during this follow-up.

These changes were tested with mocked database/AI dependencies. Concurrent or
repeated session-closure delivery and real Cowrie enforcement still need
integration acceptance; this change does not claim exactly-once processing.

## Unavailable integrations and remaining limits

The initial unit/smoke validation lacked MongoDB. The approved native acceptance
phase has now installed a verified portable MongoDB 7.0.45 into a new dedicated
location and tested real authentication, persistence/read-back, login/refresh,
Socket.IO delivery and browser rendering. See NATIVE_INTEGRATION.md for the
12 grouped passing checks and exact evidence. The database and test data are
retained; all acceptance-owned processes are stopped. Real Cowrie telemetry
remains unverified. Broad backend unit tests still use mocked database calls;
the new acceptance run uses the actual authenticated database.

ABUSEIPDB_API_KEY was absent from inspected environment files. External enrichment
and actual Cowrie/sniffer telemetry were not tested. Cowrie remains optional and
independently managed; no privileged packet-capture container was introduced.
Honeypot classifier features still use the existing session-profile approximation.
A complete dataset accuracy/coverage audit was not performed. Small-viewport
dashboard grids remain an existing UI limitation. Offline utilities for synthetic
training/demo remain in source, are not startup paths, and were not executed.

## Docker postponed (owner decision, 2026-10-14)

The previously prepared fresh deployment was never built or started. The owner
has no independently verified safe Docker host and has now postponed Docker
entirely. Its earlier offline validation is historical and is not deployment
acceptance. No Docker operations were performed during this follow-up.

Removed the newly generated root .dockerignore; deployment/fresh/ (three
Dockerfiles, Compose YAML, Nginx configuration, Mongo initialization script,
placeholder .env.example, credential generator and README); and
scripts/validate_deployment.py. These were deployment-only files, had no generated
credentials or application data, and are no longer part of the active project.
Original deployment environment files remain preserved. Future Docker resources
must be created anew only after native development and acceptance are complete
and the owner authorizes the next deployment phase.

## Reproduce

See NATIVE_DEVELOPMENT.md for native commands. Local evidence:
.test-runtime/native-ai-result.json, .test-runtime/native-ai.log and
.test-runtime/dashboard-unavailable.png. Test helpers:
scripts/native_ai_smoke.py and scripts/frontend-smoke.cjs.
No claim of complete application or deployment acceptance is made.

## Native integration acceptance, 2026-10-14

See [NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md). Real dataset rows naturally
produced ALLOW 0.0664, MONITOR 0.7000 and BLOCK 0.9242 with unchanged thresholds.
The dashboard hourly chart and refresh-token cleanup defects were fixed and
verified. Five new offline Cowrie parser tests passed; frontend rebuilt and
updated browser regression passed. All 46 protected assets still match.
Docker/WSL and recovery resources were not accessed. Cowrie live acceptance,
external enrichment and server token revocation remain pending/unsupported.

## Authentication/timezone review, 2026-10-14

[AUTHENTICATION_REVIEW.md](AUTHENTICATION_REVIEW.md) records concrete findings,
the proposed session/rotation/revocation implementation and its regression matrix.
[TIMEZONE_POLICY_PROPOSAL.md](TIMEZONE_POLICY_PROPOSAL.md) proposes UTC storage
and explicit Asia/Kolkata reporting with reviewed calendar windows.

Targeted execution: tests/auth.test.js and tests/nativeSafety.test.js passed
14 tests across 2 suites (15.629 seconds). The isolated
scripts/review_auth_timezone.cjs reproduced three current authentication defects
and host-dependent reporting boundaries; four negative controls passed. Three
additional risks were documented from source review, without exploit claims.
Evidence: .test-runtime/security-review-20261014.json. The initial probe attempt
failed because replacing Date before loading Mongoose broke schema construction;
loading the schemas first corrected the probe, which then completed successfully.

Only documentation and the offline review script changed. No runtime auth,
timezone, model, credential or environment behavior changed. No database/server
was started and no retained acceptance data or recovery resource was accessed.
Runtime changes and their regression tests remain proposed for the implementation
phase; current characterization is not successful revocation/rotation acceptance.
