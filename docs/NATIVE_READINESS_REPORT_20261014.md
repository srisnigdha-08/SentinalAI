# SentinelAI native hardening and readiness report — 14 October 2026

## A. Executive assessment

**Conditionally ready for further controlled native testing; not production-ready.**
Authentication, shared revocation, controlled HTTPS transport, genuine RF/IF
inference, persistence, browser authentication and IST reporting passed the checks
described below. Live Cowrie telemetry, real enforcement and production deployment
were not accepted. Remaining enrollment, telemetry, migration and delivery risks
must be addressed before a production claim.

Project: `C:\Users\srisn\Desktop\Projects\sentinelai-complete`.
There is no Git repository. Evidence uses source backups and hash manifests;
no Git commits or diffs are claimed. Docker and WSL remain postponed.

## B. Five-priority completion matrix

| Priority | Task | Status | Evidence | Remaining risk |
| --- | --- | --- | --- | --- |
| 1 | Configured repository lint | PASS | lint-verified-final.json: zero errors, 16 existing warnings | Warnings remain; no rules suppressed |
| 2 | Multi-process socket revocation | PASS | Native two-worker results, actual replica-set change streams and outage/recovery | Verified topology is one host/single-node replica set; business-event fan-out is separate |
| 3 | Production HTTPS/cookie controls | PARTIAL | Actual local TLS proxy, NODE_ENV=production, real Chrome/cookies, Origin/CSRF/CORS/spoof checks | Public PKI, real production proxy/network isolation and deployment not tested |
| 4 | Live Cowrie acceptance | BLOCKED | No managed Linux host or cowrie.json access supplied | Offline tests do not establish live telemetry or enforcement |
| 5 | Native end-to-end acceptance | PASS | 29 unique native scenarios; genuine models, database, browser and distinct API processes | Scope is controlled test data; broader accuracy/load/failover and live integrations remain unverified |

Evidence root: `.test-runtime/master-native-20261014-80f776da`.
Per-service/native evidence: `.test-runtime/native-readiness-20261014-01/evidence`.
The exact per-scenario results and paths are in `native-evidence-index-final.json`;
reruns are not added to the unique count.
The companion [scenario table](NATIVE_ACCEPTANCE_SCENARIOS_20261014_80f776da.md)
records each expected result, actual result, status, evidence category and path.

## C. Five-stage execution

1. **Audit/baseline:** read-only review and fresh checks preceded runtime edits.
   Backend 251 passed/12 skipped; frontend 16 passed; Python 109 passed; approved
   host frontend build succeeded with 950 modules. Lint reproduced 141 CRLF errors
   in the unchanged legacy helper. All 46 protected assets matched. Findings are
   in NATIVE_BASELINE_AUDIT_20261014_80f776da.md and its supplement.
2. **Fix/harden:** a separately verified source backup preceded changes. Added
   explicit topology/proxy controls, shared revocation availability, stronger
   log redaction, sanitized AI validation/readiness contracts and Cowrie dispatch,
   acknowledgement, closure and viewer-response protections. Each behavior has
   regression evidence; genuine Cowrie persistence is explicitly not claimed.
3. **Regression/native acceptance:** final backend 323 passed/12 skipped; Python
   125 passed; frontend's unchanged source has 16 fresh passing baseline tests and
   successful production builds. Native scenarios total 29 unique passing cases.
   Separate real-model SHAP checks passed on two archived flows.
4. **Live Cowrie:** blocked by the missing managed Linux host/log access. No
   privileged capture, firewall/IP blocking or public exposure was performed.
5. **Readiness assessment:** conditional native readiness only. Failed attempts,
   their corrections and the limits of each evidence category are retained.

## D. Commands and test evidence

Commands ran from the project root unless the working directory is stated.
Jest used an owned backend/.test-runtime TEMP/TMP and a new LOG_DIR; historical
AUTH_TEST_MONGO_URI was unset. Python used PYTHONDONTWRITEBYTECODE=1 and disabled
pytest's cache provider. These were temporary process settings; no .env was edited.

| Check/actual command | Outcome | Evidence under master evidence root |
| --- | --- | --- |
| backend: npm.cmd test -- --runInBand --json --outputFile ../.test-runtime/master-native-20261014-80f776da/backend-release.json | Exit 0; 323 passed, 12 skipped; 27 passed/3 skipped suites | backend-release.json/.log/.exit.txt |
| backend: npm.cmd run lint -- --format json --output-file ../.test-runtime/master-native-20261014-80f776da/lint-verified-final.json | Exit 0; 0 errors, 16 warnings | lint-verified-final.json/.exit.txt |
| ai-engine/.venv/Scripts/python.exe -m pytest -p no:cacheprovider ai-engine/tests --junitxml=.test-runtime/master-native-20261014-80f776da/python-final.xml | Exit 0; 125 passed; 2 warnings; 44.50s | python-final.xml/.log/.exit.txt |
| frontend: npm.cmd test -- --run; frontend production Vite builds to unique evidence directories | 16 tests passed; production builds succeeded, including 950-module builds | frontend-baseline.log/.exit.txt; native run frontend-build.log |
| backend targeted security suite: authHardening, securityTopology, revocationDelivery, logPrivacy | Exit 0; 80 passed; included in final total, not added again | security-stage2-final-host.json |
| backend targeted Cowrie lifecycle/collector/ingestion suite | Exit 0; 32 passed; included in final total | cowrie-final-offline.json/.log |
| backend targeted AI contract suite | Exit 0; 5 passed; included in final total | ai-dependency-final.json/.log |
| backend targeted Swagger/OpenAPI suite | Exit 0; 4 passed; included in final total | swagger-final.json/.log |
| Python targeted Cowrie output fixture isolation rerun | Exit 0; 4 passed; included in Python total | cowrie-output-final.xml/.log |
| ai-engine/.venv/Scripts/python.exe scripts/real_shap_readiness.py | Exit 0; genuine finite top-five explanations for two real flows; class/score/action unchanged | real-shap-smoke.json/.log/.exit.txt |
| node scripts/run_native_readiness.cjs --create; scoped --resume runs described below | Initial failures retained; successful consolidated result 29 unique native scenarios | native-evidence-index-final.json; per-run results.json |
| node scripts/scan_native_readiness_evidence.cjs | No generated credential/JWT/private-key leak in scanned owned logs/evidence | privacy-scan-*.json |
| ai-engine/.venv/Scripts/python.exe scripts/verify_master_readiness.py | Asset/source-backup verification and corrected changed-file SHA inventory | final-state-reviewed.json |

The 12 intentionally skipped historical cases are authPersistence.test.js (10),
authBrowser.test.js (1), timezonePersistence.test.js (1). Their runners are fixed
to the earlier regression environment; they were not pointed at retained data.
Fresh native tests use the approved readiness database instead. Unit counts,
native scenarios, individual HTTP assertions and smoke flows are different units;
they are not combined into an inflated grand total.

Python warnings concern pandas mixed CSV dtypes and deprecated Pydantic class
configuration. Backend logs include existing driver/index warnings. They did not
cause failures and are not presented as resolved.

### Approved runtime and successful runs

MongoDB 7.0.45, Node.js 24.14.0/npm 11.9.0, Python 3.11.9/pytest 9.1.1 and
Chrome 155.0.8059.40 were used. Existing installed dependencies were used; no
new software installation was performed in this phase.

The user approved NATIVE_ACCEPTANCE_SETUP_20261014_80f776da.md. Storage is only
`.test-runtime/native-readiness-20261014-01`; database is
`sentinelai_native_readiness_20261014`, replica set `sentinel_native_test`.
MongoDB/AI/API-A/API-B/HTTPS/HTTP listeners use 127.0.0.1 ports
27030/18000/15001/15002/13443/13080. Application MongoDB access is readWrite only
on that new database; anonymous and out-of-scope reads were rejected.

New durable credentials/TLS private material are DPAPI CurrentUser protected.
The temporary replica keyfile had user-restricted ACLs and was removed after owned
MongoDB shutdown. Public CA/leaf certificates remain; Windows trust was unchanged.
The proxy's outbound source is 127.0.0.2; API proxy trust is exactly 127.0.0.2/32.
That is a loopback socket binding, not an OS network reconfiguration.

| Run | Purpose/result |
| --- | --- |
| run-1791983891431 | Full native run: 23 pass/2 browser-driver failures. Genuine model persistence, all three decisions, callback/events, IST grouping, AI and database outage/recovery passed. Distinct worker PIDs 40752 and 3544 are in topology.json. |
| run-1791985171920 | Corrected browser run: 5 pass/0 fail, including repeated MongoDB setup check. Actual cross-tab logout/refresh, short access expiry/socket renewal and unconfirmed logout recovery passed. |
| run-1791986129697 | AI contract/counter run: 4 pass/0 fail. Incorrect internal-key readiness and recovery tested through owned worker B restart; no model/threat records added. |
| run-1791987110425 | Instrumented browser run: 5 pass/1 empty-widget assumption failure. Chrome PID/pipe ownership and actual IST timestamp rendering verified. |
| run-1791994025694 | Dedicated honeypot empty-state follow-up: 3 pass/0 fail. Real zero-session backend response, AI Unavailable rendering and owned Chrome pipe transport verified; Chrome PID 27460 exited 0. |

Scoped rerun commands were `--resume --focus-browser`, `--resume --focus-contract`
and `--resume --focus-empty`. Each created unique evidence and only the labeled
authentication fixtures needed by that run; existing real-model records were reused.
Those flags do not broaden storage/database/port permissions. Their code verifies
ownership and rejects redirected paths/port conflicts before startup.

### Failures preserved rather than counted as success

- Sandbox EPERM/temp-path and initial build limitations were retained; approved
  host runs succeeded. A stalled baseline Python run was stopped only after its
  two owned PIDs were identified; its incomplete output was not counted as passing.
- Initial native require failure used the wrong Socket.IO dependency directory;
  corrected to the already installed frontend dependency before environment creation.
- Initial model startup exceeded the 60-second allowance. Classifier-load output
  was retained, and all owned ports closed. Resumption allowed 180 seconds and used
  the actual Python interpreter/venv libraries to avoid a Windows redirector child.
- One resumed attempt connected before MongoDB was ready; startup waiting was fixed.
  One Windows spawn UNKNOWN and one Chrome DevTools startup timeout remain recorded.
- The first browser runner used the wrong button text, then asserted logout-all
  before server confirmation. Tests now wait for confirmed revocation; application
  authentication/cookie rules were not weakened. Low-level interception and shared
  scenario state were replaced with isolated short-expiry browser fixtures.
- The first wrong-key test accepted a proxy 503 before the new API worker listened.
  Its guard now requires the actual API health body and a connected database.
- The added empty-state test expected an optional/configured-node widget to be
  absent. It now tests the dedicated honeypot sessions view against its real empty
  response; no application data or UI was fabricated to obtain a pass.
- Intermediate newly introduced one-var/formatting lint errors were corrected
  locally. Every intermediate failure file remains available; final lint is separate.

## E. Security findings and remaining risk

| Finding | State/evidence | Severity and remaining work |
| --- | --- | --- |
| NATIVE-01 CRLF lint | Corrected only line endings; normalized bytes match source backup; lint passes | Low; 16 existing warnings remain |
| NATIVE-02 local-only auth revocation | Shared stream, fail-closed guard and distinct-worker tests pass | Auth scope verified; High operational risk if balanced workers are assumed to share business events without an adapter |
| NATIVE-03 broad proxy/plain API trust | Explicit IP/CIDR trust and production transport checks pass actual TLS/spoof tests | Medium; real deployment proxy/network/public certificate still needs acceptance |
| NATIVE-04 free-text log leakage | Regression-tested JWT/query/userinfo/object masking; owned evidence scan passes | Coverage is for tested shapes/generated credentials, not a blanket audit of old logs |
| NATIVE-05 sensitive parser logs | Payloads omitted; exception type only; offline privacy tests pass | Real telemetry privacy still needs managed-host acceptance |
| NATIVE-06 Cowrie dispatch/fake acknowledgements | Normalized write/config contract, supported close login payload, 400/404/503 handling and collector regressions pass | Medium; actual host/version/config, retry behavior and throughput not tested |
| NATIVE-07 repeated closure effects | Claim/identity/completion fields, deduplicated ordinary close/credentials, preserved containment; mocked concurrency/reclassification tests pass | PARTIAL: real Cowrie persistence/multi-worker lifecycle not tested. Failed/stuck claims require reviewed recovery; no exactly-once external-enforcement claim |
| NATIVE-08 pre-inference session-open threat | Existing collector still creates HIGH/0.75 SSH Brute Force before a genuine model result | High; must label/review this heuristic before live use. It was not silently changed into different model/security semantics |
| NATIVE-09 live host | Not available | BLOCKED: managed Linux Cowrie/log access and authorization required |
| NATIVE-10 nonfinite validation 500 | Sanitized 422 unit and actual AI HTTP/backend checks pass | Optional feature defaults preserved; no threshold change |
| NATIVE-11 inaccurate Q flush log | Lazy/uninitialized shutdown regression passes; actual assets preserved | No learning endpoints called; no learning write claimed |
| NATIVE-12 invalid input reported as outage | Sanitized 422 propagation, actual no-prediction-write check pass | Intentional documented response correction |
| NATIVE-13 unauthenticated readiness | Public readiness plus authenticated model-info check; bad-key/recovery tests pass | Internal key must be correctly deployed; source does not conceal auth failures |
| NATIVE-14 narrow model validation | 32 selected archived flows; row 18884 DDoS label produces ALLOW at 0.6999 | Medium; independent representative evaluation required. This sample does not justify silent threshold tuning or fresh accuracy claims |
| NATIVE-15 viewer captured-login disclosure | Five mocked controller tests verify username/password omission, preserved success/counts/storage and analyst/admin access | High remaining enrollment policy: existing public registration may create analyst accounts. Trusted operator enrollment must precede live forensic-data use |
| NATIVE-16 static enforcement label | RoleWorkspaceHeader.jsx always labels an analyst CONTAINMENT ARMED; actual screenshots show it with zero blocked IPs and no enforcement performed | Medium; replace this role decoration with permissions wording or verified operational state before live use. It is not enforcement evidence |

Other concrete limits: the optional Cowrie output sends synchronous HTTP; source
delivery has no durable outbox and command/download deduplication is not established.
Use one ingestion path per event stream. External reputation credentials were
unavailable/disabled during controlled tests; no live reputation integration claim
is made. Single-node replica-set tests do not establish HA or production load capacity.
The 800-pixel browser screenshots also show dashboard content extending beyond the
right edge. Responsive layout needs a wider viewport/mobile review; successful
data/authentication checks do not establish complete responsive visual acceptance.

## F. Lint and code quality

The pre-existing legacy helper was byte-identical before changes. Only 141 CRLF
pairs became LF; proof is lint-fix-byte-proof.json. The helper was syntax/format
checked but never executed against its old hard-coded listeners. Lint configuration
and unrelated files were not broadly reformatted. Final configured backend lint:
**zero errors, 16 pre-existing warnings**, exit 0. Root native/honeypot JavaScript
helpers were syntax-checked; Python tests/syntax checks are separate from ESLint.

## G. Authentication guarantees and cutover

Backend production now requires explicit AUTH_REVOCATION_MODE. Multiple declared
workers require mongo-stream and a replica set/sharded MongoDB; startup completes
a real cursor round trip before listening, and cannot silently fall back to single
mode. Each HTTP/session operation checks shared-delivery availability before and
after persistence. Disconnect/cursor error/stale reads deny required authorization
and disconnect local sockets; recovery uses fresh session/user state.

Measured full-run request-to-disconnection times include logout 50ms, logout-all
75ms, password change 1608ms, direct fixture disable 28ms, role change 19ms, deletion
36ms. Password duration includes bcrypt/HTTP work; these are observations, not
production SLAs. Stream outage detection uses a two-second stale guard; the old
15-second periodic socket recheck remains a defense in depth. Revocation cannot
roll back an already authorized in-flight handler or retract a delivered event.

Replay, logout, all-session logout, active-user/version checks, claims/purpose/
issuer/audience/algorithm, expiry and races have unit plus scoped native evidence.
Same-second version behavior is verified by unit regressions; native tests verified
the version increment and old-session rejection. Bcrypt behavior, role checks and
15-minute access/30-day absolute refresh-session lifetimes remain unchanged.

Browser access tokens remain in memory. Real browser tests verified legacy storage
cleanup, HttpOnly/Secure/Strict auth cookies, reload bootstrap, Web Locks across tabs,
confirmed logout-all and pending/unconfirmed logout recovery. The expiry test signs
a one-second response fixture for the actual new server session, retains genuine
cookies/refresh, and observed one successful refresh and two socket connections.
It does not change backend 900-second issuance or the absolute refresh expiry.

Release backend/frontend together. Legacy JWTs require new sign-in. Production
must explicitly declare the worker topology and trusted proxy. Cowrie closure
metadata was not backfilled: legacy closed records need a reviewed migration policy;
processing/failed attempts require inspection before any scoped retry/reclassification.
The retained acceptance database must not be used for this work.

## H. HTTPS and deployment limits

Actual encrypted localhost transport and NODE_ENV=production controls passed with
a dedicated test CA/leaf, verified Node/Python hostname trust, and a leaf-specific
Chrome SPKI pin. No global TLS bypass or Windows trust-store changes were used.
Final Chrome uses owned DevTools pipes; no extra DevTools TCP listener is needed.
Cookie path is /api/auth, SameSite Strict, Secure and HttpOnly. Real invalid Origin,
CSRF, duplicate cookie, CORS and forwarded-protocol cases were rejected.

This is controlled HTTPS acceptance, not public-PKI or real deployment acceptance.
Operators must supply an actual same-origin HTTPS frontend/API endpoint, explicit
CLIENT_URL, narrow TRUST_PROXY, independently managed authenticated MongoDB and
appropriate AUTH_REVOCATION_MODE/worker count. Business event distribution and
required sticky routing/adapter policy must be reviewed before balancing workers.
No Docker configuration or deployment was created or started.

## I. AI, reporting and Cowrie evidence

Loaded RF version rf_cicids_v2.0 and IF version v1.4_cicids with 53 features.
Published model-info thresholds remained block 0.92, monitor 0.7, anomaly -0.55.
The 32 archived requests naturally produced 17 ALLOW, 10 MONITOR and 5 BLOCK.
Examples: BENIGN row 0 score 0.0664; DDoS row 18883 score 0.7; DDoS row 18890
score 0.9242. No output or decision was forced. Stored classes/scores/vectors and
application read-back were checked. SHAP returned five finite genuine feature
contributions for each of two flows without changing class/score/action.

The primary snapshot contains 33 predictions (32 backend-owned plus one genuine
AI HTTPS callback), 16 threats and 8 alerts. Blocked IPs and honeypot sessions are
zero. Later focused runs reused those model records and added only labeled auth
fixtures. A BLOCK classification did **not** perform containment; auto-block stayed
disabled. Archived flows and documentation IP identifiers are test data, not live
production/Cowrie feeds. Historical model accuracy metadata is not a fresh benchmark.

Stored dates remain UTC instants. IST Today uses [2026-10-13T18:30Z,
2026-10-14T18:30Z); its seven-day view starts 2026-10-07T18:30Z. Real counts agree:
16 threats today in IST hour 18, 33 seven-day predictions, zero honeypot sessions
and WebSocket totalToday 16. Native grouping covers IST midnight/half-hour,
month/year/leap-day bounds and excludes the next day. Full-day reporting includes
future instants within that same calendar day; events at/after its end are excluded.
Actual UTC-browser rendering matched the stored UTC instant formatted in IST.

Cowrie evidence is strictly offline: stubbed normalized event dispatch, mocked
HTTP/models, privacy/acknowledgement and lifecycle tests. The upstream
[Cowrie output interface](https://raw.githubusercontent.com/cowrie/cowrie/main/src/cowrie/core/output.py)
defines dictionary delivery through write(); actual managed-host version compatibility
still needs confirmation. No genuine Cowrie event, recovered database, packet
capture, firewall action or independently verified enforcement was tested.

## J. Integrity, storage and changed files

All 46 protected application assets were verified at baseline and after initial
hardening; final-state-reviewed.json records the final verification and source inventory.
It also independently rechecks the new source backup: 201 files/1,547,193 bytes at
`.test-runtime/master-source-backup-20261014-80f776da`. Older complete project
backups/evidence were preserved and not overwritten. This source snapshot excludes
installed dependencies, runtime data, serialized models/datasets and existing .env;
the separate protected-asset manifest covers the listed models/data/configuration.

Runtime changes are grouped in NATIVE_HARDENING_CHANGES_20261014_80f776da.md:
backend server/topology/auth availability/shared revocation; redactor; AI service
contracts; honeypot schema/service/controller/ingestion; Python validation/deception
logging; Cowrie parser/output/collector. Added regression tests and native runner,
TLS/proxy, privacy, integrity and genuine SHAP helpers are listed with exact SHA-256
in final-state-reviewed.json. Frontend runtime source was preserved and exercised against the
actual backend. API documentation records intentional 422/409/reclassification changes.

The original final-state.json is retained. Its initial inventory incorrectly marked
two pre-existing model metadata files and paper_text.txt as additions because the
smaller source snapshot excluded them. The reviewed inventory compares their hashes
with the prior application backup manifest and records them as unchanged excluded
files, without altering those assets. Its change inventory covers changes since the
selected pre-runtime-edit source snapshot; the baseline audit and approved setup
documents were created earlier in this same task and are already in that snapshot.

No Docker/WSL operations, protected disk/backup/overlay modifications, recovered
MongoDB access, cache.db access, old acceptance database connection, existing .env
edit, model/dataset retraining or learning-state update was performed. Recovery
disk hashes were not re-read. Only new approved data/log/profile/evidence directories
were used. Every completed native run records shutdown, all six approved service
ports closed and its temporary keyfile removed; owned Chrome closed successfully.

## K. Exact next actions

1. Review trusted analyst/admin enrollment and captured-forensic-data permissions
   before connecting genuine telemetry. Public analyst registration was preserved;
   changing that contract requires an explicit product/security decision.
2. Review the existing fixed HIGH/0.75 session-open heuristic separately from genuine
   model results. Do not silently retune model thresholds to conceal that behavior
   or the 0.6999 borderline archived sample; run a representative independent evaluation.
3. Provide an authorized managed Cowrie Linux host, actual version and secure
   cowrie.json access. Accept genuine connect/login/command/close events, persistence,
   response privacy, update notifications and repeat-event behavior. No live host is
   currently available. Real containment requires separate explicit authorization.
4. Accept Cowrie lifecycle claims against a reviewed separate persistent fixture or
   the managed host; define crash recovery/migration, durable retry and duplicate
   command/download handling before enabling that ingestion path in production.
5. Review shared business-event distribution/sticky routing for multiple workers;
   the auth change stream is not a Socket.IO business-event adapter. Validate real
   production proxy/PKI/network isolation, HA/failover and workload requirements.
6. Correct the static CONTAINMENT ARMED role label before live operation and review
   dashboard layout at narrow/wide viewports. No verified enforcement is implied by
   that label or by the model's BLOCK decision.
7. Keep Docker/WSL/recovery resources and the retained acceptance database untouched.
   Retain the new test data/evidence/encrypted secrets; do not run broad cleanup or
   reconnect historical acceptance scripts. No further locally available acceptance
   prerequisite is assumed to replace the missing managed integrations.
