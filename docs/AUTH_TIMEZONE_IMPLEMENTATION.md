# Authentication and reporting implementation — 2026-10-14

The approved session-backed authentication and UTC-storage/Asia-Kolkata reporting
designs are implemented in the existing application. Backend and frontend must
be released together; all users must sign in again. Docker remains postponed.
No production-readiness or live Cowrie enforcement claim is made.

## Protection and scope

Confirmed project: `C:\Users\srisn\Desktop\Projects\sentinelai-complete`.
This checkout has no Git repository, so there is no Git diff or commit to report.
Existing source changes were preserved by a separate pre-change backup:
`C:\Users\srisn\Desktop\Projects\sentinelai-before-auth-20261014-94439a22`.
Its verification manifest records 39,263 files and 2,117,594,394 bytes, with every
copied file SHA-256 verified. The prohibited browser file named cache.db was
excluded without opening it. The earlier backup was not overwritten.

All 46 preserved application assets matched `PRESERVED_ASSETS_SHA256.json`
before changes and at final verification. Existing .env files, credentials,
model artifacts, datasets and learning state are unchanged. No Docker/WSL
operations, protected disk access, filesystem repairs, recovered MongoDB access,
or retained acceptance database connections were performed. The owner-provided
recovery working-copy hash was not independently re-read.

## Authentication changes

- Added AuthSession documents with random UUID session identity, user/version,
  generation, SHA-256 refresh-token hash, absolute expiry and revocation metadata.
  Tokens have independent cryptographic random identifiers. MongoDB's single
  document compare-and-swap consumes one refresh generation atomically; an older
  signed generation revokes its family. Unrelated families remain valid.
- Explicit HS256, issuer `sentinelai`, audience `sentinelai-browser`, purpose,
  expiry, lifetime and required-claim validation apply to access and refresh.
  Access lasts at most 900 seconds; session expiry is fixed at initial issuance
  plus 2,592,000 seconds. Rotation preserves that expiry; access near its end is
  capped by the same boundary. Session expiry is checked directly, independently
  of MongoDB TTL cleanup.
- HTTP and Socket.IO share the same active-session/user/version authorizer.
  Logout revokes the current family; logout-all increments user authVersion and
  revokes every family. Password updates atomically compare the old password and
  version, save bcrypt cost 12 and increment authVersion. Administrative role,
  status and deletion operations revoke sessions and disconnect sockets.
  Reactivation cannot restore older versions. Existing role authorization and
  inactive-account checks remain in effect.
- Socket authorization joins server-selected revocation rooms, awaits joins and
  rechecks the session before accepting incoming packets. It disconnects at token
  expiry, on in-process revocation and on failed periodic/per-packet checks.
  This closes the handshake/revocation race; packets cannot bypass initialization.
- Refresh tokens now travel only in an HttpOnly, SameSite=Strict cookie scoped to
  `/api/auth`. Secure is mandatory in production/HTTPS; insecure cookies are
  allowed only for loopback development. Production HTTP CLIENT_URL is rejected.
  Credentialed CORS accepts explicit configured origins. Auth mutations require
  trusted Origin plus a signed double-submit CSRF nonce/proof; cross-site CSRF
  bootstrap and malformed/duplicate cookie inputs cannot supply valid proof.
- Browser access tokens/user state stay in memory. Legacy localStorage tokens
  are removed and never restored. A same-tab single flight plus Web Locks
  serializes cookie/CSRF mutation across tabs. BroadcastChannel carries control
  messages only, never credentials. API requests retry after refresh at most once.
  Refresh updates context and the provider-owned socket connection.
- Logout clears local memory immediately and distinguishes server-confirmed
  success from failed/unconfirmed revocation. Nonsecret logout intent/confirmation
  markers allow later bootstrap to revoke rather than restore an uncertain
  session. The intent preserves the all-sessions scope: a queued refresh in
  another tab may complete that same logout-all operation, and its initiating tab
  recognizes the confirmation instead of attempting a downgraded current logout.
  The dashboard sidebar exposes both Logout and Logout all sessions.

## Cutover and API contract

No bulk account, threat or timestamp migration was run. Existing users without
authVersion are treated as version zero; security writes persist/increment it.
Mongoose adds the `authsessions` collection and expiry TTL index in the chosen
application database. Permissions must allow that collection/index; persistence
tests initialize and exercise them in the isolated test database.

Legacy JWTs lack mandatory session/purpose/identity claims and are rejected.
The existing .env `JWT_EXPIRES_IN` value is preserved but ignored in favor of the
approved fixed lifetime. Existing signing secrets were preserved. Coordinate
backend/frontend cutover and expect mandatory sign-in; do not run the former
localStorage client against the new backend.

Successful login/register/password/refresh responses retain success/data/user
envelopes and access `data.token`. Refresh is deliberately removed from JSON.
GET `/api/auth/csrf` supplies `data.csrfToken` and an HttpOnly nonce cookie. All
auth POST/PUT mutations require `X-CSRF-Token`, trusted Origin and that cookie.
POST `/api/auth/refresh-token` consumes only the refresh cookie. POST
`/api/auth/logout` supports a valid refresh cookie after access expiry. POST
`/api/auth/logout-all` additionally requires current access authorization; the
browser obtains it under the same coordination lock. Auth responses are no-store.
The API reference and generated OpenAPI documentation were updated and validated.

For native operation, use the documented three-service commands with a separately
approved MongoDB URI and process-environment overrides. Keep CLIENT_URL aligned
with the browser origin and use the same-origin Vite proxy. Web Locks requires a
supported browser in a secure or loopback context. No .env changes were needed.

## Reporting policy

Stored dates remain UTC instants. All reporting helpers/aggregations and browser
timestamp/clock formatting explicitly use `Asia/Kolkata`.

Today is the IST calendar day expressed as a UTC `[start, next midnight)` range.
The seven-day view includes today and its six preceding IST calendar days, not
a rolling 168-hour interval. For example, October 14, 2026 is
`[2026-10-13T18:30:00.000Z, 2026-10-14T18:30:00.000Z)`.
MongoDB `$hour` and `$dateToString` explicitly specify the named reporting zone.
Threat, attack-vector, AI and honeypot analytics return reporting timezone and
UTC range metadata; daily WebSocket counters do likewise. Queries and their
metadata share one captured time, even when a query crosses IST midnight.
All-time counters remain all-time; blocked counts still use persisted BLOCKED
status. Campaign clustering's existing rolling similarity search remains an
algorithmic rule, not a calendar reporting view. Model thresholds, classifications
and persisted timestamps were not changed.

## Regression evidence

Validated with installed Node 24.14.0, Chrome 155 and approved portable MongoDB
7.0.45. Python/model implementation was unchanged; earlier passing Python/model
checks were not repeated or represented as new results.

| Check | Actual result | Evidence |
| --- | --- | --- |
| Full backend unit suite | 248 passed; 12 database/browser cases skipped in this mocked run | `backend/.test-runtime/hardening-unit-results.json` |
| Final midnight/WebSocket regressions | 20 passed, including 3 new midnight-response tests; overlaps 17 full-suite cases | `backend/.test-runtime/hardening-reporting-results.json` |
| Corrected OpenAPI/auth checks | 39 passed in targeted rerun | `backend/.test-runtime/hardening-targeted-results.json` |
| Real MongoDB/session/socket/reporting/browser suite | 12 passed, 0 failed | `.test-runtime/auth-timezone-db-20261014-01/evidence/jest-1791973159442.json` |
| Expanded actual browser logout-all/cross-tab cutover check | 1 passed, 0 failed after fixing the cross-tab scope race | `.test-runtime/auth-timezone-db-20261014-01/evidence/jest-1791974965935.json` |
| Frontend regressions | 16 passed, 0 failed | `npm test` in frontend; tests/authClient, authInterceptors and reportingTime |
| Frontend build | Passed, 950 modules transformed | `npm run build` in frontend |
| Changed backend JavaScript lint | 30 files, 0 errors, 5 warnings | `backend/.test-runtime/hardening-changed-lint.json` |
| Repository-wide backend lint | Fails: 141 existing CRLF formatting errors in unchanged tests/verifyBlocker.js; 16 warnings | `backend/.test-runtime/hardening-lint.json`; helper hash matches pre-change backup |
| Asset preservation and complete source changes | 46/46 matching; no asset mismatches | `.test-runtime/hardening-state-verification.json` |
| Credential/bearer redaction and test shutdown | Verified separately against owned test logs/evidence only | `.test-runtime/hardening-evidence-verification.json` |

The final backend results establish 251 distinct unit cases across the full and
targeted runs. Reruns above are not additional unique cases. The 12 real cases
comprise 10 authentication/session/socket cases, one multi-assertion MongoDB
timezone fixture case, and one browser case subsequently expanded and reverified.

Coverage includes concurrent refresh CAS, sequential replay/family isolation,
logout/logout-all, same-second password/version revocation, account status and
role downgrade, wrong key/algorithm/purpose/issuer/audience and missing claims,
session-store failures, issuance/refresh/revocation races, socket expiry and
post-join revocation, HttpOnly/SameSite/Secure/Origin/CSRF/CORS, legacy storage
cleanup, cross-tab refresh, lost responses, unconfirmed logout, Web Locks/storage
unavailability and the one-retry limit. Time tests cover half-hour offset,
midnight inclusion/exclusion, leap/month/year transitions, host/browser timezone
independence, cross-service daily totals and unchanged stored timestamps.

The browser consumed actual backend responses, checked the real cookie and
storage, and verified server revocation/read-back plus copied-token rejection.
Its isolated dashboard also displayed actual AI-unavailable/empty-alert states.
It did not establish live model/Cowrie acceptance. The screenshot is retained at
`.test-runtime/auth-timezone-db-20261014-01/evidence/auth-memory-cookie-ist.png`.

Earlier failures are retained: an OpenAPI YAML description error, browser loader/
render/cookie-scope/background-polling harness issues, and the real cross-tab
logout-all defect. Final passing regressions substantiate their corrections.
There is no claim that repository-wide lint passed.

## Separate persistence-test storage and repeat commands

Only `sentinelai_auth_timezone_test_20261014` on authenticated loopback
`127.0.0.1:27029` was connected. Data/logs/evidence live under
`.test-runtime/auth-timezone-db-20261014-01`. Credentials are new random values
protected with Windows DPAPI CurrentUser, never existing acceptance credentials.
The verified MongoDB executable was used read-only from its portable binaries
directory; no old MongoDB data directory was opened. The runner checks database,
port, storage ownership, redirected paths, version, authentication and bindIp.
It stops only its owned process and retains all regression data/evidence.

Fixtures are explicitly labeled AUTH REGRESSION/AUTH BROWSER REGRESSION users
and associated sessions, plus TIMEZONE-REGRESSION records with documentation-only
IPs/future boundary dates in threat/prediction/honeypot collections. They are
confined to the approved test database, inserted without telemetry/alert callbacks,
and retained. They are not production alerts or live Cowrie events. Repeating
tests adds identifiable fixtures; do not use these commands against another URI.

```powershell
# Project root; reuses ONLY the approved regression instance with ownership checks.
node scripts/run_auth_database_tests.cjs --resume tests/authPersistence.test.js tests/timezonePersistence.test.js tests/authBrowser.test.js
node scripts/verify_auth_test_evidence.cjs
ai-engine/.venv/Scripts/python.exe scripts/verify_hardening_state.py
```

Mocked/backend and frontend tests/build are documented in NATIVE_DEVELOPMENT.md.
The historical native_acceptance, frontend-smoke and review_auth_timezone
scripts now fail before execution: their pre-cutover behavior cannot validate
session cookies and must not reconnect to retained acceptance data. Their prior
source is preserved in the verified backup and historical evidence remains.

## Remaining risks and limits

- Immediate socket revocation is verified for one API process. Multi-process
  deployment needs shared revocation delivery/Socket.IO adapter integration before
  making that guarantee across workers. Out-of-band account changes are detected
  on incoming packets and periodic checks (15 seconds plus dependency latency).
  Already-authorized in-flight work cannot be retroactively cancelled.
- Strict replay revocation intentionally requires sign-in after a consumed/lost
  refresh or uncoordinated client. No grace period extends stolen-token usability.
  Concurrent independent logout intents can still yield conservative unconfirmed
  results if one consumes the credentials needed by another; they must not be
  presented as successful account-wide revocation without confirmation.
- Web Locks is required; unsupported browsers fail safely. If browser storage is
  blocked, durable offline logout intent cannot survive a full reload; server
  confirmation remains necessary. HttpOnly cookies reduce token exposure but do
  not eliminate XSS risk; scripts running in the page can still use memory access.
- Production HTTPS/reverse-proxy/cross-origin deployment was not tested. Keep
  same-origin cookie transport and explicit Origin policy; cross-site frontends
  are incompatible with the deliberate SameSite=Strict policy without a separate
  reviewed transport change. Existing generic optional date-range parsing was
  preserved; callers should supply ISO instants with Z/offset, not ambiguous
  offset-free date-times. Calendar reporting endpoints use the tested fixed policy.
- Real Cowrie event acceptance and enforcement remain pending a managed Linux
  host/log. No privileged packet capture, external AbuseIPDB acceptance or Docker
  deployment was performed. Model accuracy/coverage limitations remain unchanged.

## Changed files

The complete added/modified source/document paths and SHA-256 values are in
`.test-runtime/hardening-state-verification.json`, compared to the separate
pre-change backup. Runtime databases, profiles, dependency installs and generated
build output are excluded from that source-change inventory. The principal
implementation files are authSessionService/AuthSession/authCookies, HTTP/user
controllers, shared websocket/auth, frontend authClient/authInterceptors/context,
reportingTime helpers and analytics/socket services. Their regressions live in
backend/tests and frontend/tests; scoped runners/evidence verifiers live in scripts.

Source inventory: 70 files (24 added, 46 modified, 0 removed).

| File | Change |
| --- | --- |
| `README.md` | modified |
| `backend/README.md` | modified |
| `backend/controllers/authController.js` | modified |
| `backend/controllers/threatController.js` | modified |
| `backend/controllers/userController.js` | modified |
| `backend/middleware/auth.js` | modified |
| `backend/middleware/authCookies.js` | added |
| `backend/models/AuthSession.js` | added |
| `backend/models/User.js` | modified |
| `backend/routes/auth.js` | modified |
| `backend/server.js` | modified |
| `backend/services/aiService.js` | modified |
| `backend/services/authSessionService.js` | added |
| `backend/services/honeypotService.js` | modified |
| `backend/services/threatService.js` | modified |
| `backend/tests/auth.test.js` | modified |
| `backend/tests/authBrowser.test.js` | added |
| `backend/tests/authHardening.test.js` | added |
| `backend/tests/authPersistence.test.js` | added |
| `backend/tests/helpers/accessFixture.js` | added |
| `backend/tests/helpers/authMemoryStore.js` | added |
| `backend/tests/internalAuth.test.js` | modified |
| `backend/tests/nativeSafety.test.js` | modified |
| `backend/tests/predictionVerification.test.js` | modified |
| `backend/tests/reportingResponse.test.js` | added |
| `backend/tests/reportingTime.test.js` | added |
| `backend/tests/timezonePersistence.test.js` | added |
| `backend/tests/trainingSample.test.js` | modified |
| `backend/tests/websocket.test.js` | modified |
| `backend/utils/reportingTime.js` | added |
| `backend/websocket/auth.js` | added |
| `backend/websocket/socketManager.js` | modified |
| `docs/ARCHITECTURE.md` | modified |
| `docs/AUTHENTICATION_REVIEW.md` | modified |
| `docs/AUTH_TIMEZONE_IMPLEMENTATION.md` | added |
| `docs/NATIVE_DEVELOPMENT.md` | modified |
| `docs/NATIVE_INTEGRATION.md` | modified |
| `docs/TIMEZONE_POLICY_PROPOSAL.md` | modified |
| `frontend/package.json` | modified |
| `frontend/src/components/AlertBell.jsx` | modified |
| `frontend/src/components/Navbar.jsx` | modified |
| `frontend/src/components/Sidebar.jsx` | modified |
| `frontend/src/components/StatusBar.jsx` | modified |
| `frontend/src/context/AuthContext.jsx` | modified |
| `frontend/src/context/SocketContext.jsx` | modified |
| `frontend/src/hooks/useLiveFeed.js` | modified |
| `frontend/src/hooks/useRealTimeFeed.js` | modified |
| `frontend/src/pages/AIAnalytics.jsx` | modified |
| `frontend/src/pages/Campaigns.jsx` | modified |
| `frontend/src/pages/Dashboard.jsx` | modified |
| `frontend/src/pages/HoneypotAnalytics.jsx` | modified |
| `frontend/src/pages/Login.jsx` | modified |
| `frontend/src/pages/Settings.jsx` | modified |
| `frontend/src/pages/ThreatLogs.jsx` | modified |
| `frontend/src/pages/UserManagement.jsx` | modified |
| `frontend/src/services/api.js` | modified |
| `frontend/src/services/authClient.js` | added |
| `frontend/src/services/authInterceptors.js` | added |
| `frontend/src/services/authSession.js` | added |
| `frontend/src/utils/reportingTime.js` | added |
| `frontend/tests/authClient.test.mjs` | added |
| `frontend/tests/authInterceptors.test.mjs` | added |
| `frontend/tests/reportingTime.test.mjs` | added |
| `frontend/vite.config.js` | modified |
| `scripts/frontend-smoke.cjs` | modified |
| `scripts/native_acceptance.cjs` | modified |
| `scripts/review_auth_timezone.cjs` | modified |
| `scripts/run_auth_database_tests.cjs` | added |
| `scripts/verify_auth_test_evidence.cjs` | added |
| `scripts/verify_hardening_state.py` | added |
