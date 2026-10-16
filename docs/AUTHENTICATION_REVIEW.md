# Authentication security review and implementation proposal

Reviewed 2026-10-14 (Asia/Calcutta). The owner approved this design and it is now
implemented. See [implementation and regression evidence](AUTH_TIMEZONE_IMPLEMENTATION.md).
Existing-flow descriptions and review probes below describe the pre-cutover
application. No retained acceptance data was accessed during implementation.

## Existing flow

Login/registration return an access JWT, refresh JWT and public user object.
Access claims contain id/role, with JWT_EXPIRES_IN or a code default of seven
days. Refresh claims contain id, with a 30-day lifetime and a separate signing
key. These are code defaults, not a disclosure/audit of existing environment
values. Both tokens have standard issued-at and expiry timestamps, but no
session identifier, random token identifier or rotation generation.

HTTP authentication verifies the signature/expiry, reads the user, and checks
active status/password changes. Authorization uses the database user's role.
Refresh repeats the user checks and returns only a new access token. Password
change saves a timestamp and returns another token pair. Socket.IO performs
user/token checks during the connection handshake and keeps the assigned role.

The React login page stores both bearer tokens in localStorage. Logout clears
access/refresh/user storage and disconnects the provider-owned socket; it makes
no server logout call. The API client redirects on 401 rather than automatically
refreshing. Registration UI ignores its token response and asks the user to log
in. These differences must be accounted for in a coordinated client/API change.

## Findings and evidence

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| AUTH-01 | High | A stolen refresh token is reusable until expiry; refresh returns no replacement and detects no replay. | Isolated calls with the same token both returned 200. authController.js:70 |
| AUTH-03 | High | Browser logout does not revoke copied access/refresh tokens. | No logout route/controller/session store; access verification has no session check. auth.js, middleware/auth.js, AuthContext.jsx |
| AUTH-05 | High | Existing sockets have no expiry timer or subsequent account/session validation. | server.js:27 and socketManager.js source review. Long-lived expiry/revocation was not dynamically exercised. |
| AUTH-02 | Medium | Same-second password changes do not invalidate earlier tokens from that second. | User.js:25 floors milliseconds and uses strict less-than. The actual model method, refresh controller and HTTP middleware accepted the older test tokens. |
| AUTH-04 | Medium | Two same-user logins in a second receive identical refresh tokens; independent sessions cannot be distinguished. | Frozen-clock login calls returned identical refresh strings. authController.js:7 |
| AUTH-06 | Medium | Script-readable localStorage exposes both bearer tokens if an XSS flaw exists. | Login.jsx:22 and AuthContext.jsx. No XSS exploit was attempted or established. |

Refresh has the general API limiter, but not the stricter login/registration
limiter. Verification also lacks explicit algorithm, issuer, audience and token
purpose requirements. These are hardening items; no signature bypass was found.
optionalAuth omits status/password checks, but no current route uses it.

The four isolated negative controls passed: a wrong signing key, expiry, a
password change in a later second, and inactive-account status rejected refresh.
Existing targeted auth/native-security suites also passed (14 tests, 2 suites).
Passing these controls does not resolve the findings above.

Machine-readable evidence: .test-runtime/security-review-20261014.json.
The new scripts/review_auth_timezone.cjs replaces model calls in memory, uses
random temporary test keys, and opens no database or original environment file.
Its three reproduced findings are characterization of defects, not assertions
that the current application meets a secure logout/rotation contract. Convert
or retire these characterization checks as the findings are fixed.

## Proposed session design

Introduce an AuthSession collection and User.authVersion (logical initial value
0). Each successful login creates a separate random session id. A session holds
user id, authVersion, current refresh-token SHA-256 hash, rotation generation,
creation/last-use timestamps, absolute expiry and revocation state/reason.
Store no plaintext token. Do not add a bulk rewrite of existing user records.
TTL cleanup may eventually remove expired session metadata, but authorization
must check expiry directly; delayed cleanup must never keep a session valid.

Keep JWT access tokens and the existing independent signing keys. New tokens
carry session id, user id, authVersion, purpose and a random jti. Require HS256,
explicit SentinelAI issuer/audience, valid claims and expiry. Continue checking
the database user's status/role. HTTP and sockets must use the same verification
service, including a live session check and matching User.authVersion.
Session-store failure returns a dependency error and authorizes no request.

Propose a 15-minute access lifetime and preserve 30 days as the session's absolute
refresh lifetime. Refresh must not restart the 30-day lifetime indefinitely.
The shorter access duration changes current behavior and requires explicit
approval/configuration review; do not silently edit JWT_EXPIRES_IN or .env.

Use a signed refresh JWT with session id, user id, authVersion, generation,
random jti, purpose and absolute expiry. Its signature lets the server recognize
an authentic older generation without retaining an unbounded spent-token array.
Hash the complete refresh token for the current-token comparison.

## Rotation and revocation contract

1. Verify refresh signature, purpose, issuer/audience, expiry and claim types;
   load the active user/session and verify version/ownership.
2. Generate the successor token and hash. Atomically compare-and-swap one session
   document using current hash/generation, active revocation state and expiry.
   Exactly one request may consume the current generation. A standalone MongoDB
   supports this single-document operation; a replica-set transaction is not
   required for the rotation itself.
3. On success, return a new access token and replace the refresh token. On a
   failed swap, re-read the session: a validly signed older generation is replay
   and revokes that session family, including its newest access token. Invalid
   signatures, unknown session ids and arbitrary bad hashes must not revoke
   unrelated sessions. Do not restore the consumed token after an error.
4. POST /auth/logout revokes the current session, clears its refresh cookie, and
   disconnects sockets for that session. Support an expired access token through
   an independently valid refresh credential. Repeated logout is idempotent and
   never grants new credentials. POST /auth/logout-all increments authVersion,
   revokes the user's sessions and disconnects their sockets.
5. Password changes atomically save the password hash and increment authVersion,
   then issue a new session if preserving the current re-login-free response.
   Old access/refresh tokens must fail even within the same second. Do not change
   the timestamp comparison to <=: it would also reject newly issued same-second
   tokens. Account disable/role-security changes use the same revocation service;
   reactivation must not resurrect old credentials.

Strict replay revocation may log out a legitimate client after concurrent refresh
or a lost refresh response. The frontend must serialize refresh, coordinate
tabs, retry the original request at most once, and require sign-in when recovery
is uncertain. Do not introduce a replay grace period without separately reviewing
its effect on stolen-token reuse. A successful logout means the revocation commit
completed; a network/storage failure can clear local credentials but must be
reported as unconfirmed server logout. Already-authorized in-flight work cannot
be retroactively undone by a later revocation.

Rotation/replay response follows the pattern in
[RFC 9700 section 4.14.2](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14.2).
SentinelAI is a custom JWT application; this reference does not establish OAuth
conformance.

## Browser transport and Socket.IO

Recommend moving refresh tokens to an HttpOnly, SameSite cookie, with Secure
required over HTTPS. Use a separate explicit loopback-development cookie policy;
never silently relax production cookie requirements. Scope refresh cookies to
auth routes. Cookie-based mutations require Origin/CSRF validation. Configure
credentialed requests/CORS deliberately; existing loopback Vite proxies can keep
browser calls on the same origin. Do not switch to cookies without these controls.

Keep access tokens in memory and bootstrap user/access state from the refresh
cookie after reload. Remove legacy localStorage token values during the approved
cutover. Refresh must update AuthContext and reconnect the socket with the new
access token. Preserve role rules, account status checks, bcrypt behavior and
the existing JSON envelope/user fields where possible. Cookie transport changes
the refresh JSON contract, so backend and frontend must ship together.

Sockets join a server-selected session room, recheck authorization after joining
(closing the handshake/logout race), and disconnect at access-token expiry.
Revocation commits trigger session/user room disconnection. Sensitive incoming
events check authorization again. Share actual middleware with tests rather than
copying server.js into a test fixture (the current websocket.test.js copy already
omits the production password-change check). Periodic checks can cover account
changes outside application routes; they provide bounded detection, not instant
revocation. Multiple API processes require shared revocation delivery before an
immediate cross-process guarantee can be claimed.

## Implementation sequence and approval boundary

1. Add session schema, token/rotation service and mocked unit tests. Review the
   exact API/cookie/TTL contracts and legacy-token cutover before wiring them.
2. Integrate HTTP authentication, logout/refresh/password/admin lifecycle and
   Socket.IO through one shared verifier. Add endpoint/real-loopback socket tests.
3. Integrate browser refresh/bootstrap/logout and cross-tab coordination. Test
   storage failures, unavailable API and refresh/logout races. Release these
   pieces together; partial rotation rollout would strand the current client.
4. Run concurrency/persistence acceptance against a separately approved new test
   database. The retained sentinelai_acceptance_20261014 database is excluded.

Legacy tokens have no session identity and cannot meet per-session revocation.
Recommend a reviewed mandatory sign-in at cutover instead of silently accepting
legacy refresh tokens indefinitely. No legacy data deletion, credential rotation,
schema migration or new acceptance records are authorized by this review alone.

Approval items: session-backed tokens and mandatory sign-in cutover; 15-minute
access lifetime; HttpOnly refresh-cookie/CSRF transport; strict replay revocation;
and isolated database acceptance setup. These items were subsequently approved;
implementation and tests are recorded in AUTH_TIMEZONE_IMPLEMENTATION.md.

## Required regression tests for implementation

- Successful login/registration/password update preserve user/role contracts;
  each login has a distinct session and token identity, including within a second.
- Refresh rotates once; old generation replay revokes its family; unrelated
  sessions survive; two concurrent swaps have one winner. Random invalid input
  must not revoke a known victim session. Test lost-response/concurrent-tab UX.
- Logout rejects copied access and refresh credentials; logout-all/password
  changes reject every prior session, including same-second tokens. Repeated
  logout succeeds safely; account reactivation does not revive old sessions.
- Refresh/logout and password/refresh races leave no authorized orphan session.
  Failed persistence must not emit usable credentials or falsely report logout.
- Wrong key/purpose/issuer/audience/algorithm, missing claims, expiry, inactive
  user and role downgrade remain rejected. Session-store outage fails closed.
- Actual socket middleware rejects expired/revoked sessions, disconnects existing
  connections, binds verified roles, and closes the handshake/revocation race.
- Cookie flags, Origin/CSRF checks, bootstrap, coordinated refresh, one retry,
  logout error states and secret redaction have browser/endpoint coverage.

No production readiness or live Cowrie enforcement is claimed.
