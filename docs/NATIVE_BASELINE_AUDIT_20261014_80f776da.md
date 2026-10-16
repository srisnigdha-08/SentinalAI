# Native baseline audit — 2026-10-14

Read-only baseline established before runtime edits. Project is
`C:\Users\srisn\Desktop\Projects\sentinelai-complete`; no .git directory exists.
The six authoritative architecture/auth/reporting/native documents and current
implementation/tests were inspected. No database, acceptance services, Docker,
WSL, recovered data, or protected disks were opened/started during this stage.
New audit artifacts are isolated in `.test-runtime/master-native-20261014-80f776da`.
Existing reports and evidence were not overwritten.

## Fresh checks

| Command/check | Exit/result | Evidence |
| --- | --- | --- |
| Backend: npm test -- --runInBand --json --outputFile ../.test-runtime/master-native-20261014-80f776da/backend-baseline.json; AUTH_TEST_MONGO_URI unset | 0; 251 passed, 12 persistence/browser cases skipped; 20 suites passed, 3 skipped | backend-baseline.json; backend-baseline.exit.txt |
| Backend: node node_modules/eslint/bin/eslint.js . -f json -o ../.test-runtime/master-native-20261014-80f776da/lint-baseline.json | 1; 141 CRLF formatting errors in tests/verifyBlocker.js; 16 warnings | lint-baseline.json; lint-baseline.exit.txt |
| Frontend: npm test | 0; 16 passed | frontend-baseline.log; frontend-baseline.exit.txt |
| Frontend: npm run build -- --outDir ../.test-runtime/master-native-20261014-80f776da/frontend-build-approved-host | 0; 950 modules; original dist preserved | frontend-build-host.log; frontend-build-host.exit.txt |
| Python: .venv/Scripts/python.exe -u -m pytest -q -p no:cacheprovider --junitxml ../.test-runtime/master-native-20261014-80f776da/python-baseline-host.xml | 0; 109 passed; pandas/Pydantic deprecation warnings | python-baseline-host.xml/log/exit.txt |
| Existing safe asset/source verifier with only its output path changed in memory | 0; all 46 assets match; lint helper hash matches verified pre-auth manifest | baseline-state.json |

Versions: Node 24.14.0, npm 11.9.0, Python 3.11.9. Python cryptography is already
available for test certificates. MongoDB 7.0.45 is the previously verified portable
binary; no instance was started in this baseline. Model artifacts are present.
These unit results are not native/live acceptance.

The first frontend build failed with sandbox realpath EPERM at frontend/index.html;
host-access rerun passed without source changes. The first sandbox Python run
stalled; only its two positively identified pytest processes were stopped, and
the separate host-access run passed. Original failed/aborted evidence is retained.
Backend tests warn about mocked timers in one reporting fixture; no live database
is used there. Reruns are not counted as extra unique cases.

## Findings before remediation

| ID / severity | Exact implementation | Evidence / reproduction | Origin | Fix and regression |
| --- | --- | --- | --- | --- |
| NATIVE-01 Low | backend/tests/verifyBlocker.js; backend/.prettierrc | File has exactly 141 CRLF pairs and 141 LF bytes; SHA-256 matches pre-auth backup manifest. ESLint reports only Delete CR formatting errors. | Verified pre-existing | Change only this helper's CRLF to LF; assert normalized bytes are otherwise identical; run global lint and syntax check. Do not execute its hard-coded mock listeners/connection rejection as live containment. |
| NATIVE-02 High for multi-worker deployment | backend/services/authSessionService.js disconnectSession/disconnectUser; backend/websocket/auth.js install | socketServer is process-local and has no shared adapter/delivery subscription. Another API process can continue outgoing room delivery until its 15-second periodic validation; incoming packets and HTTP still check shared session state. Existing real tests exercise one API process only. | Previously documented deployment gap | Add explicit topology configuration and MongoDB change-stream revocation mode; fail closed on stream/state outage. Test separate child API processes, all security mutations, races and outage/recovery in a new approved replica-set fixture. |
| NATIVE-03 Medium | backend/server.js trust proxy; backend/middleware/authCookies.js policy | Express trust proxy=1 trusts any peer at hop zero; isolated pure-function probe with 192.0.2.77 returns true. Secure cookie policy depends on CLIENT_URL/NODE_ENV, with no request transport check. No production HTTPS proxy evidence exists. | Pre-existing hop policy; transport validation gap | Require explicit trusted proxy addresses for production; reject plaintext browser API requests when not established through trusted HTTPS. Test spoofed forwarding headers, actual local TLS/reverse proxy, strict cookies and CSRF/CORS. Preserve same-origin design and existing .env files. |
| NATIVE-04 Medium | backend/utils/redact.js string branch | Pure offline probe signs a dummy JWT and places it in a URL query; redact returns it unchanged. Current regex handles Bearer and env-secret values, not bare JWTs or generic URL credentials. No real credential was printed in the probe. | Pre-existing redaction gap | Redact bare JWTs, credential query values and URL userinfo; regress structured data and free-text logs without suppressing useful nonsecret metadata. |
| NATIVE-05 High if logs exported | honeypot/parsers/log_parser.py on_cmd/on_download/process | Offline mocked-post probe with a dummy credential in a command and authenticated URL confirms it appears in captured logging. Login handlers already omit username/password. Raw exception strings can also contain malformed event values. | Pre-existing; login-only protection insufficient | Log intent/session/source metadata without raw command, URL or exception payload; preserve genuine ingestion payloads. Add caplog credential/URL/malformed-event regressions. |
| NATIVE-06 High integration defect | honeypot/cowrie/sentinel_output.py Output.write; backend/routes/honeypotIngest.js root dispatch | Output.write is pass; current Cowrie calls output plugins through write(event). Root ingestion accepts unknown/unsupported eventType with received=true, including this plugin's login events. Missing collector is also silently acknowledged. | Pre-existing | Add tested event dispatch/acknowledgement and reject unsupported/unavailable ingestion. Actual host/version installation remains unverified. |
| NATIVE-07 Medium lifecycle gap | honeypot/collectors/session_collector.js onSessionClosed; backend/services/honeypotService.js closeSession | Every duplicate close appends credentials and invokes inference/deception scoring again; fallback containment branch can repeat alerts. Existing tests guard already-linked BLOCKED threats but do not assert duplicate closure idempotency/concurrency. | Pre-existing | Add close idempotency/concurrency guards with unit evidence; no live/RL/containment operation is authorized during this task. |
| NATIVE-08 Medium model-evidence limitation | honeypot/collectors/session_collector.js onSessionOpened | Opens a HIGH SSH Brute Force threat with aiScore=0.75 before genuine model inference. This is an existing heuristic, not proof of real AI prediction. | Pre-existing application semantic | Document explicitly; changing early-session threat semantics needs a separately justified decision. Do not silently change model thresholds or cite this record as real inference evidence. |
| NATIVE-09 External blocker | managed Cowrie host and enforcement prerequisites | No independently managed Cowrie host/log access has been provided. | Known unavailable dependency | Live telemetry/closure/enforcement remain BLOCKED. Offline parser/plugin tests are separate evidence; no public attacks or privileged capture/blocking. |

The raw JWT/log probes printed booleans only. Source inspection also confirms the
same shared HTTP/socket verifier, CAS refresh rotation/replay, version revocation,
HttpOnly Strict cookies, signed Origin/CSRF mutations, in-memory tokens, coordinated
refresh/logout intents and explicit Asia/Kolkata reporting. Current aggregation
metadata shares captured time with queries; generated pipelines explicitly name
the reporting zone. No threshold/model/dataset/learning-state edits are proposed.

## Scope and approval gate

Stages 2–3 can proceed with source fixes and offline/unit verification. Persistent,
multi-process and HTTPS native acceptance must wait for explicit review approval
of NATIVE_ACCEPTANCE_SETUP_20261014_80f776da.md. Existing/retained acceptance runners
will not be used. The old standalone authentication regression database will not
be reconfigured into a replica set. A new source backup is needed because the
pre-auth backup predates the now-working session authentication implementation.

Primary references: [MongoDB change streams](https://www.mongodb.com/docs/drivers/node/current/monitoring-and-logging/change-streams/)
require replica-set/sharded topology; [Cowrie event pipeline](https://docs.cowrie.org/en/latest/EVENT_PIPELINE.html)
documents delivery to plugins through write(event). The host's actual Cowrie
version remains unavailable; upstream contracts are not live-host acceptance.
