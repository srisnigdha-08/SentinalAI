# Native hardening changes and cutover requirements

The read-only baseline is recorded in NATIVE_BASELINE_AUDIT_20261014_80f776da.md
and NATIVE_FINDINGS_SUPPLEMENT_20261014_80f776da.md. The separate source backup
is `.test-runtime/master-source-backup-20261014-80f776da`; 201 copied files were
individually verified before editing. Existing complete backups remain untouched.

## Runtime changes

- `backend/tests/verifyBlocker.js`: CRLF to LF only. Normalized bytes match the
  backup. No helper behavior or lint rule was changed.
- Shared authentication revocation uses a database-wide MongoDB change stream
  for users/AuthSession security mutations. Production must explicitly set
  `AUTH_REVOCATION_MODE=single` or `mongo-stream`; declared multiple workers
  require `mongo-stream`. That mode requires a replica set or sharded MongoDB.
  Each worker must finish a real cursor round trip before accepting connections.
  No fallback to local revocation occurs. Session operations check availability
  before and after persistence. Disconnect/error/stale stream disconnects local
  sockets and denies required authorization. A two-second stale threshold and
  500ms cursor waits provide bounded outage detection; they do not promise zero
  in-flight events or instantaneous network-failure detection. Recovery resumes
  delivery and uses fresh user/session reads.
- Production API and Socket.IO transport requires direct TLS or exact `https`
  forwarding from an explicitly trusted IP/CIDR. Numeric hop trust is rejected
  in production. `TRUST_PROXY=0` means no proxy trust. The actual production proxy
  address and network isolation must be supplied by its operator. No .env changed.
- Free-text logging now masks standalone/percent-dot JWTs, credential query
  parameters and URL userinfo; secret-shaped objects include private keys and
  captured credentials. Cowrie parser command/download/error logs omit payloads.
- FastAPI request-validation errors omit raw input/context. Non-finite input can
  return sanitized 422 JSON instead of a JSON-serialization 500. Optional input
  defaults and model/security thresholds are unchanged.
- Prediction-only shutdown no longer announces a Q-table write that did not
  happen. The scorer remains lazy; no acceptance deception/learning call is made.

## Approved controlled acceptance clarification

The user approved NATIVE_ACCEPTANCE_SETUP_20261014_80f776da.md. The proxy connects
outbound from `127.0.0.2` and the APIs trust only `127.0.0.2/32`; all listeners
still bind exclusively to `127.0.0.1` on the six reviewed ports. A direct client
from 127.0.0.1 cannot spoof its forwarded HTTPS protocol. This uses an ordinary
loopback socket source; no OS address, firewall or WSL configuration changes.

Initial invocation: `node scripts/run_native_readiness.cjs --create`.
After an interrupted/failed run, scoped `--resume` verifies the ownership file,
encrypted credentials, exact root/database/ports and unredirected paths before
starting only this same approved environment. Every invocation creates a unique
evidence subdirectory; it never overwrites an earlier result. Data and encrypted
credentials are retained. Only labeled test accounts may be changed/deleted for
security regression cases. Reporting boundary fixtures use a separate explicitly
named fixture collection and are never production telemetry or live-Cowrie proof.

TLS keys travel to the child proxy through IPC. Only public CA/leaf certificates
are plaintext files. Test clients verify the dedicated CA/hostname; Chrome uses
the dedicated leaf's SPKI pin in a new isolated profile. Windows trust stores are
unchanged. Certificates expire after seven days; resumption must not bypass expiry.

These source changes do not imply production readiness, multi-worker business
event fan-out, live Cowrie telemetry, or actual IP containment. Those are separate
evidence categories in the final readiness report.

## AI integration and Cowrie follow-up

Backend AI readiness now requires both loaded models at /ready and authenticated
access to /model/info. A wrong internal key cannot claim readiness. Invalid feature
requests rejected by Python return a sanitized 422 through /api/ai/analyze; actual
transport/model loss retains the existing 503 behavior. These changes preserve
all scores, classes, thresholds, successful response shapes and persisted dates.

The optional Cowrie output implements current normalized dictionary-event dispatch
through write(), uses CowrieConfig and keeps per-instance session state. Captured
login credentials travel through the supported closure contract; unsupported
LOGIN root events receive 400 instead of a fake success. It is not enabled or
installed on a Linux host by this work. The configured JSON parser remains a
separate ingestion option; enable only one source for the same stream to avoid
duplicate command/download events. Production operator must configure its HTTPS
URL and private internal key; existing cowrie.cfg/userdb are unchanged.

Ingestion now validates session/IP/command requirements, rejects missing records
with 404, and returns sanitized 503 if the collector cannot load. Collector errors
propagate instead of becoming successful acknowledgements. Obsolete /app dependency
fallbacks and console fallbacks were removed; native relative imports fail explicitly.
Commands/credentials remain forensic data in the existing application storage;
they are omitted from operational logs. Failed closure delivery retains local
parser/plugin state for explicit retry; a durable retry queue is still absent.

HoneypotSession has closureAnalysisState (idle/processing/complete/failed), attempt
identity and start/completion timestamps. An atomic database claim precedes
credentials, prediction, deception scoring, clustering or containment. Completed
ordinary closes return the same record, and collector repeats do not rebroadcast.
In-progress/failed ordinary retries return 409; no uncertain external side effect
is automatically repeated. A privileged analyst/admin may request intentional
reclassification via PUT /api/honeypot/sessions/{id}/close with JSON
{"reclassify":true}. Original closure time/duration are preserved. Existing BLOCKED
threats remain blocked; an existing fallback IP block does not create another block
alert. Thresholds and model decisions remain unchanged. Complete denotes a completed
attempt, not a claim that every optional upstream inference/clustering call succeeded.

No historical records were migrated. Existing closed records without a completion
marker require an operator-reviewed migration policy before repeat closure; otherwise
the first post-cutover call may perform one more analysis. Crashed processing claims
require manual review of actual side effects before any scoped repair; there is no
automatic lease recovery or exactly-once external-enforcement guarantee. Tests of
these Cowrie changes use mocked models/services only. Real Cowrie persistence and
multi-worker lifecycle concurrency remain unverified until an authorized fixture or
managed host is available. No retained acceptance database may be used for migration.

Viewer list/detail responses now exclude captured usernames/passwords but retain
credential-attempt counts and success metadata. Data is copied for response filtering;
stored records are not overwritten. Existing analyst/admin forensic access is
preserved. That access must be paired with trusted enrollment before real telemetry:
the existing public registration behavior still permits analyst accounts. No
registration-policy change or historical credential cleanup was performed here.

## Acceptance runner notes

--resume --focus-browser reuses existing real-model records and creates only the
labeled accounts necessary for browser regressions. It stops the owned AI process
before Chrome to reduce load; this is a deliberate dependency-unavailable UI check,
separate from the earlier healthy-AI browser run. The one-second access-token fixture
changes only the test browser's login response; actual backend issuance remains 900
seconds and its refresh session retains the original absolute expiry. Actual login,
cookies, CSRF, refresh and Socket.IO connections are still used.

--resume --focus-contract tests invalid-input 422, incorrect internal-key readiness
and recovery through an owned worker restart, and counters against existing records.
It creates one labeled authentication account and no new predictions/threats.
Owned process argument inventory was corrected after the first acceptance run;
use topology.json plus per-service logs for earlier distinct-worker evidence.

Windows' venv python.exe redirector can spawn another interpreter. The runner resolves
sys._base_executable and launches that same installed Python directly with the venv
site-packages on PYTHONPATH, so its owned child handle is the actual AI interpreter.
No installation or interpreter files were changed. Startup allows up to 180 seconds
for genuine model loading; early timeout/spawn/DevTools failures remain in evidence.
