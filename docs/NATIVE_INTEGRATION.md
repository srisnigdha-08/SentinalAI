# Native integration acceptance

Review date: 2026-10-14 (Asia/Calcutta). Docker is postponed.

This is the historical pre-cutover acceptance report. The retained
sentinelai_acceptance_20261014 database must not be used by current tests.
Authentication and timezone changes/results are documented in
[AUTH_TIMEZONE_IMPLEMENTATION.md](AUTH_TIMEZONE_IMPLEMENTATION.md).

## Current evidence

All 46 preserved assets matched PRESERVED_ASSETS_SHA256.json before this phase.
There is no Git repository. Existing results remain: 104 Python tests, 203
backend tests, frontend build and model/browser smoke checks passed. These
results do not establish real MongoDB or Cowrie integration acceptance.

The host is Windows 11 Home x64. mongosh 2.9.2 is installed. The existing
C:\Program Files\MongoDB\Server\8.2 directory contains data/log directories
but no bin/mongod.exe. Those directories will not be reused or opened.
No MongoDB Windows service or listener on the inspected native service ports
was reported by the read-only host inspection.

## Proposed MongoDB setup for review

Use the official MongoDB Community 7.0.45 Windows ZIP, matching the project's
documented major version. The verified official endpoint reports 634,876,648
bytes and publishes SHA-256:

7e3a435fa86e36e8ca4f2618fb41de06d75c28009c63725a20f9badd36eec6f6

Download source:
https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-7.0.45.zip
Checksum source: the same URL with .sha256 appended.

Proposed new root:
C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014

It does not exist. Its existing ancestor directories have no reparse points.
The C: filesystem reported approximately 10.7 GB free at review time.

- Extract portable binaries into this new root's binaries directory.
- Use only its newly created data directory as dbPath and logs directory for logs.
- Bind to 127.0.0.1:27028 with authentication enabled.
- Create database sentinelai_acceptance_20261014 and a readWrite application user
  restricted to it. Bootstrap a separate database administrator using the local
  exception on this fresh instance. Generate new random credentials privately.
- Start a directly managed process. Register no Windows service, change no
  system PATH or firewall settings, and alter no existing MongoDB configuration.
- Set backend connection overrides in the child process environment. Preserve
  backend/.env and all original credentials exactly.
- Keep this new development data and evidence after tests; stop only processes
  started by this acceptance run. Do not delete databases or directories.

Alternative options are the official MSI (system installation and possible
automatic service startup) or an independently managed MongoDB host with a new
database/user. The portable option provides explicit storage/process ownership.

The owner approved the portable setup and acceptance run, specifying the exact
sibling path above. Before extraction the archive must match the official
published checksum; before application tests the fresh instance must have
authentication enabled. Existing application environment files remain unchanged.

[Official Windows ZIP instructions](https://www.mongodb.com/docs/v7.0/tutorial/install-mongodb-on-windows-zip/)
confirm Windows 11 x64 support and explicit dbPath/local binding options.

## Acceptance boundaries

Only this development database may receive acceptance records. Use identifiable
acceptance accounts and real existing CICIDS2017 dataset records with provenance;
do not create a synthetic production feed or force a score to cross a threshold.
Record any naturally unavailable ALLOW/MONITOR/BLOCK branch as untested.
Automatic containment remains disabled unless separately needed and reviewed.

Logout currently clears browser authentication; the API has no logout endpoint
or token revocation store. Verify the actual behavior before describing server
session revocation as supported.

## Cowrie prerequisite

Actual Cowrie acceptance requires an independently managed Linux host, its
real cowrie.json log, backend reachability and HONEYPOT_API_KEY/SENTINEL_KEY
configuration. No such host has been identified. Do not replay synthetic events
as live telemetry. The native parser/plugin contract can be tested offline,
but that does not verify live SSH delivery or enforcement.

## Completed native acceptance

The official ZIP was downloaded and its complete SHA-256 matched the published
checksum before extraction. mongod reports version 7.0.45. Command-line options
were verified through the authenticated server: bindIp 127.0.0.1, port 27028,
authorization enabled, and dbPath exactly the approved new data directory.
No existing MongoDB data directory was opened. No installer, Windows service,
PATH/firewall change, Docker or WSL operation was performed.

Twelve grouped acceptance checks passed; the final run has no unresolved test
failures. Exact machine-readable evidence is in the approved root's
evidence/acceptance-results.json. Historical failed attempts are retained there.

| Check | Actual result |
| --- | --- |
| MongoDB readiness/version | 7.0.45, ping successful |
| MongoDB authentication | Anonymous collection read rejected (code 13) |
| Application-user permissions | Dedicated database connected; administrator collection read rejected (code 13) |
| Native service startup | AI ready, backend healthy after DB connection, Vite served frontend |
| Fresh database | Zero threats/alerts before acceptance records |
| Authentication | Admin provisioned, analyst registered, login and refresh succeeded, unauthenticated /me rejected |
| Model and persistence | Three real dataset decisions matched direct AI evaluation, backend result and persisted score; 53 finite features stored |
| Threat records | Created from an observed real dataset prediction; read-back and list API matched |
| Alerts and WebSocket | Alert persisted and delivered to its configured analyst role; threat delivered over authenticated Socket.IO |
| Browser | Real login, dashboard and threat logs rendered actual backend responses; no page exceptions |
| Dependency loss | AI stopped: health/analyze 503 and unavailable UI; new MongoDB stopped: backend health 503 and database disconnected |
| Logout | Access, refresh and user storage cleared; protected dashboard redirected to login |
| Hourly chart regression | Existing four threat records rendered in the activity chart; false empty-state message absent |

The counts above group related assertions; they are not an exhaustive claim of
all API or failure modes. The prior broad suites were not repeated. Changes here
received five new offline parser contract tests (all passed), an updated isolated
browser regression check (passed), and a rebuilt frontend (946 modules passed).

32 archived dataset rows were prepared; evaluation stopped after 24 rows once
all three decisions had occurred naturally. The samples persisted through the
backend were:

| Decision | Class | Score | Original CSV row index |
| --- | --- | --- | --- |
| ALLOW | BENIGN | 0.0664 | Monday-WorkingHours.pcap_ISCX.csv: 0 |
| MONITOR | DDoS | 0.7000 | Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv: 18883 |
| BLOCK | DDoS | 0.9242 | Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv: 18890 |

Dataset row indices are zero-based. Features and thresholds were not modified.
The source addresses 192.0.2.10/192.0.2.20 are documentation-only identifiers for
development acceptance, not claimed live attackers. Prediction records contain
acceptanceTest and dataset/row/label provenance. Manually created threat records
have NATIVE ACCEPTANCE ONLY notes and ACCEPTANCE-DATASET target service. Every
record is isolated in sentinelai_acceptance_20261014; no production feed ran.

BLOCK above is the model's decision. Automatic containment remained disabled,
so no BlockedIP records or actual connection enforcement were created. A BLOCK
prediction is not evidence of live blocking; actual Cowrie enforcement is pending.

Final retained collection counts: users 2, aipredictions 3, threatlogs 4, alerts 3;
campaigns, honeypotsessions, systemsettings, trainingsamples and blockedips 0.
Two manual threat/alert records exist because the first delivery attempt was
retained for investigation; no cleanup or deletion was performed.

## Defects fixed and failed attempts

- Logout/corrupt-auth/401 cleanup left a refresh token in localStorage. All three
  cleanup paths now remove it. Updated browser regression checks passed.
- Dashboard compared numeric hours with the API's HH:00 strings, rendering zero
  activity despite persisted threats. Matching the API labels fixed it. A
  read-only native/browser follow-up confirmed the four retained records render.
- Cowrie parser printed captured credentials and marked session creation as
  acknowledged before a successful backend response. It now omits credentials
  in login messages, marks success only after acknowledgement, and suppresses
  dependent posts when opening fails. Five offline tests passed. This does not
  provide durable event buffering or live delivery/enforcement acceptance.

The first alert delivery test timed out because it subscribed as admin while the
HIGH alert targets analysts. The corrected analyst subscription passed; application
role policy was preserved. The initial offline logout test expected a login-page
redirect, while the existing app redirects to the public home page. The assertion
was corrected and protected-route rejection verified. These were test-harness
errors; neither required an application role/navigation change.

## Protection and retained evidence

All 46 preserved assets matched their manifest again after the changes. Existing
.env files, credentials, models, datasets and original logs remained intact.
New database/application credentials are stored only in
acceptance-credentials.dpapi, encrypted using Windows DPAPI CurrentUser. Scanning
13 new textual log/evidence files found none of the generated credential values.
No credentials appear in this report.

All run-owned processes stopped. Loopback ports 27028, 8000, 5000 and 3000 were
closed after acceptance. The new data directory, ZIP, binaries and evidence were
retained. Screenshots in evidence/: dashboard-real-backend.png,
threats-real-backend.png, dashboard-ai-unavailable.png,
dashboard-hourly-chart-fixed.png. The latest chart screenshot supersedes the
initial screenshot's incorrect zero-activity chart.

## Continue native development

The historical native_acceptance runner is retired and now fails before any
database connection. Do not serve or test against the retained acceptance
database. Use separately managed, approved development storage and temporary
process-environment configuration described in NATIVE_DEVELOPMENT.md. Current
regressions use only the explicitly approved port 27029 test instance described
in AUTH_TIMEZONE_IMPLEMENTATION.md. Retain the old evidence and encrypted
credentials without using or modifying their database.

## Remaining integration limits

- Real Cowrie events and SSH/Telnet enforcement await a confirmed Linux host and
  cowrie.json access. No packet capture or privileged capability was added.
- The historical browser-local logout limitation has been addressed by the
  approved session-backed design; see current regression evidence in
  AUTH_TIMEZONE_IMPLEMENTATION.md and its remaining deployment limits.
- External AbuseIPDB enrichment was not tested; no acceptance key was supplied.
- Full model accuracy/coverage and small-viewport dashboard layout remain outside
  this acceptance run. The subsequent implementation uses UTC storage and
  explicit Asia/Kolkata reporting, with separate regression evidence.
- Native acceptance does not establish production readiness or Docker deployment.
