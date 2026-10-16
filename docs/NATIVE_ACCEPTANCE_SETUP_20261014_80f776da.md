# Proposed controlled native acceptance setup — approval required

Purpose: verify authenticated MongoDB persistence, revocation across two separate
API processes, actual HTTPS/reverse-proxy browser transport, real existing RF/IF
inference and native UI/API read-back. No Docker/WSL, recovered data, existing .env,
existing credentials, old database, public listeners, packet capture, firewall
change or real IP blocking. No new software installation is needed.

## Exact new storage and database

New dedicated root, currently absent:
`C:\Users\srisn\Desktop\Projects\sentinelai-complete\.test-runtime\native-readiness-20261014-01`.
The runner must refuse pre-existing/redirected paths on initial creation.

Database: `sentinelai_native_readiness_20261014`.
Application URI structure (credentials never printed):
`mongodb://<new-application-user>:<redacted>@127.0.0.1:27030/sentinelai_native_readiness_20261014?authSource=sentinelai_native_readiness_20261014&replicaSet=sentinel_native_test`.
Bootstrap/admin URI is limited to this instance's admin database with
`directConnection=true`; it is never the retained acceptance instance.

An authenticated, single-node test replica set is needed for MongoDB change
streams. It is a functional fixture, not a high-availability deployment. No
reconfiguration of either existing test/acceptance database is proposed.
Data: new root/data. MongoDB logs: new root/logs/mongod.log.
API/AI/proxy logs: new root/logs with separate per-service files.
Sanitized evidence and screenshots: new root/evidence.
New isolated browser profiles: new root/browser-* (never inspected for cache.db).
Public test certificate files: new root/tls. Encrypted credentials/key material:
new root/credentials.dpapi. Current environment files remain unchanged.

## Listeners and topology

All listeners bind only 127.0.0.1:

| Service | Port | Purpose |
| --- | --- | --- |
| MongoDB 7.0.45 | 27030 | New authenticated replica set/shared session store |
| Genuine Python AI engine | 18000 | Existing models, inference only; no deception/learn endpoint calls |
| API worker A | 15001 | Distinct Node process |
| API worker B | 15002 | Distinct Node process sharing the new database and ephemeral signing keys |
| Controlled HTTPS reverse proxy/static frontend | 13443 | Same-origin browser API/Socket.IO; trusted local proxy |
| Optional HTTP redirect/negative transport check | 13080 | Redirect or reject; no plaintext authenticated acceptance |

The runner rechecks port availability before startup and refuses conflicts.
Both API workers explicitly use production cookie/transport policy and shared
MongoDB change-stream revocation. Single-process-only delivery will not be claimed
as multi-process acceptance. Direct stream failure disconnects local sockets and
fails required authorization closed; availability/recovery gets separate tests.
Business-event fan-out across arbitrary workers is not implied by a revocation
subscription; native UI telemetry tests use the emitting worker explicitly.

## Credentials and TLS trust

Create new cryptographically random MongoDB admin/application passwords, test-user
passwords, JWT access/refresh keys, SENTINEL_KEY, HONEYPOT_API_KEY and replica-set
key material. Application MongoDB user gets readWrite only on the named new
database. Encrypt durable credential/key material with Windows DPAPI CurrentUser;
pass secrets through owned child-process environments/IPC, never command arguments
or printed configuration. Any temporary MongoDB keyfile is scoped to new root,
restricted to the current Windows user and removed after owned-process shutdown.
The encrypted original is retained for explicit scoped resumption.

Generate a dedicated test CA and certificate with SAN localhost/127.0.0.1 using
the installed Python cryptography library. Do not modify Windows trust stores,
existing certificates or production configuration. Node/Python test clients trust
only this new test CA and verify TLS/hostname. The isolated Chrome profile may use
the certificate-specific SPKI trust pin for this controlled certificate only;
do not use global certificate-error bypass or disabled TLS verification. This
establishes real local TLS/proxy behavior, not public-PKI/production-host readiness.
The public certificate fingerprint may appear in evidence; private keys may not.

Proxy removes client-supplied forwarding headers and sets its own HTTPS forwarding
metadata. API trust is restricted to its explicit loopback proxy address. HTTPS
cookies remain Secure/HttpOnly/Strict and auth-scoped; spoofed Origin, CSRF and CORS
are rejected. Production NODE_ENV/CLIENT_URL/proxy/multi-worker flags are temporary
process configuration only. No existing .env is edited.

## Expected persistent writes

- New replica-set configuration/oplog, MongoDB authentication users and schema indexes.
- Clearly labeled native-readiness administrator/per-scenario authentication test
  accounts, AuthSession documents, version/revocation/rotation metadata.
- Real archived CICIDS dataset requests evaluated through existing models;
  prediction records plus genuine resulting threat/alert records in this new
  database only, with run/dataset/row provenance. No forced score/decision, demo
  feed, mock prediction acceptance, or production alerts.
- If reporting fixture cases are repeated, explicitly labeled boundary records
  in the new database only, separate from real-model evidence.
- Optional explicit autoBlockEnabled=false setting, never enabled. No BlockedIP
  or privileged enforcement operation is permitted. Any BLOCK score is only a
  model decision. No Q-learning/deception state is initialized or updated.
- New encrypted credentials/TLS material, service/process PID/port inventory,
  sanitized test evidence and screenshots. Existing evidence remains intact.

## Exact startup command forms

The reviewed runner to be implemented will be invoked from the project root:

```powershell
node scripts/run_native_readiness.cjs --create
```

It may create/start only the resources above, using these child command forms.
Arguments below contain no secret values; the replica-set keyfile contains new
test-only material and is restricted to this owned root.

```powershell
& 'C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\binaries\mongod.exe' --auth --replSet sentinel_native_test --keyFile 'C:\Users\srisn\Desktop\Projects\sentinelai-complete\.test-runtime\native-readiness-20261014-01\runtime\replica-keyfile' --bind_ip 127.0.0.1 --port 27030 --dbpath 'C:\Users\srisn\Desktop\Projects\sentinelai-complete\.test-runtime\native-readiness-20261014-01\data' --logpath 'C:\Users\srisn\Desktop\Projects\sentinelai-complete\.test-runtime\native-readiness-20261014-01\logs\mongod.log' --logappend
# AI cwd ai-engine, with new internal key/model location passed in process env:
.venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 18000
# Separate backend processes, with distinct HOST/PORT and shared approved URI/keys in env:
node backend/server.js  # worker A: HOST=127.0.0.1, PORT=15001
node backend/server.js  # worker B: HOST=127.0.0.1, PORT=15002
# Controlled test-only proxy/static frontend, with owned certificate key delivered privately:
node scripts/native_readiness_proxy.cjs
```

Before application tests the runner initializes only the new replica set through
the localhost exception using
`replSetInitiate: {_id:'sentinel_native_test',members:[{_id:0,host:'127.0.0.1:27030'}]}`,
creates new admin/application MongoDB users with generated credentials, verifies
anonymous reads are rejected, and confirms authenticated bindIp/port/dbPath/auth
and replica-set primary state. No existing instance is connected or altered.
Account creation uses either the scoped new admin bootstrap or labeled test
fixtures inside this database. API application actions use current cookies/CSRF
and JWT contracts; historical acceptance scripts will not run.

## Shutdown and retention

Record PID, parent ownership, port and startup details for each child. Stop/restart
only run-owned children during outage/recovery tests. MongoDB shutdown is an
authenticated command to this exact new instance; fallback terminates only the
owned child handle. Stop API/AI/proxy/browser children; verify owned ports closed.
Retain new data, encrypted credentials, public certificates and sanitized evidence
for review. Do not delete existing/retained data or backups. Do not scan browser
profiles/database storage for secrets or inspect cache.db. Logs/evidence receive
credential and bearer-token redaction checks before publication.

**Approval requested:** create/start this exact controlled test setup and write
only its labeled regression/model-acceptance records. Live Cowrie host testing,
real blocking, packet capture, public exposure and production deployment are not
included. If approval is withheld, source/unit hardening can continue; persistent,
multi-process and actual HTTPS acceptance remain BLOCKED.
