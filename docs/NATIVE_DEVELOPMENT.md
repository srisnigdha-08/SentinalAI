# Native development

Validated on Windows with Node 24.14.0 and Python 3.11.9. MongoDB 7 is required for
backend persistence. A portable 7.0.45 instance has now passed native acceptance
using a dedicated authenticated development database and data directory. See
[NATIVE_INTEGRATION.md](NATIVE_INTEGRATION.md) for exact paths, retained evidence
and historical acceptance evidence. That retained database is excluded from
current development/testing. Do not point MongoDB at any recovered directory.
Current authentication cutover and scoped regression commands are documented in
[AUTH_TIMEZONE_IMPLEMENTATION.md](AUTH_TIMEZONE_IMPLEMENTATION.md).

## Install

From the project root in PowerShell:

```powershell
cd backend
npm ci --ignore-scripts
cd ../frontend
npm ci --ignore-scripts
cd ../ai-engine
py -3.11 -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
.venv/Scripts/python.exe -m pip check
```

The existing .venv already works; do not recreate it unless needed. Packages are
pinned for compatibility with the saved models. Joblib was aligned to the tested
1.5.3 installation; classifier/scaler artifacts were not retrained or changed.
The root models/ directory is preserved but native service startup selects
ai-engine/models/. Do not load untrusted pickle files.

## Configure

Preserve existing backend/.env and deployment environment files. For a new
environment, copy backend/.env.example only if the destination does not exist.
Generate four independent random secrets for JWT_SECRET, JWT_REFRESH_SECRET,
SENTINEL_KEY and HONEYPOT_API_KEY. They must not be placeholders and must be at
least 16 characters; 32 random bytes encoded as hex is suitable.

Set MONGO_URI to an explicitly approved fresh MongoDB database (for example
mongodb://127.0.0.1:27017/sentinelai-native-new), CLIENT_URL=http://localhost:3000,
AI_ENGINE_URL=http://127.0.0.1:8000, PORT=5000, HOST=127.0.0.1,
TRUST_PROXY=0 and NODE_ENV=development. Start your independently managed MongoDB
service with its own new data location; this project does not start or repair it.

Optional ADMIN_INITIAL_PASSWORD provisions an administrator only if its email
does not exist; otherwise existing accounts apply. Public registration is disabled;
active administrators provision new accounts using the Users page or protected
POST /api/auth/provision. See ENROLLMENT_POLICY_20261015.md. No default
password is supplied. ABUSEIPDB_API_KEY enables optional outbound HTTPS enrichment;
it is absent from inspected configuration and is not required for inference.
No other external API key is required by the core application.

## Start three terminals

Start AI first, from ai-engine. The explicit dotenv file shares the backend's
internal key without copying it into documentation or command history:

```powershell
$env:Q_TABLE_PATH = Join-Path (Get-Location).Path 'runtime/q_table.json'
.venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ../backend/.env
```

The shipped q_table.json is preserved. On the first scoring request, its state
is copied into the separate runtime path only if that destination does not exist.
Existing runtime learning state is retained.

Then backend (from backend): `npm start`. It loads backend/.env regardless of
working directory and listens only after MongoDB connects.

Then frontend (from frontend): `npm run dev -- --host 127.0.0.1`.
Open http://localhost:3000. Vite proxies API and Socket.IO traffic to port 5000.
VITE_API_BASE_URL and VITE_SOCKET_URL override browser destinations only when
needed; neither is a place for secrets. All VITE variables are public build inputs.
Use a same-origin browser proxy where possible. For a separately approved local
backend port, set SENTINEL_DEV_API_PROXY in the Vite process environment.
Keep CLIENT_URL aligned with the actual browser origin. Production CLIENT_URL
must be HTTPS; native HTTP development is restricted to localhost/127.0.0.1.
Authentication requires Web Locks (a modern browser in a secure/loopback context).
All users must sign in again after the session-backed authentication cutover.

AI /health is process liveness; /ready requires loaded models.
Backend /health returns 503 while MongoDB or the AI engine is unavailable.
The dashboard shows an unavailable state rather than claiming the engine is online.

## Validate

```powershell
cd ai-engine
.venv/Scripts/python.exe -m pytest -q
cd ../backend
npm test -- --runInBand
npm run lint
cd ../frontend
npm test
npm run build
cd ..
ai-engine/.venv/Scripts/python.exe scripts/native_ai_smoke.py
```

Backend unit tests mock database calls; Socket.IO unit tests use real loopback
connections. Database/browser suites skip unless run through the scoped approved
runner in AUTH_TIMEZONE_IMPLEMENTATION.md. That runner uses only its separate
authenticated regression database and explicitly labeled fixtures. The historical
frontend-smoke and native_acceptance scripts are retired and fail before connecting
to any database. They cannot validate the new cookie/session contract.

The native AI smoke script starts and stops its own temporary server, evaluates
existing dataset rows through /predict/eval, and verifies that statistics remain
unchanged. Prediction success is not an accuracy benchmark. Use the replay script
for broader isolated evaluation, never seed production data for a dashboard demo.

## Real honeypot integration

Cowrie is optional and requires a separately managed Linux host. Preserve
honeypot/cowrie configuration and plugin source. Set SENTINEL_API and SENTINEL_KEY
on the parser host, then run `python honeypot/parsers/log_parser.py --live --log <cowrie.json>`
against real events. It needs requests and access to the backend API.
The sniffer additionally needs Scapy/libpcap/cicflowmeter and packet capture
permissions; it has not been validated on this Windows host. No honeypot is
started automatically. The profile switcher writes configuration and requests a
manual service restart; it no longer restarts Docker containers.

The existing session-profile feature approximation and model dataset coverage
remain limitations, documented in ARCHITECTURE.md. Full MongoDB, real Cowrie and
external AbuseIPDB acceptance requires those independent services.
