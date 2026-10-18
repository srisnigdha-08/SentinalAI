# SentinelAI Presentation PC & Viva Demonstration Runbook

> **Target Platform**: Windows 11 / Windows Server (Native Execution)  
> **Host Environment**: Native Node.js v20+, Python 3.12, MongoDB 7.x  
> **Security Rule**: Passwords and secrets must NEVER be committed to repository documentation. Credentials are provided via environment variables or presentation cue cards.

---

## 1. System Pre-Flight & Service Initialization

Open an Administrative PowerShell console on the presentation host.

### Step 1.1: Verify & Start MongoDB
SentinelAI uses the native Windows MongoDB service:
```powershell
# Verify MongoDB service status
Get-Service MongoDB

# If stopped, start the service
Start-Service MongoDB

# Confirm database port 27017 is listening
Get-NetTCPConnection -LocalPort 27017 -State Listen
```

---

## 2. Environment Configuration Profile

SentinelAI includes a dedicated demonstration profile [`deployment/.env.demo`](../deployment/.env.demo) configured for local loopback HTTP (`http://localhost:3000` to `http://localhost:5000`). It maintains full RBAC validation, audit immutability, data redactions, and session enforcement while eliminating HTTPS cookie-prefix requirements on local evaluation machines.

To set the environment profile:
```powershell
$env:DOTENV_CONFIG_PATH = (Resolve-Path "deployment/.env.demo").Path
```

---

## 3. Launching Application Services

The demonstration requires three services: the AI Inference Engine (Port 8000), the Node.js Backend API (Port 5000), and the React/Vite Frontend (Port 3000).

### Step 3.1: Launch the AI Engine (Port 8000)

You can launch either the **Real Machine Learning Engine** or the **Lightweight Mock AI Engine**:

#### Option A: Real Python AI Engine (Recommended if venv is populated)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine
$env:SENTINEL_KEY = "<YOUR_CONFIGURED_SENTINEL_KEY>"
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000
```

#### Option B: Lightweight Mock Engine (Rapid 0-dependency fallback)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete
node scratch/mock_ai_engine.js
```

#### How to Tell Which Engine is Running
Run the following PowerShell check against `http://127.0.0.1:8000`:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/model/info" -Headers @{ "X-API-Key" = "<YOUR_KEY>" }
```
- **Real Python Engine**:
  - Exposes Swagger UI at `http://127.0.0.1:8000/docs`.
  - `/model/info` returns real ensemble dimensions, Random Forest features, and SHAP tree parameters.
  - Calling `/model/info` *without* an API key returns `HTTP 401 Unauthorized`.
- **Mock Engine**:
  - Exposes no Swagger docs.
  - `/model/info` immediately returns hardcoded JSON: `{"status":"ok","model":"SentinelAI-Ensemble","version":"2.4","accuracy":0.96}` without requiring an API key.

---

### Step 3.2: Launch the Backend API (Port 5000)
Open a new PowerShell window:
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete
$env:DOTENV_CONFIG_PATH = (Resolve-Path "deployment/.env.demo").Path
node backend/server.js
```
*Expected console output:*
```text
[info] [WS] Socket.IO initialized
[info] MongoDB connected: localhost/sentinel-db
[info] SentinelAI Backend ready on port 5000
```

---

### Step 3.3: Launch the Frontend Application (Port 3000)
Open a new PowerShell window:
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend
npm run dev
```
*Expected console output:*
```text
  VITE v5.x.x  ready in 250 ms
  ➜  Local:   http://localhost:3000/
```

---

## 4. Demonstration Accounts (Role-Based Access)

Use the following pre-configured demonstration accounts (passwords provided separately on presentation cue card):

| Role | Account Email | Capabilities & Interface Behavior |
| :--- | :--- | :--- |
| **Viewer** | `sara@sentinel.io` | **Observation Mode**: Read-only SOC overview. All IP addresses masked (`xxx.xxx.xxx.xxx`), honeypot commands redacted (`[REDACTED_COMMAND]`). Control buttons (`Block IP`, `Triage`) are completely absent from DOM. Admin routes denied. |
| **Analyst** | `arjun@sentinel.io` | **Defense Workspace**: Full unmasked forensic telemetry for SOC threat hunting (raw attacker IPs, unmasked shell commands, MITRE ATT&CK techniques). Action buttons (`Block IP`, `Triage Threat`) enabled. Admin routes denied. |
| **Administrator** | `admin@sentinel.io` | **Control Workspace**: Full operational control. Access to User Management (`/dashboard/users`), System Settings (`/settings`), Security Audit Log, and live user demotion / session termination controls. |

---

## 5. Five-Minute Presentation Walkthrough Script

### Minute 1: The Principle of Least Privilege — Viewer Observation Mode
1. Open Google Chrome and navigate to `http://localhost:3000/login`.
2. Open Chrome DevTools (`F12`), switch to the **Network** tab, and filter by `WS` and `Fetch/XHR`.
3. Log in as **Viewer** (`sara@sentinel.io`).
4. **Demonstrate Data Redaction**:
   - Inspect incoming REST responses (`/api/threats` and `/api/honeypot/nodes`). Show that attacker IPs are masked in-flight (e.g., `203.0.113.xxx`).
   - Switch to the DevTools WebSocket tab (`/socket.io/`). Show that real-time live threat frames (`new_threat`, `honeypot_command`) contain `[REDACTED_COMMAND]` and masked IPs.
5. **Demonstrate UI Hardening**:
   - Point out the yellow badge: `VIEWER // OBSERVATION MODE`.
   - Show that action buttons (`Block IP`, `Triage`) do not exist in the DOM.
   - Click the navigation sidebar: Management links (`Users`, `Settings`) are omitted.
   - Attempt direct URL entry in browser bar: `http://localhost:3000/dashboard/users`. Show immediate redirect to `/dashboard` with denial notification.

### Minute 2: Threat Hunting & Containment — Analyst Defense Workspace
1. In an Incognito window or after logging out, log in as **Analyst** (`arjun@sentinel.io`).
2. **Demonstrate Raw Forensic Telemetry**:
   - Point out the blue badge: `ANALYST // DEFEND`.
   - Inspect the Threat Logs table: IP addresses (`198.51.100.77`) and attack commands (`cat /etc/shadow`) are unmasked for threat analysis.
3. **Demonstrate Defensive Action**:
   - Click the **Block IP** button on an active threat.
   - Show that the system creates a `ContainmentAction` record, updates the firewall rule, and synchronously transitions the threat to `BLOCKED`.
   - Click **Triage Threat** to resolve alerts.

### Minute 3: Governance & Tamper-Evident Auditing — Admin Control Workspace
1. Log in as **Administrator** (`admin@sentinel.io`).
2. Point out the red badge: `ADMIN // CONTROL`.
3. Navigate to **User Management** (`/dashboard/users`):
   - Show active system accounts (`admin@sentinel.io`, `arjun@sentinel.io`, `priya@sentinel.io`, `sara@sentinel.io`, `operator1@sentinel.io`).
   - Explain that historical dev accounts (`admin@sentinel.local`) have been decommissioned.
4. Navigate to **Security Audit Log**:
   - Demonstrate the tamper-evident log stream.
   - Show that every administrative login, containment execution, role modification, and retention run is immutably logged with actor, target, timestamp, and metadata.

### Minute 4: Real-Time Session Invalidation & Live Demotion
1. Open two browser windows side-by-side:
   - **Window A (Left)**: Logged in as **Analyst** (`arjun@sentinel.io`) on `/dashboard/threats`.
   - **Window B (Right)**: Logged in as **Admin** (`admin@sentinel.io`) on `/dashboard/users`.
2. In Window B (Admin), locate `arjun@sentinel.io` and change his role from `Analyst` to `Viewer`.
3. **Observe Window A (Analyst) IMMEDIATELY WITHOUT REFRESHING**:
   - The server triggers token revocation and disconnects the WebSocket stream.
   - Any REST interaction in Window A immediately returns `HTTP 401 Unauthorized` (`"Invalid or revoked session"`).
   - Show that access demotion is instantaneous across both HTTP and WebSocket channels.
4. In Window B (Admin), restore `arjun@sentinel.io` back to `Analyst`.

### Minute 5: Architectural Defense-in-Depth Summary
Briefly explain the underlying database guarantees implemented in SentinelAI:
1. **Audit-First Policy**: Critical operations write an audit log before any state mutation; failure of the audit write aborts the operation.
2. **Compensating Rollback & Transaction Support**: In standalone MongoDB mode, multi-collection operations use compensating rollbacks; in replica set mode, multi-document ACID transactions execute natively.
3. **Sparse TTL Indexes**: The 48-hour sparse TTL index on `revokedAt` automatically evicts stale revoked sessions while active sessions (`revokedAt: null`) remain permanently protected from eviction.

---

## 6. Contingency & Troubleshooting Table

| Symptom / Failure | Root Cause | Immediate Remediation Step |
| :--- | :--- | :--- |
| **MongoDB Connection Refused** (`ECONNREFUSED 127.0.0.1:27017`) | Windows MongoDB service is stopped. | Run `Start-Service MongoDB` in Admin PowerShell. Check with `Get-Service MongoDB`. |
| **Port Conflict** (`EADDRINUSE: port 5000 / 3000 / 8000`) | A previous test or orphan process is holding the port. | Run `Get-NetTCPConnection -LocalPort <PORT>`. Identify `OwningProcess` PID and terminate with `Stop-Process -Id <PID> -Force`. |
| **Login Rejected (`HTTP 401 Unauthorized`)** | Stale session cookie or incorrect password. | Clear browser cookies and localStorage: `F12` -> Application -> Clear site data. Verify email spelling (`admin@sentinel.io`, not `.local`). |
| **Session Cookie Missing over HTTP** | `__Secure-` or `SameSite=None` flag blocking HTTP cookies. | Ensure `NODE_ENV=development` is loaded via `deployment/.env.demo`. Do not launch with `NODE_ENV=production` on plain HTTP loopback. |
| **AI Engine Fails / 503 Inference Unavailable** | Python venv missing or `SENTINEL_KEY` unset. | Immediately launch the fallback mock engine: `node scratch/mock_ai_engine.js`. The backend will transparently connect to port 8000 without requiring a restart. |
| **CSRF / Origin Rejected (`HTTP 403 Forbidden`)** | Request missing `Origin: http://localhost:3000` or CSRF nonce. | In automated scripts or curl calls, first query `GET /api/auth/csrf` to acquire the CSRF token and nonce cookie; pass `Origin: http://localhost:3000` and `X-CSRF-Token: <TOKEN>`. (The React frontend UI handles this automatically on load). |
| **WebSocket Connection Drops or Fails to Connect** | Vite dev proxy not routing `/socket.io`. | Confirm frontend is running via `npm run dev` (which includes proxy target `http://127.0.0.1:5000` in `vite.config.js`). Access the application via `http://localhost:3000`. |
