# SentinelAI Phase 6 — Operations Runbook

**Version:** 2.0 (Phase 6 Release)  
**Date:** 2026-10-15  
**Platform:** Windows 11 Pro Native Development & Windows Server Production  
**Project Path:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Native Integration Path:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration`  

---

## 1. Environment Configuration & Variables

### 1.1 Backend Environment Variables (`backend/.env`)

| Variable Name | Default Value | Recommended Setting | Purpose & Operational Constraints |
|---|---|---|---|
| `SESSION_INACTIVITY_TIMEOUT_SECONDS` | `900` | `900` (15 min) | Maximum idle time between authenticated requests before session revocation. Valid range: `60` to `2592000`. Server fails closed if invalid. |
| `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` | `false` | `false` | **CRITICAL SAFETY GATE.** When `false`, uses `SimulatedFirewallAdapter` (safe dry-run). Set to `true` strictly in dedicated isolated test VMs. |
| `SENTINELAI_ISOLATED_TEST_VM` | (unset) | `true` (VM only) | Required by `run-vm-firewall-tests.ps1` to prevent real firewall execution on developer host workstations. |
| `PORT` | `5000` | `5000` | HTTP port for the Node.js/Express API and WebSocket service. |
| `HOST` | `127.0.0.1` | `127.0.0.1` | Network binding interface. Keep on loopback unless reverse proxy (e.g. NGINX) is in place. |
| `MONGO_URI` | `mongodb://127.0.0.1:27017/sentinel-db` | Port 27017 | Database connection string for the live development database. |
| `HONEYPOT_API_KEY` | (managed secret) | (random 64-hex) | API key for authenticating honeypot daemon telemetry ingest at `/api/honeypot/ingest`. |
| `CLIENT_URL` | `http://localhost:3000` | `http://localhost:3000` | Origin URL for CORS and SameSite cookie policies. |

### 1.2 AI Engine Environment Variables (`backend/.env` / Process Environment)

| Variable Name | Configured Path | Purpose & Rules |
|---|---|---|
| `Q_TABLE_PATH` | `C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json` | **MUST POINT TO RUNTIME DIRECTORY.** `ai-engine/models/q_table.json` is the immutable shipped baseline model artifact. |

---

## 2. Service Lifecycle & Startup Procedures

### 2.1 Standard Native Startup Sequence (Developer Workstation)

Execute each step in a dedicated PowerShell console:

#### Step 1: MongoDB
```powershell
& "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\binaries\mongod.exe" `
    --dbpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\data" `
    --port 27017 `
    --bind_ip 127.0.0.1 `
    --logpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\mongod.log"
```

#### Step 2: AI Engine (FastAPI)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine
$env:Q_TABLE_PATH = "C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json"
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
```

#### Step 3: Backend API (Express & WebSockets)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete
powershell -ExecutionPolicy Bypass -File .\start-backend.ps1
```

#### Step 4: Frontend (Vite)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend
npm run dev -- --host 127.0.0.1
```

---

## 3. Graceful Shutdown & Supervision Runbook

### 3.1 Interactive Console Shutdown (`Ctrl+C` / `SIGINT`)
When running interactively, pressing `Ctrl+C` sends `SIGINT` to Node.js. The `GracefulShutdownManager` executes the following sequence:
1. Rejects incoming HTTP requests with `HTTP 503 Service Unavailable` and header `Connection: close`.
2. Stops recurring background reconciliation timers and health broadcasts.
3. Stops revocation change streams and background workers.
4. Gracefully disconnects all WebSocket clients via `io.disconnectSockets(true)` and closes Socket.IO.
5. Drains active in-flight requests (bounded by 5,000ms drain timeout).
6. Closes idle HTTP keep-alive connections and shuts down the HTTP server.
7. Closes the MongoDB database connection pool cleanly (`mongoose.connection.close(false)`).
8. Exits with status code `0`.

> [!NOTE]
> If cleanup hangs due to an unhandled promise, an unref'd emergency failsafe timer forces process exit with code `1` after 10,000ms.

### 3.2 Forced Windows Termination (`Stop-Process` / `taskkill /F`)
- Calling `Stop-Process -Id <pid>` or `taskkill /PID <pid> /F` executes the Win32 `TerminateProcess()` API.
- On Windows, `TerminateProcess()` immediately aborts all process threads in kernel mode. Application signal handlers (`SIGINT`/`SIGTERM`) **do not run**.
- Use `Stop-Process` only when a process is unresponsive or hung.

### 3.3 Windows Service Management via WinSW (Production / Dedicated Server)
To run SentinelAI Backend as a managed Windows Service capable of graceful shutdown:

1. **Prerequisites:** Windows Server 2022 or Windows 11 Enterprise/Pro with elevated Administrator privileges.
2. **Download WinSW:** Place `WinSW-x64.exe` as `sentinelai-service.exe` in `C:\SentinelAI\service\`.
3. **Template Configuration:** Copy `docs/templates/winsw-sentinelai-backend.xml` to `C:\SentinelAI\service\sentinelai-service.xml`.
4. **Install Service:**
   ```powershell
   .\sentinelai-service.exe install
   ```
5. **Start Service:**
   ```powershell
   Start-Service SentinelAI-Backend
   ```
6. **Graceful Stop Service:**
   ```powershell
   Stop-Service SentinelAI-Backend
   ```
   WinSW is configured with `<stopparentprocessfirst>true</stopparentprocessfirst>`, sending `CTRL_C_EVENT` to Node.js and waiting up to 15 seconds for `GracefulShutdownManager` to complete request draining and database closing before terminating.

---

## 4. Session Inactivity Operations & Semantics

### 4.1 Token & Session Lifecycles
- **Access JWT:** Valid for 15 minutes (`exp - iat = 900`). Stateless verification against `JWT_SECRET`.
- **Inactivity Timeout:** A user who makes no authenticated requests for 15 minutes has their session marked `revokedAt = Date.now()` with `revocationReason = 'inactivity-timeout'`.
- **Throttled Activity Recording:** To prevent excessive MongoDB writes, `lastUsedAt` is updated at most once every 60 seconds (`ACTIVITY_UPDATE_THROTTLE_SECONDS`).
- **Maximum Timeout Overshoot:** If a user makes a request at minute 14:59, their `lastUsedAt` is refreshed, giving an effective maximum idle window of up to 16 minutes before expiration.
- **Refresh Protection:** A refresh token presenting an idle-expired session cannot revive or extend it. The server rejects the rotation attempt with `HTTP 401 Unauthorized` and clears authentication cookies (`sentinel_refresh_v2` and `sentinel_csrf_v2`).
- **Absolute Expiry Cap:** `AuthSession.expiresAt` is capped at 30 days from creation. Active usage cannot extend a session past its 30-day absolute expiration date.

### 4.2 Excluded Operations
The following requests do **not** extend session activity:
- Unauthenticated requests (`/health`, `/api/system/health`, `/api/auth/csrf`).
- Failed authentication attempts (`/api/auth/login` with bad password).
- Static assets and frontend bundle files.
- Background WebSocket ping/pong messages (`ping_sentinel`).

---

## 5. Security Event Reliability Runbook

### 5.1 Unified Event Envelope
All security telemetry emitted across SentinelAI conforms to the standardized envelope:
```json
{
  "eventId": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "eventType": "THREAT_DETECTED",
  "source": "sentinelai-backend",
  "version": "1.0",
  "timestamp": "2026-10-15T21:51:00.000Z",
  "correlationId": "threat-6ad09f0e",
  "payload": { ... }
}
```

### 5.2 Deduplication & Outbox History
- **Deduplication Window:** The system remembers the last 1,000 event IDs. If an external collector retries sending the same event ID, the event bus suppresses duplicate processing and emits `{ status: 'duplicate_skipped' }`.
- **Outbox Ring Buffer:** Retains up to 200 recent events in-memory.
- **Client Reconnection:** Frontend clients re-establishing a dropped connection can query recent missed events via `/api/threats/recent` or request a WebSocket catch-up.

---

## 6. Cowrie Honeypot Integration Operations

### 6.1 Telemetry Status & Monitoring
To inspect the status of the Cowrie honeypot integration:
```http
GET /api/honeypot/status HTTP/1.1
Authorization: Bearer <admin-token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "collector": "available",
    "liveTelemetry": false,
    "status": "idle",
    "reason": "No active Cowrie daemon connected on host",
    "totalSessionsIngested": 0,
    "liveTelemetryBlocked": true,
    "blockReason": "Cowrie honeypot daemon is not provisioned on Windows host environment"
  }
}
```

### 6.2 Procedure for Connecting an External Cowrie Sensor
1. Provision a dedicated Linux server or isolated VM running Cowrie.
2. In `cowrie.cfg`, configure the output plugin to point to SentinelAI API:
   ```ini
   [output_sentinel]
   enabled = true
   api_url = http://<sentinel-host>:5000/api
   api_key = <HONEYPOT_API_KEY>
   ```
3. Verify that network traffic between Cowrie and SentinelAI is restricted via TLS/VPN.
4. Verify that ingested sessions appear in the SentinelAI dashboard without triggering automatic containment actions.

---

## 7. Isolated Real-Windows-Firewall Test VM Runner

### 7.1 Safety Contract & Guard Rails
- Real firewall testing is **STRICTLY FORBIDDEN** on developer workstations.
- The test harness runner (`scripts/run-vm-firewall-tests.ps1`) enforces:
  1. `SENTINELAI_ISOLATED_TEST_VM=true`
  2. Presence of `C:\sentinelai_vm_marker.txt`
  3. Elevated Administrator privileges
  4. Explicit confirmation parameter `-ConfirmExecution`
  5. Target restriction: **RFC 5737 TEST-NET-1 (`192.0.2.100`) only**

### 7.2 Execution Instructions on Dedicated Test VM
1. Log into the isolated test VM as Administrator.
2. Create the isolation marker:
   ```powershell
   New-Item -Path "C:\sentinelai_vm_marker.txt" -ItemType File -Force
   ```
3. Set the isolation environment variable:
   ```powershell
   $env:SENTINELAI_ISOLATED_TEST_VM = "true"
   ```
4. Run the test harness:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\run-vm-firewall-tests.ps1 -ConfirmExecution
   ```
5. Observe the output:
   - Audits pre-test rules matching `SentinelAI-VMTest-*` (must be 0).
   - Applies test rule to block `192.0.2.100`.
   - Verifies rule active in Windows Firewall.
   - Deletes test rule.
   - Audits post-test rules (must be 0).
