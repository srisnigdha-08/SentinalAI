# SentinelAI Operations Runbook — Phase 5 Native Windows Runtime

**Document Version:** 1.1  
**Effective Date:** 2026-10-15  
**Target Environment:** Windows 11 Native Development & Staging  
**Primary Project:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Native Integration:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration`  

---

## Document Revision History

| Version | Date | Author / Reviewer | Summary of Changes |
| :---: | :---: | :--- | :--- |
| **1.0** | 2026-10-15 | Verification Reviewer | Initial release following Phase 5 runtime activation. |
| **1.1** | 2026-10-15 | Windows Full-Stack Reviewer | **Corrective Remediation of Four Review Findings:**<br>1. Corrected `Q_TABLE_PATH` to point to `runtime\q_table.json` instead of the baseline model artifact `models\q_table.json`.<br>2. Corrected authentication documentation: separated 15-minute access token lifetime from 30-day absolute session lifetime; explicitly clarified that no 15-minute idle inactivity timeout is implemented.<br>3. Corrected backend shutdown procedure: distinguished Windows `TerminateProcess` forced termination (`Stop-Process`) from verified console `SIGINT` application-level graceful shutdown.<br>4. Separated unauthorized authentication smoke tests from authorized read-only inspection and isolated lifecycle testing. |

---

## 1. System Architecture & Service Map

The SentinelAI native stack consists of four interdependent microservices running locally over loopback (`127.0.0.1`):

```
                        +----------------------------+
                        |  Vite Frontend SPA         |
                        |  Port: 3000                |
                        +--------------+-------------+
                                       |
                                       | HTTP / WS (5000)
                                       v
+-----------------------+       +----------------------------+       +-----------------------+
|  MongoDB Database     | <---> |  Node.js Backend API       | <---> |  Python AI Engine     |
|  Port: 27017          |       |  Port: 5000                |       |  Port: 8000           |
|  DB: sentinel-db      |       |  (Express + Socket.IO)     |       |  (FastAPI / Uvicorn)  |
+-----------------------+       +--------------+-------------+       +-----------------------+
                                               |
                                               v
                                +----------------------------+
                                |  Containment Subsystem     |
                                |  - Mock Adapter (Active)   |
                                |  - Reconciler (60s loop)   |
                                |  - WinFW Adapter (Gated)   |
                                +----------------------------+
```

### Service Directory & Listener Reference
| Service | Local Port | Working Directory | Launch Mechanism | Health Endpoint |
| :--- | :---: | :--- | :--- | :--- |
| **MongoDB** | `27017` | `.../mongodb-dev/data` | `mongod.exe --dbpath ...` | Socket connect / `adminCommand({ ping: 1 })` |
| **AI Engine** | `8000` | `.../ai-engine` | `uvicorn inference.main:app` | `GET http://127.0.0.1:8000/health` |
| **Backend API** | `5000` | `.../backend` | `start-backend.ps1` (`node server.js`) | `GET http://127.0.0.1:5000/health` |
| **Frontend** | `3000` | `.../frontend` | `npm run dev -- --host 127.0.0.1` | `GET http://127.0.0.1:3000/` |

---

## 2. Process Supervision & Lifecycle Management

### 2.1 Starting Services
Always start services in topological order: **Database $\rightarrow$ AI Engine $\rightarrow$ Backend $\rightarrow$ Frontend**.

1. **MongoDB (Port 27017):**
   ```powershell
   & "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\binaries\mongod.exe" `
     --dbpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\data" `
     --port 27017 --bind_ip 127.0.0.1 `
     --logpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\mongod.log"
   ```

2. **AI Engine (Port 8000):**
   > [!IMPORTANT]
   > **Baseline Model Protection (Finding 1):** The baseline Q-table artifact resides at `ai-engine\models\q_table.json` and must remain read-only and immutable. Always configure `$env:Q_TABLE_PATH` to resolve to the **runtime** directory (`ai-engine\runtime\q_table.json`). The application automatically seeds the runtime file from the baseline model on first initialization and flushes updates only to the runtime path.

   ```powershell
   Set-Location "C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine"
   $env:Q_TABLE_PATH = "C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json"
   .\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
   ```

3. **Backend API (Port 5000):**
   ```powershell
   Set-Location "C:\Users\srisn\Desktop\Projects\sentinelai-complete"
   powershell -ExecutionPolicy Bypass -File "start-backend.ps1"
   ```

4. **Frontend Dev Server (Port 3000):**
   ```powershell
   Set-Location "C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend"
   npm run dev -- --host 127.0.0.1
   ```

### 2.2 Health Verification Script
To verify that all four services are listening and responsive without modifying state:
```powershell
@(27017, 8000, 5000, 3000) | ForEach-Object {
    $p = $_
    $conn = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "PORT $p : LISTENING (PID $($conn.OwningProcess) - $($proc.ProcessName))" -ForegroundColor Green
    } else {
        Write-Host "PORT $p : NOT LISTENING" -ForegroundColor Red
    }
}
```

### 2.3 Controlled Backend Shutdown & Restart Procedure

> [!WARNING]
> **Windows Process Termination Semantics (Finding 3):**
> On Windows platforms, `Stop-Process -Id <pid>` and `taskkill /PID <pid>` invoke the Win32 `TerminateProcess()` API. This is an **immediate forced termination** at the operating system kernel level. It does **not** deliver `SIGTERM` or `SIGINT` to the Node.js process and does **not** execute application-level graceful-shutdown handlers.
>
> Operators must understand the difference between **verified graceful shutdown** and **forced process termination**:

#### Method A: Verified Application Graceful Shutdown (Interactive Console)
When the backend is running in an interactive PowerShell or Command Prompt terminal:
1. Switch to the console window where `start-backend.ps1` is running.
2. Press `Ctrl+C`.
3. Node.js captures the console control event and executes the registered `SIGINT` handler:
   ```text
   2026-10-15 20:35:48 [info] SIGINT received
   ```
   - Stops Socket.IO health broadcast timer (`socketManager.stopHealthBroadcast()`).
   - Stops real-time token revocation delivery (`revocationDelivery.stop()`).
   - Stops containment reconciliation timer loop (`defaultReconciliationService.stop()`).
   - Closes Socket.IO active socket connections (`io.close()`).
   - Closes HTTP server to stop accepting new requests and drains active requests (`server.close()`).
   - Closes MongoDB Mongoose connection (`mongoose.connection.close()`).
   - Cleanly exits with code `0`.

#### Method B: Controlled Restart in Background / Non-Interactive Environments
When running as a background task, service, or when the console window is not directly accessible:
1. **Identify the exact backend process holding port 5000:**
   ```powershell
   $backendConn = Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue
   if (-not $backendConn) {
       Write-Host "No process currently listening on port 5000."
       return
   }
   $backendPID = $backendConn.OwningProcess
   $proc = Get-Process -Id $backendPID
   Write-Host "Target Process: PID $backendPID ($($proc.ProcessName)) Path: $($proc.Path)"
   ```
2. **Verify Process Ownership:** Confirm that the process path is `node.exe` belonging to SentinelAI, not an unrelated system service.
3. **Execute Process Termination (Forced OS Termination):**
   ```powershell
   Stop-Process -Id $backendPID -PassThru
   ```
4. **Verify Port 5000 Release:** Confirm that the operating system has released the TCP port binding before attempting to restart:
   ```powershell
   while (Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue) {
       Write-Host "Waiting for port 5000 to be freed..."
       Start-Sleep -Milliseconds 500
   }
   Write-Host "Port 5000 successfully released."
   ```
5. **Relaunch Using Verified Launcher:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Users\srisn\Desktop\Projects\sentinelai-complete\start-backend.ps1"
   ```
6. **Verify Startup Completion:** Check startup logs for:
   - `MongoDB connected: 127.0.0.1/sentinel-db`
   - `[ContainmentReconciliation] Service started (interval: 60000ms)`
   - `SentinelAI Backend ready on port 5000`
7. **Verify Health Endpoint:**
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:5000/health"
   ```

> [!CAUTION]
> Never use broad commands like `Stop-Process -Name node` or `taskkill /IM node.exe /F` as this will terminate the Vite dev server (Port 3000) and any background development tooling.

---

## 3. Containment Subsystem Operations

### 3.1 Architecture & Adapters
The Containment Subsystem (`backend/services/containmentService.js`) enforces isolation and blocking policies across threat actors.

- **`MockContainmentAdapter` (Default / Active):**
  - Safely logs containment actions in the database and audit trail.
  - Simulates latency and operating system rule execution without touching host firewall state.
  - Returns `{ success: true, mode: 'mock' }`.
- **`WindowsFirewallAdapter` (Safety-Gated):**
  - Manages Windows Defender Firewall rules via PowerShell `New-NetFirewallRule` / `Remove-NetFirewallRule`.
  - Prefix: `SentinelAI-Rule-*`.
  - **Safety Gate:** Strictly controlled by `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`. If not set to `'true'`, the adapter factory falls back automatically to `MockContainmentAdapter`.

### 3.2 Automated Reconciliation Service
The reconciliation service (`backend/services/containmentReconciliationService.js`) handles:
- **TTL Expiration:** Queries `ContainmentAction` documents where `expiresAt <= now` and status is `ACTIVE`.
- **Compensating Rollback:** Calls `adapter.removeRule(actionId, target)` and updates document status to `ROLLED_BACK`.
- **Stale State Recovery:** Identifies actions in `FAILED` or `ROLLBACK_FAILED` and retries rule cleanup up to max retries.
- **Interval:** Runs every 60,000 ms (1 minute).

### 3.3 Verifying Containment Subsystem Status (Finding 4)

#### A. Unauthorized Endpoint Protection Probing
To verify that the containment subsystem routes are mounted and protected against unauthenticated or invalid access:
```bash
# Probing without credentials returns HTTP 401 Unauthorized ("No token")
curl -i http://127.0.0.1:5000/api/containment/status
```
Expected output:
```json
{"success":false,"error":"No token","code":401}
```

#### B. Authorized Read-Only Runtime Status Inspection
When an authorized administrative or analyst token is available:
```bash
curl -H "Authorization: Bearer <ADMIN_OR_ANALYST_TOKEN>" http://127.0.0.1:5000/api/containment/status
```
Expected output:
```json
{
  "success": true,
  "data": {
    "backend": "mock",
    "adapterName": "MockContainmentAdapter",
    "realEnforcementEnabled": false,
    "activeContainmentCount": 0,
    "failedContainmentCount": 0
  }
}
```

#### C. Authorized Lifecycle Testing (Isolated Harness Only)
Never execute mutating containment actions against the live development database `sentinel-db`. Full lifecycle testing (containment creation, policy boundary checks, concurrency, rollback, and reconciler recovery) must only be executed against a temporary, disposable MongoDB instance on port 27029:
```powershell
npm test -- containment
```

---

## 4. Invariant Protection & Verification Runbook

SentinelAI enforces strict baseline invariants to prevent accidental data corruption or external host impact:

### 4.1 Database Safety Invariant
The live development database is `sentinel-db` on port 27017.
- **Never drop or seed `sentinel-db` during tests.**
- Integration tests requiring MongoDB **must** run against a temporary, disposable instance on port 27029 with explicit test URIs.

### 4.2 Protected Dataset Preservation
The following historical and acceptance data directories are write-protected and must never be altered or referenced for tests:
- `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\data`
- `D:\MongoPreservation`
- `D:\MongoPreservation_Backup_20261015`

To verify directory invariance:
```powershell
Get-Item "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\data" | Select-Object FullName, LastWriteTime
```

### 4.3 Host Firewall Invariance Check
To verify that no unauthorized host firewall rules have been created by SentinelAI:
```powershell
$rules = Get-NetFirewallRule -Name "SentinelAI-Rule-*" -ErrorAction SilentlyContinue
Write-Host "SentinelAI Firewall Rules Count:" @($rules).Count
```
**Acceptance Threshold:** Must strictly equal `0`.

---

## 5. Incident Response & Troubleshooting

### Incident A: Backend Returns HTTP 404 for Containment Endpoints
- **Symptom:** `GET /api/containment/status` returns `Route not found: GET /api/containment/status`.
- **Root Cause:** In-memory route drift caused by backend code updates on disk without restarting the running `node server.js` process.
- **Resolution:** Execute Section 2.3 (Controlled Backend Restart Procedure). Verify route availability immediately after restart.

### Incident B: Port 5000 Collision ("EADDRINUSE")
- **Symptom:** Backend fails to start with `Error: listen EADDRINUSE: address already in use 127.0.0.1:5000`.
- **Resolution:**
  1. Locate the process holding port 5000:
     ```powershell
     Get-NetTCPConnection -LocalPort 5000 -State Listen | Select-Object OwningProcess
     ```
  2. Terminate that specific PID.
  3. Re-run `start-backend.ps1`.

### Incident C: Reconciler Reports Adapter Failure
- **Symptom:** Backend log displays `[ContainmentReconciliation] Adapter removal failed for <id>: <error>`.
- **Resolution:**
  1. Inspect the failed containment record in `ContainmentAction` with status `ROLLBACK_FAILED`.
  2. The reconciler will automatically retry rollback during the next cycle (up to max retries).
  3. If persistent, verify adapter permissions and confirm whether host rule exists manually:
     ```powershell
     Get-NetFirewallRule -Name "SentinelAI-Rule-<id>"
     ```
  4. Trigger manual compensation via `POST /api/containment/rollback/<actionId>`.

### Incident D: Authentication Lifetime & Invalidation Clarification (Finding 2)
- **Symptom:** Client receives HTTP 401 `{"error": "Invalid or revoked session"}` or `{"error": "Invalid or expired token"}`.
- **Root Cause & Technical Definition:**
  1. **Access-Token Expiration (15 minutes):** Access tokens expire after exactly 900 seconds (`ACCESS_SECONDS = 900`). This is a short-lived token lifecycle. When an access token expires, the client frontend automatically invokes `POST /api/auth/refresh-token` to exchange its HTTP-only refresh cookie for a fresh access token.
  2. **Refresh-Token & Absolute Session Expiration (30 days):** Sessions are created with an absolute expiration date of 30 days (`REFRESH_SECONDS = 30 * 86400`). Rotation of the refresh token preserves the original `session.expiresAt` timestamp.
  3. **No Inactivity / Idle Timeout:** The current implementation **does not track or enforce a 15-minute inactivity timeout**. An idle user who returns after several hours will successfully refresh their access token as long as the 30-day refresh token has not been revoked or expired.
  4. **Revocation Triggers:**
     - Explicit user logout (`/api/auth/logout`)
     - Global logout across devices (`/api/auth/logout-all`, increments `authVersion`)
     - Mandatory password change (`/api/auth/update-password`, revokes existing sessions and increments `authVersion`)
     - Refresh-token replay detection (reuse of an old generation token revokes the session with `reason: 'refresh-replay'`)
     - Account deactivation (`user.status !== 'active'`)
- **Resolution:** If the session has been revoked or expired past its 30-day absolute limit, the user must authenticate via `POST /api/auth/login` to establish a new session.

---

## 6. Maintenance & Runbook Acceptance

This runbook has been verified against the live SentinelAI native Windows stack on 2026-10-15.
All procedures described herein are safe, non-destructive, and preserve development data.
