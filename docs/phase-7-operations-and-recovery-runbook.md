# SentinelAI Phase 7 — Operations & Disaster Recovery Runbook

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Auditor / Engineering Role:** Windows Platform & Reliability Engineer  
**Project:** SentinelAI Enterprise Platform  

---

## 1. Daily Operations & Service Lifecycle

### 1.1 Development Environment Service Launch
All services are bound to `127.0.0.1` and run under least-privilege user context:

```powershell
# 1. Start MongoDB (Port 27017)
& "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\binaries\mongod.exe" `
  --dbpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\data" `
  --port 27017 --bind_ip 127.0.0.1 `
  --logpath "C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\mongod.log"

# 2. Start AI Inference Engine (Port 8000)
cd "C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine"
$env:Q_TABLE_PATH = 'C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json'
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env

# 3. Start Backend API (Port 5000)
cd "C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend"
powershell -ExecutionPolicy Bypass -File "..\start-backend.ps1"

# 4. Start Frontend Vite Dev Server (Port 3000)
cd "C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend"
npm run dev -- --host 127.0.0.1
```

### 1.2 Graceful Shutdown Procedure
- **Interactive PowerShell Console:** Press `Ctrl+C` in the backend console.
  - The `GracefulShutdownManager` catches `SIGINT`.
  - Rejects incoming requests with HTTP 503 (`Connection: close`).
  - Drains in-flight requests within 5,000ms.
  - Closes WebSockets and disconnects MongoDB cleanly (exit 0).
- **Windows Service Mode (WinSW):**
  - When supervised by WinSW (`docs/templates/winsw-sentinelai-backend.xml`), stopping the service sends a `CTRL_C_EVENT` to Node.js, triggering the full graceful drain sequence before terminating.

---

## 2. Disaster Recovery & Backup Strategy

### 2.1 Component Recovery Hierarchy

```
+---------------------------------------------------------------------------------------------------------+
|                                    DISASTER RECOVERY ARCHITECTURE                                       |
+------------------------------+---------------------------+----------------------------------------------+
| Component                    | Backup Mechanism          | Restoration Verification Procedure           |
+------------------------------+---------------------------+----------------------------------------------+
| 1. Application Source Code   | Timestamped Folder/Git    | File comparison against historical archives  |
| 2. AI Model Checksums        | SHA-256 Verified Hashes   | `evaluate_model.py::verify_model_metadata()` |
| 3. MongoDB Database State    | Structured BSON/JSON Dump | Tested on Port 27029 with 100% integrity     |
| 4. Secrets & Configuration   | Offline Encrypted Storage | Compare keys against `.env.example`          |
| 5. Isolated VM Sandbox       | Hyper-V / VirtualBox Snap | Restore snapshot before each test harness run|
+------------------------------+---------------------------+----------------------------------------------+
```

### 2.2 Verified Database Backup & Restoration Procedure
This procedure was validated end-to-end on an isolated disposable MongoDB instance (`127.0.0.1:27029`):

#### Backup Procedure
```javascript
// Programmatic snapshot export of core collections
const backupSnapshot = {
  createdAt: new Date().toISOString(),
  database: 'sentinel-db',
  collections: {
    users: await db.collection('users').find({}).toArray(),
    systemsettings: await db.collection('systemsettings').find({}).toArray(),
    threatlogs: await db.collection('threatlogs').find({}).toArray(),
    containmentactions: await db.collection('containmentactions').find({}).toArray(),
  }
};
fs.writeFileSync('C:/Backups/sentinel_snapshot.json', JSON.stringify(backupSnapshot, null, 2), 'utf8');
```

#### Restoration Procedure
```javascript
const loaded = JSON.parse(fs.readFileSync('C:/Backups/sentinel_snapshot.json', 'utf8'));
for (const [colName, docs] of Object.entries(loaded.collections)) {
  if (docs.length > 0) {
    const formatted = docs.map(d => ({ ...d, _id: new mongoose.Types.ObjectId(d._id) }));
    await db.collection(colName).deleteMany({});
    await db.collection(colName).insertMany(formatted);
  }
}
```

---

## 3. Operational Troubleshooting Runbook

### 3.1 Troubleshooting Session Inactivity Timeouts
- **Symptom:** User reports being logged out after ~15 minutes of inactivity.
- **Root Cause:** Expected security behavior. The server records `lastUsedAt` on valid requests and revokes sessions exceeding `SESSION_INACTIVITY_TIMEOUT_SECONDS` (900s).
- **Diagnostics:**
  ```javascript
  const session = await AuthSession.findById(sessionId);
  console.log(`Last Active: ${session.lastUsedAt}, Revoked: ${session.revokedAt}, Reason: ${session.revocationReason}`);
  ```

### 3.2 Troubleshooting AI Engine Health
- **Symptom:** Backend `/api/system/health` reports `aiEngine.status: 'unreachable'`.
- **Diagnostics:**
  ```powershell
  # Check if port 8000 is listening
  Test-NetConnection -ComputerName 127.0.0.1 -Port 8000
  # Query health endpoint directly
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
  ```
- **Remediation:** Verify that `SENTINEL_KEY` in `backend/.env` matches the AI engine's environment.

### 3.3 Troubleshooting Containment Adapter State
- **Symptom:** Containment actions show `adapterName: 'MockContainmentAdapter'` instead of Windows Firewall.
- **Root Cause:** Safety gate `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` is active on developer host.
- **Verification:**
  ```powershell
  Get-NetFirewallRule -Name "SentinelAI*"
  # Must return 0 active rules on host workstation.
  ```
