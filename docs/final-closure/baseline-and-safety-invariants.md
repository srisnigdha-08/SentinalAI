# SentinelAI Final Closure: Baseline and Safety Invariants

**Capture Timestamp**: 2026-10-15 23:20:27 +05:30  
**Auditor**: Senior Application Security Engineer & Windows Platform Architect  
**Environment**: Windows 11 Native Development & Execution Environment  
**Status**: **FROZEN & VERIFIED**

---

## 1. Project Roots and Directory Layout

The environment consists of two co-located project trees on the local filesystem:

1. **Primary Application Root**:  
   `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
   Contains full application source code:
   - `backend/`: Node.js / Express REST API and Socket.IO real-time engine
   - `frontend/`: React / Vite single-page dashboard application
   - `ai-engine/`: Python / FastAPI / Scikit-Learn inference and evaluation pipeline
   - `docs/`: Technical specifications, architecture audits, runbooks, and closure documentation

2. **Native Windows Integration Root**:  
   `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration`  
   Contains integration assets and database data directories:
   - `mongodb-dev/data/`: Active development database storage backing port 27017
   - `mongodb-acceptance-20261014/data/`: **Protected Acceptance Database**. Strictly isolated; never used as an active development database or test fixture.

---

## 2. Process Liveness and Listening Ports

All four core services were verified active and operational without process churn or restarts:

| Service Name | Address / Port | Verified PID | Process Executable | Health / Status Endpoint |
| :--- | :--- | :--- | :--- | :--- |
| **MongoDB** | `127.0.0.1:27017` | **28468** | `mongod.exe` | Wire protocol connect: OK |
| **AI Engine** | `127.0.0.1:8000` | **35672** | `python.exe` (`uvicorn`) | `GET http://127.0.0.1:8000/ready` -> `{"status":"ok"}` (200) |
| **Backend API** | `127.0.0.1:5000` | **39136** | `node.exe` | `GET http://127.0.0.1:5000/health` -> `{"status":"ok",...}` (200) |
| **Frontend UI** | `127.0.0.1:3000` | **35704** | `vite.exe` (`node.exe`) | `GET http://127.0.0.1:3000/` -> HTML payload (200) |

---

## 3. Database State and Preservation (Port 27017)

The development database (`mongodb://127.0.0.1:27017/sentinel-db`) was queried in read-only mode. Document counts across all collections are:

| Collection Name | Document Count | Preservation Status |
| :--- | :--- | :--- |
| `users` | **1** | Preserved baseline admin user |
| `authsessions` | **2** | Preserved active sessions |
| `systemsettings` | **1** | Preserved system configuration |
| `aipredictions` | **0** | Clean baseline |
| `containmentactions` | **0** | Clean baseline |
| `threatlogs` | **0** | Clean baseline |
| `campaigns` | **0** | Clean baseline |
| `trainingsamples` | **0** | Clean baseline |
| `honeypotsessions` | **0** | Clean baseline |
| `alerts` | **0** | Clean baseline |
| `blockedips` | **0** | Clean baseline |

**Data Integrity Invariant**: The live database must experience zero unintended mutations during any verification or regression test. All integration testing must utilize disposable databases or mocks.

---

## 4. Protected AI Model Assets and Runtime Artifacts

All model files in `ai-engine/models/` and runtime files in `ai-engine/runtime/` were independently hashed via SHA-256:

| File Name | Location | Size (Bytes) | SHA-256 Checksum | Classification |
| :--- | :--- | :--- | :--- | :--- |
| `q_table.json` | `ai-engine/models/` | 2,338 | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **Frozen Reference Baseline** |
| `q_table.json` | `ai-engine/runtime/` | 1,224 | `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC` | **Active Mutable Runtime Artifact** |
| `rf_classifier_cicids_v2.pkl` | `ai-engine/models/` | 46,234,119 | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | Supervised Random Forest Classifier |
| `isolation_forest_cicids.pkl` | `ai-engine/models/` | 1,429,757 | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | Anomaly Isolation Forest Detector |
| `stacking_classifier_cicids.pkl` | `ai-engine/models/` | 44,037,489 | `B82FDD26DAD9C3341885F8F6F051C0BB0311E01E86072520D09B6634C281F0D4` | Stacking Ensemble Model |
| `xgb_classifier_cicids.pkl` | `ai-engine/models/` | 3,623,754 | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821ACD0531548BD125` | XGBoost Classifier Model |

**Baseline Safeguard**: The baseline Q-table (`models/q_table.json`) is cryptographically protected against runtime overwrites. Dynamic learning writes are redirected to `runtime/q_table.json` via `$env:Q_TABLE_PATH` and in-code path resolution safeguards.

---

## 5. Host Firewall Invariants

A host-level query via PowerShell `Get-NetFirewallRule -DisplayName 'SentinelAI*'` confirmed:
- **Active Rules**: **0**
- **Safety Gate Status**: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`
- **Adapter Factory Default**: `MockContainmentAdapter` active. Host network interfaces are 100% safeguarded from automated rule additions or blocking.

---

## 6. Host Storage and Disk Space

- **Volume C:**:
  - Used: **196.62 GB**
  - Free: **5.32 GB**
- **Safety Precaution**: With 5.32 GB remaining on the primary system volume, automated test runners and loggers must not generate unbounded large temporary files, uncompressed PCAP captures, or duplicate node_modules folders. Disposable databases must be strictly cleaned up immediately after test execution.

---

## 7. Environment Variables Inventory (Keys Only)

### Backend (`backend/.env`)
- `PORT`
- `NODE_ENV`
- `MONGO_URI`
- `JWT_SECRET`
- `JWT_EXPIRES_IN`
- `JWT_REFRESH_SECRET`
- `JWT_REFRESH_EXPIRES_IN`
- `CLIENT_URL`
- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_MAX`
- `HONEYPOT_API_KEY`
- `SENTINEL_KEY`
- `AI_ENGINE_URL`
- `LOG_LEVEL`

*(No secret values, tokens, or credentials revealed).*

---

## 8. Summary of Non-Negotiable Safety Invariants

1. Do not kill or restart PIDs `28468`, `35672`, `39136`, `35704`.
2. Do not write to `mongodb://127.0.0.1:27017/sentinel-db`.
3. Do not modify `ai-engine/models/q_table.json` (`BF9B...`).
4. Maintain `AUTONOMOUS_CONTAINMENT=false`.
5. Maintain `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`.
6. Disallow broad, unreviewed `npm update` operations.
7. Disallow access to disconnected storage archives (E: drive).
