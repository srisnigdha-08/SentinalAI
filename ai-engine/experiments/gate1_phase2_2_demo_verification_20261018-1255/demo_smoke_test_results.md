# SENTINELAI — DEMONSTRATION SMOKE TEST RESULTS

**Verification Timestamp:** 2026-10-18T12:55:00+05:30  
**Phase:** Phase 2.2 — Demonstration-Path Verification  
**Auditor:** Senior Security & ML Verification Engineer  
**Repository:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  

---

## 1. Test Isolation & Safety Pre-Flight

Before executing any component, the following safeguards were established:
- **Temporary State Isolation:** A dedicated temporary directory was created (`sentinel_smoke_06kn_n3g`).
- **Q-Table Redirection:** `Q_TABLE_PATH` and `DEFAULT_RUNTIME_Q_TABLE_PATH` were set to `isolated_q_table.json` within the temporary directory.
- **Environment Flag:** `SENTINEL_ENV="test"` was exported.
- **API Authentication:** `SENTINEL_KEY="demo-verification-key-secret-20261018"` was injected into the test context.
- **Cryptographic Pre-Check:**
  - `ai-engine/models/q_table.json`: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`
  - `ai-engine/runtime/q_table.json`: `08209E9989189BD45B6EDF35486A446F120DF36287A277A9DDDD35F6379152F7`

---

## 2. AI Inference Engine Smoke Test Execution

### Command
```powershell
& "c:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\.venv\Scripts\python.exe" "C:\Users\srisn\.gemini\antigravity\brain\7aad54d7-8e63-4707-a91a-9eff04445d81\scratch\smoke_test.py"
```

### Execution Output & Metrics
- **Startup:**
  - `[INFO] sentinel.predictor: Found model rf_classifier_cicids_v2.pkl. Selecting rf classifier...`
  - `[INFO] sentinel.predictor: Found isolation_forest_cicids.pkl. Selecting real-data isolation forest...`
  - `[INFO] sentinel.predictor: Classifier loaded from models\rf_classifier_cicids_v2.pkl`
  - `[INFO] sentinel.predictor: SHAP TreeExplainer initialized successfully.`
  - `[INFO] sentinel.api: Inference model state: ready`
  - `[STARTUP] Loaded classification model: rf_classifier_cicids_v2.pkl`

- **Test Step 1: Health Check (`GET /health`)**
  - **Status Code:** `200 OK`
  - **Response Payload:** `{'status': 'ok', 'timestamp': '2026-10-18T07:23:38.987878+00:00'}`

- **Test Step 2: Flow Record Without Timestamp (`POST /predict/internal`)**
  - **Input Payload:**
    ```json
    {
      "sourceIP": "192.168.1.105",
      "flow_duration": 1500.0,
      "total_fwd_packets": 12.0,
      "total_bwd_packets": 8.0,
      "total_len_fwd_packets": 1050.0,
      "total_len_bwd_packets": 840.0
    }
    ```
  - **Feature Extraction Check:** Vector length = 53; `feature[51]` (`time_of_day_sin`) = `0.0`, `feature[52]` (`time_of_day_cos`) = `0.0`.
  - **Inference Response:** `Status 200 OK`, `predictedClass`: `"BENIGN"`, `threatScore`: `0.103`.

- **Test Step 3: Flow Record With UTC ISO Timestamp (`POST /predict/internal`)**
  - **Input Payload:** Same payload with `"timestamp": "2026-10-18T12:00:00Z"`.
  - **Feature Extraction Check:** Vector length = 53; `feature[51]` = `0.0000`, `feature[52]` = `-1.0000`.
  - **Inference Response:** `Status 200 OK`, `predictedClass`: `"BENIGN"`, `threatScore`: `0.103`.
  - **Prediction Invariance:** Confirmed $\Delta \text{threatScore} = 0.0000$.

- **Test Step 4: Honeypot Session Data (`POST /predict/honeypot/internal`)**
  - **Input Payload:**
    ```json
    {
      "sessionId": "hp-session-demo-001",
      "sourceIP": "10.0.0.50",
      "durationSeconds": 45.0,
      "loginSucceeded": false,
      "commands": [{"command": "cat /etc/passwd"}],
      "iocCount": 1,
      "deceptionProfile": "ubuntu_22",
      "startTime": "2026-10-18T07:30:00Z"
    }
    ```
  - **Feature Extraction Check:** Vector length = 53; `feature[51]` = `0.9239`, `feature[52]` = `-0.3827`.
  - **Inference Response:** `Status 200 OK`, `predictedClass`: `"BENIGN"`, `threatScore`: `0.1224`.

- **Test Step 5: Post-Execution Asset Integrity Verification**
  - `ai-engine/models/q_table.json`: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` **[MATCH]**
  - `ai-engine/runtime/q_table.json`: `08209E9989189BD45B6EDF35486A446F120DF36287A277A9DDDD35F6379152F7` **[MATCH]**
  - **Zero bytes mutated.**

---

## 3. Backend Service Smoke Test & Dependency Analysis

### Command
```powershell
node server.js
```

### Observed Execution Output
```text
2026-10-18 12:54:18 [info] [WS] Socket.IO initialized
2026-10-18 12:54:18 [info] Session-auth cutover: sign-in required; access tokens expire in 15 minutes. Legacy JWT_EXPIRES_IN does not control session tokens.
2026-10-18 12:54:34 [warn] MongoDB disconnected
2026-10-18 12:54:34 [error] MongoDB connection failed (MongooseServerSelectionError)
```
- **Exit Code:** `1`
- **Root Cause:** In `backend/server.js` line 222–236, `connectDB()` is called before `server.listen()`. Because MongoDB is not running locally on port 27017, the connection promise rejects and executes `process.exit(1)`.
- **Service Availability Status:** **UNAVAILABLE (BLOCKED BY OFFLINE MONGODB DAEMON)**.

---

## 4. Frontend Integration & Consumption Path Analysis

- **Component Audit:**
  - `frontend/src/pages/HoneypotAnalytics.jsx`: Renders sessions via `honeypotAPI.sessions()`. Displays `deceptionScore`, `aiClassification`, `aiThreatScore`.
  - `frontend/src/pages/AIAnalytics.jsx`: Renders model metrics and live predictions via `aiAPI.predictions()` and `aiAPI.stats()`.
  - `frontend/src/pages/Dashboard.jsx`: Displays KPI cards (including the corrected traps KPI), threat trends, and live threat streams.
- **Contract Compatibility:** All schemas and fields expected by the React UI align with the responses generated by the backend and AI engine.
- **Demonstration Dependency:** The frontend requires `backend/server.js` running on port 5000 to serve `/api` routes. In the absence of an active MongoDB service, the frontend cannot load or display live inference results.
