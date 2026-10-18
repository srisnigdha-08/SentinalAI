# SENTINELAI — KNOWN LIMITATIONS & RISK REGISTER

**Verification Timestamp:** 2026-10-18T12:55:00+05:30  
**Phase:** Phase 2.2 — Demonstration-Path Verification  
**Auditor:** Senior Security & ML Verification Engineer  
**Repository:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  

---

## 1. Demonstration-Path Limitations

| Risk / Limitation | Component | Severity | Status | Description & Demonstration Impact |
| :--- | :--- | :--- | :--- | :--- |
| **LIM-01: Offline Database Dependency** | Backend (`backend/server.js`) | **HIGH (DEMO BLOCKER)** | `BLOCKED` | `backend/server.js` fails fast on startup (`process.exit(1)`) if MongoDB is not reachable on `127.0.0.1:27017`. For the live academic demonstration on Oct 20, MongoDB must be active before starting Node.js. |
| **LIM-02: Honeypot Ingestion Time Semantics** | Honeypot Collector (`session_collector.js`) | **MEDIUM** | `CONFIRMED` | `session.startTime` is created via `new Date()` upon receiving `SESSION_OPENED`. It reflects backend processing time, not the network layer event timestamp. |
| **LIM-03: Candidate Model Schema Incompatibility** | Multicorpus Candidate (`candidate_rf_multicorpus_v1.pkl`) | **HIGH** | `CONFIRMED` | This candidate model was trained on 51 features without `time_of_day_sin`/`cos`, and serialized under scikit-learn 1.7.2. Attempting to promote or pass 53-feature vectors causes an `IndexError` / crash. |
| **LIM-04: Legacy Candidate Time-Sensitivity** | Legacy Models (`rf_classifier_v2.1.pkl`, `xgb_classifier.pkl`) | **MEDIUM** | `CONFIRMED` | Legacy models have non-zero Gini importance on time features (~0.5%–1.4%). Prediction invariance does NOT generalize to them. |
| **LIM-05: Runtime Q-Table Incident State** | RL Engine (`runtime/q_table.json`) | **LOW (DEMO SAFE)** | `OWNER DECISION REQUIRED` | Hash `08209E99...` is an incident-state hash resulting from earlier readiness test execution. Dual-lock isolation prevents mutation, but restoring the pre-incident table requires project owner decision. |
| **LIM-06: Autonomous Containment Disabled** | Enforcement (`containmentService.js`) | **INFORMATIONAL** | `CONFIRMED` | Autonomous firewall blocking remains disabled (`AUTONOMOUS_CONTAINMENT=false`). Demands human-in-the-loop review for all containment actions. |

---

## 2. Academic Demonstration Preparedness Checklist

To successfully run the end-to-end demonstration on October 20, 2026:
1. **Start MongoDB First**: Ensure `mongod` is running on `127.0.0.1:27017`.
2. **Start AI Engine**:
   ```bash
   cd ai-engine
   source .venv/bin/activate  # or .venv\Scripts\activate on Windows
   export SENTINEL_KEY="<configured-key>"
   export AI_ENGINE_HOST="127.0.0.1"
   export AI_ENGINE_PORT="8000"
   uvicorn inference.main:app --host 127.0.0.1 --port 8000
   ```
3. **Start Backend**:
   ```bash
   cd backend
   npm start
   ```
4. **Start Frontend**:
   ```bash
   cd frontend
   npm run dev
   ```
5. **Model Selection**: Ensure `models/rf_classifier_cicids_v2.pkl` remains the loaded production model. Do not configure candidate models or Phase 8 multicorpus models.
