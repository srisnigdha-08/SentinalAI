# SentinelAI GATE-1 — Phase 3C: Source Call Chain and Backend Pipeline Audit

**Audit Date:** October 16, 2026  
**Auditor / Roles:** Principal ML-Security Engineer & Senior Backend Systems Auditor  
**Primary Directory:** `ai-engine/experiments/gate1_phase3c_backend_safety/`  
**Inspected Source Files:**
- `backend/services/aiEngineService.js` (Lines 1–144)
- `backend/services/threatService.js` (Lines 1–263)
- `backend/services/aiService.js` (Lines 1–282)
- `backend/models/ThreatLog.js` (Lines 1–99)
- `backend/models/AIPrediction.js` (Lines 1–59)
- `backend/models/Alert.js` (Lines 1–43)
- `backend/routes/aiEngine.js` (Lines 1–277)
- `backend/controllers/threatController.js` (Lines 1–309)
- `backend/websocket/socketManager.js` (Lines 1–210)
- `backend/utils/securityEventBus.js` (Lines 1–662)

**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Mode Only; Production Gated)

---

## 1. Executive Summary

This document presents the source-code-level verification of the SentinelAI backend call chain. Every finding in this audit has been traced directly to the active Node.js source files in `backend/` and classified as **Confirmed**, **Partially confirmed**, **Inferred**, or **Unverified** based on reproducible evidence.

### Verification of Specific Key Claims:
1. **`inferenceResult.action` is Ignored and Overwritten:** **CONFIRMED.** Line 58 of `backend/services/aiEngineService.js` recalculates `action` solely from `score` against hardcoded and fetched thresholds, discarding `result.action`.
2. **Axios Timeout Becomes `null` and Fails Open:** **CONFIRMED.** Lines 48–54 of `backend/services/aiEngineService.js` catch any Axios timeout, log a warning, return `null`, and cause `runFullPipeline()` to immediately return `null` with zero DB persistence and zero operator alert.
3. **`DEGRADED` Status is Demoted to `DETECTED`:** **CONFIRMED.** Line 101 of `backend/services/threatService.js` defaults status to `'DETECTED'` if `score < 0.70`, stripping the degraded state indicator.
4. **`ThreatLog` Schema Rejects `DEGRADED`:** **CONFIRMED.** Line 33 of `backend/models/ThreatLog.js` defines an enum whitelist omitting `'DEGRADED'`. Mongoose throws a runtime `ValidationError`.

---

## 2. End-to-End Trace of 10 Pipeline Outcomes

The table below summarizes the 10 failure and execution outcomes traced end-to-end through the backend architecture:

| Outcome # | Scenario Description | Originating Function & File | Returned Value / Thrown Error | Caller Behavior | Persisted DB Record | Operator Alert Emitted? | Can Be Confused with Benign/Allow? | Audit Finding Status |
|:---:|:---|:---|:---|:---|:---:|:---:|:---:|:---:|
| **1** | Valid BENIGN inference | `aiEngineService.runFullPipeline` (`aiEngineService.js:52`) | `{ predictedClass: 'BENIGN', threatScore: 0.02, action: 'ALLOW' }` | Returns 200 to caller | `AIPrediction` only | No alert (normal) | No (Correct Benign) | **CONFIRMED** |
| **2** | Valid attack with MONITOR | `aiEngineService.runFullPipeline` (`aiEngineService.js:52`) | `{ predictedClass: 'DDoS', threatScore: 0.85, action: 'MONITOR' }` | Returns 200 to caller | `AIPrediction` + `ThreatLog` (`MONITORING`) | Yes (`new_threat`, `new_alert`) | No | **CONFIRMED** |
| **3** | Valid attack with simulated BLOCK | `aiEngineService.runFullPipeline` (`aiEngineService.js:52`) | `{ predictedClass: 'DDoS', threatScore: 0.95, action: 'BLOCK' }` | Returns 200 to caller | `AIPrediction` + `ThreatLog` (`MONITORING` held) | Yes (`new_threat`, `new_alert`) | No (Simulated only) | **CONFIRMED** |
| **4** | Explicit degraded fallback | `aiEngineService.runFullPipeline` (`aiEngineService.js:52`) | `{ predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.50, action: 'ALLOW' }` | Returns 200 with ALLOW | `AIPrediction` only (ThreatLog suppressed) | **NO ALERT** (Silent) | **YES (Overwritten to ALLOW)** | **CONFIRMED** |
| **5** | Axios timeout ($>10\text{s}$) | `aiEngineService.predictRecord` (`aiEngineService.js:39`) | Returns `null` from `runFullPipeline` | Returns HTTP 503 or drops | **NONE** | **NO ALERT** (Silent) | **YES (Fails open)** | **CONFIRMED** |
| **6** | Connection refused (`ECONNREFUSED`) | `aiEngineService.predictRecord` (`aiEngineService.js:39`) | Returns `null` from `runFullPipeline` | Returns HTTP 503 or drops | **NONE** | **NO ALERT** (Silent) | **YES (Fails open)** | **CONFIRMED** |
| **7** | HTTP 500 error from AI engine | `aiEngineService.predictRecord` (`aiEngineService.js:39`) | Returns `null` from `runFullPipeline` | Returns HTTP 503 or drops | **NONE** | **NO ALERT** (Silent) | **YES (Fails open)** | **CONFIRMED** |
| **8** | Malformed / null threat score | `aiEngineService.runFullPipeline` (`aiEngineService.js:56`) | ThreatScore defaults to 0.0, action: `'ALLOW'` | Returns 200 with ALLOW | `AIPrediction` only | **NO ALERT** (Silent) | **YES (Defaults to ALLOW)** | **CONFIRMED** |
| **9** | DB persistence failure | `aiService.storePrediction` (`aiService.js:74`) | Rethrows `ValidationError` or `MongoError` | Rethrows to route handler (500) | Failed / Incomplete | **NO ALERT** | No (Fails closed on DB) | **CONFIRMED** |
| **10** | Notification delivery failure | `aiService.storePrediction` (`aiService.js:106`) | Caught in `catch (e)`, swallowed | Continues silently | `ThreatLog` saved | **NO ALERT** (Delivery lost) | Threat persisted, but unnotified | **CONFIRMED** |

---

## 3. Deep-Dive Code Evidence by Scenario

### Scenario 1: Valid BENIGN Inference
* **Source Location:** `backend/services/aiEngineService.js` (lines 52–95) and `backend/services/aiService.js` (lines 58–60).
* **Observed Mechanism:**  
  When Python returns `predictedClass: 'BENIGN'` and `threatScore: 0.02`:
  - `aiEngineService.js` line 58 calculates:
    `const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW';` ($0.02 < 0.70 \implies \text{'ALLOW'}$).
  - Line 72 calls `aiService.storePrediction(data)`.
  - In `aiService.js` line 59:
    `if (!data.generatedThreat && pred.threatScore >= 0.7 && pred.predictedClass !== 'BENIGN')`
    Since `pred.predictedClass === 'BENIGN'` and `threatScore < 0.7`, this evaluates to `false`.
  - No `ThreatLog` is created; no `Alert` is generated.
  - Line 139 broadcasts `socketManager.emitAIPrediction(pred)`.
* **Evidence:** Source inspection of `aiEngineService.js` lines 52–95 and `aiService.js` lines 58–60. **Status: Confirmed.**

---

### Scenario 2: Valid Attack with MONITOR Action
* **Source Location:** `backend/services/aiEngineService.js` (lines 52–95) and `backend/services/aiService.js` (lines 59–134).
* **Observed Mechanism:**  
  When Python returns `predictedClass: 'DDoS'` and `threatScore: 0.85`:
  - Line 58: $0.85 \ge 0.70 \implies \text{action: 'MONITOR'}$.
  - In `aiService.js`:
    - `AIPrediction.create(...)` creates prediction document.
    - Line 59 condition passes ($0.85 \ge 0.70$ and not BENIGN).
    - Line 60: $0.85 \ge 0.75 \implies \text{severity: 'HIGH'}$.
    - Line 71: `shouldBlock = 0.85 >= 0.92 && autoBlockEnabled` evaluates to `false`.
    - Line 72: `status = 'MONITORING'`.
    - Line 74: `ThreatLog.create(...)` stores document with `status: 'MONITORING'`.
    - Lines 110–115: `socketManager.emitNewThreat(threat)` is dispatched; `alertService.createAlertFromThreat(threat)` stores an Alert, and `socketManager.emitNewAlert(alert)` is emitted.
    - Line 122: triggers background `threatIntelService.enrichThreat(threat)`.
* **Evidence:** Source code analysis of `aiService.js` lines 59–134. **Status: Confirmed.**

---

### Scenario 3: Valid Attack with Simulated BLOCK Action
* **Source Location:** `backend/services/aiEngineService.js` (line 58) and `backend/services/aiService.js` (lines 68–95).
* **Observed Mechanism:**  
  When Python returns `threatScore: 0.95`:
  - Line 58: $0.95 \ge 0.92 \implies \text{action: 'BLOCK'}$.
  - In `aiService.js`:
    - Line 68 reads `SystemSetting.findOne({ key: 'autoBlockEnabled' })`. In this environment, `autoBlockEnabled === false`.
    - Line 71: `shouldBlock = (0.95 >= 0.92 && false) === false`.
    - Line 72: `const status = shouldBlock ? 'BLOCKED' : 'MONITORING'` $\implies$ `status: 'MONITORING'`.
    - Line 83: `autonomousAction: { taken: false }`.
    - Line 92: `if (shouldBlock)` is bypassed; no network firewall command is executed.
    - Returned object in `aiEngineService.js` line 94 has `action: 'BLOCK'`, but threat state in database is held safely at `'MONITORING'`.
* **Evidence:** Confirms simulated policy decision without actual network containment. **Status: Confirmed.**

---

### Scenario 4: Explicit Degraded Fallback from Python Service
* **Source Location:** `backend/services/aiEngineService.js` (lines 56–58) and `backend/services/aiService.js` (lines 58–60).
* **Observed Mechanism:**  
  When Python returns candidate fallback payload:
  ```json
  {
    "result": {
      "predictedClass": "UNINSPECTED_TRAFFIC",
      "threatScore": 0.50,
      "action": "MONITOR",
      "status": "DEGRADED"
    }
  }
  ```
  - In `aiEngineService.js`:
    - Line 56: `const score = result.threatScore || 0;` ($0.50$).
    - Line 58: `const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW';`
    - Because $0.50 < 0.70$, `action` becomes `'ALLOW'`.
    - The Python policy's explicit `action: 'MONITOR'` is **completely ignored**.
  - In `aiService.js`:
    - `AIPrediction.create(...)` records `threatScore: 0.50`.
    - Line 59: `pred.threatScore >= 0.7` evaluates to `false`.
    - Creation of `ThreatLog` is skipped!
    - Creation of `Alert` is skipped!
    - WebSocket alerts are skipped!
    - Only `socketManager.emitAIPrediction(pred)` is emitted.
  - Return to caller: `{ predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.50, action: 'ALLOW' }`.
* **Operational Impact:** High-risk uninspected traffic is marked as `ALLOW` and completely hidden from the SOC operator dashboard. **Status: Confirmed Defect.**

---

### Scenario 5: Axios Timeout ($>10,000\text{ ms}$)
* **Source Location:** `backend/services/aiEngineService.js` (lines 39–54).
* **Observed Mechanism:**  
  ```javascript
  const predictRecord = async (record) => {
    try {
      return (await ai.post('/predict/internal', record)).data
    } catch (e) {
      if (e.response?.status === 422) { ... }
      logger.warn('[AI] predict failed (' + e.name + ')')
      return null
    }
  }

  const runFullPipeline = async (record, io = null) => {
    const r = await predictRecord(record)
    if (!r?.result) return null  // <--- SILENT DROP
    ...
  ```
  - When an Axios timeout occurs, `e.name === 'AxiosError'`, with message `'timeout of 10000ms exceeded'`.
  - `predictRecord` logs a warning and returns `null`.
  - Line 54: `if (!r?.result) return null`.
  - `runFullPipeline` immediately terminates and returns `null`.
  - Zero database records are created (`AIPrediction`, `ThreatLog`, and `Alert` are never invoked).
  - Zero WebSocket events are dispatched.
  - In `backend/routes/aiEngine.js:124`, `if (!r) return sendError(res, 'AI failed', 503)`.
* **Operational Impact:** Fails completely open. Background traffic inspection engines receive `null` and let the traffic proceed without logging, monitoring, or containment. **Status: Confirmed Defect.**

---

### Scenario 6: Connection Refused (`ECONNREFUSED`)
* **Source Location:** `backend/services/aiEngineService.js` (lines 39–54).
* **Observed Mechanism:**  
  - If the Python AI engine is stopped or unreachable, Axios throws an error with `e.code === 'ECONNREFUSED'`.
  - Handled by the identical catch block as Scenario 5: logs warning and returns `null`.
  - `runFullPipeline()` returns `null` with zero records stored and zero alerts raised.
* **Operational Impact:** Identical fail-open behavior to Scenario 5. **Status: Confirmed Defect.**

---

### Scenario 7: HTTP Error Response from AI Engine (e.g. 500)
* **Source Location:** `backend/services/aiEngineService.js` (lines 42–50).
* **Observed Mechanism:**  
  - If Python throws an internal unhandled exception, FastAPI returns HTTP 500.
  - In `aiEngineService.js:43`:
    `if (e.response?.status === 422)` is `false` ($500 \ne 422$).
  - Falls into `logger.warn('[AI] predict failed (' + e.name + ')')` and returns `null`.
  - `runFullPipeline()` returns `null`.
* **Operational Impact:** Identical fail-open behavior. Only 422 errors are rethrown; 500/502/503 errors are silently masked as `null`. **Status: Confirmed Defect.**

---

### Scenario 8: Malformed or Null Threat Score
* **Source Location:** `backend/services/aiEngineService.js` (lines 56–58).
* **Observed Mechanism:**  
  ```javascript
  const score = result.threatScore || 0;
  const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW';
  ```
  - If `result.threatScore` is `null`, `undefined`, or `NaN`, `score` silently defaults to `0`.
  - Line 58 evaluates `0 >= 0.7`, which is `false`.
  - Action is assigned `'ALLOW'`.
  - `AIPrediction.create(...)` records `threatScore: 0`.
  - `aiService.js` line 59 bypasses `ThreatLog` creation.
* **Operational Impact:** A broken or corrupted prediction payload is silently granted access as `ALLOW`. **Status: Confirmed Defect.**

---

### Scenario 9: Database Validation or Persistence Failure
* **Subcase A: ThreatLog Rejection on `status: 'DEGRADED'`**
  - **Source Location:** `backend/models/ThreatLog.js` (lines 31–36).
  - Code:
    ```javascript
    status: {
      type: String,
      enum: ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'],
      default: 'DETECTED',
      index: true,
    }
    ```
  - If any service attempts to persist `status: 'DEGRADED'`, Mongoose throws:
    `ValidationError: ThreatLog validation failed: status: 'DEGRADED' is not a valid enum value for path 'status'.`
  - In `backend/services/threatService.js` line 20, `ALLOWED_STATUSES` also omits `'DEGRADED'`.
  - In `backend/controllers/threatController.js` line 50, `ALLOWED_THREAT_STATUSES` also omits `'DEGRADED'`.
  - **Operational Impact:** Any attempt to record degraded status crashes the ingestion pipeline. **Status: Confirmed Defect.**
* **Subcase B: Database Connection Failure**
  - **Source Location:** `backend/services/aiEngineService.js` (lines 88–91).
  - Code:
    ```javascript
    } catch (err) {
      logger.error('[AI Pipeline] Failed to persist prediction: ' + err.name)
      throw err
    }
    ```
  - When MongoDB is unreachable, `aiService.storePrediction` throws a `MongoNetworkError`.
  - `runFullPipeline` catches, logs, and rethrows the error to the route caller.
  - Express middleware catches and returns HTTP 500.
  - **Operational Impact:** Fails closed on database loss. **Status: Confirmed.**

---

### Scenario 10: Notification / WebSocket Delivery Failure
* **Source Location:** `backend/services/aiService.js` (lines 106–118).
* **Observed Mechanism:**  
  ```javascript
  try {
    const socketManager = require('../websocket/socketManager')
    const alertService = require('./alertService')
    socketManager.emitNewThreat(threat)
    if (['CRITICAL', 'HIGH'].includes(severity)) {
      const alert = await alertService.createAlertFromThreat(threat)
      socketManager.emitNewAlert(alert)
    }
  } catch (e) {
    logger.debug('[AI] Socket/Alert emission error: ' + e.message)
  }
  ```
  - If the WebSocket server or Alert document creation throws an exception, the entire catch block executes `logger.debug(...)`.
  - In standard production configurations where `LOG_LEVEL=info`, this error is completely suppressed.
  - The threat is written to `ThreatLog`, but no human operator or automated dashboard subscriber is notified.
* **Operational Impact:** Silent loss of operator visibility on communication bus failure. **Status: Confirmed Defect.**

---

## 4. Summary of Confirmed Defects & Architecture Gaps

1. **Defect D-01 (Action Overwrite):** `aiEngineService.js:58` ignores `inferenceResult.action`.
2. **Defect D-02 (Fail-Open Timeout Drop):** `aiEngineService.js:48-54` returns `null` on timeout/network failure without fallback record or alert.
3. **Defect D-03 (DEGRADED Status Demotion):** `threatService.js:101` demotes non-blocked sub-0.70 scores to `DETECTED`.
4. **Defect D-04 (ThreatLog Enum Incompatibility):** `ThreatLog.js:33` rejects `'DEGRADED'` with `ValidationError`.
5. **Defect D-05 (ThreatLog attackType Incompatibility):** `ThreatLog.js:9-28` enum rejects `'UNINSPECTED_TRAFFIC'`.
6. **Defect D-06 (Alert refModel Incompatibility):** `Alert.js:22` enum whitelist (`['ThreatLog', 'HoneypotSession', 'User']`) lacks `'AIPrediction'`.
7. **Defect D-07 (Silent Alert Emission Loss):** `aiService.js:117` swallows socket/alert errors in a debug-level log.
