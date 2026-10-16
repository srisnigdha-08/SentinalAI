# SentinelAI GATE-1 — Isolated Backend Contract and Failure Mode Tests

**Evaluation Date:** October 16, 2026  
**Auditor / Engineer:** Principal ML & Backend Security Engineering  
**Workspace Directory:** `ai-engine/experiments/gate1_phase3b_reconciliation/`  
**Execution Script:** `test_backend_contract_isolated.js`  
**Results Data:** `backend_failure_reproduction_results.json`  
**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Mode Only)

---

## 1. Executive Summary

During the Phase 3B audit, several critical architectural and contract failure modes were reported across the backend ingestion pipeline (`backend/services/aiEngineService.js`, `backend/services/threatService.js`, and `backend/models/ThreatLog.js`). Specifically, the reports identified that:
1. The backend overwrites Python AI engine actions using raw threat score comparisons, discarding fallback policy actions.
2. In degraded modes (e.g., model failure where Python yields `status: 'DEGRADED'`, `action: 'MONITOR'`, `threatScore: 0.50`), the backend demotes the action to `ALLOW` because $0.50 < 0.70$.
3. When network timeouts or connection drops occur in communicating with the AI Engine, `runFullPipeline()` silently catches the error and returns `null`, causing the packet ingestion engine to fail open with zero audit logging or operator alerting.
4. If a backend service attempts to persist `status: 'DEGRADED'`, the Mongoose `ThreatLog` schema throws a runtime `ValidationError` because `'DEGRADED'` is missing from its enum validation whitelist.

To independently verify these findings without touching active production files, restarting services, or writing to the live MongoDB database, an isolated contract test harness was implemented in `test_backend_contract_isolated.js`. 

All 10 test doubles executed successfully, reproducing and confirming **every single reported defect**.

---

## 2. Test Double Suite & Execution Matrix

The test suite executed 10 test cases modeling normal operation, boundary conditions, degraded fallback handling, network timeouts, schema validation, and persistence failures:

| Test # | Test Case Description | Injected State / Input | Observed Backend Response | Defect Reproduced? | Verdict |
|---|---|---|---|:---:|:---:|
| **TC-01** | Valid inference result with `action=MONITOR` | `threatScore=0.85`, `action=MONITOR` | Backend action: `MONITOR`, Threat status: `MONITORING` | No (Expected) | **PASS** |
| **TC-02** | Valid inference result with `action=BLOCK` | `threatScore=0.95`, `action=BLOCK` | Backend action: `BLOCK`, Gated status: `MONITORING`, Active status: `BLOCKED` | No (Expected) | **PASS** |
| **TC-03** | Model unavailable degraded fallback action overwrite | `threatScore=0.50`, `action=MONITOR`, `status=DEGRADED` | Backend action: `ALLOW`, Threat status: `DETECTED` | **YES** | **PASS (Defect Confirmed)** |
| **TC-04** | AI Engine HTTP timeout handling | Axios timeout `10000ms exceeded` | Pipeline returns `null` (zero logging, fail-open) | **YES** | **PASS (Defect Confirmed)** |
| **TC-05** | Null inference response handling | AI Engine returns `null` | Pipeline returns `null`, zero DB writes | No (Expected) | **PASS** |
| **TC-06** | Missing or malformed threat score | `threatScore=null` | Score defaulted to `0.0`, action: `ALLOW` | No (Expected) | **PASS** |
| **TC-07** | `DEGRADED` status demotion in `threatService.js` | `threatScore=0.50` | Threat status: `DETECTED` (`DEGRADED` erased) | **YES** | **PASS (Defect Confirmed)** |
| **TC-08** | Mongoose `ThreatLog` schema rejection on `status=DEGRADED` | `status='DEGRADED'` | `ValidationError: 'DEGRADED' is not a valid enum value` | **YES** | **PASS (Defect Confirmed)** |
| **TC-09** | Audit persistence failure propagation | Mock MongoDB throws `MongoNetworkError` | Error caught & re-thrown to caller | No (Expected) | **PASS** |
| **TC-10** | Verification that failure is never converted to `BENIGN` | `status=DEGRADED`, failure payload | `predictedClass='UNINSPECTED_TRAFFIC'`, score `0.50` | No (Expected) | **PASS** |

**Summary Result:** 10 / 10 Tests Passed. 4 / 4 Specific Backend Architectural Defects Replicated.

---

## 3. Deep-Dive Source Code Verification of Reproduced Defects

### Defect 1: Degraded Fallback Action Overwrite (TC-03)
* **Target File:** `backend/services/aiEngineService.js` (lines 56–59)
* **Active Code:**
  ```javascript
  const threatScore = Math.max(0, Math.min(1, Number(inferenceResult?.threatScore || 0)));
  const action = threatScore >= blockThreshold ? 'BLOCK'
    : threatScore >= 0.7 ? 'MONITOR'
    : 'ALLOW';
  ```
* **Observed Mechanism:**  
  When the candidate Python policy enters fallback mode (e.g., model corruption, feature vector mismatch), it explicitly returns:
  ```json
  {
    "action": "MONITOR",
    "threatScore": 0.50,
    "status": "DEGRADED",
    "predictedClass": "UNINSPECTED_TRAFFIC"
  }
  ```
  However, `aiEngineService.js` completely ignores `inferenceResult.action`. It recalculates `action` solely from `threatScore`. Because $0.50 < 0.70$, the backend assigns `action = 'ALLOW'`.
* **Operational Impact:**  
  A fail-safe defense action (`MONITOR`) designed by the ML safety engine is silently overridden and downgraded to `ALLOW` by the Node.js backend. Malicious traffic traversing an uninspected pipeline is permitted without surveillance.

---

### Defect 2: HTTP Timeout Fail-Open Evasion (TC-04)
* **Target File:** `backend/services/aiEngineService.js` (lines 48–55)
* **Active Code:**
  ```javascript
  async predictRecord(featureRecord) {
    try {
      const response = await this.client.post('/predict', featureRecord);
      return response.data;
    } catch (err) {
      this.logger.error(`AI Engine prediction failed: ${err.message}`);
      return null;
    }
  }

  async runFullPipeline(flowData, options = {}) {
    try {
      const inferenceResult = await this.predictRecord(flowData);
      if (!inferenceResult) {
        return null; // <--- SILENT DROP
      }
      // ...
  ```
* **Observed Mechanism:**  
  When an HTTP call to the AI Engine times out (default timeout: 10,000 ms) or encounters network congestion, `predictRecord()` catches the error, logs it to console, and returns `null`. `runFullPipeline()` immediately executes `if (!inferenceResult) return null;`.
* **Operational Impact:**  
  No `ThreatLog` record is generated, no security alert is raised in WebSockets or UI, and no policy action is returned to the packet processor. The packet capture loop continues processing without restriction. An attacker generating volumetric traffic that saturates the Python service causes the backend to fail completely open, bypassing all inspection.

---

### Defect 3: DEGRADED Status Demotion in `threatService.js` (TC-07)
* **Target File:** `backend/services/threatService.js` (lines 98–103)
* **Active Code:**
  ```javascript
  status: (threatScore >= 0.9 && action === 'BLOCK')
    ? (autoBlockEnabled ? 'BLOCKED' : 'MONITORING')
    : threatScore >= 0.7
      ? 'MONITORING'
      : 'DETECTED'
  ```
* **Observed Mechanism:**  
  Even if the AI Engine's payload reached `threatService.js`, the status assignment is hardcoded based on `threatScore >= 0.7`. A degraded payload with score `0.50` is assigned `status: 'DETECTED'`, stripping any indicator of service failure. The SOC analyst viewing the dashboard sees a low-level detected event rather than a critical system degradation.

---

### Defect 4: Mongoose `ThreatLog` Schema Rejection (TC-08)
* **Target File:** `backend/models/ThreatLog.js` (line 15)
* **Active Code:**
  ```javascript
  status: {
    type: String,
    enum: ['DETECTED', 'MONITORING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'BLOCKED'],
    default: 'DETECTED',
    index: true,
  },
  ```
* **Observed Mechanism:**  
  If a developer attempts to fix Defect 3 by passing `status: 'DEGRADED'` to `ThreatLog.create()`, Mongoose rejects the document with:
  ```
  ValidationError: ThreatLog validation failed: status: `DEGRADED` is not a valid enum value for path `status`.
  ```
* **Operational Impact:**  
  The write operation throws an unhandled rejection, aborting the transaction and preventing the threat record from being stored.

---

## 4. Evaluation: Fail-Safe vs. Fail-Open Architecture

| Dimension | Active SentinelAI Production Behavior | Required Security Standard |
|---|---|---|
| **AI Engine Timeout** | **Fail-Open:** Returns `null`, traffic allowed without logging or mitigation | **Fail-Safe / Controlled Degraded:** Log error event, generate system alert, default to `MONITOR` or quarantine |
| **Model Service Error** | **Fail-Open:** Overrides `MONITOR` with `ALLOW` ($S=0.50 < 0.70$) | **Fail-Safe:** Respect policy fallback action (`MONITOR`), trigger operator alert |
| **Telemetry / Auditing** | **Blind Spot:** No `ThreatLog` or `AuditLog` entry created on inference timeout | **Auditable:** Mandatory `SystemLog`/`AuditLog` write on every inference exception |
| **Schema Compatibility** | **Broken:** Schema rejects `'DEGRADED'` status string | **Cohesive:** Schema enum whitelists `'DEGRADED'` and `'UNINSPECTED'` |

---

## 5. Required Code Remediation Blueprint (For Future Promotion)

When GATE-1 remediation is promoted to production in a future authorized maintenance window, the following specific code edits are required:

### 1. `backend/models/ThreatLog.js`
Update the status enum to include degraded and uninspected states:
```javascript
status: {
  type: String,
  enum: [
    'DETECTED',
    'MONITORING',
    'CONTAINED',
    'RESOLVED',
    'FALSE_POSITIVE',
    'BLOCKED',
    'DEGRADED',
    'UNINSPECTED'
  ],
  default: 'DETECTED',
  index: true,
},
```

### 2. `backend/services/aiEngineService.js`
Preserve policy actions from the AI engine and implement a safe fallback on timeout:
```javascript
// In predictRecord:
async predictRecord(featureRecord) {
  try {
    const response = await this.client.post('/predict', featureRecord);
    return response.data;
  } catch (err) {
    this.logger.error(`AI Engine prediction failed: ${err.message}`);
    return {
      threatScore: 0.50,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      action: 'MONITOR',
      status: 'DEGRADED',
      error: err.message
    };
  }
}

// In runFullPipeline:
// Respect inferenceResult.action rather than strictly recomputing:
const threatScore = Math.max(0, Math.min(1, Number(inferenceResult?.threatScore || 0)));
const action = inferenceResult?.action || (
  threatScore >= blockThreshold ? 'BLOCK'
  : threatScore >= 0.7 ? 'MONITOR'
  : 'ALLOW'
);
```

### 3. `backend/services/threatService.js`
Honor the `DEGRADED` status when persisting threats:
```javascript
const threatStatus = inferenceResult?.status === 'DEGRADED'
  ? 'DEGRADED'
  : (threatScore >= 0.9 && action === 'BLOCK')
    ? (autoBlockEnabled ? 'BLOCKED' : 'MONITORING')
    : threatScore >= 0.7
      ? 'MONITORING'
      : 'DETECTED';
```

---

## 6. Conclusion

The contract verification harness has rigorously proven that:
1. The AI engine candidate's degraded fallback design is theoretically correct ($S=0.50$, `MONITOR`, `UNINSPECTED_TRAFFIC`).
2. The current active backend pipeline cannot safely consume degraded responses due to action overwrite, status demotion, schema enum restrictions, and timeout fail-open drops.
3. Therefore, candidate policy promotion cannot proceed until these backend defects are simultaneously remediated and verified under comprehensive integration testing.
4. **GATE-1 remains OPEN.**
