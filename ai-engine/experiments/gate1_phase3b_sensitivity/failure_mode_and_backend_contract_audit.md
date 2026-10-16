# SentinelAI GATE-1 Phase 3B: Failure Mode, Degraded States, and Backend Contract Audit

**Audit Date:** October 16, 2026  
**Auditor / Roles:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Workspace Root:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Location:** [`ai-engine/experiments/gate1_phase3b_sensitivity/failure_mode_and_backend_contract_audit.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/failure_mode_and_backend_contract_audit.md)  
**Status:** **AUTHORITATIVE DOWNSTREAM CONTRACT AUDIT COMPLETE**

---

## 1. Executive Summary & Core Architectural Finding

In Phase 3A, the Python candidate policy implemented a fail-safe fallback design: when inference fails, times out, or encounters missing models, `CandidateSentinelPolicy.handle_inference_failure()` outputs:
```json
{
  "predictedClass": "UNINSPECTED_TRAFFIC",
  "threatScore": 0.50,
  "severity": "MEDIUM",
  "action": "MONITOR",
  "status": "DEGRADED",
  "failureType": "INFERENCE_TIMEOUT",
  "isFailSafe": true,
  "requiresHumanReview": true
}
```

However, a rigorous audit of the downstream Node.js backend source code reveals an **architectural contract mismatch**:
1. **Action Re-Computation Overwrite:** In [`backend/services/aiEngineService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/aiEngineService.js#L56-L58):
   ```javascript
   const score = result.threatScore || 0
   const blockThreshold = await getBlockThreshold()
   const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
   ```
   The backend **discards** Python's `result.action` (`MONITOR`) and recalculates `action` based purely on `score >= 0.7`. Because the fail-safe `threatScore` is `0.50` ($0.50 < 0.70$), **the backend silently demotes the degraded flow to `action = 'ALLOW'`**!
2. **Status Demotion in Threat Logging:** In [`backend/services/threatService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/threatService.js#L98-L103):
   ```javascript
   let status = 'DETECTED'
   if (shouldBlock) {
     status = 'BLOCKED'
   } else if (score >= 0.7) {
     status = 'MONITORING'
   }
   ```
   The backend **discards** Python's `status: "DEGRADED"` and assigns `status = 'DETECTED'`.
3. **Silent Fail-Open on Network Exception:** When axios experiences an HTTP timeout or connection drop in `predictRecord()`:
   ```javascript
   logger.warn('[AI] predict failed (' + e.name + ')')
   return null
   ```
   `runFullPipeline()` immediately returns `null`. **No prediction is stored, no ThreatLog is created, no socket alert is broadcast, and the traffic passes completely uninspected and unlogged (Fail-Open)**.

---

## 2. Granular Failure Mode Analysis

| Failure Scenario | Injected Condition | Python Candidate Output | Downstream Backend Behavior | Operational Consequence | Fail-Open / Fail-Closed Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **1. Missing Model Artifacts** | Pickles missing from disk | Returns `status: "DEGRADED"`, `action: "MONITOR"`, `threatScore: 0.50` | `aiEngineService.js` recomputes `action = "ALLOW"`, sets `status = "DETECTED"` | Uninspected traffic is marked as allowed; degraded alert is hidden from SOC operators | **Fail-Open (Vulnerable)** |
| **2. Inference Latency Timeout** | Python execution $> 5.0\text{s}$ or Axios timeout $> 10.0\text{s}$ | Handled by fallback `threatScore = 0.50`, `action = "MONITOR"` | If socket drops, backend returns `null`; HTTP `/ai/analyze` returns 503 | Traffic bypasses AI analysis entirely without database audit trail | **Fail-Open (Vulnerable)** |
| **3. Non-Finite Features (NaN / Inf)** | Input contains `float("nan")` or `float("inf")` | Returns `status: "INPUT_ERROR"`, `action: "ALLOW_AUDITED"`, `threatScore: 0.0` | Backend receives `threatScore: 0.0`, recomputes `action = "ALLOW"` | Malformed payloads pass through firewall; requires downstream WAF/input sanitization | **Fail-Open (Audited)** |
| **4. Empty / Unparseable Payload** | `{}` or malformed JSON | FastAPI returns HTTP 422 Unprocessable Entity | `predictRecord()` catches 422 and throws `'Invalid AI feature input'` | Backend returns HTTP 422 to caller; request safely rejected | **Fail-Closed (Safe)** |
| **5. Missing Anomaly Score** | Isolation Forest fails | Anomaly signal defaults to `0.0`; supervised detection preserved | Backend consumes supervised score | System operates in pure supervised mode without crashing | **Fail-Safe (Graceful)** |
| **6. Unknown Predicted Class** | Supervised model predicts unmapped integer | `LABEL_NAMES.get(cls, "BENIGN")` defaults to `"BENIGN"` | Backend logs `predictedClass = "BENIGN"` | Supervised misclassification risk; must default to `"Unknown"` | **Unsafe Fallback** |

---

## 3. Operational Risks of the Current Fallback Architecture

### A. The "Never Block" Invariant vs. Fail-Open Risk
In Phase 3A, the design asserted that the candidate policy must **never issue an automatic `BLOCK`** during service failure to prevent self-inflicted denial-of-service.

While this prevents self-inflicted outages, the backend's current handling converts this fallback into **full fail-open evasion**:
- An attacker launching a denial-of-service attack against the AI Engine (or sending algorithmic complexity payloads that trigger timeouts) will cause `ai.post()` to fail.
- Because `aiEngineService.js` catches the error and returns `null`, the network traffic passes through uninspected without incident creation.
- **Operational Reality:** An attacker can blind SentinelAI by overwhelming the inference worker.

### B. Mismatch Between Python `status` and Mongoose Schema
In [`backend/models/ThreatLog.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/models/ThreatLog.js), the valid enum values for `status` are:
```javascript
status: {
  type: String,
  enum: ['DETECTED', 'MONITORING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'BLOCKED'],
  default: 'DETECTED',
}
```
Notice that `'DEGRADED'` and `'INPUT_ERROR'` are **NOT valid enum values** in `ThreatLog.status`!
If the backend attempted to store `status: "DEGRADED"` directly into MongoDB, Mongoose schema validation would throw a `ValidationError`!

---

## 4. Required Production Integration Changes

Before the candidate policy can be promoted to production, the backend contract must be hardened:

1. **Honor Python Action and Status:**
   `aiEngineService.js` must be updated to respect the authoritative decision returned by the AI Engine rather than re-computing it:
   ```javascript
   const action = result.action || (score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW')
   ```
2. **Schema Hardening for Degraded Telemetry:**
   Update `ThreatLog.js` schema enum to include `'DEGRADED'` and `'SERVICE_FAILURE'`.
3. **Durable Dead-Letter / Degradation Queue:**
   When `predictRecord()` fails or times out, `runFullPipeline()` must not return `null` silently. It must dispatch a high-priority system alert to the SOC dashboard and log a degraded threat entry with `attackType = 'UNINSPECTED_TRAFFIC'` and `status = 'MONITORING'`.
4. **Input Sanitization Pre-Validation:**
   `utils/features.py` must validate all numeric fields against finite bounds prior to numpy array assembly.
