# SentinelAI GATE-1 Phase 3E: Failure-State Traceability Matrix & Contract Verification

**Auditor**: Independent Software Auditor & ML Security Engineer  
**Date**: 2026-10-16  
**Status**: **Partially Verified (12 of 13 Scenarios Verified; 1 Identified Limitation)**

---

## 1. Defect-to-Code Traceability (DEF-01 through DEF-07)

This section traces each reported defect through the actual committed code in `780619d`, its production call path, test coverage, and test harness characteristics.

### DEF-01: Silent Failure Collapse on Inference Failure
- **Original Defect**: `predictRecord` returned `null` on timeout or network error. `runFullPipeline` checked `if (!r?.result) return null`, causing upstream callers to treat uninspected flows as benign `ALLOW`.
- **Committed Fix**: In `backend/services/aiEngineService.js` (L63-L82), when `!r || !r.result`, sets `isDegraded = true` and `result = { predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.5, action: 'MONITOR', status: 'UNAVAILABLE' }`.
- **Production Call Path**: Packet Ingestion -> `aiEngineService.runFullPipeline(record)` -> `module.exports.predictRecord(record)` -> Fallback generation -> `aiService.storePrediction(payload)`.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Tests 5, 6, 7, 8) and `test_failure_state_contract_13cases.js` (Cases 4, 5, 6, 7).
- **Test Harness Type**: Test double on `predictRecord` returning `null`/error; exercises real `runFullPipeline` decision and fallback logic.
- **Audit Verdict**: **Verified**.

---

### DEF-02: Policy Action Overwrite Collapsing Explicit MONITOR into ALLOW
- **Original Defect**: `runFullPipeline` assigned `action = score >= blockThreshold ? 'BLOCK' : 'ALLOW'`. If `score < blockThreshold` ($0.90$), explicit `MONITOR` recommendations from the model were discarded and demoted to `ALLOW`.
- **Committed Fix**: In `backend/services/aiEngineService.js` (L88-L105), enacted Action Precedence Rule:
  ```javascript
  if (isDegraded || result.status === 'DEGRADED' || result.status === 'UNAVAILABLE' || result.predictedClass === 'UNINSPECTED_TRAFFIC') {
    action = 'MONITOR'
  } else if (result.action === 'MONITOR' || result.action === 'BLOCK') {
    action = result.action
  } else {
    action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  }
  ```
- **Production Call Path**: Network Flow -> `aiEngineService.runFullPipeline(record)` -> Action Precedence Evaluator -> `aiService.storePrediction(payload)`.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Tests 2, 4, 9) and `test_failure_state_contract_13cases.js` (Cases 2, 4).
- **Test Harness Type**: Real application logic; mocked external HTTP endpoint.
- **Audit Verdict**: **Verified**.

---

### DEF-03: ThreatLog Schema Enum Rejection of Degraded States
- **Original Defect**: `ThreatLogSchema` restricted `attackType` to standard attack types (omitting `UNINSPECTED_TRAFFIC`), and `status`/`preBlockStatus` omitted `DEGRADED`. Saving degraded records threw Mongoose `ValidationError`.
- **Committed Fix**: In `backend/models/ThreatLog.js` (L27, L34, L40), appended `'UNINSPECTED_TRAFFIC'` and `'DEGRADED'`.
- **Production Call Path**: `aiService.storePrediction` -> `ThreatLog.create({...})` -> MongoDB storage.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Test 10) and `test_schemas_and_compatibility.js` (Checks 1, 2, 3).
- **Test Harness Type**: Real Mongoose model with synchronous schema validation (`validateSync()`).
- **Audit Verdict**: **Verified**.

---

### DEF-04: Alert Schema sourceRef Missing 'AIPrediction' Reference
- **Original Defect**: `AlertSchema.sourceRef.refModel` only accepted `['ThreatLog', 'HoneypotSession', 'User']`. Direct alerts on AI prediction anomalies failed schema validation.
- **Committed Fix**: In `backend/models/Alert.js` (L22), appended `'AIPrediction'` to `enum`.
- **Production Call Path**: `alertService.createAlert({ sourceRef: { refModel: 'AIPrediction' } })` -> MongoDB storage.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Test 10) and `test_schemas_and_compatibility.js` (Checks 4, 5).
- **Test Harness Type**: Real Mongoose schema validation.
- **Audit Verdict**: **Verified**.

---

### DEF-05: Service & Controller Rejection of 'DEGRADED' Status
- **Original Defect**: `threatService.js` and `threatController.js` allowlists omitted `'DEGRADED'`. Queries or updates with `status: 'DEGRADED'` were stripped or failed validation.
- **Committed Fix**: In `backend/services/threatService.js` (L20, L99) and `backend/controllers/threatController.js` (L50), added `'DEGRADED'` to `ALLOWED_STATUSES` and preserved it in `createThreat()`.
- **Production Call Path**: REST API `/api/threats?status=DEGRADED` -> `threatController.getThreats` -> `threatService.findThreats`.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Test 16) and `test_schemas_and_compatibility.js` (Check 6).
- **Test Harness Type**: Real query parsing and filtering logic with mocked Mongoose find cursor.
- **Audit Verdict**: **Verified**.

---

### DEF-06: Threat Data Dropped on DB Persistence Failure
- **Original Defect**: If MongoDB was disconnected, `runFullPipeline` logged `Failed to persist prediction` but discarded the incident in memory with zero persistent trace.
- **Committed Fix**: In `backend/services/aiEngineService.js` (L141-L157), persistence catch block invokes `emergencyAudit.writeEmergencyAudit({...})` before rethrowing.
- **Production Call Path**: `runFullPipeline` -> `aiService.storePrediction` (throws) -> catch block -> `emergencyAudit.writeEmergencyAudit` -> `fsyncSync` to disk.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Tests 12, 13) and `test_failure_state_contract_13cases.js` (Cases 9, 10).
- **Test Harness Type**: Real filesystem I/O (`fs.openSync`, `fs.writeSync`, `fs.fsyncSync`, `fs.closeSync`) writing to local disk.
- **Audit Verdict**: **Verified with limitations** (see Section 3 for disk limitations).

---

### DEF-07: Socket & Notification Error Swallowing
- **Original Defect**: In `aiService.js`, WebSocket broadcasting errors were logged only as debug messages, and no system health alerts were raised for degraded states.
- **Committed Fix**: In `backend/services/aiService.js` (L114-L130), degraded states trigger `SYSTEM_HEALTH` alerts to `['admin', 'analyst']`, and socket catch block logs at `warn` level.
- **Production Call Path**: `storePrediction` -> `socketManager.emitNewThreat` / `alertService.createAlert`.
- **Exercising Tests**: `integrated_backend_safety_regression.test.js` (Test 14) and `test_failure_state_contract_13cases.js` (Cases 11, 12).
- **Test Harness Type**: Real error handling path with mocked socket/alert transports.
- **Audit Verdict**: **Verified**.

---

## 2. Independent Verification of the 13 Failure-State Contract Cases

All 13 scenarios specified in Phase 3E Section 4 were executed via `ai-engine/experiments/gate1_phase3e_independent_verification/test_failure_state_contract_13cases.js`.

| Case # | Scenario Description | Expected Outcome | Actual Observed Behavior | Verdict |
| :---: | :--- | :--- | :--- | :---: |
| **01** | Healthy benign inference | Action `ALLOW`, `predictedClass: 'BENIGN'` | `action: 'ALLOW'`, `predictedClass: 'BENIGN'`, no threat log | **Verified** |
| **02** | Healthy attack inference | Action `MONITOR`, `predictedClass: 'Port Scan'` | `action: 'MONITOR'`, `predictedClass: 'Port Scan'` | **Verified** |
| **03** | Healthy inference eligible for block | Action `BLOCK` in pipeline; no firewall change | `action: 'BLOCK'`, `autoBlockEnabled: false`, no firewall netsh call | **Verified** |
| **04** | AI request timeout | Fallback to `UNAVAILABLE` & `MONITOR` | `action: 'MONITOR'`, `status: 'UNAVAILABLE'`, `predictedClass: 'UNINSPECTED_TRAFFIC'`, `threatScore: 0.5` | **Verified** |
| **05** | `ECONNREFUSED` connection failure | Fallback to `UNAVAILABLE` & `MONITOR` | `action: 'MONITOR'`, `status: 'UNAVAILABLE'`, `predictedClass: 'UNINSPECTED_TRAFFIC'` | **Verified** |
| **06** | AI Engine HTTP 500 error | Fallback to `UNAVAILABLE` & `MONITOR` | `action: 'MONITOR'`, `status: 'UNAVAILABLE'`, `threatScore: 0.5` | **Verified** |
| **07** | Malformed response fields | Safely handled as degraded fallback | Missing `result` handled; falls back to `UNAVAILABLE` / `MONITOR` | **Verified** |
| **08** | Missing, non-finite, negative, out-of-range scores | Clamped to $[0, 1]$; neutral default | **Score clamping ($1.95 \to 1.0$, $-0.5 \to 0.0$, $\text{undefined} \to 0.0$) verified. BUT non-finite string `'invalid_nan'` evaluates to `NaN` and falls through to `ALLOW`** | **Partially Verified (Defect Identified)** |
| **09** | Database persistence failure | Emergency disk audit invoked; error propagated | `writeEmergencyAudit` called with threat metadata; error rethrown | **Verified** |
| **10** | Emergency audit write failure | Handled safely without unhandled exception | Catches `EACCES`/`ENOSPC`, logs error, returns `{ success: false }` | **Verified** |
| **11** | Alert creation failure | Logged as warning; transaction continues | Mongoose Alert failure caught; `storePrediction` completes | **Verified** |
| **12** | Socket notification failure | Logged as warning; transaction continues | WebSocket failure caught; logged with `[warn]`; completes | **Verified** |
| **13** | Duplicate processing / retry | State machine integrity and idempotency | Re-ingested flow retains `preBlockStatus: 'DEGRADED'` | **Verified** |

---

## 3. Detailed Audit Finding: Case 8 Non-Finite Score Flaw

### Root Cause Analysis
In `backend/services/aiEngineService.js` line 85:
```javascript
const score = Math.max(0, Math.min(1, Number(result.threatScore || 0)))
```

When an upstream Python microservice or corrupted payload sends `threatScore: 'invalid_nan'`:
1. `'invalid_nan' || 0` evaluates to `'invalid_nan'` (non-empty string is truthy in JavaScript).
2. `Number('invalid_nan')` evaluates to `NaN`.
3. `Math.min(1, NaN)` evaluates to `NaN`.
4. `Math.max(0, NaN)` evaluates to `NaN`.
5. Therefore, `score` evaluates to `NaN`.
6. When evaluating the action fallback:
   ```javascript
   action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
   ```
   Both `NaN >= blockThreshold` and `NaN >= 0.7` evaluate to `false`.
7. **The pipeline falls through to `action = 'ALLOW'`!**
8. The log output confirms:
   `[info] [AI Pipeline] 192.168.1.108 -> BENIGN (NaN%) -> ALLOW`

### Severity & Impact
- **Severity**: MEDIUM.
- **Impact**: If a compromised or malfunctioning inference engine returns non-numeric string scores on attack traffic, the flow is silently allowed rather than held in `MONITOR`.
- **Recommended Remediation (Future Phase)**:
  Use `Number.isFinite`:
  ```javascript
  const rawScore = Number(result.threatScore)
  const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(1, rawScore)) : 0.5
  ```
  *(In accordance with Phase 3E safety instructions, this fix is NOT applied in this phase).*
