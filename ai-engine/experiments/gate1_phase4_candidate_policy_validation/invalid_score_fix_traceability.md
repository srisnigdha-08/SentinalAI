# SentinelAI GATE-1 Phase 4: Invalid-Score Fail-Open Defect Fix Traceability

**Component**: `backend/services/aiEngineService.js`  
**Defect Classification**: CRITICAL Security Logic Defect (Fail-Open Bypass)  
**Remediation Branch**: `feature/gate1-phase4-candidate-policy` (commit `e9f71a0`)  
**Auditor / Engineer**: Senior ML Security Engineer & Backend Security Auditor  
**Status**: **Verified**

---

## 1. Defect Diagnosis and Root-Cause Analysis

During the Phase 3E independent verification audit, an evaluation flaw was uncovered in `backend/services/aiEngineService.js` line 85:

```javascript
const score = Math.max(0, Math.min(1, Number(result.threatScore || 0)))
```

### The Failure Path:
1. When an upstream model response contained a non-numeric string (e.g. `'invalid_nan'`, `'corrupt'`) or literal `NaN`:
   - `result.threatScore || 0` evaluated to the string itself (because non-empty strings are truthy).
   - `Number('invalid_nan')` produced `NaN`.
   - `Math.min(1, NaN)` produced `NaN`.
   - `Math.max(0, NaN)` produced `NaN`.
2. Consequently, `score` evaluated to `NaN`.
3. Downstream action resolution evaluated:
   ```javascript
   let action = 'ALLOW'
   if (isDegraded || result.status === 'DEGRADED' || ...) {
     action = 'MONITOR'
   } else if (result.action === 'MONITOR' || result.action === 'BLOCK') {
     action = result.action
   } else {
     action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
   }
   ```
4. If the inference response had `status: 'HEALTHY'` and no explicit action set, the threshold checks `NaN >= blockThreshold` and `NaN >= 0.7` both evaluated to `false`.
5. **The pipeline fell through to `action = 'ALLOW'`!**
6. An uninspected, corrupted, or adversarial attack packet was thus silently permitted through the gateway as benign traffic.

---

## 2. Implemented Remediation

The raw inference score is now strictly validated *prior* to clamping. Any score that is not a finite number in $[0.0, 1.0]$ is explicitly rejected as an invalid inference response, setting `isDegraded = true` and invoking the safe degraded state:

```javascript
// backend/services/aiEngineService.js L85-L115:

  // Validate raw threatScore before clamping (Reject non-finite / out-of-range scores)
  let score = 0.5
  if (!isDegraded) {
    const rawScore =
      result.threatScore !== undefined && result.threatScore !== null && result.threatScore !== ''
        ? Number(result.threatScore)
        : NaN

    if (!Number.isFinite(rawScore) || rawScore < 0 || rawScore > 1) {
      logger.warn(
        `[AI Pipeline] Invalid threatScore received (${result.threatScore}). Rejecting inference as invalid and falling back to degraded state.`
      )
      isDegraded = true
      result = {
        predictedClass: 'UNINSPECTED_TRAFFIC',
        threatScore: 0.5,
        action: 'MONITOR',
        status: 'DEGRADED',
        isAnomaly: false,
        anomalyScore: 0,
        classProbabilities: { UNINSPECTED_TRAFFIC: 1.0 },
        modelVersion: result.modelVersion || 'v2.1-fallback',
        featureSchemaVersion: result.featureSchemaVersion || 'v2.1_53feat',
        inferenceTimeMs: result.inferenceTimeMs || 0,
        notes: `Invalid inference threatScore: ${result.threatScore}`,
      }
      score = 0.5
    } else {
      score = rawScore
    }
  }
```

### Safety Guarantees of the Patch:
1. **Never Fails Open**: Any corrupted, missing, or out-of-range score forces `isDegraded = true`, which the Action Precedence Rule maps strictly to `action = 'MONITOR'`.
2. **Neutral Threat Score**: The score is safely anchored to neutral $0.50$ (not $0.0$).
3. **Forensic Traceability**: Sets `predictedClass: 'UNINSPECTED_TRAFFIC'` and `status: 'DEGRADED'`, creating a persistent ThreatLog and emitting an alert.
4. **Valid Boundary Preservation**: Valid scores ($0.0$, $1.0$, $0.85$, and valid numeric strings like `'0.85'`) are parsed cleanly without alteration.

---

## 3. Regression Test Verification Matrix

The regression test suite (`backend/tests/integrated_backend_safety_regression.test.js`) was expanded in Test 9 to exercise all edge cases directly:

| Test Scenario | Input `result.threatScore` | Expected Status | Expected Action | Expected Stored Score | Test Result |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Out-of-range (> 1)** | `1.5` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Out-of-range (< 0)** | `-0.5` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Literal `NaN`** | `NaN` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Positive Infinity** | `Infinity` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Negative Infinity** | `-Infinity` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Non-numeric string** | `'invalid_nan'` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Missing (`undefined`)** | `undefined` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Null value** | `null` | `DEGRADED` | `MONITOR` | `0.5` | **PASS** |
| **Valid numeric string** | `'0.85'` | `HEALTHY` | `MONITOR` | `0.85` | **PASS** |
| **Valid boundary: 0** | `0` | `HEALTHY` | `ALLOW` | `0.0` | **PASS** |
| **Valid boundary: 1** | `1` | `HEALTHY` | `BLOCK` | `1.0` | **PASS** |

Execution confirmed via Jest: **17 passed, 17 total (0 failed)**.
