# SentinelAI GATE-1 Phase 3D: Source-to-Fix Traceability Matrix

## 1. Overview

This document provides complete, line-by-line traceability between the 7 confirmed backend security defects identified during the Phase 3C investigation (`ai-engine/experiments/gate1_phase3c_backend_safety/`) and the precise code modifications implemented in the Phase 3D safety patch (`feature/gate1-phase3d-backend-safety`).

All changes were implemented under strict safety constraints:
- Autonomous containment remains disabled (`AUTONOMOUS_CONTAINMENT=false`).
- Real Windows Firewall enforcement remains disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`).
- Zero changes to protected model binaries or Q-tables.
- Zero modifications to live MongoDB databases.

---

## 2. Traceability Matrix

| Defect ID | Severity | Target File(s) | Function / Scope | Lines Changed | Verifying Regression Tests | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **DEF-01** | CRITICAL | `backend/services/aiEngineService.js` | `predictRecord()`, `buildFallbackResponse()` | L67-L121 | Test 5, Test 6, Test 7, Test 8 | **RESOLVED** |
| **DEF-02** | HIGH | `backend/services/aiEngineService.js` | `runFullPipeline()` | L147-L188 | Test 2, Test 4, Test 9 | **RESOLVED** |
| **DEF-03** | HIGH | `backend/models/ThreatLog.js` | `ThreatLogSchema` | L18, L28, L46 | Test 10, Test 15 | **RESOLVED** |
| **DEF-04** | MEDIUM | `backend/models/Alert.js` | `AlertSchema.sourceRef` | L36 | Test 10 | **RESOLVED** |
| **DEF-05** | HIGH | `backend/services/threatService.js`, `backend/controllers/threatController.js` | `ALLOWED_STATUSES`, `createThreat()`, `ALLOWED_THREAT_STATUSES` | `threatService.js`: L23, L48; `threatController.js`: L14 | Test 10, Test 16 | **RESOLVED** |
| **DEF-06** | HIGH | `backend/services/aiEngineService.js`, `backend/utils/emergencyAudit.js` | `runFullPipeline()`, `writeEmergencyAudit()` | `aiEngineService.js`: L216-L233; `emergencyAudit.js`: L1-L122 | Test 12, Test 13 | **RESOLVED** |
| **DEF-07** | MEDIUM | `backend/services/aiService.js` | `recordPrediction()`, `handlePrediction()` | L121-L146, L184-L200 | Test 14 | **RESOLVED** |

---

## 3. Detailed Defect-to-Fix Analysis

### Defect DEF-01: Silent Failure Collapse on AI Engine Unreachability / Timeout

- **Root Cause**: `aiEngineService.js` previously caught axios network errors, timeouts, and non-200 HTTP responses, logged them as errors, and returned `null`. Upstream callers (`runFullPipeline` and `aiService.js`) treated `null` predictions as uninspectable, frequently allowing uninspected network packets through as if they were safe `ALLOW` traffic with zero operator alerting.
- **File**: `backend/services/aiEngineService.js`
- **Lines**: L67-L121
- **Code Diff**:
```javascript
// BEFORE:
} catch (error) {
    logger.error(`[AI Engine] Prediction failed: ${error.message}`);
    return null;
}

// AFTER:
} catch (error) {
    const errorType = error.code === 'ECONNREFUSED' ? 'ECONNREFUSED'
        : error.code === 'ETIMEDOUT' || error.message.includes('timeout') ? 'TIMEOUT'
        : error.response ? `HTTP_${error.response.status}`
        : 'INFERENCE_ERROR';
    logger.warn(`[AI Engine] Prediction failed (${errorType}): ${error.message}. Returning safe degraded fallback.`);
    return buildFallbackResponse(errorType, error.message);
}
```
- **Verification**: Tests 5, 6, 7, and 8 verify that `TIMEOUT`, `ECONNREFUSED`, `HTTP_500`, and malformed payloads return an explicit degraded payload with `status: 'UNAVAILABLE'`, `action: 'MONITOR'`, `predictedClass: 'UNINSPECTED_TRAFFIC'`, and `threatScore: 0.50`.

---

### Defect DEF-02: Policy Action Overwrite Collapsing Explicit MONITOR into ALLOW

- **Root Cause**: `runFullPipeline()` previously computed `isThreat = (prediction.threatScore || 0) >= blockThreshold`. If `threatScore < blockThreshold` (default `0.90`), it unconditionally assigned `action = 'ALLOW'`. This eradicated explicit `MONITOR` actions returned by the AI engine (e.g. scores between 0.35 and 0.89, or degraded state `0.50`), causing genuine attack signals and degraded traffic to be silently categorized as allowed benign traffic.
- **File**: `backend/services/aiEngineService.js`
- **Lines**: L147-L188
- **Code Diff**:
```javascript
// BEFORE:
const isThreat = (prediction.threatScore || 0) >= blockThreshold;
const action = isThreat ? 'BLOCK' : 'ALLOW';

// AFTER:
// Action Precedence Rule:
// 1. If prediction explicitly requests BLOCK, action is BLOCK (subject to autonomous containment config).
// 2. If threatScore >= blockThreshold, escalate to BLOCK.
// 3. If prediction explicitly requests MONITOR (or degraded), preserve MONITOR (DO NOT demote to ALLOW).
// 4. Otherwise, if threatScore >= monitorThreshold, action is MONITOR.
// 5. Only if threatScore < monitorThreshold and no explicit threat action is set, action is ALLOW.
let action = 'ALLOW';
if (prediction.action === 'BLOCK' || threatScore >= blockThreshold) {
    action = 'BLOCK';
} else if (prediction.action === 'MONITOR' || threatScore >= monitorThreshold) {
    action = 'MONITOR';
} else {
    action = 'ALLOW';
}
```
- **Verification**: Tests 2, 4, and 9 verify that explicit attack predictions (e.g. score 0.85) and degraded predictions (score 0.50) remain strictly `MONITOR`, preventing silent demotion to `ALLOW`.

---

### Defect DEF-03: ThreatLog Schema Enum Rejection of Degraded States

- **Root Cause**: `ThreatLogSchema` restricted `attackType` to a strict list that omitted `UNINSPECTED_TRAFFIC`, and restricted `status` and `preBlockStatus` to `['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']`. Any attempt to persist a degraded threat log failed schema validation, causing uninspected traffic audit trails to be dropped.
- **File**: `backend/models/ThreatLog.js`
- **Lines**: L18, L28, L46
- **Code Diff**:
```javascript
// BEFORE:
attackType: {
    type: String,
    required: true,
    enum: ['DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Botnet', 'Infiltration', 'Unknown', 'Anomaly']
},
status: {
    type: String,
    enum: ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'],
    default: 'ACTIVE'
},
preBlockStatus: {
    type: String,
    enum: ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'],
    default: null
}

// AFTER:
attackType: {
    type: String,
    required: true,
    enum: ['DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Botnet', 'Infiltration', 'Unknown', 'Anomaly', 'UNINSPECTED_TRAFFIC']
},
status: {
    type: String,
    enum: ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED'],
    default: 'ACTIVE'
},
preBlockStatus: {
    type: String,
    enum: ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED'],
    default: null
}
```
- **Verification**: Tests 10 and 15 verify that records with `attackType: 'UNINSPECTED_TRAFFIC'` and `status: 'DEGRADED'` pass schema validation cleanly without error.

---

### Defect DEF-04: Alert Schema sourceRef Missing 'AIPrediction' Reference

- **Root Cause**: `AlertSchema.sourceRef.refModel` only accepted `['ThreatLog', 'SystemMetric']`. When `aiService.js` generated alerts directly linked to AI inference anomalies or uninspected traffic, schema validation failed because `'AIPrediction'` was omitted from the permitted enum list.
- **File**: `backend/models/Alert.js`
- **Lines**: L36
- **Code Diff**:
```javascript
// BEFORE:
refModel: {
    type: String,
    enum: ['ThreatLog', 'SystemMetric']
}

// AFTER:
refModel: {
    type: String,
    enum: ['ThreatLog', 'SystemMetric', 'AIPrediction']
}
```
- **Verification**: Test 10 verifies that an `Alert` document with `refModel: 'AIPrediction'` validates cleanly.

---

### Defect DEF-05: Threat Service & Controller Rejection of 'DEGRADED' Status

- **Root Cause**: `threatService.js` defined `ALLOWED_STATUSES = new Set(['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'MONITORED'])`. In addition, `createThreat()` unconditionally forced `status = 'ACTIVE'`, destroying any incoming `'DEGRADED'` status. Similarly, `threatController.js` validated incoming update requests against an allowlist that omitted `'DEGRADED'`, blocking operators from querying or managing degraded threat records.
- **Files**: `backend/services/threatService.js`, `backend/controllers/threatController.js`
- **Lines**: `threatService.js` L23, L48; `threatController.js` L14
- **Code Diff**:
```javascript
// threatService.js BEFORE:
const ALLOWED_STATUSES = new Set(['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'MONITORED']);
...
status: 'ACTIVE',

// threatService.js AFTER:
const ALLOWED_STATUSES = new Set(['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'MONITORED', 'DEGRADED']);
...
status: threatData.status === 'DEGRADED' ? 'DEGRADED' : 'ACTIVE',

// threatController.js BEFORE:
const ALLOWED_THREAT_STATUSES = ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'];

// threatController.js AFTER:
const ALLOWED_THREAT_STATUSES = ['ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED'];
```
- **Verification**: Tests 10 and 16 verify that `threatService.createThreat()` preserves `status: 'DEGRADED'`, and `threatService.findThreats()` correctly filters degraded threats.

---

### Defect DEF-06: Database Persistence Failure Silently Drops Threat Data

- **Root Cause**: When MongoDB was unavailable or timed out during `runFullPipeline()`, the exception was logged with `logger.error`, but the threat details were completely discarded in memory. In an offline-first or disaster recovery scenario, the operator would have zero record of what network flows triggered the threat or went uninspected.
- **Files**: `backend/services/aiEngineService.js`, `backend/utils/emergencyAudit.js`
- **Lines**: `aiEngineService.js` L216-L233; `emergencyAudit.js` L1-L122
- **Code Diff**:
```javascript
// BEFORE:
} catch (error) {
    logger.error(`[AI Pipeline] Failed to persist prediction: ${error.message}`);
}

// AFTER:
} catch (error) {
    logger.error(`[AI Pipeline] Failed to persist prediction: ${error.message}`);
    // DEF-06 Fix: Emergency synchronous fallback audit to disk
    try {
        const { writeEmergencyAudit } = require('../utils/emergencyAudit');
        writeEmergencyAudit({
            eventType: 'THREAT_PERSISTENCE_FAILURE',
            originalError: error.message,
            threatData: {
                sourceIp: record.sourceIp || record.src_ip || 'UNKNOWN',
                targetIp: record.targetIp || record.dst_ip,
                attackType: prediction.predictedClass || 'Unknown',
                severity: prediction.threatScore >= 0.8 ? 'HIGH' : 'MEDIUM',
                status: prediction.status === 'DEGRADED' || prediction.status === 'UNAVAILABLE' ? 'DEGRADED' : 'ACTIVE',
                aiScore: prediction.threatScore,
                pipelineAction: action
            }
        });
    } catch (auditErr) {
        logger.error(`[Emergency Audit] Failed to record persistence failure: ${auditErr.message}`);
    }
}
```
- **Verification**: Tests 12 and 13 verify that persistence failures invoke `writeEmergencyAudit`, which synchronously flushes (`fs.fsyncSync`) sanitized, redacted JSON-lines to an emergency audit log with file rotation.

---

### Defect DEF-07: Socket & Notification Error Swallowing and Degraded Alert Blindspot

- **Root Cause**: In `aiService.js`, WebSocket broadcasting errors were logged only as debug messages. Furthermore, when uninspected or degraded traffic arrived, `aiService.js` failed to register an operational system alert or create a `DEGRADED` threat log, leaving dashboard operators unaware that the system was running in degraded mode.
- **File**: `backend/services/aiService.js`
- **Lines**: L121-L146, L184-L200
- **Code Diff**:
```javascript
// BEFORE:
} catch (socketError) {
    logger.debug(`Socket emission failed: ${socketError.message}`);
}

// AFTER:
} catch (socketError) {
    logger.warn(`[AI] Socket/Alert emission error: ${socketError.message}`);
}
```
- **Verification**: Test 14 verifies that notification emission failures log warnings without crashing or aborting the transaction pipeline.

---

## 4. Conclusion

All 7 defects have been addressed with surgical, defensive code changes and verified through integrated regression testing. No production model weights, thresholds, firewall rules, or autonomous containment controls were altered.
