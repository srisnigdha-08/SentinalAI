# SentinelAI GATE-1 — Phase 3C: Remediation Patch Plan and Deployment Blueprint

**Plan Date:** October 16, 2026  
**Auditor / Roles:** Principal Software Architect & Application Security Engineer  
**Location:** [`ai-engine/experiments/gate1_phase3c_backend_safety/remediation_patch_plan.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/remediation_patch_plan.md)  
**Status:** **PROPOSED PATCH PLAN (NOT APPLIED; PENDING AUTHORIZATION)**  
**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Mode Only)

---

## 1. Scope & Safety Guidelines

This document provides the exact code modifications required to remediate the 7 confirmed backend failure-safety defects. In accordance with strict Phase 3C safety constraints:
* **Zero production files have been modified.**
* These patches represent proposed, review-ready diffs for future authorized promotion.
* Every patch includes a minimal diff, security rationale, compatibility and migration analysis, pre/post regression test mapping, and a rollback plan.

---

## 2. Detailed Patch Specifications

### Patch 1: Schema Updates for Degraded and Uninspected States (Defects D-04, D-05, D-06)

#### A. Target File: `backend/models/ThreatLog.js`
* **Minimal Proposed Code Change:**
  ```diff
  --- a/backend/models/ThreatLog.js
  +++ b/backend/models/ThreatLog.js
  @@ -25,6 +25,7 @@ const ThreatLogSchema = new mongoose.Schema(
           'Data Exfiltration',
           'Zero-Day Exploit',
           'Unknown',
  +        'UNINSPECTED_TRAFFIC',
         ],
       },
       aiScore: { type: Number, min: 0, max: 1, default: 0 },
  @@ -32,7 +33,7 @@ const ThreatLogSchema = new mongoose.Schema(
       status: {
         type: String,
  -      enum: ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'],
  +      enum: ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED'],
         default: 'DETECTED',
         index: true,
       },
  ```
* **Security Rationale:** Prevents runtime Mongoose `ValidationError` exceptions when logging uninspected traffic and degraded pipeline states.
* **Compatibility & Migration:** Fully backward compatible. All existing values remain valid. No database migration script required; existing records are unaffected.
* **Verification Tests:**
  - Fails before: `TC-PROD-04`, `TC-PROD-05`
  - Passes after: `TC-REM-03`
* **Rollback Plan:** Revert the diff in `ThreatLog.js`.

---

#### B. Target File: `backend/models/Alert.js`
* **Minimal Proposed Code Change:**
  ```diff
  --- a/backend/models/Alert.js
  +++ b/backend/models/Alert.js
  @@ -20,7 +20,7 @@ const AlertSchema = new mongoose.Schema(
       type: {
       sourceRef: {
  -      refModel: { type: String, enum: ['ThreatLog', 'HoneypotSession', 'User'] },
  +      refModel: { type: String, enum: ['ThreatLog', 'HoneypotSession', 'User', 'AIPrediction'] },
         refId: { type: mongoose.Schema.Types.ObjectId },
       },
  ```
* **Security Rationale:** Permits creating security alerts linked directly to `AIPrediction` records when the model engine encounters degraded or anomalous behavior.
* **Compatibility & Migration:** Fully backward compatible.
* **Verification Tests:**
  - Fails before: `TC-PROD-07`
  - Passes after: `TC-REM-03`
* **Rollback Plan:** Revert diff in `Alert.js`.

---

### Patch 2: Action Preservation and Timeout Fail-Safe Fallback (Defects D-01, D-02)

#### Target File: `backend/services/aiEngineService.js`
* **Minimal Proposed Code Change:**
  ```diff
  --- a/backend/services/aiEngineService.js
  +++ b/backend/services/aiEngineService.js
  @@ -46,8 +46,14 @@ const predictRecord = async (record) => {
         throw error
       }
  -    logger.warn('[AI] predict failed (' + e.name + ')')
  -    return null
  +    logger.warn(`[AI] predict failed (${e.name}): ${e.message}`)
  +    return {
  +      result: {
  +        predictedClass: 'UNINSPECTED_TRAFFIC',
  +        threatScore: 0.50,
  +        action: 'MONITOR',
  +        status: 'UNAVAILABLE',
  +        error: e.message
  +      }
  +    }
     }
   }
   const runFullPipeline = async (record, io = null) => {
  @@ -55,8 +61,20 @@ const runFullPipeline = async (record, io = null) => {
     const { result } = r
     const score = result.threatScore || 0
     const blockThreshold = await getBlockThreshold()
  -  const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  +
  +  // Action Resolution Precedence:
  +  // 1. Degraded / Unavailable states must strictly execute MONITOR
  +  // 2. Explicit action from candidate policy is honored
  +  // 3. Fallback to score thresholds
  +  let action = 'ALLOW'
  +  if (result.status === 'DEGRADED' || result.status === 'UNAVAILABLE' || result.predictedClass === 'UNINSPECTED_TRAFFIC') {
  +    action = 'MONITOR'
  +  } else if (result.action === 'MONITOR' || result.action === 'BLOCK') {
  +    action = result.action
  +  } else {
  +    action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  +  }
  ```
* **Security Rationale:**
  1. Prevents silent fail-open drops on timeout or network refusal. Instead of returning `null`, returns a controlled degraded object with `action: 'MONITOR'`.
  2. Stops the backend from overriding Python candidate policy actions.
* **Compatibility & Migration:** Fully compatible with route callers. API routes checking `if (!r)` will receive valid structured responses; consumers expecting degraded indicators can inspect `status`.
* **Verification Tests:**
  - Fails before: `TC-PROD-01`, `TC-PROD-02`, `TC-PROD-03`
  - Passes after: `TC-REM-01`, `TC-REM-02`
* **Rollback Plan:** Revert diff in `aiEngineService.js`.

---

### Patch 3: Status Preservation and Auto-Block Gating (Defect D-03)

#### Target File: `backend/services/threatService.js`
* **Minimal Proposed Code Change:**
  ```diff
  --- a/backend/services/threatService.js
  +++ b/backend/services/threatService.js
  @@ -18,7 +18,7 @@ const ALLOWED_THREAT_SORT_FIELDS = [
   ]
   
   const ALLOWED_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
  -const ALLOWED_STATUSES = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE']
  +const ALLOWED_STATUSES = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED']
   
   const findThreats = async ({
  @@ -96,8 +96,10 @@ const createThreat = async (data) => {
     const actionTaken = shouldBlock
   
     let status = 'DETECTED'
  -  if (shouldBlock) {
  +  if (data.status === 'DEGRADED') {
  +    status = 'DEGRADED'
  +  } else if (shouldBlock) {
       status = 'BLOCKED'
     } else if (score >= 0.7) {
       status = 'MONITORING'
     }
  ```
* **Security Rationale:** Ensures that threats created from degraded AI states preserve their `DEGRADED` label rather than being obscured as standard low-severity detections.
* **Compatibility & Migration:** Expands `ALLOWED_STATUSES` so API queries filtering by `status=DEGRADED` succeed without validation errors.
* **Verification Tests:**
  - Fails before: `TC-PROD-01`
  - Passes after: `TC-REM-01`
* **Rollback Plan:** Revert diff in `threatService.js`.

---

### Patch 4: Alert Emission Telemetry and Degraded Visibility (Defect D-07)

#### Target File: `backend/services/aiService.js`
* **Minimal Proposed Code Change:**
  ```diff
  --- a/backend/services/aiService.js
  +++ b/backend/services/aiService.js
  @@ -57,7 +57,8 @@ const storePrediction = async (data) => {
     }
   
     const pred = await AIPrediction.create(payload)
  -  if (!data.generatedThreat && pred.threatScore >= 0.7 && pred.predictedClass !== 'BENIGN') {
  +  const isDegraded = data.status === 'DEGRADED' || data.status === 'UNAVAILABLE' || data.predictedClass === 'UNINSPECTED_TRAFFIC'
  +  if (!data.generatedThreat && (isDegraded || (pred.threatScore >= 0.7 && pred.predictedClass !== 'BENIGN'))) {
       const severity = pred.threatScore >= 0.9 ? 'CRITICAL' : pred.threatScore >= 0.75 ? 'HIGH' : 'MEDIUM'
   
       // Authoritative Block Threshold & autoBlockEnabled setting
  @@ -70,7 +71,7 @@ const storePrediction = async (data) => {
       const autoBlockEnabled = setting ? setting.value === true : false
   
       const shouldBlock = pred.threatScore >= blockThreshold && autoBlockEnabled
  -    const status = shouldBlock ? 'BLOCKED' : 'MONITORING'
  +    const status = isDegraded ? 'DEGRADED' : shouldBlock ? 'BLOCKED' : 'MONITORING'
   
       const threat = await ThreatLog.create({
         severity,
  @@ -115,7 +116,7 @@ const storePrediction = async (data) => {
         }
       } catch (e) {
  -      logger.debug('[AI] Socket/Alert emission error: ' + e.message)
  +      logger.warn('[AI] Socket/Alert emission error: ' + e.message)
       }
  ```
* **Security Rationale:**
  1. Guarantees that degraded or uninspected traffic automatically generates a `ThreatLog` record with `status: 'DEGRADED'` so it appears on analyst dashboards.
  2. Promotes socket emission error logging from `debug` to `warn` so failed alert deliveries are visible in production logs.
* **Compatibility & Migration:** Fully backward compatible.
* **Verification Tests:**
  - Fails before: `TC-PROD-01`, `TC-PROD-02`
  - Passes after: `TC-REM-01`, `TC-REM-02`
* **Rollback Plan:** Revert diff in `aiService.js`.

---

## 3. Rollout & Validation Sequence

```
+--------------------------------------------------------------------------------------------------+
|                                    PROMOTION DEPLOYMENT PHASES                                   |
+--------------------------------------------------------------------------------------------------+
| 1. Schema Updates          | Apply Patch 1 to ThreatLog.js & Alert.js                            |
| 2. Backend Pipeline Safety | Apply Patch 2, 3, 4 to aiEngineService.js, threatService, aiService |
| 3. Regression Testing      | Execute test_backend_safety_isolated.js -> All 13 tests must PASS   |
| 4. Integration Smoke Test  | Run backend/tests/aiDependencyContract.test.js                      |
| 5. Service Reload          | Restart backend service under maintenance authorization             |
+--------------------------------------------------------------------------------------------------+
```
