# SentinelAI GATE-1 Phase 4: Change Summary

**Branch**: `feature/gate1-phase4-candidate-policy`  
**Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Author**: Implementation Engineer & Independent Auditor  
**Date**: 2026-10-16  
**Status**: Committed to isolated candidate branch (NOT merged to `main`)

---

## 1. Overview of Changes

Phase 4 addressed critical gaps identified in the Phase 3E independent verification audit:
1. **Invalid-Score Fail-Open Remediation**: The backend previously sanitized invalid/corrupt threat scores (`NaN`, strings, infinities, out-of-bounds) to `0.0`, mistakenly routing corrupted inferences to `ALLOW` and granting uninspected access to traffic.
2. **Emergency Audit Bounded Retention**: The disk fallback logger previously rotated files indefinitely without an upper retention bound, introducing long-term denial-of-service / disk-exhaustion vulnerabilities.
3. **Frontend Degraded Triage Enablement**: The operator dashboard in `ThreatLogs.jsx` lacked visual styling for the newly introduced `DEGRADED` status and omitted `'UNINSPECTED_TRAFFIC'` from the threat type filter dropdown.
4. **Comprehensive Regression Test Coverage**: Expanded backend safety regression tests to rigorously assert all invalid score edge cases, valid boundary conditions, and audit archive pruning.

---

## 2. File-by-File Detailed Modifications

### 2.1. `backend/services/aiEngineService.js`

- **Problem Addressed**:
  In Phase 3D, line 118 attempted to sanitize scores using:
  ```javascript
  const score = Math.max(0, Math.min(1, Number(result.threatScore || 0)));
  ```
  If `result.threatScore` was `NaN`, `"invalid"`, or non-numeric, `Number(...)` produced `NaN`, and `Math.max(0, Math.min(1, NaN))` evaluated to `0`. Consequently, `result.status === 'ALLOW'`, and the traffic was allowed through without inspection.
- **Remediation**:
  Implemented strict validation against finite numbers within $[0.0, 1.0]$:
  ```javascript
  // Validate threat score is a strictly finite number within [0, 1]
  const rawScore = result.threatScore;
  const isStrictlyValidScore = typeof rawScore === 'number' && Number.isFinite(rawScore) && rawScore >= 0 && rawScore <= 1;

  if (!isStrictlyValidScore) {
    console.warn(`[AIEngineService] Invalid or corrupted threatScore received: ${rawScore}. Falling back to DEGRADED state.`);
    return {
      threatScore: 0.5,
      isAttack: false,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      action: 'MONITOR',
      status: 'DEGRADED',
      isDegraded: true,
      reason: 'AI engine returned invalid threat score',
      modelSource: result.modelSource || 'RULE_BASED'
    };
  }
  ```
- **Security Impact**:
  Guarantees that no corrupted, non-numeric, out-of-range, or `NaN` score can ever fail-open to `ALLOW`. Invalid scores are deterministically converted into `DEGRADED` events with `MONITOR` actions and `'UNINSPECTED_TRAFFIC'` labels.

---

### 2.2. `backend/utils/emergencyAudit.js`

- **Problem Addressed**:
  The rotation logic created timestamped files (`emergency-audit-<timestamp>.log`) upon reaching `MAX_FILE_SIZE` ($10\text{MB}$), but never deleted or pruned old archives. A prolonged database outage under heavy network traffic could exhaust host storage.
- **Remediation**:
  Introduced `MAX_ROTATED_FILES = 5` and automated archive pruning:
  ```javascript
  const MAX_ROTATED_FILES = 5;

  async checkRotation() {
    try {
      const stats = await fs.promises.stat(this.auditPath);
      if (stats.size >= MAX_FILE_SIZE) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const archivePath = path.join(this.auditDir, `emergency-audit-${timestamp}.log`);
        await fs.promises.rename(this.auditPath, archivePath);
        
        // Prune older rotated archives to enforce bounded disk usage
        await this.pruneOldRotations();
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error('[EmergencyAudit] Rotation check failed:', err.message);
      }
    }
  }

  async pruneOldRotations() {
    try {
      const files = await fs.promises.readdir(this.auditDir);
      const rotatedFiles = files
        .filter(f => f.startsWith('emergency-audit-') && f.endsWith('.log'))
        .map(f => ({ name: f, path: path.join(this.auditDir, f) }));

      if (rotatedFiles.length > MAX_ROTATED_FILES) {
        // Sort ascending by modification time (oldest first)
        const fileStats = await Promise.all(
          rotatedFiles.map(async f => ({
            ...f,
            mtime: (await fs.promises.stat(f.path)).mtimeMs
          }))
        );
        fileStats.sort((a, b) => a.mtime - b.mtime);
        
        const toDelete = fileStats.slice(0, fileStats.length - MAX_ROTATED_FILES);
        for (const file of toDelete) {
          await fs.promises.unlink(file.path);
        }
      }
    } catch (err) {
      console.error('[EmergencyAudit] Archive pruning failed:', err.message);
    }
  }
  ```
- **Storage Boundary**:
  Total local storage footprint is capped at:
  $$\text{Max Storage} = 10\text{MB (active)} + 5 \times 10\text{MB (rotated)} = 60\text{MB}$$

---

### 2.3. `frontend/src/pages/ThreatLogs.jsx`

- **Problem Addressed**:
  The frontend UI lacked styling definitions for the `DEGRADED` status badge and did not provide an option to filter by `'UNINSPECTED_TRAFFIC'` in the threat type dropdown.
- **Remediation**:
  1. Added `DEGRADED` badge style:
     ```javascript
     const STATUS_STYLES = {
       BLOCKED: { color: '#ff4444', bg: 'rgba(255, 68, 68, 0.1)', border: '1px solid #ff4444' },
       MONITOR: { color: '#ffaa00', bg: 'rgba(255, 170, 0, 0.1)', border: '1px solid #ffaa00' },
       ALLOW: { color: '#00cc66', bg: 'rgba(0, 204, 102, 0.1)', border: '1px solid #00cc66' },
       DEGRADED: { color: '#ffaa00', bg: 'rgba(255, 170, 0, 0.1)', border: '1px dashed #ffaa00' }
     };
     ```
  2. Added `'UNINSPECTED_TRAFFIC'` to the filter dropdown:
     ```javascript
     const TYPES = ['ALL', 'DDoS', 'PortScan', 'BruteForce', 'UNINSPECTED_TRAFFIC', 'BENIGN'];
     ```
- **Operator Impact**:
  Degraded events render prominently with a distinct dashed amber badge, and security operations personnel can immediately filter for uninspected events during pipeline health reviews.

---

### 2.4. `backend/tests/integrated_backend_safety_regression.test.js`

- **Modifications**:
  1. Replaced the single `threatScore: NaN` check in Test 9 with **10 comprehensive test cases**:
     - `null` $\to$ `DEGRADED` / `MONITOR`
     - `undefined` $\to$ `DEGRADED` / `MONITOR`
     - `NaN` $\to$ `DEGRADED` / `MONITOR`
     - String `"0.85"` $\to$ `DEGRADED` / `MONITOR`
     - String `"INVALID"` $\to$ `DEGRADED` / `MONITOR`
     - Number `1.5` ($> 1.0$) $\to$ `DEGRADED` / `MONITOR`
     - Number `-0.01` ($< 0.0$) $\to$ `DEGRADED` / `MONITOR`
     - `+Infinity` $\to$ `DEGRADED` / `MONITOR`
     - `-Infinity` $\to$ `DEGRADED` / `MONITOR`
     - Valid boundary values: `0.0` ($\to$ `ALLOW`), `1.0` ($\to$ `BLOCK`)
  2. Expanded Test 13 to simulate 8 successive file rotations and assert that exactly 5 rotated archive files remain on disk after pruning.
- **Verification Results**:
  - `integrated_backend_safety_regression.test.js`: **17/17 PASSED (100%)**
  - Full backend test suite: **78/78 PASSED across 5 test suites (100%)**

---

## 3. Protected Asset Verification

Pre-change and post-change SHA-256 digests confirm zero modification to protected runtime assets:

| Protected Asset | SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **Unmodified** |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **Unmodified** |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **Unmodified** |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **Unmodified** |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **Unmodified** |

---

## 4. Conclusion

All software engineering defects identified during Phase 3E have been remediated in `feature/gate1-phase4-candidate-policy` under full test coverage. In accordance with safety restrictions, this branch has not been merged to `main` and live services have not been modified.
