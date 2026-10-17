# SentinelAI GATE-1 Phase 3E: Schema and Frontend Compatibility Audit

**Auditor**: Independent Software Auditor & ML Security Engineer  
**Date**: 2026-10-16  
**Status**: **Partially Verified (Backend Schemas 100% Verified; UI Filter Limitation Identified)**

---

## 1. Mongoose Schema Validation Audit

Mongoose model schemas were verified using `validateSync()` in `ai-engine/experiments/gate1_phase3e_independent_verification/test_schemas_and_compatibility.js`:

| Schema & Field | Tested Enum Values | Expected Outcome | Observed Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| `ThreatLog.attackType` | `'UNINSPECTED_TRAFFIC'` | Accepts valid enum | `validateSync() === undefined` | **Verified** |
| `ThreatLog.attackType` | `'INVALID_ATTACK_TYPE_123'` | Rejects invalid enum | `ValidationError` on `attackType` | **Verified** |
| `ThreatLog.status` | `'DEGRADED'` | Accepts valid enum | `validateSync() === undefined` | **Verified** |
| `ThreatLog.status` | `'INVALID_STATE_XYZ'` | Rejects invalid enum | `ValidationError` on `status` | **Verified** |
| `ThreatLog.preBlockStatus` | `'DEGRADED'` | Accepts valid enum | `validateSync() === undefined` | **Verified** |
| `Alert.sourceRef.refModel` | `'AIPrediction'` | Accepts valid enum | `validateSync() === undefined` | **Verified** |
| `Alert.sourceRef.refModel` | `'NonExistentModel'` | Rejects invalid enum | `ValidationError` on `sourceRef.refModel` | **Verified** |

---

## 2. Database Index & Query Compatibility

1. **MongoDB B-Tree Index Dynamics**:
   - `ThreatLog` contains compound indexes on `{ status: 1, createdAt: -1 }` and `{ attackType: 1, createdAt: -1 }`.
   - In MongoDB, B-tree indexes dynamically index new string scalar values as documents are inserted. No index rebuild, schema migration, or downtime is required.
2. **Backend Query Parsing**:
   - In `backend/services/threatService.js`, `findThreats({ status: 'DEGRADED' })` parses the query correctly and sets `status: 'DEGRADED'` on the Mongoose filter object.
   - In `backend/controllers/threatController.js`, `ALLOWED_THREAT_STATUSES` contains `'DEGRADED'`, allowing REST requests to filter by degraded status without HTTP 400 validation rejection.

---

## 3. Frontend Consumer Compatibility Audit

The frontend UI codebase was audited to determine how it consumes and renders the new `'DEGRADED'` status and `'UNINSPECTED_TRAFFIC'` attack type.

### 3.1 `frontend/src/pages/ThreatLogs.jsx`
- **Status Badge Rendering**:
  ```javascript
  // Lines 206-208:
  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, padding:'3px 8px', borderRadius:1, ...(STATUS_STYLES[l.status]||STATUS_STYLES.DETECTED) }}>
    {l.status}
  </span>
  ```
  - `STATUS_STYLES['DEGRADED']` is `undefined`.
  - The fallback `STATUS_STYLES.DETECTED` is applied:
    `{ background:'rgba(0,212,255,.1)', color:'#00d4ff', border:'1px solid rgba(0,212,255,.25)' }`
  - The text `"DEGRADED"` renders inside a cyan pill badge.
  - **Verdict**: **Verified Safe**. No React rendering crashes or DOM exceptions occur.

- **Identified UI Limitation: Attack Type Filter Dropdown**:
  ```javascript
  // Line 19:
  const TYPES = ['SSH Brute Force','SQL Injection','Port Scan','DDoS','RCE Attempt',
                 'XSS Attempt','Malware Beacon','Credential Stuffing','Lateral Movement','Data Exfiltration']
  ```
  - The `TYPES` array in `ThreatLogs.jsx` defines the dropdown options for filtering by attack type.
  - `'UNINSPECTED_TRAFFIC'` is **absent** from this list.
  - **Impact**: While uninspected flows appear in the default list view and match text search (`search`), security analysts **cannot specifically filter** for `'UNINSPECTED_TRAFFIC'` using the UI dropdown menu.

### 3.2 `frontend/src/pages/Dashboard.jsx`
- **Vector Trend Chart**:
  ```javascript
  // Line 20:
  const VECTOR_COLORS = { 'SSH Brute Force': '#ff2d55', ... }
  ```
  - Unmapped attack types like `'UNINSPECTED_TRAFFIC'` are ingested by `vectorData`, but lack an entry in `VECTOR_COLORS`.
  - Recharts renders the bar segment using default palette styling.
  - **Verdict**: **Verified Safe**. No runtime chart crash occurs.
- **KPI Metrics**:
  - `totalToday` aggregates all threat records regardless of status. Degraded events are reflected in the total threat volume.

---

## 4. Alert & Event Decoupling Verification

- In `backend/services/aiService.js`, `Alert` creation and WebSocket event delivery are isolated inside an independent `try / catch` block.
- In `test_failure_state_contract_13cases.js` (Case 11 & Case 12), simulated WebSocket failure (`EPIPE`) and simulated Alert creation failure did **not** abort or roll back the primary prediction transaction.
- **Verdict**: **Verified**. Operator notification errors do not cause transaction failure.
