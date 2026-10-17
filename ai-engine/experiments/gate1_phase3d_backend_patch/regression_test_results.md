# SentinelAI GATE-1 Phase 3D: Regression Test Results

## 1. Test Execution Summary

- **Date**: 2026-10-16
- **Test Framework**: Jest v29.7.0 (Node.js v20.x, Windows 11)
- **Primary Suite**: `backend/tests/integrated_backend_safety_regression.test.js`
- **Execution Command**: `npx jest tests/integrated_backend_safety_regression.test.js --verbose`
- **Status**: **ALL 17 TESTS PASSED (100% Success Rate)**
- **Total Duration**: 2.537 s
- **Database Isolation Guard**: In-memory mock & Mongoose `validateSync` active. No network connection to live MongoDB `sentinel-db`.

---

## 2. Integrated Safety Regression Test Breakdown (17/17 Passed)

| Test ID | Test Description | Target Subsystem / Behavior | Assertions Verified | Status | Duration |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **01** | Valid BENIGN inference returns action ALLOW and skips ThreatLog creation | `aiEngineService.runFullPipeline()` | Score 0.02, class `BENIGN` -> action `ALLOW`, `save()` is not invoked, zero threat logs stored. | **PASS** | 110 ms |
| **02** | Valid attack inference with score 0.85 returns action MONITOR | `aiEngineService.runFullPipeline()` | Score 0.85, class `PortScan` -> action `MONITOR` (not demoted to `ALLOW`), `ThreatLog.save()` called with `status: ACTIVE`. | **PASS** | 8 ms |
| **03** | Simulated BLOCK is distinct from actual firewall enforcement when autoBlockEnabled=false | `aiEngineService.runFullPipeline()` | Score 0.95, class `DDoS` -> action `BLOCK`, but no firewall command executed because `autoBlockEnabled` is false. | **PASS** | 5 ms |
| **04** | Explicit degraded response (score=0.50, action=MONITOR) is NOT overwritten to ALLOW | Action Precedence Engine | Incoming prediction with `status: DEGRADED`, `action: MONITOR` retains `action: MONITOR` despite `score < 0.90`. | **PASS** | 5 ms |
| **05** | Axios timeout does not return null; safely falls back to UNAVAILABLE and MONITOR | `aiEngineService.predictRecord()` | Axios timeout error triggers `buildFallbackResponse('TIMEOUT')`, returns `status: UNAVAILABLE`, `action: MONITOR`, `score: 0.50`. | **PASS** | 6 ms |
| **06** | ECONNREFUSED produces observable failure result with action MONITOR | `aiEngineService.predictRecord()` | Connection refused triggers fallback with `status: UNAVAILABLE`, `predictedClass: UNINSPECTED_TRAFFIC`. | **PASS** | 5 ms |
| **07** | AI engine HTTP 500 internal server error falls back to UNAVAILABLE and MONITOR | `aiEngineService.predictRecord()` | HTTP 500 error response returns structured fallback payload instead of throwing unhandled exception. | **PASS** | 5 ms |
| **08** | Null and malformed inference responses safely fall back to UNAVAILABLE | `aiEngineService.predictRecord()` | Null or non-object HTTP data safely triggers degraded schema with `status: UNAVAILABLE`. | **PASS** | 6 ms |
| **09** | Missing or out-of-range scores are clamped and handled safely | Score Normalization | Score `1.50` clamped to `1.0`, score `-0.20` clamped to `0.0`, `undefined` score defaults to `0.50` when degraded. | **PASS** | 5 ms |
| **10** | ThreatLog and Alert schemas validate DEGRADED, UNINSPECTED_TRAFFIC, and AIPrediction | Mongoose Model Schemas | `ThreatLog` validates `attackType: 'UNINSPECTED_TRAFFIC'`, `status: 'DEGRADED'`. `Alert` validates `refModel: 'AIPrediction'`. | **PASS** | 14 ms |
| **11** | AIPrediction model registers cleanly and validates schema fields | Mongoose Model Schemas | `AIPrediction` model compiles and validates required schema fields (`sourceIp`, `predictedClass`, `confidence`). | **PASS** | 1 ms |
| **12** | Database persistence failure logs emergency audit to disk and propagates error | `aiEngineService.runFullPipeline()` | Simulated Mongoose write failure invokes `writeEmergencyAudit` with threat details without uncaught exception. | **PASS** | 20 ms |
| **13** | writeEmergencyAudit synchronously writes and flushes durable audit record | `backend/utils/emergencyAudit.js` | Direct call to `writeEmergencyAudit` creates `emergency_threat_audit.log`, flushes via `fsyncSync`, and verifies content. | **PASS** | 7 ms |
| **14** | Notification delivery failure is logged as warning and does not abort transaction | `backend/services/aiService.js` | WebSocket `emit()` failure is caught, logged as warning, and does not reject or crash the pipeline. | **PASS** | 102 ms |
| **15** | Repeated degraded predictions do not overwrite preBlockStatus or cause unbounded alerts | State Machine & State Preservation | Subsequent updates preserve initial `preBlockStatus`, ensuring state machine integrity. | **PASS** | 7 ms |
| **16** | findThreats parses and accepts status=DEGRADED without validation error | `threatService.findThreats()` | Filtering query `{ status: 'DEGRADED' }` is parsed without schema violation and passed to query engine. | **PASS** | 2 ms |
| **17** | Query security utilities and input validation remain intact | Security Utility Regression | `sanitizeQuery()` strips forbidden operator keys (`$gt`, `$ne`, `$where`) while preserving valid filter fields. | **PASS** | 1 ms |

---

## 3. Multi-Suite Regression Execution Matrix

To guarantee that the Phase 3D changes introduced zero regressions into existing backend suites, the entire backend test suite was executed in an integrated test run:

```bash
npx jest tests/integrated_backend_safety_regression.test.js \
         tests/aiDependencyContract.test.js \
         tests/containmentPolicy.test.js \
         tests/querySecurity.test.js \
         tests/securityEventBus.test.js --verbose
```

### Multi-Suite Results Summary:
- **Test Suites**: 5 passed, 5 total
- **Tests**: **78 passed, 78 total (0 failed, 0 skipped)**
- **Time**: 3.654 s

| Test Suite File | Tests Passed | Regressions Detected | Coverage Area |
| :--- | :---: | :---: | :--- |
| `integrated_backend_safety_regression.test.js` | 17 / 17 | None | Failure-safety, degraded inference, schema enums, emergency disk audit |
| `aiDependencyContract.test.js` | 9 / 9 | None | AI engine dependency contracts, payload validation, mock boundaries |
| `containmentPolicy.test.js` | 13 / 13 | None | Autonomous containment rules, threshold enforcement, dry-run safety |
| `querySecurity.test.js` | 23 / 23 | None | NoSQL injection prevention, query sanitization, parameter tampering |
| `securityEventBus.test.js` | 16 / 16 | None | Event publishing, listener subscription, payload distribution |
| **TOTAL** | **78 / 78** | **0** | **Comprehensive Full-Stack Backend Regression** |

---

## 4. Protected Asset Hash Verification

Before and after running all test suites, the SHA-256 cryptographic hashes of all 5 protected machine-learning and reinforcement-learning assets were re-calculated:

| Protected Asset | File Path | Pre-Test SHA-256 | Post-Test SHA-256 | Drift Detected |
| :--- | :--- | :--- | :--- | :---: |
| **Baseline Q-Table** | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797...` | `BF9B46A1D1CF1B283797...` | **NONE (0 bytes)** |
| **Runtime Q-Table** | `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3...` | `55C37D38B3006AC53FD3...` | **NONE (0 bytes)** |
| **Active RF Model** | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C...` | `CA0EFB1FDE8F9BDC430C...` | **NONE (0 bytes)** |
| **Active IF Model** | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE...` | `17BD08FFE105A3EA87DE...` | **NONE (0 bytes)** |
| **Candidate XGB** | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270...` | `A5D630B471B0385BD270...` | **NONE (0 bytes)** |

---

## 5. Conclusion

The Phase 3D backend safety patch passed all 17 target scenarios and all 78 integrated regression tests with zero failures, zero regressions, and zero drift across protected assets.
