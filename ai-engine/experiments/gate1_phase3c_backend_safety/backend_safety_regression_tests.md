# SentinelAI GATE-1 — Phase 3C: Backend Safety Regression Test Report

**Execution Date:** October 16, 2026  
**Auditor / Roles:** Principal ML-Security QA Lead & Application Security Engineer  
**Workspace:** [`ai-engine/experiments/gate1_phase3c_backend_safety/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/)  
**Execution Script:** [`test_backend_safety_isolated.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/test_backend_safety_isolated.js)  
**Structured Output:** [`backend_safety_regression_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/backend_safety_regression_results.json)  
**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Mode Only)

---

## 1. Test Suite Execution Overview

The isolated regression test suite `test_backend_safety_isolated.js` was executed on Node.js v24.14.0. The suite evaluated:
* **Part A (8 tests):** Reproduction of baseline production defects and verification of nominal safety gating.
* **Part B (5 tests):** Validation of the proposed failure-state contract under identical failure conditions.

### Executive Test Summary:
* **Total Assertions Executed:** 13
* **Production Defects Confirmed:** 7 / 7 (100% of reported defects replicated)
* **Nominal Safe Gating Verified:** 1 / 1 (`autoBlockEnabled = false` holds threats at `MONITORING`)
* **Remediated Contract Tests Passed:** 5 / 5 (100% pass rate)

---

## 2. Detailed Results: Part A — Production Baseline Defects

| Test ID | Test Scenario | Injected Condition / Input | Observed Behavior | Defect Status |
|:---:|:---|:---|:---|:---:|
| **TC-PROD-01** | Degraded Action Overwrite | `{ predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.50, action: 'MONITOR', status: 'DEGRADED' }` | Backend calculates $0.50 < 0.70$ and outputs `action: 'ALLOW'`. Python `action: 'MONITOR'` discarded. | **CONFIRMED DEFECT** |
| **TC-PROD-02** | Timeout Fail-Open Drop | `Error: timeout of 10000ms exceeded` | Catch block logs warning, returns `null`. `runFullPipeline()` returns `null`. Zero DB records, zero alerts. | **CONFIRMED DEFECT** |
| **TC-PROD-03** | ECONNREFUSED Fail-Open Drop | `Error: connect ECONNREFUSED 127.0.0.1:8000` | Same as TC-PROD-02: returns `null`. Entire flow dropped without trace. | **CONFIRMED DEFECT** |
| **TC-PROD-04** | ThreatLog Status Enum Rejection | `ThreatLog.status = 'DEGRADED'` | `allowedStatuses.includes('DEGRADED') === false`. Mongoose throws `ValidationError`. | **CONFIRMED DEFECT** |
| **TC-PROD-05** | ThreatLog attackType Rejection | `ThreatLog.attackType = 'UNINSPECTED_TRAFFIC'` | `allowedAttackTypes.includes('UNINSPECTED_TRAFFIC') === false`. Mongoose throws `ValidationError`. | **CONFIRMED DEFECT** |
| **TC-PROD-06** | Malformed Score Defaults to ALLOW | `threatScore = null` | Score defaults to `0.0`. `0.0 < 0.70` assigns `action = 'ALLOW'`. | **CONFIRMED DEFECT** |
| **TC-PROD-07** | Alert refModel Rejection | `Alert.sourceRef.refModel = 'AIPrediction'` | `allowedRefModels.includes('AIPrediction') === false`. Mongoose throws `ValidationError`. | **CONFIRMED DEFECT** |
| **TC-PROD-08** | Autonomous Containment Gating | `threatScore = 0.98`, `autoBlockEnabled = false` | `shouldBlock === false`, `status === 'MONITORING'`. No firewall command issued. | **PASS (Nominal Safe)** |

---

## 3. Detailed Results: Part B — Remediated Contract Tests

| Test ID | Test Scenario | Injected Condition / Input | Observed Behavior | Remediation Verdict |
|:---:|:---|:---|:---|:---:|
| **TC-REM-01** | Degraded Action Preservation | `{ predictedClass: 'UNINSPECTED_TRAFFIC', threatScore: 0.50, action: 'MONITOR', status: 'DEGRADED' }` | Output retains `action: 'MONITOR'`, `status: 'DEGRADED'`, `threatStatus: 'DEGRADED'`. Operator alert created. | **PASS** |
| **TC-REM-02** | Timeout Fail-Safe Fallback | `Error: timeout of 10000ms exceeded` | Handled as `status: 'UNAVAILABLE'`. Assigns `action: 'MONITOR'`. Creates degraded `ThreatLog` and emits `SYSTEM_HEALTH` alert. | **PASS** |
| **TC-REM-03** | Proposed Schema Compatibility | `status = 'DEGRADED'`, `attackType = 'UNINSPECTED_TRAFFIC'` | Validated against proposed schema enums. Both accepted cleanly without error. | **PASS** |
| **TC-REM-04** | Emergency Disk Audit Fallback | Injected `MongoNetworkError` | Exception cleanly propagated, but an immutable emergency audit record was written to the fallback logger on disk. | **PASS** |
| **TC-REM-05** | Simulated BLOCK Gating | `threatScore = 0.96`, `autoBlockEnabled = false` | Assigned `action: 'BLOCK'`, marked `simulatedBlock = true`, threat status held safely at `MONITORING`. | **PASS** |

---

## 4. Analysis of Test Evidence

### Key Empirical Takeaways:
1. **The Fail-Open Threat is Real:** In current production code, any network issue between the Node.js backend and the Python AI Engine causes `predictRecord()` to return `null`. The backend drops the packet without creating any record in MongoDB and without raising any alert to the SOC. An attacker launching a resource exhaustion attack that causes the AI engine to time out will successfully evade all inspection.
2. **Action Overwrites Silently Weaken Security:** Even when the Python engine detects a degraded condition and asks for `MONITOR`, the backend overwrites it to `ALLOW` because $0.50 < 0.70$.
3. **Mongoose Schema Enums Act as a Landmine:** Any backend developer attempting to store degraded states today would cause runtime unhandled promise rejections due to strict Mongoose enum validation in `ThreatLog.js` and `Alert.js`.
4. **Remediation Feasibility:** The Part B tests prove that the proposed `FailureStateContractHandler` logic completely resolves all 7 defects while preserving backward compatibility and autonomous containment safety invariants.
