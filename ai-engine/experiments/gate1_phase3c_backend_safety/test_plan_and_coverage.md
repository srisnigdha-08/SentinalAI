# SentinelAI GATE-1 — Phase 3C: Test Plan and Coverage Specification

**Plan Date:** October 16, 2026  
**Auditor / Roles:** Principal ML-Security QA Lead & Application Security Engineer  
**Location:** [`ai-engine/experiments/gate1_phase3c_backend_safety/test_plan_and_coverage.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/test_plan_and_coverage.md)  
**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Mode Only)

---

## 1. Test Strategy & Safety Boundaries

The goal of Phase 3C testing is to provide mathematically rigorous, externally observable proof of:
1. Current production code defects in failure handling, action overwriting, and schema validation.
2. The correctness of the proposed failure-state contract under identical failure conditions.

### Strict Safety Boundaries:
* **Zero Production Code Edits:** Production files in `backend/` and `ai-engine/` are untouched.
* **Zero Live Database Operations:** No connections or writes to `sentinel-db`.
* **Zero OS Changes:** No Windows Firewall rule adjustments (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`).
* **Deterministic Isolation:** All test doubles run in-memory with deterministic inputs and outputs.

---

## 2. Test Double vs. Live Execution Distinction

To ensure clarity for independent reviewers:

| Test Group | Execution Mechanism | Purpose |
|---|---|---|
| **Part A: Production Baseline Defects** (`TC-PROD-01` to `TC-PROD-08`) | Isolated execution of actual production logic extracted directly from active files (`aiEngineService.js:48-58`, `threatService.js:98-103`, `ThreatLog.js:12-36`, `Alert.js:22`). | Confirms beyond doubt that current production code possesses the reported defects without endangering live services. |
| **Part B: Remediated Contract Logic** (`TC-REM-01` to `TC-REM-05`) | Isolated execution of the proposed `FailureStateContractHandler` implementing the failure-state contract. | Proves that the proposed remediation satisfies all safety requirements, preserves operator visibility, and eliminates fail-open bypasses. |

---

## 3. Test Coverage Matrix

The suite covers all 10 failure outcomes traced in Task 1 and all 6 operational states defined in Task 2:

| Test ID | Failure Outcome / Operational State | Input / Injected Condition | Observable Assertion Criteria | Expected Outcome |
|:---:|:---|:---|:---|:---:|
| **TC-PROD-01** | Explicit Degraded State / State 2 | `status: 'DEGRADED'`, `action: 'MONITOR'`, `threatScore: 0.50` | `prodAction === 'ALLOW'` (Defect Confirmed) | **DEFECT CONFIRMED** |
| **TC-PROD-02** | Timeout / State 3 | `Error: timeout of 10000ms exceeded` | Output is `null` (Fails open, no DB/alert) | **DEFECT CONFIRMED** |
| **TC-PROD-03** | Connection Refusal / State 3 | `Error: connect ECONNREFUSED` | Output is `null` (Fails open, no DB/alert) | **DEFECT CONFIRMED** |
| **TC-PROD-04** | Schema Validation / State 2 & 4 | `ThreatLog.status = 'DEGRADED'` | `allowedStatuses.includes('DEGRADED') === false` | **DEFECT CONFIRMED** |
| **TC-PROD-05** | Schema Validation / State 2 & 4 | `ThreatLog.attackType = 'UNINSPECTED_TRAFFIC'` | `allowedAttackTypes.includes('UNINSPECTED_TRAFFIC') === false` | **DEFECT CONFIRMED** |
| **TC-PROD-06** | Malformed Score / State 4 | `threatScore = null` | Score defaults to `0.0`, action defaults to `ALLOW` | **DEFECT CONFIRMED** |
| **TC-PROD-07** | Alert Schema / State 4 & 6 | `Alert.sourceRef.refModel = 'AIPrediction'` | `allowedRefModels.includes('AIPrediction') === false` | **DEFECT CONFIRMED** |
| **TC-PROD-08** | Autonomous Gating / State 1 & 3 | `score = 0.98`, `autoBlockEnabled = false` | `shouldBlock === false`, `status === 'MONITORING'` | **PASS (Nominal Safe)** |
| **TC-REM-01** | Remediated Degraded State | `status: 'DEGRADED'`, `action: 'MONITOR'` | `action === 'MONITOR'`, `status === 'DEGRADED'`, `threatStatus === 'DEGRADED'` | **PASS** |
| **TC-REM-02** | Remediated Timeout Fallback | `Error: timeout of 10000ms exceeded` | `action === 'MONITOR'`, `status === 'UNAVAILABLE'`, `alertEmitted === true` | **PASS** |
| **TC-REM-03** | Remediated Schema Enums | `status = 'DEGRADED'`, `attackType = 'UNINSPECTED_TRAFFIC'` | Enums permit both without `ValidationError` | **PASS** |
| **TC-REM-04** | Remediated Persistence Failure | Injected `MongoNetworkError` | Exception caught, emergency audit written to disk | **PASS** |
| **TC-REM-05** | Remediated Simulated Block Gating | `threatScore = 0.96`, `autoBlockEnabled = false` | `action === 'BLOCK'`, `simulatedBlock === true`, `threatStatus === 'MONITORING'` | **PASS** |

---

## 4. Execution Protocol

To independently execute and verify the regression test suite:
```powershell
node "ai-engine/experiments/gate1_phase3c_backend_safety/test_backend_safety_isolated.js"
```
The script runs in $<500\text{ ms}$, logs formatted console output for all 13 test assertions, and writes structured JSON evidence to [`backend_safety_regression_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3c_backend_safety/backend_safety_regression_results.json).
