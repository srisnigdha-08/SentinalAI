# SentinelAI GATE-1 Phase 4: Failure-State Regression Test Results

**Framework**: Jest v29.7.0, Node.js v24.14.0, Windows 11  
**Target Suite**: `backend/tests/integrated_backend_safety_regression.test.js`  
**Execution Timestamp**: 2026-10-16 15:04:33  
**Status**: **ALL 17 TESTS PASSED (100% Success Rate, Exit Code 0)**

---

## 1. Test Execution Summary

The integrated backend safety regression suite was executed following the Stage 1 fail-open fix in `backend/services/aiEngineService.js` and Stage 2 bounded retention fix in `backend/utils/emergencyAudit.js`.

- **Command**: `npx jest tests/integrated_backend_safety_regression.test.js --verbose`
- **Exit Code**: `0`
- **Total Duration**: 2.199 s
- **Suites**: 1 passed, 1 total
- **Tests**: 17 passed, 17 total (0 failed, 0 skipped)

---

## 2. Detailed Per-Scenario Test Results

| Test # | Scenario Description | Target Subsystem / Verification Focus | Duration | Result |
| :---: | :--- | :--- | :---: | :---: |
| **01** | Valid BENIGN inference returns action ALLOW | Pipeline routing; skips ThreatLog creation | 83 ms | **PASS** |
| **02** | Valid attack inference with score 0.85 returns MONITOR | Action Precedence Rule preserves attack alert | 7 ms | **PASS** |
| **03** | Simulated BLOCK is distinct from actual firewall rule | Dry-run containment safety (`autoBlockEnabled=false`) | 5 ms | **PASS** |
| **04** | Explicit degraded response is NOT overwritten to ALLOW | Action Precedence Rule prevents silent bypass | 6 ms | **PASS** |
| **05** | Axios timeout safely falls back to UNAVAILABLE & MONITOR | Network timeout fault tolerance | 6 ms | **PASS** |
| **06** | ECONNREFUSED produces observable failure with MONITOR | Service outage fault tolerance | 5 ms | **PASS** |
| **07** | AI engine HTTP 500 error falls back to UNAVAILABLE | Python microservice crash handling | 16 ms | **PASS** |
| **08** | Null and malformed inference responses safely handled | Payload validation fault tolerance | 5 ms | **PASS** |
| **09** | **Missing, non-finite, and out-of-range scores rejected** | **Fail-open remediation (NaN, Inf, strings, <0, >1)** | **31 ms** | **PASS** |
| **10** | Schemas validate DEGRADED, UNINSPECTED_TRAFFIC, AIPrediction | Mongoose schema enum extension | 8 ms | **PASS** |
| **11** | AIPrediction model registers cleanly and validates schema | Model registration & BSON ObjectId integrity | 1 ms | **PASS** |
| **12** | Database persistence failure logs emergency audit to disk | Dual-persistence fallback invocation | 8 ms | **PASS** |
| **13** | **writeEmergencyAudit flushes with bounded retention** | **Hardware fsyncSync & pruning oldest archives ($\le 5$)** | **5 ms** | **PASS** |
| **14** | Notification delivery failure logged as warning | WebSocket non-blocking resilience | 16 ms | **PASS** |
| **15** | Repeated degraded predictions preserve preBlockStatus | State machine idempotency | 4 ms | **PASS** |
| **16** | findThreats parses and accepts status=DEGRADED | REST API query parsing & filtering | 1 ms | **PASS** |
| **17** | Query security utilities and input validation intact | Regex escape, pagination, IP validation | 1 ms | **PASS** |

---

## 3. Deep-Dive on Test 9 (Fail-Open Defect Remediation)

Test 9 was expanded into 10 explicit sub-assertions verifying that no malformed score can ever fail open to `ALLOW`:

1. **Sub-case 9A (Score > 1)**: `threatScore = 1.5` -> Rejected. Emits warning `[AI Pipeline] Invalid threatScore received (1.5)`. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
2. **Sub-case 9B (Score < 0)**: `threatScore = -0.5` -> Rejected. Emits warning `[AI Pipeline] Invalid threatScore received (-0.5)`. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
3. **Sub-case 9C (Literal `NaN`)**: `threatScore = NaN` -> Rejected. Emits warning `[AI Pipeline] Invalid threatScore received (NaN)`. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
4. **Sub-case 9D (Infinities)**: `threatScore = Infinity` and `-Infinity` -> Rejected. Emits warnings. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
5. **Sub-case 9E (Non-numeric string)**: `threatScore = 'invalid_nan'` -> Rejected. Emits warning `[AI Pipeline] Invalid threatScore received (invalid_nan)`. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
6. **Sub-case 9F (Missing/Null)**: `threatScore = undefined` and `null` -> Rejected. Emits warnings. Falls back to `UNINSPECTED_TRAFFIC (50%) -> MONITOR [DEGRADED]`. (**PASS**)
7. **Sub-case 9G (Valid numeric string)**: `threatScore = '0.85'` -> Valid. Preserved as numeric `0.85`, classified as `Port Scan (85%) -> MONITOR`. (**PASS**)
8. **Sub-case 9H (Valid boundary 0)**: `threatScore = 0` -> Valid. Classified as `BENIGN (0%) -> ALLOW`. (**PASS**)
9. **Sub-case 9I (Valid boundary 1)**: `threatScore = 1` -> Valid. Classified as `DDoS (100%) -> BLOCK`. (**PASS**)

---

## 4. Multi-Suite Regression Execution Evidence

Following code edits, all five backend suites were executed concurrently:

```bash
npx jest tests/integrated_backend_safety_regression.test.js \
         tests/aiDependencyContract.test.js \
         tests/containmentPolicy.test.js \
         tests/querySecurity.test.js \
         tests/securityEventBus.test.js --verbose
```

### Result:
- **Test Suites**: 5 passed, 5 total
- **Tests**: **78 passed, 78 total (0 failed, 0 skipped)**
- **Duration**: 2.729 s
- **Cryptographic Asset Integrity**: All 5 protected assets verified with 0 bytes drift before and after test execution.
- **Database Safety Guard**: Verified active. Zero connections to live `sentinel-db`.
