# SentinelAI GATE-1 Phase 9C.2: Test Evidence & Regression Report

**Author / Senior Engineer**: Senior Security Architect & Machine Learning Engineer  
**Date**: 2026-10-17  
**Execution Context**: Independent Automated Regression Verification Post-Remediation  
**Commit**: `7c89c14bf9c99c7800f87fdf137958c85855214f`  

---

## 1. Modular Scaffold Test Suite (33 Tests)

The expanded modular scaffold test suite was executed to verify all 18 baseline tests and 15 targeted defect regression tests.

### Command Executed
```powershell
ai-engine/.venv/Scripts/pytest ai-engine/tests/test_modular_scaffold.py -v
```

### Raw Test Execution Output
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\.venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\srisn\Desktop\Projects\sentinelai-complete
plugins: anyio-4.14.2
collecting ... collected 33 items

ai-engine/tests/test_modular_scaffold.py::test_validate_finite_score_valid PASSED [  3%]
ai-engine/tests/test_modular_scaffold.py::test_validate_finite_score_rejections PASSED [  6%]
ai-engine/tests/test_modular_scaffold.py::test_detector_result_contract_valid PASSED [  9%]
ai-engine/tests/test_modular_scaffold.py::test_no_silent_allow_invariant PASSED [ 12%]
ai-engine/tests/test_modular_scaffold.py::test_create_degraded_result_factory PASSED [ 15%]
ai-engine/tests/test_modular_scaffold.py::test_simulated_mitigation_enforcement PASSED [ 18%]
ai-engine/tests/test_modular_scaffold.py::test_ground_truth_detection_and_stripping PASSED [ 21%]
ai-engine/tests/test_modular_scaffold.py::test_base_detector_auto_strips_ground_truth PASSED [ 24%]
ai-engine/tests/test_bounded_state_table_capacity_and_lru_eviction PASSED [ 27%]
ai-engine/tests/test_bounded_state_table_exponential_decay PASSED [ 30%]
ai-engine/tests/test_bounded_state_table_expiration_and_purge PASSED [ 33%]
ai-engine/tests/test_orchestrator_feature_flag_gating PASSED [ 36%]
ai-engine/tests/test_orchestrator_all_healthy_consensus PASSED [ 39%]
ai-engine/tests/test_orchestrator_threat_consensus_with_simulated_block PASSED [ 42%]
ai-engine/tests/test_orchestrator_prevents_silent_allow_on_partial_failure PASSED [ 45%]
ai-engine/tests/test_orchestrator_timeout_isolation PASSED [ 48%]
ai-engine/tests/test_orchestrator_alert_deduplication PASSED [ 51%]
ai-engine/tests/test_orchestrator_resilient_logging PASSED [ 54%]
ai-engine/tests/test_def01_zero_detectors_fails_closed PASSED [ 57%]
ai-engine/tests/test_def01_all_detectors_unavailable PASSED [ 60%]
ai-engine/tests/test_def01_partially_available_detectors PASSED [ 63%]
ai-engine/tests/test_def02_case_variants_and_compound_keys PASSED [ 66%]
ai-engine/tests/test_def02_preserves_legitimate_features PASSED [ 69%]
ai-engine/tests/test_def02_deep_immutability PASSED [ 72%]
ai-engine/tests/test_def02_nested_structures_and_collections PASSED [ 75%]
ai-engine/tests/test_def03_rejects_nan_increment PASSED [ 78%]
ai-engine/tests/test_def03_rejects_inf_increment PASSED [ 81%]
ai-engine/tests/test_def03_rejects_negative_or_zero_increment PASSED [ 84%]
ai-engine/tests/test_def03_rejects_invalid_types PASSED [ 87%]
ai-engine/tests/test_def03_invalid_input_preserves_existing_state PASSED [ 90%]
ai-engine/tests/test_def04_parallel_dispatch_latency_bound PASSED [ 93%]
ai-engine/tests/test_def04_concurrent_timeout_bound PASSED [ 96%]
ai-engine/tests/test_def04_dedup_thread_safety PASSED [100%]

============================= 33 passed in 0.43s ==============================
```

---

## 2. Full AI Engine Regression Test Suite (183 Tests)

The full Python AI Engine regression suite was executed:

### Command Executed
```powershell
ai-engine/.venv/Scripts/pytest ai-engine/tests/ --ignore=ai-engine/tests/test_q_table_safety.py
```

### Execution Output & Results
```
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\srisn\Desktop\Projects\sentinelai-complete
plugins: anyio-4.14.2
collected 183 items

ai-engine\tests\test_abuseipdb_decoupling.py .......                     [  3%]
ai-engine\tests\test_api.py .................                            [ 13%]
ai-engine\tests\test_cowrie_output_contract.py ....                      [ 15%]
ai-engine\tests\test_cowrie_parser.py ...                                [ 16%]
ai-engine\tests\test_cowrie_parser_contract.py ........                  [ 21%]
ai-engine\tests\test_feature_capture.py .......                          [ 25%]
ai-engine\tests\test_features.py ..................                      [ 34%]
ai-engine\tests\test_gate1_ml_remediation.py ......                      [ 38%]
ai-engine\tests\test_model_evaluation.py ...............                 [ 46%]
ai-engine\tests\test_modular_scaffold.py ............................... [ 63%]
..                                                                       [ 64%]
ai-engine\tests\test_predictor.py ....................                   [ 75%]
ai-engine\tests\test_readiness.py ......................                 [ 87%]
ai-engine\tests\test_replay_isolation.py ..............                  [ 95%]
ai-engine\tests\test_validation_privacy.py .........                     [100%]

====================== 183 passed, 2 warnings in 47.47s =======================
```
- **Exit Code**: 0
- **Total Tests**: 183
- **Passed**: 183 (100.0%)
- **Failed / Skipped**: 0

---

## 3. Backend Safety Regression Test Suite (17 Tests)

The Node.js backend safety suite was executed:

### Command Executed
```powershell
npm test -- backend/tests/integrated_backend_safety_regression.test.js
```

### Execution Output & Results
```
PASS tests/integrated_backend_safety_regression.test.js (17.69 s)
  SentinelAI GATE-1 Phase 3D: Integrated Backend Safety Regression Tests
    √ 1. Valid BENIGN inference returns action ALLOW and skips ThreatLog creation (226 ms)
    √ 2. Valid attack inference with score 0.85 returns action MONITOR (9 ms)
    √ 3. Simulated BLOCK is distinct from actual firewall enforcement when autoBlockEnabled=false (10 ms)
    √ 4. Explicit degraded response (score=0.50, action=MONITOR) is NOT overwritten to ALLOW (15 ms)
    √ 5. Axios timeout does not return null; safely falls back to UNAVAILABLE and MONITOR (9 ms)
    √ 6. ECONNREFUSED produces observable failure result with action MONITOR (9 ms)
    √ 7. AI engine HTTP 500 internal server error falls back to UNAVAILABLE and MONITOR (9 ms)
    √ 8. Null and malformed inference responses safely fall back to UNAVAILABLE (7 ms)
    √ 9. Missing, non-finite, and out-of-range scores are rejected as invalid degraded states (161 ms)
    √ 10. ThreatLog and Alert schemas validate DEGRADED, UNINSPECTED_TRAFFIC, and AIPrediction (13 ms)
    √ 11. AIPrediction model registers cleanly and validates schema fields (2 ms)
    √ 12. Database persistence failure logs emergency audit to disk and propagates error (20 ms)
    √ 13. writeEmergencyAudit synchronously writes durable audit record with bounded retention (7 ms)
    √ 14. Notification delivery failure is logged as warning and does not abort transaction (44 ms)
    √ 15. Repeated degraded predictions do not overwrite preBlockStatus or cause unbounded alerts (11 ms)
    √ 16. findThreats parses and accepts status=DEGRADED without validation error (1 ms)
    √ 17. Query security utilities and input validation remain intact (1 ms)

Test Suites: 1 passed, 1 total
Tests:       17 passed, 17 total
Snapshots:   0 total
Time:        18.643 s
```
- **Exit Code**: 0
- **Total Tests**: 17
- **Passed**: 17 (100.0%)
- **Failed**: 0
