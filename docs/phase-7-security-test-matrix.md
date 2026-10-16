# SentinelAI Phase 7 — Comprehensive Security Test Matrix & Verification Evidence

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Auditor / Roles:** Senior Application Security Engineer & Test Auditor  
**Project Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Integration Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration`  

---

## 1. Master Regression Execution Matrix

```
========================================================================================================================
                                      PHASE 7 MASTER REGRESSION TEST MATRIX
========================================================================================================================
Test Suite Identifier                    Domain / Component       Test Type      Exit Code Passed Failed Skipped Duration
------------------------------------------------------------------------------------------------------------------------
backend/tests/sessionInactivity.test.js   Inactivity Timeout (15m) Unit / Mock    0         11     0      0       3.25s
backend/tests/sessionConcurrencyBoundary Concurrency & Boundaries Unit / Mock    0         9      0      0       2.98s
backend/tests/gracefulShutdown.test.js    Shutdown & Request Drain Unit / Mock    0         7      0      0       1.36s
backend/tests/securityEventBus.test.js   Event Bus & Ring Buffer  Unit / Mock    0         9      0      0       0.84s
backend/tests/securityObservability.test CRLF & Durable Outbox    Unit / Mock    0         6      0      0       0.84s
backend/tests/cowrieIngest.test.js       Honeypot Bounds & Redact Unit / Mock    0         6      0      0       4.79s
backend/tests/windowsFirewallSafety.test Policy Safety & Exclus.  Unit / Mock    0         8      0      0       1.01s
backend/tests/containmentLifecycle.test  Containment State Mach.  Unit / Mock    0         37     0      0       1.54s
backend/tests/auth.test.js               Authentication Core      Unit / Mock    0         14     0      0       2.50s
backend/tests/authHardening.test.js      Replay & Brute Force     Unit / Mock    0         31     0      0       3.10s
backend/tests/internalAuth.test.js       Internal Pre-shared Key  Unit / Mock    0         6      0      0       0.90s
backend/tests/containmentPolicy.test.js  Policy Exclusions        Unit / Mock    0         28     0      0       1.50s
backend/tests/containmentAPI.test.js     Containment REST Endp.   Unit / Mock    0         3      0      0       0.80s
Remaining Backend Jest Suites (26 suites)Full Backend Regression  Unit / Mock    0         305    0      0       ~4.80s
------------------------------------------------------------------------------------------------------------------------
BACKEND JEST SUMMARY (39 Active Suites)                           Unit / Mock    0         480    0      0       28.81s
------------------------------------------------------------------------------------------------------------------------
scratch/run_disposable_tests.js (Port 27029)
  - authBrowser.test.js                  Browser Cookies & Tab    Disposable DB  0         3      0      0       9.50s
  - authPersistence.test.js              MongoDB Auth Persistence Disposable DB  0         5      0      0       8.10s
  - timezonePersistence.test.js          Timezone Preferences     Disposable DB  0         1      0      0       6.20s
  - credentialLifecycleIntegration.test  Mandatory Pwd Changes    Disposable DB  0         4      0      0       5.72s
------------------------------------------------------------------------------------------------------------------------
DISPOSABLE DB SUMMARY (Port 27029)                                Disposable DB  0         13     0      0       29.52s
------------------------------------------------------------------------------------------------------------------------
scratch/test_backup_restore.js (Port 27029)
  - Disaster Recovery Backup & Restore   BSON Snapshot & Recovery Disposable DB  0         1      0      0       4.50s
------------------------------------------------------------------------------------------------------------------------
ai-engine/tests/ (12 Pytest Suites)
  - test_model_evaluation.py             Metrics, Drift, Metadata Model / Synth  0         6      0      0       8.79s
  - test_abuseipdb_decoupling.py         Async Intel Decoupling   Synthetic      0         7      0      0       1.20s
  - test_api.py                          FastAPI Endpoints & Auth Synthetic      0         17     0      0       2.10s
  - test_cowrie_output_contract.py       Cowrie Schema Contract   Synthetic      0         4      0      0       0.80s
  - test_cowrie_parser.py                Cowrie RFC JSON Parser   Synthetic      0         3      0      0       0.70s
  - test_cowrie_parser_contract.py       Contract Validation      Synthetic      0         8      0      0       1.10s
  - test_feature_capture.py              Feature Extraction       Synthetic      0         7      0      0       1.00s
  - test_features.py                     53-Feature Vector Bounds Synthetic      0         18     0      0       1.50s
  - test_predictor.py                    Random / Isolation ForestModel / Synth  0         20     0      0       3.50s
  - test_readiness.py                    Startup Check & Lifespan Synthetic      0         22     0      0       2.80s
  - test_replay_isolation.py             Replay Safety & Bounds   Synthetic      0         14     0      0       2.00s
  - test_validation_privacy.py           Credential Scrubbing     Synthetic      0         9      0      0       1.09s
------------------------------------------------------------------------------------------------------------------------
AI ENGINE PYTEST SUMMARY (12 Suites, 135 Tests)                   Synthetic/Model0         135    0      0       26.58s
------------------------------------------------------------------------------------------------------------------------
frontend/tests/*.test.mjs (Node Test Runner)
  - Auth, Browser, Timezone, Password    Frontend Logic & State   Node Runner    0         34     0      0       0.51s
------------------------------------------------------------------------------------------------------------------------
frontend/ (Vite Production Build)
  - npm run build                        Static Asset Generation  Vite Compiler  0         Pass   0      0       5.45s
------------------------------------------------------------------------------------------------------------------------
scripts/run-vm-firewall-tests.ps1
  - Host Refusal & Dual-Marker Gating    Workstation Refusal CheckHost Execution 1*        Pass   0      0       0.80s
------------------------------------------------------------------------------------------------------------------------
GRAND TOTAL VERIFIED TESTS                                                       0         663    0      0       ~96s
========================================================================================================================
* Note: scripts/run-vm-firewall-tests.ps1 is designed to fail-closed on the developer workstation (exit code 1)
  due to missing VM markers, proving that real firewall rules cannot accidentally execute on the host.
```

---

## 2. Before-and-After Invariant Verification Audit

| Invariant Parameter | Expected Pre-Execution Baseline | Observed Post-Execution Baseline | Invariant Status |
| :--- | :--- | :--- | :--- |
| **`rf_classifier_cicids_v2.pkl` SHA256** | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **100% INVARIANT** |
| **`isolation_forest_cicids.pkl` SHA256** | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **100% INVARIANT** |
| **`q_table.json` Baseline SHA256** | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **100% INVARIANT** |
| **MongoDB `sentinel-db` Port 27017 Users** | `count: 1` (`_id: 6ad09f0ef3aee120d5062a15`) | `count: 1` (`_id: 6ad09f0ef3aee120d5062a15`) | **100% INVARIANT** |
| **MongoDB `sentinel-db` Admin authVersion**| `authVersion: 0`, `loginCount: 2` | `authVersion: 0`, `loginCount: 2` | **100% INVARIANT** |
| **MongoDB `sentinel-db` Other Collections**| `authsessions: 2`, `systemsettings: 1`, others 0 | `authsessions: 2`, `systemsettings: 1`, others 0 | **100% INVARIANT** |
| **Host Windows Firewall Rules** | Active rules matching `SentinelAI*` = 0 | Active rules matching `SentinelAI*` = 0 | **100% INVARIANT** |
| **MongoDB Process (Port 27017)** | PID `28468` (`mongod.exe`) | PID `28468` (`mongod.exe`) | **ONLINE / UNCHANGED** |
| **AI Engine Process (Port 8000)** | PID `35672` (`python.exe`) | PID `35672` (`python.exe`) | **ONLINE / UNCHANGED** |
| **Backend API Process (Port 5000)** | PID `39136` (`node.exe`) | PID `39136` (`node.exe`) | **ONLINE / UNCHANGED** |
| **Frontend Vite Process (Port 3000)** | PID `35704` (`node.exe`) | PID `35704` (`node.exe`) | **ONLINE / UNCHANGED** |
| **Disposable Test Port 27029** | Closed | Closed (freed after tests) | **CLEAN TEARDOWN** |
| **Protected Acceptance Data** | `mongodb-acceptance-20261014` untouched | `mongodb-acceptance-20261014` untouched | **100% INVARIANT** |
| **Historical Preservation Directories**| `D:\MongoPreservation*` untouched | `D:\MongoPreservation*` untouched | **100% INVARIANT** |
