# SentinelAI GATE-1 — Master Defect Register
**Document Version:** 1.0.0  
**Phase:** Gate-1 Master Completion  
**Auditor:** Senior Security Architect & Independent QA Lead  
**Status:** COMPLETE (All Registered Defects Remediated or Accounted)

---

## 1. Summary of Defect Classifications
| Defect ID | Severity | Component | Summary | Remediation Status |
|---|---|---|---|---|
| **DEF-01** | CRITICAL | Modular Orchestrator | Zero-detector / empty pipeline returned verified `ALLOW` on uninspected traffic | **RESOLVED & VERIFIED** |
| **DEF-02** | HIGH | Sanitizer / Contracts | Incomplete ground-truth label stripping allowed mixed-case & compound label leaks | **RESOLVED & VERIFIED** |
| **DEF-03** | HIGH | State Table | Non-finite ($NaN$, $\pm\infty$) & negative increments corrupted connection state scores | **RESOLVED & VERIFIED** |
| **DEF-04** | MEDIUM | Orchestrator | Sequential detector execution caused timeout violation; dedup race condition | **RESOLVED & VERIFIED** |
| **DEF-05** | CRITICAL | Orchestrator | Unbounded worker pool queue accumulation under detector timeouts ($N_{queue} \to \infty$) | **RESOLVED & VERIFIED** |
| **C-07** | HIGH | Evaluation Protocol | Phase 8 "100% Web Attack recall" was simulated by reading parquet `Label` column | **AUDITED & DOCUMENTED** |

---

## 2. Technical Defect Details and Remediations

### 2.1 DEF-01: Silent ALLOW on Uninspected Traffic
- **Root Cause:** In the initial scaffold draft, when `len(self._detectors) == 0` or when all detectors failed to initialize, the consensus policy defaulted to `PolicyDecision.ALLOW` with `confidence=0.0`.
- **Security Impact:** Complete security bypass; uninspected network packets were permitted through the perimeter without evaluation.
- **Remediation Implemented:**
  - `orchestrator.py` lines 343–375: If no detectors are registered or all detectors report `UNAVAILABLE`/`ERROR`, the orchestrator returns `status=DetectorStatus.UNAVAILABLE`, `overall_decision=PolicyDecision.MONITOR`, `simulated_block=False`, `summary_evidence="Zero active detectors available"`.
- **Verification:** Covered by 3 unit tests in `test_modular_scaffold.py`: `test_def01_zero_detectors_fails_closed`, `test_def01_all_detectors_unavailable`, `test_def01_partially_available_detectors`. All pass.

### 2.2 DEF-02: Ground-Truth Label Leakage
- **Root Cause:** Sanitizer stripped only literal `"Label"` and `"Attack"` keys. Case variants (`"label"`, `"LABEL"`, `"Ground_Truth_Label"`, `"y_true"`) or nested dictionary keys bypassed sanitization.
- **Security Impact:** Classifiers or heuristics could inspect actual benchmark labels during evaluation, creating fraudulent 100% recall metrics.
- **Remediation Implemented:**
  - `sanitizer.py`: Implemented case-normalized, recursively deep key inspection against a blacklist of 40+ known label patterns, paired with a strict whitelist of the 53 authorized CICFlowMeter feature names.
- **Verification:** Covered by 4 unit tests in `test_modular_scaffold.py`: `test_def02_case_variants_and_compound_keys`, `test_def02_preserves_legitimate_features`, `test_def02_deep_immutability`, `test_def02_nested_structures_and_collections`. All pass.

### 2.3 DEF-03: Stateful Score Corruption from Non-Finite Inputs
- **Root Cause:** `BoundedConnectionStateTable.record_attempt()` performed math on `increment` before checking validity. Passing `NaN` or `Inf` permanently poisoned `decayed_score` to `NaN`, preventing future scoring.
- **Security Impact:** Denial-of-service against stateful brute-force tracking via malicious telemetry injection.
- **Remediation Implemented:**
  - `state.py`: Implemented `_validate_numeric_increment()` which verifies that increment is a real number, finite (`math.isfinite`), and strictly positive ($> 0$). Invalid inputs raise `ValueError` prior to acquiring the lock or altering table entries.
- **Verification:** Covered by 5 unit tests in `test_modular_scaffold.py`: `test_def03_rejects_nan_increment`, `test_def03_rejects_inf_increment`, `test_def03_rejects_negative_or_zero_increment`, `test_def03_rejects_invalid_types`, `test_def03_invalid_input_preserves_existing_state`. All pass.

### 2.4 DEF-04: Dispatch Concurrency and Mutex Isolation
- **Root Cause:** Detectors were executed sequentially in a single thread, causing composite pipeline latency to scale linearly with detector count and easily exceed the 50 ms budget. Alert de-duplication table had unprotected concurrent access.
- **Security Impact:** Latency degradation; race conditions resulting in duplicated or dropped alerts.
- **Remediation Implemented:**
  - Parallel submission via `ThreadPoolExecutor` with per-detector timeout isolation.
  - Re-entrant mutex (`threading.RLock()`) protecting the alert de-duplication map.
- **Verification:** Covered by 3 unit tests in `test_modular_scaffold.py`: `test_def04_parallel_dispatch_latency_bound`, `test_def04_concurrent_timeout_bound`, `test_def04_dedup_thread_safety`. All pass.

### 2.5 DEF-05: Unbounded Worker Pool Queue Accumulation Under Timeout
- **Root Cause:** When detectors timed out after 50 ms, the orchestrator returned a `TIMEOUT` finding, but the underlying worker threads continued running. Subsequent requests queued in `_work_queue` indefinitely without capacity checks. Under sustained traffic, the queue grew unbounded (+28 tasks across 8 requests in preflight testing).
- **Security Impact:** Thread starvation, memory exhaustion, and cascading host collapse.
- **Remediation Implemented:**
  - Enforced a hard ceiling on total in-flight work: `max_pending_tasks = 16` (running threads + queued items).
  - Implemented `TaskSlot` tracking with strict mutex reservation and exactly-once release.
  - If capacity is exhausted, the orchestrator immediately fast-fails without queueing, returning `status=UNAVAILABLE`, `overall_decision=MONITOR`, `reason=WORKER_POOL_SATURATED` in $\le 1$ ms.
  - On request timeout, unstarted futures are proactively cancelled and pruned from `_work_queue` via `_prune_cancelled_tasks()`.
- **Verification:** Covered by 8 unit tests in `test_modular_scaffold.py` (`test_def05_*`). All pass.

### 2.6 Audit Finding C-07: Phase 8 Web Attack Ground-Truth Leakage Simulation
- **Root Cause:** Phase 8 evaluation script (`run_phase8_experiments.py` lines 339–358) bypassed Layer 7 payload parsing and set `t2_det = True` if the row's `ground_truth_label` in the parquet was `"SQL Injection"` or `"XSS Attempt"`.
- **Security Impact:** Reported 100% web attack recall was an architectural simulation, masking the fact that transport ML achieved only 0.35% recall.
- **Remediation Implemented:**
  - Full disclosure in Phase 9A and Master Evaluation reports.
  - Implementation of true `Layer7WAFDetector` (`modular/layer7_waf.py`) that performs actual regex signature and URL decoding on HTTP strings.
  - Verified that CSE-2018 holdout parquets lack Layer 7 payload strings, and documented this dataset gap as an authoritative blocker for Gate-1 closure.
