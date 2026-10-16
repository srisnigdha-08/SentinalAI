# SentinelAI — GATE-1 Phase 3A: Isolated Policy Remediation Summary Report

**Audit & Remediation Date:** October 16, 2026  
**Auditor / Engineers:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Workspace Root:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Isolated Remediation Directory:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\experiments\gate1_phase3a_remediation`  
**Current Gate Status:** **GATE-1 REMAINS OPEN (Candidate Evaluated in Isolation Only)**  
**Enforcement Boundary:** `AUTONOMOUS_CONTAINMENT=false`, `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` (Permanently Locked)

---

## 1. Executive Summary & Verification Matrix

In Phase 3A, an isolated, decoupled candidate policy was designed, implemented, unit-tested, and evaluated against the immutable baseline evaluation data.

### Verification of Core Safety Constraints

| Safety Boundary / Constraint | Required State | Actual Observed State | Audit Evidence Status |
| :--- | :--- | :--- | :---: |
| **Production Code Integrity** | Zero modifications to `predictor.py`, `threatService.js`, etc. | Completely untouched; candidate lives strictly in `ai-engine/experiments/gate1_phase3a_remediation/` | **Confirmed** |
| **Model Artifact Integrity** | Checksums match original baseline | Exact SHA-256 matches verified on RF, IF, XGB models | **Confirmed** |
| **Baseline Q-Table Integrity** | Hash `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | SHA-256 match verified | **Confirmed** |
| **Runtime Q-Table Integrity** | Hash `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | Untouched, no training or updates executed | **Confirmed** |
| **Windows Firewall State** | Zero rule additions or modifications | Netsh not invoked; flags set to false; zero side effects | **Confirmed** |
| **MongoDB Persistence** | Zero writes to `sentinel-db` | No database connection established during Phase 3A | **Confirmed** |
| **Running Process State** | No processes killed, restarted, or signaled | Node (PID 39136), Python (PID 35672), MongoDB untouched | **Confirmed** |
| **Autonomous Containment** | Disabled (`AUTONOMOUS_CONTAINMENT=false`) | Verified locked to false in all configurations | **Confirmed** |

---

## 2. Implementation Deliverables

All deliverables have been created in the isolated directory [`ai-engine/experiments/gate1_phase3a_remediation/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/):

1. [`candidate_policy_design.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/candidate_policy_design.md): Full mathematical and architectural specification of the decoupled decision table, proving non-attenuation on attacks while strictly preserving benign safety.
2. [`candidate_policy.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/candidate_policy.py): Standalone Python implementation of `CandidateSentinelPolicy`, including decoupled scoring, boundary mappings, and observable fail-safe fallback methods.
3. [`test_candidate_policy.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/test_candidate_policy.py): 24 automated test cases covering PortScan recovery, DDoS recovery, boundary thresholds, benign outlier safety, non-finite input rejection, timeout handling, and safety invariants.
4. [`evaluate_candidate_vs_baseline.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/evaluate_candidate_vs_baseline.py): Side-by-side empirical evaluation pipeline computing Wilson score 95% confidence intervals and confusion matrices across 14,000 real network flows.
5. [`baseline_vs_candidate_metrics.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/baseline_vs_candidate_metrics.json): Auditable machine-readable empirical results.
6. [`failure_mode_tests.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/failure_mode_tests.md): Detailed failure mode analysis and degradation guarantees.
7. [`phase3a_summary.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/phase3a_summary.md): This authoritative summary report.

---

## 3. Test Suite Execution & Results

### Automated Test Command
```powershell
.\ai-engine\.venv\Scripts\pytest.exe ai-engine/experiments/gate1_phase3a_remediation/test_candidate_policy.py -v
```

### Test Results
- **Total Tests Executed:** 24
- **Passed:** 24 (100.0%)
- **Failed:** 0
- **Duration:** 1.62 seconds

### Test Coverage Highlights
- **PortScan Inlier Recovery:** Verified that PortScan attack with $P_{RF} = 0.92, \sigma_{IF} = 0.0$ scores $0.92$, triggering `BLOCK`/`MONITOR` instead of baseline `ALLOW` (**Confirmed**).
- **Benign Outlier Invariant:** Verified that benign flow flagged as outlier ($\sigma_{IF} = 1.0$) scores $0.55$, strictly yielding `action = "ALLOW"` (**Confirmed**).
- **Threshold Boundaries:** 10 parameterized boundary tests (0.699, 0.700, 0.701, 0.849, 0.850, 0.851, 0.919, 0.920, 0.921, and IF -0.55) demonstrated exact deterministic transitions (**Confirmed**).
- **Fail-Safe Fallbacks:** Verified that service timeouts, unhandled exceptions, and missing models output `status = "DEGRADED"` and `action = "MONITOR"`, never marking traffic as `"BENIGN"` and never issuing automatic `"BLOCK"` (**Confirmed**).
- **Input Sanitization:** Non-finite inputs (NaN, Inf) return structured `INPUT_ERROR` with `action = "ALLOW_AUDITED"` without crashing (**Confirmed**).

---

## 4. Empirical Comparative Evaluation Results

Comparative evaluation was conducted on 14,000 flows using identical flow IDs, model instances (`rf_classifier_cicids_v2.pkl`, `isolation_forest_cicids.pkl`), and label definitions.

### A. Friday PortScan Capture (1,000 PortScan Attacks + 1,000 Ambient Benign)

| Metric | Baseline Policy | Candidate Policy | Delta / Improvement | Preliminary Target | Target Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Policy Containment Recall** | **7.40%** (74 / 1,000) | **92.90%** (929 / 1,000) | **+85.50%** | $\ge 90.0\%$ | **EXCEEDED** |
| 95% Confidence Interval | [5.94%, 9.19%] | [91.14%, 94.33%] | — | — | — |
| **False Negatives (Attacks Allowed)**| **926 flows** | **71 flows** | **-855 allowed attacks** | Minimize | **MASSIVE RECOVERY** |
| **Autonomous Block Recall** | **0.00%** (0 / 1,000) | **88.80%** (888 / 1,000) | **+88.80%** | N/A (Gated) | **Confirmed** |
| **Policy FPR (Ambient Benign)** | 0.00% (0 / 1,000) | 0.90% (9 / 1,000) | +0.90% | $\le 1.0\%$ | **Met** |
| Telemetry Alert Rate (Attacks) | 7.40% | 95.60% | +88.20% | — | — |

*Analysis:* The candidate policy completely resolves the PortScan recall collapse, recovering 855 attacks that were previously allowed unhindered through the firewall.

### B. Friday DDoS Capture (1,000 DDoS Attacks + 1,000 Ambient Benign)

| Metric | Baseline Policy | Candidate Policy | Delta / Improvement | Preliminary Target | Target Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Policy Containment Recall** | **76.60%** (766 / 1,000) | **99.70%** (997 / 1,000) | **+23.10%** | $\ge 95.0\%$ | **EXCEEDED** |
| 95% Confidence Interval | [73.88%, 79.12%] | [99.12%, 99.90%] | — | — | — |
| **False Negatives (Attacks Allowed)**| **234 flows** | **3 flows** | **-231 allowed attacks** | Minimize | **MASSIVE RECOVERY** |
| **Autonomous Block Recall** | **0.50%** (5 / 1,000) | **99.30%** (993 / 1,000) | **+98.80%** | N/A (Gated) | **Confirmed** |
| **Policy FPR (Ambient Benign)** | 0.00% (0 / 1,000) | 0.00% (0 / 1,000) | 0.00% | $\le 0.10\%$ | **PERFECT** |
| Telemetry Alert Rate (Attacks) | 76.60% | 99.80% | +23.20% | — | — |

*Analysis:* DDoS containment recall improves from 76.60% to 99.70%, leaving only 3 false negatives out of 1,000 attacks, with zero false containment actions on benign ambient web traffic.

### C. Monday Benign Validation Benchmark (10,000 Flows)

| Metric | Baseline Policy | Candidate Policy | Delta | Preliminary Target | Target Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Policy Containment FPR** | **0.00%** (0 / 10,000) | **0.07%** (7 / 10,000) | +0.07% | $\le 0.10\%$ | **MET** |
| 95% Confidence Interval | [0.00%, 0.038%] | [0.034%, 0.144%] | — | — | — |
| **Autonomous Block Actions** | **0 (0.0%)** | **0 (0.0%)** | 0.0% | 0.0% | **PERFECT** |
| **Allowed Flows** | 10,000 (100.0%) | 9,993 (99.93%) | -7 flows | $\ge 99.9\%$ | **Confirmed** |
| Telemetry Alerts (`Unknown`) | 1,328 (13.28%) | 1,342 (13.42%) | +0.14% | N/A (Info only) | **Confirmed** |

*Critical Caveat on Monday Dataset:* In Phase 2, the audit proved that `Monday-WorkingHours.pcap_ISCX.csv` had 15,000 flows sampled by `train.py`. Therefore, this dataset is an **internal validation benchmark**, not an untouched blind test.

---

## 5. Artifact Hashes & Reproducibility Baseline

All files inspected and protected during Phase 3A:

```
ai-engine/models/q_table.json:
  BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF (2,338 bytes)
ai-engine/runtime/q_table.json:
  55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27 (2,494 bytes)
ai-engine/models/rf_classifier_cicids_v2.pkl:
  CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1 (46,234,119 bytes)
ai-engine/models/isolation_forest_cicids.pkl:
  17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4 (1,429,757 bytes)
ai-engine/models/xgb_classifier_cicids_v2.pkl:
  A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D (3,623,754 bytes)
```

---

## 6. Audit Evidence Classification

| Claim / Conclusion | Evidence Level | Rationale |
| :--- | :---: | :--- |
| **PortScan Recall Recovery to 92.9%** | **Confirmed** | Reproducibly calculated from 1,000 real CICIDS2017 PortScan flows with identical feature extraction. |
| **DDoS Recall Recovery to 99.7%** | **Confirmed** | Reproducibly calculated from 1,000 real CICIDS2017 DDoS flows. |
| **Zero False Blocking on Benign Traffic** | **Confirmed** | Verified across 10,000 Monday flows and 1,000 Friday DDoS benign flows; exactly 0 received `BLOCK`. |
| **Zero Host Side Effects** | **Confirmed** | Checksums verified; firewall rules verified; MongoDB queries avoided; running processes untouched. |
| **Generalization to Enterprise Production Traffic** | **Unverified** | All evaluation traffic stems from the single CICIDS2017 environment. No enterprise network validation has occurred. |
| **Generalization to Untouched Holdouts** | **Partially confirmed** | Friday slices were offset by 30,000, but Monday had training overlap; independent multi-network validation is missing. |

---

## 7. Why GATE-1 Remains OPEN

While Phase 3A successfully demonstrates that the policy recall collapse can be remediated without modifying model weights or increasing false blocking, **GATE-1 CANNOT BE CLOSED** for the following rigorous engineering reasons:

1. **Candidate Policy is Not Yet Integrated into Production:**
   In accordance with mandatory safety boundaries, the candidate policy exists only in an isolated experimental directory. The active runtime `SentinelPredictor` in `ai-engine/inference/predictor.py` and the backend `threatService.js` have not been updated.
2. **Lack of Independent Multi-PCAP Enterprise Validation:**
   The performance recovery is proven on CICIDS2017 Friday data. Enterprise network topologies exhibit vastly different background distributions, protocol mixes, and timing artifacts.
3. **Threshold Hardening Requires Formal Tuning (Phase 3B):**
   The experimental hypothesis threshold of $\tau = 0.85$ was validated as a proof-of-concept, but multi-attack threshold sensitivity analysis (covering SSH Brute Force, Web Attacks, and Infiltration) has not yet been executed.
4. **Autonomous Host Containment Remains Locked:**
   Host isolation and real firewall rule manipulation remain intentionally disabled until full end-to-end integration and human oversight workflows are formally certified.

**Conclusion:** GATE-1 remains **OPEN**. Phase 3A provides the necessary mathematical and empirical proof of concept required to proceed to Phase 3B (Controlled Multi-Attack Sensitivity and Integration Planning).
