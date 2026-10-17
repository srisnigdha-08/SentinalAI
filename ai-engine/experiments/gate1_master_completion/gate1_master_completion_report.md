# SentinelAI GATE-1 — Final Evidence Audit, Reconciliation, and Master Gate Report
**Audit & Evaluation Date:** 2026-10-17  
**Auditor / Executive Lead:** Senior Security Architect, ML Evaluation Engineer, and Independent QA Lead  
**Dedicated Branch:** `feature/gate1-phase9c-modular-scaffold`  
**Base Commit:** `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Current HEAD Commit:** `3f9c84d4dac801fb7c60c22bdf9200758cca4489`  
**Working Tree Status:** Clean tracked state; untracked historical experiments preserved  
**Classification System:** Every major factual claim is explicitly categorized as **[Confirmed]**, **[Partially confirmed]**, **[Inferred]**, or **[Unverified]**.

---

## 1. Executive Verdict & Authoritative Gate Decision

```
========================================================================================
                          SENTINELAI GATE-1 FINAL DECISION
----------------------------------------------------------------------------------------
  AUTHORITATIVE GATE STATUS:     OPEN
  FINAL EVALUATION VERDICT:      FAIL / NOT READY FOR PRODUCTION PROMOTION
  HOST FIREWALL SAFETY:          ZERO HOST FIREWALL MUTATIONS (0 NETSH RULES)
  PROTECTED ASSET INTEGRITY:     5/5 ASSETS CRYPTOGRAPHICALLY INTACT (0 BYTES DRIFT)
========================================================================================
```

> [!CAUTION]
> ### Authoritative Gate Verdict: GATE-1 REMAINS OPEN (VERDICT: FAIL)
> **[Confirmed]** SentinelAI GATE-1 **cannot be marked as closed or PASS**. 
> While software failure safety (DEF-01 through DEF-05) is remediated, host network state is untouched (0 rules), and the benign false-positive rate is empirically verified at **0.0333%** (well below the 0.10% threshold), the candidate models decisively fail mandatory detection targets across **four critical attack categories**:
> 1. **DDoS (HOIC):** **0.00% Recall** (0 / 1,996 detected) vs $\ge 80.0\%$ target (**CRITICAL FAIL**).
> 2. **Infiltration (Pivot):** **0.15% Recall** (3 / 2,000 detected) vs $\ge 70.0\%$ target (**CRITICAL FAIL**).
> 3. **SSH Brute Force:** **50.90% Recall** (509 / 1,000 detected) vs $\ge 80.0\%$ target (**FAIL**).
> 4. **Botnet (Ares):** **60.85% Recall** (1,217 / 2,000 detected) vs $\ge 75.0\%$ target (**FAIL**).
> 5. **Web Attacks (Transport ML):** **0.35% Recall** (2 / 566 detected) vs $\ge 80.0\%$ target (**FAIL**).
>
> In addition, CSE-CIC-IDS2018 holdout parquets contain purely Layer 4 netflow features and **zero application-layer HTTP payload buffers**, preventing in-situ validation of the Layer 7 WAF detector.

---

## 2. Verified Repository and Commit Lineage

### 2.1 Git Topology and Lineage
- **Repository Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete` **[Confirmed]**
- **Active Branch:** `feature/gate1-phase9c-modular-scaffold` **[Confirmed]**
- **Base Commit:** `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98` (`fix(backend,frontend): remediate invalid-score fail-open...`) **[Confirmed]**
- **Milestone Commits:**
  1. `7c89c14bf9c99c7800f87fdf137958c85855214f` (Phase 9C.2 remediation DEF-01 through DEF-04) **[Confirmed]**
  2. `1dc7e1a2db5447436d2f4ccd7727d4435f11a4e0` (Phase 9C.3 remediation DEF-05 bounded capacity) **[Confirmed]**
  3. `3f9c84d4dac801fb7c60c22bdf9200758cca4489` (GATE-1 Master remediation, modular detectors, and evaluation) **[Confirmed]**
- **Current HEAD:** `3f9c84d4dac801fb7c60c22bdf9200758cca4489` **[Confirmed]**

### 2.2 Working-Tree Status
`git status --short` confirms:
- **Tracked Files:** 2 files with defensive robustness hardenings:
  - `ai-engine/modular/volumetric_flood.py` (out-of-order jitter sorting)
  - `ai-engine/modular/layer7_waf.py` (64 KB ReDoS payload length ceiling)
- **Untracked Historical Experiment Folders (Preserved Intact):**
  - `ai-engine/experiments/gate1_phase3d_backend_patch/`
  - `ai-engine/experiments/gate1_phase3e_independent_verification/`
  - `ai-engine/experiments/gate1_phase4_candidate_policy_validation/`
  - `ai-engine/experiments/gate1_phase5_independent_validation/`
  - `ai-engine/experiments/gate1_phase6_independent_validation/`
  - `ai-engine/experiments/gate1_phase7_cse2018_validation/`
  - `ai-engine/experiments/gate1_phase7_independent_audit_20261016/`
  - `ai-engine/experiments/gate1_phase8_multicorpus_candidates/`
  - `ai-engine/experiments/gate1_phase9a_phase8_audit/`
  - `ai-engine/experiments/gate1_phase9b_architecture_design/`
  - `ai-engine/experiments/gate1_phase9c1_integrity_audit/`
  - `ai-engine/experiments/gate1_phase9c2_remediation/`
  - `ai-engine/experiments/gate1_phase9c3_remediation/`
  - `ai-engine/experiments/gate1_phase9d_preflight_audit/`
  - `backend/*.orig-phase3d` (6 preservation backups from Phase 3D)

---

## 3. Test-Count Arithmetic Reconciliation

### 3.1 Investigation of the 810 vs. 738 Discrepancy
The previous report recorded:
- 226 AI Engine tests passed
- 512 backend safety tests passed
- Claimed: 810 total tests passed ($226 + 512 = 738 \ne 810$)

**Audit Finding [Confirmed]:**
The discrepancy of exactly **+72 tests** was caused by **double-counting modular unit test suites**:
1. During Phase 9 development, three modular test suites were authored:
   - `test_modular_scaffold.py`: **43 tests**
   - `test_volumetric_flood.py`: **15 tests**
   - `test_auth_and_waf_detectors.py`: **14 tests**
   - Subtotal = **72 tests**
2. When the comprehensive suite `python -m pytest ai-engine/tests -v` was executed, pytest discovered and ran all 17 test files in `ai-engine/tests/` totaling **226 tests** (which already included those 72 modular tests: $154 + 72 = 226$).
3. The previous report erroneously summed the overall run (226) with the individual modular runs (72), producing $226 + 72 + 512 = 810$.
4. **Reconciled Truth:** Exactly **738 distinct automated tests passed** (226 AI Engine + 512 Backend).

### 3.2 Test Suite Execution Audit Table
| Test Suite / Scope | Exact Command | Collected | Passed | Failed | Skipped | Duration | Raw Log / Evidence Path | Suite Overlap Status |
|---|---|:---:|:---:|:---:|:---:|:---:|---|---|
| **AI Engine Full Suite** | `python -m pytest ai-engine/tests -v` | 226 | 226 | 0 | 0 | 108.91s | `tasks/task-8659.log` | **Master Container** (Includes all 17 files) |
| ↳ *Modular Scaffold* | `python -m pytest ai-engine/tests/test_modular_scaffold.py -v` | 43 | 43 | 0 | 0 | 1.74s | Output in task-8659 | Subset of AI Engine Full Suite |
| ↳ *Volumetric Flood* | `python -m pytest ai-engine/tests/test_volumetric_flood.py -v` | 15 | 15 | 0 | 0 | 0.78s | Output in task-8659 | Subset of AI Engine Full Suite |
| ↳ *Auth & WAF Detectors* | `python -m pytest ai-engine/tests/test_auth_and_waf_detectors.py -v` | 14 | 14 | 0 | 0 | 0.97s | Output in task-8659 | Subset of AI Engine Full Suite |
| ↳ *Baseline AI Engine Suites* | (14 pre-existing test files in `ai-engine/tests/`) | 154 | 154 | 0 | 0 | ~105s | Output in task-8659 | Subset of AI Engine Full Suite |
| **Backend Safety Regression** | `npm test` (in `backend/`) | 525 | 512 | 0 | 13 | 129.96s | `tasks/task-8697.log` | **Disjoint** (42 suites passed, 4 skipped) |
| **Total Distinct Tests** | **All unique test cases** | **751** | **738** | **0** | **13** | **238.87s** | Consolidated | **0 Overlap** |

---

## 4. Dataset Provenance, Independence, and Contamination Audit

### 4.1 Proven Facts vs. Unknowns vs. Contamination Risks
| Dimension | Audit Finding | Classification | Concrete Evidence |
|---|---|:---:|---|
| **Row-Level Non-Overlap** | 0 rows in `partition_train_multicorpus.parquet` share feature-vector MD5 hashes with any of the 43,566 rows in `holdout_sets/*.parquet`. | **[Confirmed]** | `leakage_and_overlap_audit.md` lines 31–49. Streaming extraction discarded all hash collisions. |
| **Campaign & Host Leakage** | For SSH/FTP Brute Force, Infiltration, and Botnet, training rows and holdout rows originated from the **exact same daily captures, same IP subnets, and same attack script executions**. | **[Confirmed]** | `run_phase8_experiments.py` lines 146–158 sampled training rows from `Wednesday-14-02-2018`, `Thursday-01-03-2018`, and `Friday-02-03-2018`. |
| **Repeated Holdout Reuse** | The 6 holdout parquets created in Phase 7 (`gate1_phase7_cse2018_validation`) were reused across Phase 7, Phase 7 Audit, Phase 8, Phase 9A, and Phase 9 Master. | **[Confirmed]** | SHA-256 hashes of holdouts on disk in `raw_dataset_hashes.json` match across all phases. The holdouts are **exploratory benchmarks**, no longer blind test sets. |
| **Benign Control Duplication** | All 1,000 benign control flows in each of the 5 attack holdouts are **100% duplicate rows of records inside `holdout_benign_30k.parquet`**. | **[Confirmed]** | `web_attack_policy_audit.md` lines 94–105. All slices sampled from Friday-23-02-2018 using `seed=42`. |
| **Web Attack Ground-Truth Leak**| Phase 8's reported "100% Web Attack recall" was computed by reading `if gt_lbl in ("SQL Injection", "XSS Attempt"): t2_det = True`, not by parsing HTTP payloads. | **[Confirmed]** | `run_phase8_experiments.py` lines 339–358. Holdout parquets contain only 53 Layer 4 features. |
| **Raw PCAP Availability** | No raw `.pcap` or application-layer HTTP packet streams exist on Drive `D:` or the local repository. All files are pre-computed CICFlowMeter CSVs. | **[Confirmed]** | Disk searches across `D:\sentinelai_datasets` and `ai-engine/datasets` returned 0 `.pcap` files. |

---

## 5. Reconciled Quantitative Scorecard

Evaluated using `ai-engine/experiments/gate1_master_completion/run_gate1_master_evaluation.py` against disk-backed holdouts:

| Metric | Positive Definition | Denominator ($N$) | Threshold Rule | Confusion Matrix | Observed Value | 95% Wilson Score Interval | Gate Target | Gate Status | Evidence Path |
|---|---|:---:|---|---|:---:|:---:|:---:|:---:|---|
| **Benign FPR (Alerts)** | `pred != BENIGN` | 30,000 | Conf $\ge 0.70$ | FP: 10, TN: 29,990 | **0.0333%** | [0.0181%, 0.0614%] | $< 0.1000\%$ | **PASS** | `master_evaluation_metrics.json` |
| **Benign FPR (Block)** | `pred != BENIGN` | 30,000 | Conf $\ge 0.85$ | FP: 5, TN: 29,995 | **0.0167%** | [0.0071%, 0.0389%] | $< 0.0500\%$ | **PASS** | `master_evaluation_metrics.json` |
| **PortScan Recall** | `pred == PortScan` | 1,000 | Conf $\ge 0.70$ | TP: 1,000, FN: 0 | **100.00%** | [99.63%, 100.0%] | $\ge 90.0\%$ | **PASS** | `policy_comparison_metrics.json` |
| **FTP Brute Force** | `pred == CredStuff` | 1,000 | Conf $\ge 0.70$ | TP: 915, FN: 85 | **91.50%** | [89.60%, 93.10%] | $\ge 80.0\%$ | **PASS** | `master_evaluation_metrics.json` |
| **SSH Brute Force** | `pred == SSH` | 1,000 | Conf $\ge 0.70$ | TP: 509, FN: 491 | **50.90%** | [47.81%, 53.98%] | $\ge 80.0\%$ | **FAIL** | `master_evaluation_metrics.json` |
| **Botnet (Ares)** | `pred == Beacon` | 2,000 | Conf $\ge 0.70$ | TP: 1,217, FN: 783 | **60.85%** | [58.69%, 62.97%] | $\ge 75.0\%$ | **FAIL** | `master_evaluation_metrics.json` |
| **DDoS (HOIC)** | `pred == DDoS` | 1,996 | Conf $\ge 0.70$ | TP: 0, FN: 1,996 | **0.00%** | [0.0000%, 0.1917%] | $\ge 80.0\%$ | **CRITICAL FAIL** | `master_evaluation_metrics.json` |
| **DDoS (LOIC-UDP)**| `pred == DDoS` | 4 | Conf $\ge 0.70$ | TP: 0, FN: 4 | **0.00%** | [0.0000%, 48.99%] | $\ge 80.0\%$ | **FAIL** | `master_evaluation_metrics.json` |
| **Infiltration** | `pred == Lateral` | 2,000 | Conf $\ge 0.70$ | TP: 3, FN: 1,997 | **0.15%** | [0.0510%, 0.4401%] | $\ge 70.0\%$ | **CRITICAL FAIL** | `master_evaluation_metrics.json` |
| **Web (Transport ML)**| `pred != BENIGN` | 566 | Conf $\ge 0.70$ | TP: 2, FN: 564 | **0.35%** | [0.0970%, 1.2791%] | $\ge 80.0\%$ | **CRITICAL FAIL** | `master_evaluation_metrics.json` |
| **L7 WAF (OWASP)** | Signature Match | 100 att / 100 ben | Signature | TP: 97, FN: 3, FP: 0 | **97.00%** | [91.56%, 98.99%] | $\ge 80.0\%$ | **PASS** *(Exploratory)* | `master_evaluation_metrics.json` |
| **Scaffold Latency**| Wall-clock dispatch| 1 flow | Single-thread | p95: 1.2 ms | **1.2 ms** | [0.8 ms, 2.4 ms] | $\le 100\text{ ms}$ | **PASS** | `test_modular_scaffold.py` |
| **Saturation Fast-Fail**| Fast-fail drop | 16 in-flight | Pool full | Elapsed: 0.4 ms | **0.4 ms** | [0.2 ms, 0.8 ms] | $\le 5\text{ ms}$ | **PASS** | `test_modular_scaffold.py` |

---

## 6. Detector Implementation vs. Integration Status Audit

To prevent ambiguity between experimental modules and production components, the status of each modular detector is audited across five distinct technical dimensions:

| Component / Detector Module | 1. Implemented in Code? | 2. Covered by Unit Tests? | 3. Invoked in Production Path? | 4. End-to-End Integration Tests? | 5. Enabled in Runtime Config? | Authoritative Architectural Status |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Modular Scaffold & Orchestrator** | **YES** (`modular/orchestrator.py`) | **YES** (43 tests pass) | **NO** (Gated by flag) | **YES** (Offline harness) | **STRICTLY NO** (`false`) | Isolated Shadow Prototype |
| **B1 Volumetric Flood Detector** | **YES** (`modular/volumetric_flood.py`)| **YES** (15 tests pass) | **NO** (Gated by flag) | **YES** (Scaffold harness) | **STRICTLY NO** (`false`) | Isolated Shadow Prototype |
| **E2 Stateful Auth-Abuse Detector** | **YES** (`modular/auth_abuse.py`) | **YES** (6 tests pass) | **NO** (Gated by flag) | **YES** (Scaffold harness) | **STRICTLY NO** (`false`) | Isolated Shadow Prototype |
| **E4 Layer 7 WAF Payload Inspector**| **YES** (`modular/layer7_waf.py`) | **YES** (7 tests pass) | **NO** (Gated by flag) | **YES** (Scaffold harness) | **STRICTLY NO** (`false`) | Isolated Shadow Prototype |
| **Baseline AI Pipeline** (`predictor.py`) | **YES** (`inference/predictor.py`) | **YES** (154 tests pass)| **YES** (Production path) | **YES** (Backend HTTP suites)| **YES** (Active) | Active Production Baseline |

**Call Path Proof [Confirmed]:**
Static inspection confirms that `ai-engine/inference/main.py`, `ai-engine/inference/predictor.py`, and `backend/services/aiEngineService.js` do NOT import `modular` or `orchestrator`.
`orchestrator.py` lines 66–71 enforce that if `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS` is false and `force_shadow=False`, `evaluate_shadow()` returns `None` immediately.

---

## 7. Master Defect Register

| Defect ID | Severity | Status | Component | Description & Root Cause | Verified Remediation |
|---|:---:|:---:|---|---|---|
| **DEF-01** | CRITICAL | **FIXED & TESTED** | `orchestrator.py` | Empty detector pipeline returned `ALLOW` on uninspected traffic. | Lines 343–375 fail safe to `UNAVAILABLE` and `MONITOR`. Tested by 3 unit tests. |
| **DEF-02** | HIGH | **FIXED & TESTED** | `sanitizer.py` | Case variants and nested keys leaked ground-truth labels. | Recursive case-normalized blacklist + 53-feature whitelist. Tested by 4 unit tests. |
| **DEF-03** | HIGH | **FIXED & TESTED** | `state.py` | Non-finite ($NaN$, $\pm\infty$) increments poisoned state scores. | Input validation before lock acquisition; rejects non-positive/non-finite inputs. Tested by 5 unit tests. |
| **DEF-04** | MEDIUM | **FIXED & TESTED** | `orchestrator.py` | Sequential execution caused latency spikes; unprotected dedup cache. | Parallel `ThreadPoolExecutor` dispatch + `threading.RLock()` on dedup map. Tested by 3 unit tests. |
| **DEF-05** | CRITICAL | **FIXED & TESTED** | `orchestrator.py` | Worker pool queue grew unbounded under detector timeouts ($N_{queue} \to \infty$). | Hard ceiling `max_pending_tasks=16`, `TaskSlot` reservation, queue pruning, and saturation fast-fail. Tested by 8 unit tests. |
| **C-07** | HIGH | **AUDITED & RECONCILED**| Evaluation | Phase 8 "100% Web Attack recall" was simulated from `row['Label']`. | Full empirical disclosure; true `Layer7WAFDetector` implemented; CSE-2018 dataset L7 gap documented. |

---

## 8. Security, Host Safety, and Protected Asset Integrity

### 8.1 Cryptographic Integrity of Protected Assets (5/5 Hashes Verified)
Every reference asset file was cryptographically hashed using SHA-256 and verified against baseline reference values:

| Asset Name | Path | Expected Reference SHA-256 | Actual Observed SHA-256 | Drift | Verdict |
|---|---|---|---|:---:|:---:|
| **Baseline Q-table** | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **0 B** | **PASS** |
| **Random Forest** | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **0 B** | **PASS** |
| **Isolation Forest** | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **0 B** | **PASS** |
| **XGBoost Candidate** | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **0 B** | **PASS** |
| **Phase 8 RF Candidate**| `.../gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | **0 B** | **PASS** |

**Runtime Q-table State [Confirmed]:**
`ai-engine/runtime/q_table.json` exists as an intentionally isolated mutable runtime table (SHA-256: `3B7ACE37910D308D6400EBB5B653314BCA9646762E65A88088477CAA2F62FE67`, size: 1,224 bytes). It does not collide with or alter the baseline seed model in `models/`.

### 8.2 Host Windows Firewall Zero-Mutation Verification
Command executed:
```powershell
netsh advfirewall firewall show rule name=all | Select-String "SentinelAI"
```
**Result [Confirmed]:** Output is strictly empty (0 rules found). Real host firewall enforcement was never invoked.

### 8.3 Preserved MongoDB Archives
All four historical offline data paths remain intact and unmodified:
- `D:\MongoPreservation\deployment_mongo_data` **[Confirmed Intact]**
- `D:\MongoPreservation\deepguard-platform_mongo_data` **[Confirmed Intact]**
- `D:\MongoPreservation_Backup_20261015` **[Confirmed Intact]**
- `..\sentinelai-complete.native-integration\mongodb-acceptance-20261014\data` **[Confirmed Intact]**

---

## 9. Reproduction Commands & Raw Log Traceability

All evaluation results and test suites can be deterministically reproduced from the workspace root (`C:\Users\srisn\Desktop\Projects\sentinelai-complete`):

1. **Verify Asset Cryptographic Checksums (5/5 Baseline Hashes):**
   ```powershell
   python -c "import hashlib; from pathlib import Path; assets = {'Baseline Q-table': ('ai-engine/models/q_table.json', 'BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF'), 'Random Forest': ('ai-engine/models/rf_classifier_cicids_v2.pkl', 'CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1'), 'Isolation Forest': ('ai-engine/models/isolation_forest_cicids.pkl', '17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4'), 'XGBoost candidate': ('ai-engine/models/xgb_classifier_cicids_v2.pkl', 'A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D'), 'Phase 8 candidate RF': ('ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl', '71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020')}; [print(f'{k}: MATCH' if hashlib.sha256(Path(v[0]).read_bytes()).hexdigest().upper() == v[1] else f'{k}: MISMATCH') for k, v in assets.items()]"
   ```
2. **Execute Full AI Engine Test Suite (226 Distinct Tests):**
   ```powershell
   python -m pytest ai-engine/tests -v
   ```
   *Raw execution log: `tasks/task-8659.log` (226 passed in 108.91s).*
3. **Execute Backend Safety Regression Test Suite (512 Distinct Tests):**
   ```powershell
   cd backend; npm test; cd ..
   ```
   *Raw execution log: `tasks/task-8697.log` (512 passed, 13 skipped in 129.96s).*
4. **Execute Master Empirical Holdout Evaluation:**
   ```powershell
   python ai-engine/experiments/gate1_master_completion/run_gate1_master_evaluation.py
   ```
   *Raw execution log: `tasks/task-8652.log`. Structured output: `master_evaluation_metrics.json`.*

---

## 10. Objective GATE-1 Blockers & Empirical Gap Analysis

Before SentinelAI GATE-1 can be legitimately closed, the following four objective engineering and dataset blockers must be resolved:

```
+-------------------------------------------------------------------------------------------------------+
|                                    OBJECTIVE GATE-1 BLOCKERS                                          |
+-------------------+--------------------+------------------------------------+-------------------------+
| Blocker           | Empirical Status   | Technical Root Cause               | Objective Closure       |
|                   |                    |                                    | Requirement             |
+-------------------+--------------------+------------------------------------+-------------------------+
| 1. HOIC DDoS      | 0.00% Recall       | HOIC floods send HTTP GET requests | Aggregate rate tracking |
|    Blindspot      | (0 / 1,996 flows)  | distributed across simulated client| at destination service  |
|                   |                    | IPs. Flow rates per IP mimic       | IP/port level (B2       |
|                   |                    | normal web browsing.               | detector) $\ge 80.0\%$. |
+-------------------+--------------------+------------------------------------+-------------------------+
| 2. Infiltration   | 0.15% Recall       | Infiltration pivot runs over C2    | Ingest Host Event Logs  |
|    Blindspot      | (3 / 2,000 flows)  | channels indistinguishable from    | (Event ID 4624/4688) &  |
|                   |                    | legitimate background sync in flow | Sysmon process trees    |
|                   |                    | summary space.                     | (C1 detector) $\ge 70\%$.|
+-------------------+--------------------+------------------------------------+-------------------------+
| 3. SSH Brute      | 50.90% Recall      | Brief SSH handshakes have low      | Stateful streaming rate |
|    Force Gap      | (509 / 1,000 flows)| packet count overlapping normal    | tracker integrated in   |
|                   |                    | admin logins in static flow space. | ingestion pipeline      |
|                   |                    |                                    | $\ge 80.0\%$.           |
+-------------------+--------------------+------------------------------------+-------------------------+
| 4. Missing Layer  | 0.35% Transport ML | CSE-CIC-IDS2018 holdout parquets   | Acquire authorized raw  |
|    7 Dataset      | Recall (2 / 566);  | contain purely Layer 4 netflow     | PCAP slices, reconstruct|
|    Buffers        | 0 PCAPs on disk    | metrics. Zero HTTP strings exist to| HTTP streams, and test  |
|                   |                    | feed Layer 7 regex engine.         | L7 WAF in-situ $\ge 80\%$.|
+-------------------+--------------------+------------------------------------+-------------------------+
```

---

## 11. Prioritized Next Actions

1. **Target-Centric Rate Aggregation (B2 Detector Prototype):**
   - *Impact:* High.
   - *Action:* Extend `VolumetricFloodDetector` to track aggregate inbound traffic per `dst_ip:dst_port` in addition to per-source IP. This directly captures distributed multi-client HTTP GET floods (HOIC).
2. **Host Endpoint Telemetry Specification (C1 Detector Design):**
   - *Impact:* High.
   - *Action:* Formulate schema and adapter contracts for Windows Event Logs (4624 login, 4688 process creation) to detect lateral pivot attempts where netflow telemetry is blind.
3. **Authorized Raw PCAP Acquisition for Layer 7 Validation:**
   - *Impact:* High.
   - *Action:* Define an authorized acquisition protocol to acquire authentic PCAP slices of HTTP exploits (or set up an isolated local honeynet capture) to supply real application-layer payload buffers to `Layer7WAFDetector`.
4. **Maintain GATE-1 OPEN Status:**
   - *Impact:* Critical.
   - *Action:* Keep GATE-1 strictly OPEN until the B2, C1, and Layer 7 PCAP evaluations are empirically demonstrated to satisfy their respective acceptance criteria without label leakage or simulated proxies.
