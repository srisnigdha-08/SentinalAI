# SentinelAI GATE-1 Phase 9A: Preflight and Integrity Audit

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base / HEAD Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Gate Status**: **GATE-1 STRICTLY OPEN**  

---

## 1. Repository State & Working Tree Audit

An independent preflight verification was conducted prior to executing any reproduction or audit analysis:

```
Repository Root: c:\Users\srisn\Desktop\Projects\sentinelai-complete
Active Dedicated Branch: feature/gate1-phase8-multicorpus-candidates
Current HEAD Commit: e9f71a0c12562eb7cb07e896b5aa9f6ee737be98
Parent Commit: e9f71a0c12562eb7cb07e896b5aa9f6ee737be98
Tracked Working Tree Status: 0 modified tracked files (Clean working tree)
```

No git branch switching, resetting, rebasing, amending, or cleaning was performed. All existing user work, backups, and artifacts from Phases 1 through 8 remain fully preserved.

---

## 2. Phase 8 Artifact Inventory & Candidate Hash Verification

The Phase 8 experiment directory [`ai-engine/experiments/gate1_phase8_multicorpus_candidates/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase8_multicorpus_candidates/) was inventoried:

| Filename | File Size | Description | Verified Status |
| :--- | :---: | :--- | :---: |
| `candidate_rf_multicorpus_v1.pkl` | 5,850,914 B | Multi-corpus trained candidate model | **SHA-256 MATCH** |
| `candidate_artifact_manifest.json` | 2,932 B | Candidate metadata & hyperparameters | Intact |
| `partition_train_multicorpus.parquet`| 16,380,842 B | Training partition (179,458 rows) | Intact |
| `partition_validation_tuning.parquet`| 3,113,638 B | Validation partition (31,623 rows) | Intact |
| `raw_dataset_hashes.json` | 5,997 B | 20 raw dataset SHA-256 hashes | Intact |
| `dataset_and_partition_manifest.json`| 8,838 B | Master partition manifest | Intact |
| `feature_ablation_results.json` | 4,074 B | Results for 6 ablation conditions (A-F) | Intact |
| `regularization_comparison.json` | 2,838 B | Results for 4 tree regularization settings | Intact |
| `per_class_confusion_matrices.json` | 6,454 B | Sealed holdout confusion matrices | Intact |
| `run_phase8_experiments.py` | 28,677 B | Master execution script | Intact |
| `build_multicorpus_pipeline.py` | 11,426 B | Multi-corpus transformation module | Intact |
| `phase8_preflight_and_integrity.md` | 3,907 B | Phase 8 preflight report | Intact |
| `feature_schema_and_label_mapping.md`| 5,687 B | Feature transformation specification | Intact |
| `leakage_and_overlap_audit.md` | 4,823 B | Zero-leakage audit report | Intact |
| `false_positive_confidence_intervals.md`| 3,072 B | Benign FPR & Wilson CI documentation | Intact |
| `layer7_and_combined_policy_evaluation.md`| 4,871 B | Defense tiers evaluation report | Intact |
| `unresolved_risks.md` | 4,113 B | Blocker register & root cause analysis | Intact |
| `phase8_final_report.md` | 7,475 B | Master Phase 8 final report | Intact |

### Candidate Model Hash Audit
```
Candidate Model Path: ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl
Expected Hash (candidate_artifact_manifest.json): 71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020
Calculated Hash (candidate_rf_multicorpus_v1.pkl): 71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020
Verdict: BIT-FOR-BIT MATCH (0 B drift)
```

---

## 3. Protected Asset Cryptographic Audit

All 5 protected models and Q-tables were independently hashed using SHA-256:

| Protected Asset Path | Expected SHA-256 Baseline | Audited SHA-256 Hash | Drift | Status |
| :--- | :--- | :--- | :---: | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | 0 B | **UNMODIFIED** |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | 0 B | **UNMODIFIED** |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | 0 B | **UNMODIFIED** |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | 0 B | **UNMODIFIED** |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | 0 B | **UNMODIFIED** |

---

## 4. Safety Invariants & Boundary Code Path Audit

Code paths governing autonomous containment and real enforcement were inspected:
1. `backend/services/containmentService.js`:
   `realEnforcementEnabled: process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'` (Evaluates to `false`).
2. `backend/services/containment/WindowsFirewallAdapter.js`:
   Explicitly checks `options.enabled !== undefined ? options.enabled : process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'`. When false, execution is bypassed with:
   `'Real Windows Firewall enforcement is disabled by safety gate. (ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT is not true).'`.
3. `Get-NetFirewallRule -DisplayName *SentinelAI*`:
   Queried PowerShell CIM interface: **0 active firewall rules**.
4. Database isolation:
   Zero connections or writes to live MongoDB `sentinel-db`.
