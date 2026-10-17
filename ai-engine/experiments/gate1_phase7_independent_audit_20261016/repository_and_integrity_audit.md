# SentinelAI GATE-1 Phase 7 Independent Audit: Repository & Integrity Audit

**Audit Scope**: Repository State, Commit Ancestry, Working Tree Invariants, and Protected Asset Integrity  
**Auditor**: Senior ML Evaluation Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Audited Directory**: `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Audit Output Directory**: `ai-engine/experiments/gate1_phase7_independent_audit_20261016/`  

---

## 1. Repository State & Commit Ancestry

An exhaustive read-only inspection was executed on the current Git repository:

| Property | Measured Repository Value | Auditor Verification Status |
| :--- | :--- | :---: |
| **Current Branch** | `feature/gate1-phase7-cse2018-holdout-validation` | **CONFIRMED** |
| **HEAD Commit** | `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98` | **CONFIRMED** |
| **Base Commit Ancestry** | `git merge-base --is-ancestor e9f71a0 HEAD` returned exit code 0 (`True`) | **CONFIRMED** |
| **Commit Subject** | `fix(backend,frontend): remediate invalid-score fail-open, add bounded audit retention, and enable UI degraded triage` | **CONFIRMED** |
| **Parent Commit** | `780619d` (`fix(backend): remediate failure-safety, degraded inference handling, and schema enums`) | **CONFIRMED** |

### Working Tree Status:
`git status --short` confirms:
- **Tracked Files Modified**: **0** (Working tree is strictly clean of untracked modifications to production code).
- **Untracked Directories**:
  * `ai-engine/experiments/gate1_phase3d_backend_patch/`
  * `ai-engine/experiments/gate1_phase3e_independent_verification/`
  * `ai-engine/experiments/gate1_phase4_candidate_policy_validation/`
  * `ai-engine/experiments/gate1_phase5_independent_validation/`
  * `ai-engine/experiments/gate1_phase6_independent_validation/`
  * `ai-engine/experiments/gate1_phase7_cse2018_validation/`
  * Backup `.orig-phase3d` files in `backend/`

No tracked production files have been modified, staged, or committed during this audit.

---

## 2. Protected Model & Q-Table Cryptographic Integrity

All 5 protected core ML assets were inspected using PowerShell `Get-FileHash -Algorithm SHA256`. The computed hashes were verified against the frozen baseline:

| Asset Name | Repository Path | Baseline Frozen SHA-256 | Current Computed SHA-256 | Byte Drift | Status |
| :--- | :--- | :--- | :--- | :---: | :---: |
| **Baseline Q-Table** | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | 0 B | **CONFIRMED** |
| **Runtime Q-Table** | `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | 0 B | **CONFIRMED** |
| **Active RF Model** | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | 0 B | **CONFIRMED** |
| **Active IF Model** | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | 0 B | **CONFIRMED** |
| **Candidate XGB** | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | 0 B | **CONFIRMED** |

Integrity verdict: **100% BIT-FOR-BIT MATCH. ZERO MODEL TAMPERING DETECTED.**

---

## 3. Phase 7 Experiment Artifact Inventory & Cryptographic Hashes

The Phase 7 experiment workspace at [`ai-engine/experiments/gate1_phase7_cse2018_validation/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase7_cse2018_validation) was audited:

| File Name | File Size (Bytes) | SHA-256 Checksum | Purpose / Description |
| :--- | :---: | :--- | :--- |
| `acceptance_criteria_frozen.md` | 3,078 | `F25813A817E68746E7A9640295BA1648290CE6619DCD2ADBAEE6AA59278A7AE1` | Frozen evaluation criteria and mathematical protocol |
| `dataset_manifest_and_provenance.md` | 3,802 | `C549242B4BC3A61579E126A1D4255E99355DB8E36A8D793309CD99085A680A76` | Manifest of 6 downloaded slices and AWS S3 provenance |
| `false_positive_confidence_intervals.md` | 3,123 | `9A96C4EFEA2ED692F32486616D48E40B840150C2C8E62FC556FA9E2573D29BB1` | Wilson score analysis of 30,000 benign flows |
| `generalization_audit_and_retraining_roadmap.md` | 4,456 | `C2FBB542CF2D7F253D945CAC0648DD748C6BD30678B1DE4227427E2A7F16FB7E` | Root cause analysis and retraining roadmap |
| `harness_phase7.py` | 13,481 | `20B4BF68C63C84753D157D9E0C6C4B64AB1AA04391D0B765158A834918288BF5` | Execution harness evaluating 4 configurations |
| `layer7_vs_l4_holdout_synthesis.md` | 3,399 | `A7A812FB681BB95817E21919DAF9185FEDC4BA7E91F890FB2080308E251C114C` | Comparison of payload WAF vs transport flow models |
| `per_attack_confusion_matrices.json` | 3,787 | `B8EE045D26C196CD8BB66E111B8E6CBE28A0D04FBCD1986B0E533418E51EA2F3` | Integer confusion counts per slice |
| `phase7_final_report.md` | 7,268 | `42A1EE42771698065634629E321F74AD67295C0CFD28D95B2BE16E7F258FFAE4` | Summary report of Phase 7 evaluation |
| `phase7_preflight_and_scope.md` | 5,764 | `1B76D6E5102F4C0DAFBD8AEB3292ABC7C5CD5F0372E4D91F7A062088396539B2` | Preflight safety rules and scope definition |
| `policy_comparison_metrics.json` | 15,499 | `BBDB0A6A75CEBC90B9845AB083A8D4ADE6FB5ACA5807927B0C0FE199E171E5C4` | Quantitative metric outputs and intervals |
| `preprocess_cse2018.py` | 14,653 | `59E5F81049592B55A16B52AEB44EB9D82E072E3BCF7363FF113A61510765DA13` | Parquet extraction and feature transformation pipeline |
| `protected_asset_hash_verification.json` | 2,147 | `26B32F3812B8FE2D4E81C3765EAF0547EA5E2C9F80D0DDF65C1D358EA9E169FE` | Automated pre/post hash verification record |

All 12 reported Phase 7 files are physically present on disk with non-zero size.

---

## 4. Secondary Storage (Drive D:) Artifact Inventory

All raw CSV downloads and extracted Parquet holdout partitions reside on secondary drive `D:\sentinelai_datasets\cse_cic_ids2018\`:

| Disk Location | File Size (Bytes) | Category | Description |
| :--- | :---: | :--- | :--- |
| `D:\sentinelai_datasets\cse_cic_ids2018\Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | Raw CSV | 331,125 rows (Infiltration + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | Raw CSV | 1,048,575 rows (Web Attacks + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | Raw CSV | 1,048,575 rows (SSH/FTP Brute Force + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | Raw CSV | 1,048,575 rows (Botnet + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | Raw CSV | 1,048,575 rows (DDoS HOIC/LOIC + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | Raw CSV | 1,048,575 rows (DoS GoldenEye/Hulk + Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_benign_30k.parquet` | 2,707,608 | Parquet Holdout | 30,000 pure benign rows |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_infiltration.parquet` | 282,933 | Parquet Holdout | 3,000 rows (2,000 Infiltration, 1,000 Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_web_attacks.parquet` | 183,694 | Parquet Holdout | 1,566 rows (566 Web Attacks, 1,000 Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_bruteforce_ssh_ftp.parquet` | 222,969 | Parquet Holdout | 3,000 rows (2,000 SSH/FTP, 1,000 Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_botnet.parquet` | 264,250 | Parquet Holdout | 3,000 rows (2,000 Botnet, 1,000 Benign) |
| `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\holdout_ddos.parquet` | 256,426 | Parquet Holdout | 3,000 rows (2,000 DDoS, 1,000 Benign) |

**Protected Storage Safety Verification**:
The auditor inspected `D:\` root and verified that historical preservation directory `D:\MongoPreservation` and `D:\MongoPreservation_Backup_20261015` were completely untouched and unmodified.

---

## 5. Containment & Operational Safety Flag Audit

1. **Firewall Enforcement Safety Gate**:
   - Inspected `backend/services/containment/adapterFactory.js`:
     Lines 25-36 establish that `WindowsFirewallAdapter` is instantiated **ONLY IF** `requestedBackend === 'windows-firewall'` **AND** `process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'`.
   - Inspected `backend/.env`: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` is absent (undefined), defaulting safely to `MockContainmentAdapter`.
2. **Active Windows Firewall Rules**:
   - Executed `Get-NetFirewallRule -DisplayName "*Sentinel*"`. Output was completely empty. Zero rules exist.
3. **Autonomous Containment Flag**:
   - Confirmed disabled across all configuration blocks.

**Integrity Verification Conclusion**: **PASS**. All repository invariants, protected files, and safety flags are strictly preserved and verified.
