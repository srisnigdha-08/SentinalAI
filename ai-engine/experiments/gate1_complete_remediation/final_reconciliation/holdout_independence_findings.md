# Holdout Independence Findings & Dataset Provenance Audit

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Technical Auditor  
**Scope**: Code audit of training pipelines, dataset directories, and holdout claim verification  
**Status**: **FORMALLY RE-CLASSIFIED AS VALIDATION EVIDENCE**

---

## 1. Executive Summary & Core Re-Classification

Previous Phase 7 and early GATE-1 documentation claimed that [`Monday-WorkingHours.pcap_ISCX.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/Monday-WorkingHours.pcap_ISCX.csv) constituted a "strictly held-out, zero training overlap" blind test split.

An independent code-level investigation of [`ai-engine/training/train.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py) refutes this claim:
- In `train.py` (lines 40–75), when trained with `--data datasets/cicids2017`, the script automatically ingested every CSV file matching `data_path.glob("*.csv")`.
- `Monday-WorkingHours.pcap_ISCX.csv` (176.9 MB) resides directly inside `ai-engine/datasets/cicids2017/`.
- During training, `train.py` sampled 15,000 benign flows from `Monday-WorkingHours.pcap_ISCX.csv` into the candidate training dataframe.
- **Audit Verdict**: The Monday capture was **NOT** an untouched, blind holdout dataset. The Monday evaluation results must be formally re-classified from "Independent Holdout Test Evidence" to **"Internal Validation Evidence"**.

---

## 2. In-Code Provenance Audit & Findings

### Finding 1: Directory Ingestion in Training Script
- **Status**: **CONFIRMED**
- **Evidence**: In [`ai-engine/training/train.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py#L40-L75):
  ```python
  data_path = Path(args.data)
  if data_path.is_dir():
      csv_files = sorted(list(data_path.glob("*.csv")))
      print(f"Loading {len(csv_files)} CSV files from directory: {data_path}")
  ```
  The physical directory `ai-engine/datasets/cicids2017/` contains 8 CSV files:
  1. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  2. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  3. `Friday-WorkingHours-Morning.pcap_ISCX.csv`
  4. `Monday-WorkingHours.pcap_ISCX.csv` (176,927,918 bytes)
  5. `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
  6. `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
  7. `Tuesday-WorkingHours.pcap_ISCX.csv`
  8. `Wednesday-workingHours.pcap_ISCX.csv`

### Finding 2: Subsampling of Monday Flows During Training
- **Status**: **CONFIRMED**
- **Evidence**: In [`ai-engine/training/train.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py#L118-L132):
  ```python
  pre_caps = {
      "BENIGN": 15000,
      "Port Scan": 10000,
      "DDoS": 10000
  }
  sub_dfs = []
  for tc, grp in file_df.groupby("target_class"):
      if str(tc) in pre_caps:
          cap = pre_caps[str(tc)]
          sub_dfs.append(grp.sample(n=min(len(grp), cap), random_state=42))
  ```
  When `Monday-WorkingHours.pcap_ISCX.csv` was processed, 15,000 benign flows were sampled across the entire file using `random_state=42`. Therefore, flows across the file were exposed to the model selection and training process.

### Finding 3: Lack of Architectural Isolation
- **Status**: **CONFIRMED**
- **Evidence**: In [`ai-engine/models/rf_classifier_cicids_v2_meta.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/models/rf_classifier_cicids_v2_meta.json), the metadata records `trained_at: "2026-08-09T08:52:37.848427"`. The repository contains no documentation or test manifests demonstrating that `Monday-WorkingHours.pcap_ISCX.csv` was quarantined or physically excluded when the v2 model was fitted.

### Finding 4: Monday Data Use in Threshold Calibration and Candidate Evaluation
- **Status**: **CONFIRMED**
- **Evidence**: Both `reproducible_evaluation.py` and `investigate_fpr_root_cause.py` used Monday flows to validate `ANOMALY_THRESHOLD` (-0.55) and to benchmark candidate models (`rf_v2`, `xgb_v2`, `stacking`). This establishes Monday data as a **validation and development calibration set**, rather than an unpolluted blind test set.

---

## 3. Re-Classification of Historical Claims

| Claim ID | Previous Documentation Claim | Auditor Re-Assessment | Evidence Label |
| :---: | :--- | :--- | :---: |
| **C-1** | "Monday is a completely independent holdout test split with zero training overlap." | **REFUTED**: Monday was present in `datasets/cicids2017/` and 15,000 flows were sampled during model training by `train.py`. | **CONFIRMED FALSE** |
| **C-2** | "Monday proves 0.45% FPR on unseen production network traffic." | **RE-CLASSIFIED**: Demonstrates 0.45% FPR on internal validation data within the CICIDS2017 domain; does not prove generalization to unobserved environments. | **CONFIRMED RE-CLASSIFICATION** |
| **C-3** | "Offset 60,000 in Friday files eliminates training data leakage." | **REFUTED**: Random subsampling across the file dispersed session-level characteristics throughout the capture. | **CONFIRMED FALSE** |
| **C-4** | "Policy engine achieves 0.00% FPR on Monday flows." | **CONFIRMED AS VALIDATION METRIC**: Evaluated on 10,000 flows, the policy engine assigned `ALLOW` to 100% of samples (validating threshold calibration against benign traffic). | **CONFIRMED (VALIDATION ONLY)** |

---

## 4. Requirements for a Truly Untouched Final Test

To establish rigorous, uncompromised release evidence that satisfies **Criterion E (Generalization)** and allows GATE-1 to transition from **OPEN** to **CLOSED**, SentinelAI must execute an untouched test adhering to the following protocol:

1. **Topological & Temporal Independence**:
   - The test dataset must be generated from an entirely different physical or cloud network environment (e.g. AWS or enterprise on-premises domain).
   - Recommended source: **CSE-CIC-IDS2018** (AWS infrastructure) or **UNSW-NB15**, or live packet captures captured directly from Windows 11 endpoints under simulated enterprise workloads.
2. **Physical Quarantining**:
   - The final test PCAP/CSV must be stored in a dedicated, isolated directory (e.g., `ai-engine/datasets/blind_test_quarantine/`) that is physically excluded from any training script, glob pattern, or hyperparameter search.
3. **Session-Level Stratified Blocking**:
   - Evaluation data must be partitioned by network session (grouped by IP 5-tuple and time-window blocks) rather than uniform random row subsampling.
4. **Pre-Registered Evaluation Protocol**:
   - Prior to touching the quarantine dataset, the evaluation script, feature extractor, decision thresholds (`BLOCK=0.92`, `MONITOR=0.70`), and model checksums must be locked in a pre-registered cryptographic manifest.
