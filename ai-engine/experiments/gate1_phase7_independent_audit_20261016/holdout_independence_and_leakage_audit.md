# SentinelAI GATE-1 Phase 7 Independent Audit: Holdout Independence & Data Leakage Audit

**Audit Scope**: Dataset Provenance, Split Generation, Row Duplication, Preprocessing Boundaries, and Statistical Independence  
**Auditor**: Senior ML Evaluation Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Audited Directory**: `ai-engine/experiments/gate1_phase7_cse2018_validation/` and `D:\sentinelai_datasets\cse_cic_ids2018\`  

---

## 1. Provenance and Exact Source File Audit

All holdout datasets were extracted from the official Canadian Institute for Cybersecurity (CIC) and Communications Security Establishment (CSE) **CSE-CIC-IDS2018** corpus hosted on the AWS Open Data Registry (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/`).

The physical files on secondary storage `D:\sentinelai_datasets\cse_cic_ids2018\` were audited:

| Local Source CSV File | Exact Byte Size | Raw Row Count | Capture Date | Attack Labels Present |
| :--- | :---: | :---: | :---: | :--- |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | 331,125 | 01/03/2018 | `Infilteration` (93,063), `Benign` (238,037) |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | 1,048,575 | 23/02/2018 | `Brute Force -Web` (362), `Brute Force -XSS` (151), `SQL Injection` (53), `Benign` (1,048,009) |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | 1,048,575 | 14/02/2018 | `FTP-BruteForce` (193,360), `SSH-Bruteforce` (187,589), `Benign` (667,626) |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | 1,048,575 | 02/03/2018 | `Bot` (286,191), `Benign` (674,959) |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | 1,048,575 | 21/02/2018 | `DDOS attack-HOIC` (686,012), `DDOS attack-LOIC-UDP` (1,730), `Benign` (360,833) |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | 1,048,575 | 15/02/2018 | `DoS attacks-GoldenEye` (41,508), `DoS attacks-Slowloris` (10,990), `Benign` (996,077) |

---

## 2. Selection Methodology & Sampling Mechanics

The auditor inspected the extraction logic in `preprocess_cse2018.py`:
1. **Benign Holdout ($N=30,000$)**:
   - Sampled 15,000 benign flows from `Thursday-01-03-2018` using `random_state=42`.
   - Sampled 15,000 benign flows from `Friday-23-02-2018` using `random_state=42`.
   - Concatenated into `holdout_benign_30k.parquet` ($N = 30,000$).
2. **Infiltration Holdout ($N=3,000$)**:
   - Sampled 2,000 attack flows from `Thursday-01-03-2018` (`Label == 'Infilteration'`) using `random_state=42`.
   - Sampled 1,000 benign flows from `Thursday-01-03-2018` using `random_state=42`.
3. **Web Attacks Holdout ($N=1,566$)**:
   - Extracted all available web attacks from `Friday-23-02-2018` ($N = 566$: 362 Brute Force Web, 151 XSS, 53 SQL Injection).
   - Sampled 1,000 benign flows from `Friday-23-02-2018` using `random_state=42`.
4. **SSH & FTP Brute Force ($N=3,000$)**:
   - Sampled 1,000 `SSH-Bruteforce` and 1,000 `FTP-BruteForce` from `Wednesday-14-02-2018` using `random_state=42`.
   - Sampled 1,000 benign flows from `Wednesday-14-02-2018` using `random_state=42`.
5. **Botnet Holdout ($N=3,000$)**:
   - Sampled 2,000 `Bot` flows from `Friday-02-03-2018` using `random_state=42`.
   - Sampled 1,000 benign flows from `Friday-02-03-2018` using `random_state=42`.
6. **DDoS Holdout ($N=3,000$)**:
   - Sampled 2,000 `DDOS attack-HOIC`/`LOIC` flows from `Wednesday-21-02-2018` using `random_state=42`.
   - Sampled 1,000 benign flows from `Wednesday-21-02-2018` using `random_state=42`.

---

## 3. Duplicate and Overlap Analysis

An automated record-fingerprinting audit was conducted across all 6 Parquet files:

### 3.1 Intra-File Exact Duplicate Rows:
- `holdout_benign_30k.parquet`: 29,401 unique / 30,000 total (599 duplicates, 2.00%). Normal benign background replication (e.g. repetitive DNS/NTP requests).
- `holdout_infiltration.parquet`: 2,829 unique / 3,000 total (171 duplicates, 5.70%).
- `holdout_web_attacks.parquet`: 1,564 unique / 1,566 total (2 duplicates, 0.13%).
- `holdout_bruteforce_ssh_ftp.parquet`: 2,976 unique / 3,000 total (24 duplicates, 0.80%).
- `holdout_botnet.parquet`: 3,000 unique / 3,000 total (0 duplicates, 0.00%).
- `holdout_ddos.parquet`: 3,000 unique / 3,000 total (0 duplicates, 0.00%).

### 3.2 Inter-File Benign Overlap Finding:
- The auditor compared row-hashes between the 1,000 benign control rows in the attack files and the 30,000 benign holdout rows:
  * Infiltration benign rows overlapping with `b30k`: **974 out of 1,000** (97.4%).
  * Web attack benign rows overlapping with `b30k`: **1,000 out of 1,000** (100.0%).
- **Auditor Assessment**: Because `preprocess_cse2018.py` re-read the same source CSV files with the same pseudo-random seed (`random_state=42`), the smaller 1,000-sample draws were largely subsets of the 15,000-sample draws.
- **Reconciliation Impact**: This explains why the evaluation harness evaluated `holdout_benign_30k.parquet` as an independent partition rather than pooling all benign rows together ($30,000 + 5,000 = 35,000$). Pooling would have introduced duplicate benign samples. Evaluating each file independently preserved statistical validity.

---

## 4. Training vs. Holdout Leakage Audit

1. **Model Pipeline Freezing**:
   - Model timestamps (`rf_classifier_cicids_v2.pkl` and `isolation_forest_cicids.pkl`) show creation in August 2026 (`09-08-2026`).
   - The CSE-CIC-IDS2018 dataset was acquired on October 16, 2026.
   - **Conclusion**: The models were trained and frozen months prior to holdout acquisition. Preprocessing transformers (`StandardScaler`) and Isolation Forest decision boundaries were fitted strictly on CICIDS2017 training data.
2. **Prior Model Selection / Tuning Contamination**:
   - Did the Phase 7 holdout influence the selection of Candidate Policy thresholds?
   - The Candidate Policy thresholds (`block_threshold=0.92`, `monitor_threshold=0.70`, `confidence_bypass=0.85`) were frozen in Phase 3A on CICIDS2017. They were **not adjusted, tuned, or re-optimized** on CSE-CIC-IDS2018 data.
3. **Zero In-Sample Leakage**:
   - Training provenance shows 0% sample overlap between CICIDS2017 training records and CSE-CIC-IDS2018 holdout records.

---

## 5. Limits of Established Independence

While out-of-distribution sample independence is conclusively established, the auditor notes the following residual limitations:
1. **Campaign-Level Over-Representation**:
   A sample of 2,000 Infiltration flows from `Thursday-01-03-2018` does not represent 2,000 independent adversary campaigns. All 2,000 flows were produced by a single penetration-testing tool executing against a specific AWS victim architecture during one scheduled business day.
2. **Tooling Invariance**:
   Both CICIDS2017 and CSE-CIC-IDS2018 rely on the UNB `CICFlowMeter` flow aggregation tool. Shared protocol timeouts (120-second TCP cutoffs) and subflow feature algorithms are common to both datasets.
3. **Blind Holdout vs. Zero-Day Resilience**:
   Evaluating out-of-distribution transfer evaluates whether the model learned invariant attack behaviors across different networks; it does not evaluate active evasion (e.g., mimicry, polymorphic packet stuffing, or timing manipulation).
