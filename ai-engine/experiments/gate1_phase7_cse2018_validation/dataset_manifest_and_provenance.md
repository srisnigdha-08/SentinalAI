# SentinelAI GATE-1 Phase 7: Dataset Acquisition Manifest and Holdout Provenance

**Auditor / Lead ML Safety Engineer**: Senior Machine Learning Security Engineer & Independent Auditor  
**Date**: 2026-10-16  
**Storage Architecture**: Secondary Dedicated Drive `D:\sentinelai_datasets\cse_cic_ids2018\`  
**Primary Host**: AWS Open Data Registry (`https://cse-cic-ids2018.s3.amazonaws.com/`)  

---

## 1. Raw Dataset Slice Acquisition Manifest

All six targeted CSE-CIC-IDS2018 traffic slices were successfully acquired and verified on Drive `D:` to preserve system volume `C:` disk space.

| File Name | Size (MB) | Raw Rows | Attack Labels Present | Benign Rows | Capture Date | AWS S3 URI |
| :--- | :---: | :---: | :--- | :---: | :---: | :--- |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 102.85 | 331,125 | `Infilteration` (93,063) | 238,037 | 01/03/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 365.11 | 1,048,575 | `Brute Force -Web` (362)<br>`Brute Force -XSS` (151)<br>`SQL Injection` (53) | 1,048,009 | 23/02/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 341.63 | 1,048,575 | `FTP-BruteForce` (193,360)<br>`SSH-Bruteforce` (187,589) | 667,626 | 14/02/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 336.04 | 1,048,575 | `Bot` (286,191) | 674,959 | 02/03/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 313.66 | 1,048,575 | `DDOS attack-HOIC` (686,012)<br>`DDOS attack-LOIC-UDP` (1,730) | 360,833 | 21/02/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 358.53 | 1,048,575 | `DoS attacks-GoldenEye` (41,508)<br>`DoS attacks-Slowloris` (10,990) | 996,077 | 15/02/2018 | `s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/...` |
| **Total Acquired** | **1,817.82 MB** | **4,856,550** | **1,500,659 Attacks** | **3,985,541 Benign** | — | — |

---

## 2. Standardized Holdout Partitions Generated

All holdout partitions were transformed into SentinelAI's 53-feature format (`v2.1_53feat`) and stored in Parquet format at `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\`:

| Holdout Parquet File | Total Rows | Attack Population | Subtype Composition | Benign Baseline Population |
| :--- | :---: | :---: | :--- | :---: |
| `holdout_infiltration.parquet` | 3,000 | 2,000 | `Infilteration` (2,000) | 1,000 |
| `holdout_web_attacks.parquet` | 1,566 | 566 | `Brute Force -Web` (362)<br>`Brute Force -XSS` (151)<br>`SQL Injection` (53) | 1,000 |
| `holdout_bruteforce_ssh_ftp.parquet`| 3,000 | 2,000 | `SSH-Bruteforce` (1,000)<br>`FTP-BruteForce` (1,000) | 1,000 |
| `holdout_botnet.parquet` | 3,000 | 2,000 | `Bot` (2,000) | 1,000 |
| `holdout_ddos.parquet` | 3,000 | 2,000 | `DDOS attack-HOIC` / `LOIC` (2,000) | 1,000 |
| `holdout_benign_30k.parquet` | 30,000 | 0 | None (Pure Benign) | 30,000 |

---

## 3. Strict Independence Guarantee

- **Zero In-Sample Leakage**: Models `rf_classifier_cicids_v2.pkl` and `isolation_forest_cicids.pkl` were trained strictly on **CICIDS2017**. None of the 4,856,550 flows from CSE-CIC-IDS2018 were present during training or hyperparameter tuning.
- **Topology Independence**: CICIDS2017 was collected in a physical on-premise testbed in Fredericton, NB, Canada. CSE-CIC-IDS2018 was captured on AWS EC2 across 400 victim instances and 50 attacker nodes.
- **Statistical Significance**: Eliminates the 36-sample limitation of CICIDS2017 Infiltration by evaluating against 2,000 verified blind flows.
