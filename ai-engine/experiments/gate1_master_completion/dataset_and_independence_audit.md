# SentinelAI GATE-1 — Dataset Integrity, Provenance, and Holdout Independence Audit
**Audit Date:** 2026-10-17  
**Auditor:** Senior Security Architect & Independent QA Lead  
**Scope:** Corpora integrity, cryptographic hashes, train/test leakage, and cross-phase evaluation consistency  
**Status:** COMPLETE (Binding Audit Record)

---

## 1. Inventory of Datasets and Partitions

The evaluation and training corpora span two public benchmark datasets:
1. **CICIDS2017**: 8 raw CSVs (`ai-engine/datasets/cicids2017/*.csv`, total 864.84 MB)
2. **CSE-CIC-IDS2018**: 6 raw daily traffic CSVs (`D:\sentinelai_datasets\cse_cic_ids2018\*.csv`, total 1.82 GB)
3. **Sealed Holdout Partitions**: 6 Parquet files (`D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\*.parquet`, total 3.73 MB, 43,566 rows)

### 1.1 Cryptographic Hashes of Sealed Holdout Partitions
| File Name | SHA-256 Checksum | Total Rows | Attack Rows | Benign Controls |
|---|---|---|---|---|
| `holdout_benign_30k.parquet` | `62FB5DDEBD915F38289EA7814E073A3C1F1A06D6FCF91F57E779D83E075480B6` | 30,000 | 0 | 30,000 |
| `holdout_ddos.parquet` | `C9F638F28D93108A56AEF4E69F1CD467A93D6E97AE531FB5D7CB2756D2A84C47` | 3,874 | 2,874 (HOIC/LOIC-UDP) | 1,000 |
| `holdout_bruteforce_ssh_ftp.parquet` | `EDF54D185F755A67C684FB6DCFA4FFC75FF8C6986348636FF4440314EC227DC7` | 3,438 | 2,438 (FTP/SSH Hydra) | 1,000 |
| `holdout_botnet.parquet` | `00FD4FA72736552FC95C976B4DBE6E5077B0B85E11BAE6A0E806BE53623CAFEA` | 2,000 | 1,000 (Ares Botnet) | 1,000 |
| `holdout_infiltration.parquet` | `094AD11F984580E08D4DC743050BCC1C25CCC49B03122D7B69D23D0A0B480F30` | 2,688 | 1,688 (MetaSploit/Pivot) | 1,000 |
| `holdout_web_attacks.parquet` | `41ABF2CF1516F30627EED35E1F136EC545D9A0D89A1CE9661EF7FFF4DBC86354` | 1,566 | 566 (SQLi, XSS, BF-Web) | 1,000 |
| **Total Sealed Population** | — | **43,566** | **8,566** | **35,000 (30k unique)** |

---

## 2. Partition Leakage and Overlap Audit

### 2.1 Training vs Holdout Partition Disjointness
Phase 8 generated a multi-corpus training set (`partition_train_multicorpus.parquet`, $N = 179,458$) and validation set (`partition_validation_tuning.parquet`, $N = 31,623$).
- **Hash Overlap:** All 43,566 holdout rows were hashed (feature-vector MD5) prior to sampling. Any raw candidate row matching a holdout hash was discarded during streaming extraction.
- **Audited Overlap:**
  - Training Partition $\cap$ Holdout Sets: **0 rows (0.0000%)**
  - Validation Partition $\cap$ Holdout Sets: **0 rows (0.0000%)**
  - Training Partition $\cap$ Validation Partition: **0 rows (0.0000%)**

### 2.2 Control Slice Redundancy Disclosure
- The 1,000 benign control flows in each of the 5 attack holdout parquets were sampled using `random_state=42` from the same underlying Friday-23-02-2018 pool as `holdout_benign_30k.parquet`.
- **Finding:** All 1,000 benign flows in `holdout_web_attacks.parquet`, `holdout_ddos.parquet`, etc., are exact duplicates of rows inside `holdout_benign_30k.parquet`.
- **Resolution:** Benign False Positive Rate must be evaluated strictly against the single canonical `holdout_benign_30k.parquet` ($N = 30,000$), not averaged across redundant slices.

---

## 3. Independent Audit of Historical Detection Claims

### 3.1 Web Attack Detection (Audit Finding C-07 Verification)
- **Claimed in Phase 8:** 100.00% Combined Detection Recall (566 / 566).
- **Audit Reproduction:** Inspection of `run_phase8_experiments.py` (lines 339–358) confirmed that the evaluation script bypassed packet parsing and executed:
  ```python
  if "web_attacks" in fn and att:
      if gt_lbl in ("SQL Injection", "XSS Attempt"):
          t2_det = True
  ```
- **Auditor Verdict:** This is a **simulated architectural assumption based on ground-truth label leakage**, not an empirical measurement.
- **Actual Transport ML Recall on Web Attacks:** When evaluated without the label leak, `candidate_rf_multicorpus_v1.pkl` detected only **2 of 566 flows (0.353%)**. Flow-level statistical summaries (packet length, inter-arrival time) do not differentiate SQLi/XSS from normal HTTP requests.

### 3.2 DoS / DDoS Generalization Gap
- **Claimed in Phase 8:** LOIC HTTP / UDP DoS achieved 99%+ on CICIDS2017, but CSE-2018 HOIC DDoS achieved **0.00% (0 / 2,874)** detection.
- **Auditor Verification:** Confirmed. HOIC floods simulate distributed HTTP GET requests across port 80. The flow statistics closely mimic legitimate multi-user web browsing. Transport models trained on SYN floods fail to detect application-layer HTTP floods unless volumetric rate-windowing (PPS/BPS/RPS) is applied at the source IP or subnet level.

### 3.3 Infiltration Detection Gap
- **Claimed in Phase 8:** Infiltration recall was **0.15% (1 / 688)**.
- **Auditor Verification:** Confirmed. The Infiltration scenario in CSE-CIC-IDS2018 consists of an internal pivot via Dropbox and Metasploit payload execution. In flow summary space, the volume and duration are indistinguishable from normal workstation background traffic.
