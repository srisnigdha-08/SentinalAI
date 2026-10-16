# SentinelAI GATE-1 Phase 3B: Dataset Provenance, Training Overlap, and Class Distribution Analysis

**Audit Date:** October 16, 2026  
**Auditor / Roles:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Workspace Root:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Location:** [`ai-engine/experiments/gate1_phase3b_sensitivity/dataset_provenance_and_overlap.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/dataset_provenance_and_overlap.md)  
**Status:** **AUTHORITATIVE PROVENANCE AUDIT COMPLETE**

---

## 1. Executive Summary

A core vulnerability in machine learning security evaluation is claiming out-of-sample generalization when evaluation data was partially or wholly ingested during model training.

Inspection of the actual training pipeline ([`ai-engine/training/train.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py#L40-L138)) proves that:
1. `train.py` loaded all 8 CSV files in [`ai-engine/datasets/cicids2017/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/).
2. For high-volume classes (`BENIGN`, `Port Scan`, `DDoS`), `train.py` executed random sampling (`grp.sample(n=cap, random_state=42)`) across each file without writing out or reserving an immutable holdout split.
3. For minority attack classes (`SSH-Patator`, `FTP-Patator`, `Web Attacks`, `Infiltration`, `Bot`), `train.py` ingested **100% of all available samples** directly into the training pool.
4. Consequently, **zero files in `datasets/cicids2017/` constitute untouched, out-of-distribution, or independent blind test sets**.

---

## 2. Complete Inventory of CICIDS2017 Capture Files

| File Name | File Size | Primary Attack Class | Total Raw Flows | Attack Flows | Benign Flows | Training Ingestion Rule |
| :--- | :---: | :--- | :---: | :---: | :---: | :--- |
| **`Monday-WorkingHours.pcap_ISCX.csv`** | 176.9 MB | Pure Benign Baseline | 529,918 | 0 | 529,918 | 15,000 sampled randomly (`random_state=42`) |
| **`Tuesday-WorkingHours.pcap_ISCX.csv`** | 135.1 MB | SSH-Patator, FTP-Patator | 445,909 | 13,835 | 432,074 | 100% of attacks (5,897 SSH, 7,938 FTP) + 15,000 benign |
| **`Wednesday-workingHours.pcap_ISCX.csv`** | 225.2 MB | DoS (Hulk, GoldenEye, slowloris) | 692,703 | 252,672 | 440,031 | 10,000 DDoS + 15,000 benign |
| **`Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`** | 52.0 MB | Web Attacks (Brute, XSS, SQLi) | 170,366 | 2,180 | 168,186 | 100% of Web Attacks (2,180) + 15,000 benign |
| **`Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`** | 83.1 MB | Infiltration (Lateral Movement) | 288,602 | **36** | 288,566 | 100% of Infiltration (36) + 15,000 benign |
| **`Friday-WorkingHours-Morning.pcap_ISCX.csv`** | 58.3 MB | Botnet (Malware Beacon) | 191,033 | 1,966 | 189,067 | 100% of Botnet (1,966) + 15,000 benign |
| **`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`** | 76.9 MB | PortScan | 286,467 | 158,930 | 127,537 | 10,000 sampled PortScan + 15,000 benign |
| **`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`** | 77.1 MB | DDoS (LOIC) | 225,745 | 128,027 | 97,718 | 10,000 sampled DDoS + 15,000 benign |

---

## 3. Training Overlap and Data Leakage Analysis

### A. The Random Sampling Mechanism in `train.py`
In `ai-engine/training/train.py` (lines 118–132):
```python
pre_caps = {
    "BENIGN": 15000,
    "Port Scan": 10000,
    "DDoS": 10000
}
sub_dfs = []
for tc, grp in file_df.groupby("target_class"):
    tc_str = str(tc)
    if tc_str in pre_caps:
        cap = pre_caps[tc_str]
        sub_dfs.append(grp.sample(n=min(len(grp), cap), random_state=42))
    else:
        sub_dfs.append(grp)
```
- Because `grp.sample()` was called with `random_state=42` on the entire dataframe without row index partitioning, rows sampled for training were drawn from arbitrary positions throughout each file.
- When evaluation scripts (e.g. `reproducible_evaluation.py`) load samples starting at `offset=30,000` or `head(10000)`, there is a non-trivial probability that individual flows overlap with the training set.

### B. Minority Attack Classes: 100% Ingestion
For the following attack classes:
- **`SSH-Patator`:** All 5,897 flows were ingested.
- **`Web Attacks`:** All 2,180 flows (Brute Force: 1,507; XSS: 652; SQL Injection: 21) were ingested.
- **`Infiltration`:** All 36 flows were ingested.
- **`Botnet`:** All 1,966 flows were ingested.

**Critical Consequence:** Any evaluation performed on these attack classes using CICIDS2017 data is an **in-sample resubstitution evaluation**. It tests model memorization and policy threshold alignment on training data, NOT generalization to unseen attack variants.

### C. Severe Class Scarcity: The Infiltration Anomaly
In `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`:
- Total rows: 288,602.
- Infiltration attacks: **36 flows (0.012% of file)**.
- Normal benign: 288,566 flows (99.988% of file).
- **Statistical Consequence:** An evaluation slice of 36 flows is statistically meaningless ($N=36$). A single misclassification swings recall by $2.78\%$, and the 95% Wilson confidence interval spans over $\pm 15\%$.
- **Audit Mandate:** Infiltration must be explicitly designated as **INSUFFICIENT DATA**, not as a passing release gate target.

---

## 4. Class Balance and Mapping Taxonomy

In `ai-engine/utils/features.py`, labels from diverse PCAP files are mapped to canonical internal threat categories:

```python
RAW_LABEL_TO_TARGET = {
    "BENIGN": "BENIGN",
    "SSH-Patator": "SSH Brute Force",
    "FTP-Patator": "Credential Stuffing",
    "PortScan": "Port Scan",
    "DDoS": "DDoS",
    "Bot": "Malware Beacon",
    "DoS Hulk": "DDoS",
    "DoS GoldenEye": "DDoS",
    "DoS slowloris": "DDoS",
    "DoS Slowhttptest": "DDoS",
    "Heartbleed": "RCE Attempt",
    "Infiltration": "Lateral Movement",
    "Web Attack \ufffd Brute Force": "Credential Stuffing",
    "Web Attack \ufffd XSS": "XSS Attempt",
    "Web Attack \ufffd Sql Injection": "SQL Injection"
}
```

### Label Parsing Caveats
In `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, raw CSV labels contain non-ASCII characters (`\ufffd` or byte `0x96` en-dash in Windows CP1252):
- `"Web Attack \x96 Brute Force"`
- `"Web Attack \x96 XSS"`
- `"Web Attack \x96 Sql Injection"`
Feature extraction must handle encoding gracefully (`encoding='cp1252'` or regex matching) to avoid dropping web attack samples during evaluation.

---

## 5. Methodological Guidelines for Multi-Attack Sensitivity Testing

To maintain scientific integrity across Phase 3B:
1. **Never Report Combined Denominators:** Monday benign ($N=10,000$), Tuesday ambient benign ($N=1,000$), and Friday ambient benign ($N=1,000$) must be evaluated and reported separately.
2. **Explicit Labeling of In-Sample Evaluation:** Evaluations on SSH Brute Force, Web Attacks, and Infiltration must be explicitly disclosed as **in-sample validation evidence**, not blind holdouts.
3. **Explicit Handling of Insufficient Classes:** Infiltration ($N=36$) must be marked `INSUFFICIENT DATA`.
4. **Generalization Scope:** All conclusions must be bounded to the CICIDS2017 environment. No enterprise production readiness claims can be derived from these PCAPs.
