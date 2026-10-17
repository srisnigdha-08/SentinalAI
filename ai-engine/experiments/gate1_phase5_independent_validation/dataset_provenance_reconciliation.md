# SentinelAI GATE-1 Phase 5: Dataset Provenance Reconciliation and Audit Manifest

**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Evaluation Scope**: 23,036 Network Flows across 8 Daily PCAP Datasets  
**Feature Schema Version**: `v2.1_53feat` (53 features)  
**Status**: **DATA CONTAMINATION CONFIRMED — BLIND HOLDOUT REJECTED**

---

## 1. Resolution of the 19,036 vs. 23,036 Evaluation Count Discrepancy

A persistent question across Phase 3B and Phase 4 was whether the evaluation suite comprised 19,036 flows or 23,036 flows. This audit independently examined the raw loading pipelines, commit histories, and evaluation logs to provide a definitive mathematical explanation:

### 1.1. Root Cause Analysis
During Phase 3B (`ai-engine/experiments/gate1_phase3b_sensitivity/`), the test suite was split into two conceptual groupings:
1. **The Initial PortScan & DDoS Baseline** (Phase 1/Phase 2 test sets):
   - Friday PortScan: 2,000 flows (1,000 attack, 1,000 benign)
   - Friday DDoS: 2,000 flows (1,000 attack, 1,000 benign)
   - *Subtotal: 4,000 flows*
2. **The New Multi-Attack Slices** (added in Phase 3B):
   - Monday Pure Benign: 10,000 flows
   - Tuesday SSH-Patator: 2,000 flows (1,000 attack, 1,000 benign)
   - Thursday Web Attacks: 2,000 flows (1,000 attack, 1,000 benign)
   - Thursday Infiltration: 1,036 flows (36 attack, 1,000 benign)
   - Friday Morning Botnet: 2,000 flows (1,000 attack, 1,000 benign)
   - Wednesday DoS Hulk: 2,000 flows (1,000 attack, 1,000 benign)
   - *Subtotal: 19,036 flows*

### 1.2. The Mathematical Reconciliation
$$\text{Multi-Attack Suite } (9,036) + \text{Monday Benign Benchmark } (10,000) = \mathbf{19,036\text{ flows}}$$
$$\text{Complete End-to-End Test Corpus } = 19,036 + \text{PortScan } (2,000) + \text{DDoS } (2,000) = \mathbf{23,036\text{ flows}}$$

When drafting summary reports in Phase 3B, the author cited the multi-attack suite subtotal ($19,036$) without adding the 4,000 flows from the PortScan and DDoS baseline slices. The physical code in `harness.py` and `multi_attack_metrics.json` loads and evaluates **all 8 slices totaling exactly 23,036 flows**. No records were dropped or added.

---

## 2. Comprehensive Provenance and Contamination Manifest

Every evaluation slice was cross-referenced against `ai-engine/training/train.py` (which trained `rf_classifier_cicids_v2.pkl` and `isolation_forest_cicids.pkl`) to determine training overlap, feature extraction integrity, duplicate treatment, and host-level leakage risks:

| Slice Key | Source Capture CSV | Total Flows ($N$) | Attack / Benign Split | Training Sampling in `train.py` | Training Ingestion Ratio | Leakage / Contamination Status |
| :--- | :--- | :---: | :---: | :--- | :---: | :---: |
| `Monday_Benign` | `Monday-WorkingHours.pcap_ISCX.csv` | 10,000 | 0 / 10,000 | 15,000 sampled from 529,918 total | 2.83% | **Partial Overlap Risk** (Shared hosts & day) |
| `PortScan` | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | 10,000 sampled from 158,930 total; offset=30,000 | 6.29% | **Controlled Offset** (Same capture & subnet) |
| `DDoS` | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | 10,000 sampled from 128,027 total; offset=30,000 | 7.81% | **Controlled Offset** (Same capture & subnet) |
| `DoS_Hulk` | `Wednesday-workingHours.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | 10,000 sampled from 231,073 total; offset=30,000 | 4.33% | **Controlled Offset** (Same capture & subnet) |
| `SSH_Patator` | `Tuesday-WorkingHours.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | **100% (5,897 / 5,897)** ingested in training | **100.0%** | **CONTAMINATED: In-Sample Resubstitution** |
| `Web_Attacks` | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | **100% (2,180 / 2,180)** ingested in training | **100.0%** | **CONTAMINATED: In-Sample Resubstitution** |
| `Botnet` | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 2,000 | 1,000 / 1,000 | **100% (1,966 / 1,966)** ingested in training | **100.0%** | **CONTAMINATED: In-Sample Resubstitution** |
| `Infiltration` | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 1,036 | 36 / 1,000 | **100% (36 / 36)** ingested in training | **100.0%** | **CONTAMINATED: In-Sample Resubstitution** |
| **Total** | | **23,036** | **6,036 / 17,000** | | | |

---

## 3. In-Depth Analysis of Leakage Vectors

### 3.1. Complete Training Resubstitution (Minority Classes)
In `ai-engine/training/train.py`, the data loader attempted to balance classes by ingesting every available sample of rare attack classes:
- **SSH-Patator**: The capture contains 5,897 attack flows. The training script ingested all 5,897. Any evaluation slice extracted from `Tuesday-WorkingHours.pcap_ISCX.csv` is drawing from the exact records used to fit tree splits in Random Forest.
- **Web Attacks**: The capture contains 2,180 total attack flows (Brute Force, XSS, SQL Injection). `train.py` ingested all 2,180.
- **Botnet**: The capture contains 1,966 flows. `train.py` ingested all 1,966.
- **Infiltration**: Only 36 flows exist in the entire dataset. `train.py` ingested all 36.

> [!CAUTION]
> **Audit Finding**: For SSH-Patator, Web Attacks, Botnet, and Infiltration, the reported recall figures (e.g. 98.9% on SSH, 98.5% on Botnet) do **not** reflect generalized machine learning detection. They reflect training set memorization. Testing on these records cannot be represented as an independent holdout.

### 3.2. Host, Subnet, and Session Leakage
Even for slices where an offset was applied (offset=30,000 for PortScan, DDoS, and DoS Hulk):
1. **Shared Network Topology**: All CICIDS2017 traffic was captured inside a single synthetic testbed at the Canadian Institute for Cybersecurity (UNB) over a 5-day period (July 3–7, 2017). All victim hosts resided on subnet `192.168.10.0/24`, and external attackers operated from `172.16.0.1` and `205.174.165.x`.
2. **Feature Collinearity**: Temporal flow features (`flow_iat_mean`, `fwd_iat_std`, `init_win_bytes_forward`) capture host operating system TCP stack idiosyncrasies (e.g., Windows 10 vs. Ubuntu 16.04 victim VMs) rather than invariant attack characteristics.
3. **Session-Level Duplication**: A single PortScan or DoS execution generates hundreds of consecutive flows with identical packet sizes and flag distributions. Applying an offset of 30,000 skips early packets of an attack campaign but still samples later packets of the *same* continuous tool execution.

---

## 4. Feature Extraction Versioning and Duplicate Handling

- **Feature Schema Version**: `v2.1_53feat` ([`ai-engine/utils/features.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/utils/features.py)).
- **Feature Vector**: 53 numerical float features. Features 0–49 correspond to CICFlowMeter statistical aggregates; features 50–52 represent engineered signals: `down_up_ratio`, `payload_entropy`, `time_of_day_sin`, and `time_of_day_cos`.
- **Duplicate Treatment in Pipeline**: Raw CICIDS2017 CSV files contain thousands of zero-duration TCP resets and identical retransmissions. The loading function [`load_slice()`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/evaluate_multi_attack_sensitivity.py) loads raw records sequentially without deduplication, preserving the physical distribution of the original PCAP file.
- **Encoding Normalization**: `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` contains non-ASCII characters in label strings (`Web Attack \x96 Brute Force`). `load_slice()` enforces `cp1252` encoding and strips replacement characters to ensure deterministic label mapping.

---

## 5. Auditor's Formal Conclusion

Every record among the 23,036 evaluation flows originates from the same 2017 UNB capture environment, and 4 out of the 7 attack classes have **100% training overlap**.

**Verdict**: The current 23,036 flow dataset is valuable as an internal exploratory benchmark, but **it cannot serve as an independent blind holdout**. Independent validation remains formally **BLOCKED** until genuinely unpolluted, external holdout data is evaluated.
