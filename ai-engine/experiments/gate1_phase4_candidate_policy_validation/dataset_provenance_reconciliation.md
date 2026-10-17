# SentinelAI GATE-1 Phase 4: Dataset Provenance and Training Overlap Reconciliation Report

**Auditor / Engineer**: Senior ML Security Engineer & Backend Security Auditor  
**Date**: 2026-10-16  
**Status**: **Authoritative Reconciliation Complete (Data Leakage Confirmed)**  
**Independent Validation Status**: **BLOCKED (Training Leakage Precludes Production Acceptance)**

---

## 1. Executive Summary: The 19,036 vs. 23,036 Flow Figure Reconciliation

During the Phase 3B investigation, an apparent discrepancy was identified between narrative statements citing "19,036 flows" and data matrices totaling **23,036 flows**.

### Root Cause Diagnosis:
Mathematical reconstruction of the evaluation slices confirms the origin of the discrepancy:
- **Phase 3A Initial Dataset**:
  - Monday Pure Benign: 10,000 flows
  - Friday PortScan: 2,000 flows (1,000 attack + 1,000 benign)
  - Friday DDoS: 2,000 flows (1,000 attack + 1,000 benign)
  - *Phase 3A Subtotal:* **14,000 flows**.
- **Phase 3B Newly Added Attack Slices**:
  - Tuesday SSH-Patator: 2,000 flows
  - Thursday Web Attacks: 2,000 flows
  - Thursday Infiltration: 1,036 flows (36 attack + 1,000 benign)
  - Friday Morning Botnet: 2,000 flows
  - Wednesday DoS Hulk: 2,000 flows
  - *Phase 3B Added Subtotal:* **9,036 flows**.
- **The Narrative Drafting Error**:
  When drafting the Phase 3B summary narrative, the author summed the newly added Phase 3B flows ($9,036$) with the Monday benign baseline ($10,000$):
  $$9,036 + 10,000 = \mathbf{19,036}$$
  This accidentally omitted the **4,000 Friday flows** (2,000 PortScan + 2,000 DDoS) that were concurrently evaluated in the pipeline:
  $$19,036 + 2,000 (\text{PortScan}) + 2,000 (\text{DDoS}) = \mathbf{23,036}$$

**Authoritative Finding**: The true, physical evaluation stream across all 8 PCAP CSV captures contains exactly **23,036 evaluation flows** ($6,036$ attacks and $17,000$ benign).

---

## 2. Granular Provenance Manifest

Every evaluation entry is deterministically mapped to its source file, offset, label, and canonical internal mapping:

| Slice Key | Source CSV Filename | Capture Date | Slice $N$ | Attack ($N_{pos}$) | Benign ($N_{neg}$) | Row Offset | Raw PCAP Label Filter | Canonical Target Label |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- | :--- |
| `PortScan` | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 2017-07-07 | 2,000 | 1,000 | 1,000 | 30,000 | `PortScan` | `Port Scan` |
| `DDoS` | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 2017-07-07 | 2,000 | 1,000 | 1,000 | 30,000 | `DDoS` | `DDoS` |
| `SSH_Patator` | `Tuesday-WorkingHours.pcap_ISCX.csv` | 2017-07-04 | 2,000 | 1,000 | 1,000 | 0 | `SSH-Patator` | `SSH Brute Force` |
| `Web_Attacks` | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 2017-07-06 | 2,000 | 1,000 | 1,000 | 0 | `Web Attack *` | `Credential Stuffing` / `XSS Attempt` / `SQL Injection` |
| `Infiltration` | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`| 2017-07-06 | 1,036 | 36 | 1,000 | 0 | `Infiltration` | `Infiltration` (Flagged: Insufficient Data) |
| `Botnet` | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 2017-07-07 | 2,000 | 1,000 | 1,000 | 0 | `Bot` | `Malware Beacon` |
| `DoS_Hulk` | `Wednesday-workingHours.pcap_ISCX.csv` | 2017-07-05 | 2,000 | 1,000 | 1,000 | 30,000 | `DoS Hulk` | `DDoS` |
| `Monday_Benign`| `Monday-WorkingHours.pcap_ISCX.csv` | 2017-07-03 | 10,000 | 0 | 10,000 | 0 | `BENIGN` | `BENIGN` |
| **TOTAL** | **8 PCAP CSV Captures** | — | **23,036**| **6,036** | **17,000** | — | — | — |

---

## 3. Duplicate Handling and Flow Identifier Construction

Because the CICIDS2017 curators pre-stripped IP 5-tuple headers (`Source IP`, `Destination IP`, `Timestamp`), flows in the raw CSV lack native UUIDs.

A canonical flow identifier is uniquely constructed as:
$$\text{FlowID} = \text{SHA256}(\text{source\_filename} \parallel \text{row\_index} \parallel \vec{X}_{79})$$

- **Attack Flows ($N=6,036$)**: Each attack class was captured on a separate day/pcap. Cross-file hash matching proves zero flow overlap between attack slices. All 6,036 attack flows are mutually exclusive.
- **Benign Ambient Flows ($N=17,000$)**: Drawn from 8 distinct captures across Monday through Friday. No flow instances are duplicated across slices.
- **Label Consistency**: Every row possesses exactly one ground-truth string in the `Label` column. Zero multi-label contamination exists.

---

## 4. Critical Audit Finding: Training Ingestion Overlap & Data Leakage

An audit of `ai-engine/training/train.py` was conducted to establish whether the evaluation slices represent an untouched blind holdout test or in-sample training data.

### Training Overlap Audit Table:

| Evaluation Category | Total Captured in PCAP | Ingested by `train.py` | Training Ingestion % | Overlap & Leakage Assessment |
| :--- | :---: | :---: | :---: | :--- |
| **PortScan** | 158,930 | 10,000 | 6.29% | Partial overlap risk (random subsample) |
| **DDoS** | 128,027 | 10,000 | 7.81% | Partial overlap risk (random subsample) |
| **SSH-Patator** | 5,897 | 5,897 | **100.00%** | **CRITICAL LEAKAGE: 100% In-sample Resubstitution** |
| **Web Attacks** | 2,180 | 2,180 | **100.00%** | **CRITICAL LEAKAGE: 100% In-sample Resubstitution** |
| **Infiltration** | 36 | 36 | **100.00%** | **CRITICAL LEAKAGE: 100% In-sample Resubstitution (Insufficient)** |
| **Botnet** | 1,966 | 1,966 | **100.00%** | **CRITICAL LEAKAGE: 100% In-sample Resubstitution** |
| **Monday Benign** | 529,918 | 15,000 | 2.83% | Same-distribution temporal overlap risk |

### Key Leakage Findings:
1. **Full In-Sample Contamination for Minority Attacks**:
   Because `SSH-Patator` ($5,897$), `Web Attacks` ($2,180$), `Infiltration` ($36$), and `Botnet` ($1,966$) had very low instance counts in the raw capture, `train.py` ingested **100% of all available attack instances** during model training.
2. **Evaluation Slices Are NOT Blind Tests**:
   Any evaluation slice drawn from `Tuesday-WorkingHours`, `Thursday-WorkingHours-Morning-WebAttacks`, `Thursday-WorkingHours-Afternoon-Infilteration`, or `Friday-WorkingHours-Morning` is evaluating flows that were **already seen during training**.
3. **Exploratory Status Only**:
   The metrics computed on these 4 attack slices reflect **in-sample memorization**, NOT true generalizable out-of-distribution performance.
4. **Governing Impact on GATE-1**:
   Because genuinely independent, blind holdout datasets are not available in the repository, **independent validation must be formally marked as BLOCKED**. Production readiness cannot be certified from in-sample training slices.
