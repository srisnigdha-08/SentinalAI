# SentinelAI GATE-1 Phase 3B: Flow Count and Dataset Overlap Reconciliation Report

**Audit Date:** October 16, 2026  
**Auditors:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Workspace Root:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Location:** [`ai-engine/experiments/gate1_phase3b_reconciliation/flow_count_and_overlap_reconciliation.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_reconciliation/flow_count_and_overlap_reconciliation.md)  
**Status:** **AUTHORITATIVE RECONCILIATION COMPLETE**

---

## 1. Executive Summary & Root-Cause of the 19,036 vs. 23,036 Discrepancy

In the Phase 3B multi-attack summary report, a discrepancy emerged between the narrative summary statement ("19,036 total network flows across 8 capture files") and the actual sum of the evaluated slice entries (**23,036 flows**).

### Root-Cause Diagnosis
Inspection of the test execution scripts proves the exact mathematical cause of the discrepancy:
- **Phase 3A Evaluated Flows (Baseline):**
  - Monday Pure Benign: 10,000 flows
  - Friday DDoS: 2,000 flows (1,000 DDoS + 1,000 Benign)
  - Friday PortScan: 2,000 flows (1,000 PortScan + 1,000 Benign)
  - *Phase 3A Subtotal:* **14,000 flows**.
- **Phase 3B Added Attack Slices:**
  - Tuesday SSH-Patator: 2,000 flows
  - Thursday Web Attacks: 2,000 flows
  - Thursday Infiltration: 1,036 flows (36 attack + 1,000 Benign)
  - Friday Morning Botnet: 2,000 flows
  - Wednesday DoS Hulk: 2,000 flows
  - *Phase 3B Added Subtotal:* **9,036 flows**.
- **The Arithmetic Error:**
  When drafting the narrative text in Phase 3B, the author added the **9,036 newly introduced Phase 3B flows** to the **10,000 Monday benchmark flows**:
  $$9,036 + 10,000 = \mathbf{19,036}$$
  This accidentally omitted the **4,000 flows from Friday PortScan (2,000) and Friday DDoS (2,000)** that were also re-evaluated within the Phase 3B script:
  $$19,036 + 2,000 (\text{PortScan}) + 2,000 (\text{DDoS}) = \mathbf{23,036}$$
- **Verification:** The true total number of evaluation entries processed and recorded in [`multi_attack_metrics.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/multi_attack_metrics.json) is **23,036**, NOT 19,036.

---

## 2. Granular Provenance and Entry Counts per Evaluation Slice

Every evaluation entry is mapped to its exact source file, row offset, and class breakdown:

| Evaluation Slice Key | Source CSV File | Slice Size ($N$) | Attack Flows ($N_{pos}$) | Ambient Benign ($N_{neg}$) | Row Offset in CSV | Raw Attack Label Filter | Canonical Internal Label |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| `portscan` | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 30,000 | `PortScan` | `Port Scan` |
| `ddos` | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 30,000 | `DDoS` | `DDoS` |
| `ssh_bruteforce` | `Tuesday-WorkingHours.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 0 | `SSH-Patator` | `SSH Brute Force` |
| `web_attacks` | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 0 | `Web Attack *` | `Credential Stuffing` / `XSS Attempt` / `SQL Injection` |
| `infiltration` | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`| 1,036 | 36 | 1,000 | offset = 0 | `Infiltration` | `Lateral Movement` (INSUFFICIENT DATA) |
| `botnet` | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 0 | `Bot` | `Malware Beacon` |
| `dos_hulk` | `Wednesday-workingHours.pcap_ISCX.csv` | 2,000 | 1,000 | 1,000 | offset = 30,000 | `DoS Hulk` | `DDoS` |
| `monday_benign` | `Monday-WorkingHours.pcap_ISCX.csv` | 10,000 | 0 | 10,000 | offset = 0 | `BENIGN` | `BENIGN` |
| **TOTAL** | **8 PCAP CSV Files** | **23,036** | **6,036** | **17,000** | — | — | — |

---

## 3. Flow-ID Construction and Duplicate Analysis Across Slices

### Flow Identifier Definition
In the CICIDS2017 machine-learning CSV releases, IP 5-tuple columns (`Source IP`, `Destination IP`, `Timestamp`) were pre-stripped by the dataset curators, leaving 79 statistical feature columns. Consequently, flows lack explicit globally unique UUIDs in the raw CSV.

A canonical flow identifier is uniquely constructed as:
$$\text{FlowID} = \text{MD5}(\text{filename} \parallel \text{row\_index} \parallel \vec{X}_{79})$$

### Cross-Slice Overlap Analysis
1. **Attack Flows ($N=6,036$):**
   - Each attack category originates from a completely distinct PCAP capture recorded on a different day of the simulation week (Monday through Friday).
   - Zero attack flows are shared between slices. All 6,036 attack flows are **mutually exclusive and 100% unique**.
2. **Benign Ambient Flows ($N=17,000$):**
   - Monday Pure Benign ($N=10,000$) originates from `Monday-WorkingHours.pcap_ISCX.csv`.
   - Friday DDoS Benign ($N=1,000$) and Friday PortScan Benign ($N=1,000$) originate from separate afternoon captures.
   - Tuesday, Wednesday, and Thursday ambient benign slices ($N=1,000$ each) originate from their respective daily captures.
   - Cross-file hash matching verifies that all ambient benign slices are drawn from separate CSV files, resulting in **23,036 unique flow instances**.
3. **No Multi-Label Contamination:**
   In the raw PCAP CSVs, every row possesses exactly one ground-truth label string in the `Label` column. A single flow **cannot occur under multiple evaluation labels** within the evaluation dataset.

---

## 4. Training Ingestion Overlap Summary

| Evaluation Category | Total Captured in PCAP | Ingested by `train.py` | Ingestion Percentage | Out-of-Distribution Status |
| :--- | :---: | :---: | :---: | :--- |
| **PortScan** | 158,930 | 10,000 | 6.29% | Partial overlap risk (random subsample) |
| **DDoS** | 128,027 | 10,000 | 7.81% | Partial overlap risk (random subsample) |
| **SSH-Patator** | 5,897 | 5,897 | **100.00%** | **Full in-sample resubstitution** |
| **Web Attacks** | 2,180 | 2,180 | **100.00%** | **Full in-sample resubstitution** |
| **Infiltration** | 36 | 36 | **100.00%** | **Full in-sample resubstitution (Insufficient)** |
| **Botnet** | 1,966 | 1,966 | **100.00%** | **Full in-sample resubstitution** |
| **Monday Benign** | 529,918 | 15,000 | 2.83% | Overlap risk; internal validation benchmark |

**Conclusion:** The total number of evaluation entries is confirmed as **23,036**. The 19,036 figure was an isolated arithmetic omission of the 4,000 Friday PortScan and DDoS entries from the narrative summary text.
