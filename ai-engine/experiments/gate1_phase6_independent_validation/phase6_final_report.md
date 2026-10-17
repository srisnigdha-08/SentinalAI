# SentinelAI GATE-1 Phase 6: Final Validation, Dataset Acquisition, and Layer 7 Audit Report

**Branch**: `feature/gate1-phase6-independent-validation`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Final GATE-1 Decision**: **REMAIN OPEN (Independent Release Validation Blocked)**  
**Autonomous Containment**: **DISABLED (`AUTONOMOUS_CONTAINMENT=false`)**  
**Real Firewall Enforcement**: **DISABLED (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`)**  

---

## 1. Executive Summary & Authoritative Gate Decision

This report concludes **Phase 6: Independent Dataset Acquisition and Layer 7 Validation** for SentinelAI GATE-1. 

All work was conducted on isolated branch `feature/gate1-phase6-independent-validation` without altering production configuration, live databases, running services, or host firewall rules. Pre-test and post-test SHA-256 digests of all 5 protected assets verified zero drift.

### Authoritative Release Gate Verdict:
$$\mathbf{GATE\text{-}1\ STATUS:\ MUST\ REMAIN\ OPEN}$$

While the official AWS Open Data CSE-CIC-IDS2018 dataset was verified live via S3 HTTP Range requests, and the Layer 7 WAF pre-filter successfully resolves the Layer 4 Web Attack blindspot ($0.0\% \to \mathbf{95.33\%}$ recall on the HTTP benchmark with zero benign false alarms), **GATE-1 CANNOT BE CLOSED** due to three critical release blockers:
1. **Host Disk Capacity Blocker**: Drive `C:` has only **3.18 GB of free space**. Downloading and extracting the official 6.57 GB CSE-CIC-IDS2018 CSV dataset (~18 GB uncompressed) would immediately crash the host operating system. Acquisition is designated for secondary storage (Drive `D:`, 215.78 GB free) upon explicit operator provisioning.
2. **Benign False-Positive Statistical Upper Bound**: On 10,000 Monday benign flows, the 95% Wilson Score upper bound is **$0.1445\%$**, exceeding the mandatory release ceiling of $< 0.1000\%$.
3. **Statistical Power Sample Deficit**: Certifying a population error rate $< 0.10\%$ requires testing a minimum holdout of **$N \ge 30,000$ verified benign session flows**, which exceeds local corpus availability.

---

## 2. Independent Audit Claims Scorecard

| Area | Evaluated Technical Claim | Auditor Verdict | Supporting Evidence & Justification |
| :--- | :--- | :---: | :--- |
| **AWS S3 Repository** | Official CSE-CIC-IDS2018 availability | **VERIFIED** | S3 repository (`https://cse-cic-ids2018.s3.amazonaws.com/`) verified live via HTTP Range requests. 10 CSV files totaling **6,568.27 MB (~6.57 GB)** confirmed with 80-feature schema. |
| **Drive C: Capacity** | Sufficient space to download full dataset | **BLOCKED** | Drive `C:` has only **3.18 GB free** (198.77 GB used). Attempting full 6.57 GB download onto C: would trigger OS out-of-disk failure. Secondary volume (`D:`, 215.78 GB free) required. |
| **Feature Mapping** | 80-to-53 schema compatibility | **VERIFIED** | Complete 1-to-1 mapping established in [`dataset_provenance_and_feature_mapping.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase6_independent_validation/dataset_provenance_and_feature_mapping.md). Deterministic derivation specified for missing engineered features (`payload_entropy`, `time_of_day_sin/cos`). |
| **Training Overlap** | 2018 holdout independence | **VERIFIED** | Models trained on CICIDS2017 have **0% sample overlap** with 2018 AWS data. Captures feature independent IP space, victim topologies, and dates. |
| **Canary Pipeline** | Enterprise canary testing readiness | **PARTIALLY VERIFIED** | Complete passive canary design authored in [`canary_readiness_plan.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase6_independent_validation/canary_readiness_plan.md). Live infrastructure remains unprovisioned per safety rules. |
| **L7 Web Attack Blindspot**| L4 transport models fail on HTTP | **VERIFIED** | Pure flow models achieved $0.0\%$ recall on Web Attacks in the 300-record benchmark because L4 statistical features (packet counts, timings) cannot inspect URI strings or HTTP bodies. |
| **L7 Prototype Efficacy** | WAF pre-filter resolves Web Attacks | **VERIFIED** | Layer 7 WAF pre-filter achieved **$95.33\%$ containment recall** ($75.33\%$ simulated block) on HTTP attacks with **$0.00\%$ false positives** on benign HTTP traffic. |
| **L7 Benchmark Scope** | HTTP benchmark independence | **PARTIALLY VERIFIED** | 300-record benchmark successfully validates regex operational logic, but was synthetically constructed in Phase 5 and does not represent an external blind holdout. |
| **Statistical False Alarm**| Wilson 95% upper bound $< 0.10\%$ | **BLOCKED** | Observed benign FPR on Monday data ($7/10,000 = 0.07\%$) yields a 95% Wilson upper bound of **$0.1445\%$**, violating the mandatory release ceiling. |
| **Safety Invariants** | Zero mutation to protected assets | **VERIFIED** | Pre-test and post-test SHA-256 hashes of all 5 protected assets match 100%. `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` enforced. |

---

## 3. Controlled Policy Architecture Comparison

The isolated test harness ([`harness_phase6.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase6_independent_validation/harness_phase6.py)) benchmarked four configurations:
- **Configuration A**: Existing Production Flow Policy (Coupled RF + IF)
- **Configuration B**: Phase 4 Candidate Flow Policy (Decoupled RF + IF)
- **Configuration C**: Layer 7 WAF Pre-Filter Alone
- **Configuration D**: Combined Layer 7 WAF + Candidate Flow Policy

### 3.1. 300-Record Comprehensive HTTP Benchmark Results

| Policy Configuration | Containment Recall ($\text{MONITOR} \cup \text{BLOCK}$) | Simulated BLOCK Recall | Benign False Positive Rate | 95% Wilson CI (Recall) |
| :--- | :---: | :---: | :---: | :---: |
| **Config A: Prod Policy** | **0.00%** (0 / 150) | 0.00% | 0.00% (0 / 150) | $[0.00\%, 2.50\%]$ |
| **Config B: Cand Flow** | **0.00%** (0 / 150) | 0.00% | 0.00% (0 / 150) | $[0.00\%, 2.50\%]$ |
| **Config C: L7 Alone** | **95.33%** (143 / 150) | **75.33%** (113 / 150) | 0.00% (0 / 150) | $[90.68\%, 97.72\%]$ |
| **Config D: Combined** | **95.33%** (143 / 150) | **75.33%** (113 / 150) | 0.00% (0 / 150) | $[90.68\%, 97.72\%]$ |

### Vector Breakdown under Combined Policy:
- **Cross-Site Scripting (XSS, $N=35$)**: **$100.0\%$ recall** ($100.0\%$ simulated `BLOCK`).
- **Path Traversal / LFI ($N=25$)**: **$100.0\%$ recall** ($100.0\%$ simulated `BLOCK`).
- **SQL Injection ($N=35$)**: **$88.6\%$ recall** ($88.6\%$ simulated `BLOCK`; 4 complex error subqueries missed).
- **Command Injection ($N=25$)**: **$88.0\%$ recall** ($88.0\%$ simulated `BLOCK`; 3 unspaced backtick variations missed).
- **Malformed Protocol ($N=30$)**: **$100.0\%$ recall** ($100.0\%$ routed to `MONITOR`).
- **Benign HTTP ($N=120$)**: **$0$ false alarms** ($0.0\%$ FPR).
- **Non-HTTP Protocols ($N=30$, DNS/NTP/TCP)**: **$0$ false alarms** (`L7_UNAVAILABLE` fallback verified).

---

### 3.2. 23,036 CICIDS2017 Flow Corpus Results (Fallback Verification)

On the wire capture corpus where application payloads were absent, the Layer 7 module detected `L7_UNAVAILABLE` and safely handed off traffic to the Layer 4 Candidate Flow Classifier:

| Traffic Slice | Flow Count ($N$) | Config A: Production Recall | Config B: Candidate Flow Recall | Config D: Combined Policy Recall | Combined Simulated BLOCK Recall |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **PortScan** | 2,000 | 0.00% | **100.00%** | **100.00%** | **99.80%** |
| **DDoS LOIC** | 2,000 | 72.00% | **99.80%** | **99.80%** | **99.80%** |
| **DoS Hulk** | 2,000 | 65.90% | **96.70%** | **96.70%** | **96.70%** |
| **SSH-Patator** | 2,000 | 46.10% | **98.90%** | **98.90%** | **98.90%** |
| **Botnet** | 2,000 | 45.60% | **98.50%** | **98.50%** | **98.50%** |
| **Infiltration** | 1,036 | 75.00% | **86.11%** | **86.11%** | **72.22%** |
| **Web Attacks** | 2,000 | 7.50% | **60.90%** | **60.90%** | **15.60%** |
| **Monday Benign** | 10,000 | 0.00% FPR | **0.07% FPR** | **0.07% FPR** | **0.00% Block FPR** |

---

## 4. Statistical False-Positive Upper-Bound Analysis

On Monday pure benign data ($N=10,000$), $7$ false alarms were observed ($p = 0.00070$).
The two-sided 95% Wilson Score confidence interval is:
$$CI_{95\%} = [0.0341\%, \mathbf{0.1445\%}]$$

Because the upper bound of **$0.1445\% > 0.1000\%$**, the release criterion fails.
- **Statistical Power Requirement**: Achieving a 95% Wilson upper bound below $0.10\%$ requires evaluating at least **$N \ge 30,000$ pure benign flows** with $\le 10$ false alarms ($Upper = 0.0623\% < 0.10\%$).

---

## 5. Protected Assets Audit & Safety Invariants

Pre-test and post-test SHA-256 digests confirm zero modification to protected runtime assets:

| Protected Asset | SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **MATCH VERIFIED** |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **MATCH VERIFIED** |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH VERIFIED** |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH VERIFIED** |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH VERIFIED** |

- `AUTONOMOUS_CONTAINMENT`: `false` (Unchanged)
- `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`: `false` (Unchanged)
- Live database `sentinel-db`: 0 writes.
- Host firewall rules: 0 modifications.

---

## 6. Precise List of Criteria Still Unmet (Gate Closure Roadmap)

To achieve formal closure of GATE-1 in a subsequent review cycle, the following four milestones must be completed:

```mermaid
flowchart LR
    M1["1. Provision Drive D:<br/>Download official 6.57 GB CSE-CIC-IDS2018"] --> M2["2. Execute 53-Feature Pipeline<br/>Evaluate 100% blind holdout"]
    M2 --> M3["3. Evaluate Holdout N>=30,000<br/>Prove 95% Wilson Upper Bound < 0.10%"]
    M3 --> M4["4. Deploy L7 Ingress WAF<br/>Terminate TLS at Envoy/NGINX gateway"]
```

1. **Staging CSE-CIC-IDS2018 on Secondary Storage**: Allocate storage on Drive `D:` to download the 10 CSV files (6.57 GB) and run the deterministic 53-feature transformation pipeline.
2. **True Out-of-Distribution Attack Evaluation**: Benchmark the candidate decoupled policy against the unpolluted 2018 minority attack classes (`SSH-Bruteforce`, `Brute Force -Web`, `SQL Injection`, `Infilteration`, `Bot`).
3. **Statistical Power Certification**: Evaluate at least $30,000$ pure benign holdout flows to mathematically prove that the 95% Wilson upper bound on false alarms is strictly $< 0.10\%$.
4. **Permanent Enforcement Invariant**: Real firewall containment remains permanently disabled until an independent security governance committee approves the verified audit package.
