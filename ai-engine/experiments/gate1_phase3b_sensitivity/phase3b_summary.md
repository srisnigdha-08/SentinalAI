# SentinelAI GATE-1 Phase 3B: Multi-Attack Sensitivity and Policy Audit Final Summary

**Audit Date:** October 16, 2026  
**Auditor / Roles:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Workspace Root:** `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Isolated Experiment Directory:** [`ai-engine/experiments/gate1_phase3b_sensitivity/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/)  
**Final Release Gate Status:** **`GATE-1 OPEN — Phase 3B analysis complete; independent validation required`**  
**Enforcement Boundary:** `AUTONOMOUS_CONTAINMENT=false`, `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` (Permanently Locked)

---

## 1. Executive Summary & Verification Matrix

In Phase 3B, an independent audit of the Phase 3A candidate policy was conducted, resolving 10 explicit discrepancies regarding decision rules, threshold boundaries, statistical denominators, and downstream contract risks. Subsequently, a comprehensive multi-attack sensitivity evaluation and threshold sweep were executed across all 8 capture files in the CICIDS2017 dataset.

### Verification of Environmental Safety Invariants

| Environmental Constraint | Initial Check | Post-Experiment Check | Integrity Status |
| :--- | :---: | :---: | :---: |
| **Baseline Q-Table** (`ai-engine/models/q_table.json`) | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **Confirmed Unchanged** |
| **Runtime Q-Table** (`ai-engine/runtime/q_table.json`) | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **Confirmed Unchanged** |
| **Random Forest Model** (`rf_classifier_cicids_v2.pkl`) | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **Confirmed Unchanged** |
| **Isolation Forest Model** (`isolation_forest_cicids.pkl`) | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **Confirmed Unchanged** |
| **XGBoost Candidate Model** (`xgb_classifier_cicids_v2.pkl`) | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **Confirmed Unchanged** |
| **Windows Defender Firewall** | Netsh rule injection disabled | Zero rules added, deleted, or modified | **Confirmed Untouched** |
| **MongoDB Database** | Zero writes to `sentinel-db` | No database connection established | **Confirmed Untouched** |
| **Running Service Processes** | PIDs 39136 (Node) and 35672 (Python) | Zero signals, restarts, or terminations | **Confirmed Untouched** |

---

## 2. Complete Deliverable Inventory (Phase 3B Workspace)

All deliverables reside in [`ai-engine/experiments/gate1_phase3b_sensitivity/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/):

1. **[`phase3a_source_and_metrics_audit.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/phase3a_source_and_metrics_audit.md)**: Explicit resolution of 10 audit discrepancies (threshold rules, IF signal transformation, simulated vs actual blocks, Wilson CI recomputation, Monday 0.144% upper bound finding, and downstream gaps).
2. **[`dataset_provenance_and_overlap.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/dataset_provenance_and_overlap.md)**: In-depth provenance audit proving that `train.py` sampled Monday benign and ingested 100% of minority attack flows (SSH, Web Attacks, Infiltration, Bot), confirming that CICIDS2017 slices represent in-sample validation rather than blind holdouts.
3. **[`evaluate_multi_attack_sensitivity.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/evaluate_multi_attack_sensitivity.py)**: Reproducible test harness executing multi-attack evaluation and threshold parameter sweeping.
4. **[`multi_attack_metrics.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/multi_attack_metrics.json)**: Canonical machine-readable metrics across 8 PCAP evaluation sets (reconciled flow counts, confusion matrices, Wilson CIs, error counts).
5. **[`threshold_sensitivity.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/threshold_sensitivity.csv)**: Full parameter sweep across $\tau \in [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92]$.
6. **[`failure_mode_and_backend_contract_audit.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/failure_mode_and_backend_contract_audit.md)**: Deep architectural trace of downstream Node.js behavior, documenting action recalculation overwrite, status demotion, and fail-open vulnerability during inference outages.
7. **[`integration_risks_and_test_plan.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/integration_risks_and_test_plan.md)**: 5-phase gated production promotion and shadow-mode verification plan.
8. **[`phase3b_summary.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_sensitivity/phase3b_summary.md)**: This authoritative final audit summary report.

---

## 3. Multi-Attack Evaluation Findings

Evaluated against 19,036 total network flows across 8 capture files:

| Attack Category | PCAP Source File | Attack Flows ($N_{pos}$) | Ambient Benign ($N_{neg}$) | Raw RF Recall | Baseline Policy Recall | Candidate Policy Recall | Candidate Simulated Block Recall | Benign Action FPR | Data Sufficiency | Provenance / Overlap Note |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **PortScan** | `Friday-Afternoon-PortScan` | 1,000 | 1,000 | 100.00% | **0.30%** | **100.00%** | 99.80% | 0.90% | **SUFFICIENT** | Offset 30,000 used; 10k sampled during training |
| **DDoS** | `Friday-Afternoon-DDos` | 1,000 | 1,000 | 99.80% | **86.40%** | **99.80%** | 99.80% | 0.00% | **SUFFICIENT** | Offset 30,000 used; 10k sampled during training |
| **SSH Brute Force**| `Tuesday-WorkingHours` | 1,000 | 1,000 | 99.50% | **46.70%** | **99.00%** | 96.00% | 0.10% | **SUFFICIENT** | In-sample: all 5,897 SSH flows ingested in training |
| **Web Attacks** | `Thursday-Morning-WebAttacks`| 1,000 | 1,000 | 99.80% | **7.40%** | **61.10%** | 16.90% | 1.20% | **SUFFICIENT** | In-sample: all 2,180 Web Attack flows ingested |
| **Infiltration** | `Thursday-Afternoon-Infiltration`| **36** | 1,000 | 97.22% | **72.22%** | **86.11%** | 61.11% | 0.30% | **INSUFFICIENT** | Only 36 flows in entire capture; highly noisy |
| **Botnet** | `Friday-Morning` | 1,000 | 1,000 | 98.80% | **44.40%** | **98.40%** | 92.40% | 0.80% | **SUFFICIENT** | In-sample: all 1,966 Bot flows ingested in training |
| **DoS Hulk** | `Wednesday-workingHours` | 1,000 | 1,000 | 97.50% | **63.60%** | **96.90%** | 92.60% | 0.10% | **SUFFICIENT** | Offset 30,000 used; 10k sampled during training |
| **Pure Benign** | `Monday-WorkingHours` | 0 | 10,000 | N/A | N/A | N/A | N/A | **0.07%** | **SUFFICIENT** | Benchmark: 15,000 flows sampled during training |

### Key Performance Insights
1. **Pervasive Baseline Recall Collapse:** The baseline policy suffered massive recall collapse across **every attack category** (PortScan at 0.30%, Web Attacks at 7.40%, Botnet at 44.40%, SSH Brute Force at 46.70%).
2. **Decoupled Recovery:** Candidate policy restored containment recall to $\ge 96.9\%$ across PortScan, DDoS, SSH Brute Force, Botnet, and DoS Hulk.
3. **The Web Attacks Anomaly:** Web Attacks achieved 61.10% containment recall under candidate policy ($\tau = 0.85$) because SQL Injection and XSS attacks have lower average RF confidence ($P_{RF} < 0.70$) and frequently lack anomaly consensus. Under $\tau = 0.60$, Web Attacks recall rises to 79.50%.
4. **Infiltration Statistical Insufficiency:** With only 36 physical attack flows in the capture, Infiltration cannot statistically support release gate certification.

---

## 4. Threshold Sensitivity Analysis Summary

Evaluating qualification thresholds $\tau \in [0.60, 0.92]$ across all datasets reveals the exact operational trade-off:

| Threshold $\tau$ | Mean Attack Recall (All Attacks) | Mean Simulated Block Recall | Monday Benign FPR | Ambient PortScan FPR | Operational Trade-off Characterization |
| :---: | :---: | :---: | :---: | :---: | :--- |
| **0.60** | **95.95%** | 79.80% | **0.14%** (14 FP) | 1.30% (13 FP) | **High Aggression / High False Alarm:** Monday FPR exceeds 0.10% safety target. |
| **0.70** | **91.62%** | 79.80% | **0.07%** (7 FP) | 0.90% (9 FP) | **Optimal Balanced Qualification:** Keeps Monday FPR $\le 0.10\%$ while preserving high attack recall. |
| **0.75** | 91.62% | 79.80% | 0.07% (7 FP) | 0.90% (9 FP) | Stable operating plateau. |
| **0.80** | 91.62% | 79.80% | 0.07% (7 FP) | 0.90% (9 FP) | Stable operating plateau. |
| **0.85** | 91.62% | 79.80% | 0.07% (7 FP) | 0.90% (9 FP) | Recommended baseline threshold for automated block gating. |
| **0.90** | 91.62% | 77.41% | 0.07% (7 FP) | 0.90% (9 FP) | Conservative block gating; drops block recall on Infiltration and Web Attacks. |
| **0.92** | 91.62% | 77.01% | 0.07% (7 FP) | 0.90% (9 FP) | Ultra-conservative block gating; strictly restricts simulated block to extreme consensus. |

---

## 5. Statistical Acceptance Criteria Reconciliation

### Monday Benign Wilson 95% Confidence Interval
- **Observed Counts:** 7 False Positives out of 10,000 Benign Flows.
- **Observed False-Positive Rate:** $\hat{p} = 0.0007 = \mathbf{0.07\%}$.
- **95% Wilson Confidence Interval:** $[\mathbf{0.0339\%}, \mathbf{0.1445\%}]$.
- **Critical Audit Finding:** The point estimate ($0.07\%$) meets the preliminary requirement of $\le 0.10\%$. However, the **95% Wilson upper bound is $0.1445\%$ ($> 0.10\%$)**. Therefore, the candidate policy does **NOT** satisfy an acceptance rule requiring the 95% upper bound to remain strictly below 0.10%.
- **Sample Size Requirement:** To prove a 95% Wilson upper bound $< 0.10\%$ with a true error rate of $0.07\%$, a minimum sample size of $N \ge 35,000$ independent benign flows is required.

---

## 6. Audit Evidence Classification

| Statement / Claim | Evidence Level | Authoritative Justification |
| :--- | :---: | :--- |
| **PortScan Recall Recovery to 100.0%** | **Confirmed** | Reproducibly calculated across 1,000 physical PCAP flows with zero missing predictions. |
| **DDoS Recall Recovery to 99.8%** | **Confirmed** | Reproducibly calculated across 1,000 physical PCAP flows. |
| **Downstream Backend Overwrite Risk** | **Confirmed** | Confirmed by direct source inspection of `aiEngineService.js` (lines 56–58). |
| **CICIDS2017 Training Overlap** | **Confirmed** | Confirmed by direct source inspection of `ai-engine/training/train.py` (lines 118–132). |
| **Zero Host Network Disruptions** | **Confirmed** | Protected file hashes verified; netsh commands not executed; DB untouched. |
| **Infiltration Release Gate Suitability** | **Inadequate / Refuted**| Sample size ($N=36$) is statistically insufficient for gate certification. |
| **Generalization to Enterprise Traffic** | **Unverified** | All evaluation traffic originates from the 2017 Canadian Institute for Cybersecurity environment. |

---

## 7. Authoritative Release Gate Verdict

### Final Status:
# `GATE-1 OPEN — Phase 3B analysis complete; independent validation required`

### Technical Justification for Keeping GATE-1 Open:
1. **Downstream Integration Defect:** `backend/services/aiEngineService.js` overwrites the candidate policy's action and fails open during inference latency timeouts. Promotion cannot occur until backend contracts are remediated (Phase 4).
2. **Statistical Upper Bound Exceedance:** Monday benign FPR upper bound ($0.1445\%$) exceeds the strict $0.10\%$ acceptance ceiling.
3. **Training Ingestion Overlap:** All minority attack classes in CICIDS2017 were 100% ingested into training data, rendering offline evaluations in-sample tests rather than blind holdouts.
4. **Enterprise Generalization Unproven:** Validation across independent, multi-PCAP corporate enterprise network captures remains required.
5. **Enforcement Permanently Locked:** Real host containment remains disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`).
