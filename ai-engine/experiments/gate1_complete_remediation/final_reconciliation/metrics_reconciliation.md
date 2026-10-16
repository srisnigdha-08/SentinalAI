# GATE-1 Final Metrics Reconciliation and Policy Recall Audit

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Technical Auditor  
**Scope**: Full metric reconciliation across raw models, composite predictors, and runtime policy engines  
**GATE-1 Verdict**: **OPEN (Technically Justified — Containment Gated)**

---

## 1. Reconciliation of Policy Confusion Matrices

### 1.1 The Anomaly Investigated
The latest evaluation report stated that runtime policy containment achieved **0.00% False-Positive Rate** on benign traffic, but simultaneously reported:
- **DDoS Policy Recall**: **76.60%** ($\text{TP}=766, \text{FN}=234$ out of 1,000 DDoS attacks).
- **PortScan Policy Recall**: **7.40%** ($\text{TP}=74, \text{FN}=926$ out of 1,000 PortScan attacks).

### 1.2 Reproduction from Saved Telemetry and Physical Ground Truth
Both values were reproduced down to individual flow decisions from [`ai-engine/experiments/gate1_evaluation/evaluation_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_evaluation/evaluation_results.json):

#### Comprehensive Subsystem Confusion Matrix & Metric Table

| Dataset Evaluated | Subsystem | TN | FP | FN | TP | Sample Count | FPR | FNR | Precision | Recall | F1-Score | Accuracy |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Friday DDoS**<br>*(1k Benign, 1k DDoS)* | **Raw Random Forest** | 1,000 | 0 | 1 | 999 | 2,000 | 0.00% | 0.10% | 100.0% | **99.90%** | 0.9995 | 99.95% |
| | **Composite Predictor** | 600 | 400 | 1 | 999 | 2,000 | 40.00% | 0.10% | 71.41% | **99.90%** | 0.8328 | 79.95% |
| | **Policy Action (`BLOCK`/`MONITOR`)** | 1,000 | 0 | 234 | 766 | 2,000 | 0.00% | 23.40% | 100.0% | **76.60%** | 0.8675 | 88.30% |
| | **Autonomous Block (`BLOCK` only)** | 1,000 | 0 | 995 | 5 | 2,000 | 0.00% | 99.50% | 100.0% | **0.50%** | 0.0100 | 50.25% |
| **Friday PortScan**<br>*(1k Benign, 1k PortScan)* | **Raw Random Forest** | 983 | 17 | 15 | 985 | 2,000 | 1.70% | 1.50% | 98.30% | **98.50%** | 0.9840 | 98.40% |
| | **Composite Predictor** | 936 | 64 | 15 | 985 | 2,000 | 6.40% | 1.50% | 93.90% | **98.50%** | 0.9614 | 96.05% |
| | **Policy Action (`BLOCK`/`MONITOR`)** | 1,000 | 0 | 926 | 74 | 2,000 | 0.00% | 92.60% | 100.0% | **7.40%** | 0.1378 | 53.70% |
| | **Autonomous Block (`BLOCK` only)** | 1,000 | 0 | 1,000 | 0 | 2,000 | 0.00% | 100.0% | 0.0% | **0.00%** | 0.0000 | 50.00% |
| **Monday Pure Benign**<br>*(10,000 Benign)* | **Raw Random Forest** | 9,955 | 45 | 0 | 0 | 10,000 | 0.45% | N/A | 0.0% | N/A | N/A | 99.55% |
| | **Composite Predictor** | 8,627 | 1,373 | 0 | 0 | 10,000 | 13.73% | N/A | 0.0% | N/A | N/A | 86.27% |
| | **Policy Action (`BLOCK`/`MONITOR`)** | 10,000 | 0 | 0 | 0 | 10,000 | 0.00% | N/A | 0.0% | N/A | N/A | 100.0% |
| | **Autonomous Block (`BLOCK` only)** | 10,000 | 0 | 0 | 0 | 10,000 | 0.00% | N/A | 0.0% | N/A | N/A | 100.0% |

#### Action Distribution Breakdown Across Physical Datasets

| Dataset & Flow Slice | Total Flows | Assigned `ALLOW` | Assigned `MONITOR` | Assigned `BLOCK` | Labeled `"Unknown"` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Friday DDoS — Attack Flows** | 1,000 | **234** (23.4%) | **761** (76.1%) | **5** (0.5%) | 0 |
| **Friday DDoS — Benign Ambient** | 1,000 | **1,000** (100.0%) | **0** (0.0%) | **0** (0.0%) | 400 (40.0%) |
| **Friday PortScan — Attack Flows** | 1,000 | **926** (92.6%) | **74** (7.4%) | **0** (0.0%) | 0 |
| **Friday PortScan — Benign Ambient** | 1,000 | **1,000** (100.0%) | **0** (0.0%) | **0** (0.0%) | 47 (4.7%) |
| **Monday Capture — Pure Benign** | 10,000 | **10,000** (100.0%) | **0** (0.0%) | **0** (0.0%) | 1,328 (13.28%) |

### 1.3 Why Policy Recall Diverges from Raw Classifier Recall
In [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L290-L302):
$$\text{threatScore} = \text{round}(0.7 \cdot P_{RF} + 0.3 \cdot \text{if\_sig}, 4)$$
$$\text{action} = \begin{cases} \text{BLOCK} & \text{if } \text{threatScore} \ge 0.92 \\ \text{MONITOR} & \text{if } 0.70 \le \text{threatScore} < 0.92 \\ \text{ALLOW} & \text{if } \text{threatScore} < 0.70 \end{cases}$$

1. **The PortScan Vulnerability**:
   - PortScan flows consist of isolated SYN packets. Because their packet lengths and durations resemble normal connection setups, Isolation Forest evaluates them as normal ($\text{if\_score} \ge \text{offset} \implies \text{if\_sig} = 0.0$).
   - When $\text{if\_sig} = 0.0$, the maximum achievable threat score is:
     $$\text{threatScore} = 0.7 \cdot P_{RF} \le 0.70$$
   - Since `MONITOR_THRESHOLD` is $0.70$, **ANY PortScan attack where Random Forest has confidence $P_{RF} < 1.0$ is assigned $\text{threatScore} < 0.70$ and receives `action = "ALLOW"`**!
   - Result: Although raw Random Forest detected 98.5% of PortScans, **92.6% of them received `action = "ALLOW"`**, collapsing policy recall to **7.40%**!
2. **The DDoS Attenuation**:
   - High-volume DDoS LOIC bursts triggered Isolation Forest ($\text{if\_sig} > 0$) for 76.6% of flows, boosting $\text{threatScore} \ge 0.70$ (761 MONITOR, 5 BLOCK).
   - However, 234 DDoS flows had low anomaly deflection, resulting in $\text{threatScore} < 0.70$ and receiving `action = "ALLOW"`.

### 1.4 Critical Governance Finding on Containment Safety
> [!WARNING]
> **Zero false blocking is NOT proof of containment safety.**
> In SentinelAI, zero policy false positives on benign traffic was achieved because the policy thresholds (`MONITOR=0.70`, `BLOCK=0.92`) and composite formula ($0.7 \cdot P_{RF} + 0.3 \cdot \text{if\_sig}$) aggressively force scores below 0.70. This suppressed benign false alarms, but simultaneously **allowed 92.6% of PortScan attacks and 23.4% of DDoS attacks to pass completely unmitigated**. A system that achieves safety by refusing to act on genuine attacks cannot be certified as production-ready.

---

## 2. Canonical Reconciliation of Random Forest Metrics

Different sections of previous reports presented varying recall and FPR metrics. Every reported result is mapped to its exact physical provenance below:

### Canonical Evaluation Record Register

| Result ID | Attack Evaluated | Reported Recall | Reported FPR | Exact Dataset Rows / Sample Selection | Model Artifact & Checksum | Prediction Threshold / Pipeline | Code Version / Provenance |
| :---: | :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| **RUN-1** | **PortScan** | **96.0%** | **8.0%** | 50 attack + 50 benign flows (start of file) | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Binary threshold in legacy `evaluate_model.py` | Phase 7 initial audit report (small 100-sample test slice). |
| **RUN-2** | **DDoS** | **98.0%** | **33.0%** | 100 attack + 100 benign flows (start of file) | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Composite predictor with `is_pos("Unknown") == True` | Phase 7 initial audit report. 33 benign flows flagged as `Unknown`. |
| **RUN-3** | **PortScan** | **100.0%** | **0.0%** | 100 attack + 100 benign at row offset 60,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model `predict()`, no anomaly override | `eval_reproduce.py` (200-sample slice). |
| **RUN-4** | **DDoS** | **100.0%** | **0.0%** | 100 attack + 100 benign at row offset 60,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model `predict()`, no anomaly override | `eval_reproduce.py` (200-sample slice). |
| **RUN-5** | **PortScan** | **100.0%** | **0.90%** | 1,000 attack + 1,000 benign at row offset 60,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model `predict()` (TN: 991, FP: 9, FN: 0, TP: 1000) | `eval_reproduce.py` (2,000-sample slice). |
| **RUN-6** | **DDoS** | **99.50%** | **0.50%** | 1,000 attack + 1,000 benign at row offset 60,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model `predict()` (TN: 995, FP: 5, FN: 5, TP: 995) | `eval_reproduce.py` (2,000-sample slice). |
| **RUN-7** | **PortScan** | **98.50%** | **1.70%** | 1,000 attack + 1,000 benign at row offset 30,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model extracted inside streaming predictor loop | `reproducible_evaluation.py` (TN: 983, FP: 17, FN: 15, TP: 985). |
| **RUN-8** | **DDoS** | **99.90%** | **0.00%** | 1,000 attack + 1,000 benign at row offset 30,000 | `rf_classifier_cicids_v2.pkl`<br>`CA0EFB1F...` | Raw model extracted inside streaming predictor loop | `reproducible_evaluation.py` (TN: 1000, FP: 0, FN: 1, TP: 999). |

### Explanation of Remaining Discrepancies
- **Sample Size Variance**: 200-sample slices (RUN-3, RUN-4) showed 100.0% recall and 0.0% FPR because 100 flows are insufficient to capture rare decision boundary boundary errors. On 2,000 samples (RUN-5 to RUN-8), the true underlying error rate ($0.5\% - 1.7\%$ FPR) was revealed.
- **Offset Sensitivity**: Offset 30,000 vs Offset 60,000 captures different portions of the Friday diurnal cycle. PortScan attacks at offset 30,000 had 98.5% recall, while at offset 60,000 they had 100.0% recall.

---

## 3. Verification of the Root-Cause Claim

### 3.1 Side-by-Side Decomposition on Identical Physical Flows
Using the exact 1,000 ambient benign flows from Friday DDoS (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`):

```
                        Physical 1,000 Benign Flows
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
Raw Random Forest                                        Isolation Forest
Predicted BENIGN: 1,000 (100.0%)                         Flagged as Outlier: 407 (40.7%)
Predicted Attack: 0 (0.00% FPR)                          Inlier: 593 (59.3%)
       │                                                         │
       └────────────────────────────┬────────────────────────────┘
                                    ▼
                         SentinelPredictor Output
                         BENIGN: 600 flows
                         Unknown: 400 flows (threatScore = 0.55)
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
Evaluation Layer (`is_pos`)                               Runtime Policy Engine
Treated "Unknown" as Attack Positive                      Evaluated threatScore = 0.55
False Positives: 400                                      ALLOW: 1,000 flows (100.0%)
Reported FPR: 40.00%                                      MONITOR: 0 flows
                                                          BLOCK: 0 flows (0.00% Policy FPR)
```

### 3.2 Where `Unknown` Operates
- **In Evaluation Layer**: **COUNTED AS ATTACK**. The legacy `evaluate_model.py` treated any non-`"BENIGN"` string as malicious attack positive.
- **In Alerting Layer**: **LOGGED AS LOW/MEDIUM INFORMATIONAL EVENT**. In [`backend/services/threatService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/threatService.js#L98-L103), `score = 0.55 < 0.70`, assigning status `DETECTED`. It does NOT trigger high-severity notifications or threat intel enrichment.
- **In Policy Layer**: **ASSIGNED `ALLOW`**. Zero containment actions, zero IP blocks, exactly zero Windows Firewall netsh calls.

---

## 4. Re-Check of Statistical Claims & Wilson Score Intervals

All confidence intervals were independently recalculated from exact numerators and denominators:

| Interval Identifier | Event Being Measured | Numerator (Successes) | Denominator (Trials) | Point Estimate | Wilson 95% CI Lower | Wilson 95% CI Upper | Formatted 95% CI |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Monday Raw RF FPR** | Benign flow classified as Attack by Raw RF | 45 | 10,000 | 0.0045 | 0.003365 | 0.006016 | **[0.336%, 0.602%]** |
| **Monday Composite FPR** | Benign flow classified as non-BENIGN (Unknown/Attack) | 1,373 | 10,000 | 0.1373 | 0.130694 | 0.144185 | **[13.069%, 14.418%]** |
| **Monday Policy FPR** | Benign flow escalated to `BLOCK` or `MONITOR` | 0 | 10,000 | 0.0000 | 0.000000 | 0.000384 | **[0.000%, 0.038%]** |
| **Friday DDoS Raw RF FPR** | Benign ambient flow classified as Attack by Raw RF | 0 | 1,000 | 0.0000 | 0.000000 | 0.003827 | **[0.000%, 0.383%]** |
| **Friday DDoS Raw RF Recall** | DDoS flow detected as Attack by Raw RF | 999 | 1,000 | 0.9990 | 0.994357 | 0.999823 | **[99.436%, 99.982%]** |
| **Friday DDoS Policy Recall** | DDoS flow escalated to `BLOCK` or `MONITOR` | 766 | 1,000 | 0.7660 | 0.738772 | 0.791192 | **[73.877%, 79.119%]** |
| **Friday PortScan Raw RF FPR** | Benign ambient flow classified as Attack by Raw RF | 17 | 1,000 | 0.0170 | 0.010641 | 0.027056 | **[1.064%, 2.706%]** |
| **Friday PortScan Raw RF Recall**| PortScan flow detected as Attack by Raw RF | 985 | 1,000 | 0.9850 | 0.975399 | 0.990889 | **[97.540%, 99.089%]** |
| **Friday PortScan Policy Recall**| PortScan flow escalated to `BLOCK` or `MONITOR` | 74 | 1,000 | 0.0740 | 0.059355 | 0.091905 | **[5.936%, 9.191%]** |

### Critical Statistical Caveat: Intra-Capture Clustering
Wilson score intervals assume **independent and identically distributed (I.I.D.) Bernoulli trials**. In network PCAPs, packets belong to multi-flow sessions sharing source/destination IP pairs and protocol behaviors. Therefore, intra-capture variance may be wider than nominal binomial intervals suggest. **A single-capture result does NOT establish the same error rate for external enterprise networks.**

---

## 5. Reassessment of Holdout Independence

As documented in [`holdout_independence_findings.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_complete_remediation/final_reconciliation/holdout_independence_findings.md):
- In `train.py`, `data_path.glob("*.csv")` ingested `Monday-WorkingHours.pcap_ISCX.csv` and sampled 15,000 benign flows.
- Therefore, Monday evaluation results are formally **re-classified as Internal Validation Evidence**, rather than unpolluted blind test evidence.
- An untouched final test requires external datasets (CSE-CIC-IDS2018 or real-time enterprise PCAPs) that have never been placed into `datasets/cicids2017/`.

---

## 6. Final Decision: Keep GATE-1 OPEN

### Final Release-Gate Determination: **OPEN**

**Technical Basis**:
1. **Policy Recall Deficit**: While policy containment achieved 0.00% false positives, it only mitigated **7.40%** of PortScan attacks and **76.60%** of DDoS attacks. Zero false blocking achieved by allowing genuine attacks to pass cannot justify release.
2. **Holdout Contamination**: The Monday baseline has been re-classified as validation evidence due to multi-file directory ingestion in `train.py`.
3. **Generalization Gap**: The models remain unverified against modern enterprise telemetry outside CICIDS2017.

**Operational Requirement**: `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` must remain strictly locked.
