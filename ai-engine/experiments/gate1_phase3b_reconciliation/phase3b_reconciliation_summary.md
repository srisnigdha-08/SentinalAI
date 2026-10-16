# SentinelAI GATE-1 — Phase 3B Reconciliation and Verification Summary Report

**Date:** October 16, 2026  
**Auditor / Reviewer:** Principal ML & Backend Systems Auditor  
**Workspace:** `ai-engine/experiments/gate1_phase3b_reconciliation/`  
**Gate Status:** **GATE-1 OPEN** (Evaluation & Verification Complete; Production Deployment Gated)

---

## 1. Executive Summary

This report delivers the authoritative reconciliation and independent verification of the **SentinelAI GATE-1 Phase 3B Multi-Attack Sensitivity Analysis and Contract Audit**. 

Following the strict safety protocol (no runtime modifications, no database writes, no firewall rules, no model overwrites), an offline, reproducible audit was conducted to resolve data discrepancies, verify disparate metric claims between Phase 3A and Phase 3B, execute threshold sensitivity across 7 policy thresholds, verify backend contract failure modes, and rigorously classify evidence.

### Key Audit Conclusions:
1. **Flow Count Discrepancy Resolved:** The discrepancy between the reported 19,036 flows and 23,036 total evaluation entries is fully explained by an arithmetic category omission in the previous summary text ($9,036 \text{ new attack slices} + 10,000 \text{ Monday benign} = 19,036$; adding the $2,000$ PortScan and $2,000$ DDoS slices yields exactly $23,036$). All flows are mutually exclusive and uniquely indexed.
2. **PortScan Metric Divergence Reproduced to the Single Flow:** The baseline policy recall divergence ($7.40\%$ in Phase 3A vs. $0.30\%$ in Phase 3B) and candidate recall divergence ($92.90\%$ in Phase 3A vs. $100.00\%$ in Phase 3B) were reproduced exactly. Phase 3A sampled attack rows $[0, 1000)$ due to a chunking iteration bug (`b_skipped < offset`), whereas Phase 3B sampled attack rows $[30000, 31000)$ (`a_skipped < offset`).
3. **Threshold Sensitivity Analyzed:** Across 7 thresholds ($\tau \in [0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92]$), policy recall and simulated block recall were mapped across all 7 attack families. At the primary threshold $\tau = 0.80$, PortScan, DDoS, SSH, Botnet, and DoS Hulk achieve $>96\%$ policy recall, but Web Attacks stall at $61.10\%$ policy recall ($16.90\%$ block recall) and Infiltration achieves $86.11\%$ policy recall ($61.11\%$ block recall).
4. **Statistical FPR Rigor (Monday Benign):** Out of 10,000 Monday benign flows, exactly 7 false alerts were observed ($\text{FPR} = 0.0700\%$). While the point estimate is below $0.10\%$, the **95% Wilson score confidence upper bound is 0.1445%**. Therefore, a strict acceptance criterion requiring the 95% upper bound to be $<0.10\%$ is **NOT satisfied**.
5. **Backend Ingestion Contract Defects Confirmed:** In an isolated test harness executing 10 test doubles, 4 critical backend failure modes were replicated: (a) degraded fallback action overwrite in `aiEngineService.js`, (b) fail-open evasion on Axios timeout, (c) `DEGRADED` status demotion in `threatService.js`, and (d) Mongoose `ValidationError` on `status: 'DEGRADED'` in `ThreatLog.js`.
6. **Final Gate Recommendation:** **GATE-1 MUST REMAIN OPEN.** The candidate policy cannot be safely promoted until backend ingestion defects are remediated and end-to-end integration is validated.

---

## 2. Protected Asset Invariant Verification

Before and throughout this audit, the SHA-256 checksums of all active models and Q-tables were continuously monitored. All checksums remain perfectly identical to baseline:

| Asset Description | File Path | Verified SHA-256 Checksum | Status |
|---|---|---|:---:|
| **Baseline Q-Table** | `ai-engine/models/q_table.npy` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **MATCH / UNCHANGED** |
| **Runtime Q-Table** | `backend/models/q_table.npy` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **MATCH / UNCHANGED** |
| **Active Random Forest** | `ai-engine/models/rf_model.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH / UNCHANGED** |
| **Active Isolation Forest** | `ai-engine/models/if_model.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH / UNCHANGED** |
| **Candidate XGBoost** | `ai-engine/models/candidate_xgb.json` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH / UNCHANGED** |

---

## 3. Task 1: Flow Count & Overlap Reconciliation

### 3.1 Resolving 19,036 vs. 23,036 Flows
The Phase 3B report header stated a benchmark count of 19,036 flows, while the category breakdown table listed 23,036 evaluation entries.

Audit of `ai-engine/experiments/gate1_phase3b_multi_attack/multi_attack_metrics.json` established the exact slice inventory:

$$\begin{aligned}
\text{Total Entries} &= \underbrace{\text{PortScan (2,000)} + \text{DDoS (2,000)}}_{\text{Phase 3A Original Slices (4,000)}} \\
&\quad + \underbrace{\text{SSH (2,000)} + \text{Web (2,000)} + \text{Infiltration (1,036)} + \text{Botnet (2,000)} + \text{DoS Hulk (2,000)}}_{\text{Phase 3B Expanded Attack Families (9,036)}} \\
&\quad + \underbrace{\text{Monday Benign Baseline (10,000)}}_{\text{Monday Normal Benchmark (10,000)}} \\
&= 4,000 + 9,036 + 10,000 = \mathbf{23,036}
\end{aligned}$$

The discrepancy arose because the author of the Phase 3B summary narrative performed the partial sum $9,036 + 10,000 = 19,036$, inadvertently omitting the $4,000$ PortScan and DDoS benchmark flows. The evaluated JSON metrics and dataset files contain all 23,036 flows without omission.

### 3.2 Slice Independence & Zero Data Leakage
The source files and offsets for each slice were verified:
1. **PortScan:** `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (Attack rows: [30000, 31000); Benign rows: [30000, 31000)).
2. **DDoS:** `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (Attack rows: [30000, 31000); Benign rows: [30000, 31000)).
3. **SSH Brute Force:** `Tuesday-WorkingHours.pcap_ISCX.csv` (SSH-Patator attacks [0, 1000); Benign [0, 1000)).
4. **Web Attacks:** `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (Brute Force/XSS attacks [0, 1000); Benign [0, 1000)).
5. **Infiltration:** `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (All 36 Infiltration flows in dataset; Benign [0, 1000)).
6. **Botnet:** `Friday-WorkingHours-Morning.pcap_ISCX.csv` (Bot attacks [0, 1000); Benign [0, 1000)).
7. **DoS Hulk:** `Wednesday-workingHours.pcap_ISCX.csv` (DoS Hulk attacks [0, 1000); Benign [0, 1000)).
8. **Monday Benign:** `Monday-WorkingHours.pcap_ISCX.csv` (Benign baseline rows [0, 10000)).

Zero overlap exists between Monday benign rows and any Friday/Tuesday/Wednesday/Thursday slices. Furthermore, benign slices within each day are extracted from mutually disjoint row ranges.

---

## 4. Task 2: PortScan Baseline & Candidate Metric Reproduction

### 4.1 Observed Metric Divergence
Between Phase 3A and Phase 3B, two conflicting PortScan evaluations were recorded on identical model artifacts:

| Evaluation Phase | Sample Range | Baseline Recall | Baseline TP | Candidate Recall | Candidate TP |
|---|---|:---:|:---:|:---:|:---:|
| **Phase 3A Report** | 1,000 attacks | **7.40%** | 74 / 1,000 | **92.90%** | 929 / 1,000 |
| **Phase 3B Report** | 1,000 attacks | **0.30%** | 3 / 1,000 | **100.00%** | 1,000 / 1,000 |

### 4.2 Exact Reproduction & Root-Cause Discovery
An isolated reconstruction script (`verify_portscan_slices.py`) extracted and scored the exact chunk slices through the active Random Forest and Isolation Forest models.

The exact divergence was reproduced to the single flow:
* **The Phase 3A Chunking Bug:** In Phase 3A's data extraction script, the offset skip condition checked:
  ```python
  if b_skipped < offset:
      # incremented b_skipped but took attack rows immediately!
  ```
  Consequently, Phase 3A extracted attack rows from index **0 to 1,000**.
  - On rows $[0, 1000)$, raw RF recall was $92.90\%$ (929 TP). The Isolation Forest detected 74 anomalies ($\sigma_{IF} > 0.05$). Under the baseline policy:
    $$\text{Baseline Action} = \text{RF} \land \text{IF} \implies \text{Recall} = \frac{74}{1000} = \mathbf{7.40\%}$$
  - Under the candidate policy (which uses RF confidence $\ge 0.80$ to override IF suppression):
    $$\text{Candidate Action} = \mathbf{92.90\%} \text{ (929 TP)}$$

* **The Phase 3B Offset Fix:** In Phase 3B, the author corrected the script to track `a_skipped < offset`, extracting attack rows from index **30,000 to 31,000**.
  - On rows $[30000, 31000)$, PortScan attacks exhibit extremely uniform flow features (packet count, window size, flow duration). The raw RF classified all 1,000 flows as PortScan with $>99\%$ confidence.
  - However, the Isolation Forest scored 997 of the 1,000 flows as perfect inliers ($\sigma_{IF} = 0.0000$), detecting only 3 anomalies!
  - Under baseline policy:
    $$\text{Baseline Action} = \text{RF} \land \text{IF} \implies \text{Recall} = \frac{3}{1000} = \mathbf{0.30\%}$$
  - Under candidate policy:
    $$\text{Candidate Action} = \mathbf{100.00\%} \text{ (1,000 TP)}$$

**Conclusion:** Both reports are mathematically honest and reproduce perfectly on their respective data slices. The divergence directly proves how catastrophically the baseline policy's Isolation Forest coupling fails on uniform port scans.

---

## 5. Task 3: Multi-Attack Sensitivity & Threshold Analysis

Using `generate_threshold_decision_matrix.py`, policy decisions and simulated block decisions were computed across the candidate qualification thresholds $\tau \in \{0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.92\}$.

The complete dataset of 56 rows is preserved in `threshold_decision_matrix.csv`.

### Key Metrics Summary Across Attack Families (at $\tau = 0.80$):

| Attack / Traffic Category | Attack Flows | Benign Flows | Baseline Policy Recall | Candidate Policy Recall | Candidate Policy FPR | Candidate Sim. Block Recall | Candidate Sim. Block FPR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **PortScan** (Slice B) | 1,000 | 1,000 | 0.30% | **100.00%** | 0.90% | 99.80% | 0.80% |
| **DDoS** (Slice B) | 1,000 | 1,000 | 76.60% | **99.80%** | 0.00% | 99.80% | 0.00% |
| **SSH Brute Force** | 1,000 | 1,000 | 38.20% | **99.00%** | 0.10% | 96.00% | 0.00% |
| **Botnet** | 1,000 | 1,000 | 6.70% | **98.40%** | 0.80% | 92.40% | 0.00% |
| **DoS Hulk** | 1,000 | 1,000 | 48.90% | **96.90%** | 0.10% | 92.60% | 0.00% |
| **Infiltration** | 36 | 1,000 | 30.56% | **86.11%** | 0.30% | 61.11% | 0.00% |
| **Web Attacks** | 1,000 | 1,000 | 3.40% | **61.10%** | 1.20% | 16.90% | 0.00% |
| **Monday Benign Baseline** | 0 | 10,000 | N/A | N/A | **0.0700%** | N/A | **0.0000%** |

### Critical Observations:
1. **Candidate Policy Stability:** Between $\tau = 0.70$ and $\tau = 0.85$, policy recall is remarkably stable for high-volume attacks (PortScan 100%, DDoS 99.8%, SSH 99.0%, Botnet 98.4%, DoS Hulk 96.9%).
2. **The Web Attack Vulnerability:** Web Attacks stall at $61.10\%$ policy recall ($389$ false negatives) and only $16.90\%$ block recall ($831$ false negatives). The underlying Random Forest model has poor discriminator capability for SQL injection, XSS, and brute force attacks when represented purely by packet statistical flow features.
3. **Infiltration Sensitivity:** Infiltration attack recall drops sharply from $86.11\%$ at $\tau = 0.85$ down to $44.44\%$ at $\tau = 0.90$ and $41.67\%$ at $\tau = 0.92$. A strict threshold of $0.90$ cuts infiltration detection capability in half.

---

## 6. Statistical FPR Analysis (Monday Benign Traffic)

A primary release criterion for SentinelAI is that benign traffic must not suffer false containment.

### 6.1 Point Estimate vs. Confidence Interval
On the 10,000 pure benign flows from `Monday-WorkingHours.pcap_ISCX.csv`:
* Total Benign Flows ($N$): $10,000$
* True Negatives ($TN$): $9,993$
* False Positives ($FP$, escalated to `MONITOR`): $7$
* False Blocks (escalated to `BLOCK`): $0$

$$\text{Observed Point Estimate FPR} = \frac{7}{10,000} = \mathbf{0.0700\%} \quad (700 \text{ ppm})$$

Using the Wilson score interval with continuity correction at 95% confidence ($\alpha = 0.05, z = 1.96$):

$$w = \frac{2n \hat{p} + z^2 \pm z \sqrt{z^2 - \frac{1}{n} + 4n\hat{p}(1 - \hat{p}) + (4\hat{p} - 2)}}{2(n + z^2)}$$

Evaluating for $n = 10,000$ and $x = 7$:
* **Wilson 95% Lower Bound:** $0.0312\%$ ($312$ ppm)
* **Wilson 95% Upper Bound:** $\mathbf{0.1445\%}$ ($1,445$ ppm)

### 6.2 Formal Assessment Against Acceptance Threshold
* If the release criterion is defined as **Observed FPR $\le 0.10\%$**, the candidate policy passes ($0.0700\% \le 0.10\%$).
* If the release criterion is defined conservatively as **95% Confidence Upper Bound $\le 0.10\%$**, the candidate policy **FAILS** ($0.1445\% > 0.10\%$).
* In production, with millions of enterprise flows per day, an upper bound of $0.1445\%$ represents up to $1,445$ false alerts daily per million flows. Additional tuning or training on out-of-distribution benign traffic is warranted before full promotion.

---

## 7. Backend Ingestion Contract Defect Summary

The 10 isolated test cases executed in `test_backend_contract_isolated.js` confirmed that the candidate policy cannot be safely deployed without companion backend changes:

```
[PASS] TC-01: Valid MONITOR (score=0.85 -> action MONITOR, status MONITORING)
[PASS] TC-02: Valid BLOCK (score=0.95 -> action BLOCK, status BLOCKED)
[DEFECT CONFIRMED] TC-03: Model failure fallback action overwritten from MONITOR to ALLOW
[DEFECT CONFIRMED] TC-04: AI Engine HTTP timeout causes runFullPipeline() to fail-open silently
[PASS] TC-05: Null inference response safely drops flow
[PASS] TC-06: Null score defaults to 0.0 and ALLOW
[DEFECT CONFIRMED] TC-07: DEGRADED status demoted to DETECTED in threatService.js
[DEFECT CONFIRMED] TC-08: ThreatLog schema rejects status: 'DEGRADED' with Mongoose ValidationError
[PASS] TC-09: DB persistence error re-thrown cleanly
[PASS] TC-10: Candidate policy never converts model failure to BENIGN
```

Full technical logs, source code mappings, and remediation blueprints are documented in [`isolated_backend_contract_tests.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3b_reconciliation/isolated_backend_contract_tests.md).

---

## 8. Clarification: Offline Simulation vs. Production Containment

It is vital to distinguish between analytical offline block metrics and live enterprise containment:
1. **Zero Real Network Blocks:** In all evaluations performed, `sim_block_recall` and `sim_block_fpr` represent simulated calculations where `threat_score >= 0.90` and `action == 'BLOCK'`. 
2. **Safety Enforcements:** At no point was the Windows Firewall manipulated, no netsh/PowerShell commands were dispatched, and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` remained `false`.
3. **Autonomous Containment Invariant:** The system configuration maintains `AUTONOMOUS_CONTAINMENT=false`. Even in the active application, high-confidence threats are currently gated at `MONITORING` unless an operator manually invokes containment via the UI.
4. **Generalization Boundary:** All evaluations were performed on slices of the CICIDS2017 dataset. In-sample performance on historical synthetic pcaps does not guarantee equivalent detection against modern, evasive zero-day attacks or enterprise traffic shifts.

---

## 9. Authoritative Gate Verdict

```
+==================================================================================================+
|                                    GATE-1 RELEASE STATUS                                         |
+==================================================================================================+
|  VERDICT: GATE-1 OPEN                                                                            |
|  REASON:  Candidate ML policy demonstrates strong simulated detection gains across 5 attack      |
|           families, but Web Attack recall remains severely depressed (61.10%), the 95% Wilson    |
|           FPR upper bound exceeds 0.10% (0.1445%), and 4 critical backend ingestion defects      |
|           cause degraded fail-open bypasses and schema rejections.                               |
+==================================================================================================+
```

### Mandatory Prerequisites for Gate Closure:
1. Remediate `backend/services/aiEngineService.js` to prevent overriding Python policy actions.
2. Implement explicit fail-safe fallback logging on AI Engine Axios timeouts instead of silent `null` returns.
3. Update `backend/models/ThreatLog.js` enum to support `'DEGRADED'` and `'UNINSPECTED'` statuses.
4. Update `backend/services/threatService.js` to preserve degraded threat statuses.
5. Retrain or augment feature extraction for Web Attacks (SQLi, XSS, Brute Force).
6. Verify benign traffic on an independent, non-CICIDS2017 modern background traffic capture to confirm empirical FPR $< 0.10\%$ with 95% confidence.
