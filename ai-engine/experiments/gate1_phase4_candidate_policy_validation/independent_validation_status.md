# SentinelAI GATE-1 Phase 4: Independent Validation Status & Release-Gate Evaluation

**Auditor / Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Evaluation Scope**: 23,036 Network Flows across 8 Daily PCAP Captures  
**Status**: **INDEPENDENT VALIDATION BLOCKED**  
**Gate 1 Verdict**: **MUST REMAIN OPEN**

---

## 1. Executive Summary & Acceptance Criteria Scorecard

To close GATE-1, the SentinelAI detection and containment policy must satisfy three non-negotiable security criteria established in the release-gate specification:
1. **Benign False-Positive Safety**: Observed FPR $< 0.10\%$ **AND** its 95% Wilson Score upper bound must also be $< 0.10\%$.
2. **Multi-Attack Recall Robustness**: Every primary attack vector must achieve $\ge 90.0\%$ detection recall with no policy-induced suppression.
3. **Genuine Out-of-Distribution Independence**: The evaluation dataset must be leakage-controlled and free of in-sample training contamination.

### Acceptance Scorecard:

| Release Criterion | Required Benchmark | Active Production Policy | Candidate Decoupled Policy | Compliance Status |
| :--- | :---: | :---: | :---: | :---: |
| **Benign FPR (Observed)** | $< 0.10\%$ | $0.00\%$ ($0/10,000$) | $0.07\%$ ($7/10,000$) | **PASS** |
| **Benign FPR (Wilson 95% Upper Bound)** | $< 0.10\%$ | $0.00\%$ | **$0.1445\%$** ($> 0.10\%$) | **FAILED (Blocker)** |
| **PortScan Recall** | $\ge 90.0\%$ | $0.00\%$ (Collapsed) | **$100.00\%$** (CI: 99.62%–100%) | **PASS** |
| **DDoS Recall** | $\ge 90.0\%$ | $72.00\%$ (Suppressed) | **$99.80\%$** (CI: 99.27%–99.95%) | **PASS** |
| **SSH-Patator Recall** | $\ge 90.0\%$ | $46.10\%$ | $98.90\%$ (In-sample) | **INVALID (Data Leakage)** |
| **Botnet Recall** | $\ge 90.0\%$ | $45.60\%$ | $98.50\%$ (In-sample) | **INVALID (Data Leakage)** |
| **DoS Hulk Recall** | $\ge 90.0\%$ | $65.90\%$ | **$96.70\%$** (CI: 95.40%–97.64%) | **PASS** |
| **Infiltration Recall** | $\ge 90.0\%$ | $75.00\%$ | **$86.11\%$** (CI: 71.34%–93.92%) | **FAILED (Insufficient: $N=36$)** |
| **Web Attack Recall** | $\ge 90.0\%$ | $7.50\%$ | **$60.90\%$** (CI: 57.84%–63.88%) | **CRITICAL FAILURE (Blocker)** |
| **Dataset Leakage Independence** | 100% Holdout | Overlap in 4 slices | Overlap in 4 slices | **FAILED (Blocker)** |

---

## 2. Statistical False-Positive Upper-Bound Failure

The GATE-1 specification mandates that the benign false-positive requirement cannot be certified based solely on sample point estimates. Because production gateways handle tens of millions of packets daily, the 95% Wilson score upper bound must remain below $0.10\%$ ($0.0010$).

### Mathematical Evaluation on Monday Pure Benign Benchmark ($N=10,000$):
- Observed Benign False Positives: **$7$ out of $10,000$** flows ($p = 0.00070 = 0.070\%$).
- Exact Wilson Score Interval:
  $$centre = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}} = \frac{0.0007 + \frac{1.95996^2}{20000}}{1 + \frac{1.95996^2}{10000}} = 0.000891$$
  $$std = \frac{z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} = 0.000552$$
  $$CI_{95\%} = [centre - std, centre + std] = [0.00034, \mathbf{0.001445}]$$
- **Result**: The 95% confidence upper bound is **$0.1445\%$ ($14.45$ per $10,000$ flows)**.
- **Verdict**: Because $0.1445\% > 0.10\%$, **the candidate policy fails Criterion 1**. A sample size of at least $30,000$ verified zero-false-positive benign flows would be mathematically required to prove an upper bound $< 0.10\%$.

---

## 3. Investigation of Weak Web Attack Performance (Criterion 2 Failure)

Under the candidate policy, Web Attack recall reached only **$60.90\%$** ($609/1000$), with simulated autonomous BLOCK recall collapsing to **$15.60\%$** ($156/1000$). Nearly $40\%$ of Web Attacks ($391/1000$) were completely missed and classified as `ALLOW`.

### Root Cause Analysis:
1. **L7 Payload Blindspot in L4 Flow Features**:
   - The Random Forest operates on 53 statistical flow features (packet size variance, inter-arrival times, TCP window flags, flow duration).
   - SQL Injection, XSS, and Web Brute Force attacks in CICIDS2017 were executed over standard HTTP/1.1 TCP connections consisting of 3 to 10 packets.
   - Statistically, a web attack packet exchange is indistinguishable from a legitimate web user fetching an HTML page or API endpoint.
2. **Confidence Degradation**:
   - Because L4 statistical features lack SQL keywords (`UNION SELECT`, `' OR 1=1`) and XSS tags (`<script>`), the Random Forest classifier produces low-to-medium confidence ($p \in [0.45, 0.68]$).
   - The candidate policy's qualification threshold requires $p \ge 0.70$ for `MONITOR` and $p \ge 0.85$ for high-confidence preservation. Consequently, borderline attack flows are attenuated below the monitor threshold into `ALLOW`.
3. **Architectural Implication**:
   - Web application security cannot be achieved via L4 transport statistical flow features alone. It fundamentally requires Layer 7 application inspection (WAF / reverse proxy) or specialized payload embedding models.

---

## 4. Training Ingestion Overlap (Criterion 3 Failure)

As documented in [`dataset_provenance_reconciliation.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase4_candidate_policy_validation/dataset_provenance_reconciliation.md), `ai-engine/training/train.py` ingested **100% of all available instances** of `SSH-Patator` ($5,897$), `Web Attacks` ($2,180$), `Infiltration` ($36$), and `Botnet` ($1,966$).

- Evaluating the model on slices extracted from those same captures constitutes **in-sample resubstitution**, not independent validation.
- The high recall figures for SSH-Patator ($98.9\%$) and Botnet ($98.5\%$) reflect training set memorization, not out-of-distribution generalization.
- Because a true, blind holdout dataset collected from a different network topology or date was never captured or partitioned, **independent validation is formally BLOCKED**.

---

## 5. Authoritative GATE-1 Verdict

$$\mathbf{GATE\text{-}1\ STATUS:\ OPEN}$$

**Blocking Justification**:
1. The 95% Wilson upper bound on benign false positives ($0.1445\%$) exceeds the $< 0.10\%$ release mandate.
2. Web Attack recall ($60.90\%$) and Infiltration recall ($86.11\%$) fail the $\ge 90.0\%$ multi-attack detection standard.
3. Direct training data contamination in minority attack slices prevents certifying out-of-sample generalization.
4. Autonomous containment (`AUTONOMOUS_CONTAINMENT=false`) and real firewall enforcement (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) must remain permanently disabled.
