# SentinelAI GATE-1: Frozen Release-Gate Acceptance Criteria

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Status**: **FROZEN PRIOR TO HOLDOUT EVALUATION**  
**Mandatory Enforcement**: Immutable Benchmark Specification (No Threshold Tuning Allowed on Test Data)

---

## 1. Objective and Anti-Overfitting Governance

To prevent p-hacking, retrospective threshold tuning, and data snooping, all quantitative acceptance criteria for SentinelAI GATE-1 closure are formally frozen in this document. 

> [!IMPORTANT]
> **Freeze Policy**:
> 1. Classification thresholds (Block Threshold $\tau_B = 0.85$, Monitor Threshold $\tau_M = 0.70$) are locked.
> 2. Acceptance metrics must be evaluated on unseen, leakage-free holdout datasets without iterative parameter adjustment.
> 3. If any frozen criterion is violated, GATE-1 must remain OPEN.

---

## 2. Quantitative Acceptance Thresholds

### 2.1. Benign Traffic False-Positive Constraints
In production enterprise environments, false positives inflict immediate operational disruption (denial of legitimate service or SOC alert fatigue):

1. **Observed Benign False Positive Rate (FPR)**:
   $$\text{Observed FPR} = \frac{FP}{FP + TN} < \mathbf{0.05\%}\ (5\text{ false alarms per }10,000\text{ flows})$$
2. **Statistical Confidence Upper Bound (Wilson 95% Score)**:
   $$\mathbf{Upper_{95\%}\text{ (Wilson)}} < \mathbf{0.10\%}\ (0.0010)$$
   *Criterion*: Point estimates alone are rejected. The 95% two-sided Wilson confidence interval upper bound must mathematically prove with $95\%$ certainty that the population false alarm rate is strictly below 1 in 1,000 flows.
3. **Separate Action Limits for Benign Traffic**:
   - **Simulated Autonomous BLOCK False Positive Rate**:
     $$\text{FPR}_{BLOCK} < \mathbf{0.01\%}\ (1\text{ per }10,000\text{ flows})$$
     Autonomous containment must virtually never trigger on benign operations.
   - **MONITOR False Positive Rate**:
     $$\text{FPR}_{MONITOR} < \mathbf{0.09\%}\ (9\text{ per }10,000\text{ flows})$$
     Non-disruptive analyst triage alerts are capped to avoid queue exhaustion.

### 2.2. Multi-Attack Detection Recall Mandates
For an attack flow to be considered detected, the policy must escalate the transaction to at least `MONITOR` or `BLOCK`. Passing as `ALLOW` is a false negative.

| Primary Attack Category | Minimum Containment Recall ($\text{MONITOR} \cup \text{BLOCK}$) | Minimum Autonomous Simulated BLOCK Recall ($\text{BLOCK}$) | Maximum Miss Rate (`ALLOW`) |
| :--- | :---: | :---: | :---: |
| **PortScan / Reconnaissance** | $\ge \mathbf{95.0\%}$ | $\ge \mathbf{90.0\%}$ | $\le 5.0\%$ |
| **DDoS (LOIC / HOIC / UDP)** | $\ge \mathbf{98.0\%}$ | $\ge \mathbf{95.0\%}$ | $\le 2.0\%$ |
| **DoS Hulk / Application DoS** | $\ge \mathbf{95.0\%}$ | $\ge \mathbf{90.0\%}$ | $\le 5.0\%$ |
| **SSH Brute Force** | $\ge \mathbf{95.0\%}$ | $\ge \mathbf{90.0\%}$ | $\le 5.0\%$ |
| **Credential Stuffing / Web Brute Force** | $\ge \mathbf{90.0\%}$ | $\ge \mathbf{80.0\%}$ | $\le 10.0\%$ |
| **SQL Injection (SQLi)** | $\ge \mathbf{90.0\%}$ | $\ge \mathbf{85.0\%}$ | $\le 10.0\%$ |
| **Cross-Site Scripting (XSS)** | $\ge \mathbf{90.0\%}$ | $\ge \mathbf{80.0\%}$ | $\le 10.0\%$ |
| **Botnet C2 / Malware Beaconing** | $\ge \mathbf{90.0\%}$ | $\ge \mathbf{85.0\%}$ | $\le 10.0\%$ |
| **Infiltration / Lateral Movement** | $\ge \mathbf{90.0\%}$ | $\ge \mathbf{80.0\%}$ | $\le 10.0\%$ |

---

## 3. Data Quality, Statistical Power, and Sample Size Requirements

### 3.1. Statistical Power Sample Size Mandate ($N \ge 30,000$)
Why is $N = 30,000$ pure benign flows the conservative requirement?
- For a binomial proportion with zero observed false positives ($k = 0$) out of $n$ samples, the Wilson Score 95% upper bound is:
  $$\text{Upper}_{95\%}(0, n) = \frac{z^2 / n}{1 + z^2 / n} \approx \frac{1.95996^2}{n + 1.95996^2} = \frac{3.84144}{n + 3.84144}$$
- Evaluating at candidate sample sizes:
  - At $n = 5,000$: $\text{Upper} = \frac{3.84144}{5003.84} = 0.000767 = 0.0767\%$ (Marginal, allows zero headroom if even 1 FP occurs; 1 FP yields $\text{Upper} = 0.126\% > 0.10\%$).
  - At $n = 10,000$: If $1$ FP occurs, $\text{Upper} = 0.00085 = 0.085\%$; if $7$ FPs occur (Phase 4), $\text{Upper} = 0.001445 = 0.1445\% > 0.10\%$.
  - At $n = 30,000$: 
    * If $k = 0$: $\text{Upper} = \frac{3.84144}{30003.84} = 0.000128 = \mathbf{0.0128\%}$.
    * If $k = 10$ ($p = 0.000333$): $\text{Upper} = \mathbf{0.000623 = 0.0623\%} < 0.10\%$.
    * If $k = 18$ ($p = 0.000600$): $\text{Upper} = \mathbf{0.000965 = 0.0965\%} < 0.10\%$.
- **Conclusion**: A benchmark of $N \ge 30,000$ verified benign flows provides sufficient statistical power to bound the true population false alarm rate below $0.10\%$ even under realistic operational noise.

### 3.2. Attack Sample Sizing
- Each distinct attack category must have a minimum sample size of **$N \ge 500$ independent flows** ($N \ge 1,000$ preferred).
- Attack slices with $N < 100$ (such as the $N=36$ Infiltration slice in CICIDS2017) are formally designated **INSUFFICIENT SAMPLE SIZE** and cannot be used to certify release gate compliance.

---

## 4. Operational, Latency, and Contract Criteria

1. **Inference Latency Budget**:
   - Single flow Layer 4 classification: $\le \mathbf{5.0\text{ms}}$ ($p_{99} \le 15.0\text{ms}$).
   - Layer 7 payload pre-filtering (WAF inspection): $\le \mathbf{2.0\text{ms}}$ ($p_{99} \le 8.0\text{ms}$).
   - Total combined pipeline transaction latency: $\le \mathbf{10.0\text{ms}}$ per request.
2. **Invalid and Degraded Response Handling**:
   - Zero tolerance for fail-open on invalid scores (`NaN`, strings, $\pm\infty$, out-of-range $<0$ or $>1$).
   - Any model timeout, upstream HTTP 500, or corrupt score must deterministically route to:
     `status: 'DEGRADED'`, `action: 'MONITOR'`, `predictedClass: 'UNINSPECTED_TRAFFIC'`, `threatScore: 0.5`.
   - Under no circumstances may degraded traffic evaluate to `ALLOW`.
3. **Session and Flow Deduplication**:
   - Network flows sharing the exact 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) within an active TCP handshake window must be grouped into unified session events to prevent multiple duplicate alerts for a single request.
4. **Treatment of Encrypted or Non-HTTP Traffic**:
   - Non-HTTP protocols (SSH, DNS, NTP, raw TCP) or encrypted traffic without TLS termination must be explicitly flagged as `L7_UNAVAILABLE` and handed off directly to Layer 4 flow inspection without throwing runtime errors or failing open.

---

## 5. Criteria for Declaring an Evaluation Inconclusive

An evaluation run must be aborted or designated **INCONCLUSIVE** if:
1. More than $5.0\%$ of evaluation records have overlapping feature vectors with the training dataset.
2. Ground-truth labels are ambiguous, unverified, or exhibit encoding corruption exceeding $0.1\%$.
3. Feature schema drift is detected (`EXPECTED_FEATURE_COUNT != 53` or column order mismatch).
4. System clock jitter or logging truncation causes lost transaction records.
