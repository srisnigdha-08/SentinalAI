# SentinelAI GATE-1 Phase 6: Frozen Release-Gate Acceptance Specification

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Status**: **FROZEN PRIOR TO HOLDOUT EVALUATION (Version 2.0)**  
**Mandatory Enforcement**: Immutable Benchmark Specification (Parameter & Threshold Tuning Prohibited)

---

## 1. Governance and Anti-Overfitting Rules

To guarantee technical integrity and prevent p-hacking or retrospective threshold adjustment:
1. **Pre-Evaluation Freeze**: All thresholds (Block Threshold $\tau_B = 0.85$, Monitor Threshold $\tau_M = 0.70$, Anomaly Threshold $\tau_A = -0.55$) and Layer 7 regex rules are locked prior to holdout evaluation.
2. **Prohibition of Retrospective Tuning**: Thresholds or WAF patterns must not be altered after observing holdout failure modes.
3. **Audit Binding**: Any failure to satisfy these criteria mandates that GATE-1 remains strictly **OPEN**.

---

## 2. Benign Traffic False-Positive Acceptance Criteria

In high-throughput enterprise networks handling tens of millions of packets daily, false alarms cause self-inflicted denial of service or analyst alert saturation.

### 2.1. Mathematical False Positive Standards:
1. **Observed Benign False Positive Rate (FPR)**:
   $$\text{Observed FPR} = \frac{FP}{FP + TN} < \mathbf{0.05\%}\quad (5\text{ per }10,000\text{ flows})$$
2. **Two-Sided 95% Wilson Score Upper Bound**:
   $$\mathbf{Upper_{95\%}\text{ (Wilson)}} < \mathbf{0.1000\%}\quad (0.0010)$$
   *Criterion*: Point estimates are rejected. The 95% Wilson confidence upper bound must prove with $95\%$ statistical certainty that the true error rate is $< 0.10\%$.
3. **Disaggregated Action Thresholds**:
   - **Simulated Autonomous BLOCK FPR**:
     $$\text{FPR}_{BLOCK} < \mathbf{0.0100\%}\quad (\le 1\text{ false block per }10,000\text{ benign flows})$$
     Autonomous containment must virtually never disrupt legitimate operations.
   - **MONITOR Alert FPR**:
     $$\text{FPR}_{MONITOR} < \mathbf{0.0900\%}\quad (\le 9\text{ false alerts per }10,000\text{ benign flows})$$

### 2.2. Sample Sizing and the "Zero False Positive" Contract:
- **Minimum Benign Sample Sizing**: The evaluation corpus must contain at least **$N \ge 30,000$ independent, unpolluted benign flows**.
- **The Zero FP Question**: Does the contract explicitly require exactly zero false positives?
  - *Mathematical Answer*: **No**. While zero false positives out of 30,000 yields $Upper = 0.0128\%$, the contract permits up to **10 observed false alarms out of 30,000** ($p = 0.000333$):
    $$Upper_{95\%}(10, 30000) = \mathbf{0.0623\%} < 0.1000\% \quad (\text{Compliant})$$
  - However, observing $\ge 19$ false alarms out of 30,000 ($p = 0.000633$) yields:
    $$Upper_{95\%}(19, 30000) = \mathbf{0.1005\%} > 0.1000\% \quad (\text{Non-Compliant / Gate Blocked})$$
  - Therefore, the contract requires **statistically bounded compliance**, with an empirical target of $\le 10$ false alarms per $30,000$ flows.

---

## 3. Multi-Attack Detection Recall Criteria

For an attack flow to be credited as detected, the policy must escalate the transaction to at least `MONITOR` or `BLOCK`. Categorization as `ALLOW` is a false negative.

| Required Attack Category | Minimum Containment Recall ($\text{MONITOR} \cup \text{BLOCK}$) | Minimum Autonomous Simulated BLOCK Recall ($\text{BLOCK}$) | Maximum Permitted Miss Rate (`ALLOW`) |
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

### Attack Sample Sizing and Insufficiency Rules:
- **Minimum Attack Category Sizing**: $N \ge 500$ independent flows per attack class ($N \ge 1,000$ preferred).
- **Rule on Deficient Samples**: Any attack class with $N < 100$ flows (e.g., CICIDS2017 Infiltration $N=36$) is formally designated **INSUFFICIENT SAMPLE SIZE** and cannot be used to certify GATE-1 closure.

---

## 4. Contractual Latency and Failure-State Behavior

1. **Transaction Latency Budget**:
   - Layer 4 flow classification: $\le \mathbf{5.0\text{ms}}$ ($p_{99} \le 15.0\text{ms}$).
   - Layer 7 payload pre-filtering (WAF inspection): $\le \mathbf{2.0\text{ms}}$ ($p_{99} \le 8.0\text{ms}$).
   - Total pipeline transaction latency: $\le \mathbf{10.0\text{ms}}$ per request.
2. **Invalid and Corrupted Score Handling (Zero Fail-Open)**:
   - Any score that is `NaN`, non-numeric string, $\pm\infty$, or outside $[0.0, 1.0]$ must deterministically trigger:
     ```javascript
     {
       status: 'DEGRADED',
       action: 'MONITOR',
       predictedClass: 'UNINSPECTED_TRAFFIC',
       threatScore: 0.5,
       isDegraded: true
     }
     ```
   - No corrupted or uninspected transaction may ever fail open to `ALLOW`.
3. **Protocol and Encryption Visibility Handling**:
   - For non-HTTP protocols (SSH, DNS, NTP) or encrypted traffic without TLS termination, the Layer 7 module must emit `L7_UNAVAILABLE` and fall back to the Layer 4 Candidate Flow Classifier without throwing errors.

---

## 5. Criteria for Declaring an Evaluation Inconclusive

An evaluation run must be declared **INCONCLUSIVE** if:
1. Feature overlap with training records exceeds $5.0\%$ of evaluation rows.
2. Ground-truth labels exhibit unresolvable encoding artifacts exceeding $0.1\%$.
3. Memory starvation, socket truncation, or pipeline timeouts corrupt $> 0.05\%$ of records.
