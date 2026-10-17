# SentinelAI GATE-1 Phase 7: Frozen Acceptance Criteria & Statistical Verification Protocol

**Auditor / Lead ML Safety Engineer**: Senior Machine Learning Security Engineer & Independent Auditor  
**Date**: 2026-10-16  
**Evaluation Scope**: CSE-CIC-IDS2018 Genuine Out-of-Distribution Network Holdout  
**Safety Status**: GATE-1 OPEN. Autonomous containment and real firewall enforcement remain strictly disabled.  

---

## 1. Frozen Evaluation Thresholds & Statistical Standards

All metrics are evaluated using **95% Wilson Score Confidence Intervals** for binomial proportions:

$$\hat{p} = \frac{x}{n}$$

$$p_{\pm} = \frac{\hat{p} + \frac{z^2}{2n} \pm z\sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}} \quad (z = 1.95996)$$

### Mandatory Acceptance Criteria:

| ID | Metric / Area | Required Threshold | Evaluated Population | Critical Failure Condition |
| :--- | :--- | :--- | :--- | :--- |
| **AC-01** | Benign False Positive Rate (Point) | $\le 0.10\%$ ($\le 10$ per 10,000) | $N = 30,000$ pure benign holdout flows | $\text{FPR} > 0.10\%$ |
| **AC-02** | Benign False Positive (Wilson 95% UB) | $< 0.10\%$ | $N = 30,000$ pure benign holdout flows | $\text{Wilson UB} \ge 0.1000\%$ |
| **AC-03** | Infiltration Attack Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $N = 2,000$ unseen Infiltration flows | Recall $< 90.0\%$ |
| **AC-04** | Web Attack Transport Flow Recall | Baseline audit only | $N = 566$ Web Attack flows | Informational |
| **AC-05** | Combined Policy Web Attack Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | Combined L7 WAF + Candidate Policy | Recall $< 90.0\%$ |
| **AC-06** | Brute Force (SSH & FTP) Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $N = 2,000$ Brute Force flows | Recall $< 90.0\%$ |
| **AC-07** | Botnet Attack Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $N = 2,000$ Botnet flows | Recall $< 90.0\%$ |
| **AC-08** | DDoS / DoS Attack Recall | $\ge 95.0\%$ (Detection), $\ge 85.0\%$ (Sim. Block) | $N = 2,000$ DDoS/DoS flows | Recall $< 95.0\%$ |
| **AC-09** | Protected Asset Integrity | 100% SHA-256 match, 0 bytes drift | All 5 protected model & Q-table files | Any hash mismatch |
| **AC-10** | Safety Boundaries Preservation | `AUTONOMOUS_CONTAINMENT=false`<br>`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` | Runtime configuration & system state | Any real containment |

---

## 2. Decision Policy Definitions

- **Detection Recall**: Fraction of true attack flows that trigger an operational security posture (`MONITOR` or `BLOCK`):
  $$\text{Recall}_{\text{detect}} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
- **Simulated Autonomous Block Recall**: Fraction of true attack flows that reach or exceed the autonomous block threshold:
  $$\text{Recall}_{\text{block}} = \frac{\text{Block TP}}{\text{TP} + \text{FN}}$$
- **Benign False Positive Rate (FPR)**:
  $$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$
- **Wilson Score Interval**: Must be calculated for all rates to rigorously quantify sampling uncertainty.
