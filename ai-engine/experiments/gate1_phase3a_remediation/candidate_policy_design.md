# SentinelAI — GATE-1 Phase 3A: Candidate Policy Design Specification

**Document Version:** 1.0.0  
**Phase:** GATE-1 Phase 3A (Isolated Policy Remediation)  
**Author:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Date:** October 16, 2026  
**Status:** **EXPERIMENTAL CANDIDATE ONLY (ISOLATED HARNESS — NO PRODUCTION MODIFICATION)**

---

## 1. Executive Summary & Problem Statement

In the Phase 2 Policy Logic Audit, an empirical reconciliation proved that SentinelAI's baseline threat scoring logic suffered from a severe **policy recall collapse**:
- **PortScan Policy Recall:** **7.40%** (74 / 1,000 attacks reached `MONITOR`, 0 reached `BLOCK`, and **926 attacks received `ALLOW`**).
- **DDoS Policy Recall:** **76.60%** (766 / 1,000 attacks reached `MONITOR` or `BLOCK`, while **234 attacks received `ALLOW`**).
- **Benign Traffic Safety:** 0.00% false positive action rate (10,000 / 10,000 benign received `ALLOW`).

### Root-Cause Diagnosis
The baseline scoring formula in `ai-engine/inference/predictor.py` (lines 290–292):
$$\text{threatScore} = \text{round}(0.7 \cdot \text{rf\_s} + 0.3 \cdot \text{if\_sig}, 4)$$
imposes a **multiplicative attenuation trap**. When an attack flow exhibits feature values that lie within the high-density normal distribution of packet lengths and inter-arrival times (as is characteristic of reconnaissance port scans), the Isolation Forest correctly identifies the flow as a geometric inlier, yielding $\text{if\_sig} = 0.0$.

Under this condition:
$$\text{threatScore} = 0.7 \cdot P_{RF} + 0.3 \cdot 0.0 = 0.7 \cdot P_{RF} \le 0.70$$
Because the operational containment threshold `MONITOR_THRESHOLD = 0.70`, any supervised confidence $P_{RF} < 1.00$ automatically forces $\text{threatScore} < 0.70$, assigning `action = "ALLOW"`. Even a flow detected with 99.0% Random Forest confidence ($P_{RF} = 0.99$) only achieves a threat score of $0.6930 < 0.70$, permitting the attack to pass unmonitored.

---

## 2. Design Principles for Decoupled Policy

The candidate policy remediation adheres to four non-negotiable architectural principles:

1. **Decouple Independent Detection Signals**:
   Supervised classification and unsupervised anomaly detection serve complementary, orthogonal defensive roles. A high-confidence supervised attack prediction ($P_{RF} \ge \tau$) must directly drive incident triage and monitoring without being attenuated by unsupervised normality. Anomaly detection must act as an *additive booster* for attacks, never an attenuating penalty.

2. **Strict Invariant on Benign Outlier Safety**:
   Legitimate, bursty, or novel benign flows flagged as outliers by the Isolation Forest ($C_{RF} = \text{"BENIGN"}$, $s_{IF} < -0.55$) must be labeled as `"Unknown"` with an informational threat score of $0.55$. Because $0.55 < \text{MONITOR\_THRESHOLD} (0.70)$, the operational action strictly remains `ALLOW`. This preserves zero false-positive containment disruptions.

3. **Fail-Safe Service Failure Architecture**:
   If model inference experiences timeouts, non-finite values, or service unreachability:
   - **Never convert uninspected traffic into a false claim that the flow is `BENIGN`.**
   - **Never default to automated host `BLOCK`** (preventing automated self-inflicted denial of service).
   - Explicitly emit `status: "DEGRADED"` / `action: "MONITOR"` with an observable audit record.

4. **Permanent Containment Gating**:
   A decision of `action = "BLOCK"` is an eligibility classification only. Automated host firewall rule injection remains strictly disabled (`AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) and requires human analyst approval in this environment.

---

## 3. Candidate Policy Decision Table

Let:
- $C_{RF} \in \{\text{BENIGN}, \text{DDoS}, \text{Port Scan}, \text{Botnet}, \dots\}$: Supervised predicted class.
- $P_{RF} \in [0.0, 1.0]$: Supervised class probability ($\max_k P(Y=k \mid X)$).
- $s_{IF} \in \mathbb{R}$: Raw Isolation Forest `score_samples()` output.
- $\sigma_{IF} \in [0.0, 1.0]$: Normalized anomaly signal from `calculate_if_anomaly_signal(s_{IF})`.
- $\text{is\_anomaly} \in \{\text{True}, \text{False}\}$: True if $s_{IF} < -0.55$.
- $\tau_{exp} = 0.85$: Experimental confidence hypothesis threshold.

| Rule ID | Supervised Class ($C_{RF}$) | Supervised Confidence ($P_{RF}$) | Anomaly Outlier ($\text{is\_anomaly}$) | Resulting Class | Resulting Threat Score ($S$) | Action | Severity | Operational Disposition |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **R-1** | `BENIGN` | Any | No ($\sigma_{IF} = 0$) | `BENIGN` | $0.05$ | **`ALLOW`** | `LOW` | Normal benign traffic. Zero alerts. |
| **R-2** | `BENIGN` | Any | Yes ($\sigma_{IF} > 0$) | `Unknown` | $0.55$ | **`ALLOW`** | `MEDIUM` | Novelty/Zero-day discovery. Informational telemetry; zero containment action. |
| **R-3** | Attack | $P_{RF} < 0.60$ | No | $C_{RF}$ | $\text{round}(P_{RF} \cdot 0.80, 4)$ | **`ALLOW`** | `LOW` | Low-confidence attack detection. Suppressed below 0.70 to prevent false alarms. |
| **R-4** | Attack | $0.60 \le P_{RF} < 0.70$ | No | $C_{RF}$ | $\text{round}(P_{RF} \cdot 0.90, 4)$ | **`ALLOW`** | `MEDIUM` | Borderline detection. Logged as informational alert. |
| **R-5** | Attack | $0.70 \le P_{RF} < \tau_{exp}$ | No | $C_{RF}$ | $\text{round}(P_{RF}, 4)$ | **`MONITOR`** | `HIGH` | Confirmed attack detection. Analyst triage and async threat intelligence dispatch. |
| **R-6** | Attack | $0.70 \le P_{RF} < \tau_{exp}$ | Yes | $C_{RF}$ | $\min(P_{RF} + 0.15 \cdot \sigma_{IF}, 0.919)$ | **`MONITOR`** | `HIGH` | Consensus attack with anomaly reinforcement. Escalated within MONITOR tier. |
| **R-7** | Attack | $P_{RF} \ge \tau_{exp} (0.85)$ | No ($\sigma_{IF} = 0$) | $C_{RF}$ | $\text{round}(P_{RF}, 4)$ | **`MONITOR`** (or `BLOCK` if $P_{RF} \ge 0.92$) | `HIGH` / `CRITICAL` | High-confidence supervised attack. Directly preserves recall on inlying scans! |
| **R-8** | Attack | $P_{RF} \ge \tau_{exp} (0.85)$ | Yes ($\sigma_{IF} > 0$) | $C_{RF}$ | $\min(P_{RF} + 0.10 \cdot \sigma_{IF}, 0.99)$ | **`BLOCK`** (if $S \ge 0.92$) else **`MONITOR`** | `CRITICAL` | Full-consensus attack. Highest containment priority candidate. |
| **R-9** | Failure | N/A (Timeout / Error) | N/A | `UNINSPECTED` | $0.50$ | **`MONITOR`** | `MEDIUM` | Fail-safe degraded fallback. Never claims BENIGN; never blocks automatically. |
| **R-10**| Invalid | N/A (NaN / Inf / Schema) | N/A | `INVALID_INPUT` | $0.00$ | **`ALLOW_AUDITED`** | `LOW` | Validation rejection. Logged to security audit; does not crash pipeline. |

---

## 4. Mathematical Properties & Proof of Non-Attenuation

Under Rule **R-7**:
For any attack where $C_{RF} \ne \text{"BENIGN"}$ and $P_{RF} \ge 0.70$:
$$S \ge P_{RF} \ge 0.70$$
Therefore:
$$\text{action} \in \{\text{MONITOR}, \text{BLOCK}\}$$
This mathematically eliminates the attenuation trap where $0.7 \cdot P_{RF} < 0.70$.

Under Rule **R-2**:
For any benign flow where $C_{RF} == \text{"BENIGN"}$:
$$S = \begin{cases} 0.05 & \text{if } \neg\text{is\_anomaly} \\ 0.55 & \text{if } \text{is\_anomaly} \end{cases}$$
Because $\max(0.05, 0.55) = 0.55 < \text{MONITOR\_THRESHOLD} (0.70) < \text{BLOCK\_THRESHOLD} (0.92)$:
$$\text{action} = \text{"ALLOW"}$$
This mathematically guarantees that benign traffic, regardless of its anomaly deflection, will **never** receive `MONITOR` or `BLOCK`. The theoretical upper bound of benign containment false-positive rate under this rule is identically $0.00\%$.

---

## 5. Failure Mode and Degraded Policy Specification

Inference subsystems can fail through several distinct modes:
1. **Network / Socket Timeout** (`requests.exceptions.Timeout`, axios timeout `10000ms`).
2. **Missing or Non-Finite Features** (`NaN`, `+Inf`, `-Inf`, missing dictionary keys).
3. **Model Artifact Unavailability** (`ModelUnavailableError`, corrupted pickle, memory allocation failure).
4. **Unhandled Runtime Exception** in scaler or tree explainer.

### Fail-Safe Contract
```python
def handle_inference_failure(reason: str, error_detail: str) -> dict:
    return {
        "predictedClass": "UNINSPECTED_TRAFFIC",
        "threatScore": 0.50,
        "severity": "MEDIUM",
        "confidence": 0.0,
        "isAnomaly": False,
        "anomalyScore": 0.0,
        "action": "MONITOR",
        "status": "DEGRADED",
        "failureReason": reason,
        "errorDetail": error_detail,
        "isFailSafeFallback": True,
        "requiresHumanReview": True
    }
```
**Rationale for `threatScore: 0.50` and `action: "MONITOR"` on Service Failure:**
- If set to `threatScore: 0.0` and `action: "ALLOW"`, an attacker who intentionally triggers inference timeouts (algorithmic complexity attack or denial-of-service against the AI engine) would bypass detection completely ("fail-open evasion").
- If set to `threatScore: 1.0` and `action: "BLOCK"`, an attacker who overwhelms the AI engine would cause the system to block all legitimate network traffic ("fail-closed self-inflicted denial of service").
- Setting `action: "MONITOR"` flags the traffic for analyst visibility and telemetry alerting without initiating host isolation or disruptive firewall rules.
