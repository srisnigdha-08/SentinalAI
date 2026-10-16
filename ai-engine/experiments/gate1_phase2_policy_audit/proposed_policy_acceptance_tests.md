# GATE-1 Phase 2: Proposed Policy Acceptance Criteria and Test Specifications

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Scope**: Specifications, decision matrices, and acceptance tests for future policy logic remediation  
**Status**: **PROPOSAL ONLY (NO PRODUCTION CODE MODIFIED)**

---

## 1. Architectural Strategy for Policy Logic Remediation

The root-cause investigation proved that policy recall collapsed because:
$$\text{threatScore} = 0.7 \cdot P_{RF} + 0.3 \cdot \text{anomalySignal}$$
penalizes confident supervised detections when the attack is structurally inlying to Isolation Forest.

### Core Principles for Future Fix
1. **Decouple Independent Detection Signals**:
   A high-confidence supervised attack classification ($P_{RF} \ge 0.85$) should directly drive threat response, regardless of whether an unsupervised anomaly detector triggered.
2. **Distinct Operational Response Levels**:
   - **Informational Alert / Telemetry**: `status: 'DETECTED'` (threatScore $0.50 - 0.69$, action `ALLOW`).
   - **Triage / Heightened Monitoring**: `status: 'MONITORING'` (action `MONITOR`, dispatches Threat Intel, zero firewall changes).
   - **Automated Host Containment**: `status: 'BLOCKED'` (action `BLOCK`, applies firewall netsh rule only if `AUTONOMOUS_CONTAINMENT=true`).
3. **Fail-Safe Containment Invariants**:
   - High-volume ambient benign traffic flagged as `"Unknown"` must **NEVER** escalate to `BLOCK`.
   - Host isolation must require explicit human analyst authorization or extreme multi-signal consensus.

---

## 2. Proposed Decision Table (Future Policy Model)

| Rule ID | Supervised Class ($C_{RF}$) | Supervised Confidence ($P_{RF}$) | Unsupervised Outlier ($s_{IF} < -0.55$) | Proposed Label | Proposed Threat Score | Proposed Action | Intended Operational Outcome |
| :---: | :--- | :---: | :---: | :--- | :---: | :---: | :--- |
| **R-1** | `BENIGN` | Any | No | `BENIGN` | $0.05$ | **`ALLOW`** | Normal legitimate traffic. Zero alerts. |
| **R-2** | `BENIGN` | Any | Yes | `Unknown` | $0.55$ | **`ALLOW`** | Anomaly discovery. Emits telemetry, zero containment disruptions. |
| **R-3** | Confirmed Attack | $P_{RF} < 0.60$ | No | Attack Name | $P_{RF} \times 0.8$ | **`ALLOW`** | Low-confidence detection. Suppressed to avoid false blocks. |
| **R-4** | Confirmed Attack | $0.60 \le P_{RF} < 0.85$ | No | Attack Name | $P_{RF}$ | **`MONITOR`** | Medium-confidence detection. Enters analyst queue & threat intel. |
| **R-5** | Confirmed Attack | $P_{RF} \ge 0.85$ | No | Attack Name | $P_{RF}$ | **`MONITOR`** (or `BLOCK` if gated) | High-confidence attack. Immediate SOC alert; candidate for blocking. |
| **R-6** | Confirmed Attack | $P_{RF} \ge 0.85$ | Yes | Attack Name | $\min(P_{RF} + 0.10, 0.99)$ | **`BLOCK`** | Consensus attack (both classifiers agree). Highest containment priority. |

---

## 3. Proposed Automated Acceptance Test Specifications

When policy logic is refactored in a subsequent phase, the following 6 acceptance tests must pass before GATE-1 can be considered for closure:

### Test Case 1: PortScan Low-Anomaly Recall Recovery
- **Input Record**: Network flow matching PortScan attack signature ($C_{RF} = \text{"Port Scan"}$, $P_{RF} = 0.92$, $s_{IF} = -0.42 \implies \text{anomalySignal} = 0.0$).
- **Expected Prior Behavior**: `threatScore = 0.6440`, `action = "ALLOW"` (FAIL: Attack allowed).
- **Required Future Behavior**:
  - `threatScore >= 0.70`
  - `action in ["MONITOR", "BLOCK"]`
  - `status == "MONITORING"`
- **Assertion**: `assert result["action"] != "ALLOW"`

### Test Case 2: Ambient Benign DDoS Traffic Invariance
- **Input Record**: Legitimate web server flow during Friday DDoS attack ($C_{RF} = \text{"BENIGN"}$, $P_{RF} = 0.99$, $s_{IF} = -0.58 \implies \text{isAnomaly} = \text{True}$).
- **Required Behavior**:
  - `predictedClass == "Unknown"`
  - `threatScore <= 0.60`
  - `action == "ALLOW"`
  - `status == "DETECTED"`
- **Assertion**: `assert result["action"] == "ALLOW"` and `assert result["predictedClass"] == "Unknown"`

### Test Case 3: High-Confidence DDoS Containment
- **Input Record**: Verified LOIC DDoS flow ($C_{RF} = \text{"DDoS"}$, $P_{RF} = 0.99$, $s_{IF} = -0.65 \implies \text{isAnomaly} = \text{True}$).
- **Required Behavior**:
  - `threatScore >= 0.92`
  - `action == "BLOCK"`
  - `status == "BLOCKED"` (if autoBlockEnabled) or `"MONITORING"` (if locked)
- **Assertion**: `assert result["action"] == "BLOCK"`

### Test Case 4: Non-Finite and Malformed Input Sanitization
- **Input Record**: Flow record containing `{"Flow Duration": float("inf"), "Flow Bytes/s": "NaN"}`.
- **Required Behavior**:
  - Predictor or API must safely reject the record with HTTP 422 or sanitize to finite floats.
  - Zero unhandled 500 exceptions.
- **Assertion**: `assert np.isfinite(feature_vector).all()`

### Test Case 5: Policy Recall on 1,000 Physical PortScan Flows
- **Evaluation Dataset**: [`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv) (1,000 attack flows at offset 30,000).
- **Target Metrics**:
  - Policy Containment Recall (`action in ["BLOCK", "MONITOR"]`): **$\ge 90.0\%$** (recovering from current 7.4%).
  - Policy Benign FPR: **$\le 0.10\%$**.

### Test Case 6: Policy Recall on 1,000 Physical DDoS Flows
- **Evaluation Dataset**: [`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv) (1,000 attack flows at offset 30,000).
- **Target Metrics**:
  - Policy Containment Recall (`action in ["BLOCK", "MONITOR"]`): **$\ge 95.0\%$** (recovering from current 76.6%).
  - Policy Benign FPR: **$\le 0.10\%$**.
