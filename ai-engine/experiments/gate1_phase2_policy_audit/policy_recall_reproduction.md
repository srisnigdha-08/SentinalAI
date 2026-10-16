# GATE-1 Phase 2: Policy Recall Reproduction and Disaggregated Outcome Report

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Scope**: Reproduction and verification of policy action recall, telemetry alert rates, and block rates using existing immutable saved artifacts  
**Evidence Source**: [`ai-engine/experiments/gate1_evaluation/evaluation_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_evaluation/evaluation_results.json)  
**Status**: **100% REPRODUCED AND VERIFIED**

---

## 1. Disaggregated Metric Reproduction Matrix

The table below provides an uncompromising separation of all pipeline outcomes. In strict compliance with audit standards, **`Unknown`**, **telemetry alerts**, **`MONITOR`**, and **`BLOCK`** are evaluated as distinct operational outcomes:

| Metric Category | Friday DDoS Capture (1k Benign, 1k Attack) | Friday PortScan Capture (1k Benign, 1k Attack) | Monday Pure Benign Capture (10k Benign) | Verification Status |
| :--- | :---: | :---: | :---: | :---: |
| **Total Evaluation Samples** | 2,000 flows | 2,000 flows | 10,000 flows | **CONFIRMED** |
| **Raw Classifier Attack Recall** | **99.90%** (999 / 1,000) | **98.50%** (985 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |
| **Raw Classifier Benign FPR** | **0.00%** (0 / 1,000) | **1.70%** (17 / 1,000) | **0.45%** (45 / 10,000) | **CONFIRMED** |
| **Composite Predictor Attack Recall** | **99.90%** (999 / 1,000) | **98.50%** (985 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |
| **Composite Predictor Benign FPR** | **40.00%** (400 / 1,000) | **6.40%** (64 / 1,000) | **13.73%** (1,373 / 10,000) | **CONFIRMED** |
| **Telemetry Alert Rate on Attack Flows** | **100.00%** (1,000 / 1,000) | **98.50%** (985 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |
| **Telemetry Alert Rate on Benign Flows** | **40.00%** (400 / 1,000) | **6.40%** (64 / 1,000) | **13.73%** (1,373 / 10,000) | **CONFIRMED** |
| **Policy Containment Recall (`BLOCK` or `MONITOR`)** | **76.60%** (766 / 1,000) | **7.40%** (74 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |
| **Policy Containment FPR on Benign** | **0.00%** (0 / 1,000) | **0.00%** (0 / 1,000) | **0.00%** (0 / 10,000) | **CONFIRMED** |
| **Autonomous Blocking Recall (`BLOCK` only)** | **0.50%** (5 / 1,000) | **0.00%** (0 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |
| **Autonomous Blocking FPR on Benign** | **0.00%** (0 / 1,000) | **0.00%** (0 / 1,000) | **0.00%** (0 / 10,000) | **CONFIRMED** |
| **ALLOW Rate on Confirmed Attack Flows** | **23.40%** (234 / 1,000) | **92.60%** (926 / 1,000) | N/A (Pure Benign) | **CONFIRMED** |

---

## 2. Granular Physical Flow Partitioning and Confusion Matrices

### 2.1 Friday DDoS Evaluation Stream (2,000 Flows)
- **Dataset**: [`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv) at offset 30,000.
- **Composition**: 1,000 ground-truth ambient benign flows + 1,000 ground-truth LOIC DDoS flows.

#### Outcome Cross-Tabulation on 1,000 DDoS Attack Flows:
```
Ground Truth: 1,000 DDoS Flows
  ├── Raw RF Classification:
  │     ├── Predicted DDoS: 999 flows (99.9%)
  │     └── Predicted BENIGN (False Negative): 1 flow (0.1%)
  └── Runtime Policy Actions Assigned:
        ├── Assigned BLOCK (score >= 0.92): 5 flows (0.5%)   <-- True Positive for Blocking
        ├── Assigned MONITOR (0.70 <= score < 0.92): 761 flows (76.1%) <-- True Positive for Monitoring
        └── Assigned ALLOW (score < 0.70): 234 flows (23.4%)  <-- False Negative for Containment!
```

#### Outcome Cross-Tabulation on 1,000 Ambient Benign Flows:
```
Ground Truth: 1,000 Benign Flows
  ├── Raw RF Classification:
  │     ├── Predicted BENIGN: 1,000 flows (100.0%)
  │     └── Predicted Attack (False Positive): 0 flows (0.0%)
  ├── Isolation Forest Anomaly Detection:
  │     ├── Inlier: 593 flows (59.3%)
  │     └── Outlier (Anomaly): 407 flows (40.7%)
  ├── Composite Predictor Labels:
  │     ├── BENIGN: 600 flows (60.0%)
  │     └── Unknown: 400 flows (40.0%, threatScore = 0.55)
  └── Runtime Policy Actions Assigned:
        ├── Assigned ALLOW: 1,000 flows (100.0%)  <-- 0 False Positives for Policy
        ├── Assigned MONITOR: 0 flows (0.0%)
        └── Assigned BLOCK: 0 flows (0.0%)
```

---

### 2.2 Friday PortScan Evaluation Stream (2,000 Flows)
- **Dataset**: [`Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/cicids2017/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv) at offset 30,000.
- **Composition**: 1,000 ground-truth ambient benign flows + 1,000 ground-truth PortScan flows.

#### Outcome Cross-Tabulation on 1,000 PortScan Attack Flows:
```
Ground Truth: 1,000 PortScan Flows
  ├── Raw RF Classification:
  │     ├── Predicted Port Scan: 958 flows (95.8%)
  │     ├── Predicted DDoS: 23 flows (2.3%)
  │     ├── Predicted Malware Beacon: 4 flows (0.4%)
  │     └── Predicted BENIGN (False Negative): 15 flows (1.5%)
  │     Total Detected by RF: 985 flows (98.5% Recall)
  └── Runtime Policy Actions Assigned:
        ├── Assigned BLOCK (score >= 0.92): 0 flows (0.0%)   <-- Exactly ZERO blocked!
        ├── Assigned MONITOR (0.70 <= score < 0.92): 74 flows (7.4%) <-- Only 74 monitored!
        └── Assigned ALLOW (score < 0.70): 926 flows (92.6%)  <-- 926 ATTACKS ALLOWED!
```

#### Outcome Cross-Tabulation on 1,000 Ambient Benign Flows:
```
Ground Truth: 1,000 Benign Flows
  ├── Raw RF Classification:
  │     ├── Predicted BENIGN: 983 flows (98.3%)
  │     └── Predicted Attack (False Positive): 17 flows (1.7%)
  ├── Isolation Forest Anomaly Detection:
  │     ├── Inlier: 953 flows (95.3%)
  │     └── Outlier (Anomaly): 47 flows (4.7%)
  ├── Composite Predictor Labels:
  │     ├── BENIGN: 936 flows (93.6%)
  │     ├── Unknown: 47 flows (4.7%)
  │     └── Attack Class: 17 flows (1.7%)
  └── Runtime Policy Actions Assigned:
        ├── Assigned ALLOW: 1,000 flows (100.0%)  <-- 0 False Positives for Policy
        ├── Assigned MONITOR: 0 flows (0.0%)
        └── Assigned BLOCK: 0 flows (0.0%)
```

---

## 3. Discrepancy Reconciliation Summary

1. **Why is Policy Recall only 7.4% on PortScan despite 98.5% RF Recall?**
   - **CONFIRMED**: The policy formula suppresses threat scores by multiplying RF confidence by 0.70. When Isolation Forest evaluates PortScan flows as inliers ($\text{if\_sig} = 0.0$), the maximum possible threat score is $0.70 \times 1.0 = 0.70$.
   - Any flow with $P_{RF} < 1.0$ falls strictly below the `0.70` threshold, forcing the action to **`ALLOW`**.
   - Exactly **926 PortScan flows** fell into this range and were allowed through.
2. **Why is Blocking Recall only 0.5% on DDoS despite 99.9% RF Recall?**
   - **CONFIRMED**: `BLOCK_THRESHOLD` is set to $0.92$. To achieve a score $\ge 0.92$, a flow requires $0.7 \cdot P_{RF} + 0.3 \cdot \text{if\_sig} \ge 0.92$.
   - Even if $P_{RF} = 1.0$, the flow requires an anomaly signal $\text{if\_sig} \ge 0.733$ (extreme outlier saturation).
   - Only 5 out of 1,000 DDoS flows exhibited an anomaly signal sufficient to reach $0.92$. 761 reached `MONITOR`, and 234 received `ALLOW`.
3. **Audit Finding**:
   - Zero policy false alarms on benign traffic was purchased at the direct cost of severe false negatives on attacks.
