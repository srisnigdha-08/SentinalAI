# SentinelAI GATE-1 Phase 7 Independent Audit: Feature & Generalization Diagnosis

**Audit Scope**: Feature Schema Verification, Tree Path Diagnostics, Feature Importance, Integer-Overflow Claim Verification, and Out-of-Distribution Generalization Failure Analysis  
**Auditor**: Senior ML Evaluation Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Audited Models**: `rf_classifier_cicids_v2.pkl` and `isolation_forest_cicids.pkl`  

---

## 1. Feature Schema & 80-to-53 Mapping Validation

The auditor inspected `ai-engine/utils/features.py` and `ai-engine/experiments/gate1_phase7_cse2018_validation/preprocess_cse2018.py`:
- **Dimensionality**: Exactly 53 features (`EXPECTED_FEATURE_COUNT = 53`, `FEATURE_SCHEMA_VERSION = "v2.1_53feat"`).
- **Pipeline Structure**: `rf_classifier_cicids_v2.pkl` is an `sklearn.pipeline.Pipeline` consisting of:
  1. `StandardScaler` (53 features in, 53 features out)
  2. `RandomForestClassifier` (200 estimators, `max_depth=20`, `min_samples_split=5`, `class_weight='balanced'`)
- **Deterministic 80-to-53 Mapping**:
  * Features 0–49: Mapped 1-to-1 from CSE-CIC-IDS2018 CSV columns (e.g. `Flow Duration`, `Tot Fwd Pkts`, `Init Fwd Win Byts`).
  * Feature 50 (`payload_entropy`): Mathematically derived via $-p_f \log_2(p_f) - p_b \log_2(p_b)$ from forward and backward packet lengths.
  * Features 51 & 52 (`time_of_day_sin`, `time_of_day_cos`): Derived from `Timestamp` (`dd/MM/yyyy HH:mm:ss`) via $\sin(2\pi \cdot t / 86400)$ and $\cos(2\pi \cdot t / 86400)$.
- **Feature Order and Numerical Equivalence**:
  The auditor tested numerical parity between row-by-row extraction (`extract_features_from_record`) and vectorized extraction (`transform_raw_df_to_sentinel_features`). The maximum absolute discrepancy across features 0–50 was **0.0117**, entirely attributable to 32-bit floating-point precision differences.

---

## 2. Feature Importance Diagnostics

The auditor extracted the Gini feature importances across all 200 trees in `rf_classifier_cicids_v2.pkl`:

| Rank | Feature Name | Gini Importance | Cumulative Importance | Architectural Interpretation |
| :---: | :--- | :---: | :---: | :--- |
| **1** | `init_win_bytes_backward` | **0.0993** (9.93%) | 9.93% | Initial TCP window size (backward). Top model driver. |
| **2** | `fwd_packet_len_max` | **0.0511** (5.11%) | 15.04% | Max forward packet length in bytes. |
| **3** | `init_win_bytes_forward` | **0.0498** (4.98%) | 20.02% | Initial TCP window size (forward). |
| **4** | `total_fwd_packets` | **0.0470** (4.70%) | 24.72% | Packet count in forward direction. |
| **5** | `fwd_packet_len_mean` | **0.0457** (4.57%) | 29.29% | Mean packet size in forward direction. |
| **6** | `fwd_header_len` | **0.0429** (4.29%) | 33.58% | Forward IP/TCP header length in bytes. |
| **7** | `total_len_bwd_packets` | **0.0402** (4.02%) | 37.60% | Total payload volume backward. |
| **8** | `bwd_packet_len_max` | **0.0392** (3.92%) | 41.52% | Max backward packet size. |
| **9** | `total_len_fwd_packets` | **0.0384** (3.84%) | 45.36% | Total payload volume forward. |
| **10** | `bwd_packet_len_min` | **0.0346** (3.46%) | 48.82% | Min backward packet size. |

Top 3 features (`init_win_bytes_backward`, `fwd_packet_len_max`, `init_win_bytes_forward`) account for over **20% of all decision criteria**.

---

## 3. Audit of the "Negative Header Length" Artifact Claim

In the Phase 7 report, it was claimed that:
> *"In CICIDS2017, a 32-bit integer overflow bug caused `fwd_header_len` to wrap into negative numbers (training mean: -9,232). Decision trees keyed on these negative values as attack indicators."*

### Empirical Verification:
The auditor parsed every tree in the Random Forest forest and examined all split nodes involving `fwd_header_len` (feature index 39):
1. **Total Split Nodes on `fwd_header_len`**: **4,044 nodes**.
2. **Nodes with Negative Split Thresholds**: **1 node (0.02%)** (threshold: -41,942,542).
3. **Nodes with Positive Split Thresholds**: **4,043 nodes (99.98%)** (median threshold: **+62.0 bytes**).

### Auditor Finding: **CLAIM CONTRADICTED / PARTIALLY INACCURATE**
- **Fact**: The CICIDS2017 training dataset *did* contain corrupted negative header values from a 32-bit integer overflow bug, which distorted the training mean (-9,232 bytes) and standard deviation (3,085,712 bytes).
- **Refutation**: However, the decision trees did **NOT** key on negative numbers to detect attacks. 99.98% of all splits on `fwd_header_len` are standard positive byte lengths (e.g. splitting on 62 bytes vs 64 bytes).
- The assertion that the model failed on 2018 data because 2018 lacked negative header lengths is **factually disproven**.

---

## 4. True Root Cause: TCP Window Size & Microsecond Timing Overfitting

The true driver of the out-of-distribution generalization failure was isolated through statistical distribution comparison and controlled ablation:

### 4.1 TCP Window Size Memorization
In CICIDS2017:
- The attacking host (Kali Linux VM) generated SSH brute force with initial forward window size `init_win_bytes_forward = 259` and half-open/dropped backward window `init_win_bytes_backward = -1`.
- In CSE-CIC-IDS2018:
  The AWS EC2 attack instance negotiated a standard Linux/AWS window size (`init_win_bytes_forward = 26,883` and `init_win_bytes_backward = 115`).
- **Controlled Offline Ablation**:
  The auditor took an authentic 2018 SSH Brute Force flow (originally predicted as `BENIGN` with 81.91% confidence). By altering *only* the two window size features back to the 2017 testbed values (`259` and `-1`), the Random Forest's `SSH Brute Force` attack probability immediately surged by **+13.2%**.
- Because TCP window size features represent the #1 and #3 most important features in the model, the trees effectively memorized the operating system TCP stack parameters of the specific VM used in 2017, rather than learning attack behavior.

### 4.2 Microsecond Timing Overfitting
- In CICIDS2017 `SSH-Patator`, median flow duration was 404 microseconds.
- In CSE-CIC-IDS2018 `SSH-Bruteforce`, median flow duration was 7 microseconds, and packet rate was 285,714 packets/sec (vs 4,950 pps in 2017).
- Unconstrained tree depth (`max_depth=20`) allowed the Random Forest to establish deep leaf rules matching microsecond-level timing thresholds unique to the Fredericton testbed's physical switch latency.

---

## 5. Summary of Generalization Findings

1. **Benign Invariance**: The model's benign classification is stable (0.02% false positive rate on 30,000 AWS flows) because legitimate web/DNS traffic maintains typical window sizes (e.g., 29,200 / 28,960) and standard HTTP packet distributions.
2. **Attack Fragility**: Attack detection completely collapsed on unseen data because the model overfit to testbed-specific TCP stack parameters (SYN/ACK window sizes) and local network latencies rather than protocol semantics.
