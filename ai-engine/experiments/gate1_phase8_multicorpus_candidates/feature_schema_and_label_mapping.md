# SentinelAI GATE-1 Phase 8: Feature Schema and Label Mapping Specification

**Author**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Status**: Multi-Corpus Candidate Specification (Non-Production)  
**Evaluated Branch**: `feature/gate1-phase8-multicorpus-candidates`  

---

## 1. Feature Engineering & Schema Evolution

### 1.1 Baseline 53-Feature Schema (`v2.1_53feat`)
The production model (`rf_classifier_cicids_v2.pkl`) was trained on an unconstrained 53-feature vector:
- **Packet counts & lengths**: `total_fwd_packets`, `total_bwd_packets`, `total_len_fwd_packets`, `total_len_bwd_packets`, packet min/max/mean/std for forward and backward.
- **Rates**: `flow_bytes_per_sec`, `flow_packets_per_sec`.
- **Microsecond Timing**: `flow_duration`, `flow_iat_*` (mean, std, max, min), `fwd_iat_*` (tot, mean, std, max, min), `bwd_iat_*` (tot, mean, std, max, min).
- **TCP Flags**: `fwd_psh_flags`, `bwd_psh_flags`, `fwd_urg_flags`, `bwd_urg_flags`, `fin_flag_count`, `syn_flag_count`, `rst_flag_count`, `psh_flag_count`, `ack_flag_count`, `urg_flag_count`.
- **Headers & Bulk**: `fwd_header_len`, `bwd_header_len`, `fwd_avg_bytes_per_bulk`, `bwd_avg_bytes_per_bulk`.
- **TCP Windows**: `init_win_bytes_forward`, `init_win_bytes_backward`.
- **Flow Dynamics**: `active_mean`, `active_std`, `idle_mean`, `idle_std`, `down_up_ratio`.
- **Engineered Context**: `payload_entropy`, `time_of_day_sin`, `time_of_day_cos`.

### 1.2 Candidate Schema F (Robust 51-Feature Schema)
Ablation experiments in Phase 8 established that the baseline schema suffered from severe testbed memorization:
1. **TCP Window Sizes Pruned**:
   - `init_win_bytes_forward` and `init_win_bytes_backward` were completely removed (reducing dimensions from 53 to 51).
   - *Rationale*: In CICIDS2017, the attacking VM used fixed SYN window sizes (`259` and `-1`), whereas in CSE-CIC-IDS2018, AWS Linux systems negotiated standard stack windows (`26,883` and `115`). Removing window sizes eliminates operating-system fingerprint memorization.
2. **Microsecond Timing Compression ($\log(1 + x)$)**:
   - All 15 flow duration and inter-arrival time (IAT) features are transformed via:
     $$\tilde{x} = \ln(1 + \max(x, 0))$$
   - *Rationale*: Network propagation delay and switch latency vary dramatically between local academic testbeds (CICIDS2017) and AWS multi-VPC clouds (CSE-CIC-IDS2018). Log-compression forces the trees to split on order-of-magnitude behavioral bursts rather than microsecond hardware jitter.
3. **Throughput & Volume Compression**:
   - `flow_bytes_per_sec`, `flow_packets_per_sec`, `total_len_fwd_packets`, and `total_len_bwd_packets` are log1p-transformed.
4. **Header Length Normalization**:
   - `fwd_header_len` and `bwd_header_len` are normalized by dividing by forward and backward packet counts respectively:
     $$\bar{h}_{\text{fwd}} = \frac{h_{\text{fwd}}}{\max(N_{\text{fwd}}, 1)}, \quad \bar{h}_{\text{bwd}} = \frac{h_{\text{bwd}}}{\max(N_{\text{bwd}}, 1)}$$
   - *Rationale*: Prevents decision trees from confusing cumulative header bytes with packet count scaling.
5. **Raw Port Exclusion**:
   - Raw source and destination port numbers (`src_port`, `dst_port`) remain strictly excluded from model features. Ablation C proved that raw ports increase false alarm susceptibility on benign web traffic without improving behavioral generalization.

---

## 2. Canonical Label Mapping

Both CICIDS2017 and CSE-CIC-IDS2018 raw labels are unified deterministically into SentinelAI's 11 canonical classes:

| Canonical ID | Canonical SentinelAI Label | CICIDS2017 Source Strings | CSE-CIC-IDS2018 Source Strings | Defense Tier Coverage |
| :---: | :--- | :--- | :--- | :--- |
| **0** | `BENIGN` | `BENIGN` | `Benign` | Baseline Allowlist |
| **1** | `SSH Brute Force` | `SSH-Patator` | `SSH-Bruteforce` | Tier 1 (Transport) |
| **2** | `SQL Injection` | `Web Attack – Sql Injection` | `SQL Injection` | Tier 2 (L7 WAF) + Tier 1 |
| **3** | `Port Scan` | `PortScan` | *(Evaluated via 2017)* | Tier 1 (Transport) |
| **4** | `DDoS` | `DDoS`, `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest` | `DDOS attack-HOIC`, `DDOS attack-LOIC-UDP`, `DoS attacks-GoldenEye`, `DoS attacks-Slowloris` | Tier 1 (Transport) |
| **5** | `RCE Attempt` | `Heartbleed` | *(None)* | Tier 2 (L7 WAF) |
| **6** | `XSS Attempt` | `Web Attack – XSS` | `Brute Force -XSS` | Tier 2 (L7 WAF) + Tier 1 |
| **7** | `Malware Beacon` | `Bot` | `Bot` | Tier 1 (Transport) |
| **8** | `Credential Stuffing` | `FTP-Patator`, `Web Attack – Brute Force` | `FTP-BruteForce`, `Brute Force -Web` | Tier 1 + Tier 2 |
| **9** | `Lateral Movement` | `Infiltration` | `Infilteration` | Tier 1 (Transport) |
| **10** | `Data Exfiltration` | *(Synthetic)* | *(Synthetic)* | Tier 1 (Transport) |

---

## 3. Mathematical Feature Transformation Formulas

```python
# 1. Payload Entropy Calculation
def compute_payload_entropy(tot_fwd: float, tot_bwd: float) -> float:
    total = tot_fwd + tot_bwd
    if total <= 0.0:
        return 0.0
    p_f = tot_fwd / total
    p_b = tot_bwd / total
    ent = 0.0
    if p_f > 0.0: ent -= p_f * np.log2(p_f)
    if p_b > 0.0: ent -= p_b * np.log2(p_b)
    return float(ent)

# 2. Time-of-Day Cyclical Encoding
def compute_time_of_day(dt: pd.Series) -> tuple:
    hours = dt.dt.hour + dt.dt.minute / 60.0 + dt.dt.second / 3600.0
    sin_val = np.sin(2.0 * np.pi * hours / 24.0)
    cos_val = np.cos(2.0 * np.pi * hours / 24.0)
    return sin_val, cos_val

# 3. Log1p Transformation on Timing and Volumetric Quantities
def log1p_transform(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.maximum(x, 0.0))
```
