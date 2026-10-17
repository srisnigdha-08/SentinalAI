# SentinelAI GATE-1 Phase 8: Unresolved Risks & Blocker Register

**Auditor / ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Status**: Formal Audit Deliverable  
**Authoritative Verdict**: **GATE-1 STRICTLY OPEN — PRODUCTION PROMOTION PROHIBITED**  

---

## 1. Release Blocker Summary

| Risk ID | Attack Category / Subsystem | Measured Holdout Metric | Frozen Gate Requirement | Status | Technical Root Cause |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **BLK-01** | DDoS HOIC & LOIC-UDP | **0.00%** Recall | $\ge 95.00\%$ | **CRITICAL BLOCKER** | Morphology mismatch: Candidate trained on GoldenEye/Slowloris (connection-exhaustion). HOIC is an HTTP volumetric GET flood on port 80. |
| **BLK-02** | Infiltration (Lateral Movement) | **0.15%** Recall | $\ge 90.00\%$ | **CRITICAL BLOCKER** | Subtle multi-stage attack (Dropbox C2, privilege escalation) whose flow-level statistics closely resemble benign HTTPS browsing. |
| **BLK-03** | SSH & FTP Brute Force | **71.20%** Recall | $\ge 90.00\%$ | **BLOCKER** | Substantial gain over Phase 7 (0.00% -> 71.20%), but FTP (91.5%) and SSH (50.9%) combined still miss the 90% threshold. |
| **BLK-04** | Botnet (Malware Beacon) | **60.85%** Recall | $\ge 90.00\%$ | **BLOCKER** | Substantial gain over Phase 7 (0.00% -> 60.85%), but periodic beaconing intervals vary across Ares/Zeus/Mirai variants. |
| **BLK-05** | Transport-Only Web Attack Recall | **0.35%** Recall | Baseline Audit | **ARCHITECTURAL LIMITATION** | Transport models cannot inspect HTTP payloads. Tier 2 L7 WAF is strictly required for application-layer protection. |

---

## 2. In-Depth Root Cause Analysis

### 2.1 BLK-01: DDoS Attack Morphology Mismatch (HOIC vs Slowloris)
- The holdout slice `holdout_ddos.parquet` contains 1,996 flows of `DDOS attack-HOIC` (High Orbit Ion Cannon) and 4 flows of `DDOS attack-LOIC-UDP`.
- High Orbit Ion Cannon utilizes multithreaded HTTP GET floods with randomized booster scripts designed to flood web servers.
- Conversely, the training set included `DoS GoldenEye` and `DoS Slowloris` from 2018 Thursday-15-02. Slowloris sends HTTP headers at extremely slow intervals (e.g. 1 packet every 15 seconds) to tie up connection pools.
- As a result, the Random Forest learned that DoS is characterized by high inter-arrival times and long flow durations. When confronted with HOIC's micro-burst packet floods, it scored them as normal traffic.

### 2.2 BLK-02: Lateral Movement Infiltration Subtlety
- Infiltration attacks in CSE-CIC-IDS2018 involved compromising an internal machine via malicious PDF/Word exploit, establishing a C2 channel via Dropbox HTTPS APIs, and pivoting internally via Nmap and SMB.
- Because traffic to Dropbox occurs over TLS on port 443 with standard packet lengths, flow-level metrics are statistically indistinguishable from background cloud sync activity. Transport models cannot detect lateral movement without endpoint telemetry or host logs.

### 2.3 BLK-03 & BLK-04: Generalization Gap
- While multi-corpus retraining successfully broke the 0.00% transfer wall of Phase 7, lifting SSH/FTP to 71.20% and Botnet to 60.85%, variance across authentication protocols (e.g. SSH handshake differences between Ubuntu 16.04 in 2017 and Amazon Linux in 2018) prevents reaching the mandatory 90% gate threshold.

---

## 3. Required Next Steps Before Gate-1 Promotion

1. **Keep GATE-1 Strictly OPEN**:
   Under no circumstances may `candidate_rf_multicorpus_v1.pkl` or any previous model be promoted to production or autonomous containment.
2. **Phase 9 Architecture Proposal**:
   - **Protocol-Specialized Detectors**: Replace the single monolithic multi-class classifier with a modular architecture:
     * High-volume volumetric flood detector for DDoS.
     * Connection frequency and failed auth detector for SSH/FTP.
     * Integrated Layer 7 WAF for HTTP Web attacks.
   - **Cross-Variant Data Augmentation**: Synthetically augment training data across diverse attack tool configurations (HOIC, LOIC, Slowloris, GoldenEye, Hulk).
