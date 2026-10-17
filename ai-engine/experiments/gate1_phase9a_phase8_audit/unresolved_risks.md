# SentinelAI GATE-1 Phase 9A: Unresolved Risks & Phase 9 Planning Prerequisites

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Verified Release Blockers

The independent reproduction confirms that four frozen acceptance criteria remain failed by the Phase 8 candidate model:

| Blocker ID | Affected Attack Category | Measured Recall | Gate Threshold | Blocker Severity | Technical Bottleneck |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **BLK-01** | DDoS HOIC & LOIC-UDP | **0.00%** (0 / 2,000) | $\ge 95.00\%$ | **CRITICAL** | Tool morphology shift: Training data contained Slowloris/GoldenEye (slow connection pool starvation). Holdout consists of HOIC (fast multithreaded HTTP volumetric GET floods). |
| **BLK-02** | Lateral Movement Infiltration | **0.15%** (3 / 2,000) | $\ge 90.00\%$ | **CRITICAL** | Transport invisibility: C2 communication occurred over standard TLS to Dropbox APIs. Flow summary metrics are statistically identical to benign browsing. |
| **BLK-03** | SSH Brute Force | **50.90%** (509 / 1,000) | $\ge 90.00\%$ | **HIGH** | Protocol version and cipher variance between Ubuntu and Amazon Linux SSH daemons. |
| **BLK-04** | Botnet (Malware Beacon) | **60.85%** (1,217 / 2,000) | $\ge 90.00\%$ | **HIGH** | Fixed beacon interval assumption fails when malware varies sleep jitter. |
| **BLK-05** | Web Attack Transport Detection | **0.35%** (2 / 566) | Baseline Audit | **STRUCTURAL** | Transport summary features cannot inspect HTTP request URIs, query strings, or payloads. |

---

## 2. Methodological & Evaluation Risks

### R-01: L7 WAF Empirical Validation Gap
While the Layer 7 WAF prototype demonstrates 100% detection on synthetic payloads and simulated mapping, it has **never been evaluated on raw PCAP HTTP byte streams** from authentic attack traffic. To certify Phase 9:
- A raw packet reassembly pipeline or reverse proxy test harness must be implemented to feed real HTTP byte streams into `Layer7PreFilter`.

### R-02: Repeated Holdout Depletion (Target Leakage)
The CSE-CIC-IDS2018 holdout benchmark ($N = 38,566$) has now been evaluated across four consecutive audit cycles. To preserve its validity:
- **FREEZE THE BENCHMARK**: Phase 9 detector development must be tuned exclusively on the Validation Partition (`partition_validation_tuning.parquet`). The sealed holdout must be evaluated only once as a final acceptance verification.

---

## 3. Mandatory Phase 9 Prerequisites (Prior to Implementation)

Before any Phase 9 code is written:
1. **Maintain GATE-1 Strictly OPEN**.
2. **Keep Safety Invariants Fully Enforced**: `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`.
3. **Formal Architectural Proposal Required**:
   - Decouple the monolithic Random Forest into specialized, modular detection engines:
     * Volumetric Packet-Rate Flood Engine for DDoS (HOIC/LOIC).
     * State-Aware Authentication Frequency Engine for SSH/FTP.
     * Native HTTP Reverse Proxy Pre-Filter for Layer 7 Web Attacks.
     * Host Process / Audit Log Telemetry for Lateral Movement.
