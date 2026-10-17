# SentinelAI GATE-1 Phase 9B: Evaluation Protocol & Acceptance Plan

**Author / Senior Reviewer**: Senior Security Architect, Machine Learning Engineer & Independent Security-Systems Reviewer  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Architecture Design & Safety Review (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Mandatory Holdout Freeze Invariant

> [!CAUTION]
> ### The CSE-CIC-IDS2018 Sealed Holdout ($N = 38,566$) is Strictly Frozen
> To prevent target leakage and adaptive test-set depletion, **no specialized detector in Phase 9 may use the CSE-CIC-IDS2018 sealed holdout for feature selection, hyperparameter tuning, rule threshold optimization, or iterative debugging**.
> - Detector development must use strictly designated training and validation partitions.
> - The frozen holdout may be queried **only once** as a final post-implementation acceptance audit.

---

## 2. Detector-Specific Evaluation Protocols

### 2.1 Volumetric Flood Detector (DDoS / DoS)
1. **Intended Threat**: Volumetric packet floods (HOIC, LOIC, SYN floods, amplification).
2. **Explicit Non-Goals**: Application business logic exploits, SQLi/XSS, low-and-slow socket starvation.
3. **Data Sources**:
   - Training/Tuning: CICIDS2017 Friday DDoS + CSE-CIC-IDS2018 Thursday-15 DoS (training slice) + CAIDA 2007 DDoS public samples.
   - Validation: CSE-CIC-IDS2018 Wednesday-21-02-2018 (non-holdout development slice).
4. **Partitioning & Grouping**: Grouped strictly by attack tool campaign and capture hour. Zero inter-campaign leakage.
5. **Acceptance Threshold**: DDoS/DoS Recall $\ge 95.00\%$, Benign False Alarm Rate $\le 0.1000\%$.
6. **Latency & Resource Limit**: $\le 5.0$ ms per window evaluation; $\le 50$ MB RAM footprint.

### 2.2 State-Aware Authentication-Abuse Detector (SSH / FTP)
1. **Intended Threat**: Automated dictionary attacks, brute forcing, credential stuffing on port 22 and port 21.
2. **Explicit Non-Goals**: Exploiting unauthenticated memory corruptions (e.g. OpenSSH regreSSHion CVE-2024-6387).
3. **Data Sources**:
   - Training/Tuning: CICIDS2017 Tuesday Patator + CSE-CIC-IDS2018 Wednesday-14 BruteForce (training slice).
   - Validation: Recorded honeypot authentication sessions ([`ai-engine/datasets/honeypot_derived/flows.csv`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/datasets/honeypot_derived/flows.csv)).
4. **Partitioning & Grouping**: Grouped by target daemon IP and distinct username key.
5. **Acceptance Threshold**:
   - Separate SSH Recall $\ge 90.00\%$.
   - Separate FTP Recall $\ge 90.00\%$.
   - Benign False Alarm Rate $\le 0.1000\%$.
6. **Latency & Resource Limit**: $\le 1.0$ ms per connection event state lookup; $\le 20$ MB state table.

### 2.3 HTTP Reverse-Proxy WAF (Layer 7 Exploit Engine)
1. **Intended Threat**: SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), Path Traversal, Command Injection.
2. **Explicit Non-Goals**: Transport-layer volumetric floods, network port scans, unencrypted protocol routing.
3. **Data Sources**:
   - Training/Tuning: CSIC 2010 HTTP Dataset + OWASP Benchmark v1.2 + SecRepo web payloads.
   - Ground-Truth Prohibition: The evaluation engine must pass raw HTTP request strings into the parser. Dataset labels may only be compared after the WAF emits its classification.
4. **Partitioning & Grouping**: Grouped by web application endpoint and HTTP request method.
5. **Acceptance Threshold**:
   - Web Attack Detection Recall $\ge 90.00\%$ on independent request corpora.
   - Simulated Autonomous Block Recall $\ge 75.00\%$.
   - Benign Web False Positive Rate $\le 0.1000\%$ on legitimate web crawls.
6. **Latency & Resource Limit**: $\le 2.5$ ms per HTTP request parse; $\le 10$ MB rule index memory.

### 2.4 Host Telemetry & Lateral-Movement Detector
1. **Intended Threat**: Post-exploitation lateral movement, reverse shells over TLS, living-off-the-land (LotL) execution.
2. **Explicit Non-Goals**: Ingress network packet filtering, edge perimeter firewalling.
3. **Data Sources**:
   - Offline Public Benchmarks: DARPA Transparent Computing datasets, Mordor project Sysmon attack logs.
   - Zero live endpoint agents or system security modifications permitted during evaluation.
4. **Acceptance Threshold**:
   - Lateral Movement Detection Recall $\ge 90.00\%$.
   - Host Audit False Positive Rate $\le 0.1000\%$ on clean workstation activity.

---

## 3. Preserved Frozen GATE-1 Acceptance Criteria

The frozen Gate-1 criteria established in previous phases remain non-negotiable:

| Acceptance Criterion ID | Performance Metric Target | Required Denominator & Verification Scope |
| :---: | :--- | :--- |
| **AC-01** | Benign Point False Positive Rate $\le 0.1000\%$ | Minimum $N = 30,000$ pure benign flows |
| **AC-02** | Benign FPR 95% Wilson Upper Bound $< 0.1000\%$ | Two-sided standard Wilson score formula |
| **AC-03** | Infiltration / Lateral Movement Recall $\ge 90.00\%$ | Evaluated against verified compromise events |
| **AC-04** | Web Attack Transport ML Recall | Baseline audit metric (disclosing transport blind spot) |
| **AC-05** | Actual Web Attack Combined Recall $\ge 90.00\%$ | Evaluated via actual HTTP request payload parsing |
| **AC-06** | SSH & FTP Brute Force Recall $\ge 90.00\%$ | Reported separately for SSH ($\ge 90\%$) and FTP ($\ge 90\%$) |
| **AC-07** | Botnet (Malware Beacon) Recall $\ge 90.00\%$ | Evaluated across diverse sleep jitter configurations |
| **AC-08** | DDoS / DoS Attack Recall $\ge 95.00\%$ | Evaluated on authentic volumetric HTTP floods (HOIC) |
| **AC-09** | Protected Asset Cryptographic Integrity | 100% bit-for-bit SHA-256 match (0 B drift) |
| **AC-10** | Mandatory Safety Invariants Preservation | `AUTONOMOUS_CONTAINMENT=false`, 0 real firewall rules |

---

## 4. Methodological Warning: Flow-Level Clustering & Non-i.i.d. Effects

> [!IMPORTANT]
> ### Independence Assumption Limitation
> Standard binomial Wilson confidence intervals assume that each evaluated flow is an independent and identically distributed (i.i.d.) trial:
> $$\mathbb{P}(X_i = 1 \mid X_{i-1} = 1) = \mathbb{P}(X_i = 1)$$
> In authentic network captures, flows from a single attack tool (e.g. 1,996 HOIC flows in a 10-second burst) originate from the same attacking machine, use the same source OS stack, and share identical destination ports.
> - A model that misses the first packet in a burst will typically miss all 1,996 packets.
> - Conversely, a model that detects the first packet will detect all 1,996 packets.
> - Therefore, **a 95% Wilson confidence interval on correlated flow bursts overstates statistical confidence**.
> Phase 9 evaluations must report both **Flow-Level Metrics** and **Campaign/Session-Level Metrics** to present an honest assessment of generalization.
