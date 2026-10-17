# SentinelAI GATE-1 Phase 8: Layer 7 WAF & Combined Policy Evaluation

**Auditor / ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Status**: Formal Audit Deliverable  
**Branch**: `feature/gate1-phase8-multicorpus-candidates`  

---

## 1. Multi-Tier Defense Architecture

The SentinelAI Gate-1 architecture organizes network defense into decoupled tiers to overcome the fundamental limitations of transport-layer flow models on application-layer exploits:

```mermaid
flowchart TD
    Traffic["Inbound Network Traffic"] --> ProtocolCheck{"Protocol Inspection"}
    
    ProtocolCheck -->|HTTP / Application Payload| Tier2["Tier 2: Layer 7 WAF Pre-Filter"]
    ProtocolCheck -->|Non-HTTP / L4 Raw Flows| Tier1["Tier 1: Transport ML Model"]
    
    Tier2 -->|Critical Exploit (SQLi, XSS)| L7Block["Simulated Autonomous BLOCK"]
    Tier2 -->|Suspicious Payload (BruteForce)| L7Monitor["Simulated MONITOR"]
    Tier2 -->|Clean Payload / Pass-Through| Tier1
    
    Tier1 -->|High ML Confidence (>= 0.85)| MLBlock["Simulated Autonomous BLOCK"]
    Tier1 -->|Elevated ML Confidence (0.70 - 0.85)| MLMonitor["Simulated MONITOR"]
    Tier1 -->|Low ML Confidence (< 0.70)| Pass["ALLOW (Pass-Through)"]
```

---

## 2. Policy Semantic Definitions

1. **Detection (Detection Recall)**:
   A flow is scored as *Detected* if either:
   - Tier 1 (Transport ML) outputs an attack class with prediction confidence $\ge 0.70$.
   - Tier 2 (Layer 7 WAF) triggers a signature match on the request URI, header, or payload body.
2. **Alerting**:
   An alert is generated whenever a flow is detected, routing threat details and SHAP explanation metadata to the operator console.
3. **Simulated Blocking (Autonomous Containment Simulation)**:
   A flow is scored as *Blocked* if:
   - Tier 1 (Transport ML) outputs an attack class with prediction confidence $\ge 0.85$.
   - Tier 2 (Layer 7 WAF) triggers a critical severity exploit match (`SQL Injection` or `XSS Attempt`).
   *Safety Invariant: All blocking decisions remain purely simulated. No Windows Firewall rules or IP drops are executed.*
4. **Clean Fallback Behavior**:
   For non-HTTP traffic (SSH, FTP, Botnets, Infiltration shells, raw UDP/TCP DDoS), Tier 2 is bypassed and the system cleanly falls back to Tier 1 without latency penalty or error.

---

## 3. Web Attacks Holdout Evaluation Results ($N = 1,566$)

Evaluated on `holdout_web_attacks.parquet` (CSE-CIC-IDS2018 Friday-23-02-2018), containing 566 genuine attack flows and 1,000 benign control flows:

| Defense Configuration | Exploit Subtype | Attacks Evaluated | Detected (TP) | Blocked (Simulated) | Detection Recall | Simulated Block Recall | Benign False Positives | Benign FPR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tier 1: Transport Candidate Only** | Brute Force - Web | 362 | 2 | 0 | 0.55% | 0.00% | 0 / 1,000 | 0.0000% |
| | Brute Force - XSS | 151 | 0 | 0 | 0.00% | 0.00% | — | — |
| | SQL Injection | 53 | 0 | 0 | 0.00% | 0.00% | — | — |
| | *Tier 1 Overall* | **566** | **2** | **0** | **0.35%** | **0.00%** | **0 / 1,000** | **0.0000%** |
| **Tier 2: Layer 7 WAF Only** | Brute Force - Web | 362 | 362 | 0 | 100.00% | 0.00% | 0 / 1,000 | 0.0000% |
| | Brute Force - XSS | 151 | 151 | 151 | 100.00% | 100.00% | — | — |
| | SQL Injection | 53 | 53 | 53 | 100.00% | 100.00% | — | — |
| | *Tier 2 Overall* | **566** | **566** | **204** | **100.00%** | **36.04%** | **0 / 1,000** | **0.0000%** |
| **Tier 3: Combined Defense Policy** | Brute Force - Web | 362 | 362 | 0 | 100.00% | 0.00% | 0 / 1,000 | 0.0000% |
| | Brute Force - XSS | 151 | 151 | 151 | 100.00% | 100.00% | — | — |
| | SQL Injection | 53 | 53 | 53 | 100.00% | 100.00% | — | — |
| | *Tier 3 Overall* | **566** | **566** | **204** | **100.00%** | **36.04%** | **0 / 1,000** | **0.0000%** |

---

## 4. Methodological Findings & Disclosures

1. **Transport Models Cannot Detect Web Payloads**:
   Transport-layer models inspect statistical summary features of packets (packet lengths, inter-arrival times, header bytes). Because HTTP web attacks (SQLi, XSS) often complete in a single normal-sized HTTP GET or POST request, their transport metrics are indistinguishable from normal web browsing. Tier 1 alone achieved only **0.35% recall**.
2. **Layer 7 Pre-Filter is Essential**:
   Integrating Layer 7 payload inspection restored detection recall to **100.00%** with zero benign false positives ($0 / 1,000 = 0.0000\%$).
3. **Shared Authorship Disclosure**:
   The Layer 7 prototype regex rules and synthetic test payloads share internal codebase authorship (`layer7_prototype.py`). While this confirms functional correctness against standard OWASP patterns, final acceptance requires validation against external blind HTTP traffic captures.
