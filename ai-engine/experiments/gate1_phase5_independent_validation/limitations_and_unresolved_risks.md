# SentinelAI GATE-1 Phase 5: Known Limitations and Unresolved Risks

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Status**: **FORMAL AUDIT REGISTER OF OPEN RISKS AND BLOCKERS**

---

## 1. Overview of Release Limitations

This document provides a comprehensive, transparent register of all architectural, statistical, and operational limitations identified during GATE-1 Phase 5. Under conservative security engineering principles, these unresolved risks dictate that **GATE-1 must remain OPEN**.

---

## 2. Risk Register & Technical Root Cause Analysis

### RISK-01: Absence of Independent Blind Holdout Datasets (Track A & Track B Blocked)
- **Status**: **BLOCKER (High Severity)**
- **Technical Description**:
  - The local workspace contains only CICIDS2017 datasets, in which minority attack classes (`SSH-Patator`, `Web Attacks`, `Infiltration`, `Botnet`) have **100% training overlap**.
  - Track A (`CSE-CIC-IDS2018`) is not staged locally on disk. Although AWS Open Data provenance and schema transformations were mapped, no evaluation could be executed on Track A without fabricating data or downloading multi-gigabyte files.
  - Track B (Authorized Enterprise Canary Traffic) has not been provisioned. Local honeypot data contains only 91 flows, which is orders of magnitude below the statistical power threshold.
- **Operational Impact**: Generalization to zero-day or external network distributions remains unproven.

---

### RISK-02: Benign False Positive Wilson Upper Bound Exceeds Mandatory Ceiling
- **Status**: **BLOCKER (High Severity)**
- **Technical Description**:
  - On the Monday pure benign benchmark ($N=10,000$), the candidate decoupled policy and combined policy produced 7 false alarms ($0.07\%$).
  - The **95% Wilson Score upper bound is $0.1445\%$**, which exceeds the frozen release limit of $< 0.1000\%$.
  - In an enterprise processing 10 million flows daily, an upper bound of $0.1445\%$ permits up to 14,450 false alarms per day, which would rapidly overwhelm security operations centers and cause legitimate traffic to be dropped if autonomous blocking were enabled.
- **Remediation Mandate**: Proving compliance with the $< 0.10\%$ standard requires collecting and testing a holdout corpus of at least $N \ge 30,000$ verified benign flows with $\le 10$ false alarms.

---

### RISK-03: Regex-Based Layer 7 Pre-Filter Evasion and Semantic Blindspots
- **Status**: **ARCHITECTURAL LIMITATION (Medium Severity)**
- **Technical Description**:
  - The Layer 7 prototype achieved 95.33% recall on the 300-record synthetic/representative HTTP benchmark with zero false positives.
  - However, regex-based signature filtering is inherently vulnerable to sophisticated obfuscation:
    * Advanced SQL injection using vendor-specific parser quirks (e.g., PostgreSQL dollar-quoted strings, MySQL binary character literals).
    * Polymorphic XSS payloads utilizing exotic DOM contexts (e.g., prototype pollution, mutation XSS, DOM clobbering).
    * Large HTTP request bodies exceeding inspection buffer windows.
- **Operational Recommendation**: The regex pre-filter must be treated as a fast, first-line defense-in-depth shield. Long-term defense requires a hybrid approach combining regular expression matching with an AST (Abstract Syntax Tree) SQL parser and an application-layer neural payload embedding model.

---

### RISK-04: Transport Encryption and Protocol Visibility Blindspots
- **Status**: **DEPLOYMENT BOUNDARY (High Severity)**
- **Technical Description**:
  - Modern web protocols (TLS 1.3, HTTP/2, HTTP/3 QUIC) encrypt transport payloads on the wire.
  - A passive network sniffer running on a gateway interface cannot inspect HTTP URIs, headers, or request bodies.
  - On raw network captures where Layer 7 payloads are not visible, the combined policy safely falls back to Layer 4 flow classification (`L7_UNAVAILABLE`). However, at Layer 4, Web Attack recall drops to $60.90\%$ ($15.60\%$ block rate).
- **Required Architecture**: Production deployment requires hosting SentinelAI's Layer 7 engine inside an API Gateway / Reverse Proxy (Envoy, NGINX) where TLS is terminated prior to inspection, or attaching host-level eBPF uprobes to cryptographic libraries.

---

### RISK-05: Denial-of-Service Vulnerabilities in Regex Processing (ReDoS)
- **Status**: **ENGINEERING RISK (Medium Severity)**
- **Technical Description**:
  - Regular expression engines that evaluate complex patterns over unbounded user-controlled text can suffer from catastrophic backtracking, leading to CPU starvation (Regular Expression Denial of Service).
  - The Phase 5 prototype mitigated this by bounding input lengths, stripping comments, and avoiding nested quantifiers.
- **Production Requirement**: A production WAF engine must enforce an explicit evaluation timeout ($\le 2.0\text{ms}$ per request) via linear-time DFA engines (such as Google RE2 or Hyperscan) rather than backtracking NFA engines.

---

## 3. Audit Summary of Safety Invariants

| Safety Invariant | Configuration Setting | Observed State | Compliance Status |
| :--- | :---: | :---: | :---: |
| **Autonomous Containment** | `AUTONOMOUS_CONTAINMENT=false` | `false` | **ENFORCED** |
| **Real Firewall Enforcement** | `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` | `false` | **ENFORCED** |
| **Live Database Protection** | Zero writes to `sentinel-db` | 0 writes | **ENFORCED** |
| **Production Model Hashes** | Unmodified SHA-256 digests | 100% Match | **ENFORCED** |
| **Working Tree Isolation** | Dedicated `feature/gate1-phase5-layer7-prototype` | No merge to `main` | **ENFORCED** |

**Conclusion**: Zero security boundaries were breached. All blockers are fully documented and auditable. GATE-1 must remain OPEN.
