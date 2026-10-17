# SentinelAI GATE-1 Phase 6: Known Limitations and Unresolved Risks

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Status**: **FORMAL AUDIT REGISTER OF OPEN RISKS AND BLOCKERS**

---

## 1. Executive Summary

This risk register provides an authoritative accounting of all technical, statistical, architectural, and environmental blockers identified during Phase 6. In accordance with conservative software security engineering principles, **these unresolved risks mandate that GATE-1 must remain OPEN**.

---

## 2. Comprehensive Risk Register

### RISK-01: Host Storage Capacity Blocker on Drive C: (3.18 GB Free vs. 6.57 GB Dataset)
- **Severity**: **BLOCKER (High)**
- **Technical Description**:
  - The workspace host volume (`C:`) has only **3.18 GB of free space** (198.77 GB used).
  - The official AWS Open Data CSE-CIC-IDS2018 CSV dataset comprises **6,568.27 MB (~6.57 GB)** across 10 files, requiring 15 GB to 22 GB when parsed or extracted.
  - Attempting to download the complete dataset to Drive C: would immediately exhaust available storage, crash the operating system, and abort all running services.
- **Remediation Requirement**: Full acquisition must be staged on secondary storage (e.g., Drive `D:`, which has 215.78 GB free) under explicit operator provisioning.

---

### RISK-02: Absence of Staged Independent Blind Holdout Datasets
- **Severity**: **BLOCKER (High)**
- **Technical Description**:
  - The local workspace contains only CICIDS2017, where minority attack classes (`SSH-Patator`, `Web Attacks`, `Infiltration`, `Botnet`) suffer from **100% training overlap**.
  - CSE-CIC-IDS2018 provenance, licensing, and schema mappings were verified live from AWS S3 via HTTP Range headers, but the physical files have not yet been downloaded to local disk.
  - No fake data was created; independent validation against external holdouts remains blocked.

---

### RISK-03: Benign False Positive Wilson Score Upper Bound Exceeds Release Ceiling
- **Severity**: **BLOCKER (High)**
- **Technical Description**:
  - On the Monday pure benign benchmark ($N=10,000$), the candidate decoupled flow policy and combined policy produced 7 false alarms ($0.070\%$).
  - The exact **95% Wilson Score upper bound is $0.1445\%$**, which exceeds the mandatory release threshold of $< 0.1000\%$.
  - In an enterprise processing 10 million flows daily, an error rate of $0.1445\%$ translates to up to 14,450 false alerts per day, saturating security operations center personnel and risking self-inflicted denial of service if autonomous blocking were enabled.

---

### RISK-04: Statistical Power Sample Size Deficit
- **Severity**: **STATISTICAL BLOCKER (Medium)**
- **Technical Description**:
  - With 7 false alarms observed in 10,000 flows, the statistical margin of error is too wide to certify compliance with the $< 0.10\%$ standard.
  - Demonstrating that the true population false positive rate is mathematically bounded below $0.10\%$ requires testing a holdout of at least **$N \ge 30,000$ verified benign session flows** with $\le 10$ observed errors.

---

### RISK-05: Benchmark Independence Limitation of 300-Record HTTP Benchmark
- **Severity**: **METHODOLOGICAL LIMITATION (Medium)**
- **Technical Description**:
  - The 300-record comprehensive HTTP benchmark evaluated in Phase 5 and Phase 6 was synthetically constructed to represent canonical OWASP Top 10 web attack patterns.
  - While it successfully proves that a Layer 7 pre-filter resolves the complete blindspot ($0\%$ recall) of transport-layer flow models on HTTP attacks, the benchmark was created by the implementation team and does not represent an external blind holdout.

---

### RISK-06: WAF Regex Evasion and Semantic Blindspots
- **Severity**: **ARCHITECTURAL LIMITATION (Medium)**
- **Technical Description**:
  - The Layer 7 prototype achieved $95.33\%$ containment recall on the HTTP benchmark, but missed 7 complex evasion variants (unspaced backtick command injection and nested error-based subqueries).
  - Regular expressions are vulnerable to polymorphic obfuscation, exotic SQL dialects, and AST-level variations. A static regex engine is a defense-in-depth shield, not a comprehensive replacement for semantic AST parsers or deep payload embedding models.

---

### RISK-07: Wire Encryption and Ingress Visibility Boundaries
- **Severity**: **DEPLOYMENT BOUNDARY (High)**
- **Technical Description**:
  - Modern web protocols (TLS 1.3, HTTP/2, HTTP/3 QUIC) encrypt payloads end-to-end.
  - On raw network captures or un-terminated gateway interfaces where Layer 7 payloads are not visible, the combined policy safely falls back to Layer 4 flow classification (`L7_UNAVAILABLE`).
  - At Layer 4, Web Attack recall drops to $60.90\%$ ($15.60\%$ block rate).
  - Production deployment fundamentally requires hosting SentinelAI at an application termination point (Envoy / NGINX reverse proxy).

---

## 3. Safety Invariants Compliance Audit

| Operational Safety Boundary | Policy Requirement | Observed State in Phase 6 | Compliance Status |
| :--- | :---: | :---: | :---: |
| **Autonomous Containment** | `AUTONOMOUS_CONTAINMENT=false` | `false` | **ENFORCED** |
| **Real Firewall Enforcement** | `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` | `false` | **ENFORCED** |
| **Live Database Protection** | Zero writes to `sentinel-db` | 0 writes | **ENFORCED** |
| **Protected Model Hashes** | Unmodified SHA-256 digests | 100% Match Verified | **ENFORCED** |
| **Working Tree Isolation** | Dedicated `feature/gate1-phase6-independent-validation` | No merge to `main` | **ENFORCED** |

**Conclusion**: Zero security invariants were compromised. GATE-1 must remain OPEN.
