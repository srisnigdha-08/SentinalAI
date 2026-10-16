# SentinelAI Final Closure: Known Limitations and Release Gates

**Date**: October 15, 2026  
**Auditor**: Application Security & Technical Acceptance Auditor  
**Status**: **FORMALLY CODIFIED**

---

## 1. Purpose and Operational Philosophy

This document serves as the authoritative, definitive register of all known architectural boundaries, technical limitations, and production release gates for SentinelAI. Rather than masking gaps with speculative claims of full production readiness, SentinelAI adopts a strict, transparent, evidence-based acceptance posture.

The platform is formally accepted for **Local Development and Controlled Internal Testing** under the explicit constraints defined below.

---

## 2. Definitive Release Gates Register

### GATE-001: Prohibition of Autonomous Containment & ML Reliability (GATE-1)
- **Operational Status**: **OPEN / IN PROGRESS (Rigorous Baseline Established, Autonomous Containment Banned)**.
- **Current Configuration**: `AUTONOMOUS_CONTAINMENT=false` strictly enforced in backend policy engine.
- **Technical Finding (October 16, 2026 Audit)**:
  1. The reported 33.0% DDoS False-Positive Rate was caused by an inference-to-evaluation pipeline interaction: `Isolation Forest` flagged bursty benign traffic as outliers (`is_anomaly=True`), overriding labels to `"Unknown"`, which binary evaluation scored as malicious attacks.
  2. The raw Random Forest classifier (`rf_classifier_cicids_v2.pkl`) actually achieves **0.45% FPR** (95% CI: `[0.34%, 0.60%]`) across 10,000 independent Monday flows and **0.00% FPR** on Friday DDoS ambient benign flows.
  3. Candidate model `xgb_classifier_cicids_v2.pkl` demonstrated **0.10% FPR** (2/2000) on Monday flows with **100.0% DDoS Recall** and **99.9% PortScan Recall**.
  4. In live runtime, policy thresholds assign threat score 0.55 (`ALLOW`) to `"Unknown"`, resulting in **0.00% Policy FPR** (0 / 10,000 benign flows escalated to MONITOR or BLOCK).
- **Mandatory Release Conditions to Close GATE-1**:
  1. Refactor metric reporting to decouple unsupervised anomaly telemetry (`Unknown`) from binary malicious attack metrics.
  2. Retrain and cross-validate models on modern, multi-datacenter enterprise traffic (beyond CICIDS2017).
  3. Formally prove statistically bounded $FPR < 0.1\%$ across $\ge 10,000$ independent benign flows (95% Wilson Score upper bound $< 0.001$).
  4. Independent peer review and sign-off by Application Security and Platform Engineering.

### GATE-002: Real Windows Firewall Host Gating
- **Operational Status**: **LOCKED / DISABLED (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`)**.
- **Technical Justification**: Real Windows Advanced Firewall enforcement (`WindowsFirewallAdapter.js`) invokes host-level `netsh advfirewall` commands. Executing real firewall blocking on developer workstations risks isolating the host machine.
- **Production Release Condition**: Real enforcement may only be activated in a dedicated, isolated Windows Server VM or containerized sandbox environment with automated rollback mechanisms.

### GATE-003: Windows Service Supervision (Session 0 Limitation)
- **Operational Status**: **UNVERIFIED ON HOST / UNIT-VERIFIED IN SIMULATION**.
- **Technical Justification**: Windows services execute in non-interactive Session 0. WinSW service shutdown relies on console control signals that fail in Session 0, causing WinSW to fall back to `TerminateProcess()`. Installing a persistent service on the developer host was omitted to prevent host service churn and privilege elevation.
- **Production Release Condition**: Prior to production server deployment, the service package must be installed and tested in a dedicated Windows Server VM under the Windows Service Control Manager (`sc.exe stop SentinelAI-Backend`) using IPC shutdown triggers.

### GATE-004: Express v5 Migration & Supply-Chain Hardening
- **Operational Status**: **ACCEPTED RESIDUAL RISK FOR LOCAL DEV / RELEASE BLOCKER FOR PUBLIC DEPLOYMENT**.
- **Technical Justification**: Production dependency audit identified transitive advisories in `proxy-addr` (Critical, CVSS 9.1) and `qs` (Moderate, CVSS 5.3) locked by Express 4.x. While fully mitigated in local development (loopback-only binding, absence of reverse proxies), external exposure requires updating these transitives.
- **Production Release Condition**: Before exposing the backend to public, untrusted networks, the Express v5 migration (`express@5.x`) and direct package upgrades (`morgan@1.12.1`, `uuid@11.1.1`) must be completed and validated.

---

## 3. Known Architectural Limitations

### 3.1 At-Least-Once Outbox Delivery
- The file-backed outbox (`FileOutboxStore`) guarantees **At-Least-Once Delivery**.
- If a subscriber executes an external side-effect (e.g. sending an alert or writing to SIEM) and the process crashes before `markDelivered` commits to disk, the event will be re-emitted upon engine recovery.
- **Requirement**: All downstream event handlers, alert receivers, and webhooks must implement idempotency checks using the `envelope.eventId` field.

### 3.2 Single-Writer Process Concurrency
- `FileOutboxStore` is architected for a **Single-Writer Node.js Process**.
- Running multiple concurrent Node processes sharing the same local `logs/event_outbox.json` file is unsupported and may trigger file locking contention.
- **Requirement**: Multi-instance clustered deployments must replace `FileOutboxStore` with a distributed outbox store (e.g. MongoDB or Redis-backed).

### 3.3 Storage Headroom on Primary Drive (C:)
- The host system volume currently has **5.32 GB of free disk space**.
- Automated test suites, loggers, and packet capture tools must enforce strict retention boundaries to prevent disk exhaustion.
- The outbox automatically caps delivered events at 100 entries (`_prune()`).

---

## 4. Acceptance Status by Target Environment

| Deployment Target | Acceptance Status | Required Prerequisites |
| :--- | :---: | :--- |
| **Local Development** | **ACCEPTED (PASS)** | All non-negotiable safety rules satisfied; mock adapters active. |
| **Controlled Internal Lab** | **ACCEPTED (PASS)** | Isolated disposable DBs used; human-in-the-loop containment enforced. |
| **Production Server** | **BLOCKED (GATED)** | Requires satisfaction of GATE-001, GATE-002, GATE-003, and GATE-004. |
