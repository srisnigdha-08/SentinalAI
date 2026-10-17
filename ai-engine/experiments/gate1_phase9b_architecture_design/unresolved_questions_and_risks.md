# SentinelAI GATE-1 Phase 9B: Unresolved Questions and Risk Register

**Author / Senior Reviewer**: Senior Security Architect, Machine Learning Engineer & Independent Security-Systems Reviewer  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Architecture Design & Safety Review (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Unresolved Technical Questions

| Question ID | Architectural Area | Unresolved Question | Proposed Investigation Path |
| :---: | :--- | :--- | :--- |
| **Q-01** | **Layer 7 WAF Evaluation** | How can the Layer 7 WAF be evaluated on authentic 2018 Web Attacks when the holdout Parquet file contains only numerical flow summaries without raw HTTP request strings? | Obtain raw PCAP slice from original AWS S3 capture for Friday-23-02-2018, reassemble HTTP request streams using `tshark` or `dpkt`, and feed reconstructed payloads into `Layer7PreFilter`. |
| **Q-02** | **SSH Brute-Force Misses** | Is the 50.9% recall on SSH brute-force caused by cipher negotiation differences between Ubuntu 16.04 and Amazon Linux, or is it driven by packet count variance per session? | Inspect raw PCAP packet byte streams for 2017 Patator vs 2018 SSH-Bruteforce; perform packet-level diff on TCP payload bytes prior to key exchange completion. |
| **Q-03** | **Volumetric Flood Thresholding**| How can the adaptive baseline in the Volumetric Flood Detector avoid false alarms during legitimate flash crowds while maintaining $\ge 95.00\%$ recall on micro-burst floods? | Implement a dual-threshold EWMA filter combining short-window (1s) burst detection with entropy-of-source-IP cross-checks. |
| **Q-04** | **Host Telemetry Privacy** | How can host process command-line logging comply with data minimization and privacy standards (GDPR, CCPA) when CLI arguments may contain sensitive tokens? | Implement client-side kernel/auditd regex redaction rules that strip passwords, tokens, and PII before log records are serialized to the detector. |
| **Q-05** | **Benchmark Depletion Risk** | How do we guarantee the frozen CSE-CIC-IDS2018 holdout ($N=38,566$) is not inadvertently adapted to during Phase 9 detector tuning? | Enforce a strict programmatic lock: Phase 9 development scripts must reject paths pointing to `holdout_sets/`, restricting tuning to `partition_validation_tuning.parquet`. |

---

## 2. Technical and Operational Risk Register

| Risk ID | Risk Description | Severity | Impact on System | Mitigation Strategy |
| :---: | :--- | :---: | :--- | :--- |
| **RSK-01** | **L7 WAF Latency Degradation** | Medium | Deep regex inspection of large HTTP request bodies could introduce latency jitter under high request volume. | Enforce strict 1 MB body inspection cutoff; bypass regex engine on streaming media; run pattern matching asynchronously where feasible. |
| **RSK-02** | **Telemetry Desynchronization** | Medium | Network flow events and host process logs may have microsecond timestamp offsets, complicating correlation. | Utilize unified monotonic clock or nanosecond NTP synchronization; introduce a $\pm 2.0$-second fuzzy correlation window. |
| **RSK-03** | **Volumetric Sampling Saturation** | High | During saturating DDoS attacks, packet capture interfaces may drop packets, yielding artificially deflated rate metrics. | Monitor interface drop counters (`rx_dropped`); if drop rate $> 5\%$, force detector state to `DEGRADED` and alert operator immediately. |
| **RSK-04** | **Premature Enforcement Risk** | Critical | Accidental activation of autonomous firewall blocking on a detector with 0.10% FPR could disconnect legitimate corporate users. | Maintain hardcoded invariant: `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`. Keep GATE-1 strictly OPEN. |

---

## 3. Prerequisite Approvals for Future Implementation

The following approvals and technical milestones must be completed prior to authorizing Phase 9 implementation:
1. **Approval of Architecture Decision Record (ADR)**: Formal user review and acceptance of Alternative 3 (Multi-Tier Modular Ensemble).
2. **Evaluation Dataset Provisioning**: Validation that independent request-level HTTP corpora and volumetric packet streams are staged without using the frozen holdout.
3. **Dedicated Phase 9 Worktree/Branch**: Creation of an isolated experiment branch (`feature/gate1-phase9-modular-detectors`) preserving all prior phase artifacts.
