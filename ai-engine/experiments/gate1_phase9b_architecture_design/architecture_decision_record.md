# SentinelAI GATE-1 Phase 9B: Architecture Decision Record (ADR)

**ADR Title**: Architectural Evolution from Monolithic Flow Classifier to Multi-Tier Modular Ensemble  
**Status**: PROPOSED (DESIGN-ONLY — PENDING EXPERIMENTAL EVALUATION)  
**Date**: 2026-10-16  
**Context**: Gate-1 Phase 9B Architecture Design & Safety Review  
**Deciders**: Senior Security Architect, Lead Machine Learning Engineer, Security-Systems Auditor  

---

## 1. Context and Problem Statement

SentinelAI's baseline architecture relies on a single monolithic classifier ([`rf_classifier_cicids_v2.pkl`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/models/rf_classifier_cicids_v2.pkl)) consuming a 53-dimensional statistical summary of network packet flows.

Independent evaluations in Phase 7 and Phase 8 proved that this monolithic design has reached its architectural limits:
1. **Application-Layer Blind Spot**: Transport flow summaries cannot distinguish HTTP attacks (SQLi, XSS) from benign traffic (0.35% recall).
2. **Encrypted C2 Invisibility**: Infiltration over TLS (Dropbox C2) has identical transport metrics to normal user cloud sync (0.15% recall).
3. **Attack Tool Morphology Shifts**: A model trained on connection exhaustion (Slowloris) fails completely on volumetric HTTP request floods (HOIC) (0.00% recall).
4. **Generalization Bottlenecks**: While multi-corpus retraining improved SSH/FTP to 71.20% and Botnets to 60.85%, no single flow model has satisfied the frozen $\ge 90.00\%$ gate criteria across all attack classes simultaneously.

---

## 2. Alternatives Considered

We evaluate three architectural candidates:

- **Alternative 1: Monolithic Flow Classifier (Status Quo)**  
  Continue training a single multi-class machine learning model (e.g. Random Forest or XGBoost) on wider multi-corpus flow datasets.
- **Alternative 2: Modular Ensemble of Specialized Network Detectors**  
  Deconstruct the network tier into specialized, decoupled network flow detectors: a Volumetric Flood Detector (DDoS), a State-Aware Authentication Detector (SSH/FTP), and an Anomaly Beaconing Detector (Botnets).
- **Alternative 3: Multi-Tier Defense-in-Depth (Reverse-Proxy WAF + Modular Network Detectors + Host Telemetry)**  
  A layered defense architecture combining:
  * Tier 1: Specialized Network Detectors (Volumetric floods, state-aware auth abuse, flow anomalies).
  * Tier 2: Inline HTTP Reverse-Proxy WAF (Plaintext payload inspection for SQLi, XSS, RCE).
  * Tier 3: Host Telemetry Connector (Offline/agentless audit logs for encrypted C2 and lateral movement).

---

## 3. Comparative Evaluation Across Mandated Criteria

| Evaluation Dimension | Alternative 1: Monolithic Flow Classifier | Alternative 2: Modular Network Detectors | Alternative 3: Multi-Tier Defense-in-Depth |
| :--- | :--- | :--- | :--- |
| **1. Observability** | Low. Single flow vector provides no visibility into HTTP URIs, payloads, or host processes. | Moderate. Network metrics exposed separately per protocol family. | **High**. Full visibility into HTTP application payloads, network packet volumetrics, and host execution context. |
| **2. Expected Detection Coverage** | Severe gaps. Proven 0.00% on HOIC DDoS, 0.15% on Infiltration, 0.35% on Web Attacks. | Improved on volumetric DDoS and SSH/FTP, but remains blind to encrypted C2 and Layer 7 payloads. | **Highest**. Closes the Layer 7 payload gap via WAF and the encrypted C2 gap via host process telemetry. |
| **3. Generalization Risk** | High. Decision trees overfit lab-specific packet timings and OS TCP window sizes. | Moderate. Volumetric and auth detectors operate on protocol invariants rather than ML tree splits. | **Low**. WAF uses standardized OWASP CRS regex rules; network flood uses conservation laws; host uses process lineage. |
| **4. Operational Complexity** | **Lowest**. Single Python inference endpoint (`predictor.py`). | Moderate. Requires managing 3 specialized detectors and an aggregation policy. | Higher. Requires reverse-proxy TLS termination and host log ingestion pipelines. |
| **5. False-Positive Management** | Difficult. Tweaking threshold globally impacts all 11 classes simultaneously. | Good. Thresholds can be tuned independently per attack family. | **Best**. High-precision WAF rules eliminate web false positives; rate thresholds tuned per service. |
| **6. Explainability & Auditability** | Poor. Monolithic tree SHAP values produce abstract feature contributions (e.g. `fwd_iat_std`). | Clear. Detectors emit domain-specific reason codes (e.g. `SYN_FLOOD_THRESHOLD_EXCEEDED`). | **Superior**. Exact regex rule matches (`OWASP_CRS_942100`) and process command lines directly auditable. |
| **7. Privacy & Data Requirements** | Minimal. Summary flow statistics only. | Minimal. Packet-level flow summaries and auth counters only. | Higher. Inspects HTTP request bodies and host command lines (requires strict regex PII masking). |
| **8. Deployment Constraints** | Lightweight. Ingests NetFlow/IPFIX passively. | Lightweight. Ingests packet telemetry or flow metrics. | More involved. Requires inline proxy for HTTP and auditd/Sysmon log routing. |
| **9. Failure Safety** | Fragile. A classifier exception drops all threat detection. | Resilient. Failure of one detector leaves other protocols fully protected. | **Most Resilient**. Graceful fallback: WAF failure degrades to transport flow inspection. |
| **10. Evaluation Cost** | Inexpensive. Evaluated against static CSVs. | Moderate. Requires flow datasets with distinct attack tool captures. | Higher. Requires separate HTTP payload corpora, network packet streams, and host audit logs. |

---

## 4. Architect's Recommendation & Decision Justification

### Recommended Decision: Alternative 3 (Multi-Tier Defense-in-Depth)
Based on empirical evidence from Phases 7, 8, and 9A:
- **Transport models cannot solve Layer 7 exploits**: No amount of multi-corpus retraining on flow summary vectors will allow a decision tree to read SQL injection payloads inside encrypted or plain HTTP packets. An HTTP reverse-proxy WAF is structurally necessary.
- **Transport models cannot solve encrypted C2**: Infiltration over TLS to legitimate cloud services (Dropbox) requires endpoint process correlation.
- **Volumetric attacks require physical rate invariants**: Decoupling DDoS into a dedicated packet-rate engine eliminates dependence on tree depth and historical training tool splits.

> [!IMPORTANT]
> ### Crucial Comparative Disclaimer
> Alternative 3 is recommended on the basis of **architectural necessity and proven domain separation**.  
> In accordance with scientific integrity, we do **not** claim Alternative 3 has achieved superior measured benchmark performance. Its superiority remains an architectural hypothesis until each specialized detector is implemented, calibrated, and evaluated in isolated, reproducible experiments.

---

## 5. Explicit Assumptions & Unresolved Open Decisions

1. **Assumption 1 (WAF Inline Feasibility)**: Assumes production deployment environments can accommodate a reverse proxy (e.g. Nginx, Envoy, Node middleware) terminating TLS in front of web services.
2. **Assumption 2 (Agentless Host Ingestion)**: Assumes host audit telemetry can be collected via standard OS log forwarding (auditd, Sysmon, Windows Event Forwarding) without installing proprietary kernel agents.
3. **Open Decision 1 (Ensemble Weighting vs Logic Gating)**: Whether the final orchestrator should use strict Boolean logic gating (WAF overrides Transport for HTTP) or calibrated multi-model probability fusion.
4. **Open Decision 2 (Hardware Sizing for L7)**: Request payload inspection introduces parsing latency ($1-3$ ms/req). Performance benchmarks must determine throughput boundaries under high load.
