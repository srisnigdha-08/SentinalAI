# SentinelAI GATE-1 Phase 7 Independent Audit: Layer 7 WAF Metrics & Policy Semantics

**Audit Scope**: Exact Reproduction of 300-Record WAF Benchmark, Metric Definitions, Rule Independence, and Protocol Boundary Audit  
**Auditor**: Senior ML Evaluation Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Audited Artifact**: `ai-engine/experiments/gate1_phase5_independent_validation/layer7_prototype.py`  

---

## 1. Exact Count Reproduction of the 300-Record HTTP Benchmark

The auditor executed an independent reproduction of the dedicated 300-record benchmark in `layer7_prototype.py`. The exact raw integer counts were reproduced without variance:

| Request Category | Ground Truth Class | Evaluated Record Count | Detected Count (`MONITOR` / `BLOCK`) | Detection Recall (%) | Simulated Block Count (`BLOCK`) | Simulated Block Recall (%) | False Positives |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN_HTTP** | Legitimate | 120 | 0 | 0.00% | 0 | 0.00% | 0 (0.00%) |
| **SQL_INJECTION** | Attack | 35 | 31 | 88.57% | 31 | 88.57% | — |
| **XSS** | Attack | 35 | 35 | 100.00% | 35 | 100.00% | — |
| **PATH_TRAVERSAL** | Attack | 25 | 25 | 100.00% | 25 | 100.00% | — |
| **COMMAND_INJECTION**| Attack | 25 | 22 | 88.00% | 22 | 88.00% | — |
| **MALFORMED_HTTP** | Attack/Anom | 30 | 30 | 100.00% | 0 | 0.00% | — |
| **NON_HTTP_PROTOCOL**| Legitimate/L4 | 30 | 0 | 0.00% | 0 | 0.00% | 0 (0.00%) |
| **Total Attacks** | **Attack** | **150** | **143** | **95.33%** | **113** | **75.33%** | — |
| **Total Non-Attacks**| **Benign** | **150** | **0** | — | **0** | — | **0 (0.00%)** |
| **Benchmark Total** | **Combined** | **300** | **143** | — | **113** | — | **0 (0.00%)** |

### Mathematical Formulas & Exact Quotients:
1. **Detection Recall**:
   $$\text{Recall}_{\text{detect}} = \frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{143}{150} = 0.953333\ldots \quad (\mathbf{95.3333\%})$$
2. **Simulated Block Rate**:
   $$\text{Recall}_{\text{block}} = \frac{\text{Block TP}}{\text{TP} + \text{FN}} = \frac{113}{150} = 0.753333\ldots \quad (\mathbf{75.3333\%})$$
3. **HTTP Benign False Positive Rate**:
   $$\text{FPR}_{\text{HTTP}} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{0}{120} = 0.000000 \quad (\mathbf{0.0000\%})$$
4. **Overall Non-Attack False Positive Rate**:
   $$\text{FPR}_{\text{Total}} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{0}{150} = 0.000000 \quad (\mathbf{0.0000\%})$$

---

## 2. Decoupled Semantic Definitions

To prevent conflation between telemetry alerting and firewall enforcement, the following operational semantic states are defined:

1. **Attack Detection**:
   - A signal is emitted indicating that an exploit pattern or anomaly was identified.
   - Triggers when `threatScore >= MONITOR_THRESHOLD (0.70)`.
   - Results in an administrative audit log and operator dashboard notification. Does not interrupt network traffic.
2. **Policy Decision**:
   - The authoritative operational action resolved by the multi-tier policy engine:
     * `BLOCK`: Hostile payload or high-confidence attack confirmed (`threatScore >= 0.85` in L7, `>= 0.92` in L4 candidate policy).
     * `MONITOR`: Suspicious or borderline traffic requiring analyst triage (`0.70 <= threatScore < 0.85`).
     * `ALLOW`: Legitimate or low-risk traffic permitted without intervention (`threatScore < 0.70`).
3. **Simulated Blocking**:
   - The operational posture where traffic *would* be dropped if autonomous containment were active.
   - Evaluated purely in memory as a simulated metric: `sim_block = (action == "BLOCK")`.
   - **Safety Guarantee**: Real packet dropping and Windows Firewall execution remain disabled (`AUTONOMOUS_CONTAINMENT=false`).
4. **False-Positive Alerting**:
   - Any benign or legitimate session flow that erroneously triggers `MONITOR` or `BLOCK`.
5. **Non-HTTP Protocol Handling**:
   - When a session record lacks HTTP fields (e.g. DNS, NTP, SSH, raw TCP/UDP flows), the Layer 7 WAF returns:
     `{"l7_evaluated": False, "l7_status": "L7_UNAVAILABLE", "l7_score": 0.0, "l7_action": "ALLOW"}`.
   - The request falls through to Layer 4 transport flow models with zero latency overhead.
6. **L7-Unavailable Fallback Behavior**:
   - If Layer 7 WAF encounters an unparseable protocol or is explicitly disabled, the Combined Policy falls back seamlessly to the Layer 4 Candidate Policy without throwing unhandled exceptions.
7. **Errors, Timeouts, and Malformed Inputs**:
   - Evaluated by `CandidateSentinelPolicy.handle_inference_failure()`:
   - Emits `action="MONITOR"`, `status="DEGRADED"`, `isFailSafe=True`.
   - Guaranteed **fail-safe**: never asserts `BENIGN`, never silently drops packets, and enforces analyst review.

---

## 3. Critical Methodological Caveats & Rule Independence

The auditor conducted a code-level review of the 300-record benchmark and identified two major methodological limitations:

### 3.1 Non-Independence of Test Payloads and Regex Rules
- The 300 test payloads in `generate_http_evaluation_benchmark()` and the regular expressions in `Layer7PreFilter` were **authored in the exact same source module** (`layer7_prototype.py`).
- For example, Rule `SQLI_001` matches `r"'\s*or\s+'?1'?\s*=\s*'?1"`, and test payload 0 is `"/products?id=1' OR '1'='1"`.
- Rule `XSS_001` matches `r"<\s*script[^>]*>"`, and test payload 0 is `"/search?q=<script>alert(1)</script>"`.
- **Auditor Verdict**: This benchmark constitutes a **unit test / regression suite**, not an independent blind evaluation. It demonstrates that the regex engine correctly identifies the strings it was programmed to match, but does not prove generalization against obfuscated, real-world zero-day web attacks.

### 3.2 Protocol Scope Limitation (HTTP vs. Non-HTTP)
- **Essential Boundary**: The Layer 7 WAF operates **strictly on HTTP application payloads**.
- High recall on this benchmark (95.33%) provides **zero protection** against non-HTTP attacks:
  * SSH Brute Force (Port 22 binary protocol)
  * FTP Brute Force (Port 21 text control session)
  * Botnet C2 (binary/IRC/encrypted beacons)
  * Infiltration (raw TCP reverse shells, Meterpreter, SMB lateral movement)
  * DDoS (SYN/UDP transport floods)
- **Auditor Conclusion**: Layer 7 inspection is an essential pillar of defense-in-depth for web applications, but it cannot substitute for generalizable Layer 4 transport models. Both tiers are mandatory.
