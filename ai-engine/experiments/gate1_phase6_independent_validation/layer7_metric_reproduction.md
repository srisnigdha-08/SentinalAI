# SentinelAI GATE-1 Phase 6: Layer 7 Prototype Metric Reproduction and Technical Audit

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Subject**: Independent Audit and Metric Reproduction of Phase 5 Layer 7 Prototype  
**Source Code**: [`ai-engine/experiments/gate1_phase5_independent_validation/layer7_prototype.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase5_independent_validation/layer7_prototype.py)  

---

## 1. Metric Terminology and Denominator Definitions

To eliminate ambiguity across evaluation reports, the audit establishes rigorous mathematical definitions for all reported performance metrics:

1. **Raw Classifier Detection Recall**:
   $$\text{Raw Recall} = \frac{\sum [y_{true} \in \text{Attack} \land \hat{y}_{raw} \ne \text{BENIGN}]}{\sum [y_{true} \in \text{Attack}]}$$
   Measures the proportion of attack flows where the raw supervised Random Forest classifier predicts an attack class prior to policy gating.
2. **Policy Containment Recall**:
   $$\text{Containment Recall} = \frac{\sum [y_{true} \in \text{Attack} \land \text{Action} \in \{\text{MONITOR}, \text{BLOCK}\}]}{\sum [y_{true} \in \text{Attack}]}$$
   Measures the proportion of attack flows that are not allowed through (i.e. escalated to analyst triage or containment).
3. **Simulated Autonomous BLOCK Recall**:
   $$\text{Simulated BLOCK Recall} = \frac{\sum [y_{true} \in \text{Attack} \land \text{Action} = \text{BLOCK}]}{\sum [y_{true} \in \text{Attack}]}$$
   Measures the proportion of attack flows that meet the high-confidence criteria for automated host containment.
4. **Benign False Positive Rate (FPR)**:
   $$\text{FPR} = \frac{\sum [y_{true} = \text{BENIGN} \land \text{Action} \in \{\text{MONITOR}, \text{BLOCK}\}]}{\sum [y_{true} = \text{BENIGN}]}$$
   Measures legitimate traffic falsely escalated to alerting or containment.

---

## 2. Independent Reproduction of Benchmark Metrics

The Phase 5 evaluation was re-executed against the 300-record comprehensive HTTP benchmark across all four configurations. The reproduction yielded identical, deterministic results:

### 2.1. Aggregate Confusion Matrix and Performance Comparison ($N=300$)

| Evaluation Configuration | True Positives (TP) | False Negatives (FN) | False Positives (FP) | True Negatives (TN) | Simulated Block TP | Containment Recall | Simulated Block Recall | Benign FPR | 95% Wilson CI (Recall) | 95% Wilson CI (FPR) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config A: Prod Policy** | 0 | 150 | 0 | 150 | 0 | **0.00%** | **0.00%** | 0.00% | $[0.00\%, 2.50\%]$ | $[0.00\%, 2.50\%]$ |
| **Config B: Cand Flow** | 0 | 150 | 0 | 150 | 0 | **0.00%** | **0.00%** | 0.00% | $[0.00\%, 2.50\%]$ | $[0.00\%, 2.50\%]$ |
| **Config C: L7 Alone** | 143 | 7 | 0 | 150 | 113 | **95.33%** | **75.33%** | 0.00% | $[90.68\%, 97.72\%]$ | $[0.00\%, 2.50\%]$ |
| **Config D: Combined** | 143 | 7 | 0 | 150 | 113 | **95.33%** | **75.33%** | 0.00% | $[90.68\%, 97.72\%]$ | $[0.00\%, 2.50\%]$ |

### 2.2. Category-by-Category Audit Breakdown

| Traffic Category | Total Records ($N$) | Ground Truth | Config A / B Detected | Config C / D Detected | Config D Simulated Blocked | Detection Status | Root Cause / Analysis |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **XSS Attempts** | 35 | Attack | 0 (0.0%) | **35 (100.0%)** | **35 (100.0%)** | **FULL DETECTION** | Inline `<script>`, `onerror=`, `onload=`, and `javascript:` URIs caught by `XSS_001`–`XSS_004`. |
| **Path Traversal** | 25 | Attack | 0 (0.0%) | **25 (100.0%)** | **25 (100.0%)** | **FULL DETECTION** | Directory backtracking (`../`, `%2e%2e/`) and `/etc/passwd` caught by `TRAV_001`–`TRAV_002`. |
| **SQL Injection** | 35 | Attack | 0 (0.0%) | **31 (88.6%)** | **31 (88.6%)** | **PARTIAL DETECTION** | Tautology, UNION SELECT, time delays caught. 4 evasion variants missed (complex error subqueries). |
| **Command Injection** | 25 | Attack | 0 (0.0%) | **22 (88.0%)** | **22 (88.0%)** | **PARTIAL DETECTION** | Shell pipes and binary executions caught. 3 variants missed (unspaced backticks). |
| **Malformed Protocol** | 30 | Attack | 0 (0.0%) | **30 (100.0%)** | **0 (0.0%)** | **MONITORED ONLY** | Invalid HTTP methods and header control chars triggered `PROTO_001`/`002` (score: 0.75/0.80 $\to$ MONITOR). |
| **Benign HTTP** | 120 | Benign | 0 FP | 0 FP | 0 Block FP | **PERFECT PASS** | Standard REST APIs, pagination, search queries, and cookies passed normalizer without false alarms. |
| **Non-HTTP Protocol** | 30 | Benign | 0 FP | 0 FP | 0 Block FP | **PERFECT PASS** | Emitted `L7_UNAVAILABLE`; successfully delegated to Layer 4 flow classifier without error. |

---

## 3. Auditing the 300-Record HTTP Benchmark: Independence & Limitations

The auditor conducted a source code and provenance inspection of how the 300 HTTP benchmark records were generated:

### 3.1. Benchmarking Provenance Finding
> [!WARNING]
> **Audit Disclosure on Benchmark Independence**:
> The 300-record HTTP benchmark evaluated in Phase 5 and Phase 6 was **synthetically constructed** by the development team in `layer7_prototype.py` to represent canonical OWASP Top 10 patterns.
>
> - **Self-Referential Risk**: The test records were formulated to test the regex rules implemented in the prototype (`SQLI_001`–`SQLI_005`, `XSS_001`–`XSS_004`, etc.). While this validates that the normalizer and regex engines operate as specified, **it does not constitute an independent blind holdout**.
> - **Evaluation Value**: The benchmark definitively proves that a Layer 7 pre-filter successfully overcomes the complete blindness ($0\%$ recall) of transport-layer flow features on HTTP attacks. However, reported recall ($95.33\%$) represents an in-distribution unit test of the rules, not a guarantee against in-the-wild obfuscated exploits.

### 3.2. Statistical Power Deficit of the Benign HTTP Sample
The benchmark tested 120 benign HTTP requests and 30 non-HTTP records ($N = 150$ total benign observations):
- Observed Benign False Positives: **$0$ out of $150$** ($0.0\%$).
- Exact 95% Wilson Score Interval: $[0.0000\%, \mathbf{2.4970\%}]$.
- **Auditor Finding**: Because the upper confidence bound of the benign sample is $2.497\%$, we cannot mathematically rule out a false alarm rate as high as $2.5$ in 100 requests. To certify compliance with the $< 0.10\%$ release mandate, an independent corpus of at least **$N \ge 30,000$ benign HTTP requests** must be evaluated.

---

## 4. Audit of Fallback and Telemetry Auditability

1. **Protocol Fallback Verification**:
   - For records lacking HTTP fields (such as the 23,036 CICIDS2017 flow records or raw DNS/NTP packets), [`Layer7PreFilter.inspect_record()`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase5_independent_validation/layer7_prototype.py) returns:
     ```python
     {
       "l7_evaluated": False,
       "l7_status": "L7_UNAVAILABLE",
       "l7_score": 0.0,
       "l7_action": "ALLOW",
       "matched_rules": [],
       "primary_threat": "UNINSPECTED_L7"
     }
     ```
   - In Configuration D, execution branches directly to the Layer 4 Candidate Flow Policy.
   - **Audit Verdict**: Verified. The system never misrepresents uninspected non-HTTP traffic as inspected.
2. **Decision Auditability**:
   - For every positive detection, the telemetry payload records:
     - `matched_rules`: Explicit array of triggered rule IDs (e.g., `["SQLI_001", "SQLI_002"]`).
     - `primary_threat`: Standardized threat taxonomy label.
     - `matched_excerpt`: Safely truncated string of the matched pattern token (avoiding sensitive body capture).
     - `latency_ms`: Microsecond-precision processing duration.
   - **Audit Verdict**: Verified. Security analysts have complete visibility into why an HTTP transaction was flagged.
