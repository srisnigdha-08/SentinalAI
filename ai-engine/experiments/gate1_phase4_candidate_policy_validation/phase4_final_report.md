# SentinelAI GATE-1 Phase 4: Final Validation, Safety Remediation, and Release-Gate Report

**Branch**: `feature/gate1-phase4-candidate-policy`  
**Base Commit**: `780619d` (Phase 3D patch)  
**HEAD Commit**: `e9f71a0` (Phase 4 remediation)  
**Evaluation Scope**: 23,036 Network Flows across 8 Daily PCAP Datasets  
**Author**: Implementation Engineer & Senior ML Security Auditor  
**Date**: 2026-10-16  
**Final GATE-1 Decision**: **REMAIN OPEN (Release Blocked)**

---

## 1. Executive Summary

This report concludes **Phase 4: Fail-Open Remediation, Candidate Policy Harness, and Multi-Attack Validation** for SentinelAI GATE-1. 

All technical objectives outlined for Phase 4 were executed in an isolated branch (`feature/gate1-phase4-candidate-policy`) without touching production runtime configurations, live databases, or active firewall rules:
1. **Invalid-Score Fail-Open Defect Remediated**: `backend/services/aiEngineService.js` now enforces strict finite numerical boundaries $[0.0, 1.0]$. All non-numeric strings, `NaN`, infinities, null/undefined, and out-of-range scores deterministically degrade to `status: 'DEGRADED'`, `action: 'MONITOR'`, `predictedClass: 'UNINSPECTED_TRAFFIC'`, and `threatScore: 0.5`.
2. **Emergency Disk Retention Bounded**: `backend/utils/emergencyAudit.js` now prunes archives beyond the newest 5 rotated files, bounding local audit storage to $\le 60\text{MB}$.
3. **Frontend Degraded Triage Supported**: `frontend/src/pages/ThreatLogs.jsx` now provides dashed-amber badge styling for `DEGRADED` events and includes `'UNINSPECTED_TRAFFIC'` in the type filter dropdown.
4. **Backend Test Suite 100% Passing**: All 17 integrated backend safety tests and all 78 total backend regression tests pass.
5. **Decoupled Candidate Policy Evaluated**: The Phase 3A decoupled policy was tested across **23,036 network flows** in an isolated harness (`harness.py`). While it successfully resolves the PortScan and DDoS recall collapse (PortScan: $0.0\% \to 100.0\%$, DDoS: $72.0\% \to 99.8\%$), **GATE-1 CANNOT BE CLOSED**.

### Three Release Blockers Keep GATE-1 OPEN:
1. **Benign False-Positive Statistical Upper Bound**: On 10,000 pure benign flows, the candidate policy incurs 7 false positives ($0.07\%$). The 95% Wilson Score confidence interval upper bound is **$0.1445\%$**, which violates the mandatory release threshold of $< 0.10\%$.
2. **Critical Blindspot on Web Attacks**: The candidate policy detects only **$60.90\%$** of Web Attacks (simulated BLOCK rate: $15.60\%$). Over $39\%$ of web attacks fail open to `ALLOW` because 53 Layer-4 statistical flow features lack Layer-7 payload awareness (SQLi/XSS keywords).
3. **Pervasive Training Set Contamination**: Provenance auditing revealed that `ai-engine/training/train.py` ingested $100\%$ of all available CICIDS2017 instances for SSH-Patator ($5,897$), Web Attacks ($2,180$), Infiltration ($36$), and Botnet ($1,966$). Slices extracted from these captures represent **in-sample resubstitution**, not independent validation.

---

## 2. Source Code Remediation Traceability (Commit `e9f71a0`)

### 2.1. Numerical Sanitization Defect
- **Vulnerability**: In Phase 3D, `Math.max(0, Math.min(1, Number(result.threatScore || 0)))` converted `NaN` or non-numeric inputs into `0`, silently allowing uninspected traffic through to `ALLOW`.
- **Patch**: `backend/services/aiEngineService.js` lines 114–132 enforce:
  ```javascript
  const rawScore = result.threatScore;
  const isStrictlyValidScore = typeof rawScore === 'number' && Number.isFinite(rawScore) && rawScore >= 0 && rawScore <= 1;
  ```
  If invalid, execution immediately branches to safe `DEGRADED` fallback.
- **Verification**: Verified across 10 explicit test assertions covering `null`, `undefined`, `NaN`, `"0.85"`, `"INVALID"`, `1.5`, `-0.01`, `Infinity`, `-Infinity`, and valid boundaries `0.0` / `1.0`.

### 2.2. Unbounded Disk Retention
- **Vulnerability**: `backend/utils/emergencyAudit.js` rotated files on exceeding $10\text{MB}$ without an upper file limit, creating an unbounded disk growth vulnerability.
- **Patch**: Added `MAX_ROTATED_FILES = 5` and `pruneOldRotations()`. When rotation triggers, files sorted ascending by modification time are pruned until $\le 5$ archives remain.
- **Verification**: Verified via test simulating 8 rapid rotations; verified that exactly 5 archives plus the active log remain.

### 2.3. Frontend Dashboard Alignment
- **Patch**: `frontend/src/pages/ThreatLogs.jsx`:
  - Added `STATUS_STYLES.DEGRADED`: `{ color: '#ffaa00', bg: 'rgba(255, 170, 0, 0.1)', border: '1px dashed #ffaa00' }`.
  - Added `'UNINSPECTED_TRAFFIC'` to the `TYPES` filter array.

### 2.4. Test Suite Execution Summary
- `npx jest tests/integrated_backend_safety_regression.test.js`: **17 / 17 passed (100%)**.
- Full backend multi-suite regression: **78 / 78 passed across 5 test suites (100%)**.
  - `integrated_backend_safety_regression.test.js`: 17 passed
  - `threat_event_lifecycle_regression.test.js`: 15 passed
  - `ai_service_regression.test.js`: 15 passed
  - `qlearning_agent_regression.test.js`: 15 passed
  - `threat_logging_regression.test.js`: 16 passed

---

## 3. Dataset Provenance and Flow Count Reconciliation

### The 19,036 vs. 23,036 Discrepancy Resolved
Previous documentation intermittently cited 19,036 and 23,036 total evaluation flows:
- **Root Cause**: An arithmetic drafting oversight in the Phase 3B summary text that summed only Monday Benign ($10,000$) and the six multi-attack slices ($9,036$), yielding $19,036$, while omitting the Friday PortScan ($2,000$) and Friday DDoS ($2,000$) slices ($19,036 + 4,000 = 23,036$).
- **Reconciliation**: The actual, verified offline evaluation corpus comprises **exactly 23,036 flows** partitioned across 8 slices:

| Slice Identifier | Source Capture File | Flow Count | Attack Type |
| :--- | :--- | :---: | :--- |
| `pure_benign` | `Monday-WorkingHours.pcap_ISCX.csv` | 10,000 | Pure Benign Traffic |
| `portscan` | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 2,000 | PortScan |
| `ddos` | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 2,000 | DDoS LOIC |
| `dos_hulk` | `Wednesday-workingHours.pcap_ISCX.csv` | 2,000 | DoS Hulk |
| `web_attacks` | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 1,000 | Brute Force, XSS, Sql Injection |
| `infiltration` | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 36 | Dropbox Infiltration |
| `botnet` | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 2,000 | Ares Botnet |
| `ssh_patator` | `Tuesday-WorkingHours.pcap_ISCX.csv` | 4,000 | SSH-Patator Brute Force |
| **Total Flows** | | **23,036** | |

---

## 4. Candidate Decoupled Policy vs. Active Production Policy Performance

The Phase 4 test harness (`harness.py`) executed the offline evaluation across all 23,036 flows. 

### 4.1. Comparative Performance Matrix

| Traffic Slice | Flow Count ($N$) | Production Policy Recall (MONITOR/BLOCK) | Candidate Policy Recall (MONITOR/BLOCK) | Candidate Simulated BLOCK Recall | Candidate 95% Wilson Confidence Interval |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Monday Benign (FPR)** | 10,000 | **0.00%** (0 FP) | **0.07%** (7 FP) | 0.00% (0 Block) | $[0.034\%, \mathbf{0.145\%}]$ |
| **PortScan** | 2,000 | **0.00%** (0 TP) | **100.00%** (2000 TP) | **99.80%** (1996 Block) | $[99.62\%, 100.00\%]$ |
| **DDoS LOIC** | 2,000 | **72.00%** (1440 TP) | **99.80%** (1996 TP) | **99.80%** (1996 Block) | $[99.27\%, 99.95\%]$ |
| **DoS Hulk** | 2,000 | **65.90%** (1318 TP) | **96.70%** (1934 TP) | **96.70%** (1934 Block) | $[95.40\%, 97.64\%]$ |
| **SSH-Patator** | 4,000 | **46.10%** (1844 TP) | **98.90%** (3956 TP) | **98.90%** (3956 Block) | $[98.48\%, 99.20\%]^*$ |
| **Botnet** | 2,000 | **45.60%** (912 TP) | **98.50%** (1970 TP) | **98.50%** (1970 Block) | $[97.77\%, 98.99\%]^*$ |
| **Infiltration** | 36 | **75.00%** (27 TP) | **86.11%** (31 TP) | **72.22%** (26 Block) | $[71.34\%, 93.92\%]^*$ |
| **Web Attacks** | 1,000 | **7.50%** (75 TP) | **60.90%** (609 TP) | **15.60%** (156 Block) | $[\mathbf{57.84\%}, \mathbf{63.88\%}]$ |

*\*Note: Marked confidence intervals are statistically compromised due to in-sample training data leakage.*

---

## 5. Threshold Sensitivity Analysis

A sensitivity sweep across qualification threshold $T_{qual} \in [0.60, 0.85]$ and suppression threshold $T_{sup} \in [0.75, 0.95]$ demonstrates the performance frontier:

| Qualification Threshold ($T_{qual}$) | Suppression Threshold ($T_{sup}$) | Benign False Positive Rate | PortScan Recall | DDoS LOIC Recall | DoS Hulk Recall | Web Attack Recall |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 0.60 | 0.80 | 0.16% | 100.00% | 99.90% | 97.20% | 71.40% |
| 0.65 | 0.80 | 0.11% | 100.00% | 99.85% | 96.90% | 66.20% |
| **0.70 (Candidate)** | **0.85 (Candidate)** | **0.07%** | **100.00%** | **99.80%** | **96.70%** | **60.90%** |
| 0.75 | 0.85 | 0.04% | 100.00% | 99.60% | 95.80% | 53.10% |
| 0.80 | 0.90 | 0.02% | 99.90% | 98.40% | 94.10% | 41.80% |
| 0.85 | 0.95 | 0.01% | 99.70% | 95.20% | 91.00% | 29.50% |

- Lowering $T_{qual}$ to improve Web Attack recall ($71.4\%$ at $0.60$) drives benign FPR to $0.16\%$, completely destroying benign-traffic safety.
- Raising $T_{qual}$ to drive benign FPR below $0.05\%$ further crushes Web Attack recall below $50\%$.
- **Conclusion**: There exists no scalar threshold combination in the current feature space that satisfies both the FPR $< 0.10\%$ criterion and the Web Attack recall $\ge 90\%$ criterion.

---

## 6. Detailed Analysis of Release Blockers

### Blocker 1: Statistical False-Positive Upper-Bound Exceeded
- **Requirement**: Observed FPR $< 0.10\%$ AND 95% Wilson Upper Bound $< 0.10\%$.
- **Finding**: On 10,000 benign flows, 7 false positives were observed ($p = 0.0007$).
- **Wilson Score Calculation**:
  $$CI_{95\%} = [0.0341\%, \mathbf{0.1445\%}]$$
- **Significance**: Because the upper bound of the confidence interval is $0.1445\%$, we cannot reject the hypothesis that the candidate policy produces more than 14 false alarms per 10,000 benign flows. In an enterprise network processing 10 million flows per day, this would yield up to 14,450 false alarms daily, saturating SOC operators.
- **Remediation Requirement**: Achieving a 95% Wilson upper bound below $0.10\%$ requires testing a minimum of $30,000$ strictly non-violating benign flows ($0$ false positives out of $30,000 \implies CI_{95\%} \le 0.098\%$).

### Blocker 2: Web Attack Detection Blindspot
- **Requirement**: Per-attack recall $\ge 90.0\%$ across all attack classes.
- **Finding**: Web Attack recall is only **$60.90\%$** ($609/1000$), with autonomous BLOCK recall at **$15.60\%$**. $39.10\%$ of attacks bypass detection into `ALLOW`.
- **Root Cause**: The 53 features extracted by the flow generator are purely transport-layer statistical aggregates (e.g., packet lengths, inter-arrival times, TCP window sizes). Web attacks (SQL injection, Cross-Site Scripting, HTTP Brute Force) execute over ordinary HTTP connections that mimic legitimate browser traffic at the transport layer. Without Layer 7 application inspection (URI decoding, regex pattern matching, SQL syntax tokenization), transport-level statistical classifiers cannot reliably separate web attacks from benign web requests.

### Blocker 3: Severe Training Data Leakage
- **Requirement**: Independent evaluation on unbiased, leakage-free blind holdouts.
- **Finding**: Audit of `ai-engine/training/train.py` proved that $100\%$ of all available samples of SSH-Patator ($5,897$), Web Attacks ($2,180$), Infiltration ($36$), and Botnet ($1,966$) in the CICIDS2017 dataset were ingested during model training.
- **Consequence**: Testing on slices extracted from these captures constitutes in-sample resubstitution. High scores on Botnet ($98.5\%$) and SSH-Patator ($98.9\%$) reflect training memorization rather than true out-of-distribution generalization. True generalization to zero-day or unseen attack signatures remains unproven.

---

## 7. Protected Assets & Safety Invariants Audit

All protected assets were verified before and after Phase 4 execution. No bits were modified:

```json
{
  "timestamp": "2026-10-16T15:08:30Z",
  "branch": "feature/gate1-phase4-candidate-policy",
  "verified_assets": {
    "baseline_q_table": {
      "path": "ai-engine/models/q_table.json",
      "expected_sha256": "BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF",
      "status": "MATCH_VERIFIED"
    },
    "runtime_q_table": {
      "path": "ai-engine/runtime/q_table.json",
      "expected_sha256": "55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27",
      "status": "MATCH_VERIFIED"
    },
    "rf_model": {
      "path": "ai-engine/models/rf_classifier_cicids_v2.pkl",
      "expected_sha256": "CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1",
      "status": "MATCH_VERIFIED"
    },
    "isolation_forest_model": {
      "path": "ai-engine/models/isolation_forest_cicids.pkl",
      "expected_sha256": "17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4",
      "status": "MATCH_VERIFIED"
    },
    "xgb_model": {
      "path": "ai-engine/models/xgb_classifier_cicids_v2.pkl",
      "expected_sha256": "A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D",
      "status": "MATCH_VERIFIED"
    }
  }
}
```

- `AUTONOMOUS_CONTAINMENT`: `false` (Unchanged)
- `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`: `false` (Unchanged)
- Live database `sentinel-db`: Unchanged (0 writes)
- Running services: No reboots, no signals sent.

---

## 8. Release Gate Recommendation & Future Roadmap

$$\mathbf{GATE\text{-}1\ VERDICT:\ MUST\ REMAIN\ OPEN}$$

### Roadmap for Gate Closure:
1. **Model Architecture Enhancement (Layer 7 Hybridization)**:
   - Introduce an application-layer payload inspection module (e.g., lightweight WAF signatures or transformer-based character tokenizer) to handle HTTP/Web attack traffic before feeding transport stats into the L4 classifier.
2. **True Out-of-Distribution Data Collection**:
   - Collect fresh, independent network captures from distinct environments or dates (e.g., CSE-CIC-IDS2018 or real-time canary captures) that were never touched during model training.
3. **Statistical Power Expansion**:
   - Evaluate against a holdout dataset of at least $50,000$ pure benign flows to empirically verify that the 95% Wilson upper bound on false alarms stays below $0.10\%$.
4. **Controlled Candidate Model Promotion**:
   - Once out-of-distribution retraining and evaluation satisfy all three criteria, promote the decoupled policy in a staged canary deployment under manual operator supervision.
