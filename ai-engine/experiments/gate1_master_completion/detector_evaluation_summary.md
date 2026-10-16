# SentinelAI GATE-1 — Empirical Detector Evaluation Summary
**Evaluation Date:** 2026-10-17  
**Engine:** `ai-engine/experiments/gate1_master_completion/run_gate1_master_evaluation.py`  
**Evaluator:** Senior ML Evaluation Engineer & Independent QA Lead  
**Candidate Model:** `candidate_rf_multicorpus_v1.pkl` (SHA-256: `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020`)  
**Status:** Binding Empirical Deliverable  

---

## 1. Benign False Positive Rate (FPR) Evaluation

Evaluated against the sealed, independent holdout dataset `holdout_benign_30k.parquet` ($N = 30,000$ benign network flows unseen during training or hyperparameter tuning).

| Metric | Empirical Observed | Gate Criterion Target | Verdict |
|---|---|---|---|
| **Sample Size ($N$)** | 30,000 legitimate flows | $N \ge 30,000$ | **PASS** |
| **False Positive Count (Alerts)** | 10 flows | $\le 30$ flows | **PASS** |
| **False Positive Count (Simulated Block)** | 5 flows | $\le 15$ flows | **PASS** |
| **Point Estimate FPR** | **0.0333%** (10 / 30,000) | $< 0.1000\%$ | **PASS** |
| **95% Wilson Score Interval** | **[0.0181%, 0.0614%]** | Upper Bound $< 0.1000\%$ | **PASS** |

### Auditor Analysis:
The candidate model decisively satisfies the Benign FPR contract. With an observed false-positive rate of 0.0333% and a 95% Wilson upper bound of 0.0614%, operational false alarm rates in legitimate production environments are well within the required safety envelope.

---

## 2. Attack Detection Recall by Category

Evaluated against the sealed attack holdout sets in `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\`.

| Attack Family | Holdout Dataset | Attacks ($N$) | Detected (TP) | Empirical Recall | 95% Wilson Interval | Gate Target | Gate Status |
|---|---|---|---|---|---|---|---|
| **PortScan** | CICIDS2017 Holdout | — | — | **99.98%** | [99.95%, 100.0%] | $\ge 90.0\%$ | **PASS** |
| **FTP Brute Force** | `holdout_bruteforce_ssh_ftp` | 1,000 | 915 | **91.50%** | [89.60%, 93.10%] | $\ge 80.0\%$ | **PASS** |
| **SSH Brute Force** | `holdout_bruteforce_ssh_ftp` | 1,000 | 509 | **50.90%** | [47.81%, 53.98%] | $\ge 80.0\%$ | **FAIL** |
| **Botnet (Ares)** | `holdout_botnet` | 2,000 | 1,217 | **60.85%** | [58.69%, 62.97%] | $\ge 75.0\%$ | **FAIL** |
| **DoS / DDoS (HOIC)** | `holdout_ddos` | 1,996 | 0 | **0.00%** | [0.00%, 0.19%] | $\ge 80.0\%$ | **FAIL** |
| **DoS / DDoS (LOIC-UDP)**| `holdout_ddos` | 4 | 0 | **0.00%** | [0.00%, 48.99%] | $\ge 80.0\%$ | **FAIL** |
| **Infiltration (Pivot)** | `holdout_infiltration` | 2,000 | 3 | **0.15%** | [0.05%, 0.44%] | $\ge 70.0\%$ | **FAIL** |
| **Web Attacks (Transport)**| `holdout_web_attacks` | 566 | 2 | **0.35%** | [0.10%, 1.28%] | $\ge 80.0\%$ | **FAIL** |

---

## 3. Specialized Modular Detectors Performance

### 3.1 B1 Volumetric Flood Detector Prototype
- **Implementation:** `ai-engine/modular/volumetric_flood.py`
- **Unit & Contract Tests:** 15 / 15 passed (`ai-engine/tests/test_volumetric_flood.py`)
- **Capabilities:** Multi-window sliding rates (1s burst, 10s surge, 60s sustained), bounded state table with LRU eviction, non-finite input fail-safety.
- **Evaluation Finding:** Successfully detects high-rate volumetric floods ($\ge 5,000$ pps). However, when tested against `holdout_ddos.parquet`, HOIC traffic in CSE-2018 exhibited an average packet rate of only 1,051 pps spread across thousands of distinct simulated IP addresses. A single-source volumetric rate detector alone cannot detect low-rate distributed HTTP floods without cluster/subnet aggregation.

### 3.2 E2 Stateful Auth-Abuse Detector Prototype
- **Implementation:** `ai-engine/modular/auth_abuse.py`
- **Unit & Contract Tests:** 6 / 6 passed (`ai-engine/tests/test_auth_and_waf_detectors.py`)
- **Capabilities:** Bounded connection table with exponential decay ($\lambda = \ln(2)/30$), frequency thresholding on authentication ports (21, 22, 23, 3389).
- **Evaluation Finding:** Effectively detects repetitive SSH and FTP connection floods from single sources in streaming environments. However, on isolated, pre-summarized offline tabular holdouts lacking continuous time-series replay, rate counters reset across shuffled flows.

### 3.3 E4 Layer 7 WAF Deep Payload Inspection Detector Prototype
- **Implementation:** `ai-engine/modular/layer7_waf.py`
- **Unit & Contract Tests:** 7 / 7 passed (`ai-engine/tests/test_auth_and_waf_detectors.py`)
- **OWASP Benchmark Evaluation ($N=200$):**
  - Malicious Payloads Evaluated: 100 (SQLi, XSS, Path Traversal, Command Injection)
  - Benign HTTP Requests: 100
  - Detections (TP): 97 / 100 (**97.00% Recall**)
  - False Alarms (FP): 0 / 100 (**0.00% FPR**)
  - Simulated Blocks: 97
- **Dataset Limitation Disclosure:** `holdout_web_attacks.parquet` contains only 53 numerical netflow features and lacks HTTP string buffers. Layer 7 WAF correctly degrades to `INCOMPLETE` / `MONITOR` when fed flow summaries without string buffers, honestly exposing the dataset gap rather than simulating detection via ground-truth label checks.

---

## 4. Summary of Empirical Deficiencies
1. **DDoS HOIC (0.00%):** Transport ML models fail completely on HTTP application-layer floods. Volumetric detectors require subnet-level aggregation to detect distributed low-rate attack nodes.
2. **Infiltration (0.15%):** Network flow summaries are structurally incapable of distinguishing a stealthy single-session pivot from normal background traffic. Host-based endpoint telemetry (EDR/process auditing) is required.
3. **SSH Brute Force (50.90%):** Short, low-packet SSH authentication handshakes do not consistently separate from legitimate SSH sessions in static flow space.
4. **Web Attacks (0.35% Transport ML):** Network layer netflow summaries cannot identify SQLi or XSS without application-layer payload inspection.
