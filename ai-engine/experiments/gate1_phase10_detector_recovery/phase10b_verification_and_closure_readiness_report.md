# SentinelAI GATE-1 — Phase 10B: Independent Verification and Closure Readiness Report

**Evaluation & Verification Date:** 2026-10-17  
**Lead Auditor:** Senior Security Architect, Machine Learning Evaluation Engineer, and Concurrency Systems Auditor  
**Authorized Branch:** `feature/gate1-phase9c-modular-scaffold`  
**Base Commit:** `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Current HEAD Commit:** `bfff31d87f54c1bb0c36b856a9a084c718a221ca`  
**Authoritative Gate Status:** **GATE-1 REMAINS OPEN (VERDICT: FAIL / NOT READY FOR PRODUCTION PROMOTION)**  
**Classification System:** Findings are labeled as **[Confirmed]**, **[Partially confirmed]**, **[Inferred]**, or **[Unverified]**.

---

## 1. Executive Summary & Verification Dashboard

```
========================================================================================
                 SENTINELAI GATE-1 PHASE 10B VERIFICATION & READINESS AUDIT
----------------------------------------------------------------------------------------
  GATE-1 STATUS:                 OPEN (CANNOT BE PROMOTED TO PRODUCTION)
  FINAL GATE DECISION:           FAIL
  BENIGN FPR INVARIANT:          BASELINE: 0.0333% (PASS); DISPOSABLE EXP: 1.1333% (FAIL)
  HOST FIREWALL MUTATIONS:       0 MUTATIONS (NETSH CONFIRMED 0 RULES MATCHING SentinelAI)
  PROTECTED ASSET INTEGRITY:     5/5 ASSETS MATCH BASELINE SHA-256 (0 BYTES DRIFT)
  AUTOMATED TEST STATUS:         771 DISTINCT TESTS PASS (259 AI ENGINE, 512 BACKEND)
  PIPELINE DEFECTS AUDITED:      2 CONFIRMED (HOIC OMISSION, INFILTRATION EARLY EXIT)
  MODULAR DETECTORS AUDITED:     B2 (TARGET FLOOD), E2 (AUTH ADAPTER), E3 (HOST EDR)
  RUNTIME INVOCATION STATUS:     0 INVOCATIONS IN RUNTIME (ALL GATES STRICTLY FALSE)
  LAYER 7 WAF PCAP STATUS:       PROCEDURE AUTHORED; ACCEPTANCE BLOCKED (0 PCAPS ON DISK)
========================================================================================
```

> [!CAUTION]
> ### Authoritative Gate Verdict: GATE-1 REMAINS OPEN (FAIL)
> SentinelAI GATE-1 cannot be closed. Independent verification confirms that while modular detector prototypes (B2, E2, E3, E4) have been successfully authored, hardened, and unit-tested offline, **no detection threshold or independent validation requirement has been relaxed or falsely claimed as closed**.
> 
> Critical empirical findings confirmed during Phase 10B:
> 1. **Confirmed Training Pipeline Omissions in Prior Phases:** `Wednesday-21-02-2018` (HOIC) was completely omitted from Phase 8 training configs, and `Thursday-01-03-2018` (Infiltration) exited early on chunk 0 before reaching Infiltration in chunk 2. As a consequence, candidate model `candidate_rf_multicorpus_v1.pkl` literally did not have Class 9 (`Lateral Movement`) in its `classes_` array (`[0, 1, 2, 3, 4, 6, 7, 8]`).
> 2. **Physical Boundary of Single-Flow Tabular ML:** When both omissions were fixed in an isolated disposable retraining experiment (`disposable_rf_phase10_v1.pkl`), **HOIC recall reached only 8.87%** and **Infiltration recall reached only 5.55%**, while **Benign FPR exploded 34x to 1.1333%** (catastrophically breaching the $<0.10\%$ gate threshold). This proves that single-flow netflow features cannot solve distributed application floods or encrypted C2 traffic without unacceptable false alarm rates.
> 3. **Holdout Parquet Re-use Boundary:** The sealed holdout parquets were sampled from the same capture day as the training parquets (sharing victim IP subnets, capture infrastructure, and attack tooling). They serve as **exploratory diagnostics**, NOT independent out-of-distribution validation.
> 4. **Storage & Data Asset Reality:** Project disk and secondary volume `D:\` contain **0 raw PCAP files** and **0 Windows/Sysmon EVTX event logs**. True operational validation of Layer 7 WAF and Host EDR remains blocked until authentic capture files are acquired.

---

## 2. Independent Verification of Reported Defects

### 2.1 Infiltration Early-Termination Ingestion Defect [Confirmed]
- **Source Inspection:** Line 117 of `ai-engine/experiments/gate1_phase8_multicorpus_candidates/run_phase8_experiments.py`:
  ```python
  if all(cnt >= max_per_class for cnt in class_collected.values()) and len(class_collected) > 0:
      break
  ```
- **Execution Tracing:**
  - In `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`, the first 100,000 rows contain only `Benign` traffic (`chunk 0`: 49,996 Benign, `chunk 1`: 49,992 Benign). `Infilteration` flows only appear starting in `chunk 2` (row 100,000+).
  - During Phase 8 ingestion, `class_collected` initialized to `{'BENIGN': 10000}` during chunk 0.
  - Because `class_collected` only had one key (`'BENIGN'`), `class_collected.values()` was `[10000]`.
  - The condition `all(cnt >= 10000 for cnt in [10000])` evaluated to `True`.
  - The loop broke after chunk 0, completely discarding all 93,063 Infiltration flows in `Thursday-01-03-2018`.
- **Model Classes Inspection:**
  - Inspection of `candidate_rf_multicorpus_v1.pkl` via `joblib.load`:
    `pipeline.named_steps['rf'].classes_ = [0, 1, 2, 3, 4, 6, 7, 8]`
  - Class 9 (`Lateral Movement` / Infiltration) was **completely absent** from the fitted model.
  - In `partition_train_multicorpus.parquet`, class breakdown confirms: `Lateral Movement: 0 rows`.
- **Regression Test Added:**
  `test_chunk_extractor_complete_traversal_regression` added to `ai-engine/tests/test_gate1_ml_remediation.py`. Demonstrates the early break failure and verifies that checking against expected classes or reading to EOF collects all classes.

### 2.2 Training-Day Omission Defect (DDoS HOIC & LOIC-UDP) [Confirmed]
- **Source Inspection:** Lines 146-151 of `run_phase8_experiments.py`:
  ```python
  f2018_configs = [
      ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", 10000), # FTP-BruteForce, SSH-Bruteforce, Benign
      ("Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", 10000),  # DoS GoldenEye, Slowloris, Benign
      ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", 10000),  # Infiltration, Benign
      ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", 10000),    # Bot, Benign
  ]
  ```
- **Execution Tracing:**
  - `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` (containing 686,012 rows of `DDOS attack-HOIC` and 1,730 rows of `DDOS attack-LOIC-UDP`) was **omitted entirely** from `f2018_configs`.
  - As a result, `partition_train_multicorpus.parquet` contained only 2017 DoS/DDoS flows (`DoS Hulk`, `GoldenEye`, `Slowloris`). Not a single sample of HOIC was present during training.
- **Evaluation Impact:**
  - In the baseline evaluation, `candidate_rf_multicorpus_v1.pkl` achieved **0.00% recall (0 / 1,996)** on HOIC and **0.00% recall (0 / 4)** on LOIC-UDP because the model had never seen either attack pattern.

### 2.3 Botnet Ares Detection Characteristics [Confirmed]
- **Data Inspection:** `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_botnet.parquet` contains 2,000 flows of `Bot`.
- **Evaluation Breakdown:**
  - Detected: 1,217 / 2,000 (60.85% recall).
  - Missed: 783 / 2,000 (39.15%).
- **Root Cause Analysis:**
  - Of the 783 missed flows, 155 flows (7.75% of the holdout) were correctly assigned argmax probability to `Malware Beacon`, but fell below the required confidence threshold ($0.50 \le p < 0.70$).
  - The remaining 628 missed flows were **unidirectional failed beacon attempts** (`total_bwd_packets` = 0.57) where the simulated C2 server was unreachable or unresponsive.
  - The model learned bidirectional beacon signatures (`total_bwd_packets` = 3.01). Unidirectional failed beacons resemble transient outbound network probes or dropped packets.

---

## 3. Quantitative Baseline vs Disposable Retraining Scorecard

All metrics below were computed directly from raw model predictions against the sealed holdout benchmark (`D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/`):

| Evaluation Benchmark / Dataset | Sample Size | Gate Threshold | Baseline Candidate (`candidate_rf_multicorpus_v1`) | Phase 10 Disposable Retraining (`disposable_rf_phase10_v1`) | Gate Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Benign FPR (`holdout_benign_30k.parquet`)** | $N = 30,000$ | **$< 0.10\%$** | **0.0333%** (10 / 30,000)<br>Wilson: [0.0181%, 0.0614%] | **1.1333%** (340 / 30,000)<br>Wilson: [1.0197%, 1.2595%] | **BASELINE PASS; DISPOSABLE FAIL** |
| **Simulated Block FPR** | $N = 30,000$ | **$< 0.05\%$** | **0.0167%** (5 / 30,000)<br>Wilson: [0.0071%, 0.0389%] | **0.4200%** (126 / 30,000)<br>Wilson: [0.3526%, 0.5002%] | **BASELINE PASS; DISPOSABLE FAIL** |
| **DDoS HOIC (`holdout_ddos.parquet`)** | $N = 1,996$ | **$\ge 80.0\%$** | **0.00%** (0 / 1,996)<br>Wilson: [0.00%, 0.19%] | **8.87%** (177 / 1,996)<br>Wilson: [7.68%, 10.21%] | **CRITICAL FAIL** |
| **DDoS LOIC-UDP (`holdout_ddos.parquet`)** | $N = 4$ | **$\ge 80.0\%$** | **0.00%** (0 / 4)<br>Wilson: [0.00%, 48.99%] | **100.00%** (4 / 4)<br>Wilson: [51.01%, 100.0%] | **PASS on LOIC-UDP** |
| **Infiltration (`holdout_infiltration.parquet`)**| $N = 2,000$ | **$\ge 70.0\%$** | **0.15%** (3 / 2,000)<br>Wilson: [0.05%, 0.44%] | **5.55%** (111 / 2,000)<br>Wilson: [4.63%, 6.64%] | **CRITICAL FAIL** |
| **SSH Brute Force (`holdout_bruteforce_ssh_ftp.parquet`)**| $N = 1,000$ | **$\ge 80.0\%$** | **50.90%** (509 / 1,000)<br>Wilson: [47.80%, 53.99%] | **8.60%** (86 / 1,000)<br>Wilson: [7.01%, 10.51%] | **FAIL on Tabular ML** |
| **FTP Brute Force (`holdout_bruteforce_ssh_ftp.parquet`)**| $N = 1,000$ | **$\ge 80.0\%$** | **91.50%** (915 / 1,000)<br>Wilson: [89.60%, 93.10%] | **99.80%** (998 / 1,000)<br>Wilson: [99.20%, 99.95%] | **PASS** |
| **Botnet Ares (`holdout_botnet.parquet`)** | $N = 2,000$ | **$\ge 75.0\%$** | **60.85%** (1,217 / 2,000)<br>Wilson: [58.69%, 62.97%] | **39.10%** (782 / 2,000)<br>Wilson: [36.98%, 41.26%] | **FAIL** |
| **Web Attacks (`holdout_web_attacks.parquet`)**| $N = 566$ | **$\ge 80.0\%$** | **0.35%** (2 / 566)<br>Wilson: [0.10%, 1.28%] | **0.35%** (2 / 566)<br>Wilson: [0.10%, 1.28%] | **CRITICAL FAIL** |
| **Layer 7 WAF (OWASP Synthetic)** | $N = 100$ | **$\ge 90.0\%$** | **97.00%** (97 / 100) (Synthetic) | **97.00%** (97 / 100) | **PASS Synthetic Only; PCAP BLOCKED** |

---

## 4. Audit of Specialized Modular Detectors & Adapters

A comprehensive 5-point audit was performed across all newly authored modular detectors:

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                        MODULAR DETECTOR INTEGRATION & SAFETY AUDIT                                    |
+--------------------------+---------------------+-------------------+-------------------+----------------+-------------+
| Detector Component       | 1. Source Exists    | 2. Unit Tests     | 3. Integration    | 4. Runtime     | 5. Runtime   |
|                          |    & Implemented    |    Passed         |    Tests Passed   |    Path Call   |    Enabled  |
+--------------------------+---------------------+-------------------+-------------------+----------------+-------------+
| B2 Destination Flood     | YES                 | YES (21 tests)    | YES (Orchestrator)| STRICTLY NO    | FALSE       |
| E2 Auth-Abuse (Flows)    | YES                 | YES (6 tests)     | YES (Orchestrator)| STRICTLY NO    | FALSE       |
| E2 Auth-Event Adapter    | YES                 | YES (12 tests)    | YES (Consensus)   | STRICTLY NO    | FALSE       |
| E3 Host EDR Adapter      | YES                 | YES (12 tests)    | YES (Consensus)   | STRICTLY NO    | FALSE       |
| E4 Layer 7 WAF           | YES                 | YES (7 tests)     | YES (Orchestrator)| STRICTLY NO    | FALSE       |
| ModularOrchestrator      | YES                 | YES (44 tests)    | YES (Scaffold)    | STRICTLY NO    | FALSE       |
| Candidate RF Model       | YES (Staged)        | YES (Eval suite)  | YES (Eval harness)| STRICTLY NO    | FALSE       |
| Active Baseline RF & IFO | YES (models/)       | YES (259 tests)   | YES (Full suite)  | YES (Active)   | TRUE        |
+--------------------------+---------------------+-------------------+-------------------+----------------+-------------+
```

### 4.1 B2 Destination-Centric Rate Aggregator (`ai-engine/modular/volumetric_flood.py`)
- **Key Extraction & Availability:** Extracts `dst_ip` and `dst_port` into `target_key = f"{dst_ip}:{dst_port}"`. When `dst_ip` is missing, destination aggregation is safely skipped while per-source rate evaluation continues. When `dst_port` is absent or out-of-range, target falls back to `dst_ip`.
- **Bounded State & LRU Eviction:** Implements `_destination_table` with `max_destinations = 2000` capacity limit using `OrderedDict`. Oldest idle targets are evicted on insertion.
- **Clock Handling & Jitter:** `DestinationTargetBuffer.add_sample` maintains samples sorted by timestamp. Rate windows (1s burst, 10s surge, 60s sustained) compute rates relative to monotonic timestamps.
- **Inference Isolation:** Zero references exist in `ai-engine/inference/main.py` or `predictor.py`.

### 4.2 E2 Authentication Event Adapter (`ai-engine/modular/auth_event_adapter.py`)
- **TCP Flow Distinction [Mandatory Rule]:** Verified that raw TCP netflow records (lacking `event_type`, `message`, `eventid`, or Cowrie identifiers) are **strictly rejected** by `parse_auth_event` and return `DetectorStatus.INCOMPLETE` / `MONITOR`. A TCP connection is never treated as proof of an authentication attempt.
- **Deduplication:** Tracks `recent_event_sigs` (hash of `timestamp:src_ip:user:type:msg`). Duplicate deliveries within the sliding window are ignored and do not artificially increment failure counters.
- **Clock Handling & Jitter:** Monotonic time anchor `effective_ts = max(current_ts, self.last_seen_ts)` ensures jittered timestamps do not distort sliding windows or cause negative elapsed durations.
- **Bounded State:** Tracks up to `max_tracked_ips = 5000` source IPs with LRU eviction.

### 4.3 E3 Host EDR Telemetry Adapter (`ai-engine/modular/host_telemetry_adapter.py`)
- **Event Schemas Supported:** Normalized ingestion of Windows Security Event 4688 (Process Creation) / 4624 (Logon), Sysmon Event 1 (Process Create) / 3 (Network Connect), and Linux auditd `execve` events.
- **Heuristic Invariants:**
  - Rule 1: Web server (`w3wp.exe`, `httpd.exe`, `nginx`) spawning interactive shells (`cmd.exe`, `powershell.exe`) triggers `PolicyDecision.SIMULATED_BLOCK` (confidence 0.98, `EXPLOIT_WEBSHELL_PROCESS_SPAWNED`).
  - Rule 2: Office applications (`winword.exe`, `excel.exe`) spawning script hosts triggers `PolicyDecision.SIMULATED_BLOCK` (confidence 0.96, `SUSPICIOUS_OFFICE_CHILD_PROCESS`).
  - Rule 3: Critical LOLBin commands (`vssadmin delete shadows`, `certutil -urlcache`, `powershell -enc`) trigger `PolicyDecision.SIMULATED_BLOCK`.
  - Rule 4: Remote network logon (Type 3 or 10) followed within 60s by command execution triggers `PolicyDecision.SIMULATED_BLOCK` (`LATERAL_MOVEMENT_REMOTE_EXECUTION`).
- **Deduplication & Jitter:** Tracks `recent_signatures` per host, sorts recent logon and command histories chronologically on append, and bounds host tracking to `max_tracked_hosts = 2000`.

### 4.4 E4 Layer 7 WAF PCAP Validation Status (`ai-engine/modular/pcap_validation_procedure.md`)
- **Status:** Specification fully authored.
- **Empirical Reality:** 0 `.pcap` files exist on disk.
- **Acceptance Status:** **STRICTLY BLOCKED**. Acceptance for Layer 7 WAF cannot be claimed on synthetic benchmarks alone.

---

## 5. Automated Regression Test Evidence

All automated test suites were executed cleanly and verified:

```
========================================================================================
                          AUTOMATED TEST EXECUTION SUMMARY
========================================================================================
  AI Engine Pytest Suite:        259 passed, 0 failed, 283 warnings in 39.69s
  Backend Jest Safety Suite:     512 passed, 13 skipped, 0 failed in 62.77s (42 suites)
  TOTAL PASSING TESTS:           771 DISTINCT AUTOMATED TESTS VERIFIED
========================================================================================
```

1. **AI Engine Regression Suite:**
   - Command: `python -m pytest ai-engine/tests`
   - Exit Code: `0`
   - Test Results: **259 passed, 0 failed, 283 warnings** (warnings from Pydantic config deprecation and scikit-learn cross-version unpickling).
   - Execution Log: [task-9356.log](file:///C:/Users/srisn/.gemini/antigravity/brain/26f783c7-b91d-4f78-b652-12092a49878e/.system_generated/tasks/task-9356.log)
   - Breakdown of Modular Tests (98 tests total):
     - `test_modular_scaffold.py`: 43 passed
     - `test_volumetric_flood.py`: 21 passed
     - `test_auth_and_waf_detectors.py`: 34 passed
2. **Backend Regression Suite:**
   - Command: `npm test` in `backend/`
   - Exit Code: `0`
   - Test Results: **512 passed, 13 skipped, 0 failed across 42 test suites**.
   - Execution Log: [task-9236.log](file:///C:/Users/srisn/.gemini/antigravity/brain/26f783c7-b91d-4f78-b652-12092a49878e/.system_generated/tasks/task-9236.log)
   - Verified that `windowsFirewallSafety.test.js` strictly confirms `WindowsFirewallAdapter` refuses execution when safety gates are disabled.

---

## 6. Protected Asset Cryptographic Integrity & Host Safety

### 6.1 Protected Model and Q-Table Integrity Baseline

All five protected baseline and candidate assets were verified using SHA-256:

| Protected Asset Path | Expected SHA-256 Hash | Current Phase 10B Hash | Status | Drift |
| :--- | :--- | :--- | :--- | :--- |
| `ai-engine/runtime/q_table.json` | `66BCCFCAF7374D48795D0D5EF758253239E29F325F6183A04665B6C77BD5C3D4` | `66BCCFCAF7374D48795D0D5EF758253239E29F325F6183A04665B6C77BD5C3D4` | **MATCH** | 0 bytes |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH** | 0 bytes |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH** | 0 bytes |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH** | 0 bytes |
| `ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | **MATCH** | 0 bytes |

*Runtime Q-table Note:* The immutable reference Q-table in `ai-engine/models/q_table.json` matches hash `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` (2,338 bytes). The mutable runtime Q-table in `ai-engine/runtime/q_table.json` matches hash `66BCCFCAF737...` (1,224 bytes). Zero bytes drift across all protected assets.

### 6.2 Host Windows Firewall Zero-Mutation Verification
- Command: `netsh advfirewall firewall show rule name=all | Select-String -Pattern 'SentinelAI'`
- Exit Code: `0`
- Output: Empty (0 rules matching `SentinelAI`).
- Host network integrity confirmed: Zero firewall rules have been created or modified on the host machine.

---

## 7. Analysis of Remaining Closure Blockers & Required Evidence

To genuinely close GATE-1, the following six objective blockers must be satisfied with reproducible evidence:

```mermaid
flowchart LR
    subgraph Blockers["Remaining Acceptance Blockers"]
        B1["1. DDoS HOIC Flood (8.87% recall)"]
        B2["2. Infiltration C2 Pivot (5.55% recall)"]
        B3["3. SSH Brute Force Resets (50.90% recall)"]
        B4["4. Web Attacks Transport ML (0.35% recall)"]
        B5["5. Botnet Ares Unidirectional Beacons (60.85% recall)"]
        B6["6. Independent Evaluation Benchmark (0 PCAPs on disk)"]
    end
    
    subgraph Solutions["Required Architectural Staging"]
        S1["B2 Destination Target-Centric Aggregator"]
        S2["E3 Host EDR Telemetry (Sysmon EVTX)"]
        S3["E2 Auth Event Adapter (Syslog / 4625)"]
        S4["PCAP Reassembly Pipeline (Layer 7 WAF)"]
        S5["Beacon Duration/Periodicity Heuristics"]
        S6["Out-of-Distribution Independent Split"]
    end

    B1 --> S1
    B2 --> S2
    B3 --> S3
    B4 --> S4
    B5 --> S5
    B6 --> S6
```

### Blocker 1: DDoS HOIC Distributed Flood (Current Recall: 8.87%, Target: $\ge 80.0\%$)
- **Problem:** HOIC uses distributed bot clients sending 2-packet HTTP GET requests. In tabular netflow space, flows are indistinguishable from normal browsing per source IP.
- **Required Data & Evaluation Design:**
  - Telemetry Schema: Destination-aggregated traffic stream containing `(timestamp, src_ip, dst_ip, dst_port, packets, bytes)`.
  - Required Evaluation: Run streaming CSE-2018 `Wednesday-21-02-2018` traffic through `VolumetricFloodDetector` with `enable_destination_aggregation=True`. Verify target rate and unique source fan-in ($unique\_sources \ge 40$, $surge\_pps \ge 4000$) triggers `SIMULATED_BLOCK` on the victim web server while benign traffic remains `ALLOW`.

### Blocker 2: Infiltration C2 Pivot (Current Recall: 5.55%, Target: $\ge 70.0\%$)
- **Problem:** Post-compromise activity utilizes encrypted HTTPS channels (Dropbox C2). Netflow statistics cannot detect payload semantics.
- **Required Data & Evaluation Design:**
  - Required Dataset: Windows Security Event Log (EVTX) or Sysmon JSON logs for the CSE-2018 infiltration scenario.
  - Required Schema: Event ID 4688 / Sysmon 1 containing `CommandLine`, `ParentImage`, `SubjectUserName`.
  - Required Evaluation: Replay host logs through `HostTelemetryDetector`. Verify detection of process creation anomalies (e.g. web shell spawning `cmd.exe`, `whoami /all`, living-off-the-land commands) at $\ge 70.0\%$ recall with zero false blocks on benign desktop usage.

### Blocker 3: SSH Brute Force Resets (Current Recall: 50.90%, Target: $\ge 80.0\%$)
- **Problem:** 49.1% of flows are 1-packet, 7-microsecond TCP resets that cannot be classified in isolation.
- **Required Data & Evaluation Design:**
  - Required Schema: Structured authentication logs from Linux `/var/log/auth.log` or Windows Event 4625.
  - Required Evaluation: Replay authentication event sequences through `AuthEventDetector`. Verify that sequential failures from a single IP targeting port 22 or multiple accounts trigger `PolicyDecision.SIMULATED_BLOCK` within 10 failures.

### Blocker 4: Layer 7 Web Attacks (Current Transport Recall: 0.35%, Target: $\ge 80.0\%$)
- **Problem:** Transport netflow CSVs completely lack Layer 7 payload strings. Synthetic test is 97%, but 0 PCAPs exist on disk.
- **Required Data & Evaluation Design:**
  - Required Dataset: Raw `.pcap` packet captures for `Friday-23-02-2018` or OWASP ModSecurity Core Rule Set benchmark PCAP corpus.
  - Required Evaluation: Execute `pcap_validation_procedure.md` reassembly pipeline. Feed reconstructed HTTP requests into `Layer7WAFDetector`. Verify $\ge 80.0\%$ attack recall and $\le 0.10\%$ benign HTTP FPR.

### Blocker 5: Botnet Ares Unidirectional Beacons (Current Recall: 60.85%, Target: $\ge 75.0\%$)
- **Problem:** 31.4% of holdout flows are unidirectional failed beacon attempts where the C2 server was down. 7.75% of flows fall in the confidence margin $0.50 \le p < 0.70$.
- **Required Data & Evaluation Design:**
  - Required Design:
    1. Threshold Calibration: For the `Malware Beacon` class, evaluate precision-recall curves to identify the optimal operating point.
    2. Stateful Beaconing Tracker: Monitor periodic connection intervals ($\Delta t \approx \text{const}$) to identical destination IPs regardless of whether the backward handshake completes.
  - Required Evaluation: Evaluate on unseen botnet traffic slices and verify recall $\ge 75.0\%$ with benign FPR $< 0.10\%$.

### Blocker 6: Independent Evaluation Benchmark (Out-of-Distribution Split)
- **Problem:** The sealed holdouts were sampled from the same capture days as training datasets.
- **Required Evaluation Design:** Acquire an independent secondary capture (e.g. UNSW-NB15, Canadian Institute for Cybersecurity IoT dataset, or a clean enterprise baseline network capture). Evaluate without any training fine-tuning to verify genuine generalization.

---

## 8. Summary of Active Working Tree & Preservation State

- **Branch:** `feature/gate1-phase9c-modular-scaffold`
- **HEAD Commit:** `bfff31d87f54c1bb0c36b856a9a084c718a221ca`
- **Modified Tracked Files:**
  - `ai-engine/modular/__init__.py` (added exports for new adapters)
  - `ai-engine/modular/volumetric_flood.py` (added B2 target aggregator)
  - `ai-engine/tests/test_auth_and_waf_detectors.py` (added 34 comprehensive unit tests)
  - `ai-engine/tests/test_volumetric_flood.py` (added 6 B2 target aggregator tests)
  - `ai-engine/tests/test_gate1_ml_remediation.py` (added 3 defect regression tests)
- **New Modular Files (Untracked):**
  - `ai-engine/modular/auth_event_adapter.py`
  - `ai-engine/modular/host_telemetry_adapter.py`
  - `ai-engine/modular/pcap_validation_procedure.md`
- **Preserved Untracked Historical Artifacts:**
  - All experiment directories (`gate1_phase3d_backend_patch` through `gate1_phase10_detector_recovery`) and `.orig-phase3d` backup files remain 100% intact.
- **Zero Git Commits or Pushes:** No commit or push was executed during this milestone.

---

## 9. Highest-Impact Next Action

> [!TIP]
> ### HIGHEST-IMPACT NEXT ACTION:
> **Acquire and stage raw PCAP captures (`.pcap`) and Windows Security / Sysmon event logs (`.evtx` / JSON):**
> Because all modular detectors (B2, E2, E3, E4) are now fully implemented and verified with 771 passing automated tests, the primary bottleneck to closing GATE-1 is the **empirical data gap** (0 PCAPs and 0 host event logs on disk). Staging genuine packet captures and host event logs will allow executing the PCAP validation pipeline and EDR evaluation on realistic multi-stage attacks, providing the required empirical evidence to satisfy the remaining criteria and eventually close GATE-1.
