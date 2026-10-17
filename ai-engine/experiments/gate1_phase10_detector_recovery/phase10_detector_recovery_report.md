# SentinelAI GATE-1 — Phase 10: Evidence-Driven Detector Recovery Report
**Evaluation & Investigation Date:** 2026-10-17  
**Lead Investigator:** Senior Security Architect, ML Evaluation Engineer, and Concurrency Systems Auditor  
**Dedicated Branch:** `feature/gate1-phase9c-modular-scaffold`  
**Base Commit:** `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Current HEAD Commit:** `bfff31d87f54c1bb0c36b856a9a084c718a221ca`  
**Authoritative Gate Status:** **GATE-1 REMAINS OPEN (VERDICT: FAIL / NOT READY FOR PRODUCTION PROMOTION)**  
**Classification System:** Major findings are labeled as **[Confirmed]**, **[Partially confirmed]**, **[Inferred]**, or **[Unverified]**.

---

## 1. Executive Verdict & Core Findings

```
========================================================================================
                      SENTINELAI GATE-1 PHASE 10 RECOVERY AUDIT
----------------------------------------------------------------------------------------
  GATE-1 STATUS:                 OPEN (CANNOT BE PROMOTED TO PRODUCTION)
  FINAL GATE DECISION:           FAIL
  BENIGN FPR INVARIANT:          BASELINE: 0.0333% (PASS); DISPOSABLE EXP: 1.1333% (FAIL)
  HOST FIREWALL INTEGRITY:       0 HOST FIREWALL RULES (NETSH VERIFIED)
  PROTECTED ASSET INTEGRITY:     5/5 ASSETS MATCH BASELINE HASHES (0 BYTES DRIFT)
  AUTOMATED TEST STATUS:         760 DISTINCT TESTS PASS (248 AI ENGINE, 512 BACKEND)
  NEW DETECTORS/ADAPTERS:        B2 DESTINATION AGGREGATOR, E2 AUTH ADAPTER, E3 HOST EDR
  PCAP VALIDATION SPEC:          AUTHORED (ACCEPTANCE BLOCKED: 0 PCAPS ON DISK)
========================================================================================
```

> [!CAUTION]
> ### Authoritative Verdict: GATE-1 REMAINS OPEN (FAIL)
> **[Confirmed]** SentinelAI GATE-1 cannot be closed or promoted to production.
> Phase 10 forensic tracing and empirical testing confirmed that the failure of Candidate ML models on **HOIC DDoS (0.00%)**, **Infiltration (0.15%)**, **SSH Brute Force (50.90%)**, and **Transport Web Attacks (0.35%)** is driven by both **historical pipeline omissions** and **fundamental physical limits of single-flow tabular features**:
> 1. **DDoS HOIC & LOIC Data Ingestion Omission:** `Wednesday-21-02-2018` (containing 686,012 HOIC flows) was completely omitted from the Phase 8 training configuration (`f2018_configs`). The candidate model was evaluated against an attack it was never trained on.
> 2. **Infiltration Early-Termination Ingestion Bug:** `Thursday-01-03-2018` was terminated after ~50,000 rows because `all(cnt >= max_per_class)` evaluated to `True` on `BENIGN` before reading row 238,038 where `Infilteration` begins. Class 9 (`Lateral Movement`) was never trained into `candidate_rf_multicorpus_v1.pkl`.
> 3. **Fundamental Tabular ML Limit:** When an isolated disposable model was trained with both omissions fixed, **HOIC DDoS recall only reached 8.87%** and **Infiltration recall only reached 5.55%**, while **Benign FPR exploded by 34x to 1.1333%** (violating the <0.10% gate threshold).
> 4. **Single-flow HTTP GET & TCP Reset Ambiguity:** 85.5% of HOIC flows are 2-packet, 100-byte HTTP GET requests, and 49.1% of SSH brute-force flows are 1-packet, 7-microsecond TCP resets. In static tabular netflow space, these are indistinguishable from legitimate web browsing and network resets per flow.
> 5. **Architectural Resolution Implemented in Phase 10:**
>    - **B2 Target-Centric Aggregator:** Implemented in `ai-engine/modular/volumetric_flood.py`. Detects multi-source distributed HTTP GET floods (HOIC) hitting a destination target (`dst_ip:dst_port`) with unique source fan-in tracking while preserving low per-flow FPR.
>    - **E2 Structured Authentication Event Adapter:** Implemented in `ai-engine/modular/auth_event_adapter.py`. Parses syslog, Windows Event 4625/4624, and Cowrie events with sliding-window failure/credential stuffing tracking.
>    - **E3 Host EDR Telemetry Adapter:** Implemented in `ai-engine/modular/host_telemetry_adapter.py`. Ingests Windows Event 4688 and Sysmon Event 1 process trees, detecting web shell execution, Office macro droppers, LOLBins, and lateral movement.
>    - **PCAP Validation Procedure Specification:** Formally authored in `ai-engine/modular/pcap_validation_procedure.md`. Documents that 0 raw PCAPs exist on disk, marking Layer 7 WAF acceptance as strictly blocked until genuine packet captures are staged.

---

## 2. Quantitative Baseline vs Post-Fix Scorecard

All metrics below were evaluated on the sealed holdout benchmark (`D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/`):

| Attack Category / Benchmark | Gate Target | Baseline Metric (`candidate_rf_multicorpus_v1`) | Phase 10 Disposable Model (`disposable_rf_phase10_v1`) | Offline Modular Prototype Status | Gate Compliance Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Benign FPR (N=30,000)** | **< 0.10%** | **0.0333%** (10/30,000) [0.018%, 0.061%] | **1.1333%** (340/30,000) [1.020%, 1.260%] | Unit tested (Isolated) | **FAIL on Disposable Model** |
| **Simulated Block FPR** | **< 0.05%** | **0.0167%** (5/30,000) [0.007%, 0.039%] | **0.4200%** (126/30,000) | Unit tested (Isolated) | **FAIL on Disposable Model** |
| **DDoS HOIC** | $\ge 80.0\%$ | **0.00%** (0 / 1,996) [0.00%, 0.19%] | **8.87%** (177 / 1,996) [7.68%, 10.21%] | **B2 Target Aggregator Implemented** | **CRITICAL FAIL on Tabular ML** |
| **DDoS LOIC-UDP** | $\ge 80.0\%$ | **0.00%** (0 / 4) [0.00%, 48.99%] | **100.00%** (4 / 4) [51.01%, 100.0%] | In-situ Port 80 Block | **PASS on LOIC-UDP** |
| **Infiltration (Pivot)** | $\ge 70.0\%$ | **0.15%** (3 / 2,000) [0.05%, 0.44%] | **5.55%** (111 / 2,000) [4.63%, 6.64%] | **E3 Host EDR Adapter Implemented** | **CRITICAL FAIL on Tabular ML** |
| **SSH Brute Force** | $\ge 80.0\%$ | **50.90%** (509 / 1,000) [47.8%, 54.0%] | **8.60%** (86 / 1,000) (High threshold) | **E2 Auth Event Adapter Implemented** | **FAIL on Tabular ML** |
| **FTP Brute Force** | $\ge 80.0\%$ | **91.50%** (915 / 1,000) [89.6%, 93.1%] | **99.80%** (998 / 1,000) [99.2%, 99.9%] | AuthAbuse Frequency Tracked | **PASS** |
| **Botnet (Ares)** | $\ge 75.0\%$ | **60.85%** (1,217 / 2,000) [58.7%, 63.0%] | **39.10%** (782 / 2,000) | State Table Tracking | **FAIL** |
| **Web Attacks (Transport ML)**| $\ge 80.0\%$ | **0.35%** (2 / 566) [0.10%, 1.28%] | **0.35%** (2 / 566) [0.10%, 1.28%] | Holdout parquets lack L7 fields | **CRITICAL FAIL on Tabular ML** |
| **Layer 7 WAF (OWASP)** | $\ge 90.0\%$ | **97.00%** (97 / 100) (Synthetic) | **97.00%** (97 / 100) | PCAP Procedure Authored (Blocked) | **PASS on Synthetic; BLOCKED on PCAP** |

---

## 3. Forensic Root-Cause Analysis for Every Failing Category

### 3.1 DDoS HOIC (0.00% Baseline Recall)
- **Files Involved:**
  - `ai-engine/experiments/gate1_phase8_multicorpus_candidates/run_phase8_experiments.py`
  - `D:/sentinelai_datasets/cse_cic_ids2018/Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv`
  - `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_ddos.parquet`
- **Root Cause [Confirmed]:**
  1. *Pipeline Omission:* Phase 8 training configuration (`f2018_configs`) completely omitted `Wednesday-21-02-2018`. Not a single row of HOIC was present in `partition_train_multicorpus.parquet`.
  2. *Single-Flow Tabular Feature Boundary:* High Orbit Ion Cannon operates as a distributed HTTP GET flood. The mean flow statistics in `holdout_ddos.parquet` are:
     - `flow_duration`: 9,265 $\mu$s (~9.2 ms)
     - `total_fwd_packets`: 2.23 packets, `total_bwd_packets`: 0.94 packets
     - `total_len_fwd_packets`: 70.9 bytes, `total_len_bwd_packets`: 219.7 bytes
     These 2-packet HTTP GET requests look identical to legitimate web browsing per client IP. When trained on HOIC in Phase 10, RF recall only reached 8.87% because classifying these flows as attacks based on packet count alone causes severe false alarms on normal traffic.
- **Phase 10 Remediation [Confirmed]:** Implemented the **Destination-Centric / Subnet Rate Aggregator (B2 Detector)** in `ai-engine/modular/volumetric_flood.py`. Tracks inbound surge rates, burst rates, and unique client source fan-in per `dst_ip:dst_port`, detecting distributed floods while keeping benign single-user browsing within normal ALLOW limits.

### 3.2 Infiltration (0.15% Baseline Recall)
- **Files Involved:**
  - `ai-engine/experiments/gate1_phase8_multicorpus_candidates/run_phase8_experiments.py`
  - `D:/sentinelai_datasets/cse_cic_ids2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`
  - `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_infiltration.parquet`
- **Root Cause [Confirmed]:**
  1. *Ingestion Early-Break Defect:* In `Thursday-01-03-2018`, the first 238,037 rows are all `Benign`. The 93,063 `Infilteration` rows only appear after row 238,037. In `run_phase8_experiments.py`, line 117 checked `all(cnt >= max_per_class)`. Because `class_collected` only contained `{'BENIGN': 10000}` after the first chunk, `all(...)` evaluated to `True`. The extractor broke out of the loop after reading only ~50,000 rows, completely missing all 93,063 rows of Infiltration!
  2. *Missing Target Class:* As a consequence, `candidate_rf_multicorpus_v1.pkl` was fitted with `classes_ = [0, 1, 2, 3, 4, 6, 7, 8]`. Class 9 (`Lateral Movement` / Infiltration) literally did not exist in the candidate model.
  3. *Protocol Blindspot:* Infiltration in CSE-CIC-IDS2018 is an encrypted C2 session over Dropbox. Even when 8,000 Infiltration rows were ingested in the disposable model, netflow ML recall only reached 5.55% because netflow features cannot see inside encrypted HTTPS tunnels.
- **Phase 10 Remediation [Confirmed]:** Implemented the **Host EDR Telemetry Adapter (E3 Detector)** in `ai-engine/modular/host_telemetry_adapter.py`. Parses Windows Event 4688 and Sysmon Event 1 process creation trees, detecting living-off-the-land commands, web shell execution, Office macro droppers, and remote interactive logon correlations.

### 3.3 SSH Brute Force (50.90% Baseline Recall)
- **Files Involved:**
  - `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_bruteforce_ssh_ftp.parquet`
  - `ai-engine/modular/auth_abuse.py`
  - `ai-engine/modular/auth_event_adapter.py`
- **Root Cause [Confirmed]:**
  - Forensic comparison of the 509 detected vs 491 missed SSH flows:
    - *Detected SSH Flows (509 flows):* Mean `flow_duration` = 367,398 $\mu$s (~367 ms), 22.4 forward packets, 21.3 backward packets (full SSH key exchange and authentication handshake).
    - *Missed SSH Flows (491 flows):* Mean `flow_duration` = 6.9 $\mu$s, 1.004 forward packets, 1.000 backward packets, 0 payload bytes!
  - In automated SSH brute-force campaigns (e.g. Hydra, Patator), rapid connection attempts produce interleaved single-packet TCP reset/teardown flows alongside completed auth attempts. In static tabular classification without time-series state, a 1-packet, 7-microsecond TCP reset cannot be classified as an attack without generating massive false positives on normal TCP resets.
- **Phase 10 Remediation [Confirmed]:** Implemented the **Authentication Event Adapter (E2 Detector)** in `ai-engine/modular/auth_event_adapter.py`. Parses structured auth events (syslog, Windows Event 4625/4624, Cowrie) and tracks sliding-window failure frequencies and multi-account credential stuffing per source IP.

### 3.4 Botnet Ares (60.85% Baseline Recall)
- **Files Involved:**
  - `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_botnet.parquet`
  - `ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl`
- **Root Cause [Confirmed]:**
  - 155 of the missed Botnet flows (7.75% of the holdout) were correctly classified as Malware Beacon by argmax, but fell below the 0.70 confidence threshold ($0.50 \le p < 0.70$).
  - The remaining 628 missed flows were unidirectional beaconing attempts (`total_bwd_packets` = 0.57) where the C2 server was unreachable or failed to return a payload.
  - The candidate model learned bidirectional beacon signatures (`total_bwd_packets` = 3.01). Unidirectional failed beacons resemble transient outbound network probes.

### 3.5 Web Attacks on Transport ML (0.35% Baseline Recall)
- **Files Involved:**
  - `D:/sentinelai_datasets/cse_cic_ids2018/Friday-23-02-2018_TrafficForML_CICFlowMeter.csv`
  - `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/holdout_web_attacks.parquet`
  - `ai-engine/modular/layer7_waf.py`
  - `ai-engine/modular/pcap_validation_procedure.md`
- **Root Cause [Confirmed]:**
  1. *Training Data Exhaustion:* In `Friday-23-02-2018`, only 566 attack rows existed across the entire 1,048,575-row CSV (362 Web Brute Force, 151 XSS, 53 SQLi). Phase 7 extracted all 566 into the holdout parquet, leaving 0 rows in CSE-2018 for training.
  2. *Feature Protocol Mismatch:* `holdout_web_attacks.parquet` contains only 53 Layer 4 netflow features. SQL Injection and XSS attacks are Layer 7 payload exploits (`' UNION SELECT...`, `<script>alert(1)</script>`). An SQL injection query and a normal API call have identical packet counts and timing. Transport ML is fundamentally blind to Layer 7 web attacks.
  3. *Missing PCAP Data:* Drive `D:/sentinelai_datasets/cse_cic_ids2018/` contains only CSV flow summaries. No `.pcap` files exist on disk, preventing packet payload reassembly.
- **Phase 10 Remediation [Confirmed]:** Authored the complete **PCAP Validation Procedure Specification** (`ai-engine/modular/pcap_validation_procedure.md`), defining TCP stream reassembly, HTTP parsing, dechunking, decompression, canonicalization, and blinded scoring. Formally marked acceptance as blocked until PCAP captures are acquired.

---

## 4. Detector Integration & Runtime Call-Path Audit

A strict audit of all modular detectors in the codebase confirms:

```
+-------------------------------------------------------------------------------------------------------+
|                                    DETECTOR INTEGRATION STATUS AUDIT                                  |
+--------------------------+-------------+------------------+--------------------+----------------------+
| Detector Component       | Code Exists | Unit Test Suite  | Offline Harness    | Runtime Production   |
|                          |             | Coverage         | Integration        | Path Activation      |
+--------------------------+-------------+------------------+--------------------+----------------------+
| VolumetricFloodDetector  | YES (B1+B2) | YES (20 tests)   | YES (Step 5 pass)  | STRICTLY NO (false)  |
| AuthAbuseDetector        | YES (E2)    | YES (6 tests)    | YES (Step 5 pass)  | STRICTLY NO (false)  |
| AuthEventDetector        | YES (E2-Ad) | YES (8 tests)    | YES (Adapter test) | STRICTLY NO (false)  |
| Layer7WAFDetector        | YES (E4)    | YES (7 tests)    | YES (Step 5 pass)  | STRICTLY NO (false)  |
| HostTelemetryDetector    | YES (E3)    | YES (9 tests)    | YES (Adapter test) | STRICTLY NO (false)  |
| ModularOrchestrator      | YES         | YES (44 tests)   | YES (Step 5 pass)  | STRICTLY NO (false)  |
| Candidate RF Multi-Corpus| YES         | YES (eval suite) | YES (Step 4 eval)  | STRICTLY NO (staged) |
| Active Baseline RF & IFO | YES         | YES (full suite) | YES (active)       | ACTIVE (in models/)  |
+--------------------------+-------------+------------------+--------------------+----------------------+
```

- **Runtime Path Verification [Confirmed]:** `git grep -n "modular" ai-engine/inference/ backend/` returns 0 matches. Neither `ai-engine/inference/main.py`, `predictor.py`, nor `backend/services/aiEngineService.js` imports or invokes `modular`.
- **Runtime Safety Gates [Confirmed]:**
  - `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS = false`
  - `AUTONOMOUS_CONTAINMENT = false`
  - `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = false`
  - Host Windows Firewall rules: **0 rules** matching `SentinelAI`.

---

## 5. Automated Regression Testing & Verification

All automated test suites were executed cleanly in the target environment:

1. **Modular Unit Test Suites (94 tests):**
   - Command: `python -m pytest ai-engine/tests/test_volumetric_flood.py ai-engine/tests/test_auth_and_waf_detectors.py ai-engine/tests/test_modular_scaffold.py -v`
   - Result: **94 passed** (0 failed).
2. **Full AI Engine Test Suite (248 tests):**
   - Command: `python -m pytest ai-engine/tests`
   - Result: **248 passed in 48.77s** (0 failed, 283 deprecation/sklearn version warnings).
3. **Backend Jest Safety Regression Suite (512 tests):**
   - Command: `npm test` in `backend`
   - Result: **512 passed, 13 skipped in 62.77s** (0 failed across 42 test suites).
4. **Total Distinct Tests Verified:**
   - **760 passed, 0 failed, 13 skipped**.

---

## 6. Protected Asset Cryptographic Integrity

All five baseline and candidate model assets were verified via SHA-256:

| Asset Path | Expected SHA-256 Hash | Current Phase 10 Status | Drift |
| :--- | :--- | :--- | :--- |
| `ai-engine/runtime/q_table.json` | `66BCCFCAF7374D48795D0D5EF758253239E29F325F6183A04665B6C77BD5C3D4` | **MATCH** | 0 bytes |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH** | 0 bytes |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH** | 0 bytes |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH** | 0 bytes |
| `ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | **MATCH** | 0 bytes |

---

## 7. Remaining Objective Blockers & Highest-Impact Next Action

### Remaining Objective Blockers to Closing GATE-1:
1. **Raw PCAP Capture Acquisition:** Drive `D:` and repository currently contain 0 raw `.pcap` files. Authentic PCAP captures for CSE-2018 or OWASP benchmark traffic must be staged to run the authored `pcap_validation_procedure.md` pipeline.
2. **Authentic Host EDR Event Datasets:** While `HostTelemetryDetector` and `AuthEventDetector` are fully implemented and unit-tested, validating them against full CSE-2018 campaign event logs requires acquiring Windows Security Log (EVTX) or Sysmon captures.
3. **Multi-Corpus Candidate Model Recalibration:** Retraining the candidate multi-corpus RF with fixed ingestion loops without destroying benign FPR requires exploring class re-weighting, threshold optimization per class, or decomposing multi-corpus inference across specialized sub-models.

### HIGHEST-IMPACT NEXT ACTION:
> **Acquire and stage raw PCAP and Sysmon EVTX captures to execute the PCAP Validation Procedure and EDR Validation Pipeline:**
> Staging genuine packet captures (`.pcap`) and Windows Security / Sysmon event logs (`.evtx` / JSON) will enable running the newly implemented `HostTelemetryDetector`, `AuthEventDetector`, and `Layer7WAFDetector` against realistic adversarial campaigns, establishing the empirical evidence required to resolve the remaining failing categories and close GATE-1.
