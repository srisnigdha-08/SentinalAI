# SentinelAI GATE-1 — Acceptance Criteria Mapping & Verification Audit

**Phase:** GATE-1 Phase 14.1 — Read-Only Independent Evidence Adjudication  
**Date:** October 18, 2026  
**Registry Source:** `GATE1_CONTRACT.md` Section 6 (Phase 11 Registry) & Authoritative Amendments  
**Phase Directory:** `ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/`  
**Adjudication Scope:** Complete mapping of every official GATE-1 criterion to primary evidence artifacts, current verdicts, evidence limitations, required remediation actions, and owner-approval requirements.

---

## 1. Master Acceptance Criteria Scorecard

```
┌──────┬───────────────────────────────────┬──────────────┬───────────────────────────────┬──────────────────────┐
│ ID   │ Criterion Description             │ Target       │ Current Evaluated Metric      │ Verdict              │
├──────┼───────────────────────────────────┼──────────────┼───────────────────────────────┼──────────────────────┤
│ A1   │ Whole-Pipeline Benign FPR         │ ≤ 0.100%     │ 0.112% (28/25k) [V3]          │ FAIL                 │
│ B1   │ Bounded Concurrency / Queue       │ Bounded Mem  │ Bounded under test load       │ PASS (Engineering)   │
│ B2   │ DDoS HOIC / LOIC Recall           │ ≥ 80.0%      │ 85.68% [V3, burned set]       │ PASS (Burned) / UNVER│
│ C1   │ Pipeline Integrity & Ingestion    │ Full ingest  │ 5/5 integrity tests passed    │ PASS (Engineering)   │
│ C2   │ Multiclass Coverage (10 Classes)  │ 10 classes   │ 9 classes in model (N=11 C5)  │ FAIL / BLOCKED (OD2) │
│ D1   │ Botnet Ares Recall                │ ≥ 75.0%      │ 94.72% [V3, burned set]       │ PASS (Burned) / UNVER│
│ D2   │ Web Attacks Recall (SQLi / XSS)   │ ≥ 80.0%      │ 82.69% (N=52, CI [70%, 91%])  │ INCONCLUSIVE / ARCH  │
│ E1   │ SSH Brute Force Recall (Per-Flow) │ ≥ 80.0%      │ 100.0% [V3, burned set]       │ PASS (Burned) / UNVER│
│ E2   │ Authentication Event Adapter      │ Functional   │ 48/48 contract tests passed   │ PASS (Engineering)   │
│ E3   │ Infiltration (Lateral Movement)   │ ≥ 70.0%      │ 0.04% (1/2500) [V3]           │ FAIL / BLOCKED (OD3) │
│ E4   │ Layer 7 WAF Real Traffic          │ High Acc L7  │ Synthetic only; no real pcap  │ UNVERIFIED (Traffic) │
│ F1   │ ai-engine Test Suite              │ 100% pass    │ 285/285 passed                │ PASS (Engineering)   │
│ F2   │ backend Test Suite                │ 100% pass    │ 512/512 passed (13 skipped)   │ PASS (Engineering)   │
│ F3   │ Windows Firewall Safety Gate      │ Mock only    │ Mock adapter enforced in code │ PASS (SAFE)          │
├──────┼───────────────────────────────────┼──────────────┼───────────────────────────────┼──────────────────────┤
│ SUPP │ Credential Stuffing Recall        │ ≥ 80.0%      │ 100.0% [V3, burned set]       │ PENDING OWNER CONF   │
└──────┴───────────────────────────────────┴──────────────┴───────────────────────────────┴──────────────────────┘
```

---

## 2. Detailed Mapping for Every Acceptance Criterion

---

### Criterion A1: Whole-Pipeline Benign False-Positive Rate (FPR)

- **Target Specification:** Total Benign False Positive Rate across the entire intrusion detection pipeline must be $\le 0.100\%$ ($\le 25$ false positives out of 25,000 benign flows).
- **Existing Primary Evidence:**
  - **Phase 12 Sealed Test:** Evaluated Candidate V2 against `final_sealed_test.parquet`. Produced **26 false positives / 25,000 = 0.104% FPR** (Status: FAIL). False positives clustered heavily on Lateral Movement (10 FPs) and Malware Beacon (6 FPs).
  - **Phase 13 Sealed Test:** Evaluated Candidate V2 and Candidate V3 against `final_test_v2.parquet` (`final_acceptance_evaluation.json` lines 14–24 & 103–113):
    - Candidate V2 (raw $P \ge 0.70$): **30 false positives / 25,000 = 0.120% FPR**, 95% Wilson CI [0.0841%, 0.1713%] (FAIL).
    - Candidate V3 (cross-fitted isotonic calibration): **28 false positives / 25,000 = 0.112% FPR**, 95% Wilson CI [0.0775%, 0.1618%] (FAIL).
- **Current Verdict:** **FAIL**.
- **Evidence Limitations:**
  - Both `final_sealed_test.parquet` and `final_test_v2.parquet` were evaluated and are now **BURNED** per Contract Section 5. They cannot be used to tune or validate candidate models.
  - Phase 12's reported "0.0840% calibrated FPR" was optimistic in-sample validation (calibrated on the exact validation partition it evaluated).
  - Phase 13's isotonic calibration optimized per-class thresholds independently, allowing false positives across 8 attack classes to accumulate beyond the global 0.100% budget.
- **Required Next Action:**
  - Implement a joint, multi-class constrained threshold search on permitted validation data:
    $$\max \sum \text{Recall}_k \quad \text{subject to } \text{FPR}_{\text{validation}} \le 0.070\%$$
  - The 0.070% ceiling provides the necessary headroom buffer to absorb test-set sampling variance without breaching the 0.100% contract ceiling.
  - Update decision rule fallback from attack argmax to Benign (Class 0).
- **Owner Approval Required:** **NO** (Algorithm optimization is within engineering scope; relaxing the 0.100% target would require owner approval).

---

### Criterion B1: Bounded Concurrency / Queue Management

- **Target Specification:** Under concurrent network flow ingestion, the AI engine and backend queue must maintain bounded memory, prevent unhandled queue growth, and apply graceful backpressure without crashing.
- **Existing Primary Evidence:**
  - Unit and integration tests in `ai-engine/tests/test_volumetric_flood.py` (24 tests) verify `DestinationTargetAggregator` saturation bounds:
    `test_destination_capacity_saturation_bound`, `test_late_event_arriving_after_horizon_is_pruned_without_skewing_rates`.
  - Backend threat queue tests in `backend/tests/` verify worker concurrency and bounded queueing.
  - Verified across the full 285-test ai-engine suite and 512-test backend Jest suite.
- **Current Verdict:** **PASS (Engineering)**.
- **Evidence Limitations:** Evaluated using automated unit and mock load fixtures; sustained real-world streaming load at line rate (10 Gbps) has not been demonstrated in production network hardware.
- **Required Next Action:** Maintain regression assertions during all candidate model integration phases.
- **Owner Approval Required:** **NO**.

---

### Criterion B2: DDoS HOIC / LOIC Recall

- **Target Specification:** Recall on High Orbit Ion Cannon (HOIC) and Low Orbit Ion Cannon (LOIC) packet streams must be $\ge 80.0\%$.
- **Existing Primary Evidence:**
  - **Phase 12 Candidate V2:** On sealed test, recall collapsed to **9.95%** at $P \ge 0.70$ (199 / 2,000) and **27.4%** at $P \ge 0.50$ (548 / 2,000) due to omitted 21-Feb ingestion and in-sample calibration decay.
  - **Phase 13 Candidate V3:** On `final_test_v2.parquet`, achieved **85.68% recall** (2,142 / 2,500), 95% Wilson CI [84.25%, 87.00%] (Status: PASS on this dataset).
  - `ai-engine/modular/volumetric_flood.py` implements a shadow packet-rate detector (`target_burst_pps_limit=1500.0`, `target_surge_pps_limit=800.0`).
- **Current Verdict:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Evidence Limitations:**
  - `final_test_v2.parquet` is burned.
  - Ref 3 census confirms DDoS HOIC exists *exclusively* on `Wednesday-21-02-2018` (686k flows). Per Contract Section 5, single-day classes must be partitioned into time-contiguous blocks separated by a 30-minute blackout gap and labeled "same-day, time-gap separated".
- **Required Next Action:**
  - Generate a fresh, unburned evaluation holdout using time-gap block partitioning on 21-Feb data.
  - Evaluate frozen candidate model once. Maintain shadow B2 volumetric flood detector.
- **Owner Approval Required:** **NO**.

---

### Criterion C1: Pipeline Integrity & Ingestion Traversal

- **Target Specification:** Complete end-to-end ingestion traversal without data loss, infinite loops, premature loop termination, or feature truncation; must include complete ingestion of 21-Feb HOIC/LOIC data.
- **Existing Primary Evidence:**
  - Premature chunk-loop exit bug resolved in Phase 10 (`build_candidate_v2_fixed.py` lines 6–10).
  - Ingestion of 21-Feb HOIC validated in `ai-engine/tests/test_data_pipeline_integrity.py` (5 tests passing).
  - Verified that all CSV chunks are traversed until target quotas or EOF are reached.
- **Current Verdict:** **PASS (Engineering)**.
- **Evidence Limitations:**
  - While raw CSV traversal is intact, feature schema drift exists: `features.py` specifies 53 features, whereas candidate models are trained on 51 features (V2) or 49 features (V3). Loading a 51/49-feature candidate into `SentinelPredictor` currently raises `ValueError`.
- **Required Next Action:**
  - Freeze canonical 51-feature schema (without time features) in `features.py`. Update `EXPECTED_FEATURE_COUNT = 51` and pipeline schema validators.
- **Owner Approval Required:** **NO**.

---

### Criterion C2: Multiclass Coverage (10 Classes)

- **Target Specification:** Full multi-class classification capability across all 10 defined classes (Classes 0 through 9: Benign, SSH, SQLi, PortScan, DDoS, RCE Attempt, XSS Attempt, Malware Beacon, Credential Stuffing, Lateral Movement).
- **Existing Primary Evidence:**
  - Candidate V1: 8 classes (missing Class 5 and Class 9).
  - Candidate V2 (`candidate_rf_multicorpus_v2_fixed.pkl`): 9 classes (Classes 0, 1, 2, 3, 4, 6, 7, 8, 9; missing Class 5).
  - Candidate V3 (`candidate_rf_multicorpus_v3.pkl`): 9 classes (missing Class 5).
  - Heartbleed Audit (`class5_heartbleed_audit.json`): Total sample population across all available corpora is **$N = 11$ flows** (all in CICIDS2017 Wednesday; 0 in CSE-CIC-IDS2018).
- **Current Verdict:** **FAIL / BLOCKED ON OWNER DECISION 2**.
- **Evidence Limitations:**
  - Extreme dataset sparsity ($N = 11$) makes statistical learning mathematically impossible. An 80/20 train/test split yields 3 test samples, where 1 error drops recall by 33.3% and 95% Wilson CI spans 56.15 percentage points.
  - Heartbleed is CVE-2014-0160 (TLS memory over-read), an Information Disclosure flaw, not RCE.
- **Required Next Action:**
  - Per Contract Section 7 & 8, Class 5 cannot be silently dropped or redefined by engineering.
  - Present **Owner Decision 2** to formally re-scope Criterion C2 to 9 classes for the statistical flow classifier, and delegate Heartbleed to Layer 7 signature inspection.
- **Owner Approval Required:** **YES (Owner-Only Decision per Contract Section 7 & 8)**.

---

### Criterion D1: Botnet Ares Recall

- **Target Specification:** Recall on Botnet Ares command-and-control (C2) / beaconing traffic must be $\ge 75.0\%$.
- **Existing Primary Evidence:**
  - **Phase 12 Candidate V2:** On sealed test, recall collapsed to **42.85%** at $P \ge 0.70$ (857 / 2,000) and **74.15%** at $P \ge 0.50$ (1,483 / 2,000) (Status: FAIL).
  - **Phase 13 Candidate V3:** Achieved **94.72% recall** (2,368 / 2,500), 95% Wilson CI [93.77%, 95.53%] (Status: PASS on this dataset).
- **Current Verdict:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Evidence Limitations:**
  - `final_test_v2.parquet` is burned.
  - Ref 3 confirms Botnet Ares has high discriminative signal on flow IAT and duration, but lowering thresholds to maximize Botnet recall can inflate Benign FPR if not calibrated jointly.
- **Required Next Action:**
  - Verify that the calibrated Botnet threshold satisfies the joint validation FPR budget ($\le 0.070\%$).
  - Evaluate on a fresh, unburned multi-corpus holdout.
- **Owner Approval Required:** **NO**.

---

### Criterion D2: Web Attacks Recall (SQL Injection & XSS)

- **Target Specification:** Recall on Web Application attacks (SQL Injection, Cross-Site Scripting) must be $\ge 80.0\%$.
- **Existing Primary Evidence:**
  - **Phase 12 Candidate V2:** On sealed test, recall was **0.0%** (0 / 566 detected).
  - **Phase 13 Candidate V2:** On `final_test_v2.parquet`, recall was **0.0%** (0 / 52 detected).
  - **Phase 13 Candidate V3:** Achieved **82.69% recall** (43 / 52 detected), but because $N = 52$, the 95% Wilson confidence interval was **[70.27%, 90.62%]**. Per Contract Section 3, because the confidence interval straddles the 80% target, the formal verdict is **INCONCLUSIVE**.
- **Current Verdict:** **INCONCLUSIVE (Statistical) / ARCHITECTURAL DEFECT on Flow Features**.
- **Evidence Limitations:**
  - Ref 4 (`network-attack-research/README.md` line 54) explicitly documents that Web Attacks in CIC-IDS consist of HTTP GET/POST injection strings. Flow-level statistics (packet counts, IATs) are identical to normal web browsing; transport flow models miss >95% of web exploits without Layer 7 payload visibility.
  - Sample size $N = 52$ is statistically inadequate ($N \ge 384$ required for CI half-width $\le 0.05$).
- **Required Next Action:**
  - Primary detection for Web Attacks must be designated to the Layer 7 WAF inspection module (`ai-engine/modular/` or WAF reverse proxy).
  - Prepare adequate test corpus ($N \ge 400$) with authentic HTTP request streams.
- **Owner Approval Required:** **NO** (if L7 WAF architecture is recognized); **YES** if modifying metric thresholds.

---

### Criterion E1: SSH Brute Force Recall (Official Per-Flow Standard)

- **Target Specification:** Per-flow recall on SSH Brute Force (SSH-Patator) must be $\ge 80.0\%$. Contract Section 7 confirms: *"SSH per-flow recall is the official criterion; session-level is supplementary and only valid with real IPs/timestamps."*
- **Existing Primary Evidence:**
  - **Phase 12 Candidate V2:** On sealed test, achieved **50.80% recall** at $P \ge 0.70$ (508 / 1,000) and **50.90%** at $P \ge 0.50$ (509 / 1,000). Forensic audit revealed that 491 of the 492 misses were pure TCP RST/FIN connection teardown flows with 0 payload bytes and 6 $\mu$s duration.
  - **Phase 13 Candidate V2:** On `final_test_v2.parquet`, achieved **82.68% recall** (2,067 / 2,500) (Status: PASS).
  - **Phase 13 Candidate V3:** Achieved **100.0% recall** (2,500 / 2,500), 95% Wilson CI [99.85%, 100.0%] (Status: PASS).
- **Current Verdict:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Evidence Limitations:**
  - Evaluated on burned test set.
  - However, the underlying physical signal is strong: Ref 1 and Ref 4 confirm that SSH credential guessing produces distinctive forward packet length distributions and TCP handshake timing.
- **Required Next Action:**
  - Validate per-flow recall on fresh multi-corpus holdout without time features.
- **Owner Approval Required:** **NO** (Contract Section 7 already established per-flow as official).

---

### Criterion E2: Authentication Event Adapter

- **Target Specification:** Functional authentication telemetry processing and normalization from honeypot / Cowrie authentication logs, decoupled from raw ML flow inference.
- **Existing Primary Evidence:**
  - `ai-engine/modular/auth_event_adapter.py` implemented and verified.
  - 40 tests in `test_auth_and_waf_detectors.py` and 8 tests in `test_cowrie_parser_contract.py` pass with 100% success.
  - Decoupling verified in `test_abuseipdb_decoupling.py` (7 tests passing).
- **Current Verdict:** **PASS (Engineering)**.
- **Evidence Limitations:** Evaluated against mock and synthetic Cowrie event logs; live deployment requires streaming syslog / JSON socket verification.
- **Required Next Action:** Maintain contract regression tests.
- **Owner Approval Required:** **NO**.

---

### Criterion E3: Infiltration / Lateral Movement Recall

- **Target Specification:** Recall on Infiltration / Lateral Movement traffic must be $\ge 70.0\%$.
- **Existing Primary Evidence:**
  - **Phase 12 Candidate V2:** On sealed test, achieved **0.35% recall** (7 / 2,000 detected) (Status: FAIL).
  - **Phase 13 Candidate V2:** On `final_test_v2.parquet`, achieved **0.0% recall** (0 / 2,500 detected) (Status: FAIL).
  - **Phase 13 Candidate V3:** On `final_test_v2.parquet`, achieved **0.04% recall** (1 / 2,500 detected) (Status: FAIL).
  - **Ref 3 t-SNE & Model Benchmark:** Across 24,290 Infiltration flows, XGBoost misclassified 18,208 (74.96%) as Benign.
  - **SentinelAI Phase 13 Ablation:** Forcing Infiltration recall to 24%–50% caused Benign FPR to surge to 0.51%–8.59%, catastrophically breaching Criterion A1.
- **Current Verdict:** **FAIL / BLOCKED ON OWNER DECISION 3**.
- **Evidence Limitations:**
  - Infiltration in CSE-CIC-IDS2018 consists of user-mode compromise followed by C2 beaconing and internal port scanning. The vast majority of flows exhibit standard desktop TCP/IP mechanics that overlap visually and statistically with benign traffic in transport flow space.
- **Required Next Action:**
  - Present **Owner Decision 3**: Retain 70% recall on tabular flow features (which conflicts with Criterion A1 FPR $\le 0.100\%$) OR formally decouple Infiltration acceptance from tabular flow ML and re-scope to endpoint/EDR event telemetry (process execution trees, abnormal SMB/RPC bindings).
- **Owner Approval Required:** **YES (Owner-Only Decision per Contract Section 7 & 8)**.

---

### Criterion E4: Layer 7 WAF Real Traffic Verification

- **Target Specification:** Layer 7 Web Application Firewall detection of OWASP Top 10 web injection vectors (SQLi, XSS, Path Traversal) evaluated against realistic, authentic HTTP traffic streams.
- **Existing Primary Evidence:**
  - WAF module and signature filters implemented in `ai-engine/modular/`.
  - 40 tests in `test_auth_and_waf_detectors.py` pass successfully.
- **Current Verdict:** **PARTIALLY CONFIRMED / UNVERIFIED on Real Traffic**.
- **Evidence Limitations:**
  - All current test cases evaluate synthetic or hardcoded string fixtures.
  - Contract Section 2 strictly mandates: *"Synthetic replay is never real-traffic evidence."*
- **Required Next Action:**
  - Obtain an authentic, non-synthetic HTTP traffic benchmark (e.g. CSIC 2010 or ModSecurity CRS test suite).
  - Evaluate Layer 7 WAF performance against authentic HTTP request streams.
- **Owner Approval Required:** **NO**.

---

### Criterion F1: AI Engine Automated Test Suite

- **Target Specification:** 100% passing test execution across all unit, integration, and safety tests in `ai-engine/tests/`.
- **Existing Primary Evidence:**
  - Verified in Phase 12: **285 passed, 0 failed, 0 errors** across 19 test modules (`metrics.json` lines 74–100).
- **Current Verdict:** **PASS (Engineering)**.
- **Evidence Limitations:** Tests verify code logic, regression boundaries, and safety invariants; unit tests passing does not constitute detector acceptance per Contract Section 3.
- **Required Next Action:** Maintain 100% test pass rate with isolated fixtures during remediation phases.
- **Owner Approval Required:** **NO**.

---

### Criterion F2: Backend Automated Test Suite

- **Target Specification:** 100% passing test execution across all backend Jest test suites.
- **Existing Primary Evidence:**
  - Verified in Phase 12: **512 passed, 13 skipped, 0 failed** out of 525 tests (`metrics.json` lines 68–73).
- **Current Verdict:** **PASS (Engineering)**.
- **Evidence Limitations:** Backend tests run against mocked AI engine endpoints.
- **Required Next Action:** Maintain regression suite pass rate.
- **Owner Approval Required:** **NO**.

---

### Criterion F3: Windows Firewall Safety Gate

- **Target Specification:** Absolute prohibition against mutating real Windows Firewall rules or executing live containment during development and acceptance testing; enforcement flags must remain strictly disabled.
- **Existing Primary Evidence:**
  - Statically verified in `ai-engine/modular/contracts.py` lines 91–97: raises `ValueError("Safety Violation: Real firewall containment cannot be enabled in this milestone.")` if `simulated` is false.
  - Verified in `backend/adapters/WindowsFirewallAdapter.js` and `adapterFactory.js`: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` defaults strictly to `MockContainmentAdapter`.
  - Verified in `ai-engine/modular/orchestrator.py`: `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS` defaults to `false`.
  - Verified dynamically in `test_modular_scaffold.py` and `integrated_backend_safety_regression.test.js`.
- **Current Verdict:** **PASS (SAFE)**.
- **Evidence Limitations:** None. Safety boundaries are hardcoded and verified.
- **Required Next Action:** Maintain all safety flags disabled across all future experimental runs.
- **Owner Approval Required:** **NO**.

---

### Supplementary Standard: Credential Stuffing Recall

- **Target Specification:** Status of the `"Credential Stuffing >= 80%"` target noted in Phase 12.
- **Existing Primary Evidence:**
  - Contract Section 6 records:
    > *"Credential Stuffing >=80% appeared in Phase 12 with no documented source: treat it as an OWNER DECISION, not a criterion, unless a source is found."*
  - In `features.py`, `"FTP-Patator"` and `"Web Attack Brute Force"` are synthesized into `"Credential Stuffing"`.
  - Candidate V2 achieved **49.72% recall** (1,243 / 2,500) in Phase 13.
  - Candidate V3 achieved **100.0% recall** (2,500 / 2,500), 95% Wilson CI [99.85%, 100.0%] in Phase 13.
- **Current Verdict:** **PENDING OWNER CONFIRMATION (Owner Decision 4)**.
- **Evidence Limitations:** Synthesized label aggregation; not present in original CSE-CIC-IDS2018 or CICIDS2017 labels under this name.
- **Required Next Action:**
  - Owner to formally confirm whether Credential Stuffing $\ge 80\%$ is an official GATE-1 acceptance criterion or a supplementary diagnostic metric.
- **Owner Approval Required:** **YES (Owner Decision 4)**.
