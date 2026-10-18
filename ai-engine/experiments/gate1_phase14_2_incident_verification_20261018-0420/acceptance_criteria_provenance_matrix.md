# SentinelAI GATE-1 — Phase 14.2: Acceptance Criteria Provenance & Authority Matrix

**Phase:** GATE-1 Phase 14.2 — Independent Incident Verification and Acceptance Contract Audit  
**Date:** October 18, 2026  
**Primary Authority:** [`GATE1_CONTRACT.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/GATE1_CONTRACT.md) Section 6 (Phase 11 Registry) & Authoritative Historical Documents  
**Adjudication Scope:** Complete tracing of all 14 official criteria (A1–F3) and Credential Stuffing to their authoritative origin, measurement method, primary evidence, current status, and amendment history.

---

## 1. Master Acceptance Criteria Provenance Matrix

```
┌──────┬───────────────────────────────────┬──────────────────────┬───────────────────────────────┬─────────────────────────┬──────────────────────┐
│ ID   │ Criterion Description             │ Authority & Origin   │ Required Target & Metric      │ Current Evidence Source │ Current Status       │
├──────┼───────────────────────────────────┼──────────────────────┼───────────────────────────────┼─────────────────────────┼──────────────────────┤
│ A1   │ Whole-Pipeline Benign FPR         │ Original Contract    │ FPR ≤ 0.100% (≤25 / 25k)      │ Phase 13 eval.json: 28  │ FAIL                 │
│ B1   │ Bounded Concurrency / Queue       │ Original (Phase 9B)  │ Bounded memory under load     │ Phase 12 metrics.json   │ PASS (Engineering)   │
│ B2   │ DDoS HOIC / LOIC Recall           │ Original Contract    │ Recall ≥ 80.0%                │ Phase 13 eval.json: 85% │ PASS (Burned) / UNVER│
│ C1   │ Pipeline Ingestion Integrity      │ Approved Amendment   │ Complete traversal, 21-Feb    │ test_data_pipeline.py   │ PASS (Engineering)   │
│ C2   │ Multiclass Coverage (10 Classes)  │ Original Contract    │ 10 classes covered in system  │ class5_audit.json: N=11 │ FAIL / BLOCKED (OD2) │
│ D1   │ Botnet Ares Recall                │ Original Contract    │ Recall ≥ 75.0%                │ Phase 13 eval.json: 94% │ PASS (Burned) / UNVER│
│ D2   │ Web Attacks Recall (SQLi / XSS)   │ Original Contract    │ Recall ≥ 80.0%                │ Phase 13 eval.json: 82% │ INCONCLUSIVE (N=52)  │
│ E1   │ SSH Brute Force Recall (Per-Flow) │ Original (Approved)  │ Per-flow Recall ≥ 80.0%       │ Phase 13 eval.json: 100%│ PASS (Burned) / UNVER│
│ E2   │ Authentication Event Adapter      │ Approved Amendment   │ Functional telemetry parsing  │ test_auth_waf.py (40/40)│ PASS (Engineering)   │
│ E3   │ Infiltration / Lateral Movement   │ Original Contract    │ Recall ≥ 70.0%                │ Phase 13 eval.json: 0.04│ FAIL / BLOCKED (OD3) │
│ E4   │ Layer 7 WAF Real Traffic          │ Approved (Phase 9B)  │ High-accuracy L7 inspection   │ test_auth_waf.py (synth)│ UNVERIFIED (Traffic) │
│ F1   │ ai-engine Test Suite              │ Original Release Gate│ 100% pass across all tests    │ Phase 12 metrics: 285/0 │ PASS (Engineering)   │
│ F2   │ backend Test Suite                │ Original Release Gate│ 100% pass across Jest suite   │ Phase 12 metrics: 512/0 │ PASS (Engineering)   │
│ F3   │ Windows Firewall Safety Gate      │ Original Safety Rule │ Zero live firewall mutations  │ contracts.py / mock adp │ PASS (SAFE)          │
├──────┼───────────────────────────────────┼──────────────────────┼───────────────────────────────┼─────────────────────────┼──────────────────────┤
│ SUPP │ Credential Stuffing Recall        │ Merely Proposed (P12)│ Status of ≥ 80.0% target      │ Phase 13 eval.json: 100%│ OWNER DECISION REQ   │
└──────┴───────────────────────────────────┴──────────────────────┴───────────────────────────────┴─────────────────────────┴──────────────────────┘
```

---

## 2. Detailed Provenance, Measurement Protocol & Evidence by Criterion

---

### Criterion A1: Whole-Pipeline Benign False-Positive Rate (FPR)
- **Authority & Origin:** **Original Inception Criterion**. Defined in early GATE-1 specifications and confirmed in [`GATE1_CONTRACT.md#L85`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/GATE1_CONTRACT.md#L85).
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 85.
- **Required Target & Measurement Method:**
  - $\text{FPR} = \frac{\text{False Positives}}{\text{Total Benign Test Flows}} \le 0.0010$ ($\le 0.100\%$).
  - Measured on an untouched, single-pass benign holdout of at least $N = 25,000$ flows ($\le 25$ false positives permitted).
  - Calculated across the entire end-to-end pipeline (including all modular filters and decision fallbacks).
- **Current Evidence & Provenance:**
  - Phase 12 Sealed Test: **26 FPs / 25,000 = 0.104% FPR** ([`gate1_phase12_evidence_repair/sealed_test_evaluation.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase12_evidence_repair/sealed_test_evaluation.json)).
  - Phase 13 Candidate V2: **30 FPs / 25,000 = 0.120% FPR**, 95% Wilson CI [0.0841%, 0.1713%] ([`final_acceptance_evaluation.json#L106`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L106)).
  - Phase 13 Candidate V3: **28 FPs / 25,000 = 0.112% FPR**, 95% Wilson CI [0.0775%, 0.1618%] ([`final_acceptance_evaluation.json#L17`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L17)).
- **Current Status:** **FAIL**.
- **Amendment History:** None. The 0.100% ceiling is an invariant contract requirement.

---

### Criterion B1: Bounded Concurrency / Queue Management
- **Authority & Origin:** **Original Architectural Requirement**. Formulated during Phase 9B modular scaffold design to prevent unhandled memory exhaustion under line-rate traffic bursts.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 85; [`docs/final-closure/master-execution-plan-and-issue-register.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/docs/final-closure/master-execution-plan-and-issue-register.md).
- **Required Target & Measurement Method:**
  - Bounded memory footprint under concurrent ingestion.
  - Zero dropped connections or worker process leaks during traffic surges.
  - Verification via memory-bounded queue assertions (`DestinationTargetAggregator` saturation limits).
- **Current Evidence & Provenance:**
  - 24 unit/integration tests in [`ai-engine/tests/test_volumetric_flood.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/tests/test_volumetric_flood.py) verify bounded aggregation.
  - Backend threat service worker pool tests in `backend/tests/` verify worker throttling and bounded asynchronous persistence.
- **Current Status:** **PASS (Engineering)**.
- **Amendment History:** None.

---

### Criterion B2: DDoS HOIC / LOIC Recall
- **Authority & Origin:** **Original Intrusion Detection Criterion**. Mandated in early release gates for high-volume denial-of-service mitigation.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 86.
- **Required Target & Measurement Method:**
  - $\text{Recall} = \frac{\text{True Positives}}{\text{Total DDoS Flows}} \ge 0.800$ ($\ge 80.0\%$).
  - Measured on a disjoint holdout of HOIC/LOIC flows.
  - Contract Section 5 requirement: Single-day HOIC traffic (`Wednesday-21-02-2018`) must be partitioned into time-contiguous blocks separated by a 30-minute blackout gap and labeled "same-day, not independent".
- **Current Evidence & Provenance:**
  - Phase 12 Candidate V2: 9.95% at $P \ge 0.70$; 27.4% at $P \ge 0.50$ (FAIL).
  - Phase 13 Candidate V3: **85.68% recall** (2,142 / 2,500), 95% Wilson CI [84.25%, 87.00%] ([`final_acceptance_evaluation.json#L42`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L42)).
- **Current Status:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Amendment History:** Shadow volumetric flood detector added as supplementary detector in Phase 9C/11.

---

### Criterion C1: Pipeline Integrity & Ingestion Traversal
- **Authority & Origin:** **Approved Historical Amendment**. Originated in Phase 9C/10 after the discovery of the chunk-loop premature termination bug and the omission of 21-Feb DDoS data during training ingestion. Formally codified in Phase 11.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, lines 86–87; [`ai-engine/experiments/gate1_phase10_detector_recovery/build_candidate_v2_fixed.py#L5-L11`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase10_detector_recovery/build_candidate_v2_fixed.py#L5-L11).
- **Required Target & Measurement Method:**
  - Ingestion pipeline must traverse all CSV chunks until quotas or EOF are reached without silent truncation.
  - Verification that 21-Feb HOIC/LOIC flows are ingested and available for training/evaluation.
- **Current Evidence & Provenance:**
  - 5 tests pass in [`ai-engine/tests/test_data_pipeline_integrity.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/tests/test_data_pipeline_integrity.py).
  - Traversal verified in `build_candidate_v2_fixed.py`.
- **Current Status:** **PASS (Engineering)**.
- **Amendment History:** Formally added to criteria registry in Phase 11.

---

### Criterion C2: Multiclass Coverage (10 Classes)
- **Authority & Origin:** **Original Core Requirement**. Mandated 10 distinct threat classifications in the ML schema.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 87; [`ai-engine/utils/features.py#L37-L41`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/utils/features.py#L37-L41).
- **Required Target & Measurement Method:**
  - Detection coverage across Classes 0 through 9: Benign (0), SSH (1), SQLi (2), PortScan (3), DDoS (4), RCE Attempt (5), XSS (6), Malware Beacon (7), Credential Stuffing (8), Lateral Movement (9).
- **Current Evidence & Provenance:**
  - Candidate V2 and V3 models contain only **9 classes** (`classes_ = [0, 1, 2, 3, 4, 6, 7, 8, 9]`). Class 5 is missing.
  - Audit confirms Heartbleed has only $N = 11$ flows total across all corpora ([`class5_heartbleed_audit.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/class5_heartbleed_audit.json)).
- **Current Status:** **FAIL / BLOCKED ON OWNER DECISION 2**.
- **Amendment History:** Contract Section 7 explicitly established that Class 5 cannot be silently dropped or remapped by engineering. Requires **Owner Decision 2** to formally re-scope tabular ML to 9 classes and assign Class 5 to Layer 7 signature inspection.

---

### Criterion D1: Botnet Ares Recall
- **Authority & Origin:** **Original Threat Detection Requirement**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 87.
- **Required Target & Measurement Method:**
  - $\text{Recall} = \frac{\text{True Positives}}{\text{Total Botnet Flows}} \ge 0.750$ ($\ge 75.0\%$).
  - Measured on a disjoint test partition of Botnet Ares flows (`Friday-02-03-2018`).
  - Contract Section 7 prohibits using a flat 0.50 threshold (which yielded 0.51% FPR); requires joint calibration.
- **Current Evidence & Provenance:**
  - Phase 12 Candidate V2: 42.85% at $P \ge 0.70$; 74.15% at $P \ge 0.50$ (FAIL).
  - Phase 13 Candidate V3: **94.72% recall** (2,368 / 2,500), 95% Wilson CI [93.77%, 95.53%] ([`final_acceptance_evaluation.json#L66`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L66)).
- **Current Status:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Amendment History:** Calibration requirement codified in Contract Section 7.

---

### Criterion D2: Web Attacks Recall (SQL Injection & XSS)
- **Authority & Origin:** **Original Threat Detection Requirement**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 88.
- **Required Target & Measurement Method:**
  - Recall on Web Application attacks $\ge 0.800$ ($\ge 80.0\%$).
- **Current Evidence & Provenance:**
  - Phase 12 Candidate V2: 0.0% recall (0 / 566 detected).
  - Phase 13 Candidate V3: **82.69% recall** (43 / 52 detected), but 95% Wilson CI is **[70.27%, 90.62%]** ([`final_acceptance_evaluation.json#L54-L60`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L54-L60)).
  - Per Contract Section 3, because the Wilson CI straddles the 80.0% target, the formal verdict is **INCONCLUSIVE**.
- **Current Status:** **INCONCLUSIVE (Statistical Sample Size) / ARCHITECTURAL DEFECT on Flow Features**.
- **Amendment History:** None. Recognized in Phase 9B that Layer 7 WAF is the structurally sound detector.

---

### Criterion E1: SSH Brute Force Recall (Official Per-Flow Standard)
- **Authority & Origin:** **Original Threat Detection Requirement with Owner Amendment**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 88; Section 7, line 99:
  > *"SSH per-flow recall is the official criterion; session-level is supplementary and only valid with real IPs/timestamps."*
- **Required Target & Measurement Method:**
  - Per-flow $\text{Recall} \ge 0.800$ ($\ge 80.0\%$) evaluated across all SSH connection flows (including teardowns).
- **Current Evidence & Provenance:**
  - Phase 12 Candidate V2: 50.80% recall at $P \ge 0.70$ (508 / 1,000 detected; 491 were 0-byte teardowns).
  - Phase 13 Candidate V2: **82.68% recall** (2,067 / 2,500 detected) (PASS).
  - Phase 13 Candidate V3: **100.0% recall** (2,500 / 2,500 detected), 95% Wilson CI [99.85%, 100.0%] ([`final_acceptance_evaluation.json#L30`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L30)).
- **Current Status:** **PASS on Candidate V3 (Burned Set) / UNVERIFIED on Fresh Set**.
- **Amendment History:** Owner approved per-flow as official in Contract Section 7.

---

### Criterion E2: Authentication Event Adapter
- **Authority & Origin:** **Approved Historical Amendment**. Introduced during Phase 9B modular decoupling to ingest Cowrie honeypot authentication logs without routing raw JSON through the tabular ML flow pipeline.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 89; [`ai-engine/modular/auth_event_adapter.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/auth_event_adapter.py).
- **Required Target & Measurement Method:**
  - Validated schema compliance, IP reputation decoupling, and event parsing from Cowrie JSON records.
- **Current Evidence & Provenance:**
  - 40 tests in [`ai-engine/tests/test_auth_and_waf_detectors.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/tests/test_auth_and_waf_detectors.py) and 8 tests in `test_cowrie_parser_contract.py` pass with 100% success.
- **Current Status:** **PASS (Engineering)**.
- **Amendment History:** Formally registered in Phase 11.

---

### Criterion E3: Infiltration / Lateral Movement Recall
- **Authority & Origin:** **Original Threat Detection Requirement**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 89.
- **Required Target & Measurement Method:**
  - $\text{Recall} \ge 0.700$ ($\ge 70.0\%$) on Infiltration traffic (`Thursday-01-03-2018`).
- **Current Evidence & Provenance:**
  - Phase 12 Candidate V2: 0.35% recall (7 / 2,000) (FAIL).
  - Phase 13 Candidate V3: **0.04% recall** (1 / 2,500 detected), 95% Wilson CI [0.007%, 0.226%] ([`final_acceptance_evaluation.json#L90`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L90)).
  - Ref 3 external benchmark: XGBoost misclassified **74.96%** (18,208 / 24,290) of Infiltration flows as Benign.
  - Phase 13 ablation: Forcing Infiltration recall on tabular flow features caused Benign FPR to surge to **0.51%–8.59%**, violating Criterion A1.
- **Current Status:** **FAIL / BLOCKED ON OWNER DECISION 3**.
- **Amendment History:** None to date. Requires **Owner Decision 3** to decouple Infiltration acceptance from tabular flow features and re-scope to endpoint/EDR event telemetry.

---

### Criterion E4: Layer 7 WAF Real Traffic Verification
- **Authority & Origin:** **Approved Historical Amendment**. Introduced in Phase 9B to provide structural web application exploit detection.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 89; [`ai-engine/modular/layer7_waf.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/layer7_waf.py).
- **Required Target & Measurement Method:**
  - Evaluation of SQLi, XSS, and command injection detection against authentic HTTP request streams.
  - Contract Section 2 constraint: *"Synthetic replay is never real-traffic evidence."*
- **Current Evidence & Provenance:**
  - Unit tests in `test_auth_and_waf_detectors.py` evaluate synthetic fixtures only.
- **Current Status:** **UNVERIFIED on Real Traffic**.
- **Amendment History:** Registered in Phase 11.

---

### Criterion F1: AI Engine Test Suite
- **Authority & Origin:** **Original Engineering Quality Gate**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 90.
- **Required Target & Measurement Method:**
  - 100% passing execution across all automated test modules in `ai-engine/tests/`.
- **Current Evidence & Provenance:**
  - Verified in Phase 12 `metrics.json`: **285 passed, 0 failed, 0 errors** across 19 modules.
- **Current Status:** **PASS (Engineering)**.
- **Amendment History:** None.

---

### Criterion F2: Backend Test Suite
- **Authority & Origin:** **Original Engineering Quality Gate**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, line 90.
- **Required Target & Measurement Method:**
  - 100% passing execution across all Jest backend suites.
- **Current Evidence & Provenance:**
  - Verified in Phase 12 `metrics.json`: **512 passed, 13 skipped, 0 failed** out of 525 tests.
- **Current Status:** **PASS (Engineering)**.
- **Amendment History:** None.

---

### Criterion F3: Windows Firewall Safety Gate
- **Authority & Origin:** **Original Non-Negotiable Operational Safety Invariant**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 2, lines 35–42; Section 6, line 90.
- **Required Target & Measurement Method:**
  - Absolute prohibition against modifying real Windows Firewall rules or executing live containment during testing.
  - Hardcoded runtime assertions must verify mock enforcement.
- **Current Evidence & Provenance:**
  - Verified in [`ai-engine/modular/contracts.py#L91-L97`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/contracts.py#L91-L97): `simulated=True` required; raises `ValueError` if false.
  - Verified in `backend/adapters/WindowsFirewallAdapter.js` and `adapterFactory.js`: `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`.
- **Current Status:** **PASS (SAFE)**.
- **Amendment History:** Invariant safety rule.

---

### Supplementary Standard: Credential Stuffing Recall
- **Authority & Origin:** **Merely Proposed in Phase 12 (UNVERIFIED SOURCE)**.
- **Exact Source in Repository:** `GATE1_CONTRACT.md` Section 6, lines 93–95:
  > *"Credential Stuffing >=80% appeared in Phase 12 with no documented source: treat it as an OWNER DECISION, not a criterion, unless a source is found."*
- **Required Target & Measurement Method:**
  - Status of $\ge 80.0\%$ target requires formal owner confirmation.
  - In `features.py`, `"FTP-Patator"` and `"Web Attack Brute Force"` were synthesized into `"Credential Stuffing"`.
- **Current Evidence & Provenance:**
  - Phase 13 Candidate V2: 49.72% recall (1,243 / 2,500) ([`final_acceptance_evaluation.json#L167`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L167)).
  - Phase 13 Candidate V3: **100.0% recall** (2,500 / 2,500), 95% Wilson CI [99.85%, 100.0%] ([`final_acceptance_evaluation.json#L78`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/final_acceptance_evaluation.json#L78)).
- **Current Status:** **OWNER DECISION REQUIRED (Owner Decision 4)**.
- **Amendment History:** Codified as requiring owner decision in Contract Section 6.
