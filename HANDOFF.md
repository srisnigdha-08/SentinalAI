# SENTINELAI GATE-1 — PHASE 14.1 HANDOFF REPORT

**Date:** October 18, 2026  
**Phase:** Phase 14.1 — Independent Evidence Adjudication  
**Repository Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Active Git Branch:** `feature/gate1-phase9c-modular-scaffold` (Verified; zero branch switching or resetting performed)  
**Git HEAD Commit:** `bfff31dc352e142ad0aae448148121d3e91f98de`  
**Phase Run Directory:** `ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/`  
**Master Gate Verdict:** **FAIL — GATE-1 REMAINS OPEN** (Phase 14.1 Read-Only Evidence Adjudication complete; strictly stopped for owner review)

---

## 1. Executive Summary & Verification Highlights

Phase 14.1 performed an independent, strictly read-only evidence adjudication of all root-cause findings, source code paths, data artifacts, and reference methods established in Phase 14. In compliance with the non-negotiable safety rules:
- Zero model training was executed.
- Zero burned test sets were re-evaluated.
- Zero protected assets were modified.
- All safety flags remained disabled.

### Key Adjudication Findings:
1. **Time-Feature Leakage Trace:**
   - Traced `time_of_day_sin`, `time_of_day_cos`, and `datetime.now()` through training, validation, schema, runtime extraction, and inference.
   - **CONFIRMED:** The production model currently loaded at runtime (`rf_classifier_cicids_v2.pkl`, 53 features) is directly impacted by server wall-clock time fallback in `compute_time_of_day(None)`.
   - **NECESSARY BUT NOT SUFFICIENT:** Removing time features reduced adversarial validation AUC dramatically (SSH: 1.0 $\to$ 0.59, Malware: 1.0 $\to$ 0.57, Benign: 0.76 $\to$ 0.58), but residual shift remains in DDoS (0.7466) and Infiltration (0.6336) due to capture-session variance and packet dynamics. Multi-corpus pooling and time-gap block splitting are additionally required.
2. **Infiltration Claim Adjudication:**
   - Adjudicated Ref 3's t-SNE evidence (`evaluation.ipynb` Cell 18) and SentinelAI Phase 13 ablation.
   - **CONFIRMED:** Visual overlap in 2D t-SNE, poor separability for tested models (XGBoost misclassified 74.96% of 24,290 Infiltration flows as Benign), and empirical FPR/recall trade-off (forcing recall to 24%–50% spikes Benign FPR to 0.51%–8.59%).
   - **UNVERIFIED / HYPOTHESIS:** The claim of "mathematical inseparability". 2D t-SNE is a local distance projection and does not prove topological or Bayes-optimal inseparability in $\mathbb{R}^{51}$. Required permitted validation evidence includes validation ROC/PR curves, feature importance breakdown, and EDR/periodicity adapter evaluation.
3. **Heartbleed (Class 5) Adjudication:**
   - Verified that Heartbleed is **CVE-2014-0160 (Information Disclosure)**, not RCE, with **exactly 11 flows total** across all corpora (11 in CIC-IDS2017 Wednesday; 0 in CSE-CIC-IDS2018).
   - Proven that statistical generalization on $N = 3$ test samples is mathematically impossible (1 error swings recall by 33.3%; Wilson 95% CI width is 56.15%).
   - Strictly enforced Contract Section 7: Class 5 cannot be silently dropped or replaced without an approved architecture and acceptance amendment. Awaiting **Owner Decision 2**.
4. **Q-Table Incident Forensic Reconstruction:**
   - Reconstructed exact execution path: `test_readiness.py` line 104 pointed `Q_TABLE_PATH` at seed; `deception.py` lines 27–29 redirected it to the real file `runtime/q_table.json`; the test set `episode_count = 99` and called `deception.save_scorer()`, directly overwriting the repository file on disk at `2026-10-17T20:41:04.822130+00:00`.
   - Verified that current `conftest.py` autouse fixture protects pytest runs, but standalone Python scripts outside pytest remain unisolated if `DEFAULT_RUNTIME_Q_TABLE_PATH` is unset.
   - Structured options for **Owner Decision 1** (Restore pre-Phase-12 baseline `5242A649...` vs formal Re-baseline to `08209E99...`).
5. **Proposed FPR Calibration Procedure Verification:**
   - Audited Ref 3's `calibrate_thresholds` and `predict_calibrated`.
   - Identified that independent per-class F1 grid searching allows false positives across classes to accumulate, violating Criterion A1 ($\le 0.100\%$).
   - Formulated a joint multi-class constrained calibration procedure on permitted validation data with a $\le 0.070\%$ validation ceiling to provide necessary headroom against test-set sampling variance, falling back to Benign rather than attack argmax.
6. **Authoritative Acceptance Criteria Mapping:**
   - Mapped all 14 official criteria (A1–F3) and Credential Stuffing to primary evidence, verdicts, limitations, and owner decisions.

---

## 2. Protected Assets SHA-256 Audit

Computed and verified; recorded in `raw_logs/protected_asset_hashes.txt`:

| Protected Artifact | Size (bytes) | Expected SHA-256 (Contract) | Current SHA-256 | Status | Drift |
|---|---|---|---|---|---|
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | 46,234,119 | `CA0EFB1F...60023F1` | `CA0EFB1F...60023F1` | **MATCH** | False |
| `ai-engine/models/isolation_forest_cicids.pkl` | 1,429,757 | `17BD08FF...94E19DA4` | `17BD08FF...94E19DA4` | **MATCH** | False |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | 3,623,754 | `A5D630B4...0A7D210D` | `A5D630B4...0A7D210D` | **MATCH** | False |
| `ai-engine/models/q_table.json` (Seed) | 2,338 | `BF9B46A1...98990FF` | `BF9B46A1...98990FF` | **MATCH** | False |
| `ai-engine/runtime/q_table.json` (Runtime) | 1,224 | `5242A649...0F326E6` | `08209E99...379152F7` | **INCIDENT STATE** | **False (0 drift)** |
| `candidate_rf_multicorpus_v1.pkl` | 5,850,914 | `71A1756E...31952020` | `71A1756E...31952020` | **MATCH** | False |
| `candidate_rf_multicorpus_v2_fixed.pkl` | 9,290,458 | `F83C1F87...8354C2` | `F83C1F87...8354C2` | **MATCH** | False |

Zero drift occurred across all protected assets.

---

## 3. Operational Safety Flags Status

- `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS`: Verified `false` in `ai-engine/modular/orchestrator.py`.
- `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`: Verified `false` in `backend/adapters/WindowsFirewallAdapter.js` and `adapterFactory.js`.
- Autonomous Containment: Verified strictly governed by `CONTAINMENT_BACKEND` (`'mock'`) and `SimulatedMitigation(simulated=True)` in `contracts.py`.
- Test Isolation: Verified active in `ai-engine/tests/conftest.py`.

---

## 4. Owner-Only Decisions List

The following decisions require owner instruction per Contract Sections 7 & 8:

1. **Owner Decision 1: Runtime Q-Table Disposition**
   - **Option A (Recommended):** Restore `ai-engine/runtime/q_table.json` from git commit `bfff31d` (pre-Phase-12 state) where SHA-256 matches `5242A6496FA3E8EB00B101E9C3C24F354FDB849A1C5042686E207384B0F326E6`.
   - **Option B:** Formally re-baseline to the current SHA-256 `08209E99...` with documentation that prior Q-values were reset.
2. **Owner Decision 2: Criterion C2 & Class 5 (Heartbleed) Scope**
   - **Option A:** Retain Class 5 as mandatory in tabular ML (requires finding external authentic data; currently impossible with $N=11$).
   - **Option B (Recommended):** Formally re-scope Criterion C2 to 9 classes for the statistical tabular flow classifier, delegating Heartbleed to Layer 7 TLS heartbeat length inspection.
3. **Owner Decision 3: Criterion E3 (Infiltration / Lateral Movement) Scope**
   - **Option A:** Retain 70% recall on tabular flow features (mathematically conflicts with Criterion A1 FPR $\le 0.100\%$).
   - **Option B (Recommended):** Decouple Infiltration acceptance from tabular flow ML; re-scope acceptance to endpoint/EDR event telemetry (process tree anomalies, unauthorized SMB/RPC bindings).
4. **Owner Decision 4: Credential Stuffing Acceptance Standard**
   - Formally confirm whether Credential Stuffing $\ge 80\%$ is an official GATE-1 acceptance criterion or a supplementary diagnostic metric.

---

## 5. Deliverables Created in Phase 14.1

- Evidence Directory: [`ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/)
  - [`HANDOFF.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/HANDOFF.md)
  - [`evidence_adjudication_matrix.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/evidence_adjudication_matrix.md)
  - [`q_table_incident_review.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/q_table_incident_review.md)
  - [`acceptance_criteria_mapping.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_1_evidence_adjudication_20261018-0407/acceptance_criteria_mapping.md)
  - `raw_logs/protected_asset_hashes.txt`
  - `raw_logs/git_status.txt`
  - `raw_logs/model_feature_inspection.txt`
- Root [`HANDOFF.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/HANDOFF.md) (Synchronized)

---

## 6. Mandatory Stop Notice

Per Section 1, 6, and 10 of the instruction:
- Phase 14.1 is strictly **READ-ONLY**.
- No models were trained.
- No burned test sets were evaluated.
- No candidate model was generated.
- GATE-1 remains **OPEN**.
- **Execution is halted. Awaiting owner review and decision intake before Phase 2.**
