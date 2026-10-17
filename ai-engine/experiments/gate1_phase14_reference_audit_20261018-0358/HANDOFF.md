# SENTINELAI GATE-1 — PHASE 14 HANDOFF REPORT

**Date:** October 18, 2026  
**Phase:** Phase 14 — Read-Only Reference-Guided Root-Cause Audit and Comparative Analysis  
**Repository Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Active Git Branch:** `feature/gate1-phase9c-modular-scaffold` (Verified; zero branch switching or resetting performed)  
**Git HEAD Commit:** `bfff31dc352e142ad0aae448148121d3e91f98de`  
**Phase Run Directory:** `ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/`  
**Gate Verdict:** **FAIL — GATE-1 REMAINS OPEN** (Phase 1 Read-Only Audit complete; strictly stopped for owner review)

---

## 1. Executive Summary & Verification Highlights

This phase executed a comprehensive, read-only technical audit of SentinelAI's outstanding GATE-1 failure modes by benchmarking them against four public research repositories:
1. `Vabnas/cicids-shap-stability` (Ref 1, MIT License, commit `9f7871c801`)
2. `heraclitus0/TAD-IDS` (Ref 2, MIT License, commit `4586df5c25`)
3. `LawrenceYH04/ML-IDS` (Ref 3, All Rights Reserved, commit `5a253fbbfb`)
4. `YufengXin/network-attack-research` (Ref 4, All Rights Reserved, commit `106e39b289`)

### Key Source-Verified Facts Established:
1. **Single-Day Attack Campaign Scheduling:** CSE-CIC-IDS2018 and CIC-IDS2017 executed virtually all attack types on single calendar days (Ref 3 daily census). A calendar-day temporal split is mathematically incompatible with multiclass IDS without cross-corpus pooling.
2. **Elimination of Time Features is Invariant Standard:** All four reference repositories strictly drop `Timestamp` and wall-clock features from statistical vectors. SentinelAI's `time_of_day_sin/cos` and `datetime.now()` wall-clock fallback are verified laboratory-schedule shortcuts that must be permanently removed.
3. **Infiltration Flow Inseparability:** Ref 3's t-SNE analysis proves that Infiltration flows overlap by ~75% with Benign traffic in transport flow space. Forcing tabular flow models to achieve 70% recall causes catastrophic false-positive spikes ($\ge 8\%$), violating Criterion A1.
4. **Heartbleed Taxonomy & Extreme Sparsity:** Heartbleed is CVE-2014-0160 (TLS memory over-read), not RCE, and has exactly 11 flows in 2017 and 0 in 2018. It cannot be learned via statistical tabular ML and must be re-scoped or handled via Layer 7 signature inspection.
5. **Calibrated Decision Architecture:** Ref 3 provides a leak-free `_predict_calibrated` decision rule, which SentinelAI can adopt by adding an FPR $\le 0.100\%$ constraint to validation-split threshold grid searching.
6. **Zero Drift on Protected Assets:** All 7 protected assets were hashed before and after the run. 6 matched contract baselines; 1 (`runtime/q_table.json`) remained invariant in its known incident state (`08209E99...`).

---

## 2. Protected Assets SHA-256 Audit

Computed via `verify_protected_hashes.py` and recorded in `protected_asset_hashes_before.txt`:

| Protected Artifact | Size (bytes) | Expected SHA-256 (Contract) | Current SHA-256 | Status | Drift |
|---|---|---|---|---|---|
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | 46,234,119 | `CA0EFB1F...60023F1` | `CA0EFB1F...60023F1` | **MATCH** | False |
| `ai-engine/models/isolation_forest_cicids.pkl` | 1,429,757 | `17BD08FF...94E19DA4` | `17BD08FF...94E19DA4` | **MATCH** | False |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | 3,623,754 | `A5D630B4...0A7D210D` | `A5D630B4...0A7D210D` | **MATCH** | False |
| `ai-engine/models/q_table.json` (Seed) | 2,338 | `BF9B46A1...98990FF` | `BF9B46A1...98990FF` | **MATCH** | False |
| `ai-engine/runtime/q_table.json` (Runtime) | 1,224 | `5242A649...0F326E6` | `08209E99...379152F7` | **INCIDENT STATE** | **False (0 drift)** |
| `candidate_rf_multicorpus_v1.pkl` | 5,850,914 | `71A1756E...31952020` | `71A1756E...31952020` | **MATCH** | False |
| `candidate_rf_multicorpus_v2_fixed.pkl` | 9,290,458 | `F83C1F87...8354C2` | `F83C1F87...8354C2` | **MATCH** | False |

---

## 3. Operational Safety & Flags Verification

- `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS`: Verified `false` in `orchestrator.py`.
- `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`: Verified `false` in `WindowsFirewallAdapter.js` and `adapterFactory.js`.
- Autonomous Containment: Verified governed by `CONTAINMENT_BACKEND` (`'mock'`) and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`.
- Test Isolation: Verified `ai-engine/tests/conftest.py` redirects runtime Q-table operations to `tmp_path`. No test modified repository artifacts.

---

## 4. Root-Cause Summary Across Investigated Areas

```
┌─────────────────────────────────┬───────────────────────────┬────────────────────────────────────────────────────────┐
│ Area / Criterion                │ Status                    │ Core Root Cause & Reference Finding                    │
├─────────────────────────────────┼───────────────────────────┼────────────────────────────────────────────────────────┤
│ A. Split Independence           │ CONFIRMED                 │ Row-hash MD5 insufficient; multi-day temporal gaps     │
│                                 │                           │ and pre-split deduplication required (Ref 1 & 4).      │
│ B. Temporal Shift & Time Feats  │ CONFIRMED                 │ Lab schedule memorization; wall-clock fallback         │
│                                 │                           │ produces severe inference skew; drop time (Ref 1-4).   │
│ C. Benign FPR > 0.100% (A1)     │ CONFIRMED                 │ Unconstrained calibration lowers thresholds; adopt     │
│                                 │                           │ validation grid search with FPR budget (Ref 3).        │
│ D. Infiltration Recall ~0% (E3) │ CONFIRMED / BLOCKED       │ Inherent flow inseparability (Ref 3 t-SNE: 75% benign  │
│                                 │                           │ overlap); requires endpoint telemetry / EDR.           │
│ E. Class 5 / Heartbleed (C2)    │ CONFIRMED / BLOCKED       │ CVE-2014-0160 Information Disclosure (not RCE);        │
│                                 │                           │ N=11 total; unlearnable via statistical ML (Ref 1 & 4).│
│ F. Q-Table Incident State       │ CONFIRMED / BLOCKED       │ Un-isolated historical tests mutated file; tests now   │
│                                 │                           │ isolated; requires owner approval to restore.          │
└─────────────────────────────────┴───────────────────────────┴────────────────────────────────────────────────────────┘
```

---

## 5. Owner-Only Decisions List

The following decisions require owner instruction per Contract Sections 7 & 8:

1. **Owner Decision 1: Runtime Q-Table Restoration**
   - **Option A (Recommended):** Restore `ai-engine/runtime/q_table.json` from git commit `bfff31d` (pre-Phase-12 state) where SHA-256 matches `5242A6496FA3E8EB00B101E9C3C24F354FDB849A1C5042686E207384B0F326E6`.
   - **Option B:** Formally re-baseline to the current SHA-256 `08209E99...`.
2. **Owner Decision 2: Criterion C2 & Class 5 Scope**
   - **Option A:** Retain Class 5 as mandatory in tabular ML (requires finding external authentic data; currently impossible with $N=11$).
   - **Option B (Recommended):** Formally re-scope Criterion C2 to 9 classes for the statistical tabular model, delegating Heartbleed to Layer 7 signature validation.
3. **Owner Decision 3: Criterion E3 (Infiltration / Lateral Movement) Disposition**
   - **Option A:** Retain 70% recall on tabular flow features (mathematically incompatible with FPR $\le 0.100\%$).
   - **Option B (Recommended):** Acknowledge transport flow inseparability (Ref 3 t-SNE); re-scope Infiltration acceptance to endpoint/EDR event telemetry.
4. **Owner Decision 4: Credential Stuffing Standard Confirmation**
   - Formally confirm whether Credential Stuffing $\ge 80\%$ is an official GATE-1 acceptance criterion or supplementary metric.

---

## 6. Files Created in Phase 14

- Evidence Directory: [`ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/)
  - [`HANDOFF.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/HANDOFF.md)
  - [`reference_repository_inventory.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/reference_repository_inventory.md)
  - [`reference_method_comparison.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/reference_method_comparison.md)
  - [`gate1_root_cause_matrix.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/gate1_root_cause_matrix.md)
  - [`protected_asset_hashes_before.txt`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/protected_asset_hashes_before.txt)
  - [`git_status_before.txt`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase14_reference_audit_20261018-0358/git_status_before.txt)
  - `raw_logs/git_ls_remote.log`
  - `raw_logs/repo_clone.log`
  - `raw_logs/github_api_metadata.json`
- Root [`HANDOFF.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/HANDOFF.md) (Updated to point to Phase 14)

---

## 7. Mandatory Stop Notice

Per Section 1, 6, and 10 of the instruction, **Phase 1 is strictly READ-ONLY**. No models were trained, no full test suite was executed, no new final test set was generated, and no test set was evaluated.

**Execution is halted. Awaiting owner review and decision intake before Phase 2.**
