# SENTINELAI — PHASE 2.1 CLAIM VERIFICATION

**Verification Timestamp:** 2026-10-18T12:55:00+05:30  
**Phase:** Phase 2.2 — Demonstration-Path Verification  
**Auditor:** Senior Security & ML Verification Engineer  
**Repository:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  

---

## 1. Summary of Claim Adjudication

| Claim | Verified Aspect | Adjudication Status | Evidence Reference |
| :--- | :--- | :--- | :--- |
| **Claim 1** | Deterministic missing-timestamp fallback to `(0.0, 0.0)` | **CONFIRMED** | `test_features.py::test_time_of_day_none_timestamp_deterministic_fallback`<br>Smoke test Sample 1: `f51=0.0, f52=0.0` |
| **Claim 2** | Equivalent instants represented as epoch, UTC ISO, offset ISO | **CONFIRMED** | `test_features.py::test_time_of_day_utc_consistency`<br>Verified: `1500000000.0`, `'2017-07-14T02:40:00Z'`, `'2017-07-14T08:10:00+05:30'` yield identical coordinates |
| **Claim 3** | Repeated-record feature-vector determinism (no clock drift) | **CONFIRMED** | `test_features.py::test_features_repeated_record_idempotency`<br>`np.testing.assert_array_equal(vec1, vec2)` passes |
| **Claim 4** | Production Random Forest feature importance and prediction invariance | **CONFIRMED** | Inspection of `rf_classifier_cicids_v2.pkl`: `fi[51]=0.00000000`, `fi[52]=0.00000000`<br>Prediction ThreatScore delta $\Delta p = 0.000000$ |
| **Claim 5** | Candidate-model invariance without retraining | **PARTIALLY CONFIRMED / LIMITATION FOUND** | See Section 2 below: Invariance holds for `xgb_classifier_cicids_v2.pkl`, but FAILS for legacy candidate models and multicorpus candidate |
| **Claim 6** | 53-feature vector schema, naming, and order | **CONFIRMED** | `test_features.py::test_features_vector_schema_and_order_invariance`<br>`len(FEATURE_NAMES) == 53`, `sin` at 51, `cos` at 52 |
| **Claim 7** | Q-table write protection and test isolation | **CONFIRMED** | 21 passing tests in `test_q_table_safety.py`<br>Zero byte mutation across smoke test execution |

---

## 2. In-Depth Audit of Candidate Models & Generalization Limits

The previous audit cautioned against generalizing production Random Forest results to candidate models. Direct forensic inspection of all model binaries in `models/` and `experiments/` reveals the following:

### Model Feature Importance Inspection Matrix

```
ai-engine/models/rf_classifier_cicids_v2.pkl (Production RF):
  Step: ['scaler', 'rf']
  Features: 53
  Feature 51 (time_of_day_sin): 0.00000000
  Feature 52 (time_of_day_cos): 0.00000000
  Prediction Invariance: 100% CONFIRMED

ai-engine/models/rf_classifier_cicids.pkl (Earlier CICIDS RF):
  Step: ['scaler', 'rf']
  Features: 53
  Feature 51 (time_of_day_sin): 0.00000000
  Feature 52 (time_of_day_cos): 0.00000000
  Prediction Invariance: 100% CONFIRMED

ai-engine/models/xgb_classifier_cicids_v2.pkl (Candidate XGBoost v2):
  Step: ['scaler', 'xgb']
  Features: 53
  Feature 51 (time_of_day_sin): 0.00000000
  Feature 52 (time_of_day_cos): 0.00000000
  Prediction Invariance: 100% CONFIRMED

ai-engine/models/xgb_classifier_cicids.pkl (Candidate XGBoost v1):
  Step: ['scaler', 'xgb']
  Features: 53
  Feature 51 (time_of_day_sin): 0.00000000
  Feature 52 (time_of_day_cos): 0.00000000
  Prediction Invariance: 100% CONFIRMED

ai-engine/models/rf_classifier_v2.1.pkl (Legacy Candidate RF):
  Step: ['scaler', 'rf']
  Features: 53
  Feature 51 (time_of_day_sin): 0.01121848
  Feature 52 (time_of_day_cos): 0.01375460
  Prediction Invariance: FAILS (Model is sensitive to timestamp features!)

ai-engine/models/xgb_classifier.pkl (Legacy Candidate XGBoost):
  Step: ['scaler', 'xgb']
  Features: 53
  Feature 51 (time_of_day_sin): 0.00541366
  Feature 52 (time_of_day_cos): 0.00564090
  Prediction Invariance: FAILS (Model is sensitive to timestamp features!)

ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl (Phase 8 Multicorpus Candidate):
  Step: ['scaler', 'rf']
  Features: 51 (IndexError on feature 51/52!)
  Serialization Format: scikit-learn 1.7.2 (incompatible with environment's scikit-learn 1.4.0)
  Status: BROKEN / UNUSABLE IN RUNTIME
```

### Forensic Finding on Generalization
- **Finding:** `CONFIRMED`.
- The claim that feature importances for `time_of_day_sin` and `time_of_day_cos` are `0.000000` is **strictly true** for the CICIDS2017 models (`rf_classifier_cicids_v2.pkl`, `rf_classifier_cicids.pkl`, `xgb_classifier_cicids_v2.pkl`, and `xgb_classifier_cicids.pkl`).
- However, for earlier legacy models (`rf_classifier_v2.1.pkl` and `xgb_classifier.pkl`), time features were actively used by tree splits (importances ~0.5% to 1.4%).
- Furthermore, the Phase 8 multicorpus candidate model (`candidate_rf_multicorpus_v1.pkl`) completely omitted the time features, resulting in a **51-dimensional input shape** that throws an immediate `IndexError` when passed a 53-dimensional feature vector.
- **Rule Enforcement:** Under no circumstances should `candidate_rf_multicorpus_v1.pkl` or legacy models be selected or promoted into the runtime pipeline.
