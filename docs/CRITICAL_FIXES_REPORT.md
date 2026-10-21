# SentinelAI AI Engine — Critical Fixes Report (C1, C2)

Date: 2026-10-21, branch `db-fixes`. The issues are defined in `docs/AI_ENGINE_STUDY_GUIDE.md`, Phase 4.

| ID | Issue | Status | Where |
|---|---|---|---|
| **C1** | Every honeypot session was classified BENIGN by the served model | **Fixed** (commit `94124f0`) | `inference/predictor.py`, `utils/features.py`, backend honeypot labelling |
| **C2** | Headline metrics came from a duplicate-contaminated random split; the independent results were weaker and unreported | **Fixed in code and in the served model; the alert line was re-validated and raised to 0.90** (§2.6). The paper text still has to be edited by you (wording below) | `training/train.py`, `evaluation/day_holdout_eval.py`, new model `cicids_v3` |

---

## 1. C1 — Honeypot sessions classified BENIGN (fixed earlier today)

**Problem:**
- `predict_from_honeypot` fabricated a flow vector for each rule profile. The feature means came from the *synthetic* data generator.
- It then pushed that vector through the CICIDS-trained Random Forest.
- All six session types came back BENIGN, with scores of 0.08–0.11. That included failed logins, `wget`+`chmod`, `nmap` and `scp`, so the AI path never raised a threat for the honeypot.

**Fix:**
- The engine now returns the rule verdict directly (`classify_honeypot_session`), with a fixed score per class. No model runs on this path.

  | Class | Score |
  |---|---|
  | BENIGN | 0.40 |
  | Port Scan | 0.75 |
  | SSH Brute Force | 0.90 (was 0.86; raised with the alert line, §2.6) |
  | Lateral Movement | 0.90 |
  | RCE Attempt | 0.93 |
  | Data Exfiltration | 0.95 |

  Non-BENIGN classes get +0.01 per command, capped at 0.99.
- The response is labelled `classificationMethod: "honeypot_rules"`. The backend stores it as `modelType: "rules"`.

**Verification:**
- `tests/test_honeypot_rules.py` (17 tests).
- On the live engine, a failed login now returns `SSH Brute Force 0.90 MONITOR`.

---

## 2. C2 — Honest training and evaluation

### 2.1 What was wrong

- `training/train.py` split rows at random **without removing duplicates**.
  - In the training frame it builds, 23,481 of 148,015 rows (15.9%) were exact copies of another row.
  - 17.3% of test rows had an identical twin in train. For Port Scan it was 98.4%.
- The served artifact (`rf_classifier_cicids_v2.pkl`, August) could not be rebuilt from the current code. Its metadata did not record:
  - that it was trained with `--smote`;
  - its parameters, data hashes or git commit;
  - the extra class-10 dummy row.
- The only numbers anyone quoted (98.43% / 0.9862) came from that contaminated split.

### 2.2 Code changes

| File | Change |
|---|---|
| `ai-engine/training/train.py` | **`drop_duplicate_rows`** removes identical (features, label) rows before `train_test_split` and keeps the first copy. Feature vectors that carry two different labels are kept and counted. |
| | **`--version NAME`** writes `rf_classifier_NAME.pkl` / `isolation_forest_NAME.pkl` and refuses to overwrite an existing file, so old artifacts stay for rollback. |
| | **Metadata** now records the evaluation protocol (`independent_holdout: false`), the parameters, `smote`, the deduplication stats, the train/test class counts, and provenance (CLI args, git commit, Python/sklearn/numpy versions, SHA-256 of every input CSV). The IF metadata records its parameters, feature names and benign row count. |
| | Bug fixed on the way: `--synthetic` training had been failing since the M9 strict-column check, because the generator has no init-window/active/idle columns by design. The strict check now applies to real data only. |
| `ai-engine/evaluation/day_holdout_eval.py` | Files load Monday → Friday, and exact duplicates are dropped **keeping the earliest day's copy**. A held-out later day therefore never re-tests a flow already seen in training. `--no-dedupe` reproduces the old runs. |
| | The `deployed` protocol scores whatever `models/registry.json` serves instead of a hard-coded file name. |
| `ai-engine/evaluation/reproduce_reported_metrics.py` | The default still rebuilds the August split exactly (it reproduces 0.9843 / 0.9862 / 0.8448). `--deduplicated` uses the new split. The registered model is listed first. |
| `ai-engine/evaluation/evaluate_model.py` | `verify_model_metadata` reports the registered artifacts instead of a hard-coded `rf_classifier_cicids_v2.pkl`. |
| `scripts/ai_engine_endpoint_check.py` | Checks that `/model/info` serves the file pinned in `registry.json` instead of a hard-coded name. |

### 2.3 Retrained and registered model

Command (from `ai-engine/`):

```bash
.venv/Scripts/python.exe training/train.py --data datasets/cicids2017 --model-dir models --version cicids_v3
```
```bash
.venv/Scripts/python.exe training/register_model.py --classifier rf_classifier_cicids_v3.pkl --type rf --anomaly isolation_forest_cicids_v3.pkl
```

| | August model (`rf_classifier_cicids_v2`) | New model (`rf_classifier_cicids_v3`) |
|---|---|---|
| Recipe | StandardScaler + RF(200 trees, depth 20, balanced) + **SMOTE** (Beacon → 4,000, XSS → 1,500) + 1 dummy row | Same RF, **no SMOTE, no dummy row**. This is the same recipe that `day_holdout_eval.py` and `retrain_from_samples.py` evaluate, so one recipe now describes the served model |
| Training rows | 121,827 (incl. 3,414 synthetic) | 99,627 real, deduplicated |
| Classes | 0–10 (class 10 learned from one all-zero row) | 0–9 (Data Exfiltration has no real data, so it is not offered) |
| IsolationForest | 80,000 benign rows, `offset_` −0.474 | 74,682 benign rows, `offset_` −0.470. The −0.55 anomaly line is unchanged |
| sha256 | `ca0efb1f…` | `482d1fc6…` (classifier), `46b16b74…` (IF) |
| Rollback | — | The v2 files are untouched. Re-register them with `register_model.py --classifier rf_classifier_cicids_v2.pkl --anomaly isolation_forest_cicids.pkl` and call `POST /model/reload`. The previous registry is saved at `.test-runtime/registry.pre_v3.json` |

**What deduplication removed:**

| Scope | Duplicates removed |
|---|---|
| Training frame | 23,481 of 148,015 rows (15.9%); 33 vectors carry two labels |
| Full dataset (evaluation) | 628,877 of 2,827,876 rows (22.2%) |

| Class (full dataset) | Raw rows | Unique rows | Duplicates |
|---|---|---|---|
| **Port Scan** | 158,804 | **1,956** | **98.8%** |
| SSH Brute Force | 5,897 | 3,219 | 45% |
| Malware Beacon | 1,956 | 1,437 | 27% |
| Credential Stuffing | 9,442 | 7,401 | 22% |
| DDoS (all DoS tools) | 379,737 | 321,744 | 15% |
| BENIGN | 2,271,320 | 1,862,522 | 18% |

The "near-perfect Port Scan" result therefore came from about 2,000 distinct flows copied about 80 times each.

### 2.4 The numbers: before and after

All rows use the production threat score. **"Alerts"** means score ≥ 0.85 and a class other than BENIGN, which was the alert line when these were measured. The line is now 0.90; see §2.5–2.6 for rates at every line. **"Detect"** is the share of attack flows that raise one.

**A. Random 80/20 split as built by `train.py` (row-level; NOT an independent estimate)**

| | Accuracy | Weighted F1 | Macro F1 |
|---|---|---|---|
| August model, duplicates in the split (paper) | 0.9843 | 0.9862 | 0.8448 |
| New model, deduplicated split | 0.9847 | 0.9864 | 0.8419 |

The headline barely moves. The duplicates inflated *which* rows were easy (Port Scan) more than the overall average.

**B. Independent protocols (`day_holdout_eval.py`, same recipe retrained per protocol)**

| Protocol | Duplicates | Accuracy | Macro F1 | Alert benign FPR [95% CI] | Attack detect |
|---|---|---|---|---|---|
| Chronological per class (first 70% → train, 1% gap, last 29% → test) | kept (C1 run) | 0.9757 | 0.7390 | 0.073% | 87.8% |
| **Chronological per class** | **removed** | **0.9765** | **0.7497** | **0.331% [0.304%, 0.360%]** | **79.5%** |
| Leave-one-day-out (Tue / Wed / Thu / Fri held out) | removed | 0.69 / 0.66 / 0.93 / 0.84 | 0.19–0.30 | 0.02–0.16% | **0.0% / 0.3% / 0.4% / 0.4%** |

Both chronological rows are read at the same 0.85 line (from each run's threshold sweep). The committed C1 summary table used the older 0.70 line.

**Chronological per-class recall, deduplicated:**

| Class | Recall | Test rows |
|---|---|---|
| BENIGN | 0.99 | 160,000 |
| SSH Brute Force | 0.95 | 934 |
| Port Scan | 0.88 | 568 |
| DDoS | 0.88 | 20,000 |
| Credential Stuffing | 0.88 | 2,148 |
| Lateral Movement | 0.82 | 11 |
| Malware Beacon | 0.81 | 418 |
| RCE Attempt | 0.75 | 4 |
| XSS Attempt | 0.64 | 190 |
| SQL Injection | 0.29 | 7 |

Classes with fewer than 30 test rows are not statistically meaningful.

**What this means:**
1. On the deduplicated chronological test, which is the most honest single number for "known attack types, later traffic", the model detects **about 80% of attack flows**, with **macro F1 0.75**.
2. With duplicates in the data, the same protocol overstated detection by about 8 points and understated the benign alert rate by about 4.5×.
3. **Attacks the model has never seen are not detected.** Leave-one-day-out detection is ≤ 0.4%. This holds before and after the fix, and the Isolation Forest does not compensate (H5).

### 2.5 Threshold validation (deduplicated)

`day_holdout_eval.py --protocols threshold` (`experiments/c2_dedup_eval/threshold_validation/`) works without touching the test rows:
- It splits the chronological training portion again: fit 80%, validate 20%.
- It picks the lowest alert line whose benign alert rate on validation is ≤ 0.1%.
- Only then does it measure the test rows once.

| Line | Validation benign FPR | Test benign FPR [95% CI] | Test attack detection |
|---|---|---|---|
| 0.85 (previous `ALERT_THRESHOLD`) | 0.183% | **0.306%** [0.280%, 0.335%] | 79.6% |
| 0.88 | 0.123% | 0.198% | 78.9% |
| **0.90** (point rule: lowest line meeting the target on validation; **now the default**) | 0.097% | 0.154% [0.136%, 0.174%] | 78.6% |
| 0.91 (Wilson-bound rule) | ≤ 0.1% upper bound | 0.129% [0.113%, 0.148%] | 78.4% |
| 0.92 (current `BLOCK_THRESHOLD`) | 0.063% | 0.104% [0.089%, 0.121%] | 78.3% |
| 0.95 | 0.028% | 0.046% | 77.7% |

On deduplicated data, **the previous 0.85 alert line misses the project's 0.1% benign-alert target by about 3×.** It was chosen on the duplicate-inflated C1 split. Raising the line costs very little detection, because most attack flows score near 1.0: going from 0.85 to 0.92 loses 1.3 points of detection and cuts false alerts by about two thirds. As in C1, the rate on later traffic (test) is about 1.5× the validation rate, so a margin is needed.

### 2.6 Alert line raised to 0.90

**Done.** `ALERT_THRESHOLD` now defaults to **0.90**, the line the validation procedure selects. On later traffic it halves false alerts (0.306% → 0.154%) for 1 point of detection (79.6% → 78.6%).

| Where | Change |
|---|---|
| `ai-engine/inference/predictor.py` | `MONITOR_THRESHOLD` default 0.85 → **0.90**, with the evidence in the comment |
| `backend/services/aiEngineService.js` | `DEFAULT_ALERT_THRESHOLD` (used only until the first `/model/info` fetch) 0.85 → 0.9 |
| `ai-engine/.env.example`, `deployment/.env.compose.example`, `docker-compose.yml` | 0.85 → 0.90 |
| `HONEYPOT_RULE_SCORES` | SSH Brute Force 0.86 → **0.90**. Otherwise a failed honeypot login would drop to ALLOW and stop raising a threat. The other attack classes were already ≥ 0.90 |
| Tests | `test_model_evaluation` expects monitor 0.90. `test_abuseipdb_decoupling` puts its MONITOR case at 0.91 (between 0.90 and 0.92). `test_improvements` mock updated |
| Docs | README alerting paragraph, `IMPROVEMENTS_REPORT.md` (marked superseded), study guide |

Setting `ALERT_THRESHOLD` in an environment still overrides the default. The MONITOR band is now narrow (0.90–0.92), so most detected attacks land on the BLOCK line. Auto-block stays off unless an administrator enables `autoBlockEnabled`.

### 2.7 What the paper should now say (replace Table IV's sentence and abstract claim)

> The deployed Random Forest is trained on all eight CICIDS2017 MachineLearningCVE files after removing
> exact duplicate flows (22% of the dataset; 98.8% of PortScan rows). On a stratified random 80/20 split it
> reaches 98.47% accuracy, 0.986 weighted F1 and 0.842 macro F1. Because random row splits overstate
> performance on CICIDS2017, we also evaluate chronologically within each capture: macro F1 is 0.750 and,
> at the deployed alert threshold, 79.5% of attack flows raise an alert at a benign alert rate of 0.33%
> (95% CI 0.30–0.36%); the alert line re-selected on a validation split (0.90) gives 78.6% detection at
> 0.15%. When an entire capture day is held out, attacks from that day are essentially not
> detected (≤ 0.4%), so the classifier should be understood as a detector of known attack types rather
> than of novel attacks. SMOTE is not used in the deployed model; class imbalance is handled with balanced
> class weights.

Also fix the other contradictions listed in the study guide (H1): 53 features (not 46); 8 files (not 4); XGBoost trained on real data (0.9913 on the random split) but not deployed; no SGD learner in the code; 10 of 11 classes have real data, and Data Exfiltration has none.

### 2.8 Verification

| Check | Result |
|---|---|
| `tests/test_c2_honest_evaluation.py` (new, 5 tests) | Deduplication keeps first copies and counts label conflicts; no train/test identical rows after the split; the holdout keeps the earliest day; files load Monday → Friday; `--version` writes provenance and refuses to overwrite |
| Updated tests | `test_medium_fixes::test_shipped_registry_matches_shipped_models` (expects `rf_classifier_cicids_v3.pkl`); `test_model_evaluation::test_model_metadata_verification` (checks against the registry hashes instead of hard-coded ones) |
| `register_model.py --check` | classifier OK, anomaly OK |
| Full AI-engine pytest | **415 passed**, 0 failed (62.8 s) |
| Backend Jest | Not re-run: C2 changed no backend file. The last run, after C1, was 1025 passed / 13 skipped |
| Live engine (`scripts/ai_engine_endpoint_check.py`) | `/model/info` serves `rf_classifier_cicids_v3.pkl` + `isolation_forest_cicids_v3.pkl` (sha256 verified), metrics 0.9847 / 0.9864 / 0.8419. Real rows: 90% benign → BENIGN, 97% attacks → attack. Served vector = training vector for 110/110 rows. Honeypot: SSH Brute Force 0.86. **21/22 pass.** The one failure is the known CSV-header skew (H4, not in scope) |
| `reproduce_reported_metrics.py --deduplicated` | Test rows with an identical vector in train: **15 (0.1%)**, down from 5,135 (17.3%). The 15 are flows that carry a different label. Registered model: 0.9847 / 0.9864 / macro 0.8419; alert line 0.85 → benign 0.155%, detection 92.9%. The older artifacts score *higher* here only because they were trained on rows now in this test set |

### 2.9 Not done in this pass

- **Editing the paper.** The wording is above; the PDF is yours to change.
- **Re-evaluating XGBoost chronologically** (M-5 in the study guide). It may beat the RF, but `day_holdout_eval.fit` only builds RFs today.
- **Old artifacts.** `rf_classifier_cicids_v2.pkl`, the root `models/` copy and the other files listed in the study guide §1.5 are still on disk. They are no longer served; they remain for rollback and comparison.
