# Network-flow ML generalisation (Rank 5)

How well does the deployed network-flow model `xgb_cicids_v1` work on traffic it has not seen? This page explains
what each available measurement does and does not show, how the frozen model is evaluated, and how to reproduce it.
The numbers below come from `audit/rank5_network_flow_generalisation/run_20261114T123741Z/` (the full report is
`RANK5_GENERALISATION_REPORT.md` in that folder).

## What 98.97 % means

98.97 % accuracy (macro F1 0.874) is the model's score on its own held-out 20 % of a **stratified random row
split** of its de-duplicated CICIDS2017 training pool (`models/xgb_classifier_xgb_cicids_v1_meta.json` records
`independent_holdout: false`). Flows from the same capture days and the same attack bursts sit on both sides of
such a split, so it measures **in-distribution** performance: it shows the model learned the training data's
patterns, not that it works on other days, networks or tools. Rank 5 reproduced it exactly (accuracy 0.989682,
macro F1 0.87384, 24,907 rows; all counts equal the model meta).

## The frozen model is never changed

The evaluator (`ai-engine/evaluation/rank5_generalisation.py`):
- verifies the classifier, Isolation Forest and golden-set SHA-256 against `models/registry.json` before and after;
- loads through `SentinelPredictor` (registry + golden-set check);
- scores with the served path: `prepare_features` and P5's `served_scores` (classifier + Isolation Forest +
  `combine_threat_score` + the Unknown/REVIEW override, at the served 0.90 / 0.92 lines). A sample of every file
  (2,100 rows in total) is also scored through `SentinelPredictor.predict(record)`, the production request path;
  0 mismatches.

Nothing is trained, fitted on evaluation data, saved into `models/`, promoted or loaded into the running engine. The
53-feature contract, class map, thresholds and score formula are untouched. Retraining is a separate decision with its
own protocol (`audit/ML_DEV_PROTOCOL_V4.md`).

## Three evaluation sets, never pooled

| Set | What it is | Independent? |
|---|---|---|
| **E1 random split** | the model's own held-out 20 %, rebuilt by P5's loader and refused unless every count equals the meta | No: same days and attack episodes |
| **E2 2017 unseen rows** | CICIDS2017 rows never sampled into the training pool, minus every row whose exact vector is in the pool (390,049 excluded) | No: same days and episodes. Only BENIGN, Port Scan and DDoS have unseen rows (every row of every other class was in the pool) |
| **E3 2018 development days** | every row of the six local CSE-CIC-IDS2018 development days (Feb–Mar 2018), labels mapped to the 11 served classes by `evaluation/taxonomies.py` | **Later and from another network**, never used to train this model or choose its lines; but used in earlier development of *other* candidates, so not a sealed holdout |

The four **protected 2018 days** (16-02, 20-02, 22-02, 28-02) are not on disk and were not opened
(`evaluation/protected_data.assert_permitted` on every path). They remain the registered one-shot external test,
which needs owner approval.

## Results

Attack-vs-benign at the served alert line (0.90), and multiclass on the argmax class:

| Set | Rows | Accuracy | Balanced acc. | Macro F1 | Attack recall @ alert | Benign FPR @ alert | ROC-AUC (attack) | Majority baseline acc. |
|---|---|---|---|---|---|---|---|---|
| E1 random split | 24,907 | 0.9897 | 0.8848 | 0.8738 | 0.9522 | 0.0023 | 0.9998 | 0.7496 |
| E2 2017 unseen rows | 2,289,812 | 0.9980 | 0.9826 | 0.9787 | 0.9958 | 0.0010 | 0.9999 | 0.8647 |
| E3 2018 development days | 5,549,447 | 0.7294 | 0.1273 | 0.1145 | **0.1498** | 0.0039 | **0.6546** | **0.7296** |

**On later traffic from another network the model is no better than always answering BENIGN** (accuracy 0.7294 vs
0.7296; balanced accuracy 0.127 vs 0.125). It catches 15 % of attack flows at the alert line. The de-duplicated
sensitivity (3,672,442 unique rows) and the subset without any vector seen in 2017 give the same picture.

Per class on E3 (support, recall): SSH brute force 187,589 / 0.000; DDoS 740,240 / 0.023; Malware Beacon (bot)
286,191 / 0.0001; Credential Stuffing (FTP and web brute force) 193,716 / 0.000 as a class, most predicted as Port
Scan (so still flagged as an attack); Lateral Movement (infiltration) 92,403 / 0.0002; SQL Injection 53 and XSS 151
(too few to be reliable, both 0). Per day the attack recall of the classifier decision ranges from 0 % (21-02 HOIC / LOIC-UDP DDoS, ROC-AUC 0.19;
23-02 web attacks; 02-03 bot) to 75 % (14-02 FTP/SSH brute force); 01-03 has a 6 % benign false-positive rate.

**Rare and missing classes.** Training rows: SQL Injection 17, RCE Attempt 9, Lateral Movement 29, Data Exfiltration
**0**. The model has not learned Data Exfiltration at all; results for the other three are not meaningful in any set.

## Leakage checks

| Check | Result |
|---|---|
| Training CSVs equal the hashes recorded in the model meta | PASS (8/8) |
| E1 split reproduces the meta counts | PASS |
| E1 test vectors also in training | 15 of 24,907 (conflicting-label vectors that de-duplication keeps) |
| E2 rows sharing a vector with the pool | excluded (390,049) |
| E3 rows sharing an exact vector with the 2017 pool | 12,693 of 5,549,447 (metrics without them unchanged) |
| E3 dated after every training day | PASS: 0 rows on or before 2017-07-07; 5 rows on 14-02 carry 1970 clock-artefact dates |
| Protected days opened | No |
| Anything fitted on evaluation data | No |
| Time-of-day features | constant 0 in training and every set (no timestamp passed) |
| 2018 files cut at the spreadsheet row limit | **Suspected** for 5 of 6 files (exactly 1,048,575 rows): later flows of those days are missing |
| Near-duplicates | not measured |

Assessment: **LIMITED**. No available set is both independent and unused in development.

## Drift diagnostics

Population Stability Index (10 reference-quantile bins) and two-sample Kolmogorov–Smirnov per feature, 2017 training
rows vs each 2018 day (20,000-row deterministic samples, all rows and benign rows). On every 2018 day 27–37 of the
53 features show a large PSI (≥ 0.25) over all rows, and 27–38 over benign rows alone (benign median KS 0.13–0.60), led by backward
packet length, header length and IAT features. Every day's benign traffic differs strongly from the training benign
traffic.

What this does and does not show: the feature distributions of the 2018 network differ strongly from 2017. That is
covariate and measurement shift (another network, other tools, another CICFlowMeter build). It is **not** proof of
concept drift, and the data cannot separate the two. A high anomaly score is not proof of a new attack.

## Verdict

- Evaluation tooling: ready and tested.
- Random-split and same-day results: excellent, but in-distribution.
- Chronologically later, different-network traffic: **poor** (no better than the majority baseline).
- Independent generalisation: **not verified**. The only registered independent test (the protected 2018 days) has not
  been run, and the development evidence predicts it would fail (`audit/ML_DEV_RESULTS.md`).

Do not describe the model as accurate on real or new networks. Say: "98.97 % on a random split of its training data;
on later traffic from another network it catches about 15 % of attacks and is no better than predicting benign."

## Reproduce

```bash
cd ai-engine
.venv/Scripts/python evaluation/rank5_generalisation.py
```

About 10–15 minutes and up to ~2 GB of memory. It needs `datasets/cicids2017/` and the six development days in
`D:/sentinelai_datasets/cse_cic_ids2018` (or `SENTINEL_2018_DEV_DIR`). Each run writes a new
`audit/rank5_network_flow_generalisation/run_<UTC>/` folder, never an existing one. `--max-rows N` makes a quick smoke
run; its folder is marked `_smoke`, it is labelled "not evidence", and the dashboard ignores it.

Tests (synthetic fixtures only):

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_rank5_generalisation.py -q
```

```bash
cd backend
npx jest --runInBand tests/rank5Capability.test.js
```

## Still missing

- An independent evaluation: the protected 2018 days (owner approval) or newly collected, independently labelled
  traffic from another network.
- Near-duplicate analysis, and complete 2018 day files (five appear truncated).
- Any operational measurement on live traffic (live capture is not enabled).

## Rank 8: class support, unmodelled classes and features the model cannot use (2026-11-19)

These are read from the frozen model's own metadata. The model was not retrained or changed, and the E3
limitations above stand.

**Class support** (`GET /model/info` -> `classSupport`; project threshold `MIN_TRAINING_ROWS = 100`):

| Class | Training rows | Status |
|---|---|---|
| SQL Injection | 17 | `low_support` (predictions not validated) |
| RCE Attempt | 9 | `low_support` (predictions not validated) |
| Lateral Movement | 29 | `low_support` (predictions not validated) |
| Data Exfiltration | 0 | `unmodeled` |
| Others | 283 to 74,682 | `supported` |

**Data Exfiltration:**
- It has a label index (10), but zero training or test rows.
- The served XGBoost classifier has 10 output classes (0 to 9), so it can never predict it.
- The model status lists it under `unmodeledClasses`, and the dashboard says it is not modelled.
- Adding it needs an explicitly approved training and evaluation cycle with suitable labelled data.

**Time of day** (`time_of_day_sin`, `time_of_day_cos`, positions 51 and 52 of the 53-feature schema):
- In training both were a constant 0. The CICIDS2017 CSVs used carry no timestamp, and the training drift
  reference holds one edge at 0.0 for 100% of rows.
- XGBoost gives both an importance of 0.0.
- They are extracted correctly from a flow's `timestamp` (UTC), which PCAP replay and capture provide; the Demo B
  CSV replay has none, so it stays 0.
- They cannot change any prediction. Tests prove it on the golden vectors and on full records, for many times of day.
- The model status reports this under `featureLimitations`.

**Global SHAP:**
- `scope=recent` (the dashboard's recent-verdicts view) is computed in memory and lost on restart.
- `scope=reference` is reproducible: the golden vectors pinned in `models/registry.json`, cached as JSON under
  `ai-engine/derived/global_shap/` (outside `models/`). It is keyed by model SHA-256, feature schema, golden-set
  SHA-256 and SHAP configuration, so a change to any of them gives a new key and a stale result is never served.
- The reference sample is 20 fixed regression vectors: reproducible, but not a representative traffic sample.

**Naming:**
- The served classifier is XGBoost. The engine reports `classifierType`, `classifierVersion` and
  `classifierMetrics`, plus `modelType` per prediction.
- `rfVersion` and `rfMetrics` remain as legacy fields.
- Stored predictions use `modelType: xgboost`. They no longer use `ensemble`; old records still validate.
- Model artifacts and the registry identifier are unchanged.
