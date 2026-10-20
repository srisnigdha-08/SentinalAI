# C1 — Independent Re-evaluation of the Detection Model: Plan and Results

Date: 2026-10-21 · Script: `ai-engine/evaluation/day_holdout_eval.py` · Raw output:
`ai-engine/experiments/c1_day_holdout_eval/results.json` (+ `results_summary.md`) · Runtime: 14.3 min.

## 1. Why this was needed

The deployed model's metadata (`ai-engine/models/rf_classifier_cicids_v2_meta.json`) reports
**98.43 % accuracy, 0.9862 weighted F1, 0.8448 macro F1**. Those numbers come from
`training/train.py:195`: `train_test_split(..., test_size=0.2, random_state=42, stratify=y)`, a
random split over individual flow rows. CICIDS2017 attacks arrive as bursts of near-identical flows
from one tool on one afternoon, so a random split puts sibling flows from the same burst in both
train and test. The score then measures "can the model recognise a flow it has effectively already
seen", not "will it catch this attack later or elsewhere".

## 2. Plan (protocols)

All protocols use the **same cleaned data** (8 CSVs, 2,827,876 rows after dropping NaN/inf rows,
exactly as `train.py` does) and the **production recipe**: per-file caps (BENIGN 15k, Port Scan 10k,
DDoS 10k for training), `StandardScaler + RandomForestClassifier(RF_PARAMS)`, benign-only
`IsolationForest(IF_PARAMS)`, and the production threat score from `inference/predictor.py`
(`0.7·RF confidence + 0.3·IF anomaly signal`, "Unknown" override, threat raised at ≥ 0.70 as the
backend does in `aiService.storePrediction`).

| Protocol | Split | Question it answers |
|---|---|---|
| **Random** (baseline) | stratified random 80/20 rows | Does the pipeline reproduce the reported number? |
| **Chronological** | inside every (file, class): first 70 % of rows train, 1 % purge gap, last 29 % test | Known attack types, seen *later in time*: the honest "in-distribution" estimate |
| **Leave-one-day-out** (the "day-held-out" plan) | train on 4 capture days, test on the 5th, for each day | Attacks from a day/tool never trained on: generalisation to new campaigns |
| **Deployed artifact** | shipped `rf_classifier_cicids_v2.pkl` on the chronological test rows | Comparison only — its training rows are unknown and come from the same files, so **not independent** |

Metrics per protocol: accuracy, macro F1, weighted F1, per-class precision/recall/support, benign
false-positive rate with a 95 % Wilson interval (both "classifier says attack" and "backend would
raise a threat"), and attack detection rate (classifier, and threat raised).

Reproduce: `cd ai-engine && .venv/Scripts/python.exe evaluation/day_holdout_eval.py` (full) or
`--smoke` (~1.5 min sanity run). Unit tests: `tests/test_day_holdout_eval.py`.

## 3. Results

The last column is under the **legacy** score rule (before the C3 fix); §5.2 has the current rule.

| Protocol | Accuracy | Macro F1 | Weighted F1 | Benign FPR (classifier) | Attack detection (classifier) | Attack detection (threat raised ≥ 0.70, legacy rule) |
|---|---|---|---|---|---|---|
| Random 80/20 (as reported) | **0.9869** | **0.8778** | 0.9884 | 1.05 % | 99.69 % | 23.24 % |
| Chronological per class | 0.9757 | **0.7390** | 0.9796 | 1.39 % [1.34, 1.45] | 93.86 % | 29.41 % |
| Deployed artifact on chronological test (not independent) | 0.9875 | 0.8497 | 0.9908 | 1.33 % | 99.77 % | 20.49 % |
| Leave-out Tuesday | 0.5892 | 0.2472 | 0.4384 | 0.30 % | **0.03 %** | 0.00 % |
| Leave-out Wednesday | 0.6616 | 0.2656 | 0.5310 | 0.70 % | **0.31 %** | 0.00 % |
| Leave-out Thursday | 0.9350 | 0.1935 | 0.9157 | 1.30 % | **0.14 %** | 0.00 % |
| Leave-out Friday | 0.7520 | 0.2856 | 0.6611 | 0.10 % | **7.69 %** | 0.21 % |
| Leave-out Monday (benign only) | 0.9920 | — | — | 0.80 % | — | — |

Benign FPR for "threat raised" is very low everywhere (0.000 %–0.040 %; see `results.json` for Wilson CIs).

Per-class under the chronological split (recall / F1): SSH Brute Force 0.985 / 0.992 · Port Scan 0.997 / 0.997 ·
DDoS 0.919 / 0.954 · Credential Stuffing 0.908 / 0.941 · **Malware Beacon 0.134 / 0.056** ·
**XSS 0.611 / 0.433** · SQL Injection 0.286 / 0.333 (n = 7) · RCE 0.75 (n = 4) · Lateral Movement 0.727 (n = 11).

Leave-one-day-out, per class: every attack class was missed on its held-out day, **including classes
present in training from another day** — Credential Stuffing on Tuesday (trained from Thursday's
web brute force): recall 0.000; DDoS on Wednesday (trained from Friday's DDoS): 0.000; DDoS on
Friday (trained from Wednesday's DoS tools): 0.169.

## 4. What this means (say it this way in the viva)

1. **The reported 98.4 % is reproducible but optimistic.** Our random-split replication gives 98.7 %.
   Splitting by time inside each attack episode — so test flows come strictly after training flows —
   keeps accuracy at 97.6 % but **macro F1 falls from 0.88 to 0.74**: the frequent classes (SSH brute
   force, port scan, DDoS) hold up, the rare ones (bot/C2 beaconing, XSS, SQLi) do not.
   Evidence the random split leaks: the deployed model scores *better* on the chronological test
   (99.8 % detection) than a model honestly trained only on earlier rows (93.9 %), because the deployed
   model was trained on rows from those same episodes.
2. **The model does not generalise to attacks from a different capture day**, even of the same
   category: leave-one-day-out detection is 0–8 %. It learns the fingerprint of specific tools in a
   specific lab, which is the known limitation of CICIDS2017-only training. Novel-attack coverage
   would have to come from the anomaly detector, and with the current configuration it does not.
3. **Benign false positives are low at the alerting level** (≤ 0.04 % of benign flows raise a threat),
   but the classifier alone mislabels ~1.0–1.4 % of benign flows; most of those are suppressed by
   the scoring rule below — which also suppresses most true detections.

Accurate one-line claim: *"98.7 % accuracy on a random CICIDS2017 split; on a chronological split
97.6 % accuracy and 0.74 macro F1; the model does not generalise to attack days it was not trained on."*

## 5. New critical finding (C3): the threat score suppresses most correct detections

`inference/predictor.py::predict` computes `threatScore = 0.7·rf_s + 0.3·if_sig`. For a flow the RF
classifies as an attack but the Isolation Forest considers an inlier (`if_sig = 0`), the score is at
most `0.7 × confidence` — **below the 0.70 threat line unless the RF is exactly 100 % confident**, and
it can never reach the 0.92 block line. Result: the classifier detects 94–99.8 % of attacks, but only
**20–29 % would raise a ThreatLog/alert** in the backend. Reproduced live through the full stack during
the C2 test: a correctly classified DDoS flow scored **0.6999 → ALLOW, no threat created**.

Options considered: (1) `max(rf_s, blend)` for attack classes; (2) keep the blend, lower the threat
line; (3) keep as is. Acceptance test set in advance: chronological "threat raised" detection must rise
well above 29 % while benign "threat raised" FPR stays under the 0.1 % target.

### 5.1 Applied: option 1
`inference/predictor.py::combine_threat_score(rf_s, if_sig, is_attack)` — for attack classes
`max(rf_s, 0.7·rf_s + 0.3·if_sig)` (classifier confidence is a floor, the anomaly signal can only raise
it); BENIGN keeps the plain blend; the "Unknown" override is unchanged. Used by `predict()` and
`predict_from_honeypot()`, and by this evaluation script (single source of truth). Thresholds are
unchanged (threat 0.70, block 0.92).

### 5.2 Measured effect (full re-run, same trained models, both rules scored)

| Protocol | Threat raised (≥ 0.70): legacy → current | Block line (≥ 0.92): legacy → current |
|---|---|---|
| | attack detection / benign FPR | attack detection / benign FPR |
| Random 80/20 | 23.2 % / 0.013 % → **97.7 % / 0.425 %** | 4.7 % / 0.000 % → **93.6 % / 0.119 %** |
| **Chronological per class** | 29.4 % / 0.029 % → **89.7 % / 0.496 %** [0.463, 0.532] | 5.0 % / 0.000 % → **86.5 % / 0.046 %** [0.037, 0.058] |
| Deployed artifact (not independent) | 20.5 % / 0.028 % → 98.6 % / 0.648 % | 6.7 % / 0.000 % → 95.4 % / 0.070 % |
| Leave-out Tue / Wed / Thu / Fri | 0.0–0.2 % → 0.0–0.2 % (benign FPR up to 0.54 % on Thu) | ≈ 0 % → ≈ 0 % (benign FPR ≤ 0.17 %) |

Classifier-level metrics (accuracy, F1, per-class) are identical to §3 — the change affects only the
score, not the class.

**Verdict against the acceptance test:** detection criterion **met** (29.4 % → 89.7 %); benign alert FPR
criterion **not met at the 0.70 line** (0.50 % vs < 0.10 %). At the block line the rule meets the target
(0.046 %). Leave-one-day-out detection is unchanged — the score rule cannot recover attacks the classifier
does not recognise.

### 5.3 Threshold sweep (chronological protocol, current rule)

| Threat line | 0.70 | 0.75 | 0.80 | **0.85** | 0.90 | 0.92 | 0.95 | 0.99 |
|---|---|---|---|---|---|---|---|---|
| Attack detection | 89.7 % | 89.2 % | 88.5 % | **87.8 %** | 86.8 % | 86.5 % | 86.1 % | 77.3 % |
| Benign FPR | 0.496 % | 0.322 % | 0.105 % | **0.073 %** | 0.053 % | 0.046 % | 0.037 % | 0.017 % |

Legacy blend for comparison: at no line above 29.4 % detection (0.85 → 15.0 %).
Raising the threat line to **0.85** would meet both criteria (87.8 % detection, 0.073 % benign FPR).
That is a further change to the backend's alert threshold (`aiService.storePrediction`, `aiEngineService`
action rule, `MONITOR_THRESHOLD`) and is **not applied** — and because this sweep picks the line on the
same test rows it then reports, the line should be confirmed on a separate validation split before
quoting 87.8 % / 0.073 % as final. Raw data: `experiments/c1_day_holdout_eval/threshold_sweep/results.json`.

## 6. Recommended next steps (C1 follow-up)

| Step | Effort | Done when |
|---|---|---|
| Update README / paper metrics to the wording in §4 (keep the random-split number, label it) | 30 min | No unlabelled "98.43 %" claims remain |
| C3 scoring fix (option 1) — **done**, see §5.1–5.2 | — | Detection met; alert FPR met only with a higher threat line |
| Choose the alert line on a validation split (sweep suggests ≈ 0.85), apply in predictor + backend | 1–2 h | Benign alert FPR < 0.1 % on the chronological test with detection reported |
| Retrain on the chronological protocol and ship that model (+ meta records `split: chronological`) | 1 h | `rf_classifier_cicids_v2_meta.json` metrics come from an independent split |
| Improve rare classes (Bot, XSS, SQLi): class-specific features, more data, or merge into broader classes | 1–2 days | Chronological macro F1 ≥ 0.85 |
| Add a second dataset (e.g. CSE-CIC-IDS2018 — candidates already exist in `experiments/gate1_phase7*`) for cross-dataset testing | 2–3 days | Cross-dataset results reported alongside CICIDS2017 |

## 7. Limitations of this evaluation
- Row order in the MachineLearningCVE CSVs is used as time order (no timestamp column); it is close to,
  but not exactly, chronological.
- Hyperparameters are the documented `RF_PARAMS`; if the deployed model was trained with `--tune`, its
  exact parameters are unknown (its own metadata does not record them).
- Very small classes (SQLi n = 7, RCE n = 4, Lateral Movement n = 11 in the chronological test) have
  wide uncertainty; their per-class numbers are indicative only.
- Single seed (42). Variance across seeds was not measured.
