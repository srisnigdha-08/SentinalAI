# Evaluation plan for the served classifier `xgb_cicids_v1` (ML-004, ML-005, RET-001)

Written 2026-11-01, corrected 2026-11-02 (file vs calendar-day holdout; sampling description; P5 results added).
P5 (inference) and the approved P3/P4 evaluation fits have been run (2026-11-02). No model has been saved, replaced, reloaded or promoted.

Corrections to the 2026-11-01 version:
- It said "8 folds, one file each" for leave-one-day-out. CICIDS2017 has **8 files from 5 calendar days**; holding out
  one *file* and holding out one *day* are different protocols (§3). `evaluation/day_holdout_eval.py` already
  groups by calendar day (`DAYS`, `day_of()`), i.e. 5 folds.
- It said training used "`--rows 20000` per file". For real data `--rows` is unused: `training/train.py` pre-caps
  each file (BENIGN 15,000, Port Scan 10,000, DDoS 10,000, `random_state 42`), then caps globally (BENIGN 100,000,
  Port Scan 40,000, DDoS 40,000), keeps every row of the other classes, then removes exact duplicates.

## 1. What is served (verified)

| Item | Value | Evidence |
|---|---|---|
| Classifier | `ai-engine/models/xgb_classifier_xgb_cicids_v1.pkl`, sha256 `6d08ef19…360b` = `registry.json` | P5 run (recomputed) |
| Anomaly model | `isolation_forest_xgb_cicids_v1.pkl`, sha256 `46b16b74…c5ec053` = `registry.json` | P5 run (recomputed) |
| Loaded through | `SentinelPredictor.load()`: registry hash check + golden set (20 rows) passed | P5 run |
| Served in practice | 30/30 replayed flows stored with `modelVersion: xgb_cicids_v1` | integration harness |
| Trained | 2026-10-21 from commit `cf667f1`, dirty tree (`git_dirty: true`); `training/train.py` is unchanged since `cf667f1`, `utils/features.py` changed only in honeypot functions | git diff |
| Data | 8 CICIDS2017 MachineLearningCVE CSVs; sha256 of all 8 equal the recorded hashes | P5 run |
| Dataset after caps | 148,015 rows → 124,534 after exact-duplicate removal (23,481 removed, 33 vectors with conflicting labels kept) | meta + P5 reconstruction |
| Split | `stratified_random_80_20`, `random_state 42`, not an independent hold-out | meta `evaluation` |
| Latency (measured earlier, not re-run) | in-process XGB+IF, 1 flow: p50 18.0 ms, p95 41.3 ms (n = 1,000); flow → ThreatLog: p50 65 ms | `metrics_report/SENTINELAI_METRICS_REPORT.md` |

## 2. Class support

### By file (full files, project label map, before any cap)

| File (day) | BENIGN | DDoS | Port Scan | Malware Beacon (Bot) | Lateral (Infiltration) | Cred. Stuffing | XSS | SQLi | SSH BF | RCE (Heartbleed) |
|---|---|---|---|---|---|---|---|---|---|---|
| Monday | 529,918 | – | – | – | – | – | – | – | – | – |
| Tuesday | 432,074 | – | – | – | – | 7,938 (FTP-Patator) | – | – | 5,897 | – |
| Wednesday | 440,031 | 252,661 (4 DoS tools) | – | – | – | – | – | – | – | 11 |
| Thursday AM WebAttacks | 168,186 | – | – | – | – | 1,507 (web brute force) | 652 | 21 | – | – |
| Thursday PM Infiltration | 288,566 | – | – | – | 36 | – | – | – | – | – |
| Friday AM | 189,067 | – | – | 1,966 | – | – | – | – | – | – |
| Friday PM PortScan | 127,537 | – | 158,930 | – | – | – | – | – | – | – |
| Friday PM DDoS | 97,718 | 128,027 (LOIC) | – | – | – | – | – | – | – | – |

### By calendar day (what a day holdout removes)

| Day | Files | Attack classes present |
|---|---|---|
| Monday | 1 | none (benign only) |
| Tuesday | 1 | Credential Stuffing (FTP-Patator), SSH Brute Force |
| Wednesday | 1 | DDoS (DoS Hulk/GoldenEye/slowloris/Slowhttptest), RCE (Heartbleed, 11 flows) |
| Thursday | 2 | Credential Stuffing (web brute force), XSS, SQLi, Lateral Movement |
| Friday | 3 | DDoS (LOIC), Port Scan, Malware Beacon |

- **7 of the 10 trained classes occur on exactly one calendar day** (SSH BF Tue; RCE Wed; XSS, SQLi, Lateral Thu;
  Port Scan, Malware Beacon Fri). In a day holdout, that day's fold has the class **absent from training**: its
  per-class recall is 0 by construction. Report those folds only on the binary attack-vs-benign question
  ("unseen-attack detection") and mark the class "absent from training".
- Only **DDoS** (Wed DoS tools ↔ Fri LOIC) and **Credential Stuffing** (Tue FTP-Patator ↔ Thu web brute force) span
  two days, and in both cases the other day uses a different tool: these folds measure cross-tool transfer.
- **Data Exfiltration** (class 10) has 0 samples; P5 confirms the model never saw it. It should be removed from the
  label map or shown as "untrained".
- Capping and de-duplication shrink some classes drastically: Port Scan 158,930 raw → 10,000 pre-cap → **354 after
  de-duplication** (283 train / 71 test), so the served model's Port Scan numbers rest on 71 test flows.

## 3. Protocols

| # | Protocol | Train | Test | Answers |
|---|---|---|---|---|
| P1 | Reproduce | served recipe from a **clean commit**, same seed | the P5 test rows | Is the artefact reproducible? per-class F1 within ±0.002 of P5 |
| P3 | Chronological | Mon–Wed | Thu + Fri | forward-in-time; mostly binary (only DDoS overlaps), plus Cred. Stuffing cross-tool |
| P4 | **Calendar-day holdout**, 5 folds | 4 days | 1 day | per-fold binary recall + benign FPR; per-class only where the class is in training |
| P4f | File holdout, 8 folds (secondary) | 7 files | 1 file | **Not** a day holdout: on Thu/Fri the held-out file shares a day (same network state, same benign sessions' neighbours) with training files. Report only beside P4, labelled "file holdout" |
| P5 | Served model on its reconstructed test split | none | 24,907 rows | **done 2026-11-02** (§5) |

Identical boundaries (baseline vs candidate): every comparison uses one **frozen split manifest** per protocol —
for each test row the `(file, row index)` pair, plus the training row set — written once by the evaluator and
reused for every model. The served model cannot be the P3/P4 baseline as is: it was trained on rows from every day,
so on any day fold it has seen that day. The baseline for P3/P4 is therefore **the served recipe refitted on each
fold's training rows** (same code path as the candidate); the served artefact itself is compared only on P5/P1.
Same caps, same de-duplication (applied before splitting, within the pool), same feature list, same thresholds
(alert 0.90, block 0.92), same random_state.

Metrics for every protocol: accuracy; macro and weighted P/R/F1; per-class P/R/F1 with support and Wilson 95 % CI;
confusion matrix; attack recall, benign FPR and FNR at the classifier argmax and at both lines; PR-AUC
(attack vs benign; ROC-AUC is uninformative at this imbalance); Brier score and a 10-bin reliability table.

Leakage checks before any number is reported: feature vectors shared between train and test (P5: 15 of 24,907
test rows — vectors whose duplicates carry another label, kept by design); time-of-day columns constant (P5:
yes); no IP/port/timestamp/Flow-ID features (P5: none in the 53).

## 4. Comparison and promotion criteria

A candidate replaces `xgb_cicids_v1` only if, on P3 **and** P4 (same manifests as the refitted baseline):
1. binary attack recall ≥ the baseline's, and benign FPR at the alert line ≤ the baseline's;
2. macro F1 on P1 does not drop by more than 0.01;
3. no class with ≥ 100 test rows loses more than 0.02 recall;
4. golden set passes and p95 single-flow latency ≤ 50 ms;
5. trained from a clean commit; meta records the protocol and the manifest hash.

Promotion goes through `training/retrain_from_samples.py` → `register_model.py` (appends to
`models/registry_history.jsonl`); RET-001 closes with one such run, promoted or rejected.

## 5. P5 results (run 2026-11-02, inference only)

Command: `ai-engine/.venv/Scripts/python evaluation/p5_served_model_eval.py` (≈ 2 min).
Artefacts: `ai-engine/experiments/p5_served_eval_20261102/results.json`, `confusion_matrix.csv`.

Split reconstruction: dedup statistics and **all 20 per-class train/test counts equal the model meta**; accuracy
and macro/weighted F1 reproduce the recorded values exactly (0.9897 / 0.8738 / 0.9907).

| Class | Precision | Recall | F1 | Test support | Recall 95 % CI |
|---|---|---|---|---|---|
| BENIGN | 0.9994 | 0.9964 | 0.9979 | 18,671 | 0.995–0.997 |
| SSH Brute Force | 0.9984 | 1.0000 | 0.9992 | 644 | 0.994–1.0 |
| SQL Injection | 1.0000 | 0.5000 | 0.6667 | **4** | 0.15–0.85 |
| Port Scan | 0.8500 | 0.9577 | 0.9007 | 71 | 0.88–0.99 |
| DDoS | 0.9967 | 0.9994 | 0.9981 | 3,610 | 0.998–1.0 |
| RCE Attempt | 1.0000 | 1.0000 | 1.0000 | **2** | 0.34–1.0 |
| XSS Attempt | 0.4071 | 0.7923 | 0.5379 | 130 | 0.71–0.85 |
| Malware Beacon | 0.8824 | 0.9896 | 0.9329 | 288 | 0.97–0.997 |
| Credential Stuffing | 0.9772 | 0.8980 | 0.9359 | 1,480 | 0.88–0.91 |
| Lateral Movement | 0.8333 | 0.7143 | 0.7692 | **7** | 0.36–0.92 |

Macro precision 0.8944, macro recall 0.8848. Largest errors: Credential Stuffing → XSS 148, BENIGN → Malware Beacon
38, XSS → Credential Stuffing 26, BENIGN → DDoS 12, BENIGN → Port Scan 11. The XSS / Credential Stuffing confusion
is between two Thursday-morning web attacks against the same server (web brute force is mapped to "Credential
Stuffing"), so it is partly a taxonomy problem.

Operating lines (attack = any non-BENIGN true label; 6,236 attack / 18,671 benign test rows):

| Decision | Attack recall | Benign FPR (95 % CI) | FP / FN |
|---|---|---|---|
| Classifier argmax ≠ BENIGN | 0.9981 | 0.359 % (0.28–0.46 %) | 67 / 12 |
| Alert line (score ≥ 0.90) | 0.9522 | **0.230 %** (0.17–0.31 %) | 43 / 298 |
| Block line (score ≥ 0.92) | 0.9476 | 0.225 % (0.17–0.30 %) | 42 / 327 |

- The served alert line costs 4.6 points of attack recall against the classifier alone (286 more misses of 6,236
  attacks) in exchange for 36 % fewer false alarms (67 → 43). Benign FPR at the alert line (0.23 %) is **above the project's 0.10 % acceptance line** on this
  in-distribution split.
- 942 benign-predicted rows got the "Unknown" override; 180 went to REVIEW, all of them truly benign (0 attacks).
- PR-AUC (attack vs benign) 0.9995; Brier 0.0028. Reliability: 18,520 rows with p < 0.1 are 0.03 % attacks; 6,259
  rows with p ≥ 0.9 are 99.3 % attacks; the 128 rows in between are poorly calibrated (e.g. 0.7–0.8 bin: mean p 0.74,
  attack rate 0.14) — too few rows to recalibrate on.
- Batch scoring cost 0.024 ms/row (24,907 rows in one call); not a substitute for the single-flow latency above.

What P5 does **not** show: generalisation to unseen days, tools or networks (P3/P4), and anything for SQLi, RCE and
Lateral Movement beyond "≤ 7 test flows".

## 5b. P3 / P4 / P4f prepared (2026-11-02, plan only — nothing trained)

`ai-engine/evaluation/xgb_holdout_eval.py` builds the same 124,534-row pool as the served model (caps + dedup,
reusing the P5-verified loader), keeps each row's file and calendar day, and writes `plan.json` with one frozen
manifest per fold (row ids `file#row`, sha256 recorded). The manifest files themselves are git-ignored (~6 MB each)
and regenerate identically. Baseline (the served recipe refitted per fold) and any candidate must be scored on the
same manifest. Labels are re-encoded per fold over the classes present in training (XGBoost requires contiguous
labels); test rows of a class absent from training are scored only as attack vs benign. Unit tests:
`ai-engine/tests/test_xgb_holdout_eval.py`.

| Protocol | Fold | Train rows | Test rows | Test classes absent from training |
|---|---|---|---|---|
| P3 | Mon–Wed → Thu + Fri | 52,916 | 71,618 | Lateral Movement, Malware Beacon, Port Scan, SQL Injection, XSS |
| P4 | Monday | 112,512 | 12,022 | – (benign only) |
| P4 | Tuesday | 103,496 | 21,038 | SSH Brute Force |
| P4 | Wednesday | 104,678 | 19,856 | RCE (Heartbleed) |
| P4 | Thursday (2 files) | 100,430 | 24,104 | Lateral Movement, SQL Injection, XSS |
| P4 | Friday (3 files) | 77,020 | 47,514 | Malware Beacon, Port Scan |
| P4f | 8 file folds | 102,506–114,402 | 10,132–22,028 | see `plan.json` (secondary; not a day holdout) |

Only Monday's fold has every test class in training, and it has no attacks. P3/P4 will therefore mostly measure
whether unseen attack types are flagged as *some* attack, plus DDoS and Credential Stuffing across tools, and must
be reported that way.

Commands (PowerShell, from `ai-engine/`):

```powershell
.venv\Scripts\python evaluation\xgb_holdout_eval.py                                   # plan (about 1 min, done)
.venv\Scripts\python evaluation\xgb_holdout_eval.py --run --approved --protocols P3,P4  # needs your approval
```

Resources: building the pool took about 25 s and ~2 GB RAM. Measured fit time (run of 2026-11-02): 3.7–11.2 s per
fold on 16 cores; the earlier ~2 min/fit estimate was far too high.

## 5c. P3 / P4 results (run 2026-11-02, approved: six evaluation fits, nothing saved or promoted)

Command (from `ai-engine/`): `.venv\Scripts\python evaluation\xgb_holdout_eval.py --run --approved --protocols P3,P4
--out experiments\xgb_holdout_20261102`. Output: `ai-engine/experiments/xgb_holdout_20261102/results.json`.

Conditions: 124,534-row pool (same as the served model), frozen manifests (each fold's sha256 checked against
`plan.json` before fitting; train/test disjoint asserted), served recipe (StandardScaler fitted on the fold's
training rows only + XGBClassifier `n_estimators 200, max_depth 6, learning_rate 0.1, random_state 42`, balanced
sample weights), no hyperparameter search, labels re-encoded per fold. Python 3.11.9, numpy 1.26.4, pandas 2.2.0,
scikit-learn 1.4.0, xgboost 2.0.3, git `c44f0c8` (+ uncommitted evaluator changes). Fit time 3.7–11.2 s per fold
(16 cores). `models/` and `runtime/` unchanged (git status).

**Operating lines in the first table are lower bounds** (full served score: §5c-2). The served threat score for an attack prediction is
max(confidence, 0.7·confidence + 0.3·IF signal); the Isolation Forest was not refitted per fold (outside the six
approved fits; reusing the served IF would leak held-out-day benign traffic), so "line" rows use confidence only.
Attack recall at a line can only rise with the IF term; benign rows that the IF would push over the line are missing.

| Fold | Train / test rows | Attack recall, classifier argmax (95 % CI) | Benign FPR, argmax (95 % CI) | Attack recall at 0.90 line (LB) | Benign FPR at 0.90 (LB) | PR-AUC | Macro F1, seen classes |
|---|---|---|---|---|---|---|---|
| **P5 random split** (served model) | 99,627 / 24,907 | **99.81 %** | **0.359 %** (0.28–0.46) | **95.22 %** (served rule, with IF) | **0.230 %** | 0.9995 | 0.8738 (all classes) |
| **P3** Mon–Wed → Thu+Fri | 52,916 / 71,618 | **50.6 %** (49.8–51.5) | **0.118 %** (0.09–0.15) | 12.1 % | 0.062 % | 0.876 | 0.691 |
| P4 Monday (benign only) | 112,512 / 12,022 | – (no attacks) | 0.233 % (0.16–0.34) | – | 0.067 % | – | – |
| P4 Tuesday | 103,496 / 21,038 | 3.1 % (2.8–3.5) | 0.379 % (0.28–0.51) | 0.6 % | 0.067 % | 0.835 | 0.399 |
| P4 Wednesday | 104,678 / 19,856 | 33.4 % (32.4–34.5) | 0.237 % (0.16–0.34) | 1.7 % | 0.093 % | 0.966 | 0.407 |
| P4 Thursday | 100,430 / 24,104 | 17.3 % (15.8–19.0) | **4.12 %** (3.86–4.39) | 0.2 % | 3.97 % | 0.430 | 0.597 |
| P4 Friday | 77,020 / 47,514 | 23.4 % (22.7–24.2) | **2.71 %** (2.54–2.88) | 10.4 % | 0.025 % | 0.804 | 0.591 |

Classes in training but on a **different tool** in the held-out data (true cross-tool generalisation):

| Fold | Class | Trained on | Tested on | Recall (as that class) |
|---|---|---|---|---|
| P3 | DDoS | Wednesday DoS Hulk/GoldenEye/slowloris/Slowhttptest | Friday LOIC | 54.2 % (53.2–55.1) |
| P4 Wednesday | DDoS | Friday LOIC | Wednesday DoS tools | **0.0 %** (0–0.05) |
| P3 | Credential Stuffing | Tuesday FTP-Patator | Thursday web brute force | 38.2 % (35.8–40.7) |
| P4 Tuesday | Credential Stuffing | Thursday web brute force | Tuesday FTP-Patator | **0.0 %** (0–0.06) |
| P4 Thursday | Credential Stuffing | Tuesday FTP-Patator | Thursday web brute force | 13.7 % (12.1–15.6) |
| P4 Friday | DDoS | Wednesday DoS tools | Friday LOIC | 16.9 % (16.2–17.7) |

Classes **absent from training** (reported only as "flagged as any attack"; no multiclass recall exists for them):

| Fold | Class (test rows) | Flagged as an attack (95 % CI) | Mostly predicted as |
|---|---|---|---|
| P3 | Malware Beacon (1,437) | 0 % (0–0.3) | BENIGN 1,437 |
| P3 | Port Scan (354) | 4.8 % (3.0–7.6) | BENIGN 337 |
| P3 | XSS (652) | 46.3 % (42.5–50.2) | Credential Stuffing 301, BENIGN 350 |
| P3 | SQL Injection (21) | 7 of 21 | BENIGN 14 |
| P3 | Lateral Movement (36) | 0 of 36 | BENIGN 36 |
| P4 Tuesday | SSH Brute Force (3,219) | 8.9 % (7.9–9.9) | BENIGN 2,934 |
| P4 Wednesday | RCE / Heartbleed (11) | 1 of 11 | BENIGN 10 |
| P4 Thursday | XSS (652) / SQLi (21) / Lateral (36) | 21.9 % / 4 of 21 / 1 of 36 | BENIGN |
| P4 Friday | Malware Beacon (1,437) / Port Scan (354) | 0 % / 13.8 % | BENIGN |

Feature-vector collisions: the pool holds **33 vectors carrying two labels** (66 rows): BENIGN/Port Scan 27,
BENIGN/DDoS 4, BENIGN/Malware Beacon 2. They are kept by design (train.py de-duplicates on vector + label). In the
folds, 0 test rows repeat a training vector with the same label (no exact leakage across days); 3, 0, 3, 29 and 28
test rows (P3, Tue, Wed, Thu, Fri) repeat a training vector with a **different** label — irreducible label noise
the model cannot get right. In P5 the same effect is the 15 shared vectors.

### 5c-2. Full-hybrid P3/P4 (run 2026-11-02, approved: 6 XGBoost re-fits + 6 Isolation Forest fits)

Command (from `ai-engine/`): `.venv\Scripts\python evaluation\xgb_holdout_eval.py --run --approved --with-if
--approved-if --protocols P3,P4 --out experiments\xgb_holdout_hybrid_20261102 --expect
experiments\xgb_holdout_20261102\results.json`. The frozen `plan.json` was copied into the output folder first, so
every manifest hash was checked. All six refitted classifiers reproduced the earlier argmax metrics exactly; each
Isolation Forest was fitted on its fold's benign training rows only (35,705–81,558 rows, 0.7–1.0 s); the deployed
scoring constants were not changed. Output: `ai-engine/experiments/xgb_holdout_hybrid_20261102/results.json`.

| Fold | Recall at 0.90, served score (95 % CI) | Benign FPR at 0.90 (95 % CI) | Precision at 0.90 | Recall at 0.92 | Attacks scored "Unknown" (BENIGN + anomalous) | REVIEW queue: attack / benign |
|---|---|---|---|---|---|---|
| P3 Mon–Wed → Thu+Fri | 12.14 % (11.6–12.7) | 0.062 % (0.05–0.09) | 0.979 | 11.93 % | 67 | 9 / 1,338 |
| P4 Monday (benign only) | – | 0.067 % (0.03–0.13) | – | – | 0 | 0 / 35 |
| P4 Tuesday | 0.64 % (0.50–0.83) | 0.067 % (0.03–0.13) | 0.881 | 0.44 % | 2 | 0 / 39 |
| P4 Wednesday | 1.65 % (1.39–1.95) | 0.093 % (0.05–0.17) | 0.924 | 1.49 % | **3,747** | **209 / 55** |
| P4 Thursday | 0.18 % (0.07–0.47) | **3.97 %** (3.72–4.23) | 0.005 | 0.05 % | 115 | 6 / 88 |
| P4 Friday | 10.40 % (9.86–11.0) | 0.025 % (0.01–0.05) | 0.993 | 8.16 % | 35 | 2 / 310 |

Findings:
- **The Isolation Forest term changes almost nothing at the operating lines.** Hybrid recall equals the
  classifier-only lower bound (P3: +1 flow; P4 identical), and FPR is unchanged. On unseen days the deployed hybrid
  score alerts on 0.2–12 % of attacks at the 0.90 line.
- **The anomaly model does see unseen DoS.** On Wednesday 3,747 of 8,061 attacks (46 %) are classified BENIGN but
  scored anomalous ("Unknown"), against 570 of 11,795 benign flows (4.8 %). By design "Unknown" never alerts; 209
  attacks and 55 benign flows reach the REVIEW queue. This is the only place the hybrid adds signal — as an
  analyst-review input, not as an alert (a 4.8 % benign "Unknown" rate is far too high to alert on).
- Thursday's alerts are almost all false (precision 0.005): benign flows predicted as an attack class with high
  confidence. The Isolation Forest cannot lower an attack prediction's score.

### What the results justify

- The 98.97 % accuracy / 95.2 % alert-line recall is an **in-distribution** figure: train and test rows come from
  the same capture sessions. On traffic from days (and tools) not seen in training the same recipe detects 3–51 %
  of attacks at its own decision boundary and ≤ 12 % at the 0.90 line (classifier term), and benign FPR rises to
  2.7–4.1 % on Thursday/Friday. **The model does not generalise across capture days.**
- Even a class that *is* in training is missed when a different tool produces it (DDoS LOIC → DoS tools 0 %;
  web brute force → FTP-Patator 0 %). Detection here is "recognise flows like the ones seen", not "recognise attacks".
- Justified claims: "On CICIDS2017 with a stratified random split, the served XGBoost reaches 98.97 % accuracy and
  0.874 macro F1"; "cross-day evaluation shows poor generalisation (P3 attack recall 50.6 %, P4 3–33 %)". Not
  justified: detection of novel/zero-day attacks, real-network accuracy, the 0.10 % FPR target being met.
- Consistent with the earlier Random Forest leave-one-day-out result (README: macro F1 0.19–0.29).

## 5d. Weakness analysis (evidence, cause, fixability)

| Weakness | Evidence | Root cause | Fixable with this dataset? | Justified next step and how to evaluate it |
|---|---|---|---|---|
| No cross-day / cross-tool generalisation | §5c | **Data**: each attack class comes from one tool on one day; flow statistics differ per tool | Partly — no new tools exist in CICIDS2017 | Train on CICIDS2017 + CSE-CIC-IDS2018 (same feature extractor, different network and dates; a prior gate1 branch built a multi-corpus pipeline), evaluate P3/P4 on 2017 and a full hold-out on 2018 |
| XSS ↔ "Credential Stuffing" confusion (P5: 148 CS→XSS, XSS precision 0.41; P3: XSS→CS 301) | 5-NN in scaled feature space: XSS neighbours are 57.5 % web brute force, 41.8 % XSS; FTP-Patator neighbours 99.9 % FTP-Patator | **Labelling + observability**: "Credential Stuffing" merges two unrelated clusters (FTP-Patator, HTTP brute force); XSS and HTTP brute force are both form posts to the same DVWA server, and flow features carry no payload | Yes for the taxonomy | Split "Credential Stuffing" into FTP brute force and web brute force, or merge XSS/SQLi/web brute force into one "Web Attack" class; compare macro F1 on P5 and P4 Thursday on identical manifests. Payload-level distinction needs HTTP inspection (not in flow features) |
| SQLi 21 / RCE 11 / Lateral 36 flows in total | §2 | **Data** scarcity | No | Report counts, not rates; for RCE/Heartbleed a rule (TLS heartbeat length) beats a classifier; more data (CSE-CIC-IDS2018 has none of Heartbleed) |
| Data Exfiltration: class 10, 0 samples | P5 `classes_never_seen` | **Label map** lists a class with no data | Yes | Remove it from `LABEL_MAP` (or mark "untrained" in the UI); a model change, so with the next retrain |
| Port Scan 158,930 → 354 unique rows | §2; 27 BENIGN/Port Scan conflicting vectors | **Data**: scan flows are near-identical; de-duplication is correct; some vectors are labelled both ways | No (duplicates carry no information) | Keep de-duplication; report support |
| Benign FPR above 0.10 % | P5 0.230 % at 0.90; sweep: 0.139 % even at 0.995, 0.032 % only at 0.999 (recall 86.2 %); cross-day 2.7–4.1 % at argmax | **Model + policy**: the target is not reachable by threshold without large recall loss; out of distribution it is far worse | Threshold alone: no | Choose any new line on a separate validation split (never P5 test); add the IF/review tier and alert aggregation (per-source rate) before any auto-block; evaluate on P3/P4 with the IF refitted per fold (needs approval) |
| Threshold trade-off | `experiments/p5_served_eval_20261102/threshold_sweep.json` | Score is mostly classifier confidence; out of distribution confidence collapses (P3: 50.6 % argmax → 12.1 % at 0.90) | — | Calibrate on a held-out *day* (isotonic on P4 folds), not on the random split |
| Train/test similarity in P5 | P5 vs P3/P4 gap; 0 same-label cross-day collisions but 15 in P5 | Random row split inside the same sessions | — | Always report P3/P4 next to P5 |

No model was retrained and no threshold was changed.

## 6. Runs that still need approval

| Run | Cost (estimate, this laptop) | Writes |
|---|---|---|
| P1 reproduce from a clean commit | 1 XGB fit on ~100k rows: minutes | `ai-engine/experiments/` only |
| ~~P3 + P4~~ done 2026-11-02 (§5c). P4f (8 file folds) | 8 XGB fits, ~1 min CPU (measured 4–11 s per fit) | `ai-engine/experiments/` only; no model saved |
| P3/P4 operating lines with the Isolation Forest refitted per fold | 6 IF fits (seconds each) | same |
| RET-001 promotion | depends on candidate; changes the served model | `models/`, `registry.json` |
