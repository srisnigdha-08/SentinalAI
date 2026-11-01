# Evaluation plan for the served classifier `xgb_cicids_v1` (ML-004, ML-005, RET-001)

Written 2026-11-01. Nothing here has been trained or promoted; section 6 lists the runs that need approval.

## 1. What is served (verified)

| Item | Value | Evidence |
|---|---|---|
| Classifier | `ai-engine/models/xgb_classifier_xgb_cicids_v1.pkl`, sha256 `6d08ef19…360b` | `models/registry.json` (pinned; inference refuses a mismatch) |
| Anomaly model | `isolation_forest_xgb_cicids_v1.pkl`, sha256 `46b16b74…c5ec053` | same |
| Served in practice | every one of 30 replayed flows was stored with `modelVersion: xgb_cicids_v1` | `scripts/integration/run_integration.cjs`, run 2026-11-01 |
| Trained | 2026-10-21 16:03 from commit `cf667f1` **with a dirty tree** (`git_dirty: true`) | `xgb_classifier_xgb_cicids_v1_meta.json` → `provenance` |
| Data | all 8 CICIDS2017 MachineLearningCVE CSVs; **sha256 of each file re-checked today: all 8 match** the recorded hashes | read-only hash run, 2026-11-01 |
| Sampling | `--rows 20000` per file cap, then exact-duplicate removal: 148,015 → 124,534 rows (23,481 removed, 33 conflicting-label vectors) | meta `deduplication` |
| Split | `stratified_random_80_20`, `random_state 42`, `independent_holdout: false` | meta `evaluation` |
| Reported metrics | accuracy 0.9897, F1 weighted 0.9907, **F1 macro 0.8738** on that random split | meta `metrics` |
| Latency (already measured, not re-run) | in-process XGB+IF, 1 flow: p50 18.0 ms, p95 41.3 ms (n = 1,000); flow → ThreatLog stored: p50 65 ms, p95 123 ms (n = 56) | `metrics_report/SENTINELAI_METRICS_REPORT.md` §latency |

The 0.99 figures are **in-distribution** numbers: train and test rows come from the same capture sessions, a minute
apart. They say nothing about a day, attack run or network the model has not seen.

## 2. Class support by capture day (computed 2026-11-01, full files, project label map)

| File | BENIGN | DDoS | Port Scan | Malware Beacon (Bot) | Lateral Mvmt (Infiltration) | Cred. Stuffing | XSS | SQLi | SSH Brute Force | RCE (Heartbleed) |
|---|---|---|---|---|---|---|---|---|---|---|
| Monday | 529,918 | – | – | – | – | – | – | – | – | – |
| Tuesday | 432,074 | – | – | – | – | 7,938 (FTP-Patator) | – | – | 5,897 | – |
| Wednesday | 440,031 | 252,661 (DoS ×4) | – | – | – | – | – | – | – | 11 |
| Thursday AM (WebAttacks) | 168,186 | – | – | – | – | 1,507 (web brute force) | 652 | 21 | – | – |
| Thursday PM (Infiltration) | 288,566 | – | – | – | 36 | – | – | – | – | – |
| Friday AM | 189,067 | – | – | 1,966 | – | – | – | – | – | – |
| Friday PM PortScan | 127,537 | – | 158,930 | – | – | – | – | – | – | – |
| Friday PM DDoS | 97,718 | 128,027 (LOIC) | – | – | – | – | – | – | – | – |

Consequences for any temporal or leave-one-day-out (LODO) protocol:

- **7 of the 10 trained attack classes occur in exactly one file** (Port Scan, Malware Beacon, Lateral Movement, XSS,
  SQLi, SSH Brute Force, RCE). Holding that file out removes the class from training; its recall on that fold is 0 by
  construction. Report these folds as "class absent from training: novel-attack detection only" and score them on
  the binary attack-vs-benign question, never as per-class recall.
- Only **DDoS** (Wednesday DoS tools vs Friday LOIC) and **Credential Stuffing** (FTP-Patator vs HTTP brute force) span
  two files, so they are the only classes where cross-day *same-class* generalisation can be measured — and in both
  cases the second day uses a different tool, so it measures cross-tool transfer.
- **Data Exfiltration** is in the label map (class 10) but has **0 samples** anywhere. The model can emit it in
  principle; no metric for it can exist. It should be removed from the class list or labelled "untrained".
- Heartbleed has 11 flows total (≤ 3 in a 20 % test split): no per-class number for RCE is statistically meaningful
  (one error moves recall by ≥ 33 points). Report counts, not rates.
- The existing `evaluation/day_holdout_eval.py` implements random / temporal / LODO protocols for the **RF recipe**
  only; earlier RF LODO attack detection was 0.03–7.7 % (`docs/C1_EVALUATION_PLAN_AND_RESULTS.md`). The served XGB
  has **no LODO result** (ML-004 still open).

## 3. Protocols to run

| # | Protocol | Train | Test | Answers |
|---|---|---|---|---|
| P1 | Reproduce | served recipe from a **clean commit** (ML-005), same seed | same random 20 % | Is the served artefact reproducible? Compare per-class F1 and the confusion matrix with the meta; sha256 will differ (pickle), metrics must match within ±0.002 |
| P2 | Grouped random | as P1, but split by **flow-group** (dedupe on the 53-feature vector *before* splitting, already done) and **cap per-file** | 20 % | Leakage check: rows whose feature vectors collide across splits = 0 |
| P3 | Chronological | Mon–Wed + Thu AM | Thu PM + Fri (all three) | Forward-in-time generalisation; only BENIGN/DDoS-family overlap, so mostly a *binary* attack/benign test |
| P4 | LODO, 8 folds | 7 files | 1 file | Per-fold binary attack recall + benign FPR; per-class recall **only** for DDoS and Credential Stuffing folds; table flags "absent from training" |
| P5 | Served model on its own random test split | none (inference) | P1 split rows | Per-class precision/recall/F1, confusion matrix, FPR/FNR at the served rule (alert ≥ 0.90, block ≥ 0.92) |

Metrics for every protocol (one JSON + one markdown table per run, under `ai-engine/experiments/xgb_eval_<date>/`):
accuracy; macro and weighted P/R/F1; per-class P/R/F1 **with support**; full confusion matrix; benign FPR and attack
FNR at both score lines; PR-AUC for attack-vs-benign (ROC-AUC is uninformative at this imbalance); Wilson 95 % CIs for
any class with < 100 test rows; calibration (reliability curve, Brier) for the attack probability, since the alert
and block lines are probability thresholds.

Leakage / duplicate checks before any number is reported: exact-duplicate vectors across train/test = 0;
`time_of_day_*` columns constant (they are zero in CICIDS rows, ML-001 withdrawn — re-assert); no `Flow ID`, IP, port
or timestamp columns in the 53 features (assert against `FEATURE_NAMES`).

## 4. Model comparison and promotion criteria

A candidate replaces `xgb_cicids_v1` only if, on P3 **and** P4 (not P1):
1. binary attack recall is ≥ the served model's, and benign FPR at the alert line is ≤ the served model's
   (or ≤ 0.10 %, the project's acceptance line, if that is higher);
2. macro F1 on P1 does not drop by more than 0.01;
3. no class with ≥ 100 test rows loses more than 0.02 recall;
4. the golden set (`models/golden_set.json`, 20 rows) passes and p95 single-flow latency stays ≤ 50 ms;
5. it is trained from a clean commit (`git_dirty: false`) and its meta records the split protocol.

Promotion goes through the existing human-gated path (`training/retrain_from_samples.py` → `register_model.py`,
which appends to `models/registry_history.jsonl`). RET-001 is closed by one such end-to-end run, promoted **or
rejected**, with its registry_history entry.

## 5. Rollback (preserved)

The served files are pinned by sha256 in `models/registry.json`; `registry_history.jsonl` keeps prior entries, and
`POST /model/reload` (admin key) hot-swaps. Rollback = restore the previous `registry.json` entry and reload; the
`xgb_cicids_v1` files must not be deleted while any candidate is under evaluation. `verify_protected_hashes.py`
covers the protected files.

## 6. Runs that need your approval

| Run | Cost (estimate, this laptop) | Writes |
|---|---|---|
| P1 reproduce from a clean commit | 1 XGB fit on ~100k rows: minutes | `ai-engine/experiments/` only |
| P3 + P4 (9 XGB fits) | ~10–30 min CPU | `ai-engine/experiments/` only |
| P5 (inference on the served model) | < 2 min | `ai-engine/experiments/` only |
| RET-001 promotion | depends on candidate; changes the served model | `models/`, `registry.json` |

No run in this table has been executed. P5 needs only the served model and the data, so it can go first.
