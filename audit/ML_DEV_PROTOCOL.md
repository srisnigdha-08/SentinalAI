# Controlled model-development protocol (pre-registered 2026-11-02, version 1)

This file fixes, **before any candidate is trained**, what will be compared, on which data, how a winner is chosen and
what it must achieve. Changing any of it after results are seen requires a new dated version and invalidates
comparisons with version 1. Nothing here has been trained.

## 1. Verified baseline (2026-11-02)

- Git: `f831af5` on `db-fixes`, clean apart from `.claude/`.
- Deployed models unchanged: classifier `6d08ef19…`, anomaly `46b16b74…`, golden set `c8d72dd9…` (= `registry.json`);
  runtime Q-table `08209e99…` (unchanged).
- Frozen P3/P4 manifests (sha256 prefix): P3 `06d910df99`, Mon `5a172c8c00`, Tue `57a48ae783`, Wed `111f6b504f`,
  Thu `754ffee3f7`, Fri `04a7f5d298` (`experiments/xgb_holdout_20261102/plan.json`).
- P5 random split: attack recall 99.81 %, benign FPR 0.359 % (classifier); 95.22 % / 0.230 % at the 0.90 line.
- P3/P4 classifier: P3 50.6 %; P4 Tue 3.1, Wed 33.4, Thu 17.3, Fri 23.4 %. Full hybrid at 0.90: P3 12.1 %,
  P4 0.6 / 1.7 / 0.2 / 10.4 %; benign FPR up to 3.97 % (Thu).
- 2018 earlier work: Phase 7 (RF v2 on 2018 holdouts: 0 % on 4 of 5 families), Phase 8 (multi-corpus RF: brute force
  71 %, botnet 61 %, DDoS 0 %, infiltration 0.15 %; holdouts shared days with training).

## 2. Protected final external test

The four never-downloaded CSE-CIC-IDS2018 days — **16-02, 20-02, 22-02, 28-02** — are the prospective final test.
- Enforced in code: `ai-engine/evaluation/protected_data.py`; every 2018 loader calls `assert_permitted()` before
  opening a file; `permitted_files()` lists and skips them. Tests: `ai-engine/tests/test_dev_experiments.py`.
- They are not downloaded. They are used **once**, after §7 has selected and frozen a candidate, together with the
  baseline, with no change of features, thresholds or architecture afterwards (`SENTINEL_FINAL_EXTERNAL_EVAL=I_HAVE_APPROVAL`
  is required by the guard; the run records that it was used).
- CSE-CIC-IDS2018 is a laboratory dataset (AWS testbed, scripted attacks); a good result there would show
  cross-testbed transfer, **not** real-world intrusion-detection performance.

## 3. Feature ablation (`evaluation/feature_sets.py`; stateless, row-wise, cannot leak between splits)

| Variant | Change | Hypothesis | Accept if (vs A, same candidate otherwise, D17 + D18 folds) | Compatibility |
|---|---|---|---|---|
| A | 53 served features | baseline | — | current contract |
| B | − 6 constant features | no information; time-of-day is dataset identity (zero in 2017, real hours if a 2018 loader ever filled it) | no metric worse beyond CI (expected ≈ identical for trees) | inference can still receive 53; drop inside the pipeline |
| C | B − `init_win_bytes_forward/backward` | TCP initial window encodes OS/tool (KS 0.87–1.00 across tools); removing it forces behavioural features | mean cross-day binary recall ↑ ≥ 5 points with benign FPR not worse | same |
| D | A with log1p timing / rate / volume | **trees are invariant** to monotone per-feature transforms (beyond binning): expected no change for XGB/RF; may change the Isolation Forest | only judged on the IF review signal | same |
| E | C + D + header length per packet | per-packet header length is a ratio (changes tree inputs); Phase 8 "Schema F" | recall ↑ over C with FPR not worse | same |

Not removed merely for being shifted: packet-length and timing features also shift between tools, but they describe
behaviour; removing them is not part of version 1.

## 4. Architecture comparison

| Architecture | Implementation | What it can and cannot fix |
|---|---|---|
| Single-stage multiclass (current) | Scaler + XGBoost, balanced weights | baseline |
| Random Forest baseline | `training/train.py RF_PARAMS` | checks whether the model family matters |
| Two-stage | Stage 1 binary XGBoost (benign vs attack), Stage 2 multiclass on attack rows only; class = Stage 2 if p(attack) ≥ 0.5 | the alert decision depends only on the binary task (more attack data per decision); cannot invent behaviour not in training |
| Isolation Forest | review signal only (§5c-2: 46 % of unseen DoS flagged "Unknown" vs 4.8 % benign) | not an alert source |
| Conservative confidence / UNKNOWN | REVIEW tier as today | operational; evaluated with the chosen candidate later |

Binary-first is not assumed better: it is candidate C2/C4 against C1 on identical folds.

## 5. Taxonomy (`evaluation/taxonomies.py`; experiment-only — model output classes, API, stored records and UI unchanged)

| Raw label (corpus) | Family (T2) | T0 (deployed) | T1 | Flow-observable? |
|---|---|---|---|---|
| BENIGN / Benign | Benign | BENIGN | BENIGN | — |
| SSH-Patator (17), SSH-Bruteforce (18) | Brute Force | SSH Brute Force | SSH Brute Force | yes |
| FTP-Patator (17), FTP-BruteForce (18) | Brute Force | **Credential Stuffing** (merged) | FTP Brute Force | yes |
| Web Attack – Brute Force (17), Brute Force -Web (18) | Brute Force | **Credential Stuffing** (merged) | Web Brute Force | yes |
| Web Attack – XSS (17), Brute Force -XSS (18) | Web Attack | XSS Attempt | XSS Attempt | **no** (payload) |
| Web Attack – Sql Injection (17), SQL Injection (18) | Web Attack | SQL Injection | SQL Injection | **no**; 21 flows in 2017 |
| DoS Hulk/GoldenEye/slowloris/Slowhttptest, DDoS (17); DoS attacks-*, DDOS attack(s)-HOIC/LOIC-* (18) | DoS/DDoS | DDoS | DDoS | yes; LOIC-UDP has no 2017 counterpart |
| PortScan (17) | Reconnaissance | Port Scan | Port Scan | yes; 354 unique vectors; none in 2018 |
| Bot (17, 18) | Botnet | Malware Beacon | Malware Beacon | yes |
| Infiltration (17), Infilteration (18) | Infiltration | Lateral Movement | Lateral Movement | yes; 36 flows in 2017 |
| Heartbleed (17) | Exploit | RCE Attempt (misnamed: information disclosure) | RCE Attempt | **no**; 11 flows; a TLS rule fits |
| — | — | Data Exfiltration (**no data**) | dropped | — |

T2 merges XSS + SQLi into "Web Attack" (not separable by flows) and keeps brute force as one family. TB = binary.
A taxonomy change becomes a deployment question only after it wins (§7) and an approved migration maps old classes.

## 6. Candidate matrix (frozen; `evaluation/dev_experiments.py CANDIDATES`)

| ID | Features | Taxonomy | Architecture | Model | Training data | Purpose |
|---|---|---|---|---|---|---|
| C0 | A | T0 | multiclass | XGB | 2017 | served recipe baseline |
| C0rf | A | T0 | multiclass | RF | 2017 | model-family baseline |
| C1 | C | T0 | multiclass | XGB | 2017 | testbed-robust features |
| C1e | E | T0 | multiclass | XGB | 2017 | + per-packet headers (+ log) |
| C2 | C | T1 | two-stage | XGB | 2017 | binary-first |
| C3 | C | T2 | multiclass | XGB | 2017 | family taxonomy |
| C4 | C | T1 | two-stage | XGB | 2017 + 2018 dev | multi-dataset |

Fold sets: **D17** = leave one 2017 calendar day out (5 folds; for C4 the training side also has all 2018 dev rows);
**D18** = leave one 2018 development day out (6 folds; 2017-only candidates are trained on 2017 only, so D18 measures
their cross-testbed transfer). Pools: 2017 = the served pool (124,534 rows); 2018 = the six development days,
per file per label capped at 15,000 benign / 10,000 per attack label (`random_state 42`), cleaned like 2017,
time-of-day zero, de-duplicated on vector + label. Preprocessing (scaler, label encoding, sample weights) is fitted
on each training fold only. Fixed hyperparameters (train.py's); no search.

## 7. Selection rule and acceptance (pre-registered)

Primary metric per candidate: mean over attack-containing folds (D17 and D18 separately) of binary attack recall at
the classifier decision, with mean benign FPR as a constraint. Secondary: PR-AUC, Brier, per-family flagged rate,
cross-tool rows (DoS↔LOIC/HOIC, FTP↔HTTP brute force), predict µs/row, model bytes.

A candidate is **eligible** if, on both D17 and D18: mean benign FPR ≤ the baseline's (C0) + 0.1 percentage points,
and no fold's benign FPR exceeds 2 %. Among eligible candidates the **selected** one has the highest D18 mean recall;
ties (within 2 points) go to the simpler one (fewer stages, T0 over T1/T2, 2017-only over multi-dataset).

The selected candidate is **recommended for the final external test** only if its D18 mean recall beats C0 by
≥ 10 points and its D17 mean recall is not lower than C0's. After the final test it is recommended for deployment
only if, on the four protected days: binary recall beats C0 by ≥ 10 points; benign FPR Wilson upper bound
≤ 0.10 % at a line chosen on D17/D18 only; p95 single-flow latency ≤ 50 ms; model ≤ 2× current size; and the golden
set / protected-hash checks pass. Otherwise the served model stays, and the result is reported as is.

## 8. Resources (measured where stated)

- Plan run (measured, `ai-engine/experiments/dev_20261102/plan.json`): 2017 pool 124,534 rows (= served pool),
  2018 development pool 129,374 rows (benign 81,821; DDoS HOIC 8,193, LOIC-UDP 1,730; DoS GoldenEye 9,993, Slowloris
  8,854; infiltration 7,548; bot 5,610; SSH 5,045; web brute force 340, XSS 150, SQLi 51; **FTP brute force 39** —
  10,000 sampled rows collapse to 39 unique vectors), built in 73 s; peak memory stayed within the ~1 GB free.
  Fold sizes: D17 test 12,022–47,514 rows; D18 test 14,194–31,936; training 77k–125k (2017-only) or 206k–242k (C4).
  None of the protected files is on disk; the guard reported none.
- XGBoost fit 3.7–11.2 s per fold on ~50k–113k rows, 16 cores (measured, P3/P4). Two-stage ≈ 2 fits.
- First batch (C0, C1, C2 on D17 + D18): 3 candidates × 11 folds ≈ 33 fold trainings, 44 XGBoost fits
  ≈ 5–15 min CPU (estimate). Full matrix: 7 × 11 = 77 fold trainings, RF slower (≈ 30–60 min total, estimate).
- RAM: 2018 files are read in 250k-row chunks; peak ≈ 1–2 GB (estimate; this machine has 7.7 GB, ~1 GB free).
- Disk: results JSON only; no model is saved.

## 9. Approval requested for the first training batch

```powershell
cd ai-engine
.venv\Scripts\python evaluation\dev_experiments.py --run --approved --candidates C0,C1,C2 --folds D17,D18 `
  --out experiments\dev_20261102_batch1
```

Throwaway fold models only; `models/`, the registry and the protected days untouched. Recommended order afterwards:
batch 2 = C1e, C3, C0rf; batch 3 = C4 (multi-dataset); then §7 selection; then — with separate approval — the one-shot
external test (download of the four protected days, 4.98 GB).
