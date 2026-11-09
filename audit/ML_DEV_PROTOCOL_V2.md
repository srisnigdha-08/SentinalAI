# Controlled model-development protocol, version 2 (pre-registered 2026-11-02, before any v2 run)

Version 1 (`ML_DEV_PROTOCOL.md`) and its results (`ML_DEV_RESULTS.md`, batches 1 and 3) stay unchanged and stay
valid: under v1 no candidate is eligible. Version 2 adds two frozen candidates and new reporting; it does not change
the v1 folds, metrics, selection rule or acceptance criteria. Nothing in this file has been trained.

## 1. State verified before writing (2026-11-02)

- Git `3b1f349` on `db-fixes`; working tree: `.claude/` plus the new, uncommitted v2 files listed in §8.
- `models/` and `runtime/` unchanged (git diff empty): classifier `6d08ef19…`, anomaly `46b16b74…`, golden
  `c8d72dd9…`, Q-table `08209e99…`. Registry, production API, thresholds, RL settings, firewall adapter (disabled)
  and Demos A/B/C untouched.
- Protected days 16-02, 20-02, 22-02, 28-02-2018: not on disk, not read (guard reported none in every run).
- v2 plan run (`experiments/dev_20261102_v2plan/plan.json`): C4, C4A, C4B fold manifests are **byte-identical** to
  batch 3's C4 manifests (all 11 folds); pools 124,534 (2017) + 129,374 (2018 dev) rows, as in v1.

## 2. Why C4 has a high FPR — root cause of the 21-02-2018 false positives

Analysis is model-free (`evaluation/fp_diagnostics_2018.py`, `evaluation/pipeline_integrity.py`); row-level C4
predictions were not stored in batch 3, so which rows were flagged is **not yet known** (§6 gives the procedure).

### Confirmed

| Fact | Evidence |
|---|---|
| 21-02 fold: 14,999 benign, 8,193 HOIC, 1,730 LOIC-UDP test rows; C4 flagged 3,647 benign (FPR 24.3 %) and caught 25.1 % of attacks | batch 3 `results.json` |
| **The day's benign traffic is effectively one pattern.** In the full file 358,523 of 360,833 benign rows (99.4 %) share: initial windows 65535 fwd / 32768 bwd, 5 forward packets, max forward packet exactly 935 bytes, TCP, destination ports ≥ 49152 (16,378 distinct) | read-only scan of the raw CSV |
| No other day looks like this: share of the most common benign pattern is 1.7–5.0 % on 2017 days and 3.1–4.0 % on other 2018 dev days, **99.3 % on 21-02** (28 distinct patterns vs 2,293–9,791) | `pipeline_integrity.py` |
| The pattern is out of distribution for the training side: KS vs other 2018 benign 0.992 (`init_win_bytes_forward`), 0.988 (`fwd_packet_len_std`) | `fp_diagnostics_2018.py` |
| It is **not** a copy of training attacks: 0 exact duplicates against training rows of either label (features A and C); nearest training neighbour is benign for 99.93 % of rows (9 infiltration, 2 brute force) | same |
| 99.9 % of these benign rows are timestamped inside the attack period (mostly hour 02, concurrent with HOIC 02:11–02:33 as recorded; the file stores 12-hour times without AM/PM) | same; diagnosis only |
| The 2017-only candidates flag almost none of it (C0/C1 1 row, C2 0) and catch 0 % of the day's attacks | batch 1 |

### Interpretation

- The 24.3 % is a property of **one traffic pattern**, not of 15,000 independent benign flows. Its FPR is close to
  a single yes/no observation ("does the model call this pattern an attack?") repeated 15,000 times; its Wilson CI
  (23.6–25.0 %) badly understates the uncertainty.
- The pattern lies where C4 has no training data on either side; the decision there is extrapolation by the trees
  (nearest neighbour is benign, yet a quarter is flagged), not memorised attacks.
- **C4's FPR problem is not only 21-02.** Without that fold, C4's D18 FPR is still 2.88 % mean / 2.88 % pooled,
  worst fold 15-02 6.98 % (C0: 0.45 %). So removing or explaining 21-02 alone would not make C4 eligible.

### Hypothesis (not verified, not acted on)

The 935-byte, 5-packet flows to ephemeral ports during HOIC look like the server side of the HOIC HTTP flows (or
another scripted response stream) labelled benign by the dataset's time/IP-window labelling. Verifying it needs the
source/destination IPs or PCAP, which the processed file does not contain (only `Dst Port`, `Protocol`,
`Timestamp`). **No relabelling** — there are no independently verified grounds. The labels stay as published.

## 3. Pipeline-integrity verification (`evaluation/pipeline_integrity.py`, read-only, output `experiments/pipeline_integrity_20261102/integrity.json`)

| Check | Result |
|---|---|
| Feature definitions 2017 vs 2018 | 50 of 53 served features mapped from the 2018 CSV (Phase 8 mapping), `payload_entropy` derived by `prepare_features` in both corpora, `time_of_day_sin/cos` known-absent; 0 unaccounted |
| Time-of-day leak (DATA-002) | zero in every 2017 and 2018 row |
| IP / port / timestamp / day as features | none; they are read only by the diagnostics script, never by `fit_predict` |
| Label mapping | `taxonomies.map_labels` raises on unknown labels; every raw label of both corpora mapped (v1 tests) |
| Train / test separation | `assert not (tr & te).any()` per fold; manifests hashed and equal to the plan |
| Variant B's six constant features | constant in the 2017 pool, the 2018 pool and their union → dropping them is information-free for trees |
| Exact-duplicate contamination (C4 folds) | features A: 0–18 same-label test rows per fold; features C: 178–3,431 (dropping the TCP windows makes more flows identical). 21-02: 0 same-label under A and C |
| Contradictory vectors (same vector, other label in training) | features A: 0–488 per fold (most on 01-03, infiltration); C: 99–1,056; 21-02: 0 (A) / 370 (C) — under C some 21-02 attack vectors also occur as benign in training. Irreducible label overlap, reported, not removed |
| Cross-corpus identical vectors | 23 of 129,374 2018 rows equal a 2017 vector |
| Sample weights | `compute_sample_weight("balanced")` fitted on each training fold only (both stages) |
| Probability interpretation | `p_attack` = stage-1 P(attack) (two-stage) or 1 − P(benign) (multiclass); the v1 decision is argmax / 0.5 at stage 1; PR-AUC and Brier use `p_attack` |
| Absent classes | classes are re-encoded per fold; families absent from a fold's training are listed in each fold record (e.g. LOIC-UDP when 21-02 is held out) |

**C0 vs C4 comparison limitations** (unchanged results, stated explicitly): C0 is trained on 2017 only, so on D18
it measures cross-testbed transfer, while C4 on D18 has seen five other 2018 days (same testbed, other tools); on D17
C4 has all 2018 rows in training, C0 none. They also differ in features (A vs C), taxonomy (T0 vs T1) and
architecture (multiclass vs two-stage). The comparison answers "is the C4 recipe better than the served recipe",
not which of these four changes is responsible. C4-A/C4-B isolate the feature change.

**Macro vs pooled** (`evaluation/dev_summary.py`): v1 §7 uses macro (mean of per-fold rates). Pooled counts differ
materially for recall (C0 D18 macro 11.1 % vs pooled 25.1 %, because folds have very different attack counts) and
little for FPR (benign test sizes are similar). Both are reported from now on; selection stays macro, as registered.

## 4. Frozen v2 candidates (`dev_experiments.py CANDIDATES`)

| ID | Features | Taxonomy | Architecture | Model | Data | Differs from C4 only by |
|---|---|---|---|---|---|---|
| C4-A (`C4A`) | A (53, served) | T1 | two-stage | XGB | 2017 + 2018 dev | keeps TCP windows and the six constants |
| C4-B (`C4B`) | B (47) | T1 | two-stage | XGB | 2017 + 2018 dev | keeps TCP windows; the six verified-constant features dropped |
| C4-C (`C4`) | C (45) | T1 | two-stage | XGB | 2017 + 2018 dev | — (the existing C4; re-run for row-level predictions and a reproduction check) |

Same hyperparameters, seed, pools, D17/D18 folds (identical manifests) and decision rule as v1. No search, no
threshold change, no other modification. Hypothesis (from batch 1, ML-011): keeping the TCP-window features restores
the per-testbed benign anchor and lowers FPR on the non-homogeneous folds; on 21-02 the effect is not predicted,
because that day's window values (65535/32768) are themselves out of distribution. Expected C4-A ≈ C4-B (constant
features carry no information; any difference would indicate a pipeline problem).

## 5. Comparison plan and acceptance criteria

Reported for each of C0 (existing), C4-C, C4-A, C4-B, per fold set:
- attack recall, benign FPR (mean, pooled, worst fold), precision, F1, PR-AUC, Brier, per-family flagged rate,
  cross-tool rows, µs/row, model bytes — macro and pooled shown side by side;
- 21-02: benign FP count per variant, the predicted class of those FPs, their `p_attack` distribution, and how
  the flagged rows split across the 28 benign patterns (from the prediction dump);
- a descriptive view without the homogeneous fold (21-02). **It cannot make a candidate eligible**.

Acceptance (v1 §7 unchanged): eligible only if on both D17 and D18 mean benign FPR ≤ C0 + 0.1 pp and no fold
> 2 %; selected = highest D18 mean recall; external test only if D18 recall ≥ C0 + 10 points and D17 recall not
lower. No threshold change is introduced in v2. Any future threshold must be chosen on D17/D18 training-side data
only, justified independently of the protected days, and registered as a new protocol version before it is used.

Reproduction check: C4-C must reproduce batch 3 per fold (tp/fp/fn/tn). A mismatch is reported and blocks
interpretation of the v2 batch until explained.

## 6. Row-level predictions for the 21-02 analysis

`dev_experiments.py --dump-predictions` (requires `--run --approved`) writes `predictions_<candidate>.csv`:
fold, corpus, day, file, pool row index, raw label, predicted class, `p_attack`, for development test rows only.
No model is saved. The 21-02 analysis then joins these rows to the raw-CSV metadata via `fp_diagnostics_2018.py`.

## 7. Resources

- Measured (batch 3, C4): 8.5–13.2 s fit per fold, 5.8–9.1 µs/row, 4.0–4.6 MB per fold model; pool build ≈ 75 s.
- v2 batch: 3 candidates × 11 folds = 33 two-stage fold trainings ≈ 66 XGBoost fits ≈ 6–10 min CPU (estimate),
  RAM ≈ 1–2 GB (as v1). Disk: results JSON + three prediction CSVs ≈ 3 × 254k rows ≈ 60 MB (estimate).
- No GPU, no download, nothing written outside `experiments/`.

## 8. Files (uncommitted)

`evaluation/fp_diagnostics_2018.py`, `evaluation/pipeline_integrity.py`, `evaluation/dev_summary.py`,
`evaluation/dev_experiments.py` (C4A/C4B, `--dump-predictions`), `tests/test_dev_protocol_v2.py` (6 tests),
`experiments/fp_diag_20261102/`, `experiments/pipeline_integrity_20261102/`, `experiments/dev_20261102_v2plan/`.

## 9. Blockers

- Labelling hypothesis for 21-02 cannot be verified without IPs/PCAP (not in the processed CSV; the raw PCAPs are
  in the same public bucket but are large and would need separate approval to download — not requested).
- SEC-001 remains open (user action, §10 of the batch notes / `SEC001_REMEDIATION.md`).
- C4's FPR is above the limit even without 21-02 (15-02 6.98 %); if C4-A/C4-B do not bring it down, v3 needs a
  new idea, pre-registered before any run.

## 10. Approval requested for v2 batch 1

```powershell
cd ai-engine
.venv\Scripts\python evaluation\dev_experiments.py --run --approved --dump-predictions --candidates C4,C4A,C4B `
  --folds D17,D18 --out experiments\dev_20261102_v2batch1
```

Throwaway fold models only; `models/`, registry, runtime and the protected days untouched; no promotion.
