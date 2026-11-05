# Controlled model-development protocol, version 3 (pre-registered 2026-11-02, before any v3 run)

Versions 1 and 2 (`ML_DEV_PROTOCOL.md`, `ML_DEV_PROTOCOL_V2.md`) and all their results stay as published: no
candidate is eligible under them. Version 3 makes exactly **two** changes, both motivated by evidence and both
**decided after the v1/v2 results were seen**, which is stated here so the results can be read with that in mind:

1. **A verified label correction** (label set `corrected_v3`), applied identically to every candidate including the
   baseline C0.
2. **One new candidate, C4-A-I:** C4-A with infiltration rows removed from training.

Folds, features, hyperparameters, seed, pools, decision rule, metrics and the §7 thresholds are unchanged. Nothing
in this file has been trained.

## 1. State verified before writing

- Git `3b1f349` on `db-fixes`; all v2/v3 work uncommitted.
- `models/` and `runtime/` unchanged (git diff empty): classifier `6d08ef19…`, golden `c8d72dd9…`, registry
  `5f76c136…`, Q-table `08209e99…`. Production API, thresholds, RL settings, the disabled firewall adapter and
  Demos A/B/C are untouched.
- Protected 2018 days 16-02, 20-02, 22-02, 28-02: not on disk, not read.
- v3 plan runs (no training): `experiments/dev_20261102_v3plan_published/plan.json` and
  `…_v3plan_corrected_v3/plan.json`. C0 and C4-A fold manifests are **identical** to v1/v2 under both label sets.

## 2. Change 1: the verified label correction

**Evidence** (`LABEL_VERIFICATION_PLAN.md`): the rule was pre-registered before the data was obtained, and the
verdict is **VERIFIED**. Of the 63,022 BENIGN-labelled probe flows in the 2017 Thursday afternoon file:
- 98.4 % involve 192.168.10.8;
- 95.3 % fall in the CIC-scheduled "Portscan + Nmap" window (15:04–15:45 ± 5 min);
- they reach 11 internal hosts;
- 60,030 rows meet all conditions.

The source is a public mirror, which joins our file on 100 % of rows; the IP and timestamp columns cannot be
authenticated beyond that (a stated limitation).

**Correction:**
- Those 60,030 row positions are frozen in
  `ai-engine/evaluation/label_corrections/cicids2017_thursday_scan_v3.csv` (sha256 `c4e3f1c1…6807`, pinned in
  `dev_experiments.CORRECTION_V3`; the runner refuses a modified file).
- With `--labels corrected_v3`, pooled rows of that file at those positions change from `benign` to `portscan`.
  In the pool this is **816 rows** (of 254k).
- It is applied after pooling, so no row enters or leaves any fold.
- The dataset files on disk are **not** modified, and nothing else is relabelled.
- The 2018 data (including 21-02, DATA-004) is **not** corrected; that hypothesis is unverified.

## 3. Change 2: candidate C4-A-I

| ID | Features | Taxonomy | Architecture | Data | Differs from C4-A only by |
|---|---|---|---|---|---|
| C4-A-I (`C4AI`) | A (53) | T1 | two-stage XGB | 2017 + 2018 dev | rows of family Infiltration (2017 "Infiltration" 36, 2018 "Infilteration" 7,548) are removed from every **training** side |

Infiltration rows remain in every **test** fold and count as attacks, so the recall cost is measured and not hidden.
Evidence:
- 84 % of C4-A's D18 benign false positives (1,068 of 1,269) are predicted "Lateral Movement".
- Infiltration's own recall on unseen days is 1.5–2.8 %.
- Day 01-03 has 488 vectors that also occur under another label (ML-016, ML-014).

The trade-off is that the system would no longer have a flow-level infiltration class; it barely detects one today.

## 4. Runs (fold sets D17 + D18, 11 folds each)

| Label set | C0 | C4-A | C4-A-I |
|---|---|---|---|
| published | exists (v1 batch 1) | exists (v2 batch 1) | **run** |
| corrected_v3 | **run** | **run** | **run** |

That is 4 × 11 = 44 fold trainings. C0 and C4-A are not re-run on published labels; v2 already confirmed exact
reproduction.

## 5. Selection and acceptance

- **Primary label set: `corrected_v3`.** The §7 rule is applied unchanged, with C0 re-run on the same labels as
  the baseline:
  - **Eligible:** on both D17 and D18, mean benign FPR ≤ C0 + 0.1 pp, and no fold above 2 %.
  - **Selected:** the highest D18 mean recall, with ties within 2 points going to the simpler candidate.
  - **Recommended for the external test:** only if D18 recall is at least C0 + 10 points and D17 recall is not
    lower than C0's.
- **Published-label results** are reported next to every number. They cannot make a candidate eligible, and a
  candidate is not excused on them.
- Why corrected is primary: the published labels call 816 verified scan flows benign, so a detector is penalised
  for detecting them. Using the corrected set is a measurement fix, independently verified. It is **not** a change
  of thresholds, and it is disclosed as decided after seeing results.
- **The final external test is unchanged.** It runs on the four protected 2018 days with published labels; no
  correction is verified there. The §7 deployment criteria are unchanged: ≥ 10 points recall over C0, FPR Wilson
  upper bound ≤ 0.10 %, p95 ≤ 50 ms single-flow, ≤ 2× size, golden/hash checks. It needs separate approval,
  including the 4.98 GB download, and may run only once.
- **Latency:** v2 timings were distorted by machine load. p95 latency must be re-measured on an idle machine
  before the deployment criteria are judged.

**Reported per run:**
- per-fold TP/FP/TN/FN, recall, FPR, precision, F1, PR-AUC and Brier;
- macro and pooled metrics, plus the worst fold;
- per-family flagged rate, including infiltration recall (C4-A-I's cost);
- the 2017-Thursday and 21-02 benign FP counts, and the predicted classes of the false positives;
- under corrected labels, how many of the 816 corrected rows each model flags;
- model bytes and µs/row, flagged as load-sensitive.

## 6. Pre-registered expectations

These are estimates from v2's stored predictions, **not results**; retraining will change them.

| | Expectation | Basis |
|---|---|---|
| C4-A, corrected | 2017-Thursday FPR ≈ 0.5 % (from 4.20 %) | 810 of its 920 Thursday FPs are corrected rows |
| C4-A-I | D18 benign FPs fall by up to ≈ 1,068; fold FPRs ≈ 0.1–0.8 %; infiltration recall ≈ 0 % | its FPs by predicted class |
| C4-A-I, corrected | could meet every §7 limit (rough D18 mean ≈ 0.3 % vs a limit of about 0.47 %) | the two estimates combined |
| C0, corrected | Thursday FPR probably falls too, which also raises the bar for the candidates | C0's 903 Thursday FPs; v1 stored no predictions, so the overlap is unknown |

The selection is made only from the actual results under §5. If no candidate passes, the result is reported as
negative and the thresholds are not changed.

## 7. Resources

- 44 two-stage fold trainings, about 88 XGBoost fits. The last run took 48 min for 33 folds on a loaded machine
  (estimate 60–70 min; ≈ 15 min if idle).
- RAM 1–2 GB.
- Disk: results JSON plus prediction CSVs, about 28 MB per candidate per label set (≈ 110 MB).
- Throwaway models only; nothing written outside `experiments/`.

## 8. Code and tests (uncommitted)

- `evaluation/dev_experiments.py`: `C4AI`, `CORRECTION_V3`, `apply_label_set`, `train_mask`, `--labels`, and a
  `label_used` column in the prediction dumps.
- `evaluation/verify_labels_2017.py`: writes the frozen row list on VERIFIED.
- `evaluation/label_corrections/cicids2017_thursday_scan_v3.csv`.
- `tests/test_dev_protocol_v2.py` has 4 new v3 tests:
  - the correction touches only the listed benign rows of one file;
  - a modified row list is refused;
  - the frozen file matches its pinned hash;
  - C4-A-I differs from C4-A only by its training mask.
- 32/32 pass across the v2, dev and holdout suites.

## 9. Approval requested (two commands, run one after the other; no other training)

```powershell
cd ai-engine
.venv\Scripts\python evaluation\dev_experiments.py --run --approved --dump-predictions --labels corrected_v3 `
  --candidates C0,C4A,C4AI --folds D17,D18 --out experiments\dev_20261102_v3_corrected
.venv\Scripts\python evaluation\dev_experiments.py --run --approved --dump-predictions --labels published `
  --candidates C4AI --folds D17,D18 --out experiments\dev_20261102_v3_published
```

After the runs come verification (manifests, models/runtime unchanged) and analysis against §5. Nothing is
promoted, no threshold changes, and the protected days are not downloaded without a further, separate approval.

## 10. Addendum (2026-11-02, written before running): stability check

**Why not seeds.** The fold models use XGBoost without row or column subsampling, so `random_state` has no effect.
This was checked: identical predictions for seeds 42, 1 and 2 on synthetic data. "More seeds" would only reproduce
the same models. The instability seen in v3 (single-fold recall moving by up to 55 points after relabelling 0.3 % of
rows) is sensitivity to the **training sample**, so that is what the check perturbs.

**Design.**
- 2 replicates (`--train-subsample 0.9 --subsample-seed 1` and `2`).
- In each replicate, every fold trains on a seeded random 90 % of its training rows.
- Test folds are unchanged, so test rows and counts are identical to v3.
- Candidates C4AI and C0 on `corrected_v3` labels; D17 + D18; predictions dumped.
- The full-data v3 run is the reference.

**Reported (descriptive only; nothing below changes the selection, the frozen lines or any threshold):**
- per replicate: macro and pooled recall and FPR at the argmax decision, and whether §5 eligibility would still hold;
- at the **frozen** lines (C4AI 0.915614, C0 0.974834): recall, FPR, Wilson upper bound and per-fold FPR;
- the line §2 of `OPERATING_LINE_V3.md` would choose on each replicate (for information; the frozen line stays);
- the spread (min–max) across the three models of each fold's recall and FPR.

**Command (approved by the owner 2026-11-02):**

```powershell
cd ai-engine
foreach ($s in 1,2) { .venv\Scripts\python evaluation\dev_experiments.py --run --approved --dump-predictions --labels corrected_v3 `
  --candidates C0,C4AI --folds D17,D18 --train-subsample 0.9 --subsample-seed $s --out experiments\dev_20261102_v3_stab_s$s }
```
