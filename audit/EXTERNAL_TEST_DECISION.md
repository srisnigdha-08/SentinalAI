# External-test go/no-go memorandum (2026-11-02)

**Recommendation: DEFER.** Do not download or evaluate the four protected CSE-CIC-IDS2018 days (16-02, 20-02, 22-02,
28-02) for C4-A-I. Evidence: `ML_DEV_RESULTS.md` (v3 and stability), `OPERATING_LINE_V3.md`,
`experiments/dev_20261102_v3_corrected/error_breakdown.json`.

## 1. What the one-shot test would establish

Whether a model frozen on development data keeps its advantage on four unseen days of the same 2018 testbed, at a
false-alarm line fixed in advance. It measures generalisation to unseen days and tools **within one laboratory
testbed**. It does not measure real-network performance.

## 2. Likely outcome on existing evidence: failure of the deployment criterion

- At the frozen lines, C4-A-I's lead over C0 on the 2018 development folds is +0.9 / +4.4 / +7.3 points pooled across
  three trained models, against the +10 required. 2018 DoS/DDoS recall is 21.9 vs 21.5 %.
- The protected days are mostly DoS/DDoS: 20-02 LOIC-HTTP is most of the volume, plus 16-02 Hulk/SlowHTTPTest,
  22-02 web attacks and 28-02 infiltration. At the line on development data, C4-A-I detects:
  - 2017 Hulk at 20 % and SlowHTTPTest at 26 %;
  - web attacks at 0–13 %;
  - infiltration at 0 %, with no infiltration class;
  - LOIC-UDP at 0 %.
- The FPR bound is also at risk. With correlated flows resampled as (day, pattern) clusters, the development-data
  95 % bound at the line is 0.125 % (C0 0.138 %), above the 0.10 % limit. The row-wise Wilson bound of 0.0997 %
  understates the uncertainty.

## 3. Is the candidate frozen and reproducible?

Partly.
- **Frozen:**
  - code (`396e7c1`, `412169d`);
  - recipe (features A, T1 two-stage XGBoost, fixed hyperparameters, deterministic);
  - the correction list (pinned sha256);
  - the lines;
  - the 2017 and 2018 development data hashes recorded in each results file.
- **Not frozen:** the **final model** has not been trained. The external test needs one model trained on all
  development data, which is a further training run. The line comes from out-of-fold scores and may not transfer
  exactly to that model.

## 4. Are taxonomy, schema, preprocessing and thresholds fully specified?

Taxonomy (T1), feature schema (the 53 served features; the 2018 mapping from Phase 8), the cleaning steps and the
lines are specified. **Gaps that must be pre-registered before any run:**
- how the protected days are loaded: all rows, or the capped and de-duplicated sampling used for development;
- the recall metric: pooled over the four days, or a per-day macro average;
- the exact final training set and its de-duplication;
- the C0 baseline: retrained on 2017 with corrected labels (as in v3), or the served `xgb_cicids_v1`;
- how the 12-hour 2018 timestamps are handled (they are not features, but they matter for any per-attack-window
  reporting).

## 5. Fair baseline comparison (if run)

- Same protected rows for both models.
- Each model at its own pre-registered line, chosen by the same rule.
- C0 retrained by the same pipeline on the same label set; the served model reported as well.
- Pooled and per-day recall reported; FPR with both Wilson and cluster-bootstrap bounds.
- One run, and the result reported whatever it is.

## 6. If the candidate fails

The served model stays. The result is reported as a negative finding, and the protected days are then used up for
any future candidate drawn from the same development evidence. No re-tuning on those days is permitted.

## 7. Unsupported even if it passes

- Real-network or production detection performance: the data are laboratory captures from one testbed per dataset.
- Detection of infiltration and lateral movement: no such class.
- Stable recall: replicates vary by up to 55 points per fold.
- Behaviour on traffic from other flow exporters: features and timing depend on CICFlowMeter.
- Any effect of the T1 taxonomy on the running system: deploying it would need an approved class migration.
- The label correction rests on a mirror file whose IP and timestamp columns could not be independently
  authenticated.

## Decision

DEFER. Keep the protected days for a future candidate whose development results at the operating line show a clear
margin, at least +10 points across retraining replicates and a cluster-aware FPR bound ≤ 0.10 %. Running now would
most likely confirm "do not deploy" and spend the only independent test set. If you nonetheless want to run it,
first close the gaps in §4 in a pre-registered addendum. Training the final model and downloading the 4.98 GB each
need separate approval.
