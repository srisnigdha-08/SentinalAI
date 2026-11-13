# Development protocol v4: domain-balanced candidates (pre-registered 2026-11-13)

This protocol is written and committed **before** any v4 candidate is trained. Results go to
`ai-engine/experiments/candidate_v4_<date>/` and `audit/ML_DEV_RESULTS.md`, section "Protocol v4". Earlier protocols
(v1–v3) stay as they are. Their folds, label set and baseline numbers are reused unchanged.

## 1. Question

Does weighting training data so that **every capture day contributes equally**, combined with stronger regularisation,
improve detection on capture days the model never saw, without raising benign false alarms?

Motivation, from v1–v3:
- The served recipe (C0) and the best earlier candidate (C4-A-I) both fail on unseen days.
- Large days and tools dominate the training weight. For example, 2017 Wednesday DoS is 4× the rows of most attack days.
- A model can then learn "what Wednesday looks like" instead of what attack behaviour looks like.

## 2. Data, folds, labels (unchanged from v3)

- **Pools:** `evaluation/dev_experiments.py` `pool_2017` and `pool_2018`, with the same caps and deduplication.
- **Data limits:**
  - CSE-CIC-IDS2018: only the six development days.
  - The four protected days (`evaluation/protected_data.py`) are never opened.
- **Labels:** `corrected_v3`, the verified 2017-Thursday scan correction, pinned by SHA-256.
- **Folds:**
  - D17: leave one 2017 day out (5 folds).
  - D18: leave one 2018 development day out (6 folds).
  - Training uses 2017 plus the 2018 development data.
- **Infiltration:** excluded from training, as in C4-A-I. It stays in every test fold.
- **Validation:** none of the test folds is used for fitting, weighting, threshold choice or early stopping.

## 3. Candidates (frozen)

| Id | Architecture | Features | Weights | Classifier |
|---|---|---|---|---|
| C0 | multiclass (served recipe) | A (53) | class-balanced | XGB 200 trees, depth 6, lr 0.1 (baseline; 2017 only) |
| C4AI | two-stage | A | class-balanced | as C0 (v3 best; reference) |
| **C5** | two-stage | A | **domain-balanced** | **XGB 400 trees, depth 4, lr 0.05, min_child_weight 5, subsample 0.8, colsample_bytree 0.8, reg_lambda 2** |
| **C5E** | two-stage | **E** (C + log + header-per-packet) | domain-balanced | as C5 |

**Domain-balanced weights.** Every (corpus, day) group in a fold's training rows gets the same total weight. Inside a
group, the weight is split equally between benign and attack rows (stage 1), or between classes (stage 2). Groups with
only one side keep their whole share on that side. Weights are normalised to mean 1.

Seeds: 42 for every model. No hyperparameter search. The values above are the whole design.

## 4. Metrics (all reported, per fold and summarised)

- **Binary decision at the classifier (argmax / p ≥ 0.5):**
  - attack recall and benign FPR, each with a 95 % Wilson interval
  - precision, F1 and balanced accuracy
  - the binary confusion matrix (TP/FP/FN/TN)
- **Threshold-free and calibration:** PR-AUC, Brier score, and expected calibration error (10 equal-width bins).
- **Per attack family:** the share flagged, with a Wilson interval.
- **Summaries:**
  - macro: the mean over folds that contain attacks
  - pooled: summed counts
  - worst-fold benign FPR
- **Paired comparisons (C5 and C5E against C4AI and C0, per fold set):** the mean difference in fold recall and fold FPR,
  with a 95 % bootstrap interval over folds (10,000 resamples, seed 20261113). With 5–6 folds these intervals are
  wide by construction.

## 5. Pre-registered decision rule

A v4 candidate is **eligible to become the shadow candidate** (never the deployed model) only if **all** of these hold,
against C4AI:
1. Macro recall is higher on **both** D17 and D18.
2. Pooled benign FPR is no more than C4AI's + 0.10 percentage points, on both D17 and D18.
3. The worst-fold benign FPR is at most 2 %.

If both C5 and C5E qualify, the one with the higher mean of the D17 and D18 macro recall is chosen. If neither
qualifies, the result is reported as negative and nothing changes.

**No candidate is deployed or promoted by this protocol.** Promotion would need:
- the one-shot external test on the protected days (owner approval)
- a frozen operating line chosen on development data
- the owner's explicit decision

## 6. What this protocol cannot show

- It cannot show generalisation to networks beyond CICIDS2017 and the CSE-CIC-IDS2018 development days.
- Only the protected 2018 days, or new independently labelled traffic, can answer that.
- The evaluation needs more independent capture days, ideally from new networks and tools, with verified labels.
