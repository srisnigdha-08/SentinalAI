# P5 — served `xgb_cicids_v1` on its reconstructed test split (inference only)

Produced 2026-11-02 by `ai-engine/evaluation/p5_served_model_eval.py`. No model was trained, saved, reloaded or
promoted; `models/` and `runtime/` were unchanged (git status before/after).

- `results.json` — artefact hashes, split-reconstruction check (must equal the model meta, else no metrics),
  leakage checks, per-class metrics with Wilson CIs, confusion matrix, operating lines (argmax / 0.90 / 0.92),
  PR-AUC, Brier, reliability bins, error pairs.
- `confusion_matrix.csv` — rows = true class, columns = predicted.

Interpretation and caveats: `audit/ML_EVAL_PLAN.md` §5. This is an in-distribution split (same capture sessions as
training); it says nothing about unseen days or networks.
