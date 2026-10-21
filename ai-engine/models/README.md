# ai-engine/models

**Served:** exactly the two files pinned by SHA-256 in `registry.json`, currently `xgb_classifier_xgb_cicids_v1.pkl` and `isolation_forest_xgb_cicids_v1.pkl`, produced by `training/pipeline.py`.
- `golden_set.json` holds 20 fixed vectors and the outputs they must reproduce at startup (pinned in the registry).
- `registry_history.jsonl` is the append-only record of every registration.
- Without `registry.json` the engine loads nothing. The legacy "first matching file name" order applies only with `ALLOW_UNREGISTERED_MODELS=1`, intended for development and tests.
- To change the served model, run `training/register_model.py` and then `POST /model/reload`.

**Everything else here is kept for rollback, comparison or because `docs/PRESERVED_ASSETS_SHA256.json` lists it. None of it is loaded:**

| File | What it is |
|---|---|
| `rf_classifier_cicids_v3.pkl`, `isolation_forest_cicids_v3.pkl` | De-duplicated Random Forest (served after C2, until XGBoost won M-5) |
| `rf_classifier_cicids_v2.pkl`, `isolation_forest_cicids.pkl` | August models (served before C2; trained on a split with duplicates, SMOTE) |
| `rf_classifier_cicids.pkl` | Older RF v1 |
| `xgb_classifier_cicids.pkl` | XGBoost on real CICIDS2017 (not deployed) |
| `xgb_classifier_cicids_v2.pkl` | **Byte-identical copy** of `xgb_classifier_cicids.pkl` |
| `xgb_classifier_cicids.pkl.bak`, `xgb_classifier_cicids_meta.json.bak` | Earlier XGBoost run |
| `stacking_classifier_cicids.pkl` | RF + XGBoost stacking (not deployed) |
| `rf_classifier_v2.1.pkl`, `xgb_classifier.pkl`, `isolation_forest_v1.4.pkl` | Trained on synthetic data |
| `q_table.json` | Seed Q-table for the deception learner. Copied once to the runtime path and never written; hash-pinned in `GATE1_CONTRACT.md` |

The repository-root `models/` directory is another archived copy (see `models/README.md` there).
