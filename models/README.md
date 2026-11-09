# Archived model copies — not loaded

Nothing in SentinelAI loads this directory. The inference engine resolves `MODEL_DIR` relative to
`ai-engine/` and loads only the files pinned (by SHA-256) in `ai-engine/models/registry.json`.

These files are kept because `docs/PRESERVED_ASSETS_SHA256.json` lists them as preserved assets. They
differ from the deployed models:

| File | Here (repo root) | Deployed (`ai-engine/models/`) |
|---|---|---|
| `rf_classifier_cicids_v2.pkl` | trained 2026-08-14, sha256 `a7f98d2e…`, metadata acc 0.9863 / macro F1 0.8714 | trained 2026-08-09, sha256 `ca0efb1f…`, acc 0.9843 / macro F1 0.8448 |
| `isolation_forest_cicids.pkl` | identical (`17bd08ff…`) | identical |
| `sgd_classifier_cicids.pkl` | only here; never loaded | — |

They were most likely produced by running `training/train.py` from the repository root, whose
`--model-dir` default (`models`) is relative to the current directory. To deploy a different model,
copy it into `ai-engine/models/` and run `ai-engine/training/register_model.py`.
