# Experiment model artifacts — library versions (L10)

The engine's pinned environment is Python 3.11 + scikit-learn **1.4.0** (`requirements.txt`, `models/registry.json`). The candidate models below were pickled under scikit-learn **1.7.2**, which comes from a different, unpinned environment (the repository also holds `cpython-313` bytecode). Under 1.4.0 the RF candidates fail to unpickle with `IndexError` (tree node array layout changed between versions). They are **evidence only**: nothing loads them and they are not deployable as-is.

The version was read from the `_sklearn_version` field stored inside each pickle (2026-10-21).

| Artifact | Size | scikit-learn | sha256 (first 12) |
|---|---|---|---|
| `gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl` | 5.9 MB | 1.7.2 | `71a1756e64fe` |
| `gate1_phase10_detector_recovery/candidate_rf_multicorpus_v2_fixed.pkl` | 9.3 MB | 1.7.2 | `f83c1f878e55` |
| `gate1_phase10_detector_recovery/disposable_rf_phase10_v1.pkl` | 7.4 MB | 1.7.2 | `ea6fb47a1f74` |
| `gate1_phase12_evidence_repair/calibration_models.joblib` | < 0.1 MB | 1.7.2 | `938cf26ae64e` |
| `gate1_phase13_shift_and_leakage/candidate_rf_multicorpus_v3.pkl` | 28.4 MB | 1.7.2 | `d8a18ccf6cae` |
| `gate1_phase13_shift_and_leakage/candidate_v3_calibration.pkl` | < 0.1 MB | 1.7.2 | `5506086b058f` |

To inspect one, use a separate virtual environment with `scikit-learn==1.7.2`. To deploy a candidate, retrain it in the pinned environment with `training/train.py --version …` and register it; never set `ALLOW_SKLEARN_MISMATCH`.
