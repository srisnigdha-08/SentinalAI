# SentinelAI AI Engine — Low-Priority Fixes Report (L1–L12)

Date: 2026-10-21, branch `db-fixes`. The issues are defined in `docs/AI_ENGINE_STUDY_GUIDE.md`, Phase 4. This is separate from `docs/LOW_PRIORITY_FIXES_REPORT.md`, which covers the earlier backend audit.

| ID | Issue | What changed | Where |
|---|---|---|---|
| L1 | `/predict/auth/shadow` echoed exception text | Returns `"shadow evaluation failed"` and logs only the exception type | `inference/main.py` |
| L2 | `AuthTelemetryRecord` untyped and unbounded | Optional fields are `Optional`. String length limits: 64 for most fields, 256 for the user, 4096 for the raw message. Port limited to 0–65535; timestamp must be finite | `inference/main.py` |
| L3 | Honeypot +0.02 per command, even for BENIGN | Already fixed with C1 | — |
| L4 | Backend retries of `/predict/internal` double-counted stats and drift | A delivery seen before (same `X-Request-Id` **and** same feature vector) is scored and returned but not counted again. Distinct flows in one backend request are still counted. Bounded to 10,000 keys | `inference/main.py` `_first_delivery` |
| L5 | Dead AbuseIPDB client logging raw IPs | Removed (`get_ip_reputation`, its cache, the `requests`/`ipaddress` imports). Enrichment lives in the backend. Tests now assert that no HTTP request is made during scoring | `inference/predictor.py`, `tests/test_predictor.py`, `tests/test_abuseipdb_decoupling.py` |
| L6 | `log_transform_features` imported but unused | Import removed from `train.py`. The function **stays**, documented, because the archived SGD model (`models/sgd_classifier_cicids.pkl`, a preserved asset) pickled a reference to it and would not load without it | `training/train.py`, `utils/features.py` |
| L7 | `evaluate_model.py` hard-coded model names | Already fixed with C2 (uses the registry) | — |
| L8 | `--tune` compared against hard-coded numbers | The baseline is now the untuned recipe fitted on the **same** split. A saved model file was dropped as the baseline, since after deduplication it may have been trained on today's test rows | `training/train.py` |
| L9 | `pytest` unpinned, `scipy` missing | `pytest==9.1.1`, `scipy==1.17.1`. Every line in `requirements.txt` is now `==`-pinned. The pandas "pyarrow" warning is cosmetic; pyarrow is not used | `ai-engine/requirements.txt` |
| L10 | Experiment pickles don't load | Read from the pickles: all six were written by scikit-learn 1.7.2, while the engine pins 1.4.0. Recorded with hashes and guidance; they are evidence only | `ai-engine/experiments/ARTIFACT_VERSIONS.md` |
| L11 | The registry hash sits next to the pickles it protects | Optional `MODEL_REGISTRY_SHA256` (set outside the model volume) pins `registry.json` itself; on a mismatch the engine serves nothing. `register_model.py` prints the value. `/model/info` `registry.registryPinned` shows whether the pin is active. Compose and `.env.example` document it | `inference/predictor.py`, `training/register_model.py`, `docker-compose.yml` |
| L12 | `/predict/batch` ran both forests once per row | `SentinelPredictor.predict_many` makes **one** classifier pass and **one** Isolation Forest pass for the whole batch. `predict()` is its one-row case, so single and batch results are identical. The batch route applies the same input policy (M2) per row | `inference/predictor.py`, `inference/main.py` |

## Verification

| Check | Result |
|---|---|
| New tests | `tests/test_low_priority_ml.py`, 16 tests:<br>• shadow error text not echoed<br>• telemetry bounds<br>• retry counted once, distinct flows all counted, independent calls counted<br>• unused import gone, SGD archive still loads, requirements fully pinned<br>• tuning baseline from the same split<br>• registry pin mismatch/match<br>• batch = one `predict_proba` call with results identical to single scoring; batch route makes one call<br>Plus `test_predictor::test_engine_has_no_ip_reputation_client` |
| Updated tests | `test_predictor.py`: the reputation-client unit tests were removed along with the client. `test_abuseipdb_decoupling.py`: "never called" became "no HTTP request during scoring". `test_api.py` / `test_high_priority_ml.py`: their test doubles gained `predict_many` |
| Full AI-engine pytest | **472 passed**, 0 failed |
| Live engine (`scripts/ai_engine_endpoint_check.py`) | **22/22 pass** (benign rows 92% BENIGN, attack rows 97% non-BENIGN). The script now reads each CSV in 100k-row chunks and samples randomly per chunk: with only ~0.6 GB of RAM free on this machine, the whole-file read failed with `out of memory` |
| Backend | No backend file changed in this pass. The last run was 1038 passed / 13 skipped |

With C1–C2, H1–H6, M1–M9 and L1–L12, every issue in the study guide's Phase 4 is now fixed or explicitly decided. The deliberate decisions are:
- **H2:** no class rename (needs a DB migration).
- **M4:** duplicate files kept (preserved assets).
- **M6:** the TCP-window features kept (measured).
- **H6:** the seed Q-table left unchanged (hash-pinned).
- **H1:** the paper PDF is still to be edited by you.
