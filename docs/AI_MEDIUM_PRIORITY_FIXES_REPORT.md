# SentinelAI AI Engine — Medium-Priority Fixes Report (M1–M9)

Date: 2026-10-21, branch `db-fixes`. The issues are defined in `docs/AI_ENGINE_STUDY_GUIDE.md`, Phase 4. This is separate from `docs/MEDIUM_PRIORITY_FIXES_REPORT.md`, which covers the earlier backend audit.

| ID | Issue | Status |
|---|---|---|
| M1 | Threat counter and severity bands differ between the engine and the backend | **Fixed** |
| M2 | Missing features take fabricated defaults | **Fixed:** flagged as `incompleteInput` and never auto-blocked |
| M3 | Artifact not reproducible, thin metadata | Fixed with C2 |
| M4 | Duplicate artifacts and a silent first-match fallback | **Fixed:** the registry is mandatory. Duplicates are documented, not deleted (they are preserved assets) |
| M5 | Unmapped labels silently become BENIGN | **Fixed** |
| M6 | Shortcut features (`init_win_bytes_*`) | **Measured** (§M6). Features kept |
| M7 | Drift reference is the capped/SMOTE mix; mean/variance on heavy tails | **Fixed:** PSI against benign training quantiles |
| M8 | `train.py --cv` evaluates a different recipe | **Fixed** |
| M9 | One static shared key for everything | **Fixed:** separate admin key for model reload; the engine has no host port |

## M1 — One threshold and severity scale

- `inference/main.py`: the engine's `THRESHOLD` (the `/model/stats` threat counter and the `/predict` callback line) now defaults to the alert line (0.90) instead of 0.70. `SCORE_THRESHOLD` still overrides it.
- Severity is anchored on the shared lines in both services:

  | Severity | Score |
  |---|---|
  | CRITICAL | ≥ block line (0.92) |
  | HIGH | ≥ alert line (0.90) |
  | MEDIUM | ≥ 0.50 |
  | LOW | below 0.50 |

  - Engine: `score_to_severity` in `predictor.py`. Backend: new `backend/utils/severity.js`.
  - `aiService.storePrediction` and `honeypotService` both use it.
  - Before, they used 0.90/0.70/0.50 (engine), 0.90/0.75 (backend threats) and 0.85/0.70/0.40 (honeypot threats).

## M2 — Incomplete input

- `inference/main.py` `_score` (all flow routes):
  - `defaultedFeatures` now covers **all** raw schema features the caller did not send under any recognised name. That includes `init_win_*`, `active_*`, `idle_*` and `down_up_ratio`, which the old list missed.
  - `incompleteInput = len(defaultedFeatures) > MAX_DEFAULTED_FEATURES` (default 5, overridable by environment).
  - When the input is incomplete, a `BLOCK` action is capped at `MONITOR`, with `actionCappedReason: "incomplete_input"`.
- Backend: `aiEngineService` passes `incompleteInput` through. `AIPrediction.incompleteInput` stores it (new field, default false). `aiService.storePrediction` never auto-blocks it: the threat is still created, but stays MONITORING.
- **Why not reject such payloads:** analyst `/api/ai/analyze` calls, demos and many tests send partial flows. The danger was an automatic block triggered by fabricated features, and that is what is prevented. The sniffer and the replay script send complete flows and are unaffected.

## M4 — Model registry

- `SentinelPredictor.load` refuses to load anything without `models/registry.json`. The legacy first-match order now requires `ALLOW_UNREGISTERED_MODELS=1`; the test suite sets it in `tests/conftest.py` for its throwaway model folders.
- A new test checks that production refuses.
- The duplicate and legacy files (an identical XGBoost pair, `.bak` files, synthetic models, the root `models/` copy) are listed in `docs/PRESERVED_ASSETS_SHA256.json`, so I did not delete them. `ai-engine/models/README.md` now says which two files are served and that nothing else is loaded.

## M5 — Labels

`prepare_features` raises `ValueError: N unmapped label(s): …` instead of `fillna(0)`. For example, a CSV with a real en-dash in "Web Attack – Brute Force" would previously have trained those attacks as BENIGN.

## M6 — Shortcut features

`day_holdout_eval.py` has a new option, `--drop-features a,b`. It sets those columns to 0; trees never split on a constant column, so this equals removing them.

I retrained without `init_win_bytes_forward` and `init_win_bytes_backward` (`experiments/c2_dedup_eval/ablation_no_init_win/`) and compared against the same protocols with them kept (`experiments/c2_dedup_eval/isolation_forest/`). Alert line 0.90.

| Protocol | Macro F1: with → without | Attack detection: with → without | Benign alert rate: with → without |
|---|---|---|---|
| Chronological | 0.750 → **0.619** | 78.8% → 78.8% | 0.20% → **1.76%** |
| Leave out Monday (benign only) | 0.995 → 0.972 | — | 0.08% → 0.99% |
| Leave out Wednesday | 0.267 → 0.260 | 0.2% → 0.3% | 0.01% → 0.41% |
| Leave out Thursday | 0.194 → 0.190 | 0.1% → 0.1% | 0.09% → 0.41% |
| Leave out Tue / Fri | ≈ unchanged | ≈ 0 | ≈ unchanged |

**Finding:** the TCP initial-window features are not what the model uses to *detect* attacks. Detection is the same without them. Their contribution is recognising *benign* hosts: without them benign false alerts rise about 9×, and BENIGN recall drops from 0.992 to 0.940. Removing them would not cure the generalisation gap either (leave-one-day-out stays ≈ 0).

**Decision:** keep them. Two things remain true:
- They encode testbed-specific OS defaults, so the benign alert rate on a different network will likely be higher than measured here.
- An attacker who mimics a benign host's window sizes gains little, because detection doesn't depend on them.

Both points belong in the paper's limitations.

## M7 — Drift reference

- `monitoring/drift.py`:
  - `benign_reference()` stores per-feature decile edges and bin fractions of the **benign training rows**.
  - `DriftMonitor.report_psi()` computes the Population Stability Index of the **benign-predicted** live flows against it. Attack traffic no longer counts as drift, and features that were constant in training (time of day) are skipped.
  - A feature drifts at PSI > 0.25; the window drifts when ≥ 10% of features do (same rule as before).
- `train.py` writes `drift_reference` into the model metadata.
- For the served `cicids_v3` model I added it from the identical deduplicated split: 74,682 benign rows and 41 informative features. Only the JSON metadata changed, not the pickle, so `register_model.py --check` still passes.
- `GET /model/drift` uses PSI when the reference exists (`"method": "psi_benign_quantiles"`) and falls back to the old scaler mean/variance otherwise. The backend drift alert prints `PSI x` per feature.

## M8 — Cross-validation recipe

`train.py --cv` now:
- folds the **training split only**, never the test rows;
- applies SMOTE inside each fold when `--smote` is set, via the shared `smote_strategy()`;
- adds dummy rows only for classes present in validation but missing from the fold, the same rule as the final model. Before, it forced all 11 classes.

## M9 — Admin key

- Engine: `POST /model/reload` uses `verify_admin_key`. When `SENTINEL_ADMIN_KEY` is set it requires `X-Admin-Key` (constant-time compare) in addition to `X-API-Key`. When unset it behaves as before and logs a warning at startup.
- Backend: `aiEngineService.reloadModel` sends `X-Admin-Key` from `AI_ENGINE_ADMIN_KEY`.
- `docker-compose.yml` passes one `SENTINEL_ADMIN_KEY` to both services. The env examples document both variables and the rotation step (update engine and backend together).
- The engine already had **no host port mapping** in Compose; it is reachable only on the internal network.

## Verification

| Check | Result |
|---|---|
| New engine tests | `tests/test_medium_priority_ml.py` (15): severity bands, threat counter, incomplete-input cap, alias counting, unmapped labels, PSI, endpoint PSI path, `smote_strategy`, CV on the training split, admin key. Plus `test_medium_fixes::test_missing_registry_refuses_to_guess_the_production_model` |
| New backend tests | `tests/aiMediumFixes.test.js` (8): severity scale, block vs incomplete-input. `aiDependencyContract.test.js` (+1): `X-Admin-Key` sent only when configured |
| Tests updated for the new behaviour | `test_replay_isolation.py`: its sample attack is now a complete flow, since partial flows no longer BLOCK. `test_feature_capture.py`: callback score 0.95, above the 0.90 callback line. `conftest.py` opts the suite in to unregistered test models |
| Full AI-engine pytest | **463 passed**, 0 failed |
| Full backend Jest | **1038 passed**, 13 skipped, 0 failed |
| Live engine (`scripts/ai_engine_endpoint_check.py`) | **22/22 pass**. Thresholds monitor 0.90, block 0.92, review 0.55; `/model/drift` responds |
| `register_model.py --check` | classifier OK, anomaly OK (only the v3 *metadata* gained `drift_reference`) |

**Behaviour changes to be aware of:**
- Engine `/model/stats.totalThreats` and `/predict` callbacks now count from 0.90, not 0.70.
- Threat severities are now relative to the alert/block lines, so most threats are CRITICAL (≥ 0.92) or HIGH.
- Payloads missing more than 5 features are never auto-blocked.
- The engine will not start serving without `models/registry.json`.
- Setting `SENTINEL_ADMIN_KEY` requires the backend to have the same value in `AI_ENGINE_ADMIN_KEY`, or reloads will get 403.
