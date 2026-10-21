# SentinelAI AI Engine — Study Guide and Verification Report (Phases 1–6)

Generated 2026-10-21 from branch `db-fixes` (HEAD `ec11c12`, clean tree). Every claim cites a file, a
function, or a command I ran. **NOT FOUND** means I searched and it isn't in the code.

## What I actually ran

| Check | Result |
|---|---|
| `ai-engine/.venv` | Python 3.11.9. Every package in `requirements.txt` is installed at its pinned version |
| `pytest` (ai-engine) | **393 passed**, 0 failed (69.6 s) |
| `python evaluation/reproduce_reported_metrics.py` (new, added in this pass) | Reproduces the paper **exactly**: deployed RF acc **0.9843**, weighted F1 **0.9862**, macro F1 **0.8448**; XGBoost acc **0.9913** |
| `python scripts/ai_engine_endpoint_check.py` (new, added in this pass) | Isolated engine on a random port; 22 checks, **21 pass, 1 fails on purpose** (it exposes the CSV-header skew bug, issue H4) |
| Model introspection (joblib) | All 18 model files inventoried: hashes, classes, params, scaler stats |
| Honeypot probe (in-process) | **All 6 session types were classified BENIGN** by the deployed model (issue C1, **fixed 2026-10-21**, see C1) |
| Chronological / leave-one-day-out numbers | Taken from the committed `experiments/c1_day_holdout_eval/results.json` (generated 2026-10-20). **I did not re-run that script** (it takes ~1 h) |
| Backend / MongoDB / Cowrie | **Not started.** I read the Node client code only |

## Your beliefs, checked first

| You believe | Verdict | Evidence |
|---|---|---|
| FastAPI service | **Correct** | `ai-engine/inference/main.py:74` `app = FastAPI(...)` |
| RF + XGBoost for classification, IsolationForest for anomalies | **Partly.** RF and IF are both **served**. XGBoost is **trained but not served**: the registry pins the RF only | `ai-engine/models/registry.json` → `rf_classifier_cicids_v2.pkl` + `isolation_forest_cicids.pkl`. XGBoost would only load if you re-registered it |
| Tabular Q-learning deception scorer, updates at runtime, linked to Cowrie | **Correct.** It updates on every scored session. An optional rotator **can** now apply its advice to Cowrie | `rl_engine/deception_scorer.py`, `honeypot/deception_rotator.py` |
| Trained on CICIDS2017 | **Correct.** All **8** CSVs (all five days) are used. Your paper says "four" | `ai-engine/datasets/cicids2017/*.csv`, `training/train.py:42` |
| Called by the Node/Express backend | **Correct** | `backend/services/aiEngineService.js:8-14` (axios, `X-API-Key`) |
| DL / PPO / DQN / BERT / EWC are future work | **Correct. None of them is in the code** | grep across `ai-engine/` finds no torch, tensorflow, transformers or PPO/DQN code |
| *(implied)* No supervised retraining loop | **REFUTED.** A human-gated, offline retraining pipeline exists. It has **never been run** | `training/retrain_from_samples.py`. No `experiments/retraining/` directory exists |

---

# PHASE 1 — MAP OF THE AI ENGINE

## 1.1 Folder structure (tracked files only; `.venv/` and `__pycache__` omitted)

```
ai-engine/
├── inference/            ← THE SERVICE
│   ├── main.py           FastAPI app: routes, auth, Pydantic schemas, stats, drift, reload
│   ├── predictor.py      SentinelPredictor: loads models, scores flows, fuses RF+IF, SHAP
│   ├── deception.py      Singleton factory for the Q-learning scorer (path safety, seed copy)
│   └── errors.py         ModelUnavailableError
├── rl_engine/
│   └── deception_scorer.py   Q-learner, reward function, locked atomic Q-table persistence
├── utils/
│   ├── features.py       53-feature schema, label mapping, train-time & serve-time feature builders
│   └── data_generator.py Synthetic CICIDS-like flows (used by --synthetic training and tests)
├── training/
│   ├── train.py          Offline training CLI (RF / XGBoost / Stacking + IsolationForest)
│   ├── register_model.py Pins deployed models by SHA-256 in models/registry.json
│   └── retrain_from_samples.py  Offline retrain with analyst samples, gated promotion
├── evaluation/
│   ├── day_holdout_eval.py   Random vs chronological vs leave-one-day-out evaluation
│   ├── evaluate_model.py     Older evaluator (metadata/integrity, KS drift helper, synthetic eval)
│   └── reproduce_reported_metrics.py   NEW — re-scores the shipped models on train.py's exact split
├── monitoring/drift.py   Rolling-window input drift vs the scaler's training statistics
├── modular/              Shadow-mode rule detectors (volumetric flood, auth abuse, WAF) — off by default
├── demo/replay_cicids.py Replays real CICIDS rows to /predict/eval or the backend
├── models/               Model artifacts (see 1.5), registry.json, q_table.json (seed)
├── datasets/cicids2017/  8 CICIDS2017 MachineLearningCVE CSVs (~885 MB)
├── datasets/synthetic.csv, datasets/honeypot_derived/flows.csv
├── experiments/          ~40 audit/evaluation folders (gate1_*, c1_day_holdout_eval)
├── tests/                28 pytest test modules + conftest.py
├── requirements.txt, Dockerfile, .env.example, .python-version (3.11)
models/                   ← ROOT-LEVEL DUPLICATE COPY (not loaded by anything; see 1.5)
scripts/ai_engine_endpoint_check.py   NEW — live HTTP check of every endpoint
```

**Notebooks:** NOT FOUND (no `.ipynb` anywhere in the repo). All training is the `train.py` script.

## 1.2 How the FastAPI app boots

1. **Entry point.** `uvicorn inference.main:app`, run from `ai-engine/`.
   - Docker: `ai-engine/Dockerfile:27` binds `0.0.0.0:8000`.
   - Standalone `python -m inference.main`: `main.py:396-416` binds `AI_ENGINE_HOST` (default `127.0.0.1`) and `AI_ENGINE_PORT` (default `8000`).
2. **`.env` loading.** `main.py:17-19` loads `ai-engine/.env` (`override=False`, so real env vars win). It is skipped under pytest. This happens *before* `predictor.py` is imported, because the thresholds are read at import time (`predictor.py:95-100`).
3. **Fail-closed key check.** `main.py:48-51`: no `SENTINEL_KEY` means a `RuntimeError` and the process never starts.
4. **Model directory.** `main.py:45-46`: `MODEL_DIR` defaults to `ai-engine/models`. A relative path is resolved against `ai-engine/`, not your shell's working directory.
5. **Model load: once, at startup, never per request.** `lifespan()` (`main.py:58-63`) builds one `SentinelPredictor(model_dir=MODEL_DIR)`. Inside `SentinelPredictor.load()` (`predictor.py:190-303`):
   - a. Reads `models/registry.json` (`load_registry`, `predictor.py:157-176`).
   - b. SHA-256 of both pinned files must match the registry (`:223-231`). Otherwise inference is unavailable and `/ready` returns 503.
   - c. The installed scikit-learn must equal `registry.sklearn_version` (`1.4.0`) unless `ALLOW_SKLEARN_MISMATCH=1` (`:234-240`).
   - d. `joblib.load` of the classifier and the IF (`:278-280`).
   - e. Schema guards: `n_features_in_ == 53` and metadata `feature_names == FEATURE_NAMES` (`:289-296`).
   - f. A SHAP `TreeExplainer` is built (`:337-354`), plus optional shadow detectors (`:305-335`).
   - Without a registry, a legacy "first file that exists" order applies (`:200-208`, `:252-259`).
6. **The Q-learner loads lazily**, on the first `/deception/*` call (`deception.py:17-98`). It is flushed to disk on shutdown (`main.py:64-72`).
7. **Hot swap.** `POST /model/reload` (`main.py:261-275`) builds a new predictor and swaps it in only if it loaded and verified.

## 1.3 Environment variables (all read in code)

| Variable | Default | Read at | Purpose |
|---|---|---|---|
| `SENTINEL_KEY` | **required** | `main.py:48` | Shared secret; `X-API-Key` on every protected route; also sent on callbacks |
| `MODEL_DIR` | `ai-engine/models` | `main.py:45`, `deception.py:21` | Where registry + pickles live |
| `SENTINEL_API` | `http://localhost:5000/api` | `main.py:47` | Backend URL for `_notify` callbacks |
| `SCORE_THRESHOLD` | `0.7` | `main.py:53` | Engine-side "threat" counter + callback line (≠ the alert line; see M1) |
| `ALERT_THRESHOLD` | `0.85` | `predictor.py:100` | MONITOR line |
| `BLOCK_THRESHOLD` | `0.92` | `predictor.py:95` | BLOCK line |
| `CORS_ORIGINS` | `http://localhost:5000` | `main.py:95-99` | CORS allow-list |
| `METRICS_TOKEN` | unset → loopback only | `main.py:221-225` | `/metrics` access |
| `ALLOW_SKLEARN_MISMATCH` | off | `predictor.py:237` | Override the pickle-version guard |
| `Q_TABLE_PATH`, `DEFAULT_RUNTIME_Q_TABLE_PATH` | `%LOCALAPPDATA%\SentinelAI\runtime\q_table.json` | `deception.py:29-36`, `deception_scorer.py:57-66` | Runtime Q-table location |
| `SENTINEL_ALLOW_REPO_RUNTIME_WRITE` | off | `deception_scorer.py:45` | Allow writing `ai-engine/runtime/q_table.json` |
| `Q_SAVE_EVERY` | `1` | `deception_scorer.py:276` | Save every N episodes |
| `DRIFT_WINDOW`, `DRIFT_MIN_SAMPLES` | 2000, 200 | `drift.py:36-37` | Drift monitor window |
| `ENABLE_SHADOW_B2`, `ENABLE_SHADOW_E2` | false | `predictor.py:306,321` | Shadow rule detectors |
| `AI_ENGINE_HOST/PORT/RELOAD`, `SENTINEL_ENV` | 127.0.0.1 / 8000 | `main.py:405-415` | Standalone runner only |
| `ABUSEIPDB_API_KEY` | unset | `predictor.py:54` | Only inside `get_ip_reputation`, which **no code calls any more** |

## 1.4 Dependencies (`ai-engine/requirements.txt`, all match the installed `.venv`)

| Package | Pin | Why it is there |
|---|---|---|
| fastapi | 0.109.2 | HTTP API, dependency-injected auth (`Depends(verify_api_key)`) |
| uvicorn[standard] | 0.27.1 | ASGI server |
| pydantic | 2.6.1 | Request schemas `Record`, `SessionData` (`main.py:114-161`) |
| scikit-learn | **1.4.0** | RF, IsolationForest, StandardScaler, Pipeline, metrics. **Pinned hard**: the pickles were written by 1.4.0 and the loader refuses other versions |
| xgboost | 2.0.3 | XGBClassifier (trained, not served) |
| numpy / pandas | 1.26.4 / 2.2.0 | Arrays / CSV loading |
| joblib | 1.5.3 | Model (de)serialisation |
| shap | 0.45.1 | `?explain=true` per-prediction feature contributions |
| imbalanced-learn | 0.12.0 | SMOTE (`train.py --smote`) |
| httpx | 0.26.0 | Async callbacks to the backend (`main.py:196`) |
| requests | 2.31.0 | Legacy AbuseIPDB call (dead code) and demo scripts |
| python-dotenv | 1.0.1 | `.env` loading |
| pytest | `>=8.0.0` (**unpinned**; 9.1.1 installed) | Tests |
| *scipy* | **not listed** (1.17.1 arrives with scikit-learn) | Used directly by `evaluate_model.py:309` (KS test) |

## 1.5 Every model file in the repo

`sha` is the first 12 hex digits of SHA-256. "Loaded by" means a code path that loads the file at runtime.

| File | Size | Modified | sha | What it is (introspected) | Loaded by |
|---|---|---|---|---|---|
| **`ai-engine/models/rf_classifier_cicids_v2.pkl`** | 46.2 MB | 2026-08-09 | `ca0efb1fde8f` | Scaler+RF, 200 trees, depth 20, classes 0–10, **121,827 training rows** | **SERVED.** Pinned in `registry.json`; also `day_holdout_eval.run_deployed`, `evaluate_model.py:142` |
| **`ai-engine/models/isolation_forest_cicids.pkl`** | 1.4 MB | 2026-08-09 | `17bd08ffe105` | Scaler+IF, 200 trees, contamination 0.1, 80,000 benign rows, `offset_` −0.4740 | **SERVED** (registry) |
| `ai-engine/models/rf_classifier_cicids.pkl` | 39.0 MB | 2026-08-08 | `b7beff5602e3` | RF v1, 118,413 rows | Legacy fallback #2 (`predictor.py:202`), only with no registry |
| `ai-engine/models/xgb_classifier_cicids.pkl` | 3.6 MB | 2026-08-09 | `a5d630b471b0` | XGB, 200 trees, depth 6, lr 0.1, real CICIDS | Fallback #4; nothing else |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | 3.6 MB | 2026-08-08 | `a5d630b471b0` | **Byte-identical duplicate** of the file above | Fallback #3 |
| `ai-engine/models/xgb_classifier_cicids.pkl.bak` | 2.6 MB | 2026-08-08 | `727ff477dc9f` | Older XGB (156,635 rows) | Nothing |
| `ai-engine/models/stacking_classifier_cicids.pkl` | 44.0 MB | 2026-08-09 | `b82fdd26dad9` | RF+XGB → LogisticRegression, classes 0–9 | Fallback #7 |
| `ai-engine/models/rf_classifier_v2.1.pkl` | 36.3 MB | 2026-08-08 | `de57c85d53e1` | RF on **synthetic** data (16,000 rows) | Fallback #5 |
| `ai-engine/models/xgb_classifier.pkl` | 3.2 MB | 2026-08-08 | `5190065e138e` | XGB on **synthetic** data | Fallback #6 |
| `ai-engine/models/isolation_forest_v1.4.pkl` | 2.7 MB | 2026-08-08 | `569c30de7762` | IF on **synthetic** data | IF fallback (`predictor.py:269`) |
| `ai-engine/models/q_table.json` | 1 KB | 2026-10-06 | `bf9b46a1d1cf` | Seed Q-table, 12,087 episodes | Copied once to the runtime path (`deception.py:90-96`); never written |
| **`models/rf_classifier_cicids_v2.pkl` (root)** | 40.8 MB | 2026-08-14 | `a7f98d2e5946` | Different RF: classes 0–9, 118,412 rows | **Nothing** |
| `models/isolation_forest_cicids.pkl` (root) | 1.4 MB | 2026-08-14 | `17bd08ffe105` | **Identical** to the served IF | Nothing |
| `models/sgd_classifier_cicids.pkl` (root) | <0.1 MB | 2026-08-14 | `6e477db242c2` | SGDClassifier, classes 0–9 (loads fine under sklearn 1.4.0) | **Nothing** (no SGD code exists) |
| `experiments/gate1_phase8/…/candidate_rf_multicorpus_v1.pkl`, `phase10/…v2_fixed.pkl`, `phase10/disposable_rf_phase10_v1.pkl`, `phase13/…v3.pkl` | 6–28 MB | 2026-10-18 | — | Experiment candidates; **fail to unpickle** in the pinned env (`IndexError`) | Nothing |
| `experiments/…/calibration_models.joblib`, `candidate_v3_calibration.pkl` | <0.1 MB | 2026-10-18 | — | Calibration dicts | Nothing |
| `ai-engine/runtime/q_table.json` (git-ignored) | 1 KB | 2026-10-17 | — | Old repo-runtime table, 99 episodes | Only if `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1` |

**Duplicates flagged:**
- `xgb_classifier_cicids.pkl` ≡ `xgb_classifier_cicids_v2.pkl` (same hash, even though their metadata dates differ).
- Root `models/isolation_forest_cicids.pkl` ≡ the served IF.
- Root `models/rf_classifier_cicids_v2.pkl` is a **different model under the same name**: it disagrees with the served RF on **94 of 29,603** test rows (0.32%) and scores slightly better (acc 0.9863, macro F1 0.8714). It was almost certainly written by running `train.py` from the repo root, because `--model-dir` defaults to the relative `models` (`train.py:569`).

---

# PHASE 2 — HOW IT WORKS, FROM SCRATCH

## 2.1 Data

**Files.** `train.py --data datasets/cicids2017` globs every `*.csv` in the folder (`train.py:42`). That is all 8 MachineLearningCVE files, Monday to Friday. These CSVs have **no Timestamp, Flow ID or IP columns** (the header starts `Destination Port, Flow Duration, …`). That fact matters for the leakage discussion in 2.2.

**Loading** (`train.py:47-137`), step by step:

1. Scan every file's `Label` column to print the raw distribution (`:47-57`).
2. Per file, read only the columns the schema needs (`:72-101`), strip header whitespace, and map labels (`:104-109`).
3. **Cleaning** (`:112-115`). Every feature is coerced to numeric (`errors='coerce'`), `±inf` becomes NaN, and **rows with any NaN are dropped**. This mainly hits `Flow Bytes/s` and `Flow Packets/s`, which CICFlowMeter writes as `Infinity` or `NaN` when the duration is 0.
4. **Duplicates: NOT FOUND.** There is no `drop_duplicates` anywhere in `train.py`. I measured **23,514 exact duplicate rows (15.9%)** in the final training frame (see H3).
5. **Per-file pre-cap** (`:118-132`): BENIGN ≤ 15,000, Port Scan ≤ 10,000, DDoS ≤ 10,000 *per file*, random sample with seed 42.
6. **Global cap** (`:164-184`): BENIGN ≤ 100,000, Port Scan ≤ 40,000, DDoS ≤ 40,000.

**Label mapping.** The model is **multi-class (11 target classes)**, not binary (`features.py:40-63`):

| Raw CICIDS label | rows (raw) | → Target class |
|---|---|---|
| BENIGN | 2,273,097 | BENIGN (0) |
| SSH-Patator | 5,897 | SSH Brute Force (1) |
| Web Attack – Sql Injection | 21 | SQL Injection (2) |
| PortScan | 158,930 | Port Scan (3) |
| DDoS, DoS Hulk, DoS GoldenEye, DoS slowloris, DoS Slowhttptest | 128,027 + 231,073 + 10,293 + 5,796 + 5,499 | **DDoS (4)** — five different attacks merged |
| Heartbleed | 11 | **RCE Attempt (5)** |
| Web Attack – XSS | 652 | XSS Attempt (6) |
| Bot | 1,966 | Malware Beacon (7) |
| FTP-Patator, Web Attack – Brute Force | 7,938 + 1,507 | **Credential Stuffing (8)** — FTP and HTTP brute force merged |
| Infiltration | 36 | Lateral Movement (9) |
| — | 0 | **Data Exfiltration (10): no real rows at all** |

The web-attack labels contain the byte `U+FFFD` (the CSV's broken en-dash), and the mapping keys use the same character. I verified the counts land in the right classes. Any label that is *not* in the map silently becomes **BENIGN** (`features.py:513`, `.fillna(0)`). See M5.

**Class balance**, as reproduced by running `train.py`'s own code:

| Class | After cleaning + caps (train+test) | Train (80%) | Test (20%) | Deployed model's training rows (after SMOTE) |
|---|---|---|---|---|
| BENIGN | 100,000 | 80,000 | 20,000 | 80,000 |
| DDoS | 20,000 | 16,000 | 4,000 | 16,000 |
| Port Scan | 10,000 | 8,000 | 2,000 | 8,000 |
| Credential Stuffing | 9,442 | 7,554 | 1,888 | 7,554 |
| SSH Brute Force | 5,897 | 4,717 | 1,180 | 4,717 |
| Malware Beacon | 1,956 | 1,565 | 391 | **4,000** (+2,435 SMOTE) |
| XSS Attempt | 652 | 521 | 131 | **1,500** (+979 SMOTE) |
| Lateral Movement | 36 | 29 | 7 | 29 |
| SQL Injection | 21 | 17 | 4 | 17 |
| RCE Attempt | 11 | 9 | 2 | 9 |
| Data Exfiltration | 0 | 0 | 0 | **1 all-zero dummy row** |
| **Total** | 148,015 | 118,412 | 29,603 | **121,827** |

The last column is a deduction, but the arithmetic is exact:
- The served RF's scaler reports `n_samples_seen_ = 121,827`.
- That equals 118,412 + 2,435 + 979 + 1.
- 2,435 and 979 are exactly what `train.py --smote` adds (Malware Beacon → `max(n+1, 4000)`, XSS → `max(n+1, 1500)`, `train.py:204-207`).
- The final 1 is a zero-vector dummy row for class 10.

So **the deployed RF was trained with `--smote`**, even though your paper says SMOTE was not applied (see H1). DDoS was capped to 20,000 of 380,688 and Port Scan to 10,000 of 158,930, because the 10k per-file pre-cap bites first.

## 2.2 Features

**Exact list (53, in this order):** `utils/features.py:12-30`.
- 49 CICFlowMeter statistics: duration, packet counts/lengths, bytes/s, packets/s, IAT stats, flag counts, header lengths, bulk averages, initial windows, active/idle, down/up ratio.
- 1 engineered feature: `payload_entropy`.
- 2 time features: `time_of_day_sin`, `time_of_day_cos`.

`Destination Port` is **not** used.

**Engineering steps:**

| Step | Train time | Serve time |
|---|---|---|
| Column → schema mapping | `prepare_features` (`features.py:431-517`), name candidates in `CANDIDATES` (`:65-131`) | `extract_features_from_record` (`:240-319`), same `CANDIDATES` |
| `payload_entropy` | Shannon entropy of the fwd/bwd byte split: `−p_f·log2 p_f − p_b·log2 p_b` (`:472-487`) | `compute_payload_entropy` (`:133-144`), same formula |
| Time of day | Column absent in the CSVs → filled with **0.0** (`:467`, listed in `KNOWN_ABSENT_FEATURES` `:426`) | `compute_time_of_day(timestamp)` → (sin, cos) of the UTC hour; **missing timestamp → (0.0, 0.0)** (`:146-238`) |
| Missing / non-numeric | `to_numeric(...).fillna(0.0)`, `inf → 0` (`:449, :498`). The rows were already dropped by `train.py` | Pydantic rejects NaN/inf with **422** (`main.py:141-153`). **Absent fields take `Record` defaults** (`main.py:115-137`, e.g. `flow_duration=1000`, `flow_bytes_per_sec=60000`), **not 0** (see M2) |
| Scaling | `StandardScaler` as step 1 of the sklearn `Pipeline` (`train.py:313`) | The same pickled pipeline applies the same fitted scaler. There is no separate scaler file, so the two cannot drift apart |
| Encoding | None needed (all numeric); labels are mapped to ints | — |
| Feature selection | **NOT FOUND.** No MI, RFE or importance pruning; all 53 go in. `log_transform_features` (`features.py:519-528`) is imported but **never called** | — |

**Where the time-of-day leakage fix lives.** `compute_time_of_day` (`features.py:146-238`):
- Its docstring (`:154-158`) states the policy: no `datetime.now()` fallback.
- Bad or missing timestamps return `(0.0, 0.0)` (`:165-166`, `:227-228`, `:230-232`).
- Before the fix, a missing timestamp used the *server's wall clock*. Training rows had 0.0, so serve-time values were a different distribution. That is train/serve skew, and worse, the hour of *scoring* could influence the prediction.
- `drift.py:66` also excludes zero-variance features (the time pair) from the drift verdict.

**Proof that the time features do nothing in the shipped models** (commands in Phase 3):
- Scaler variance of `time_of_day_sin/cos` is **0** in every CICIDS artifact. That covers the served RF, the root RF, XGB, stacking, the IF, and SGD.
- RF importance **0.0**, XGB importance **0.0**.
- Feeding the training-mean flow with each of the 24 hours gives **identical probabilities** (`np.allclose` = True).

The synthetic models (`rf_classifier_v2.1`, `xgb_classifier`, `isolation_forest_v1.4`) *do* have non-zero time variance (0.33–0.44), but they are not served.

Four more features are dead in the served RF (importance 0): `bwd_psh_flags`, `bwd_urg_flags`, `fwd_avg_bytes_per_bulk`, `bwd_avg_bytes_per_bulk`. They are constant in CICIDS2017.

## 2.3 Training

| Item | Value | Where |
|---|---|---|
| Split | **Random, row-level, stratified 80/20**, `random_state=42`. Not time-based | `train.py:196` |
| RF | `n_estimators=200, max_depth=20, min_samples_split=5, min_samples_leaf=1, class_weight="balanced", random_state=42` | `train.py:23` |
| XGBoost | `n_estimators=200, max_depth=6, learning_rate=0.1, eval_metric="mlogloss", random_state=42`, plus `compute_sample_weight("balanced")` | `train.py:261-264` |
| IsolationForest | `n_estimators=200, contamination=0.1, max_samples="auto", random_state=42`, fitted on **benign training rows only** (80,000) | `train.py:24, 545-548` |
| Stacking | RF + XGB base models, LogisticRegression meta-learner, `cv=3` | `train.py:277-296` |
| SMOTE | Optional `--smote`, applied **after** the split, to train only (correct) | `train.py:199-232` |
| Dummy rows | A zero vector for any class missing from train | `train.py:236-242` |
| Tuning | Optional `--tune`: `RandomizedSearchCV` (15 draws, 3-fold, `f1_macro`) over trees {200,400,600} × depth {15,20,30,None} × leaf {1,2,4} | `train.py:324-376` |
| Cross-validation | Optional `--cv`: 5-fold stratified, on the **whole** dataset, without SMOTE | `train.py:420-500` |
| Seeds | 42 everywhere (sampling, split, models, SMOTE) | — |

**How the hyperparameters were chosen:**
- **NOT FOUND:** any record of a search that produced `RF_PARAMS`. They are fixed constants.
- The `--tune` path compares against hard-coded "baseline" numbers (`train.py:325-327`), and nothing records whether it was ever run.
- XGBoost uses common defaults.
- `contamination=0.1` is a guess at the anomaly fraction. It only sets `offset_`, and the live threshold (−0.55) was chosen separately (2.5).

**Is the deployed artifact reproducible from today's `train.py`? Not exactly.**
- Today's dummy-row logic (`:236`) only adds classes that appear in train ∪ test. Class 10 appears in neither, so today's code would produce classes 0–9, like the root copy and the stacking model.
- The served RF has classes 0–10, so it came from an earlier `train.py`.
- The metadata records neither `--smote` nor the parameters, data hash, or git commit (`train.py:505-508`).

## 2.4 Evaluation

**What `train.py` computes** (`:381-398`), on the 20% random test split:
- accuracy, weighted F1, macro F1
- the full `classification_report` (per-class precision, recall, F1, support)
- the confusion matrix
- feature importances

Only accuracy, weighted F1 and macro F1 are saved into the metadata.

**Re-computed by me on that exact split** (`evaluation/reproduce_reported_metrics.py`), served RF:

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.9984 | 0.9878 | 0.9931 | 20,000 |
| SSH Brute Force | 1.0000 | 0.9932 | 0.9966 | 1,180 |
| SQL Injection | 0.3333 | 0.2500 | **0.2857** | **4** |
| Port Scan | 0.9990 | 0.9990 | 0.9990 | 2,000 |
| DDoS | 0.9960 | 0.9975 | 0.9968 | 4,000 |
| RCE Attempt | 1.0000 | 1.0000 | 1.0000 | **2** |
| XSS Attempt | 0.3814 | 0.8473 | **0.5261** | 131 |
| Malware Beacon | 0.6419 | 0.9949 | 0.7803 | 391 |
| Credential Stuffing | 0.9902 | 0.9073 | 0.9469 | 1,888 |
| Lateral Movement | 1.0000 | 0.8571 | 0.9231 | **7** |
| **accuracy / macro / weighted** | | | **0.9843 / 0.8448 / 0.9862** | 29,603 |

How to read it:
- **Benign rows predicted as attacks: 244 of 20,000 (1.22%).** 217 of those become "Malware Beacon", which is why Beacon precision is only 0.64.
- **Web Brute Force vs XSS**: 170 Credential Stuffing rows are predicted as XSS. In flow statistics both are "many short HTTP requests to one server", so they look alike.
- Classes with 2–7 test rows have F1 values that mean almost nothing. One more correct row moves them by 15–50 points.

**The independent evaluations already in the repo** (`evaluation/day_holdout_eval.py`, results in `experiments/c1_day_holdout_eval/results_summary.md`, generated 2026-10-20, not re-run by me):

| Protocol | Accuracy | Macro F1 | Benign alert rate | Attack detection |
|---|---|---|---|---|
| Random 80/20 (retrained, same recipe) | 0.9869 | 0.8778 | 0.43% | 97.7% |
| **Chronological** (first 70% of each file/class → train, 1% gap, last 29% → test) | 0.9757 | **0.7390** | 0.50% | 89.7% |
| **Leave-one-day-out**: Tuesday / Wednesday / Thursday / Friday | 0.59 / 0.66 / 0.94 / 0.75 | 0.19–0.29 | 0.02–0.54% | **≈ 0%** |

So the model recognises **attack types it has seen**. When the only examples of an attack come from a held-out day it detects essentially nothing, and the IsolationForest does not rescue it (H5). Malware Beacon recall drops from 0.99 (random split) to **0.13** (chronological).

## 2.5 Inference — every endpoint

Every route except `/health`, `/ready` and `/metrics` requires `X-API-Key == SENTINEL_KEY`, compared in constant time (`main.py:108-112`): missing → 401, wrong → 403. Inference routes are plain `def`, so FastAPI runs them in a thread pool, and shared state is lock-protected (`main.py:172-175`).

| Route | Input | What runs | Side effects | Caller |
|---|---|---|---|---|
| `GET /health` | — | — | — | liveness |
| `GET /ready` | — | 503 unless the models loaded and verified | — | backend `getHealth` |
| `GET /model/info` | — | thresholds, versions, metrics, registry | — | backend |
| `GET /model/stats` | — | counters | — | backend |
| `GET /metrics` | bearer or loopback | Prometheus text | — | Prometheus |
| `GET /model/drift` | — | `DriftMonitor.report` vs the scaler's mean/var | — | backend `driftMonitorService` |
| `POST /model/reload` | — | re-load registry models, atomic swap | swaps predictor | backend admin route |
| `POST /predict` | `Record` | full flow pipeline | stats, drift, **callback to backend** if score ≥ 0.7 | legacy / direct |
| **`POST /predict/internal`** | `Record` | full flow pipeline; returns the raw `featureVector` | stats, drift; no callback | **backend `predictRecord`** (`aiEngineService.js:68`) |
| `POST /predict/eval` | `Record` | full flow pipeline | **none** (no stats, no callback) | `demo/replay_cicids.py` |
| `POST /predict/batch` | `List[Record]` ≤ 500 | loop of `predict` | stats, callbacks | — |
| `POST /predict/honeypot` | `SessionData` | `predict_from_honeypot` | stats, callback | — |
| **`POST /predict/honeypot/internal`** | `SessionData` | `predict_from_honeypot` | stats | **backend** (`aiEngineService.js:223`) |
| **`POST /deception/score`** | `SessionData` | `SessionScorer.process_session` → **Q-update + save** | Q-table file | **backend** (`:231`; deliberately not retried) |
| `GET /deception/recommendation?current=` | profile name | ε-greedy `choose_action` (no update) | — | backend → `honeypot/deception_rotator.py` |
| `POST /predict/auth/shadow` | `AuthTelemetryRecord` | shadow E2 rules if enabled | — | — |

**The flow pipeline**, `SentinelPredictor.predict` (`predictor.py:424-492`):

1. **Validate.** Pydantic `Record` (`main.py:114-153`). Unknown extra fields are allowed; non-finite feature values give 422.
2. **Build the vector.** `extract_features_from_record(record.model_dump())` → 53 floats (`features.py:240-319`).
3. **Classify.** One forest pass: `predict_proba` → class = argmax, `max_p` = its probability (`_classify`, `:375-386`).
4. **Anomaly score.** `if_score = IF.score_samples(scaler(X))`. Lower means more anomalous; median benign ≈ −0.41 (measured on 3,000 Monday rows), threshold −0.55 (`:444-445`).
   - `isAnomaly = if_score < −0.55`.
   - `if_sig = clip((−0.55 − if_score) / 0.20, 0, 1)` (`anomaly_signal`, `:110-123`).
5. **Fuse.** This is not voting and not stacking: it is a **fixed rule** (`combine_threat_score`, `:125-137`):
   ```
   rf_s  = max_p            if class ≠ BENIGN   else 1 − max_p
   blend = 0.7·rf_s + 0.3·if_sig
   threatScore = max(rf_s, blend)   for attack classes   (confidence is a floor; the anomaly can only raise it)
               = blend              for BENIGN
   if class == BENIGN and isAnomaly:  class = "Unknown", threatScore = max(threatScore, 0.55)
   ```
6. **Decide.** `BLOCK` if score ≥ 0.92, `MONITOR` if ≥ 0.85, else `ALLOW` (`:473`). Severity: ≥0.90 CRITICAL, ≥0.70 HIGH, ≥0.50 MEDIUM, else LOW (`:139-143`).
7. **Explain (optional).** `?explain=true` gives the top-5 SHAP contributions for the predicted class (`:388-422`).

**Response** (`/predict/internal`; the public routes strip `featureVector` and `featureSchemaVersion`, `main.py:167-170`):

```json
{"success": true, "result": {
  "predictedClass": "DDoS", "threatScore": 0.9987, "severity": "CRITICAL", "confidence": 0.9987,
  "isAnomaly": false, "anomalyScore": -0.4312, "classProbabilities": {"BENIGN": 0.0, "DDoS": 0.9987, "...": 0},
  "inferenceTimeMs": 36.4, "action": "BLOCK", "modelVersion": "rf_cicids_v2.0", "featureImportance": [],
  "ipReputationScore": null, "featureVector": [53 floats], "featureSchemaVersion": "v2.1_53feat",
  "defaultedFeatures": ["...fields the caller did not send..."]}}
```

The backend creates a threat when `threatScore ≥ alert line (0.85)` **and** `predictedClass ≠ "BENIGN"` (`backend/services/aiService.js:71-73`). It auto-blocks at ≥ 0.92 only when the `autoBlockEnabled` setting is true (`:92-97`).

**The honeypot path**, `predict_from_honeypot` (`predictor.py`, after the C1 fix):
- Cowrie sessions contain no packet statistics, so **no model runs**.
- `classify_honeypot_session` (`utils/features.py`) picks the class with **keyword rules**, checked in this order:
  1. failed login → "SSH Brute Force";
  2. logged in, no commands → "Port Scan";
  3. ≥ 3 IOCs, duration over 120 s, or `scp/tar/nc…` → "Data Exfiltration";
  4. `ssh/nmap/ping…` → "Lateral Movement";
  5. `wget/curl/chmod…` → "RCE Attempt";
  6. anything else → "BENIGN".
- Score = `HONEYPOT_RULE_SCORES[class]`: BENIGN 0.40, Port Scan 0.75, SSH Brute Force 0.86, Lateral Movement 0.90, RCE 0.93, Exfiltration 0.95. Non-BENIGN classes get `+0.01` per command, capped at 0.99.
- The response says `classificationMethod: "honeypot_rules"` and `modelVersion: "honeypot_rules_v1"`; `confidence` and `anomalyScore` are null. The backend stores it as `modelType: "rules"`.
- *Before the fix:* the rules built a fake flow from synthetic-generator means and pushed it through the RF, which scored **every** profile BENIGN (0.08–0.11).

## 2.6 The Q-learning deception scorer

**Where:** `rl_engine/deception_scorer.py`. Wired through `inference/deception.py` and `main.py:339-360`.

| Element | Implementation | Where |
|---|---|---|
| **States S** | The 6 honeypot personas: `ubuntu_22, debian_11, centos_7, windows_srv, aws_ec2, raspberry_pi`. State = the persona served **before** this session (`previousProfile`, or the last one seen) | `:73-81`, `:300-301` |
| **Actions A** | The same 6 personas. Action = the persona that was **active during** this session | `:298-299` |
| **Next state s′** | Set equal to the action (`update(state, active, reward, active)`) | `:305` |
| **Reward r** | `2·ln(1 + duration/60) + 0.3·#commands + Σ intent bonus + 0.5·#IOCs + 2·(login succeeded)`, **capped at 20**. Bonuses: MALWARE_DOWNLOAD 3.0, REVERSE_SHELL 2.5, PERSISTENCE 2.0, CREDENTIAL_HARVEST 1.5, PRIVILEGE_ESCALATION 1.5 | `calc_reward`, `:83-94` |
| **Negative reward** (paper: "negative rewards for detected honeypot identification") | **NOT FOUND.** The reward is always ≥ 0 | — |
| **α (learning rate)** | 0.1 | `:139` |
| **γ (discount)** | 0.9 | `:139` |
| **ε (exploration)** | 0.2, decayed as `ε / (1 + 0.01·episodes)` | `choose_action`, `:266-269` |
| **Initialisation** | All Q = 0.0 (`:142`). Then overwritten by the file at `q_table_path` if it exists; on first run the runtime file is created as a byte copy of the seed `models/q_table.json` | `_load` `:149-160`; `deception.py:90-96` |
| **Update** | `Q(s,a) ← Q(s,a) + α·[r + γ·max_a′ Q(s′,a′) − Q(s,a)]`, rounded to 4 dp | `_td_update`, `:162-169` |
| **Persistence** | After **every** episode (`Q_SAVE_EVERY=1`). Cross-process `O_EXCL` lock file, merge-and-replay if another process wrote meanwhile, write temp + `fsync` + `os.replace` (atomic) | `save`, `:184-264`; lock `:108-135`; merge `:171-182` |
| **Reload** | Read on first `get_scorer()` call after startup; flushed on shutdown | `deception.py:17-98`, `main.py:64-72` |
| **Write protection** | Never writes into `models/`; the repo `runtime/` needs explicit opt-in; tests get a per-PID temp file | `:197-229`, `:47-71` |
| **Concurrency** | In-process `_scorer_lock` around every call (`main.py:341, 354`) plus the file lock | — |
| **Convergence check** | **NOT FOUND.** Only `reward_history` (last 100) and `avgRecentReward` are kept | `get_stats`, `:282-284` |
| **Applying the advice** | The engine never touches Cowrie (`recommendationApplied: False`, `:308`). `honeypot/deception_rotator.py` can poll the recommendation, rewrite `cowrie.cfg` and restart Cowrie. It is optional and has **no evidence of a live run** | — |

**Worked example.** I ran this one through the live engine with an isolated Q-table seeded from `models/q_table.json`.

An attacker logs in to the **centos_7** persona; the previous persona was **ubuntu_22**. The session lasts 480 s, has 3 IOCs, and runs `wget` (MALWARE_DOWNLOAD) and `chmod +x` (PERSISTENCE).

1. Reward:
   - duration term: 2·ln(1 + 480/60) = 2·ln 9 = **4.394**
   - commands: 2 × 0.3 = **0.6**
   - intent bonuses: 3.0 + 2.0 = **5.0**
   - IOCs: 3 × 0.5 = **1.5**
   - login succeeded: **2.0**
   - total r = **13.494**, below the cap of 20; `deceptionScore = min(5r, 100) = 67.5`
2. s = ubuntu_22, a = centos_7, s′ = centos_7.
3. Values from the seed table: Q(ubuntu_22, centos_7) = 136.1195, and max_a′ Q(centos_7, a′) = Q(centos_7, ubuntu_22) = 136.3908.
4. TD target = 13.494 + 0.9 × 136.3908 = **136.2457**.
5. TD error = 136.2457 − 136.1195 = 0.1262.
6. New Q = 136.1195 + 0.1 × 0.1262 = **136.1321**. The engine wrote 136.1322 (the reward was rounded for display).
7. Next recommendation from centos_7: greedy = ubuntu_22. ε is effectively 0.2 / (1 + 120.87) = **0.0016**, so it explores about once in 600 calls.

**Why the numbers sit near 136.** With s′ = a, repeating sessions on one persona pushes Q towards the fixed point r̄ / (1 − γ) = 10·r̄. An average reward of ~13.6 gives ~136. In other words, **the Q-values mostly measure the long-run average engagement of a persona, times ten.** The "state" carries very little information. That makes this effectively a *contextual bandit over personas*, not a sequential decision problem. See H6.

## 2.7 Pipeline diagram

```
                          ┌─────────────────────────── OFFLINE ────────────────────────────┐
 CICIDS2017 8 CSVs ──► train.py: coerce→drop NaN/inf→cap per file→cap global→prepare_features
                       →80/20 stratified random split→(SMOTE train)→Pipeline[StandardScaler→RF]
                       →IF on benign train rows→joblib .pkl + _meta.json
                       register_model.py → models/registry.json {file, sha256, sklearn 1.4.0}
                       retrain_from_samples.py (+analyst JSONL) → gates → --promote → registry
                          └────────────────────────────────────────────────────────────────┘
 ONLINE
 sniffer/flow_mapping.py ─┐                              ┌───────────── ai-engine (FastAPI :8000) ───────────┐
 (CICFlowMeter → snake)   │  POST /api/... (Node)        │ verify_api_key → Pydantic Record (422 on NaN/inf) │
 demo/replay_cicids.py ───┼──► backend aiEngineService ──┼─► extract_features_from_record → 53-float vector │
                          │    (axios, X-API-Key,        │    ├─► RF pipeline.predict_proba → class, max_p    │
 Cowrie JSON → parser ────┘     circuit breaker,         │    └─► IF pipeline.score_samples → if_score       │
   → honeypotService            retry stateless)         │  combine_threat_score: max(rf_s, .7rf_s+.3if_sig) │
                                                         │  BENIGN+anomaly → "Unknown" (score ≥ .55)         │
                                                         │  action: ≥.92 BLOCK | ≥.85 MONITOR | else ALLOW   │
                                                         │  stats + DriftMonitor.record(vector)              │
                                                         └──────────────┬────────────────────────────────────┘
   backend aiService.storePrediction ◄──── JSON {predictedClass, threatScore, action, featureVector, ...} ┘
     ├─ score ≥ 0.85 and class ≠ BENIGN → ThreatLog (+ auto-block ≥ 0.92 if autoBlockEnabled)
     └─ analyst labels → TrainingSample → exportTrainingSamples.js → retrain_from_samples.py (offline)

 Cowrie session ─► backend ─► /predict/honeypot/internal (rules → class + score; no model)  [C1 fixed]
                          └─► /deception/score ─► reward ─► Q-update ─► atomic save ─► nextProfile
 deception_rotator.py ─► GET recommendation ─► rewrite cowrie.cfg ─► restart Cowrie  (optional)
```

## 2.8 The algorithms in plain language, and how you used each one

**Decision tree** (the building block). A tree asks yes/no questions about the features, for example "is `init_win_bytes_backward` ≤ 229?". It picks each question to make the two resulting groups as pure as possible in class (sklearn measures purity with the Gini index). It stops at depth 20, or when a node has fewer than 5 rows (`min_samples_split=5`). One deep tree memorises its training data: low bias, high variance.

**Random Forest.** Train 200 trees, each on a bootstrap resample of the rows, and at every split let it consider only √53 ≈ 7 random features. The trees make different mistakes, and averaging their probability votes cancels much of the variance. `class_weight="balanced"` multiplies each class's weight by N / (k·n_class), so a SQL-injection row counts thousands of times more than a benign one.
- *Your use:* the served classifier. `predict_proba` gives the vote share per class, the argmax is the label, and the top share is `confidence`.
- *Why it suits this problem:* it is robust to unscaled, heavy-tailed features, works on tabular data, needs no GPU, and gives free feature importances plus exact SHAP (TreeExplainer).
- The StandardScaler in front is harmless but unnecessary for trees. It is useful for the IF and for the drift monitor's reference statistics.

**XGBoost** (gradient boosting). Build trees *sequentially*. Each new shallow tree (depth 6) is fitted to the gradient of the log-loss of the current ensemble, which is roughly "what the previous trees still get wrong". It adds the new tree's output with a learning rate of 0.1. Boosting reduces bias; random forests reduce variance.
- *Your use:* trained on real CICIDS with balanced sample weights. It beats the RF on the same split (macro F1 0.907 vs 0.845; benign misclassification 0.26% vs 1.22%), but it is **not deployed**. It is selectable by re-registering (`register_model.py --type xgboost`).

**Isolation Forest** (unsupervised anomaly detection). Build random trees that pick a random feature and a random split value, and keep splitting until each point is alone. Outliers are isolated in **few** splits, because they sit in sparse regions. The average path length h(x) is normalised to a score; sklearn's `score_samples` returns the negative of that score, so **lower means more anomalous**. `contamination=0.1` only places `offset_` at the 10th percentile of training scores (−0.474).
- *Your use:* trained on benign rows only, so it models "what normal looks like". The live threshold is −0.55, which flags about 5% of benign test flows and only 16% of attacks. Its output can raise an attack's score or relabel a benign verdict as "Unknown". **On its own it can never raise an alert** (H5).

**Q-learning** (model-free reinforcement learning). An agent in state s takes action a, receives reward r, and lands in s′. The Q-value Q(s,a) estimates "the total discounted reward I'll get if I do a here, then act greedily forever". The update moves Q a fraction α towards the *TD target* r + γ·max Q(s′,·). This is the Bellman optimality equation, used as a sampling rule. With enough exploration (ε-greedy) and a decaying α, tabular Q-learning converges to the optimal Q* in a finite MDP.
- *Your use:* 6 personas × 6 personas = 36 numbers, with the reward being attacker engagement.
- Two of the convergence conditions are not met: α is constant, and exploration collapses because of the ε decay. So the table is a running engagement estimate per persona, not a proven-optimal policy.

---

# PHASE 3 — IS IT WORKING? (VERIFIED)

## 3.1 Commands (Windows PowerShell or Git Bash, from the repo root)

```bash
cd ai-engine
```
```bash
py -3.11 -m venv .venv
```
```bash
.venv/Scripts/python.exe -m pip install -r requirements.txt
```
Train each model. These write into `ai-engine/models/`; do it on a branch, then re-register:
```bash
.venv/Scripts/python.exe training/train.py --data datasets/cicids2017 --model-dir models --model rf --smote
```
```bash
.venv/Scripts/python.exe training/train.py --data datasets/cicids2017 --model-dir models --model xgboost
```
```bash
.venv/Scripts/python.exe training/register_model.py --classifier rf_classifier_cicids_v2.pkl --type rf --anomaly isolation_forest_cicids.pkl
```
```bash
.venv/Scripts/python.exe training/register_model.py --check
```

The IsolationForest is trained by every `train.py` run (`train.py:542-559`); `--model` only selects the classifier. **Always pass `--model-dir models` from inside `ai-engine/`.** Running from the repo root created the stray root `models/` copy.

Start the engine. Use a real key from `.env` in practice:
```bash
.venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000
```

Verify:
```bash
.venv/Scripts/python.exe -m pytest -q
```
```bash
.venv/Scripts/python.exe evaluation/reproduce_reported_metrics.py
```
```bash
.venv/Scripts/python.exe evaluation/day_holdout_eval.py --smoke
```
```bash
cd .. && ai-engine/.venv/Scripts/python.exe scripts/ai_engine_endpoint_check.py
```

## 3.2 Test script: `scripts/ai_engine_endpoint_check.py` (new)

It starts its own engine on a random port with a throwaway key, an isolated Q-table under `.test-runtime/`, and a dead callback URL. It then exercises every endpoint and sends 5 real rows per raw CICIDS label (110 rows) through `/predict/internal`.

Results from my run:

| Raw label → target | n | Correct | Predictions | Mean score | Actions |
|---|---|---|---|---|---|
| BENIGN | 40 | 37 | BENIGN, Malware Beacon, Unknown | 0.054 | ALLOW 40 |
| Bot → Malware Beacon | 5 | 5 | Malware Beacon | 0.994 | BLOCK 5 |
| DDoS / DoS Hulk → DDoS | 10 | 10 | DDoS | 0.998 | BLOCK 10 |
| DoS GoldenEye / slowloris / Slowhttptest → DDoS | 15 | 15 | DDoS | 0.91–0.94 | BLOCK 8, MONITOR 3, ALLOW 4 |
| FTP-Patator → Credential Stuffing | 5 | 5 | Credential Stuffing | 0.9999 | BLOCK 5 |
| Heartbleed → RCE Attempt | 5 | 5 | RCE Attempt | 0.894 | BLOCK 4, ALLOW 1 |
| Infiltration → Lateral Movement | 5 | 5 | Lateral Movement | 0.822 | BLOCK 2, ALLOW 3 |
| PortScan → Port Scan | 5 | 5 | Port Scan | 0.9998 | BLOCK 5 |
| SSH-Patator → SSH Brute Force | 5 | 5 | SSH Brute Force | 0.998 | BLOCK 5 |
| Web Brute Force → Credential Stuffing | 5 | 3 | Credential Stuffing, XSS | 0.694 | **ALLOW 5** |
| Web SQL Injection → SQL Injection | 5 | 4 | BENIGN, SQL Injection | 0.669 | **ALLOW 5** |
| Web XSS → XSS Attempt | 5 | 5 | XSS Attempt | 0.852 | MONITOR 3, ALLOW 2 |

Overall: benign predicted BENIGN 92%; attacks predicted non-BENIGN 99%. The predictions are sensible for volumetric and brute-force attacks. **Web attacks are classified right but scored below the 0.85 alert line, so they would not raise a threat.** These rows come from the training CSVs, so this is a serving-path sanity check, not an accuracy estimate.

Endpoint checks that passed:
- 401 with no key, 403 with a wrong key, 422 for NaN, 400 for a batch over 500.
- `/model/info` reports the registry-pinned, SHA-verified files.
- `/metrics` works from loopback; `/model/drift` reports (`insufficient_data` at 115 < 200 samples); `/model/stats` counts.
- `/model/reload` swaps the models.
- `/predict` and `/predict/batch` work, and the callback fails quietly.
- `/deception/score` updated and persisted the Q-table; `/deception/recommendation` works, and an unknown profile gives 422.
- `/predict/auth/shadow` works with E2 enabled.

## 3.3 Train/serve consistency: proof

| Concern | Evidence | Verdict |
|---|---|---|
| Same feature order | Both builders emit `FEATURE_NAMES` order (`features.py:497`, `:301-319`). The loader refuses metadata whose `feature_names` differ (`predictor.py:295`) | ✅ |
| Same scaler | The scaler is *inside* the pickled `Pipeline`. One object is used at both stages | ✅ |
| Same numeric vector | Endpoint check [3]: `featureVector` from `/predict/internal` equals the training `prepare_features` vector (`np.allclose`) for **110/110** real rows | ✅ |
| Same entropy formula | `compute_payload_entropy` ≡ the vectorised block in `prepare_features` (covered by the 110/110 equality) | ✅ |
| Time features | 0 at train; (0,0) at serve without a timestamp; a real timestamp gives non-zero values, but the models ignore them (importance 0) | ✅ harmless, but dead |
| **Missing fields** | Train: never missing (the rows were dropped). Serve: absent → `Record` defaults (`flow_duration=1000`, `fwd_packet_len_*=60`, `syn_flag_count=1`, `flow_bytes_per_sec=60000`, …), not 0 | ⚠️ M2 |
| **CSV-style field names** | Endpoint check [4]: sending raw headers (`"Flow Duration": 24`) → the engine used `flow_duration = 1000.0` (the default), and 43 fields were reported defaulted | ❌ H4 |
| Honeypot sessions | Rule verdict, no model (formerly synthetic vectors → always BENIGN) | ✅ C1 fixed |

## 3.4 Re-run against the paper's numbers

| Metric | Paper | Deployed artifact metadata | Re-scored now (same split, current code) |
|---|---|---|---|
| RF accuracy | 98.43% | 0.9843 | **0.9843** ✅ |
| RF weighted F1 | 0.9862 | 0.9862 | **0.9862** ✅ |
| RF macro F1 | 0.8448 (caveat) | 0.8448 | **0.8448** ✅ |
| XGBoost accuracy | Paper Table IV: **83.67% (synthetic)**. 99.13% is only in `xgb_classifier_cicids_meta.json` | 0.9913 | **0.9913** ✅ (real CICIDS model) |
| Accuracy on test rows that are *not* exact copies of a train row | — | — | RF 0.9822, XGB 0.9896 |
| Chronological macro F1 / attack detection | not reported | — | 0.739 / 89.7% (repo results) |
| Leave-one-day-out attack detection | not reported | — | **≈ 0%** (repo results) |

**Did the leakage fix change the numbers? No.** The re-score with today's code is bit-for-bit the August metadata. The time features were always 0 in training (no Timestamp column), so the deployed model never learned them, and fixing the serve-time fallback cannot move a test-set metric.

**Do the models need retraining?**
- **Not for time leakage.**
- **Yes for honesty and quality:**
  - a. duplicates leak across the split (17.3% of test rows have an identical twin in train; Port Scan 98.4%);
  - b. the served artifact cannot be reproduced by today's `train.py` and doesn't record `--smote`;
  - c. the root and ai-engine RFs disagree;
  - d. the independent protocols show weak generalisation.

What to do (Phase 5, M-1):
1. Dedupe.
2. Retrain with one recorded command.
3. Evaluate chronologically.
4. Report both numbers.

## 3.5 "No supervised retraining loop, only Q-table updates at runtime": REFUTED as stated

**At runtime: confirmed.** Only the Q-table and the in-memory counters/drift window change while serving. No request path calls `fit`, `partial_fit` or `train`.

**Offline: a supervised loop exists**, added in commit `6166f30`:
1. Analysts label predictions in the backend (`backend/models/TrainingSample.js`, `routes/trainingSamples.js`).
2. `backend/utils/exportTrainingSamples.js` exports a JSONL file with the stored `featureVector` and `featureSchemaVersion`.
3. `ai-engine/training/retrain_from_samples.py`:
   - loads them, rejecting any with a different schema version, an unknown label, or non-finite values (`:39-54`);
   - trains a baseline and a candidate on the **chronological** train portion (`:122-133`);
   - scores both on the sealed chronological test.
4. Gates (`:34-35`): macro F1 may not drop by more than 0.005, and the benign alert rate must be ≤ 0.1%.
5. `--promote` writes **new versioned files** (it never overwrites), re-pins `registry.json`, and keeps `registry.previous.json` for rollback (`promote`, `:57-103`).
6. `POST /model/reload` hot-swaps the new model.
7. `GET /model/drift` (`monitoring/drift.py`) is the trigger signal.

**But:** it has **never been run** (no `experiments/retraining/`, and `registry.json` still points at the August files). It is **manual**: a human runs a CLI and passes `--promote`. The SGD `partial_fit` "online learner" your paper describes is **NOT FOUND** in code (only an unused root `models/sgd_classifier_cicids.pkl`).

## 3.6 Which RF copy is loaded, and do the copies differ?

- **Loaded:** `ai-engine/models/rf_classifier_cicids_v2.pkl`, sha256 `ca0efb1f…`.
  - Proof 1: `registry.json` pins it.
  - Proof 2: `/model/info` returned `"classifier": "rf_classifier_cicids_v2.pkl", "verified": true` from the engine started with `MODEL_DIR=ai-engine/models`.
  - Proof 3: `main.py:45-46` makes the path independent of the working directory.
  - The Node backend never loads a model; it only calls the engine over HTTP.
- **Root `models/rf_classifier_cicids_v2.pkl`** (`a7f98d2e…`) is loaded by nothing. It is a different training run: classes 0–9 instead of 0–10, no SMOTE rows, trained 2026-08-14.
- **They do give different predictions: 94 of 29,603 test rows (0.32%).** Root: acc 0.9863, macro F1 0.8714. Served: 0.9843 / 0.8448.

## 3.7 Verdict table

| Component | Status | Evidence | File |
|---|---|---|---|
| FastAPI service, auth, validation | **Working** | 393 tests; live 401/403/422/400 checks | `inference/main.py` |
| Model registry + SHA-256 + sklearn pin | **Working** | `/model/info` verified=true; `register_model.py --check` | `inference/predictor.py:157-249`, `training/register_model.py` |
| RF flow classifier | **Working** (on known attack types) | 0.9843 reproduced; 109/110 real rows sensible | `models/rf_classifier_cicids_v2.pkl` |
| RF generalisation to unseen days | **Broken / weak** | LODO detection ≈ 0%, chronological macro F1 0.739 | `experiments/c1_day_holdout_eval/` |
| XGBoost | **Partially** (trained, better, not served) | 0.9913 / macro 0.907 reproduced; not in the registry | `models/xgb_classifier_cicids.pkl` |
| Stacking | **Partially** (trained, not served, no SHAP) | macro F1 0.795 | `models/stacking_classifier_cicids.pkl` |
| IsolationForest anomaly tier | **Partially** | Loads and scores; flags 16% of attacks; cannot raise an alert alone | `predictor.py:444-452` |
| Score fusion and thresholds | **Working** (as designed) | Matches `day_holdout_eval` numbers at 0.70/0.85/0.92 | `predictor.py:110-137` |
| SHAP explanations | **Working** | `TreeExplainer` initialised; `?explain=true` | `predictor.py:337-422` |
| Train/serve feature consistency | **Working** for schema-named input; **Broken** for CSV-named input | 110/110 equal; CSV test FAIL | `utils/features.py:240-319`, `main.py:114-139` |
| Time-of-day leakage fix | **Working** (and moot for deployed models) | (0,0) fallback; importance 0; 24-hour invariance | `utils/features.py:146-238` |
| Honeypot session classification | **Working** (rule-based, since the C1 fix) | Live: failed login → SSH Brute Force 0.86 MONITOR; `tests/test_honeypot_rules.py` | `predictor.py` `predict_from_honeypot`, `features.py` `classify_honeypot_session` |
| Q-learning scorer (update + persistence) | **Working** | Worked example reproduced; atomic save; lock and merge | `rl_engine/deception_scorer.py` |
| Q-learning as a *learning* policy | **Partially** | ε ≈ 0.0016; 4/6 rows explored one action; no convergence check | same |
| Recommendation applied to Cowrie | **Untested** (code exists, optional) | No live-run evidence | `honeypot/deception_rotator.py` |
| Drift monitor | **Working** (screening statistic) | `/model/drift` reports; needs 200 samples | `monitoring/drift.py` |
| Supervised retraining + gated promotion | **Untested** (implemented, never run) | No `experiments/retraining/` | `training/retrain_from_samples.py` |
| Hot reload | **Working** | Live `POST /model/reload` → success | `main.py:261-275` |
| SGD online learner (paper) | **Not implemented** in code | Artifact only, no loader | root `models/sgd_classifier_cicids.pkl` |
| 1D-CNN/LSTM, autoencoder, PPO, DQN, BERT, GAN, EWC | **Not implemented** | No code | — |

---

# PHASE 4 — ISSUES AUDIT

Severity is judged for this project's context: a viva/demo system, with containment off by default.

## Critical

### C1. Every honeypot session is classified BENIGN by the served model — **FIXED 2026-10-21**
- **Where:** `utils/features.py:344-356` (`PROFILES_MEANS`), `inference/predictor.py:494-550`; consumed at `backend/services/honeypotService.js:259-280`.
- **What is wrong:** `extract_features_from_honeypot` fabricates a "representative" flow per rule profile. Those means were copied from the **synthetic** generator (`utils/data_generator.py:9-21`), not from CICIDS. The CICIDS-trained RF sees all six fabricated vectors as BENIGN (confidence 0.88–0.92), with scores 0.077–0.112. This includes failed-login brute force, `wget`+`chmod`, `nmap`, and `scp`.
- **Why it matters:**
  - The dashboard records attacker sessions as `aiClassification: "BENIGN"`.
  - No AI-path threat is ever created from the honeypot (it needs ≥ 0.85 and a class other than BENIGN).
  - In a viva demo, an examiner who runs the brute-force scenario sees "BENIGN".
- **Fix applied:** `predict_from_honeypot` now returns the rule verdict and runs no model.
  - `classify_honeypot_session` was factored out of `extract_features_from_honeypot`. That function is kept but no longer used for serving.
  - `HONEYPOT_RULE_SCORES` puts every attack class at or above the 0.85 alert line, and RCE and exfiltration at or above the 0.92 block line. Auto-block still needs `autoBlockEnabled`. BENIGN (0.40) and Port Scan (0.75) stay below the alert line.
  - The engine still answers 503 when the models aren't loaded, so the service stays fail-closed as a whole.
  - Backend: `modelType: 'rules'` (enum extended in `AIPrediction.js`) and `classificationMethod` fallback `'honeypot_rules'`. The frontend tooltip was corrected.
  - Tests: `ai-engine/tests/test_honeypot_rules.py` (17 tests). It covers the rule classes, that no model is called, the thresholds, the command cap, fail-closed behaviour, the HTTP route, and a regression on the registered artifacts.
- **Defending it:** nobody legitimate uses a decoy, so a rule verdict scaled by how far the attacker got is the honest signal. It is labelled "rule-based" end to end.
- **Known limits:**
  - The keyword rules match substrings: `nc` matches `once`, `sh` matches `/etc/shadow`. Whole-word matching would be the next step.
  - The rule order puts duration and IOCs first, so a long `wget` session reports as Data Exfiltration.

### C2. The headline metrics come from a contaminated random split; the independent results are much weaker and are not in the paper
- **Where:** `training/train.py:196`; paper Table IV.
- **What is wrong:**
  - Rows are split at random. 15.9% of rows are exact duplicates, and 17.3% of test rows have an identical twin in train (Port Scan 98.4%, SSH 45%).
  - Chronologically split, macro F1 is 0.739 and Malware Beacon recall falls to 0.13.
  - Leave-one-day-out, detection is ≈ 0%.
- **Why it matters:** "98.43%" will be challenged in any viva. It is a statement about *in-distribution, near-duplicate* recognition, not about operational detection.
- **Fix:** see M-1 in Phase 5 (dedupe, chronological evaluation, report both). The wording to use is in Phase 6.

## High

### H1. The paper contradicts the code in several checkable places
| Paper says | Code / artifact says |
|---|---|
| "SMOTE … has not yet been applied" | The served RF has exactly the SMOTE-added rows (121,827 = 118,412 + 2,435 + 979 + 1) |
| "fixed 46-feature subset" | 53 features (`features.py:12-33`); 6 have zero importance |
| "four integrated CICIDS2017 capture files" | All 8 CSVs (`train.py:42`) |
| XGBoost "synthetic, 83.67%"; "not yet trained on real CICIDS" | `xgb_classifier_cicids.pkl` is trained on real data: 0.9913 / macro 0.907 |
| RF synthetic 93.20%, XGB synthetic 83.67% | Metadata says 0.9285 and 0.9345 (`rf_classifier_v2.1_meta.json`, `xgb_classifier_meta.json`) |
| "only six of the eleven target classes have real examples" | 10 of 11 have real rows (class 10 has none; three classes have 11–36 rows) |
| "SGD-based online learner … partial_fit" implemented | NOT FOUND in code |
| "False-positive rate … not yet instrumented" | It is now: `day_holdout_eval.py` reports benign FPR with Wilson CIs |
| "Recommendation … not automatically applied" | Still true in the engine, but `honeypot/deception_rotator.py` can now apply it |
| "AbuseIPDB enrichment integrated" (into the engine) | The engine no longer calls it; `get_ip_reputation` is dead code (`predictor.py:16-86`). Enrichment moved to the backend |

**Fix:** correct the paper (Phase 6 has the wording), or retrain without SMOTE. Don't defend a sentence the artifact disproves.

### H2. The label taxonomy merges different attacks and invents classes the data can't support
- **Where:** `utils/features.py:47-63`.
- **What is wrong:**
  - Five DoS/DDoS tools are merged into "DDoS". DoS slowloris is a slow, low-rate attack, the opposite of a flood.
  - FTP-Patator and HTTP form brute force are merged into "Credential Stuffing". Credential stuffing means re-using breached credentials, which neither attack does.
  - Heartbleed (11 rows) is labelled "RCE Attempt", but Heartbleed is a memory disclosure, not code execution.
  - Data Exfiltration has 0 real rows. The served model still has a class-10 output, learned from one all-zero dummy row (`train.py:236-242`, in the older version).
- **Why it matters:** an examiner can ask "how do you detect exfiltration?" and the honest answer is "we don't". Per-class metrics on 2–7 test rows are noise.
- **Fix:** rename the classes to what the data is (`DoS/DDoS`, `Brute Force (FTP/HTTP)`, `Heartbleed`, `Infiltration`, `Botnet`). Drop class 10 from training, or mark it "rules-only". Report classes with fewer than 30 test rows separately.
  ```python
  # features.py — honest names; train.py: drop the dummy-row block for classes with no real data
  RAW_LABEL_TO_TARGET.update({"Heartbleed": "Heartbleed", "FTP-Patator": "Brute Force",
                              "Web Attack � Brute Force": "Brute Force"})
  ```
  This is a schema change. Bump `FEATURE_SCHEMA_VERSION`/`LABEL_MAP` together and retrain.

### H3. No de-duplication, so test rows have exact copies in train
- **Where:** `training/train.py:111-196`.
- **Fix** (before the split):
  ```python
  X, y = prepare_features(df, max_missing=0)
  Xy = np.column_stack([X, y])
  _, keep = np.unique(Xy, axis=0, return_index=True)       # exact duplicate rows, same label
  X, y = X[np.sort(keep)], y[np.sort(keep)]
  print(f"Removed {len(Xy) - len(keep):,} duplicate rows")
  X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
  ```

### H4. Train/serve skew: CSV-named fields are silently replaced by schema defaults
- **Where:** `inference/main.py:114-139` + `utils/features.py:244-252`.
- **What is wrong:** `Record` gives every snake_case field a default, and `model_dump()` always includes them. `g()` checks the exact snake_case key first, so a caller that sends `"Flow Duration": 24` gets `flow_duration = 1000.0` (verified live). Only the sniffer and the replay script use snake_case today; any CICFlowMeter-native integration would get wrong predictions with no error.
- **Fix:** let explicitly sent extras win over untouched defaults.
  ```python
  # main.py
  def _record_payload(record: "Record") -> dict:
      """Defaults only for fields the caller did not send under any recognised name."""
      sent = record.model_dump(exclude_unset=True)
      return {**{k: v for k, v in record.model_dump().items() if k not in sent and not _alias_sent(k, sent)}, **sent}

  def _alias_sent(field, sent):
      from utils.features import CANDIDATES
      return any(c in sent for c in CANDIDATES.get(field, []) if c != field)
  # then: predictor.predict(_record_payload(record), ...) in /predict, /predict/internal, /predict/eval, /predict/batch
  ```
  Simpler and stricter alternative: reject requests in which more than N schema fields are defaulted (`defaultedFeatures` already computes this).

### H5. The IsolationForest cannot raise an alert on its own, so the "zero-day" story does not hold
- **Where:** `inference/predictor.py:448-452`, `backend/services/aiService.js:71-73`.
- **What is wrong:**
  - If the RF says BENIGN, then `threatScore = 0.7·(1−max_p) + 0.3·if_sig`. With max_p ≥ 0.5 that is at most 0.65, and "Unknown" is pinned at 0.55. Both are below the 0.85 alert line.
  - The backend also requires class ≠ BENIGN, and "Unknown" passes that check, but its score still fails the threshold.
  - Measured: the IF flags 4.98% of benign flows and 16.4% of attacks, and LODO attack detection is ≈ 0%.
- **Why it matters:** the paper's tier-3 claim ("detection of zero-day and previously unseen attacks") is not supported by the implementation.
- **Fix:** route "Unknown" to the analyst queue explicitly and stop calling it detection.
  ```python
  # predictor.py — predict()
  if cname == "BENIGN" and is_anomaly:
      cname = "Unknown"; score = max(score, 0.55)
      action = "REVIEW"            # new action: create an analyst task, never auto-block
  ```
  Tune `ANOMALY_THRESHOLD` on a validation split for a target review rate, and report IF-alone precision/recall honestly.

### H6. The Q-learning design is a near-degenerate MDP with collapsed exploration
- **Where:** `rl_engine/deception_scorer.py:139, 266-269, 296-308`.
- **What is wrong:**
  - **s′ = a always.** There are no environment dynamics; the "state" is just the last action, so this is effectively a bandit.
  - **ε decays to 0.0016** at 12,087 episodes. After about 1,000 episodes the learner almost never explores.
  - In the seed table, 4 of 6 states have only one non-zero action (`ubuntu_22`).
  - The seed's `reward_history` alternates exactly 10.62 / 19.73 / 10.62…, a scripted pattern. **NOT FOUND:** any record of what generated those 12,087 episodes.
  - There is no negative reward for fingerprinting (the paper says there is), and α is constant.
  - There is no convergence criterion. The rewards are also non-stationary: attacker populations change.
- **Fix:**
  1. Reset the seed to zeros, or label it "synthetic warm start".
  2. Use a floor on ε.
  3. Add a fingerprint penalty.
  4. Track convergence.
  ```python
  # deception_scorer.py
  EPS_MIN = 0.05
  def choose_action(self, state):
      eps = max(EPS_MIN, self.epsilon / (1 + self.episode_count * 0.01))
      ...
  FINGERPRINT_CMDS = ("cat /proc/cpuinfo", "dmidecode", "systemd-detect-virt", "uname -a; cat /etc/issue")
  def calc_reward(session):
      ...
      if any(f in str(c.get("command", "")) for c in cmds for f in FINGERPRINT_CMDS): r -= 5.0
      return max(min(r, 20.0), -10.0)
  # update(): self.last_td_error = abs(target - cur); keep a rolling mean as a convergence signal in get_stats()
  ```
  Defend it in the viva as a bandit (Phase 6, Q11).

## Medium

### M1. Thresholds and severity bands are inconsistent between the engine and the backend
- **Where:** `main.py:53, 190, 194` (`SCORE_THRESHOLD=0.7` for "threats" counter and callbacks), against `predictor.py:100` (alert 0.85).
- Severity bands also differ: the engine uses 0.9/0.7/0.5 (`predictor.py:139-143`); the backend uses 0.9/0.75 (`aiService.js:80-86`).
- `/model/stats.totalThreats` counts flows that never become threats.
- **Fix:** derive `THRESHOLD` from `MONITOR_THRESHOLD`.
  ```python
  from inference.predictor import MONITOR_THRESHOLD
  THRESHOLD = float(os.getenv("SCORE_THRESHOLD", MONITOR_THRESHOLD))
  ```

### M2. Missing fields: training uses 0, serving uses non-zero defaults
- **Where:** `main.py:115-137` (`flow_duration=1000`, `syn_flag_count=1`, `flow_bytes_per_sec=60000`, …), against `features.py:449, 467`.
- **Why it matters:** a partial payload is scored as a fabricated flow. `defaultedFeatures` reports it, but nothing acts on it.
- **Fix:** reject when `len(defaultedFeatures) > 5` on the internal routes, or make the defaults 0.0 to match training.

### M3. The served artifact is not reproducible, and the metadata is too thin
- **Where:** `train.py:505-508`.
- **What is wrong:** the metadata does not record the CLI flags (`--smote`), the parameters, a dataset hash, the row counts, the git commit, or library versions. Today's code would not produce classes 0–10.
- **Fix:**
  ```python
  meta.update({"cli_args": vars(args), "params": pipe.get_params(deep=False) if hasattr(pipe, "get_params") else None,
               "train_rows": int(len(X_train)), "test_rows": int(len(X_test)),
               "class_counts_train": {LABEL_NAMES[int(k)]: int(v) for k, v in zip(*np.unique(y_train, return_counts=True))},
               "data_sha256": {f.name: file_sha256(f) for f in sorted(Path(args.data).glob("*.csv"))} if args.data else None,
               "git_commit": subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip(),
               "sklearn": sklearn.__version__, "split": "stratified_random_80_20_seed42"})
  ```

### M4. Duplicate and legacy artifacts, plus a silent first-match fallback
- **Where:** `ai-engine/models/` (identical XGB pair, `.bak` files, synthetic models), root `models/`, `predictor.py:200-259`.
- **What is wrong:** if `registry.json` is deleted, the first file that exists becomes production, with a warning only.
- **Fix:**
  - Delete the root `models/` copy, `xgb_classifier_cicids_v2.pkl` and the `.bak` pair, or move them to `models/archive/`.
  - Make the registry mandatory outside tests:
  ```python
  else:
      log.error("No models/registry.json; refusing to guess which model is production"); return
  ```

### M5. Unmapped labels silently become BENIGN
- **Where:** `features.py:513`, `.map(LABEL_MAP).fillna(0)`.
- **What is wrong:** a re-encoded CSV (for example `Web Attack – Brute Force` with a real en-dash) would train attacks as benign. `train.py:59-64` only prints a warning.
- **Fix:**
  ```python
  y = mapped.map(LABEL_MAP)
  if y.isna().any():
      raise ValueError(f"Unmapped labels: {sorted(set(s_lbls[y.isna()]))[:10]}")
  y = y.astype(int)
  ```

### M6. The model leans on shortcut features that are easy to evade
- **Where:** the served RF's top importance is `init_win_bytes_backward` (0.099), then `init_win_bytes_forward` (0.050). These are TCP initial window sizes, which reflect the CICIDS testbed's OS/tool fingerprints, not attack behaviour.
- **Why it matters:** an attacker controls their own window size, and other networks differ. Shortcut features of this kind are a widely reported CICIDS2017 weakness (see Engelen, Rimmer & Joosen, 2021, on the dataset's flaws).
- **Fix:** run an ablation (train without `init_win_*` and `Destination Port`-like features) and report the delta; consider dropping them. Look at the evaluation's feature-attribution output (SHAP).

### M7. The drift reference is the capped, SMOTE-augmented training sample, and mean/variance tests on heavy tails
- **Where:** `monitoring/drift.py:57-79`, reference `scaler.mean_/var_`.
- **What is wrong:** BENIGN is 66% of the reference, against ~80% in real traffic, and SMOTE rows are included. Mean and variance on heavy-tailed flow features flag "drift" easily.
- **Fix:** store per-feature quantiles of the *benign* training rows at train time, and use PSI or KS on those (`evaluate_model.check_drift` already has a KS helper).

### M8. `train.py --cv` evaluates a different recipe
- **Where:** `train.py:431`. CV runs on the full X, y without SMOTE, so its numbers don't describe the deployed model; it also reuses `XGB_PARAMS` from the other branch.
- **Fix:** wrap SMOTE and the model in an `imblearn.pipeline.Pipeline` and cross-validate that pipeline with `StratifiedGroupKFold`, grouped by file/day.

### M9. The engine is protected by a single static shared key
- **Where:** `main.py:108-112`; Docker binds `0.0.0.0` (`Dockerfile:27`).
- **What is wrong:** there is no key rotation, no mTLS, and no per-caller identity. Anyone with the key can mutate the Q-table (`/deception/score`) and hot-swap models (`/model/reload`).
- **Fix:** bind the engine to the internal Docker network only (no `ports:` mapping); use a separate admin key for `/model/reload`; rotate `SENTINEL_KEY`.

## Low

| # | Issue | Where | Fix |
|---|---|---|---|
| L1 | `/predict/auth/shadow` returns `str(exc)` to the caller | `main.py:393-394` | `return {"success": False, "error": "shadow evaluation failed"}` and log the exception |
| L2 | `AuthTelemetryRecord` uses `str = None` without `Optional`, with no length limits | `main.py:362-370` | `Optional[str] = Field(None, max_length=512)` |
| L3 | ~~Honeypot score adds 0.02 per command even for BENIGN~~ | `predictor.py` | **Fixed with C1** (+0.01 per command, non-BENIGN only) |
| L4 | `/predict/internal` is retried by the backend (`retry: true`), so a retried call double-counts stats and drift | `aiEngineService.js:68` | Dedupe by `X-Request-Id` in `_upd`, or don't retry |
| L5 | `get_ip_reputation` is dead and logs raw IPs at INFO | `predictor.py:16-86` | Delete it |
| L6 | `log_transform_features` imported, never used | `train.py:18`, `features.py:519-528` | Delete it |
| L7 | `evaluate_model.py` hard-codes the model filenames instead of reading the registry | `evaluate_model.py:142-145` | Use `load_registry` |
| L8 | `--tune` baseline hard-coded | `train.py:325-327` | Always compute it from the current registered model |
| L9 | `pytest>=8` unpinned; `scipy` used but not listed; no pyarrow (pandas warning) | `requirements.txt` | Pin `pytest==9.1.1`, add `scipy==1.17.1` |
| L10 | Experiment pickles don't load in the pinned env | `experiments/gate1_phase8/10/13/*.pkl` | Archive them, or record their sklearn version |
| L11 | Pickle loading executes code; the SHA-256 in `registry.json` lives in the same directory as the pickles | `predictor.py:221-231, 278-280` | Fine for a single-host demo; for production, sign the registry or keep the hashes outside the writable model volume (`skops.io` is a safer format) |
| L12 | The batch endpoint scores sequentially, one `predict_proba` per row | `main.py:322-330` | Vectorise: build a matrix and do one `predict_proba` call |

What is already done well (examiners like hearing this):
- The fail-closed key check, constant-time key comparison, and NaN/inf rejection.
- Validation errors that don't echo input.
- The SHA-256 and sklearn-version pin.
- The atomic, locked, merge-on-conflict Q-table writes.
- Request-id correlation.
- Hot reload with verification.
- The chronological and LODO evaluation, and gated promotion.

---

# PHASE 5 — IMPROVEMENTS

## Quick wins (< 1 hour each)

| # | Change | Effort | Impact | Files |
|---|---|---|---|---|
| Q1 | Derive `SCORE_THRESHOLD` from the alert line (M1) | 10 min | Consistent stats and callbacks | `inference/main.py` |
| Q2 | Raise on unmapped labels (M5) | 10 min | Prevents silent label poisoning | `utils/features.py` |
| Q3 | Delete root `models/`, the duplicate XGB and the `.bak` files; make the registry mandatory (M4) | 20 min | One canonical model path | `models/`, `ai-engine/models/`, `inference/predictor.py` |
| Q4 | Remove the dead code (`get_ip_reputation`, `log_transform_features`) (L5, L6) | 15 min | Less to defend | `predictor.py`, `features.py`, `train.py` |
| Q5 | Pin `pytest` and `scipy` (L9) | 5 min | Reproducible env | `requirements.txt` |
| Q6 | ε floor 0.05 + convergence stat (H6, partial) | 30 min | The learner keeps exploring | `rl_engine/deception_scorer.py` |
| Q7 | Sanitise the shadow error and type the fields (L1, L2) | 15 min | Hygiene | `inference/main.py` |
| Q8 | Add both new scripts to CI (smoke mode) | 30 min | Regression guard for skew and metrics | `.github/workflows/ci.yml` |

## Must-fix before the demo/viva

| # | Change | Effort | Impact | Files |
|---|---|---|---|---|
| M-1 | **Retrain honestly.** Dedupe (H3), record full metadata (M3), one documented command, register the result, and quote **random and chronological and LODO** results with macro F1 and benign FPR (C2) | 3–4 h (CPU time included) | Removes the biggest viva risk | `training/train.py`, `models/registry.json`, `docs/` |
| M-2 | ~~Fix honeypot classification (C1)~~ **Done** | 1–2 h | The demo stops showing BENIGN for attackers | `inference/predictor.py`, `utils/features.py`, tests |
| M-3 | **Fix the CSV-name skew** (H4) and reject heavily defaulted payloads (M2) | 1 h | Silent wrong predictions become explicit 422s | `inference/main.py`, tests |
| M-4 | **Correct the paper** (H1, H2): SMOTE, 53 features, 8 files, XGB real-data result, SGD, class names | 2 h | No contradictions an examiner can find | paper |
| M-5 | **Decide on XGBoost.** It wins on every metric on the same split (macro 0.907 vs 0.845, benign misclassification 0.26% vs 1.22%). Run `day_holdout_eval` with an XGB `fit()`; if it still wins chronologically, register it | 2 h | Better model, a defensible choice | `evaluation/day_holdout_eval.py`, `models/registry.json` |
| M-6 | **Reframe the IF** as an analyst-review signal (H5) | 1 h | The claim matches the behaviour | `predictor.py`, backend `aiService.js` |
| M-7 | **Reset or label the seed Q-table** (H6) | 15 min | No unexplained 12k "episodes" | `ai-engine/models/q_table.json`, `models/README.md` |

## Upgrades toward "self-evolving"

| # | Upgrade | Effort | Impact | Files |
|---|---|---|---|---|
| U1 | **Run the existing retraining loop once, end to end.** Label ~50 predictions in the UI → `exportTrainingSamples.js` → `retrain_from_samples.py` → `--promote` → `POST /model/reload`. Keep the report as evidence | 2 h | Turns "implemented" into "demonstrated" | existing files, `experiments/retraining/` |
| U2 | **Drift-triggered retraining.** When `/model/drift` says `drift` for N consecutive polls, open a "retrain candidate" task (never auto-promote) | 4 h | Closes the loop with a human gate | `backend/services/driftMonitorService.js` |
| U3 | **Model registry with history.** Keep `registry.json` as current plus an append-only `registry_history.jsonl` (version, metrics, gate result, who promoted); `/model/info` shows lineage | 3 h | Versioning and rollback beyond one step | `training/retrain_from_samples.py`, `register_model.py` |
| U4 | **Honeypot feedback into supervised data.** Cowrie IOCs and attacker IPs → label matching sniffer flows (`honeypot/sniffer/`) as attacks → TrainingSamples (QUARANTINED → analyst) | 1–2 days | Real, local attack data: the honest form of "self-evolving" | `honeypot/sniffer/flow_mapping.py`, backend training samples |
| U5 | **SHAP in the UI and a global summary.** Already per-prediction; add a mean-SHAP chart per class and show `featureImportance` on threat details | 4 h | Explainability you can demo | `predictor.py` (already), frontend |
| U6 | **Bandit before DQN.** Replace tabular Q with UCB1 or Thompson sampling over personas (it matches the problem). Move to DQN only once the state has real features (attacker tool fingerprint, command n-grams, time); with 6 actions and a 1-dimensional state, DQN would add nothing | 1 day (bandit), 1–2 weeks (DQN) | Algorithm matches the problem | `rl_engine/` |
| U7 | **Probability calibration.** `CalibratedClassifierCV(method="isotonic")` on a chronological validation split, so 0.85 means about 85% | 3 h | Thresholds become meaningful | `training/`, `predictor.py` |

## Production-readiness

| # | Change | Effort | Impact | Files |
|---|---|---|---|---|
| P1 | Docker exists (`ai-engine/Dockerfile`, non-root, healthcheck). Add: no host port mapping for the engine; read-only `models/` volume | 1 h | Smaller attack surface | `docker-compose.yml` |
| P2 | Unit tests for preprocessing: CSV-name vs snake-name parity, missing-field policy, label-map completeness, honeypot non-BENIGN | 2 h | Locks in C1/H4/M2/M5 fixes | `ai-engine/tests/test_features.py` |
| P3 | One reproducible training entry point (`make train` / `train.ps1`) that dedupes, trains, evaluates three protocols, writes metadata, and registers | 3 h | Anyone can rebuild the artifact | `training/`, `scripts/` |
| P4 | Monitor the prediction distribution: export a per-class rate and a `threatScore` histogram to `/metrics`, and alert on a class-mix shift (the Grafana stack already exists) | 2 h | Catches silent model failure | `inference/main.py`, `deployment/` |
| P5 | A golden-set check at startup: score 20 fixed rows and refuse `/ready` if the predictions differ from the stored expectation | 2 h | Catches a bad pickle or env drift | `inference/predictor.py` |

---

# PHASE 6 — VIVA PREP

## 20 likely questions, with strong honest answers

**1. What dataset did you use and how did you prepare it?**
CICIDS2017, all eight MachineLearningCVE CSVs, Monday to Friday.
- I coerce every feature to numeric and drop rows with NaN or infinity. Those come from zero-duration flows in Flow Bytes/s.
- I cap the dominant classes: benign at 100k, and DoS and port scan at 10k per file.
- I map the 15 raw labels onto my taxonomy.
- That leaves 148,015 rows, split 80/20 stratified.

**2. Why is your accuracy so high? Isn't CICIDS2017 known to be easy?**
Yes. 98.43% is a random row-level split, and 17% of the test rows have an identical twin in training. When I split chronologically within each capture, macro F1 drops to 0.74. When I hold out a whole day, attacks from that day are essentially not detected. So 98.43% means "recognises known attack types from the same testbed", not "detects attacks in the wild".

**3. Why report macro F1?**
Accuracy is dominated by benign traffic, which is 68% of the test set. Macro F1 averages over classes equally, so the 0.53 F1 on XSS and 0.29 on SQL injection show up. Mine is 0.845, against a weighted F1 of 0.986. That gap *is* the class-imbalance story.

**4. What is the benign false-positive rate?**
1.22% of benign flows get an attack label, mostly Malware Beacon. But an alert needs a threat score of at least 0.85, and at that line the benign alert rate is 0.115% with 95.7% attack detection on the random split. On the chronological split it is about 0.5% at 0.70. I chose the 0.85 line on a validation split, not the test set.

**5. What was the time-of-day leakage, and did fixing it change your results?**
- At inference, a missing timestamp used to fall back to the server's clock, while in training the time features were always zero (the CSVs have no timestamp). That is train/serve skew.
- I changed the fallback to (0,0).
- It did not change the metrics, and I re-scored to confirm, getting identical numbers. The deployed model has zero variance and zero importance on those features, and its predictions are identical across all 24 hours.

**6. Why Random Forest?**
- Tabular, heavy-tailed features with no need for scaling.
- Robust with little tuning.
- Fast on CPU (median 36 ms per flow, measured in-process over 200 flows).
- Built-in class weighting.
- Exact SHAP explanations through TreeExplainer.

XGBoost actually scored higher on the same split (macro F1 0.91). I kept RF in production because my independent chronological evaluation and gating pipeline were built around it. Moving to XGBoost is my next change, *if it also wins chronologically*. (Only say this if you haven't done M-5. If you have, give the result.)

**7. How do RF and XGBoost differ?**
RF trains deep trees independently on bootstrap samples and averages them, which reduces variance. XGBoost adds shallow trees one after another, each correcting the previous ensemble's errors along the loss gradient, which reduces bias.

**8. What does the Isolation Forest add?**
It is trained only on benign flows and scores how easily a flow is isolated by random splits. Honestly, it adds little. It can raise the score of an attack the classifier already found, and it relabels "benign but anomalous" flows as Unknown for an analyst. It cannot raise an alert on its own, and it flags only 16% of attacks. Presenting it as a zero-day detector would be overclaiming.

**9. How do you combine the models?**
With a fixed rule, not a learned meta-learner:
- For attack classes, the score is the maximum of the classifier confidence and 0.7·confidence + 0.3·anomaly.
- For benign, it is the blend.
- Then two thresholds: monitor at 0.85, block at 0.92. Blocking happens only if an administrator has enabled auto-block.

**10. Explain your Q-learning formulation.**
- States and actions are the six honeypot personas.
- The reward is attacker engagement: log of duration, number of commands, intent bonuses such as malware download, IOCs, and a successful login, capped at 20.
- α = 0.1, γ = 0.9, ε = 0.2 decaying.
- The update is the standard TD rule.
- The table is persisted atomically after every session, with a cross-process lock.

**11. Is that really an MDP? What does the state capture?**
Weakly. The next state is the persona just served, so the problem is close to a contextual multi-armed bandit, and the Q-values converge to about ten times each persona's average engagement. I'd defend tabular Q-learning as interpretable and adequate for six discrete actions. The honest improvement is either a bandit algorithm, or adding real state features (the attacker's tooling) before moving to DQN.

**12. How do you know it converged?**
I don't have a formal convergence test. I track recent average reward. ε also decays quickly: after 12,000 episodes it is about 0.002, so it barely explores. A minimum exploration rate and a TD-error-based convergence signal are the fixes.

**13. Where did the 12,087 episodes in the seed Q-table come from?**
Answer honestly that they are a warm start from development and simulated sessions, not real attackers. The repeating reward pattern shows this. (Better: reset it before the viva, M-7.)

**14. Is the honeypot recommendation applied automatically?**
The engine only recommends. A separate rotator script can poll the recommendation, rewrite the Cowrie config and restart Cowrie. It is optional and I haven't run it against a live Cowrie for the evaluation.

**15. How is the system "self-evolving"?**
Two mechanisms, both bounded:
1. The deception learner updates online after every honeypot session.
2. Supervised retraining is offline and human-gated:
   - analysts label predictions;
   - the labels are exported and a candidate is retrained;
   - it is scored on a sealed chronological test;
   - it is promoted only if macro F1 doesn't drop by more than 0.005 and the benign alert rate stays ≤ 0.1%;
   - then the model is hot-reloaded.

Drift monitoring tells the analyst when to retrain. There is no unsupervised online learning of the classifier, and that is deliberate, because of data poisoning. (After U1, add: "and I've run it end to end; here's the report.")

**16. How do you prevent train/serve skew?**
- One feature module for both stages.
- The scaler lives inside the pickled pipeline.
- The loader refuses a model whose feature names or count differ.
- A test proves the served vector equals the training vector on real rows.

(Know the one gap: fields sent under CSV names are overridden by defaults. Fixed in M-3, or say it's known.)

**17. What about model integrity and the security of pickles?**
- Pickles can execute code, so the engine loads only files pinned in `registry.json` by SHA-256.
- It refuses to load under a different scikit-learn version.
- It fails closed without the API key.

For production I'd sign the registry or use a non-executable format.

**18. Could an attacker evade your classifier?**
Yes. The top feature is the TCP initial window size, which the attacker controls, and which partly reflects the testbed rather than the attack. Slow, low-volume attacks also resemble benign traffic. Adversarial robustness is untested, and that's future work.

**19. What does your model do for classes you have almost no data for?**
- SQL injection has 21 rows, Heartbleed 11, infiltration 36. Their per-class scores are based on 2–7 test rows and are not statistically meaningful.
- Data Exfiltration has no real training data at all, so the model cannot detect it.

I report these separately.

**20. What is implemented, and what is future work?**
See the table below. Never claim deep learning, PPO, DQN, BERT, GAN or EWC.

## The 2-minute explanation (memorise this)

> SentinelAI's AI engine is a FastAPI service that the Node backend calls over HTTP with a shared API key.
> It scores network flows using fifty-three CICFlowMeter-style features.
>
> The classifier is a Random Forest — two hundred trees, balanced class weights — trained on all eight
> CICIDS2017 capture files. Next to it, an Isolation Forest trained only on benign traffic measures how unusual
> each flow is. I combine them with a fixed rule: for attacks, the classifier's confidence is a floor and the
> anomaly score can only raise it. Above 0.85 the backend opens a threat; above 0.92 it can block, if an
> administrator has enabled auto-block.
>
> On a random split the Random Forest reaches 98.4 percent accuracy, but macro F1 is 0.84, and when I
> evaluate chronologically, or hold out whole days, performance drops sharply. So I present it as a strong
> detector of *known* attack types, not of novel ones.
>
> Every deployed model is pinned by SHA-256 in a registry, with its scikit-learn version, and can be
> hot-swapped. A drift monitor compares live inputs with the training statistics.
>
> The adaptive part has two loops. First, a tabular Q-learning agent picks which of six honeypot personas
> to present, rewarding longer and deeper attacker engagement, and it updates after every session. Second,
> analysts label predictions; those labels feed an offline retraining script that promotes a new model only
> if it passes a sealed chronological test — no drop in macro F1, benign alert rate at most 0.1 percent.
>
> Deep learning, PPO, DQN, BERT and EWC are in my design and are explicitly future work.

## Implemented vs future work: exact wording

| Say this | Never say this |
|---|---|
| "A Random Forest trained on CICIDS2017 achieves 98.43% accuracy and 0.986 weighted F1 **on a stratified random split**; macro F1 is 0.845, and chronological evaluation gives macro F1 0.74." | "98.43% detection accuracy." / "Detects 98% of attacks." |
| "XGBoost and a stacking model were trained and evaluated; the Random Forest is the deployed model." | "An RF + XGBoost ensemble." |
| "An Isolation Forest provides an anomaly signal that raises scores and flags unusual benign traffic for review." | "Detects zero-day attacks." |
| "Fusion is a fixed weighted rule." | "A meta-learner fuses the tiers." |
| "A tabular Q-learning agent recommends honeypot personas from engagement rewards and updates after every session; a rotator can apply the recommendation." | "A reinforcement-learning agent autonomously reconfigures the honeypot." / "PPO." |
| "Human-gated offline retraining with promotion gates, drift monitoring, and hot reload." | "The model continuously retrains itself." / "Self-evolving via meta-learning/EWC." |
| "SHAP explanations per prediction." | "Fully explainable AI." |
| "Implemented in a lab setting; containment through the OS firewall is off by default." | "Autonomous response." / "DQN response engine." |
| "1D-CNN/LSTM, autoencoder, PPO, DQN, BERT, GAN augmentation and EWC are designed but not implemented." | Anything implying those exist. |

---

## Files added in this pass

- `ai-engine/evaluation/reproduce_reported_metrics.py`: re-scores the shipped models on `train.py`'s exact split; prints duplicates, per-class results, confusion matrices, threshold rates, and RF-copy disagreement.
- `scripts/ai_engine_endpoint_check.py`: isolated live-engine check of every endpoint, real rows per class, train/serve vector equality, the CSV-name skew probe, and honeypot and deception calls.
- `docs/AI_ENGINE_STUDY_GUIDE.md`: this document.

No model, registry, Q-table, or engine source file was changed.
