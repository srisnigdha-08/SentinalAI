# Improvements Report (Phase 5 roadmap + open follow-ups)

Date: 2026-10-21 · Branch `db-fixes` · **Uncommitted.** Builds on the fixes in `docs/HIGH_PRIORITY_FIXES_REPORT.md`,
`docs/MEDIUM_PRIORITY_FIXES_REPORT.md` and `docs/LOW_PRIORITY_FIXES_REPORT.md`.

## Summary

| # | Improvement | Status | Where |
|---|---|---|---|
| 1 | Alert line validated on a validation split; one configurable threshold shared by engine and backend | Done (0.85) | `ai-engine/evaluation/day_holdout_eval.py --protocols threshold`, `inference/predictor.py`, `backend/services/aiEngineService.js`, `aiService.js`, `honeypotService.js` |
| 2 | Supervised retraining pipeline with gated, human-approved promotion | Done | `backend/utils/exportTrainingSamples.js`, `ai-engine/training/retrain_from_samples.py` |
| 3 | Model hot reload | Done | `POST /model/reload` (engine), `POST /api/ai/engine/reload` (admin, audited) |
| 4 | Input-drift detection and alerting | Done | `ai-engine/monitoring/drift.py`, `GET /model/drift`, `GET /api/ai/engine/drift`, `backend/services/driftMonitorService.js` |
| 5 | Adaptive deception: the Q-learner's recommendation is applied to Cowrie | Done | `GET /deception/recommendation`, `GET /api/honeypot/deception/recommendation`, `honeypot/deception_rotator.py` |
| 6 | Live packet-to-detection streaming | Done (mapping unverified on live capture) | `POST /api/honeypot/ingest/flow`, `honeypot/sniffer/flow_mapping.py`, `sniffer.py` (`SNIFFER_DETECT=1`) |
| 7 | Node → engine resilience: retries + circuit breaker | Done | `backend/utils/circuitBreaker.js`, `aiEngineService.js` |
| 8 | Request-ID correlation and structured logs | Done | `backend/utils/requestContext.js`, `utils/logger.js` (`LOG_FORMAT=json`), engine middleware |
| 9 | Prometheus metrics | Done | backend `GET /metrics` (`utils/metrics.js`), engine `GET /metrics` |
| 10 | Docker Compose (+ optional Prometheus) | Written, **not run** (no Docker on this machine) | `docker-compose.yml`, three `Dockerfile`s, `frontend/nginx.conf`, `deployment/prometheus.yml`, `deployment/.env.compose.example` |
| 11 | CI: MongoDB-backed suites + model-integrity job | Done; the 4 suites verified locally | `.github/workflows/ci.yml` |
| 12 | Interpreter / library pinning | Done | `ai-engine/.python-version`, `sklearn_version` in `models/registry.json` (engine refuses a mismatch) |
| 13 | Durable outbox wired to live events | Done | `MongoOutboxStore` + `OUTBOX_STORE`, `models/OutboxEvent.js`, socket events recorded via `recordDelivered` |
| 14 | README metric claims | Done | `README.md` (per-split table + alerting) |
| 15 | Housekeeping | Done | `audit/backup/` removed; application-code lint warnings fixed; stale auth tests updated |

## 1. Alert line — validated, configurable, shared

**Method** (`--protocols threshold`, `experiments/c1_day_holdout_eval/threshold_validation/results.json`): the
chronological training rows are split chronologically again (fit 80 % / validation 20 %); candidate lines
0.70–0.99 are scored on validation only; the chosen line is then measured once on the untouched later test rows.

| Rule (decided on validation) | Line | Validation benign alerts | Test benign alerts [95 % CI] | Test attack detection |
|---|---|---|---|---|
| Point estimate ≤ 0.1 % | 0.79 | ≤ 0.1 % | 0.134 % [0.118, 0.154] | 88.4 % |
| Wilson upper bound ≤ 0.1 % (added after seeing the line above) | 0.80 | 0.073 % | 0.109 % [0.094, 0.127] | 88.3 % |
| **Deployed default: 2× margin on validation** | **0.85** | **0.046 %** | 0.086 % (from the test sweep) | 87.5 % |
| Previous default | 0.70 | 0.43 % | 0.661 % | 89.3 % |

**Honest reading.** Both rules chosen purely on validation missed the target on later traffic, because the
benign false-alert rate rose about 1.5× between the validation and test periods (temporal drift). 0.85 adds
a 2× margin; that margin was chosen *after* observing the drift, and its test numbers come from a sweep that
was recorded for transparency, not used for selection. Treat 0.85 as a defensible operating point, not a
proven one: re-check it with the drift monitor (§4) and the evaluation script on new data.

**Implementation.** `ALERT_THRESHOLD` (default 0.85) and `BLOCK_THRESHOLD` (0.92) are read by the engine and
published in `/model/info`; the backend reads both from there (cached 60 s, fallbacks 0.85/0.92) and uses the
alert line for threat creation (`aiService.storePrediction`), the MONITOR action (`runFullPipeline`), honeypot
threat status and threat-intel enrichment — no more hard-coded 0.7. `ai-engine/inference/main.py` now loads
`.env` before importing the predictor so the variable takes effect.

## 2–3. Retraining loop and hot reload
1. `node backend/utils/exportTrainingSamples.js --out ai-engine/datasets/training_samples.jsonl` — read-only export
   of analyst-approved samples (`ELIGIBLE_FOR_TRAINING`).
2. `python ai-engine/training/retrain_from_samples.py --samples <file>` — trains the production recipe on the
   chronological training rows **plus** the samples (schema/label/vector-checked), and a baseline without them;
   both are scored on the same sealed chronological test rows. Writes the candidate and `report.json` to
   `experiments/retraining/<version>/`.
3. `--promote` applies the gates (macro F1 not worse than baseline by > 0.005; benign alert rate ≤ 0.1 %),
   copies the candidate under **new** versioned names (never overwrites), re-pins `models/registry.json` (keeping
   `registry.previous.json` for one-step rollback). Nothing promotes without the flag.
4. `POST /api/ai/engine/reload` (admin, audit-logged) → engine `POST /model/reload`: builds and verifies a new
   predictor from the registry and swaps it in; on failure it keeps serving the old model and returns 409.
   Verified live with the real models.

## 4. Drift detection
The engine records every scored real flow (not evaluation calls, not synthetic honeypot vectors) in a rolling
window (`DRIFT_WINDOW`, 2000) and compares it with the training statistics stored in the deployed pipeline's
StandardScaler: per-feature standardised mean shift (> 0.5 sd) and variance ratio (outside ¼–4×). Zero-variance
training features (the time features) are ignored. "drift" when ≥ 10 % of features drift; "insufficient_data"
below `DRIFT_MIN_SAMPLES` (200). The backend checks every 30 min and raises one SYSTEM_HEALTH alert per 24 h while
drift persists. These are screening statistics that trigger re-evaluation/retraining, not a hypothesis test.

## 5. Adaptive deception
`honeypot/deception_rotator.py` (on the honeypot host, admin account) asks for the recommended persona
(ε-greedy from the Q-table with the served persona as state), rewrites `cowrie.cfg` via `switch_profile.py`,
restarts Cowrie with `--restart-cmd` (argv, no shell) and records the persona with
`PUT /api/honeypot/deception/profile`. A failed restart records nothing. `--dry-run`/`--once` for inspection.
With this, the learner explores and its Q-values diverge per persona instead of updating one cell.
Not run against a live Cowrie here.

## 6. Live flow detection
`SNIFFER_DETECT=1` makes the sniffer POST each extracted flow to `POST /api/honeypot/ingest/flow` (honeypot key):
only the 50 known numeric flow fields are forwarded (≥ 10 required, non-finite dropped), the backend runs the
full pipeline (prediction, threat/alert at the alert line, dashboard push) and is rate-limited per service key.
**Unverified:** the cicflowmeter column names and units (CICIDS2017 durations are microseconds) have not been
checked against a live capture — validate a few flows before trusting live scores.

## 7–9. Resilience and observability
- **Circuit breaker**: 5 consecutive infrastructure failures (connection errors, timeouts, 5xx) open it for 30 s
  (`AI_CIRCUIT_FAILURES`, `AI_CIRCUIT_RESET_MS`); calls then fail fast as "AI unavailable" (degraded, MONITOR).
  4xx never trips it. **Retries** (2, jittered exponential from 200 ms) only for fast transient failures and only
  on stateless calls — never `/deception/score` (would learn twice) or reload.
- **Request IDs**: every API request gets/keeps an `X-Request-Id` (echoed; added to every backend log line and
  forwarded to the engine, whose log lines carry it too). `LOG_FORMAT=json` for one-JSON-object console logs.
- **Metrics**: `/metrics` on both services (Prometheus text). Backend: requests and latency by route/status, AI
  call outcomes, socket clients, Mongo connected, circuit open. Engine: predictions by class, inference time,
  model loaded. Bearer `METRICS_TOKEN` when set; otherwise loopback only.

## 10. Docker Compose (written, not run)
`docker compose up --build` → MongoDB, engine (Q-table on a volume), backend, nginx-served dashboard on :8080;
`--profile monitoring` adds Prometheus. Secrets from `.env` (`deployment/.env.compose.example`); the compose
file refuses to start without them. Docker is not installed on this machine, so **no image was built** — the
files were checked statically (paths, YAML). Also fixed `deployment/mongo-init.js`: its least-privilege app role
lacked `campaigns`, `trainingsamples`, `archived_*` (retention), `outboxevents` and index privileges, so a backend
connecting as `sentinel_app` would have failed on those collections and on Mongoose index builds.

## 11. CI
- `backend-mongo` job: MongoDB service on 127.0.0.1:27029 for the four suites that were always skipped. Running
  them locally for the first time found two stale tests (an admin deactivating/demoting *their own* account,
  which the RBAC commit `efd76a4` deliberately forbids) and a missing `SENTINEL_KEY` in that environment; the
  tests now use a second admin and the job sets CI-only keys. Locally: **13/13 pass**.
- `model-integrity` job: `register_model.py --check` plus a real model load and prediction.

## 12. Pinning
`ai-engine/.python-version` = 3.11. `models/registry.json` records `sklearn_version` 1.4.0; the engine refuses to
load the models under another version (`ALLOW_SKLEARN_MISMATCH=1` to override). Verified: the `.venv` loads with
warnings-as-errors; this machine's global Python 3.13 / scikit-learn 1.7.2 is now refused instead of silently
loading the pickles.

## 13. Outbox
`OUTBOX_STORE=mongo|file` gives the SecurityEventBus a durable store (`MongoOutboxStore`: upsert, failure count →
FAILED after 3, redrive, stats; delivered records expire after `OUTBOX_RETENTION_DAYS`). Every event pushed to
dashboards is now also recorded on the bus (history/subscribers/metrics, and a DELIVERED record with a store), so
`/api/system/outbox` reflects real traffic instead of test data. Recording never affects socket delivery.

## Test results

| Suite | Result |
|---|---|
| Backend Jest (full, `--runInBand --ci`) | **1024 passed**, 13 skipped (the four MongoDB-gated suites without `AUTH_TEST_MONGO_URI`), 0 failed; 63/67 suites; clean exit |
| Backend MongoDB-gated suites (local mongod on 27029) | **13/13 passed** |
| AI engine pytest (`.venv`, sklearn 1.4.0) | **393 passed** (incl. 11 in `test_improvements.py`, 3 in `test_deception_rotator.py`) |
| Frontend Vitest + production build | **36 passed**, build OK |
| Live engine (real models, port 8015) | `/model/info` thresholds block 0.92 / monitor 0.85 / anomaly −0.55, registry verified; `/model/drift` → `insufficient_data`; `/deception/recommendation` OK; loopback `/metrics` OK; `X-Request-Id` echoed; `/model/reload` swapped successfully |

## Still not done / limits
- Docker images never built or run here.
- Live Cowrie, the rotator against a real Cowrie restart, and sniffer live detection not exercised end to end.
- The 0.85 alert line carries a margin chosen after observing drift (see §1).
- 33 unused-variable lint warnings remain inside test files only (application code is clean).
- Real Windows Firewall enforcement still never run against a live host.
