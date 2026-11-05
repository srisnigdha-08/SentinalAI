# SentinelAI inference engine

See [native startup](../docs/NATIVE_DEVELOPMENT.md) and
[architecture and model contract](../docs/ARCHITECTURE.md).

Python 3.11 (`.venv`; the models are pickled with scikit-learn 1.4.0); `pip install -r requirements.txt`;
run from this directory: `python -m uvicorn inference.main:app --host 127.0.0.1 --port 8000`.
`ai-engine/.env` is loaded automatically (already-set environment variables win).

Required: SENTINEL_KEY and the registered RF/Isolation Forest model files.
Optional: MODEL_DIR, SENTINEL_API, CORS_ORIGINS, Q_TABLE_PATH, Q_SAVE_EVERY, SENTINEL_ALLOW_REPO_RUNTIME_WRITE.
Missing/broken models produce unavailable responses, never random predictions.
No training runs during normal startup.

| Endpoint | Behavior |
| --- | --- |
| GET /health | Public liveness |
| GET /ready | Public readiness; 503 when models unavailable |
| GET /model/info, /model/stats | Internal key required |
| POST /predict, /predict/batch, /predict/honeypot | Production inference and threshold notifications |
| POST /predict/internal, /predict/honeypot/internal | Backend owns persistence; no callback notification |
| POST /predict/eval | Isolated evaluation; no persistence, containment or statistics mutation |
| POST /deception/score | Stateful Q-learning; separate writable runtime path |

All non-health endpoints require X-API-Key. Public prediction results omit raw
feature vectors; the backend-owned internal route returns them for storage.
The simulation endpoint has been removed. Existing thresholds and classifier
semantics are retained. Run `python -m pytest -q` from this directory.

## Model artifacts

- `models/registry.json` pins the deployed classifier and Isolation Forest by file name and SHA-256.
  The engine loads exactly those files; a missing file, hash mismatch or malformed registry makes
  inference unavailable. Other `.pkl` files in `models/` are not loaded. After training a new model:
  `python training/register_model.py --classifier <file>.pkl --type rf --anomaly <file>.pkl`, and
  `python training/register_model.py --check` to verify.
- `models/q_table.json` is only the **seed** for the deception Q-learner and is never written.
  Its provenance is not recorded in this repository: it was saved on 2026-10-05 with 12,087 episodes
  and first committed in `5ea7051` (2026-10-16); no script here regenerates it, so treat it as
  pre-seeded demonstration state, not as learning from real attackers. Learning state lives in
  `%LOCALAPPDATA%/SentinelAI/runtime/q_table.json` (or `runtime/` with
  `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1`); delete that file to restart learning from the seed.
- Independent evaluation of the deployed recipe: `python evaluation/day_holdout_eval.py`
  (see `docs/C1_EVALUATION_PLAN_AND_RESULTS.md`).
