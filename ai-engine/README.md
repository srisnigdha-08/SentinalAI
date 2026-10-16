# SentinelAI inference engine

See [native startup](../docs/NATIVE_DEVELOPMENT.md) and
[architecture and model contract](../docs/ARCHITECTURE.md).

Python 3.11; `pip install -r requirements.txt`; run from this directory:
`python -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ../backend/.env`.

Required: SENTINEL_KEY and the supplied RF/Isolation Forest model files.
Optional: MODEL_DIR, SENTINEL_API, CORS_ORIGINS, Q_TABLE_PATH.
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
