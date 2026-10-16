# SentinelAI application architecture

Inspection: 2026-10-13. This checkout has no `.git` directory. Before any edits,
all 38,360 files (2,093,870,770 bytes), including installed dependencies, models,
datasets, logs and hidden environment files, were copied to
`C:\Users\srisn\Desktop\Projects\sentinelai-backup-20261013-8962d597`.
An independent threaded verifier compared SHA-256 of every source/copy pair;
all matched. The slower redundant PowerShell verifier was then cancelled.
No original Docker disks, recovery copies, backups or recovered databases were accessed.
The recovery hash supplied by the owner is recorded, not re-read or independently verified:
`660D98A97461FE44D4B23C72D151F80985BA53010DDA67F03D2C887B82A269CC`.

## Services and boundaries

| Service | Native port | Requirements and responsibility |
| --- | --- | --- |
| React/Vite | 3000 | Node 24; React 18; npm lockfile. Proxies `/api` and `/socket.io` to backend. |
| Express/Socket.IO | 5000 | Node 24; MongoDB; JWT authentication, role authorization, ingestion, persistence, containment policy and broadcasts. |
| FastAPI | 8000 | Python 3.11; pinned requirements; RF and Isolation Forest artifacts; internal `X-API-Key`. |
| MongoDB | 27017 | MongoDB 7, an explicitly chosen fresh database; never recovered database directories. |
| Optional Cowrie | 2222 | Linux SSH honeypot. Parser forwards real Cowrie JSON events; sniffer requires packet capture privileges and additional dependencies. |

Browser traffic uses same-origin API and Socket.IO by default. Backend calls the AI
engine through `AI_ENGINE_URL`. Direct AI inference can notify `SENTINEL_API`;
`/predict/eval` is an isolated evaluation endpoint without notifications, database
writes, statistics updates or containment. AbuseIPDB enrichment is asynchronous in
the backend and optional; it does not change the model ThreatScore.

## Configuration

Backend: `PORT`, `NODE_ENV`, `MONGO_URI`, `CLIENT_URL`, `AI_ENGINE_URL`,
`JWT_SECRET`, `JWT_REFRESH_SECRET`, `HONEYPOT_API_KEY`,
`SENTINEL_KEY`, `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX`, `LOG_LEVEL`.
Optional administrator bootstrap: `ADMIN_EMAIL`, `ADMIN_NAME`,
`ADMIN_INITIAL_PASSWORD`, `ADMIN_DEPARTMENT`. Optional enrichment:
`ABUSEIPDB_API_KEY` (absent in inspected environment files).
Existing secret values are preserved and are never printed here.
The preserved legacy `JWT_EXPIRES_IN` setting is now ignored. Session-backed
access tokens last 15 minutes; refresh sessions have a 30-day absolute lifetime.
CLIENT_URL defines trusted browser Origin and cookie transport. Production
requires HTTPS; HTTP cookies are permitted only for loopback development.

AI: `MODEL_DIR`, `SENTINEL_API`, `SENTINEL_KEY`, `CORS_ORIGINS`,
`SCORE_THRESHOLD` (notification/statistics threshold, default 0.7), `Q_TABLE_PATH`.
Parser: `SENTINEL_API`, `SENTINEL_KEY`, `COWRIE_LOG`. Cowrie blocker:
`SENTINEL_API_URL`, `HONEYPOT_API_KEY`.

## Model contract and persistence

The selected models are `ai-engine/models/rf_classifier_cicids_v2.pkl` and
`isolation_forest_cicids.pkl`, with their `_meta.json` files. Both are serialized
scikit-learn pipelines with 53 inputs: scaler + RF, scaler + Isolation Forest.
The RF classes are 0 through 10. SHAP 0.45.1 explains the scaled RF inputs.
Feature order is defined in `utils/features.py`; entropy and cyclic time features
are derived. Honeypot feature extraction uses existing heuristic session profiles,
not measured packet flows; those semantics remain unchanged.

ThreatScore remains `0.70 * RF signal + 0.30 * IF signal`; the RF signal is
attack confidence, or one minus benign confidence. IF normalization uses the
trained offset and a 0.20 span. A benign anomalous classification becomes Unknown
with minimum score 0.55. Existing honeypot command bonus remains 0.02 per command,
capped at 0.99. Decisions remain ALLOW below 0.70, MONITOR from 0.70, BLOCK from
0.92. Raw anomaly threshold remains -0.55. Actual automatic blocking additionally
requires the persisted `autoBlockEnabled` setting, default false.

MongoDB collections: `users`, `threatlogs`, `honeypotsessions`, `alerts`,
`aipredictions`, `blockedips`, `campaigns`, `systemsettings`, `trainingsamples`,
`authsessions`. AuthSession expiry TTL removes session metadata only; active
authorization checks expiry directly and never depend on timely TTL deletion.
User authVersion increments revoke all older sessions, independent of timestamp precision.
Mongoose schemas own their indexes, including unique email/session identifiers,
threat lookups, training sample quarantine indexes, and alert expiry TTL.
The obsolete init script covered only five of these collections.
Reporting uses Asia/Kolkata calendar boundaries and explicit MongoDB timezone
expressions. Stored dates remain UTC instants. See AUTH_TIMEZONE_IMPLEMENTATION.md.

Preserved persistent assets: both model directories, all CICIDS/synthetic/honeypot
datasets, `ai-engine/models/q_table.json`, backend logs, environment files and
Cowrie configuration/user database. Runtime Q-learning state should use a separate
`Q_TABLE_PATH`, never overwrite the shipped model artifact. New deployment volumes
must be dedicated to this deployment; no recovered database bind mounts.

## Obsolete deployment removal

Removed after this extraction and verified backup:

- `ai-engine/Dockerfile`: retrained synthetic models during builds and masked failures.
- `backend/Dockerfile`, `frontend/Dockerfile`: old image definitions.
- `ai-engine/.dockerignore`, `backend/.dockerignore`: old build context rules.
- `frontend/nginx.conf`: old deployment-specific reverse proxy.
- `deployment/docker-compose.yml`: old names, volumes and service coupling.
- `deployment/mongo-init.js`: partial index initialization superseded by schemas.
- `deployment/query`: obsolete Docker service-name scratch file.
- `honeypot/Dockerfile.cowrie`, `.parser`, `.sniffer`: old optional deployment definitions.
- `backend/tests/dockerInfraHardening.test.js`: tests tied to the obsolete Compose layout;
  application security tests remain. Docker work is postponed by the owner.

The environment files under `deployment/` remain untouched because they contain
configuration and credentials. They are not automatically used by the new deployment.
`honeypot/switch_profile.py` retains application profile generation but loses the
automatic Docker restart. Application source, datasets, certificates (none found),
models, papers, diagrams and presentation files are retained.

## Native-only follow-up, 2026-10-14

The owner postponed all Docker operations. The unbuilt fresh deployment files
and their validator were removed; see VALIDATION.md for the removal record.
Original environment files, models, datasets and persistent data remain protected.
