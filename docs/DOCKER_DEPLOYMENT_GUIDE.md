# SentinelAI Docker deployment gate and guide

**No runnable Docker deployment exists from this task. Preflight is BLOCKED.** Read DOCKER_PREFLIGHT_20261015.md before any installation, image pull/build, volume creation or startup. Commands for nonexistent Compose files are intentionally not presented as working instructions.

## Actual application contracts inspected

| Component | Existing entry/port | Dependencies |
| --- | --- | --- |
| React 18/Vite 5 | npm run dev / npm run build; native 3000 | Node 24, frontend npm lockfile; same-origin /api and /socket.io |
| Express/Socket.IO | backend/server.js; native 5000 | Node 24, backend npm lockfile, authenticated MongoDB, Python AI |
| FastAPI | inference.main:app; native 8000 | Python 3.11, pinned requirements, RF/IF/scaler metadata and 53-feature pipeline |
| MongoDB | native default 27017 | Fresh authenticated dedicated data; replica set required for mongo-stream revocation |
| Cowrie | independently managed Linux host, optional | Real Cowrie JSON/output events and private authenticated ingestion; no host currently available |

Backend health is `/health` (actual dependency readiness); AI `/ready` plus authenticated `/model/info`. Model loading is not a replacement for end-to-end authenticated readiness. Frontend must use same-origin HTTPS API/Socket.IO in production. Login/access/session lifetime remains 15 minutes/30 absolute days. Enrollment is administrator-only; see ENROLLMENT_POLICY_20261015.md.

## Configuration reference (names only; existing .env untouched)

| Component | Names and purpose | Secret? |
| --- | --- | --- |
| Backend | MONGO_URI; authenticated new database URI | Contains credentials |
| Backend | JWT_SECRET, JWT_REFRESH_SECRET; distinct token keys | Yes |
| Backend/AI/ingest | SENTINEL_KEY, HONEYPOT_API_KEY; distinct internal boundaries | Yes |
| Backend | CLIENT_URL; exact same-origin browser HTTPS origin | No |
| Backend | NODE_ENV, PORT, AI_ENGINE_URL | No |
| Backend | AUTH_REVOCATION_MODE, API_WORKERS; declared topology | No |
| Backend | TRUST_PROXY; explicit trusted IP/CIDR, no numeric-hop production trust | No |
| Backend | RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX, LOG_LEVEL, LOG_DIR | No |
| Initial admin | ADMIN_EMAIL, ADMIN_NAME, ADMIN_DEPARTMENT; operator identity | Private identity |
| Initial admin | ADMIN_INITIAL_PASSWORD; temporary bootstrap only | Yes |
| Optional reputation | ABUSEIPDB_API_KEY | Yes |
| Frontend | VITE_API_BASE_URL; default /api, no secrets in Vite variables | No |
| AI | MODEL_DIR; required existing artifacts | No |
| AI | SENTINEL_API, CORS_ORIGINS; callback/origin configuration | No |
| AI | Q_TABLE_PATH; separate runtime learning state; SCORE_THRESHOLD; existing semantics only | No |
| Optional parser | COWRIE_LOG; genuine source path; SENTINEL_API/SENTINEL_KEY | Key secret |

Future deployment must pin reviewed compatible image versions/digests, use lockfiles, non-root application users and read-only model artifacts. Exclude .env, credentials/cert private keys, datasets, node_modules, .venv, browser profiles, databases and all .test-runtime evidence from build contexts. Select required runtime artifacts explicitly; never train models during builds.

## Startup, verification, shutdown — pending implementation

After owner-reviewed safe storage: verify Docker/Compose versions, context/daemon and storage destination; review reconstructed configuration; validate exact image names, build contexts, proxy identities, isolated network, loopback HTTPS port and unique unused database/volume before builds. Start authenticated MongoDB and required replica-set readiness, then AI, backend and TLS frontend/proxy. Confirm health, auth/provisioning, inference, persistence/read-back, socket events, IST and dependency-loss behavior before acceptance. Restart only the newly owned containers to verify their new records persist. Stop only owned task services and retain images/data/evidence; never run prune or volume deletion.

Until a tested business-event adapter exists, the explicitly supported event-routing topology is exactly one API process, with every HTTP and Socket.IO request routed to it. This is a limitation, not cross-worker event fan-out. Multi-worker production requires separately tested distribution plus socket routing. Do not silently change AUTH_REVOCATION_MODE or declare one process while launching several.

No local access URL or final port mapping is active. Future troubleshooting starts with disk capacity, verified context/storage, required secrets, authenticated health and exact proxy peer; do not relax TLS/Origin/CSRF/CORS to resolve failures. Backup/restore procedures must target only a newly approved dedicated database and destination; test restoration into a separate fresh resource after review, never against recovered or retained data.
