# SentinelAI application architecture

Inspection: 2026-10-13. This checkout has no `.git` directory. Before any edits,
all 38,360 files (2,093,870,770 bytes), including installed dependencies, models,
datasets, logs and hidden environment files, were copied to
`%USERPROFILE%\Desktop\Projects\sentinelai-backup-20261013-8962d597`.
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

## Components added 2026-11-13 (limitation remediation)

| Component | Where | Default state |
|---|---|---|
| Passive flow capture (PCAP replay, opt-in live) | `ai-engine/capture/`; heartbeat `POST /api/honeypot/ingest/capture-heartbeat`; status `GET /api/system/capture` | offline PCAP replay implemented and verified; live capture implemented, not enabled |
| Capture provenance per prediction | `AIPrediction.captureSource` (set by the receiving route) | always on |
| Correlated auto-block | `backend/services/containmentCorrelationService.js`; `ThreatLog.containmentDecision` | correlated |
| Real host-firewall adapters with post-apply verification | `backend/services/containment/` (Windows, Linux iptables, `enforcementSafety.js`) | not enabled (mock) |
| Learning-evidence provenance and v1 dedupe | `rl_engine/deception_scorer.py`; `HoneypotSession.evidenceSource`; `GET /deception/stats`; `GET /api/honeypot/evidence` | always on |
| Unsupported Windows persona | `UNSUPPORTED_PROFILES` (engine), `switch_profile.UNSERVABLE`, `backend/utils/deceptionProfiles.js` | never selectable |
| v2 independent evaluation, rollback rehearsal | `evaluation/persona_policy_independent_eval.py`, `honeypot/rollback_rehearsal.py` | offline tools |
| Arena attacker profiles and batch statistics | `demo/deception_arena.py`, `evaluation/arena_batch.py` | simulated |
| Session-ML pipeline (shadow, no model) | `ai-engine/session_ml/`; `sessionML` block on `/predict/honeypot/internal`; `GET /session-ml/status`; `HoneypotSession.sessionMl` | pipeline verified; model blocked: no independent labels |
| Capability Status | `GET /api/system/capabilities`, `/dashboard/capabilities` | always on |

Status of each: [CAPABILITIES.md](CAPABILITIES.md).

## Rank 8 remediation notes (2026-11-19)

**MITRE ATT&CK** (`backend/utils/attackTechniques.js`, `mitreMapping.js`):
- Every technique id, name and tactic is verified against ATT&CK Enterprise v20.1 (where Defense Evasion is now
  Stealth plus Defense Impairment). Techniques are shown with their tactic in Threat Logs, Honeypot Analytics,
  Attack Time Machine and Deception Arena.
- T1595 Active Scanning (Reconnaissance, pre-compromise network probing) is no longer used for on-host commands;
  `uname`, `id`, `whoami` and `ifconfig` map to Discovery techniques. T1595 remains a candidate for network port scans.
- Intent-level techniques are used only where true for every command in the intent; otherwise the precise
  per-command technique applies.
- Windows rules are persona-gated. Unknown behaviour gets no technique.

**Engine request bodies:** a 2 MB limit on the bytes actually received for every engine route (see SESSION_ML.md).
The backend's own JSON limit (10 KB, express `raw-body`) already counts received bytes.

**Socket.IO latency.** Baseline from `node backend/benchmarks/socketLatency.js` on 2026-11-19:
- Setup: an isolated in-process server with the app's Socket.IO options, loopback, Node 24, socket.io 4.8.3,
  i5-12500H. Server and clients share one process.
- No latency SLO is defined; an owner-approved target is still needed.

| Scenario | p50 | p95 | p99 |
|---|---|---|---|
| WebSocket round trip, 1 client | 0.21 ms | 0.31 ms | 0.41 ms |
| WebSocket round trip, 50 clients | 6.8 ms | 8.6 ms | 9.6 ms |
| Broadcast to 10 clients, about 490 B events | 6.5 ms | 11.6 ms | 14.1 ms |
| Broadcast to 50 clients | 42 ms | 73 ms | 86 ms |
| 512 KB events to 10 clients | 14.7 ms | 25.6 ms | 28.5 ms |

- Sustained throughput: about 49,000 deliveries/s (10 clients).
- 0 events dropped in every scenario.
- Connection setup (p50): 38 ms over WebSocket for 1 client; 70 to 188 ms with the default polling-then-upgrade
  transport.
- A message over 1 MB from a client closes that connection (`transport close`).
- A server-side disconnect is not reconnected automatically (Socket.IO behaviour). A dropped transport reconnects in
  about 0.6 to 0.9 s.

**Test isolation:**
- Under Jest, every backend log and audit sink (`utils/logPaths.js`) refuses the real `backend/logs`.
- No Python test reloads a production module (`tests/test_test_isolation.py`).
