# SentinelAI — Pre-Startup Safety Check & Backend Review (Phase 2C)

**Document Date:** 15 October 2026  
**Auditor / Systems Engineer:** Antigravity (Senior Windows Systems Engineer, Application Security Reviewer, and Data-Integrity Auditor)  
**Project Root:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Native Integration Directory:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration`  
**Development DB Path:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\data`  
**Audit Reference:** [`docs/POST_CLEANUP_READINESS_AUDIT_20261015.md`](file:///C:/Users/srisn/Desktop/Projects/sentinelai-complete/docs/POST_CLEANUP_READINESS_AUDIT_20261015.md)  
**Enrollment Policy Reference:** [`docs/ENROLLMENT_POLICY_20261015.md`](file:///C:/Users/srisn/Desktop/Projects/sentinelai-complete/docs/ENROLLMENT_POLICY_20261015.md)  
**Safety Mandate:** Read-only inspection; zero files deleted, zero configurations modified, zero services started, zero databases created or migrated during review.

---

## 1. Executive Summary & Startup Decision

| Audit Phase | Focus Area | Evidence Summary | Status |
| :--- | :--- | :--- | :---: |
| **Phase 1: External Backup** | Drive E: Codebase & Models Backup | Verified fresh ZIP at `E:\SentinelAI_Backup_20261015\sentinelai_codebase_models_20261015.zip` (292.3 MB, 283 files, SHA-256: `EB453575C...`). Excludes secrets and node_modules. Historical DB archive untouched. | **PASS (VERIFIED)** |
| **Phase 2A: DB Safety** | Binary and Port Verification | MongoDB Community v7.0.45 verified at `...\mongodb-acceptance-20261014\binaries\mongod.exe`. Port 27017 verified free prior to launch. Isolation confirmed. | **PASS (VERIFIED)** |
| **Phase 2B: DB Initialization** | Development `mongod` Startup | Started `mongod` daemon (PID `27764`) bound strictly to `127.0.0.1:27017` using dedicated `mongodb-dev\data`. Ping verified `{ ok: 1 }`. Catalog clean: only `admin`, `config`, `local`. | **PASS (ACTIVE)** |
| **Phase 2C: Backend Startup Review** | Configuration, Call Flow, Writes, Admin Provisioning & Shutdown | Audited `backend/server.js`, `backend/config/db.js`, `backend/models/User.js`, routes, services, and shutdown handlers. Zero startup migrations or drops. Safe admin bootstrap confirmed. | **PASS (AUDITED)** |
| **Startup Safety Verdict** | Overall Backend Launch Gate | **SAFE TO PROCEED** — Development database is isolated and healthy. All prerequisites satisfied. Awaiting operator authorization. | **READY (AWAITING OPERATOR APPROVAL)** |

---

## 2. Phase 2C Itemized Verification Results (Checks A – E)

### Check A: Active Database Target
*Evidence Rating: **Confirmed***

1. **Effective Connection String:**
   - Source: `backend/.env:MONGO_URI` loaded via `dotenv.config()` at `backend/server.js:1` and passed to `mongoose.connect()` at `backend/config/db.js:31`.
   - Effective Value: `mongodb://localhost:27017/sentinel-db`
2. **Credentials, Parameters, and TLS:**
   - Username / Password: None embedded in URI.
   - Query Parameters / Options: None in connection string. Connection options passed in code are `{ maxPoolSize: 10, serverSelectionTimeoutMS: 5000 }` (`backend/config/db.js:32-33`).
   - TLS / SSL: Disabled (standard loopback plaintext connection).
3. **Host and Port Binding:**
   - Target Host: `localhost` (resolves to `127.0.0.1`).
   - Target Port: `27017` (actively hosted by PID `27764`).
4. **Target Database Name:**
   - Target Database: `sentinel-db`.
5. **Running MongoDB Instance State:**
   - Live query via MongoClient on `127.0.0.1:27017` confirms current databases:
     - `admin` (40 KB)
     - `config` (12 KB)
     - `local` (72 KB)
   - `sentinel-db` does **not** exist yet. Zero application collections or documents are present.
6. **Physical and Logical Isolation:**
   - Acceptance DB: `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-acceptance-20261014\data` operates on port `27028` and is currently offline. Latest file write timestamp remains `14 October 2026 13:39:10`.
   - Historical Preserved DBs: `D:\MongoPreservation\deployment_mongo_data` and `D:\MongoPreservation\deepguard-platform_mongo_data` remain offline on physical Drive D:. Latest file write timestamp remains `15 October 2026 13:06:29`.
   - The backend connection string points exclusively to loopback port `27017` and cannot physically or logically route to or modify the acceptance or preserved databases.

---

### Check B: Startup Call Flow and Database Writes
*Evidence Rating: **Confirmed***

1. **Call Flow Trace from Server Entry Point (`backend/server.js`):**
   - **Step 1 (`server.js:1-3`):** Loads `backend/.env` and executes `validateEnv()`. Validates presence and minimum entropy of `JWT_SECRET`, `JWT_REFRESH_SECRET`, `HONEYPOT_API_KEY`, and `SENTINEL_KEY`. Rejects known insecure placeholders.
   - **Step 2 (`server.js:18-20`):** Configures security topology and trusted proxy handlers (`config/securityTopology.js`).
   - **Step 3 (`server.js:21-32`):** Initializes HTTP server and Socket.IO instance on `/socket.io` with secure transport origin filters.
   - **Step 4 (`server.js:34-44`):** Installs WebSocket authentication and instantiates `revocationDelivery` service (`services/revocationDelivery.js`). In development (`NODE_ENV=development`), `authTopology.mode` defaults to `'single'`. In single mode, `revocationDelivery.start()` is a no-op that returns immediately without opening a change stream or watching MongoDB.
   - **Step 5 (`server.js:47-85`):** Registers middleware: Helmet security headers, CORS with strict allowed origins, rate limiters (`/api`, `/api/auth/*`), compression, body parsers (`express.json({ limit: '10kb' })`), and Mongo sanitization (`express-mongo-sanitize`).
   - **Step 6 (`server.js:88-213`):** Registers endpoints and route routers (`/api/auth`, `/api/threats`, `/api/honeypot`, `/api/campaigns`, `/api/alerts`, `/api/users`, `/api/ai`, `/api/training-samples`, Swagger UI docs, and health checks).
   - **Step 7 (`server.js:218-226`):** If `NODE_ENV !== 'test'`, executes `connectDB()` (`config/db.js`):
     - Connects to `mongodb://localhost:27017/sentinel-db`.
     - Triggers Mongoose schema indexing (`createIndexes()`) for all registered models.
     - Calls `await ensureDefaultAdmin()`.
     - Awaits `revocationDelivery.start()`.
     - Starts HTTP server on `127.0.0.1:5000`.
2. **Itemized Database Operations on Startup:**
   - **Schema Migrations:** None. The backend contains no automated migration frameworks (such as Flyway, Umzug, or migrate-mongo).
   - **Database Drops / Resets:** None. No `dropDatabase()`, `collection.drop()`, or destructive queries exist in the startup path.
   - **Automatic Collection Creation & Indexing:** Mongoose models registered during startup (`AIPrediction`, `Alert`, `AuthSession`, `BlockedIP`, `Campaign`, `HoneypotSession`, `SystemSetting`, `ThreatLog`, `TrainingSample`, `User`) define indexes. On first connection to an empty database, MongoDB automatically creates these collections as empty collections and generates the declared indexes.
   - **Document Inserts / Seeding:**
     - `ensureDefaultAdmin()` (`config/db.js:3-27`): If `ADMIN_INITIAL_PASSWORD` is unconfigured, logs a skip message and performs **zero writes**. If `ADMIN_INITIAL_PASSWORD` is provided, executes one `User.countDocuments()` query, and if 0, inserts exactly one initial administrator document.
     - `utils/seed.js` and `utils/clean.js`: Manual utility scripts only. Neither is called by `server.js` or `npm start`.
   - **Background Schedulers & Workers:**
     - `socketManager.startHealthBroadcast()` (`websocket/socketManager.js:189-215`): Runs on a 15-second interval. Has an immediate guard clause: `if (io.engine.clientsCount === 0) return`. When zero WebSocket clients are connected, it does not query the database. When clients are connected, it issues only read-only `ThreatLog.countDocuments` aggregation queries. Zero writes occur.
     - Outbound Threat Intelligence (`services/threatIntelService.js`): Purely event-driven; triggers only when an incoming threat is processed via `/api/threats`. It does not execute at startup.

---

### Check C: Administrator Provisioning and Enrollment Policy
*Evidence Rating: **Confirmed***

1. **`ensureDefaultAdmin()` Logic (`backend/config/db.js:3-27`):**
   - **Activation Condition:** Activated solely when `process.env.ADMIN_INITIAL_PASSWORD` is defined and non-empty.
   - **Default Credentials:**
     - **Email:** `process.env.ADMIN_EMAIL || 'admin@sentinel.io'` (trimmed and lowercased).
     - **Name:** `process.env.ADMIN_NAME || 'Admin User'`.
     - **Department:** `process.env.ADMIN_DEPARTMENT || 'SOC'`.
     - **Password:** **No hardcoded password exists.** If `ADMIN_INITIAL_PASSWORD` is missing, startup logs:
       `ADMIN_INITIAL_PASSWORD is not configured. Skipping default administrator auto-provisioning.`
       and returns immediately without creating any account.
   - **Idempotency & Conflict Handling:**
     - Executes `User.countDocuments({ email: adminEmail })`.
     - If `count === 0`: Inserts the administrator document.
     - If `count > 0`: Does nothing. It will **not** overwrite, reset, or update existing passwords or roles.
2. **Password Hashing:**
   - Enforced by `backend/models/User.js:18-22` via Mongoose `pre('save')` middleware:
     ```javascript
     UserSchema.pre('save', async function (next) {
       if (!this.isModified('password')) return next()
       this.password = await bcrypt.hash(this.password, 12)
       next()
     })
     ```
   - Password is never stored in plaintext. Hashed with `bcryptjs` using cost factor 12.
   - `password` field has `select: false` to prevent accidental inclusion in queries, and `toJSON()` deletes the password attribute before serialization.
3. **Cross-Reference with Enrollment Policy (`docs/ENROLLMENT_POLICY_20261015.md`):**
   - **Public Self-Registration is DISABLED:**
     `POST /api/auth/register` is hard-coded to return HTTP 403 Forbidden:
     `{ success: false, error: 'Public registration is disabled. Contact an administrator for access.' }` (`controllers/authController.js:20-21`).
   - **Administrator Provisioning:**
     `POST /api/auth/provision` is protected by `protect` and `restrictTo('admin')` middleware (`routes/auth.js:137`), requiring an active administrator session, trusted Origin, and CSRF token.
4. **Safe Bootstrap Procedure for First Administrative Login:**
   - Because public registration is disabled and the development database is completely empty, an administrator cannot be provisioned via the web UI or API endpoint until the first administrator account exists.
   - **Recommended Procedure:**
     Inject `ADMIN_INITIAL_PASSWORD` ephemerally in the terminal session when starting the backend for the first time:
     ```powershell
     cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend
     $env:ADMIN_INITIAL_PASSWORD = "YourStrongDevPassword2026!"
     npm start
     ```
   - `ensureDefaultAdmin()` will detect that `admin@sentinel.io` does not exist, hash the password with bcrypt (cost 12), and insert the user document with role `admin` and status `active`.
   - The operator can immediately sign in at `http://localhost:3000` using `admin@sentinel.io` and the chosen password.
   - After the first startup, clear the terminal variable (`$env:ADMIN_INITIAL_PASSWORD = $null`). Subsequent backend startups do not require this variable because the account already exists.

---

### Check D: Safe Startup and Shutdown Procedure
*Evidence Rating: **Confirmed***

1. **Exact Startup Command (Native Windows):**
   - **Working Directory:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend`
   - **Command:**
     ```powershell
     npm start
     ```
     *(Which executes `node server.js` per `package.json:7`).*
2. **Required Environment Variables:**
   - All core application secrets are pre-configured in `backend/.env` and validated by `validateEnv()`:
     - `PORT=5000`
     - `NODE_ENV=development`
     - `MONGO_URI=mongodb://localhost:27017/sentinel-db`
     - `JWT_SECRET`, `JWT_REFRESH_SECRET`, `HONEYPOT_API_KEY`, `SENTINEL_KEY`
   - Ephemeral (First boot only): `ADMIN_INITIAL_PASSWORD` (minimum 8 characters).
3. **Shutdown Behavior (`server.js:228-244`):**
   - Signal Handlers: Traps `SIGINT` (Ctrl+C) and `SIGTERM`.
   - Teardown Sequence:
     1. Calls `socketManager.stopHealthBroadcast()` (stops 15s health interval).
     2. Calls `await revocationDelivery.stop()` (stops revocation watchdog).
     3. Calls `io.close()` (disconnects WebSocket clients).
     4. Calls `server.close()` (stops accepting HTTP connections).
     5. Calls `await mongoose.connection.close()` (cleanly shuts down MongoDB connection pool).
     6. Exits process with code 0.
   - Watchdog: A fallback `setTimeout(() => process.exit(1), 10000)` ensures the process does not hang indefinitely if an asynchronous resource fails to close.
4. **Outbound Network Calls on Startup:**
   - **Zero Outbound Calls:** The backend makes no outbound network requests at startup.
   - `aiEngineService.js`: Communicates exclusively with loopback `http://localhost:8000`. Requests occur only on demand when client requests hit `/health` or threat detection routes.
   - `threatIntelService.js`: Queries AbuseIPDB only when processing public IPs during threat events. It is inactive at startup and fails safely when `ABUSEIPDB_API_KEY` is omitted.
   - No analytics, telemetry, or external DNS resolution routines exist.

---

### Check E: Current State Reconfirmation
*Evidence Rating: **Confirmed***

1. **Development MongoDB Daemon:**
   - Status: **RUNNING** on `127.0.0.1:27017` (PID `27764`).
   - Binary: MongoDB Community v7.0.45 x64 (`mongodb-acceptance-20261014\binaries\mongod.exe`).
   - Data Directory: `C:\Users\srisn\Desktop\Projects\sentinelai-complete.native-integration\mongodb-dev\data`.
   - Health: Verified non-destructively via ping `{ ok: 1 }`.
2. **Application Tiers:**
   - Backend (Port 5000): **STOPPED** (Port 5000 verified FREE).
   - AI Inference Engine (Port 8000): **STOPPED** (Port 8000 verified FREE).
   - Frontend React / Vite (Port 3000): **STOPPED** (Port 3000 verified FREE).
3. **Database Purity:**
   - Existing databases on port 27017: `admin`, `config`, `local`.
   - `sentinel-db` has not been created and contains 0 collections and 0 documents.
4. **Preserved Data Integrity:**
   - Acceptance Database (`mongodb-acceptance-20261014\data`): Untouched; latest write remains `14 October 2026 13:39:10`.
   - Preserved Databases (`D:\MongoPreservation\`): Untouched; latest write remains `15 October 2026 13:06:29`.
   - Physical USB Drive E: Backups: Both `mongo_preservation_archive_20261015.zip` (13.7 MB) and `sentinelai_codebase_models_20261015.zip` (292.3 MB) remain verified and intact.

---

## 3. Operator Instructions for First Startup

When you are ready to start SentinelAI, execute the three tiers in the following recommended order across separate PowerShell terminals:

### Step 1: Terminal 1 — Start the Backend (with Admin Bootstrap)
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\backend

# Set ephemeral administrator password for initial boot
$env:ADMIN_INITIAL_PASSWORD = "ChangeMeAdmin2026!"

# Start backend
npm start
```
**Expected Console Output:**
- `MongoDB connected: localhost/sentinel-db`
- `Administrator account provisioned for: admin@sentinel.io`
- `Authentication revocation mode: single`
- `SentinelAI Backend ready on port 5000`

*(Once started, clear the variable from your terminal session: `$env:ADMIN_INITIAL_PASSWORD = $null`)*.

---

### Step 2: Terminal 2 — Start the AI Inference Engine
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine
$env:Q_TABLE_PATH = Join-Path (Get-Location).Path 'runtime\q_table.json'
.\.venv\Scripts\python.exe -m uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ..\backend\.env
```
**Expected Console Output:**
- `Uvicorn running on http://127.0.0.1:8000`
- `Application startup complete.`

---

### Step 3: Terminal 3 — Start the Frontend Dashboard
```powershell
cd C:\Users\srisn\Desktop\Projects\sentinelai-complete\frontend
npm run dev -- --host 127.0.0.1
```
**Expected Console Output:**
- `VITE v5.x.x ready in ... ms`
- `Local: http://127.0.0.1:3000/`

---

### Step 4: First Administrative Login
1. Open your browser and navigate to `http://localhost:3000`.
2. Sign in with:
   - **Email:** `admin@sentinel.io`
   - **Password:** The password provided in `$env:ADMIN_INITIAL_PASSWORD`.
3. Navigate to **User Management** to provision additional analysts or viewers as needed.

---

## 4. Unresolved Risks and Operational Caveats

1. **Pre-AI Engine Health Status:** If the backend is accessed via `GET /health` before the AI Engine (port 8000) is running, it will return HTTP 503 (`aiEngine: unreachable`). This is expected fail-closed behavior and will resolve as soon as Terminal 2 is launched.
2. **Ephemeral Password Hygiene:** Do **not** commit `ADMIN_INITIAL_PASSWORD` into `backend/.env` or source control. Passing it in the PowerShell session environment ensures credentials remain ephemeral.
3. **Public Registration Cutover:** Any external automated test or legacy script attempting to use `POST /api/auth/register` will receive HTTP 403 Forbidden per the 15 October 2026 enrollment policy. New accounts must be created via `POST /api/auth/provision` using the authenticated administrator session.

---

**Current Status:** All read-only Phase 2C checks are complete. System remains in a safe, non-running state. Awaiting operator authorization to begin service startup.


---

## 5. Phase 2D: Controlled Backend Startup Verification (Completed 15 October 2026)

- **Backend Process ID (PID):** `12096` (`node.exe` running `node server.js`)
- **Listening Address:** `127.0.0.1:5000` (loopback only)
- **Database Engine:** MongoDB Community v7.0.45 x64 (PID `27764` on `127.0.0.1:27017`)
- **Database Name:** `sentinel-db`
- **Application Collections Initialized (10 total):**
  - `users` (1 document: `admin@sentinel.io`, 2 indexes)
  - `aipredictions` (0 documents, 4 indexes)
  - `systemsettings` (0 documents, 2 indexes)
  - `threatlogs` (0 documents, 8 indexes)
  - `campaigns` (0 documents, 3 indexes)
  - `trainingsamples` (0 documents, 9 indexes)
  - `authsessions` (0 documents, 3 indexes)
  - `honeypotsessions` (0 documents, 6 indexes)
  - `alerts` (0 documents, 5 indexes)
  - `blockedips` (0 documents, 2 indexes)
- **Administrator Provisioning Status:**
  - Account: `admin@sentinel.io`
  - Role: `admin` | Status: `active` | Department: `SOC`
  - Password Security: Hashed with bcrypt (cost 12) via Mongoose `pre('save')` hook. Zero plaintext passwords or password hashes retrieved or stored in reports.
- **HTTP Endpoint Verification:**
  - `GET http://127.0.0.1:5000/`: HTTP 200 OK (`service: "SentinelAI API"`, `status: "ok"`)
  - `GET http://127.0.0.1:5000/health`: HTTP 503 (`database: connected`, `aiEngine: unreachable`) — Expected fail-closed behavior while Tier 2 (AI Engine) is stopped.
- **Isolation Invariance:**
  - Acceptance Database (`mongodb-acceptance-20261014\data`): Untouched (last write: `14 October 2026 13:39:10`).
  - Preserved Databases (`D:\MongoPreservation\`): Untouched (last write: `15 October 2026 13:06:29`).
- **Remaining Application Tiers:** AI Inference Engine (port 8000) and Frontend (port 3000) remain strictly **STOPPED**.


---

## 6. Phase 2E: AI Inference Engine Startup & Authentication Verification (Completed 15 October 2026)

- **AI Inference Engine Process ID (PID):** `1648` (Python 3.11.9 / Uvicorn server process)
- **Listening Address:** `127.0.0.1:8000` (loopback only)
- **Model State:** `ready` (Loaded `rf_classifier_cicids_v2.pkl`, SHAP TreeExplainer initialized)
- **Q-Table Immutability:** Verified; `runtime/q_table.json` not created; `models/q_table.json` untouched.
- **Service Authentication:** Verified; Backend connected with `X-API-Key: SENTINEL_KEY` and authenticated successfully (`authenticated: true`).
- **End-to-End Health Check:**
  - `GET http://127.0.0.1:5000/health` returned **HTTP 200 OK**:
    - `database`: `connected` (`sentinel-db`)
    - `aiEngine`: `connected` (`status: "ok"`, `authenticated: true`)
    - `websocket`: `connectedClients: 0`, `revocation.ready: true`
- **Isolation Invariance:**
  - Acceptance Database (`mongodb-acceptance-20261014\data`): Untouched (last write: `14 October 2026 13:39:10`).
  - Preserved Databases (`D:\MongoPreservation\`): Untouched (last write: `15 October 2026 13:06:29`).
- **Remaining Service:** Frontend React / Vite Dashboard (port 3000) remains strictly **STOPPED**.


---

## 7. Phase 2G: React Frontend Startup Verification (Completed 15 October 2026)

- **Frontend Process ID (PID):** `34392` (`node.exe` running Vite dev server v5.4.21)
- **Listening Address:** `127.0.0.1:3000` (loopback only, exact port 3000 confirmed; 0 fallback ports)
- **HTTP Response:** `GET http://127.0.0.1:3000/` returned **HTTP 200 OK** (HTML payload verified)
- **Vite Reverse Proxy:** Tested via `GET http://127.0.0.1:3000/api/system/health` -> returned **HTTP 200 OK** (successfully routed through port 3000 to backend on port 5000)
- **Backend Health:** `GET http://127.0.0.1:5000/health` verified **HTTP 200 OK** (`database: connected`, `aiEngine: connected`, `authenticated: true`)
- **File System Impact:** Only Vite internal dependency cache (`frontend\node_modules\.vite\deps\`) was generated; zero source files, zero config files, and zero `.env` files modified.
- **Outbound Network:** Zero outbound internet connections. PID `34392` confirmed solely in `Listen` state on `127.0.0.1:3000`.
- **Database Invariance:**
  - Acceptance Database (`mongodb-acceptance-20261014\data`): Untouched (last write: `14 October 2026 13:39:10`).
  - Preserved Historical Databases (`D:\MongoPreservation\`): Untouched (last write: `15 October 2026 13:06:29`).
- **All 4 Native Tiers Active:** MongoDB (27017), Backend (5000), AI Engine (8000), and Frontend (3000) are running together natively on Windows.


---

## 8. Phase 2I: Post-Login State Verification (Completed 15 October 2026)

- **Database Target:** `sentinel-db` on dedicated `127.0.0.1:27017` (PID `27764`, dbpath: `mongodb-dev\data`)
- **Administrator Identity:** `admin@sentinel.io`
  - `role`: `admin` | `status`: `active` | `department`: `SOC`
  - `loginCount`: `2` (successfully incremented from baseline `0`)
  - `lastLogin`: `2026-10-15T10:17:33.925Z` (verified updated upon authentication)
  - `authVersion`: `0`
- **Session Records (`authsessions` collection):**
  - Total Sessions: `2`
  - **Active Session:** Exactly `1` active session record (`expiresAt: 2026-11-14T10:17:33.000Z` [30 days], `revokedAt: null`, `generation: 0`, SHA-256 hashed refresh token).
  - **Revoked Session:** Exactly `1` revoked session record (`revokedAt: 2026-10-15T10:17:27.371Z`, rotated from initial handshake).
  - **Expired Sessions:** `0`.
- **System Settings Initialized:** Exactly `1` document in `systemsettings` (`autoBlockEnabled: false`, loaded upon SOC dashboard mount).
- **Isolation Invariance:**
  - Acceptance Database (`mongodb-acceptance-20261014\data`): Untouched (last write: `14 October 2026 13:39:10`).
  - Preserved Databases (`D:\MongoPreservation\`): Untouched (last write: `15 October 2026 13:06:29`).
- **All 4 Native Tiers Active:** MongoDB (27017), Backend (5000), AI Engine (8000), and Frontend (3000) running concurrently.
