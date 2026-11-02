# Deployment validation — what was checked here, and the procedure for a machine with Docker

Written 2026-11-02. This machine has **no Docker and no nginx**, so nothing below marked "procedure" has been executed.

## Checked here

| Item | Result | How |
|---|---|---|
| `docker-compose.yml` is valid YAML; services, ports, volumes as intended | yes | PyYAML parse |
| Every required `${VAR:?}` in compose is documented in `deployment/.env.compose.example` | yes (optional `MODEL_REGISTRY_SHA256` undocumented) | static script |
| Ports publish on `127.0.0.1` by default (`BACKEND_BIND_ADDRESS`, `DASHBOARD_BIND_ADDRESS`) | yes | static |
| MongoDB least-privilege role covers every collection the services write | **yes, at runtime**: full A–D run as `sentinel_app` on a throwaway `mongod --auth` provisioned by `mongo-init.js`, 35/35, no authorization errors | `scripts/integration/run_with_mongo_auth.cjs` |
| Dashboard CSP string | served by `vite preview` and checked in a browser (11 pages, 0 violations); `nginx.conf` holds the identical string (unit test) | `frontend/tests/csp.test.mjs` |
| Health semantics | `/health` = readiness (Mongo + engine + revocation): 503 while the engine is down, API keeps serving | integration harness |
| Python pins vs installed venv | equal; served models load without version warnings | `pip freeze` compare |

## Procedure on a machine with Docker (not run)

PowerShell, repository root:

```powershell
Copy-Item deployment\.env.compose.example .env      # then fill every CHANGE_ME with: openssl rand -hex 32 (hex only)
docker compose config --quiet                       # must print nothing and exit 0
docker compose up --build -d
docker compose ps                                   # mongo, ai-engine, backend, frontend: healthy
```

```powershell
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:5000/health          # 200 once the engine is up
curl.exe -sI http://127.0.0.1:8080/ | Select-String "Content-Security-Policy|X-Content-Type-Options|Referrer-Policy"
docker compose exec mongo mongosh --quiet --eval "db.getSiblingDB('sentinel-db').users.findOne()"
# expected: "requires authentication" (auth is on)
# Authenticate with the credentials already in the container's environment (read by mongosh's process.env inside
# --eval), so no password is typed, echoed, stored in shell history or visible in a process list:
docker compose exec mongo mongosh --quiet --eval "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); db.getSiblingDB('sentinel-db').getUsers().users.map(u=>u.user)"
# expected: [ 'sentinel_app', 'sentinel_audit' ]
```

Never put a password after `-p` on a command line, and never paste `.env` contents into a terminal or ticket.

Then run the integration harness against the compose stack: open the dashboard on http://127.0.0.1:8080, sign in,
check the browser console for CSP violations on every page, and replay flows
(`ai-engine/demo/replay_cicids.py --target backend --backend-url http://127.0.0.1:5000 --origin http://localhost:8080`).

**Existing volume created before auth was enabled — do not delete it.** The image creates the root user and runs
`mongo-init.js` only on an empty data directory, so an existing `mongo-data` volume keeps its data but may have no
users. Back it up first, then provision in place:

```powershell
# 1. Back up (to a host folder that is not inside the repository)
docker compose exec mongo mongodump --archive=/tmp/pre-auth.archive --quiet
docker compose cp mongo:/tmp/pre-auth.archive D:\backups\sentinel-pre-auth.archive
# 2. First user through MongoDB's localhost exception (only works while the database has no users); credentials
#    from the container environment, never from the command line
docker compose exec mongo mongosh --quiet admin --eval "db.createUser({user: process.env.MONGO_INITDB_ROOT_USERNAME, pwd: process.env.MONGO_INITDB_ROOT_PASSWORD, roles: ['root']})"
# 3. App and audit users (mongo-init.js reads SENTINEL_APP_PASSWORD / SENTINEL_AUDIT_PASSWORD from the same environment)
docker compose exec mongo mongosh --quiet --eval "db.getSiblingDB('admin').auth(process.env.MONGO_INITDB_ROOT_USERNAME, process.env.MONGO_INITDB_ROOT_PASSWORD); load('/docker-entrypoint-initdb.d/mongo-init.js')"
```

If step 2 reports that users already exist, the volume was provisioned before: skip to step 3 only if `sentinel_app`
is missing. None of these commands has been executed on this machine.

## Production blockers (not addressed)

- **TLS:** the stack serves plain HTTP; `backend/config/securityTopology.js` refuses non-HTTPS in `NODE_ENV=production`, so
  production needs a TLS-terminating proxy (`TRUST_PROXY`) — none is configured or tested.
- Compose has never been started; real Windows Firewall enforcement never exercised (stays disabled).
- Dependency pins are early 2024 (FastAPI 0.109, scikit-learn 1.4.0); no CVE scan was run (needs network).
- Model generalisation: see `ML_EVAL_PLAN.md` §5c — not production-grade outside CICIDS2017 conditions.
