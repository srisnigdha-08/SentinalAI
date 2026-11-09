# Deployment and backup plan (2026-11-03)

What is supported today, what exists but was never run, and what a safe deployment would still need. Nothing here
has been deployed publicly; Docker is not installed on the project laptop; real firewall enforcement stays off.

## 1. Readiness matrix

| Area | Status | Evidence / gap |
|---|---|---|
| Native single-host (Windows services + MongoDB 7 + WSL Cowrie) | **Implemented and tested** | clean clone, demo scripts, integration harness 42/42, batch 15 rehearsal |
| Production frontend build | **Implemented and tested** | `npm run build`; served with CSP by `vite preview` in the clean-clone test |
| Health / readiness | **Implemented and tested** | backend `/health` (503 when database or engine is down); engine `/ready` (models verified) and `/health` |
| Restart and recovery | **Implemented and tested** | engine/MongoDB outages, socket reconnect, `restart-engine.ps1` (11 s) |
| Database backup and restore | **Implemented and tested (Node scripts)** | batch 15 round trip: `sentinel-demo` → new database, 12/12 collections identical in documents and indexes, after fixing the dropped `sparse` index option |
| CORS, cookies, origins | **Implemented, tested on loopback** | `CLIENT_URL` allow-list; cookies `httpOnly`, `SameSite=Strict`, `Secure` in production; plain HTTP refused off loopback |
| Docker Compose (MongoDB 7 with auth, engine, backend, nginx frontend, optional Prometheus/Grafana) | **Implemented, untested** | Docker not installed; the 2026-10-15 attempt was blocked at preflight |
| nginx (`frontend/nginx.conf`) | **Implemented, untested** | serves the built SPA on 8080 with CSP, HTTP only, container only |
| Monitoring (Prometheus rules, Grafana dashboard, `/metrics`) | **Implemented, partly tested** | rules unit-tested in CI (`promtool`); never scraped live |
| HTTPS / TLS | **Missing** | no certificate or TLS termination configuration in the repository |
| Scheduled backups | **Missing** | backups are manual |
| Secrets management | **Missing** | `.env` files; SEC-001 (credentials in Git history) open, risk accepted |
| Real firewall enforcement | **Blocked by design** | Windows Firewall adapter disabled, never run live |
| Multi-host / public deployment | **Missing** | not designed or tested |
| Installing Docker or MongoDB Database Tools | **Blocked: needs owner approval** | system-wide installs |

## 2. Docker Compose prerequisites (when approved)

1. Docker Engine or Docker Desktop with Compose v2; about 4 GB free memory for MongoDB, engine, backend and
   frontend (more with monitoring); disk on a drive with room for the `mongo-data` volume.
2. `cp deployment/.env.compose.example .env` and set every value (hex secrets, `openssl rand -hex 32`): `SENTINEL_KEY`,
   `SENTINEL_ADMIN_KEY`, `HONEYPOT_API_KEY`, `JWT_SECRET`, `JWT_REFRESH_SECRET`, `ADMIN_EMAIL`,
   `ADMIN_INITIAL_PASSWORD`, `ALERT_THRESHOLD`, `METRICS_TOKEN`, `MONGO_ROOT_PASSWORD`, `MONGO_APP_PASSWORD`,
   `MONGO_AUDIT_PASSWORD`.
3. `docker compose up --build` → dashboard on http://localhost:8080 (bound to 127.0.0.1 unless
   `DASHBOARD_BIND_ADDRESS` is set); `--profile monitoring` adds Prometheus (127.0.0.1:9090) and Grafana
   (127.0.0.1:3001).
4. First acceptance run to perform (never done): build all images, verify `/ready` and `/health`, log in, replay
   flows through the backend, restart each container and confirm recovery, back up and restore the volume, run the
   integration harness against the stack.

The compose stack runs `NODE_ENV=development` over plain HTTP on loopback. It is not a production configuration.

## 3. TLS termination requirements

- Put a reverse proxy (nginx, Caddy or similar) in front of the backend and dashboard, terminating HTTPS on 443 with
  a real certificate; forward to the backend on loopback.
- Backend: `NODE_ENV=production` (cookies become `Secure`); `TRUST_PROXY` set to the proxy's explicit address(es) —
  hop counts are rejected in production; `CLIENT_URL` set to the `https://` dashboard origin; with several workers,
  `AUTH_REVOCATION_MODE=mongo-stream`.
- Proxy: forward WebSocket upgrades for `/socket.io/`, set HSTS, keep the dashboard's CSP.
- Keep the AI engine on loopback; it must never be exposed.

## 4. MongoDB backup and restoration

**Available now (verified 2026-11-03).** Node scripts that need no extra installation:

```powershell
# Back up (read-only on the source). Writes backups\sentinel-db-<time>\ (git-ignored).
$env:MONGO_URI = 'mongodb://127.0.0.1:27017/sentinel-demo'; node scratch\backup_sentinel_db.mjs

# Restore into a NEW database name first and compare, never straight over the live one.
$env:MONGO_URI = 'mongodb://127.0.0.1:27017/sentinel-restore-check'
node scratch\restore_sentinel_db.mjs backups\<folder> --target-db sentinel-restore-check --confirm
```

- The restore **replaces** the documents of every collection in the target database (`deleteMany` then insert) and
  refuses unless `--target-db` matches the connected database and `--confirm` is given.
- A backup folder contains password hashes, refresh-session records and raw attacker data: keep it on the machine or
  an encrypted drive; never commit or share it.
- Batch 15 round trip: 12/12 collections identical (documents and indexes), users including password hashes
  identical. The test found and fixed a defect: the backup dropped index options, so the unique **sparse**
  `containmentactions.targetLock` index (one active containment per target) was lost on restore.

**Recommended later (needs approval to install MongoDB Database Tools):** `mongodump --uri <uri> --out <dir>` and
`mongorestore --uri <uri> --nsFrom 'sentinel-demo.*' --nsTo 'sentinel-restore-check.*' <dir>`; schedule a daily dump
with Windows Task Scheduler and keep at least 7 copies.

**Before a demo:** back up `sentinel-demo` once (above). If demo data goes wrong, `scripts\demo\reset-demo-db.ps1`
clears activity while keeping users and settings.

## 5. Service monitoring

| Signal | Where |
|---|---|
| Liveness / readiness | backend `/health`, engine `/ready` and `/health` |
| Metrics | backend `/metrics` (`METRICS_TOKEN`), engine `/metrics`; Prometheus rules `deployment/prometheus/alerts.yml`; Grafana dashboard `deployment/grafana/dashboards/sentinelai-overview.json` |
| Application log | `backend\logs\sentinel*.log` (rotating, 20 MB × 14), `errors.log`; containment `[AUDIT]` lines |
| Security audit | `auditlogs` collection (Settings → audit log): sign-ins, permission denials, settings, manual block/unblock |
| In-app alerts | "AI Engine UNAVAILABLE" and other health alerts on the dashboard |

## 6. Environment variables

Required and optional variables with defaults: [`FINAL_PROJECT_GUIDE.md`](FINAL_PROJECT_GUIDE.md) §7; templates
`backend/.env.example`, `ai-engine/.env.example`, `deployment/.env.compose.example`. The backend refuses to start with
any `CHANGE_ME` placeholder.

## 7. Recovery after a restart of the machine

| Component | Starts by itself? | Action |
|---|---|---|
| MongoDB | yes (Windows service) | `Get-Service MongoDB` |
| Engine, backend, frontend, parser | no | `scripts\demo\start-demo.ps1` |
| Cowrie (WSL) | no | `bash scripts/demo/cowrie-demo-mode.sh on` (the WSL address may have changed; start-demo finds it) |
| Dashboards | reconnect by themselves | reload if a tab was suspended |

## 8. Production-readiness blockers

1. No TLS termination; plain HTTP.
2. Credentials in Git history (SEC-001) not rotated; no secrets manager.
3. Docker deployment never executed; no multi-host design.
4. No scheduled backups or tested disaster recovery beyond the manual round trip.
5. Detection does not generalise to unseen attack days or tools; flows are replayed, not captured.
6. Enforcement simulated; single-flow auto-block without correlation.
7. Single engine process (≈ 120–130 requests/s); analytics queries grow linearly with stored threats.
