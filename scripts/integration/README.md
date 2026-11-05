# Cross-service integration checks

Real services, no mocks inside them: the AI engine (uvicorn), the backend (`node server.js`) and MongoDB, wired
together on a throwaway database. Containment uses the mock adapter only. Secrets and passwords are generated per
run and never printed; neither service reads your `.env` files. Evidence (sanitised `results.json` and service
logs) is written to `scripts/integration/runs/<time>/`, which git ignores.

Prerequisites: `backend/node_modules`, `frontend/node_modules` (for `socket.io-client`), `ai-engine/.venv`, the
CICIDS2017 CSVs in `ai-engine/datasets/cicids2017/` (git-ignored, so this does not run in GitHub CI), and a MongoDB on
`127.0.0.1:27017`. Ports 15100 (backend) and 18100 (engine) must be free.

PowerShell, from the repository root:

```powershell
node scripts/integration/run_integration.cjs              # workflows A-D, about 4 minutes (one 60 s TTL wait)
node scripts/integration/run_integration.cjs --cowrie     # + live Cowrie in WSL: real SSH, persona rotation, Q-table
node scripts/integration/run_with_mongo_auth.cjs          # same run on a throwaway mongod --auth as sentinel_app
```

Workflow letters follow the demo naming used in every document: **A** Honeypot Intelligence, **B** AI Threat
Detection, **C** Autonomous Incident Response; **D** is authentication and sessions.

| Workflow | What runs |
|---|---|
| A | a Cowrie JSON log → `honeypot/parsers/log_parser.py --file` → ingest → closure analysis (rules, MITRE, deception score), canary alert, idempotent replay, foreign key refused |
| A-live (`--cowrie`) | `cowrie_lab.sh` in WSL: Cowrie on 127.0.0.1:2222, two real SSH sessions, `honeypot/deception_rotator.py --once` switches the persona and restarts Cowrie, the second session shows the new hostname and is credited to the new persona, the Q-table file is checked. The original `cowrie.cfg` and running/stopped state are restored afterwards (backup `etc/cowrie.cfg.integ-<tag>` until then) |
| B | `ai-engine/demo/replay_cicids.py --target backend` → `/api/ai/analyze` → FastAPI → `AIPrediction` / `ThreatLog` → `new_threat` / `ai_prediction` on an admin socket |
| C | protected target refused; `block-ip` → deny-list + mock adapter `ACTIVE` + AuditLog + `ip_blocked`; idempotent repeat; blocker `check-block`; `unblock-ip` → `ROLLED_BACK` + `ip_unblocked`; a 60 s policy action rolled back by reconciliation; auto-block enabled → every flow at/above the block line contained via the mock adapter |
| D | CSRF-guarded login, wrong password, `/auth/me`, RBAC (viewer/analyst/admin), bad socket token, socket reconnects after a backend restart, logout revokes the access token and disconnects the socket |
| Resilience | engine stopped: the flow is kept as a `DEGRADED` threat (never blocked), one "AI Engine" alert is raised, `/health` reports 503 (readiness), the API keeps serving |

The database is `sentinelai_integration_<time>` (the name must contain `integration`) and is dropped at the end
unless `--keep`.
