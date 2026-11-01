# SentinelAI readiness assessment — 2026-11-01 (after fix batch 4)

Base: `6883308` + batch 4 working tree (see `FIXES.md`, batch 4). Every "verified" below was executed on this machine
(Windows 11, local MongoDB 7.0, WSL Ubuntu with Cowrie) and has an evidence file; "not verified" means not run.

## 1. End-to-end results

| Workflow | Result | How | Evidence |
|---|---|---|---|
| A — AI detection | **VERIFIED (replay)**: 30 CICIDS2017 flows → `/api/ai/analyze` → FastAPI → 30 `AIPrediction` (`xgb_cicids_v1`), 15 DDoS → 15 `ThreatLog` → 15 `new_threat` + 30 `ai_prediction` socket events | `scripts/integration/run_integration.cjs` | `scripts/integration/runs/<time>/results.json` |
| B — Honeypot (fixture) | **VERIFIED**: Cowrie JSON → real parser → ingest → closure analysis (rule class `RCE Attempt`, 12 MITRE techniques, deception score), canary alert, idempotent replay, foreign key refused | same | same |
| B — Honeypot (live) | **VERIFIED**: real Cowrie in WSL on 127.0.0.1:2222, two real SSH sessions, persona switch applied by the rotator (`ubuntu_22` → `raspberry_pi`), hostname in the SSH output changed (`ubuntu-prod-srv` → `raspberrypi`), second session credited to the new persona, Q-table file updated; lab config and state restored (hash equal) | `run_integration.cjs --cowrie` | run `20261101_104646` |
| C — Containment | **VERIFIED (mock adapter)**: loopback refused; block-ip → deny-list + adapter `ACTIVE` + AuditLog + `ip_blocked`; repeat idempotent; blocker `check-block` true; unblock → `ROLLED_BACK` + `ip_unblocked`; 60 s policy action rolled back by reconciliation 15 s after expiry | same | same |
| D — Authentication | **VERIFIED**: CSRF-less login 403, wrong password 401, three roles, no token 401, viewer block 403, analyst user-list 403, bad socket token refused, logout revokes the access token | same | same |
| Resilience | **VERIFIED**: engine stopped → flow kept as `DEGRADED` (MEDIUM, not blocked), "AI Engine UNAVAILABLE" alert, `/health` 503, API still serving | same | run `20261101_113220` |
| Least-privilege MongoDB | **VERIFIED**: the whole A–D run passes as `sentinel_app` on a throwaway `mongod --auth` provisioned by `deployment/mongo-init.js`; no authorization error in the backend log | `run_with_mongo_auth.cjs` | run `20261101_105440` |
| Dashboard CSP | **VERIFIED in Chromium (built-in browser)** on the production build via `vite preview`: header present, fonts load, 11 pages (dashboard, threats, honeypot, campaigns, AI, users, settings, landing, login, about, features) with 0 `securitypolicyviolation` events, socket connected | manual browser check | this report |
| Playwright E2E (3 browsers) | see §5 | `npx playwright test` | `frontend/playwright-report/` |

Not run: Docker Compose (Docker not installed), real Windows Firewall adapter / VM harness, the dashboard behind nginx,
auto-block end to end (unit-tested only), WebSocket reconnection after a server restart.

## 2. Remaining security risks

| Risk | Status |
|---|---|
| Five leaked account passwords still valid (public repo) | **REQUIRES YOUR ACTION** — `audit/SEC001_REMEDIATION.md` |
| Leaked key in public Git history | key dead (rotated, verified on every local env and the WSL host); history purge **REQUIRES APPROVAL** (optional) |
| Plain HTTP in the dev/compose stack | by design for localhost; production needs TLS + `NODE_ENV=production` (`securityTopology.js` enforces it) |
| Local MongoDB service on 27017 has no auth | loopback-only bind; compose now enables auth (untested in Docker) |
| Real firewall enforcement | never exercised; stays disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) |

## 3. Simulated or limited functionality (say so in the demo)

- Detection runs on **replayed CICIDS2017 flow records**, not live packet capture.
- Containment uses the **mock adapter**: a recorded state machine, no firewall rule. The honeypot deny-list does stop
  is the only real enforcement: Cowrie's blocker plugin refuses deny-listed IPs. This run verified the plugin's
  `check-block` lookup returns `blocked: true`; the plugin refusing a live connection was not exercised here.
- Honeypot sessions are classified by **rules** (`classificationMethod: honeypot_rules`), not by the network model.
- The persona learner is a **tabular Q-learning / bandit recommender**; the rotator applies its choice by rewriting
  `cowrie.cfg` and restarting Cowrie (verified live once). Each recommendation request samples ε-greedy afresh, so the
  `recommendedProfile` stored on a session is not necessarily the persona the rotator applies next (RL-001). No
  evidence yet that learning improves engagement over a fixed persona.
- ML metrics (accuracy 0.99) are from a random split of the same capture sessions; cross-day generalisation of the
  served XGB is **unmeasured** (`audit/ML_EVAL_PLAN.md`).

## 4. Demo readiness

| Demo | Ready? | Notes |
|---|---|---|
| A | **Yes, as replay** | `replay_cicids.py --target backend`; say "replayed flow records" |
| B | **Yes** | WSL Cowrie (`scripts/demo/cowrie-demo-mode.sh`), parser, dashboard; rotation can be shown live with `rotate --once` |
| C | **Yes, simulated** | manual block / unblock / TTL expiry with the mock adapter; say "simulated firewall rule" |

Final-year demonstration: ready, once the five passwords are changed. Production deployment: **not ready** — no TLS
deployment has been run, compose with auth is untested, real enforcement untested, model generalisation unmeasured,
dependency pins are early-2024.

## 5. Test results

| Suite | Result |
|---|---|
| Backend Jest | 1133 passed, 13 skipped, 0 failed |
| Backend ESLint | clean |
| AI engine pytest | 596 passed, 0 failed |
| Frontend unit + build | 52/52, build OK |
| Playwright E2E (Chromium, Firefox, WebKit) | 177/177 (was 163/177 at the start of the batch: 1 stale test, 2 test-isolation/race bugs, 1 real backend bug CORE-008) |
| Integration harness | 25/25; live Cowrie 30/30; least-privilege Mongo 24/24 |

## 6. Next recommended batch

1. You: change the five passwords (SEC-001 step 1), then I re-run the checker.
2. With approval: ML protocol P5 (inference only) then P3/P4 for the served XGB (`ML_EVAL_PLAN.md`).
3. On a machine with Docker: `docker compose config` and one `up` with auth, then the harness against it.
4. Decide RL-001 (apply the stored recommendation vs. a fresh draw) and trace E2E-002 in Firefox.
