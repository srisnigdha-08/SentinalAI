# SentinelAI readiness assessment — 2026-11-01, updated 2026-11-02 (after batch 6)

**Batch 6 (cross-day ML).** The approved P3/P4 evaluation shows the served XGBoost recipe **does not generalise** to
capture days or tools it has not seen: attack recall 50.6 % (P3, classifier decision; 12.1 % at the alert line) and
3–33 % on held-out days, with benign FPR up to 4.1 %. The 98.97 % accuracy is an in-distribution figure only
(`ML_EVAL_PLAN.md` §5c). SEC-001 still requires your action (unchanged).


**2026-11-02 update.** All suites green on the batch-5 tree: Jest 1147, pytest 604, frontend 52 + build, Playwright
180/180 (3 browsers), secret scan clean, integration 41/41 with live Cowrie, least-privilege MongoDB 35/35. New
verified behaviour: session invalidation (7 requirements, `SEC001_REMEDIATION.md`), self-service password change,
auto-block with protected-target refusal / duplicate suppression / rollback / audit lines, socket reconnection
without duplicate events, persisted persona decisions applied by id (RL-001). SEC-001 still **requires your action**:
the leaked passwords open 9 account records.

Base: `6883308` + batch 4 working tree (see `FIXES.md`, batch 4). Every "verified" below was executed on this machine
(Windows 11, local MongoDB 7.0, WSL Ubuntu with Cowrie) and has an evidence file; "not verified" means not run.

## 1. End-to-end results

| Workflow | Result | How | Evidence |
|---|---|---|---|
| Demo A — Honeypot Intelligence (fixture) | **VERIFIED**: Cowrie JSON → real parser → ingest → closure analysis (rule class `RCE Attempt`, 12 MITRE techniques, deception score), canary alert, idempotent replay, foreign key refused | same | same |
| Demo A — Honeypot Intelligence (live) | **VERIFIED**: real Cowrie in WSL on 127.0.0.1:2222, two real SSH sessions, persona switch applied by the rotator (`ubuntu_22` → `raspberry_pi`), hostname in the SSH output changed (`ubuntu-prod-srv` → `raspberrypi`), second session credited to the new persona, Q-table file updated; lab config and state restored (hash equal) | `run_integration.cjs --cowrie` | run `20261101_104646` |
| Demo B — AI Threat Detection | **VERIFIED (replay)**: 30 CICIDS2017 flows → `/api/ai/analyze` → FastAPI → 30 `AIPrediction` (`xgb_cicids_v1`), 15 DDoS → 15 `ThreatLog` → 15 `new_threat` + 30 `ai_prediction` socket events | `scripts/integration/run_integration.cjs` | `scripts/integration/runs/<time>/results.json` |
| Demo C — Autonomous Incident Response | **VERIFIED (mock adapter)**: loopback refused; block-ip → deny-list + adapter `ACTIVE` + AuditLog + `ip_blocked`; repeat idempotent; blocker `check-block` true; unblock → `ROLLED_BACK` + `ip_unblocked`; 60 s policy action rolled back by reconciliation 15 s after expiry; **auto-block enabled (2026-11-02): 4/4 new threats at/above 0.92 contained by "AI Auto-Block" through the mock adapter** (no flow fell between 0.90 and 0.92 in that run, so the not-blocked branch was not exercised end to end) | same | run `20261101_202242` (UTC) |
| D — Authentication | **VERIFIED**: CSRF-less login 403, wrong password 401, three roles, no token 401, viewer block 403, analyst user-list 403, bad socket token refused, logout revokes the access token; **socket reconnects 9.7 s after a backend restart and receives events; logout disconnects the user's socket server-side (2026-11-02)** | same | run `20261101_202242` (UTC) |
| Resilience | **VERIFIED**: engine stopped → flow kept as `DEGRADED` (MEDIUM, not blocked), "AI Engine UNAVAILABLE" alert, `/health` 503, API still serving | same | run `20261101_113220` |
| Least-privilege MongoDB | **VERIFIED**: the whole A–D run passes as `sentinel_app` on a throwaway `mongod --auth` provisioned by `deployment/mongo-init.js`; no authorization error in the backend log | `run_with_mongo_auth.cjs` | run `20261101_105440` |
| Dashboard CSP | **VERIFIED in Chromium (built-in browser)** on the production build via `vite preview`: header present, fonts load, 11 pages (dashboard, threats, honeypot, campaigns, AI, users, settings, landing, login, about, features) with 0 `securitypolicyviolation` events, socket connected | manual browser check | this report |
| Playwright E2E (3 browsers) | see §5 | `npx playwright test` | `frontend/playwright-report/` |

Demo names used everywhere: A Honeypot Intelligence, B AI Threat Detection, C Autonomous Incident Response
(the first version of this report had A and B swapped).

Not run: Docker Compose (Docker not installed), real Windows Firewall adapter / VM harness, the dashboard behind nginx.

## 2. Remaining security risks

| Risk | Status |
|---|---|
| Leaked passwords still open 9 account records in 2 databases (public repo); 114 historical sessions unusable (verified) but not revoked | **REQUIRES YOUR ACTION** — checklist in `audit/SEC001_REMEDIATION.md`; the UI now lets each user change their password |
| Leaked key in public Git history | key dead (rotated, verified on every local env and the WSL host); history purge **REQUIRES APPROVAL** (optional) |
| Plain HTTP in the dev/compose stack | by design for localhost; production needs TLS + `NODE_ENV=production` (`securityTopology.js` enforces it) |
| Local MongoDB service on 27017 has no auth | loopback-only bind; compose now enables auth (untested in Docker) |
| Real firewall enforcement | never exercised; stays disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) |

## 3. Simulated or limited functionality (say so in the demo)

- Detection runs on **replayed CICIDS2017 flow records**, not live packet capture.
- Containment uses the **mock adapter**: a recorded state machine, no firewall rule. The honeypot deny-list is the
  only real enforcement: Cowrie's blocker plugin refuses deny-listed IPs. This run verified the plugin's
  `check-block` lookup returns `blocked: true`; the plugin refusing a live connection was not exercised here.
- Honeypot sessions are classified by **rules** (`classificationMethod: honeypot_rules`), not by the network model.
- The persona learner is a **tabular Q-learning / bandit recommender**; the rotator applies its choice by rewriting
  `cowrie.cfg` and restarting Cowrie (verified live). Since 2026-11-02 each rotation applies one persisted decision
  (RL-001); the per-session `recommendedProfile` is still a separate closure-time draw (informational). No evidence
  yet that learning improves engagement over a fixed persona.
- ML metrics (accuracy 0.9897, macro F1 0.8738 — reproduced by the inference-only P5 run) are from a random split of
  the same capture sessions; benign FPR at the alert line is 0.23 % there. **Measured cross-day (P3/P4, 2026-11-02):
  attack recall 3–51 %, benign FPR up to 4.1 %** — say "high accuracy on CICIDS2017's random split; poor on unseen
  days", never "detects novel attacks".

## 4. Demo readiness

| Demo | Ready? | Notes |
|---|---|---|
| Demo A — Honeypot Intelligence | **Yes** | WSL Cowrie (`scripts/demo/cowrie-demo-mode.sh`), parser, dashboard; rotation can be shown live with `rotate --once` |
| Demo B — AI Threat Detection | **Yes, as replay** | `replay_cicids.py --target backend`; say "replayed flow records" and quote P3/P4 next to the 98.97 % |
| Demo C — Autonomous Incident Response | **Yes, simulated** | manual block / unblock / TTL expiry with the mock adapter; say "simulated firewall rule" |

Final-year demonstration: ready, once the five passwords are changed. Production deployment: **not ready** — no TLS
deployment has been run, compose with auth is untested, real enforcement untested, the model does not generalise across days (measured),
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
