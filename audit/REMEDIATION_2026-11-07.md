# Backend remediation — fix report (2026-11-07)

Branch `backend-remediation`, created from `f04eae03e3c2f610a79a8897e6b85322b2c46cdc` (= `db-fixes` = PR #1 head).
Local commits only; nothing pushed, PR #1 not merged, nothing deployed.

## A. Summary

Seven findings and two containment reviews were worked; three real data-consistency defects were found by the
new fault-injection tests and fixed. SEC-001 is unchanged (owner action). All suites green.

## B. Fix table

| ID | Status | Commit | What changed | Proof |
|---|---|---|---|---|
| F-03 health | FIXED | b8cc177 | `/health/live` (always 200), `/health/ready` (Mongo + revocation required; AI engine reported, `degraded`); `/health` unchanged; compose healthcheck | `healthEndpoints` 6 (6/6 fail on old code); live probe |
| F-04 shutdown | FIXED | 943788d | HTTP stops before Socket.IO (no false ERR_SERVER_NOT_RUNNING), repeated signals join one shutdown, single exit, unhandled rejection → exit 1 | `gracefulShutdownReal` 6 (6/6 fail on old code), real-process `serverLifecycle`, probe exit 0 in 136 ms |
| F-05 body errors | FIXED | 90addc5 | fixed messages for body-parser errors (400 malformed, 413 too large, 415 charset); 11000 without keyValue no longer throws | `requestBodyErrors` 9 (6 fail on old code); probe |
| F-06 multi-document | PARTIALLY FIXED | b93a550 | map + 3 fixes: blockIP audit failure unblocked a legitimate block; updateUser left partial changes; retention stuck after interruption | `multiDocumentFaults` 19 on standalone and replica set (5 + retention fail on old code); `F06_MULTI_DOCUMENT_OPERATIONS.md` |
| F-07 containment audit | FIXED | fbbbd37 | `containment_audit_events`: append-only, deduplicated, DB sequence + DB clock, per-action ordering, outage backlog, `GET /actions/:id/audit` (admin/analyst) | `containmentAuditDurable` 10 (10/10 fail on old code); harness; probe across Mongo restart |
| CONT-R1 clocks | VERIFIED (no change needed beyond F-07) | fbbbd37, 3f6a603 | review: all comparisons single-clock; audit uses DB time | `CONTAINMENT_CLOCKS.md`; skewed-clock test |
| CONT-R2 operator recovery | FIXED | 3f6a603 | admin diagnosis (read-only, signed single-use token) + recover (trusted Origin, token, reason, CAS on version, same `_recoverOne`; never releases on UNKNOWN) | `containmentOperatorRecovery` 14; roleMatrix RBAC + Origin |
| F-08 coverage | PARTIALLY FIXED | 7e5ecaa | scope adds websocket, routes, models, config, server.js; tests for priority files | see C |
| F-09 findings index | FIXED | 7f90cc4 | generated `STATUS_INDEX.md` (+ `--check`); history unchanged | generator check |
| DEP-002 dependencies | PARTIALLY FIXED | 60020f1 | compatible `npm audit fix`; backend 0 high (body-parser fixed), frontend axios / react-router fixed | suites green; remaining in E |
| SEC-001 | REQUIRES OWNER ACTION | ebd56ef | redacted inventory + procedure only | secret scans 0 |
| TEST-012 (new) | NOT VERIFIED (environment) | — | in-memory mongod start timeout under load, 2/5 runs | last 3 runs clean |

## C. Coverage (same tests, honest scopes)

| Scope | Lines | Branches |
|---|---|---|
| Old scope (services, utils, controllers, middleware), before new tests | 83.74 % | 74.42 % |
| Wide scope (+ websocket, routes, models, config, server.js), before new tests | 84.12 % | 74.32 % |
| Wide scope, after | **85.72 %** | **76.66 %** |

containmentController 45.6 → 97.8 %, threatService 67.0 → 98.9 %, middleware/auth 86.3 → 100 %, websocket/auth
85.4 → 97.9 % (lines). server.js stays 76 %: its startup/shutdown test runs out of process and is not counted.

## D. Verification (2026-11-07, this branch)

| Check | Result |
|---|---|
| Backend Jest (full) | 1425 passed, 13 skipped (pre-existing skips); last 3 consecutive runs clean |
| Frontend unit / lint / build | 84/84, 0 problems, build OK |
| Backend lint | 0 problems |
| Integration harness (real engine + backend, disposable mongod :27032) | 36 passed, 0 failed (`runs/20261107_112124`) |
| Live probe (disposable mongod, dev mode, AI engine down) | all expected statuses; no secrets in log; 0 uncaught |
| Bounded load (loopback, conc 20) | /health/live 2000 req 343 req/s p95 93 ms; /health/ready 469 req/s p95 79 ms; /api/threats 59 req/s p95 658 ms; /api/containment/actions 46 req/s p95 732 ms; **0 5xx**, heap 98 MB after |
| Secret scan | tree 0, f04eae0..HEAD 0, history 0 outside baseline |
| Model registry / models | registry `5f76c136…`; XGB, IF, golden set match registry sha256 |
| Q-tables | demo `90b310ba…`, seed `bf9b46a1…`, runtime `08209e99…` unchanged |
| Firewall | mock adapter only; `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` everywhere |

Notes: the probe's p99 for /health/live (1.6 s) is a single-machine tail under concurrent load, not a measured SLO.
The load section raised `RATE_LIMIT_MAX` for the probe process only.

## E. Requires owner decision

- SEC-001: change the 9 passwords (`SEC001_REMEDIATION.md`), then the read-only checker.
- F-06: replica-set migration (`F06_MULTI_DOCUMENT_OPERATIONS.md` §5), needs a backup and approval.
- Major upgrades: frontend vite 5 → 8 (esbuild dev-server advisory, high); backend swagger-jsdoc → 6.2.8
  (glob/minimatch, moderate); Jest toolchain advisories (dev only; npm's suggested jest 25 is a downgrade, not
  recommended).
- Push of `backend-remediation`, and whether it goes into PR #1 or a separate PR.

## F. Not changed (by constraint)

ML models, Isolation Forest, registry hashes, Q-tables, RL behaviour, thresholds; real firewall enforcement;
the developer's MongoDB installation and databases; credentials; Git history; network exposure; standalone
MongoDB support.

## G. Pre-PR safety review (addendum)

Six defects found by reviewing the diff (not by the earlier tests), each fixed with a regression test that fails
on the previous code: REV-001 … REV-006 in `FINDINGS.md` (commits fc1064b, 3452bbf, bd01bfc, 6cdcd2f, 435abc1).
TEST-012 root cause: orphaned test processes from an aborted run plus post-install scanning; no harness defect.
SEC-001: owner runbook `SEC001_ROTATION_RUNBOOK.md` and read-only checker `scripts/security/sec001_check.cjs`.

Audit durability guarantees (F-07): stored events survive MongoDB restarts (probe); retries cannot duplicate
(unique eventId, tested); per-action order is preserved across outages (tested); events queued during an outage
are in memory only and are lost if the process dies before MongoDB returns (still in the application log);
shutdown waits for in-flight writes and flushes once (finalizer).

Final verification after the review fixes: backend Jest 1438 passed / 13 skipped in 2 consecutive full runs (no
start timeouts); integration harness 36/36 (`runs/20261107_121210`); live probe all expected; load 0 5xx
(/health/ready 2766 req/s p95 12 ms, /api/threats 273 req/s p95 102 ms); frontend 84/84, lint, build; secret scans
0; models, registry and Q-tables unchanged; `db-fixes` still `f04eae0`.
