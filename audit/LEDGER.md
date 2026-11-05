# Audit Ledger — SentinelAI evidence-driven audit (v2)

Started 2026-10-20. Auditor: Claude. Writes only under `audit/`, except fix batch 1 (user-requested, see FIXES.md).

## Status
| Stage | State |
|---|---|
| 1 Inventory | DONE (at f2e6bc8) |
| 2 Critical flows | DONE (at f2e6bc8) — STAGE2_FLOWS.md; superseded by REPORT.md §2 at a5856b7 |
| Fix batch 1 | APPLIED + VERIFIED 2026-10-21 (Jest 948, pytest 335, frontend 36 + build) — FIXES.md |
| Re-verification | DONE at a5856b7 (16 new commits e5318ac…a5856b7 landed during the audit) |
| 3 Claims vs reality | DONE — REPORT.md §3 |
| 4 Security | DONE — REPORT.md §4, FINDINGS.md |
| 5 ML validity | DONE — FINDINGS.md ML-001 (withdrawn), ML-004, ML-005, RET-001 |
| 6 Tests | DONE — REPORT.md §5 (suites not re-run at a5856b7) |
| 7 Ops/docs | DONE — OPS-002/003/004, EVT-001 |
| Final report | DONE — REPORT.md |
| Fix batch 3 | APPLIED 2026-11-01 — FIXES.md (baseline breakers: Windows Q-table race, CI lint; OPS-002/004, SEC-005, EVT-001) |
| Fix batch 4 | APPLIED 2026-11-01 — FIXES.md, READINESS_2026-11-01.md, SEC001_REMEDIATION.md, ML_EVAL_PLAN.md (integration A-D + live Cowrie + auth Mongo verified; E2E 177/177) |
| Fix batch 5 | APPLIED 2026-11-02 — FIXES.md (SEC-001 sessions verified, self-service password change, scanner hardening, P5, P3/P4 plan, RL-001 decisions, Firefox E2E stall; all suites green) |
| Batch 6 | DONE 2026-11-02 — P3/P4 measured (no cross-day generalisation, ML-007), weakness analysis, RL review, deployment procedure |
| Batch 7 | DONE 2026-11-02 — generalisation root cause (tool fingerprints), ranked options, CSE-CIC-IDS2018 plan, hybrid-eval mode (not run), deployment doc safety |
| Batch 8 | DONE 2026-11-02 — pre-registered development protocol (ML_DEV_PROTOCOL.md), protected-test guard, feature/taxonomy/runner infrastructure (plan only) |
| PR #1 | 2026-11-05 — first e2e.yml run failed: CI-002 rate-limit config, fixed (FINDINGS.md) |
| Batch 20 | DONE 2026-11-04 — CONT-005 post-ACTIVE re-sync, CONT-006 concurrent release 409, CONT-007 back-off, THR-005 startup warm-up, TEST-011 batch 19 sign-out regression (FINDINGS.md) |
| Batch 19 | DONE 2026-11-04 — CI 7/7 on f90d23a; CONT-004 fencing, OBS-001 recovery view, THR-004 source, TEST-010 fixed; E2E-002 synchronised (FINDINGS.md) |
| Batch 18 | DONE 2026-11-04 — CI 7/7 on 97dfa87; THR-003 fixed; CONT-003 review; PR-001 cleanup prepared; HYG-001 keep; TEST-010 (FINDINGS.md) |
| Batch 17 | DONE 2026-11-04 — CONT-003 fixed (apply recovery, adapter inspectRule); THR-002 fixed (owner-approved alert-line alignment); PR-001, HYG-001 noted (FINDINGS.md) |
| Batch 16 | DONE 2026-11-04 — re-audit at 452666f: CONT-002, ML-021, UI-005 fixed; DOC-003, HYG-002; CONT-003, THR-002, DEP-001 open (FINDINGS.md) |
| Batch 15 | DONE 2026-11-03 — demo A/B/C rehearsal on the real stack; CONT-001 and OPS-004 fixed; runbook corrections; presenter script, metrics, presentation, viva bank, deployment/backup plan |
| Batch 14 | DONE 2026-11-03 — final validation: WS-002 live-feed duplicates and catch-up, TEST-009 root cause, clean-clone setup fixes, demo A/B/C revalidated, final guide and viva guide |
| Batch 13 | DONE 2026-11-03 — performance and resilience: PERF-001 engine threading, WS-001 socket reconnect, UI-004, load/failure harness, docs |
| Batch 12 | DONE 2026-11-03 — GitHub Actions failures reproduced on Linux and fixed (CI-001), job timeouts, TEST-007, REPRO-001, frontend lint 0 warnings; awaiting CI confirmation |
| Batch 11 | DONE 2026-11-03 — per-threat SHAP (XAI-001), Threat Logs race (UI-003), frontend lint (LINT-001), E2E-002 experiment |
| Batch 10 | DONE 2026-11-02 — engineering validation, verified Demo A/B/C runbook, UI-002 fix, TEST-006, XAI-001 documented, latency probe |
| Batch 9 | DONE 2026-11-02 — 21-02 FP diagnostics, pipeline integrity, macro/pooled summary, protocol v2 (C4A/C4B, prediction dump; not run) |

## Commands run in the final pass (read-only)
- git log/diff/branch -r --contains/grep; value comparison of HONEYPOT_API_KEY vs history (match flag only)
- `.venv/Scripts/python -I -c` loading xgb v1 / rf v3 / rf v2 pickles to read feature_importances_ (no writes)
- python reading meta/registry JSON; greps over backend, ai-engine, honeypot, frontend, compose

## Open questions for the user
- Is the GitHub repo public? (decides whether SEC-001 history purge is needed in addition to rotation)
- Another session/process committed while the audit ran; confirm no one else is editing before acting on the roadmap.

## Next step
v3 + operating line + stability check done 2026-11-02. C4-A-I eligibility and frozen lines robust (ML-020); at the lines
the 2018 recall advantage over C0 is +0.9 to +7.3 points, so the deployment criterion is predicted to fail. Owner
decides whether to spend the one-shot external test (4.98 GB). Served model stays. SEC-001: OPEN, risk accepted by the owner 2026-11-02 (passwords left unchanged; local-only exposure; SEC001_REMEDIATION.md).
