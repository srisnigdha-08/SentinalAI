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

## Commands run in the final pass (read-only)
- git log/diff/branch -r --contains/grep; value comparison of HONEYPOT_API_KEY vs history (match flag only)
- `.venv/Scripts/python -I -c` loading xgb v1 / rf v3 / rf v2 pickles to read feature_importances_ (no writes)
- python reading meta/registry JSON; greps over backend, ai-engine, honeypot, frontend, compose

## Open questions for the user
- Is the GitHub repo public? (decides whether SEC-001 history purge is needed in addition to rotation)
- Another session/process committed while the audit ran; confirm no one else is editing before acting on the roadmap.

## Next step
Fix batch 2 done and suites re-run green on 2026-11-01 (FIXES.md). Remaining: SEC-001 host/history/passwords,
the paper wording, and one live Cowrie run (F1-001, CORE-004).
