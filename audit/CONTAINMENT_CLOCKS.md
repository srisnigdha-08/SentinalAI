# CONT-R1 — Clock use in containment (review, 2026-11-07)

Question: does any containment decision depend on two clocks agreeing (backend host vs. MongoDB server), and
should database time be used instead?

## Where time is used

| Decision | Written with | Compared with | Same clock? |
|---|---|---|---|
| TTL expiry (`reconcileExpiredActions`: `expiresAt <= now`) | backend `new Date()` at activation (`containmentPolicyService`) | backend `new Date()` in the pass | yes (backend) |
| Stuck-request grace (`recoverAbandonedApplications`: `updatedAt <= now - grace`) | Mongoose `timestamps` (backend clock) | backend `new Date()` | yes (backend) |
| Late-rule back-off (`lateRuleNextAttemptAt`) | backend | backend | yes (backend) |
| Operator recovery minimum age and token expiry (CONT-R2) | backend | backend | yes (backend) |
| Audit ordering (F-07) | **database** counter `seq` and `$$NOW` (`recordedAt`); backend time kept as `occurredAt` | — | ordering is independent of the backend clock |

Every comparison reads both sides from the backend clock, so a constant offset between the backend host and
the MongoDB server has no effect, with one backend process (the supported deployment). The audit trail, where
order is the point, now uses the database clock and a database sequence
(`tests/containmentAuditDurable.test.js` runs with the backend clock 3 h fast).

## Remaining clock risks (not changed)

- **A backend clock step** (manual change, NTP correction of a large drift) moves every TTL decision. A step
  forward ends blocks early (an address is unblocked before its duration); a step back extends them. Bounded
  by the size of the step; no rule is ever left without a database record.
- **Several backend processes on different hosts** would compare one host's `expiresAt` with another host's
  clock. Not a supported deployment; if it becomes one, switch the expiry and grace queries to `$$NOW`
  (`$expr: { $lte: ['$expiresAt', '$$NOW'] }`), which is a small, testable change.

Recommendation: keep NTP on the backend host (Windows Time service, the default) and leave the expiry logic as
it is. Switching expiry to database time is not justified for a single-process deployment and would change
tested TTL behaviour; it is listed as an option for the owner, not applied.
