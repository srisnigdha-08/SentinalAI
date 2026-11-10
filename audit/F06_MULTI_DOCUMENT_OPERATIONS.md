# F-06 — Multi-document operations: map, fault injection, replica-set plan

Branch `backend-remediation`, 2026-11-07. Disposable MongoDB only (mongodb-memory-server: standalone and a
single-member replica set). No existing MongoDB installation or database was read, converted or changed.

## 1. Why this matters

The backend runs on a **standalone** MongoDB by default (`docker-compose.yml`, native install). Standalone MongoDB
has no multi-document transactions, so every operation that writes more than one document relies on one of:

| Mechanism | Where |
|---|---|
| **T** — transaction when `MONGO_USE_TRANSACTIONS=true` **and** the server is a replica set; otherwise the compensating fallback (`utils/transactionHelper.js`) | user provisioning / update / force-logout, threat block |
| **C** — compensating writes that undo the earlier step on failure | the fallbacks above, `containmentService.blockThreat` (Scenario A), `blockIPManual` (Scenario B), `aiService.storePrediction` |
| **S** — durable state machine plus a reconciliation pass that finishes or repairs the operation later | containment (`ContainmentAction` + adapter rule + `BlockedIP` + `ThreatLog`) |
| **I** — idempotent, ordered steps: a retry converges, an interruption leaves a safe state | retention (archive, then delete), honeypot closure (`$setOnInsert` deny-list) |
| **N** — no cross-document guarantee; the second write is best-effort and logged | listed in §2 with the consequence |

## 2. Map

| Operation | Documents written (order) | Mechanism | Interruption between writes leaves | Fault-injection test |
|---|---|---|---|---|
| `provisionUser` (`POST /api/users`) | User → AuditLog | T / C (delete user) | T: nothing. C: user deleted, 503 | `multiDocumentFaults` ×2 modes |
| `updateUser` (`PUT /api/users/:id`) | User → AuditLog | T / C (restore snapshot) | T: nothing. C: **was** partial (fixed, §3) | `multiDocumentFaults` ×2 modes, 2 cases |
| `forceLogoutUser` | AuditLog → User (`$inc authVersion`) | T / C (abort before the user write) | C: an audit entry for a force-logout whose `$inc` then failed (the audit records an attempted action) | `multiDocumentFaults` ×2 modes |
| `blockIP` (`POST /api/threats/:id/block`) | ThreatLog → BlockedIP → ThreatLog.containmentId → AuditLog, then adapter rule (after commit) | T / C (restore snapshot) | T: nothing. C: **was** unblocking a legitimately blocked IP (fixed, §3) | `multiDocumentFaults` ×2 modes, 3 cases |
| `containmentService.blockThreat` | ThreatLog → BlockedIP | C (Scenario A: revert ThreatLog) | ThreatLog reverted; a failed compensation is flagged `isInconsistent` and logged CRITICAL | `blockFromTriageStatus`, `mediumContainment` |
| `blockIPManual` / `unblockIPManual` | BlockedIP → ThreatLogs (many) | C (Scenario B) | BlockedIP restored or removed | `mediumContainment`, `unblockRepeatDetections` |
| `requestContainment` | ContainmentAction (REQUESTED…APPLYING) → adapter → ContainmentAction ACTIVE → legacy BlockedIP / ThreatLog (`legacySync.pending`) | S (unique `targetLock`, `optimisticConcurrency`, reconciliation) | APPLYING: recovery inspects the rule (PRESENT / ABSENT / UNKNOWN), never releases on UNKNOWN; pending legacy sync re-run | `containmentApply*`, `containmentStuckRecovery`, `containmentPostActive`, `containmentLifecycle` |
| `rollbackContainment` / TTL expiry | ContainmentAction ROLLING_BACK → adapter remove → ROLLED_BACK → BlockedIP / ThreatLog restore | S (fencing; concurrent release → 409) | ROLLING_BACK with rule state unknown → `ROLLBACK_FAILED`, surfaced in `/api/containment/recovery` | `containmentLifecycle`, `containmentPostActive` |
| `aiService.storePrediction` | AIPrediction → ThreatLog → (auto-block) | C (unlink `generatedThreat` when the ThreatLog write fails) | prediction without a threat link; auto-block runs only after the ThreatLog exists | `aiDegradedMode`, `aiMediumFixes`, `thresholdConsistency` |
| Honeypot session closure (`analyseClosure`) | HoneypotSession → ThreatLog → BlockedIP (`$setOnInsert`) → Alert | I + N | a session analysed without its alert; the deny-list upsert is idempotent; the alert is best-effort | `honeypotPhase5`, `mediumHoneypot` |
| `applyRetention` | archive copies (3 collections) → deletes (3) → AIPrediction unlink → AuditLog | I (archive before delete; archive now upsert-only, §3) | live records + archived copies; the next run finishes | `multiDocumentFaults` (retention), `retentionPolicy` |
| `restoreFromArchive` | live collections (`$setOnInsert`) | I | partial restore; rerun converges | `retentionPolicy` |
| Auth session rotation (`authSessionService.rotate`) | single AuthSession document (conditional update) | single-document atomic | — | `authPersistence`, `authHardening` |
| Training sample transitions | TrainingSample (single doc) | single-document atomic | — | `trainingSample` |

## 3. Defects found by fault injection and fixed

All three are in the standalone fallback, which is the default deployment path. Every test below fails on
`f04eae0` and passes on this branch (`tests/multiDocumentFaults.test.js`: 5 of 18 failed on the old code;
the retention case failed with E11000).

1. **`blockIP` audit failure unblocked a legitimately blocked IP.** The compensation deleted the IP's
   `BlockedIP` entry and set the threat to its pre-block status unconditionally. On a repeated block, or on an
   IP another threat had already deny-listed, an audit-write failure therefore *removed* an existing block. It
   also left `handledBy`, `containmentId` and `autonomousAction` from the failed block. Fix: snapshot the
   threat's block fields and the existing `BlockedIP` document before the block, and restore exactly that
   snapshot (re-insert the prior entry, or delete only an entry this request created).
2. **`updateUser` audit failure left part of the change applied.** Only role / status / authVersion were
   reverted, so a name or department change stayed while the API answered "change not applied", and
   `tokenVersion` stayed incremented. Fix: snapshot every field in the update plus both session counters.
3. **Retention stuck after an interrupted run.** Archive copies keep the original `_id`; with `insertMany`, a
   run that archived and then failed before deleting made every later run fail with E11000, so retention never
   completed again without manual cleanup. No data was lost (archive before delete held). Fix: archive with an
   insert-only upsert (`$setOnInsert`, keyed by `_id`), so the retry keeps the first archived copy and finishes.

Remaining standalone limitations (documented, not changed):
- A compensation is itself a write and can fail (connection lost between the two writes). `blockThreat` flags
  that as `isInconsistent` and logs CRITICAL; the controller-level compensations log `[AUDIT_FAILURE]`. Only a
  transaction removes this window.
- A compensation restores a snapshot taken at the start of the request; a concurrent change to the same
  document in that window would be overwritten by the restore. Requests on the same user or threat by two
  administrators within milliseconds are rare; transactions remove this too.
- `forceLogoutUser` writes the audit entry first: if the `$inc` then fails, the log shows an attempted
  force-logout that did not take effect (the error is returned to the operator).

## 4. Existing replica-set tests (`tests/transactionSupport.test.js`, Part A.3)

These connect to a fixed replica set on port 27030 with hard-coded test credentials and **return early (pass)
when it is not running**, which is the normal case locally and in CI, and they exercise MongoDB's own
transactions on hand-built models rather than the application's code paths. They were left unchanged (removing
or rewriting existing tests was not in scope); `multiDocumentFaults.test.js` now covers the transaction path
through the real controllers on a disposable `MongoMemoryReplSet`, and asserts `shouldUseTransactions() === true`
so it cannot silently fall back to the standalone path.

## 5. Replica-set migration plan (not executed; requires owner approval)

Goal: run the existing deployment as a single-node replica set so `MONGO_USE_TRANSACTIONS=true` takes effect.
Standalone support stays: the fallback path is unchanged and still tested.

Pre-checks
1. Back up first: `mongodump --uri "$MONGO_URI" --out <backup-dir>` and verify with `mongorestore --dryRun`.
2. Record the current `db.version()` and `rs.status()` (expected: "not running with --replSet").

Docker (`docker-compose.yml`)
3. Add `command: ["mongod", "--replSet", "rs0", "--bind_ip_all"]` to the `mongo` service. With authentication
   enabled a replica set also needs `--keyFile` (a 400-permission file mounted read-only), even single-node.
4. Start, then once: `mongosh --eval 'rs.initiate({_id:"rs0",members:[{_id:0,host:"mongo:27017"}]})'`.
5. Change the backend `MONGO_URI` to add `replicaSet=rs0`, and set `MONGO_USE_TRANSACTIONS=true`.
6. Healthcheck: replace the ping with `rs.status().ok` so the backend waits for a PRIMARY.

Native Windows service
3. Add to `mongod.cfg`: `replication: { replSetName: rs0 }` (plus `security.keyFile` if auth is on); restart
   the service; `rs.initiate()` with host `127.0.0.1:27017`.
4–6 as above.

Verification
7. `GET /health/ready` is 200; `node -e` check that `shouldUseTransactions()` is true at runtime (a log line at
   startup is suggested as a follow-up).
8. Run `npx jest tests/multiDocumentFaults.test.js` (disposable) and the integration harness against the
   migrated stack.

Rollback
9. Remove `--replSet` / `replication`, restart, remove `replicaSet=rs0` and `MONGO_USE_TRANSACTIONS`. Data files
   are compatible; the `local.oplog.rs` collection is simply unused.

Risks: a single-node replica set adds no redundancy; it is only for transactions. If the node is not PRIMARY
(e.g. after an unclean restart while initiating), writes fail until it is, which `/health/ready` reports as
`database: disconnected` only if the driver cannot select a primary.
