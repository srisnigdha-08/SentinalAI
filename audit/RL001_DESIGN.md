# RL-001 — stored recommendation vs applied persona: cause and proposed mechanism

Investigated 2026-11-02 (code reading + the live lab run of 2026-11-01). **Implemented later on 2026-11-02**
(section "Implemented"); the learning policy itself is unchanged.

## What happens today

| Step | Code | Draw? |
|---|---|---|
| A session closes → backend `finishClosure` → engine `POST /deception/score` | `SessionScorer.process_session` (`ai-engine/rl_engine/deception_scorer.py`) updates Q[prev][active] and then calls `learner.choose_action(active)` | **yes**: stored on that session as `recommendedProfile` (`backend/services/honeypotService.js` `finishClosure`) |
| Rotator asks what to serve → `GET /api/honeypot/ingest/deception/recommendation` → engine `GET /deception/recommendation` | `main.py deception_recommendation` calls `choose_action(current)` | **yes**, fresh |
| Rotator finds the backend's recorded persona differs from cowrie.cfg → records it → asks again | `honeypot/deception_rotator.py rotate_once` | **yes**, a second fresh draw |
| Rotator applies `nextProfile` from the last response | `switch_profile.generate_config`, restart, `PUT …/deception/profile` | — |

`choose_action` is ε-greedy (ε = 0.2 decaying with episodes, floor `EPSILON_MIN`) or UCB1. With N sessions closed
between two rotations there are N + 1 or N + 2 independent draws; only the last is applied, and nothing records it.
In the 2026-11-01 lab run session 1 stored `debian_11` (greedy) while the rotator's own draw explored to
`raspberry_pi`, which was applied.

What is **not** broken: credit assignment. Each closure is credited to the persona the session was served
(`servedProfile`, captured at session start and read from cowrie.cfg), with the previously served persona as state,
so learning uses the applied action regardless of which draw chose it.

What is wrong:
1. The per-session `recommendedProfile` is shown as "recommended" but is never a decision anyone applies.
2. Exploration happens at request time, so the effective exploration rate depends on how often the rotator (or an
   analyst's dashboard, which calls the same engine method) asks — not on ε.
3. Nothing records which draw was applied, whether it was exploration, or the Q-state it came from, so a switch
   cannot be audited or reproduced.

## Proposed mechanism (deterministic decision → application)

One decision object per rotation, created once, applied once:

```
DeceptionDecision {
  decisionId, state (persona served when decided), action (persona to serve next),
  explored: bool, policy, epsilon, rngSeed, qEpisode (episode_count), qHash (sha256 of the Q-table row),
  basis: { sessionsClosedUnderState, since },
  status: PENDING | APPLIED | FAILED | SUPERSEDED, createdAt, appliedAt, appliedBy, failureReason
}
```

1. **Closures stop sampling.** `process_session` keeps the Q update and returns `greedyProfile` (deterministic,
   informational) instead of a draw; the session field becomes `greedyProfileAtClose`. Q-learning itself is unchanged.
2. **Decide once.** `GET …/deception/recommendation` returns the PENDING decision for the currently served persona
   if one exists; otherwise it creates one atomically (`findOneAndUpdate({state, status:'PENDING'}, $setOnInsert,
   {upsert:true})` with a unique partial index on `status:'PENDING'`). Repeated or concurrent requests — two
   rotators, the dashboard, the rotator's second call — all get the same decision. The engine draws with a seeded
   RNG (`rngSeed = hash(decisionId)`), so the choice is reproducible from the stored state.
3. **Evidence before deciding.** No decision until at least `DECEPTION_MIN_SESSIONS` (e.g. 3) sessions have closed
   under the current persona, or `DECEPTION_MIN_DWELL_MINUTES` has passed; otherwise the response is "keep" without
   a draw. Today a rotation can explore away from a persona that has no observed reward yet.
4. **Apply by id.** The rotator applies `action` and records it with `PUT …/deception/profile {profile, decisionId}`.
   The backend marks the decision APPLIED only if it is still PENDING and its `state` equals the recorded persona
   (compare-and-set), then records the served persona. A failed restart (the rotator already restores cowrie.cfg)
   marks it FAILED with the reason; the next request creates a new decision.
5. **Concurrent sessions.** Unchanged rules, made explicit: the rotator does not apply while `activeSessions > 0`
   (unless `--force`, which is logged on the decision); a session open across a switch stays credited to the persona
   it started under; sessions that start after the restart get the new persona. A PENDING decision older than the
   rotation interval × 2 is SUPERSEDED so a stale choice is never applied after long attacker activity.
6. **UI.** Show "serving X since …", "pending decision: Y (explore | exploit), basis N sessions", and the history of
   applied decisions — not a per-session recommendation.

Tests this needs (when implemented): two concurrent recommendation requests return one decisionId; closures do not
change the pending decision; apply with a stale decisionId is rejected; failed restart → FAILED and cfg restored;
fixed seed → same action; the live lab check asserts the applied persona equals the decision's action.

Open choice for you: keep the per-session field (renamed, greedy) or drop it.

## Implemented (2026-11-02)

| Part of the proposal | Done? | Where |
|---|---|---|
| Decision object, unique id, persisted | yes | `backend/models/DeceptionDecision.js` (`decisionId`, state, action, explored, policy, provenance, status, applied*/failure*) |
| Decide once; repeat and concurrent requests reuse it | yes — unique partial lock (`pendingLock`) makes "one PENDING decision" a database guarantee; a concurrent loser's draw is discarded | `backend/services/deceptionDecisionService.js currentDecision`; both recommendation routes |
| Apply by id, compare-and-set | yes — must be PENDING, drawn for the persona currently recorded, and the profile must be its action; else 409 | `applyDecision`; `PUT …/deception/profile {profile, decisionId}` (ingest and dashboard routes) |
| "Keep" decisions closed | yes — the rotator acknowledges them, so the next rotation draws anew (same cadence as before) | `honeypot/deception_rotator.py _acknowledge` |
| Failed application recorded | yes — FAILED with reason; cowrie.cfg restored (ROT-001) | `POST /api/honeypot/ingest/deception/decision/:id/fail`, rotator `_fail` |
| Stale / wrong-state decisions never applied | yes — SUPERSEDED when the recorded persona changes or after `DECEPTION_DECISION_TTL_MINUTES` (default 120) | `currentDecision` |
| Learning credits the served persona | unchanged (already true: `servedProfile` from cowrie.cfg) | — |
| Dashboard views no longer draw | yes — the Honeypot Analytics request returns the pending decision | `routes/honeypot.js` |
| Closures stop sampling | **no** — the engine still draws at closure and the backend stores it as `session.recommendedProfile` (informational; nothing applies or displays it; two tests assert it). Changing it means an engine change; left for your decision | — |
| Evidence before deciding (min sessions / dwell) | **no** — changes rotation cadence, i.e. the policy; needs your decision | — |
| Seeded RNG for reproducible draws | **no** — engine change | — |

Backward compatible: a rotator without `decisionId` support still works (it records personas as before), and a
backend without decisions makes the new rotator behave as before. Least-privilege MongoDB role: `deceptiondecisions`
added to `deployment/mongo-init.js`.

Tests: `backend/tests/deceptionDecision.test.js` (7, in-memory MongoDB: reuse, 6 concurrent first requests → 1
decision, compare-and-set refusals, supersede by state and TTL, failure, engine down), route tests in
`honeypotRotatorKey.test.js` and `roleMatrix.test.js`, rotator tests in `ai-engine/tests/test_deception_rotator.py`
(switch / keep / failed restart / deferred), and the live lab check in `run_integration.cjs --cowrie` asserts that the
applied persona equals the APPLIED decision's action.
