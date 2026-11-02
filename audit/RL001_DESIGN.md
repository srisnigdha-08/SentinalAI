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

## Review of the remaining design choices (2026-11-02, evidence-based)

**What is verified** (tests + live lab, batch 5): one draw → one `decisionId`; 6 concurrent first requests → 1
decision (unique pending lock); the rotator applies, acknowledges or fails that id (compare-and-set, 409 otherwise);
stale/wrong-state decisions are superseded and cannot be applied; a failed restart restores `cowrie.cfg` and marks the
decision FAILED; the served persona is read from `cowrie.cfg` and credited (`servedProfile`); the Q-learning update
code and its tests are unchanged (pytest 604 green); least-privilege role includes `deceptiondecisions`.

**Retention:** one decision per rotation (hourly by default ≈ 8,800 small documents per year). Not covered by
`retentionService`; harmless at this size, but if it is wanted: add `deceptiondecisions` (APPLIED/FAILED/SUPERSEDED
older than N days) to the retention job. Not changed.

**Per-session `recommendedProfile`:** the engine draws at every closure and the backend stores it; nothing applies
or displays it. Recommendation: stop storing it (or store the greedy choice as `greedyProfileAtClose`) — an engine +
backend change and two test updates; it changes no learning. Awaiting your choice.

**Minimum evidence before switching:** today a rotation can draw while the served persona has 0 closed sessions.
Measured data: `sentinel-db` has 8 sessions (7 synthetic `demo-*`), `sentinel-demo` 12 (all from integration runs,
all `ubuntu_22`) — so every Q-value in use comes from the synthetic seed. Switching with no observations is pure
exploration. A rule "≥ N closed real sessions under the current persona, or ≥ T hours" (e.g. N = 5, T = 24) is
justified; it changes the rotation cadence, i.e. the policy, so it needs your decision.

**Instability:** each switch restarts Cowrie (drops live sessions; the rotator waits while any are open) and changes
the host's OS, kernel string and filesystem. A host whose OS changes every hour is itself a honeypot tell for a
returning attacker. Switching is also the treatment being evaluated, so frequent switching makes attribution of
rewards noisier. Both argue for a longer dwell (above).

**Reward:** `calc_reward` (`rl_engine/deception_scorer.py`) = 2·log(1 + minutes) + 0.3·commands + intent bonuses +
0.5·IOCs + 2 (login) − fingerprint penalty, clipped to [−10, 20]. It measures **engagement / intelligence collected**,
not a defensive outcome (blocked follow-up attacks, analyst-useful IOCs, attacker deception confirmed). It is also
confounded by the attacker population (bots vs humans, time of day), which the persona does not control.

### Evidence needed before claiming RL beats a fixed persona

1. **Baseline arm:** a fixed persona (e.g. the shipped `centos_7`) and a uniform-random rotation arm.
2. **Assignment:** alternate arms in fixed time blocks (e.g. 24 h), same host, same exposure, randomised block order,
   pre-registered length; or two identical honeypots on adjacent addresses, one per arm.
3. **Metric:** mean per-session reward (pre-registered), plus non-reward outcomes: sessions with ≥ 1 command, unique
   IOCs per day, fingerprint-command rate (a direct "detected the honeypot" proxy), session length.
4. **Size:** n per arm from the observed reward variance: n ≈ 2·(1.96 + 0.84)²·σ²/δ² for δ the smallest effect of
   interest (80 % power). σ is unknown today (the 12 real sessions are self-generated); estimate it from the first week.
5. **Only real attacker sessions** (exclude `demo-*`, integration sessions, own IPs).
6. **Report:** effect with CI, per arm, plus the learner's Q-table trajectory; a non-significant result is reported as such.

Until that experiment runs, the justified claim is: "a tabular Q-learning / bandit recommender selects personas and
the system applies them safely and auditably"; **not** "adaptive deception improves engagement".

## Recommended defaults (2026-11-02; not implemented — they change the policy, so they need your approval)

| Choice | Recommendation | Effect on behaviour | Effect on the Demo A rotation |
|---|---|---|---|
| Per-session `recommendedProfile` | **Rename** to `greedyProfileAtClose` and store the greedy choice (no draw at closure); keep the field for analytics. Engine: `process_session` returns `greedyProfile`; backend stores it | removes the misleading second "recommendation"; one draw per rotation decision only | none |
| Minimum real-session evidence | `DECEPTION_MIN_SESSIONS=5` closed, non-synthetic (`demo-*` excluded), non-own-IP sessions under the current persona before a new decision is drawn; otherwise the recommendation endpoint answers "keep" without drawing | no exploration away from a persona with no observations | the scripted demo has only 1–2 sessions: run `cowrie-demo-mode.sh rotate --once --force` with `DECEPTION_MIN_SESSIONS=0` for the demo, stated as a demo override |
| Minimum dwell | `DECEPTION_MIN_DWELL_HOURS=24` since the last applied decision | ≤ 1 OS change per day — less of a honeypot tell, cleaner reward attribution | same override for the demo |
| Fixed-persona baseline | arm "fixed `centos_7`" and arm "uniform random", alternated in 24 h blocks with randomised order, same host; needs a new rotator option (proposed `--policy fixed|random|learner`; does not exist yet) | enables the comparison in "Evidence needed" above | none |

Until the baseline comparison has run, documentation and the viva say: "persona selection by a tabular Q-learning /
bandit recommender, applied safely and auditably; effectiveness versus a fixed persona not yet measured".
