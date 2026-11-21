# Persona policy v2: fixing synthetic-seed dominance (shadow by default)

**Status:** implemented and running in **shadow** mode; readiness on 2026-11-12: **NOT READY FOR PRODUCTION PROMOTION** (section 6). The deployed decisions still come from the v1 Q-learner.
v2 is *not* proven against real attackers. Read "Promotion gates" before activating it.

## 1. The problem (v1, `rl_engine/deception_scorer.py`)

| Fact | Evidence |
|---|---|
| The runtime table starts from the shipped seed `models/q_table.json`: **12,087 synthetic episodes**, Q-values up to ~136 | the seed file; `seed_provenance.synthetic: true` |
| Real Cowrie rewards average **3.4** (sd 3.1, 18 sessions); the seed's own rewards were 10.6–19.7 | demo Q-table `reward_history`, 2026-11-12 |
| With γ = 0.9, a persona's value settles near r̄ / (1 − γ). Real data supports about 34, while the seed says about 136, and every update bootstraps from the seed's values | Q update `Q ← Q + α[r + γ·max Q(s′) − Q]` |
| ε = 0.2 / (1 + 0.01·episodes) counts the synthetic episodes, so it starts at its 0.05 floor | `current_epsilon` |
| State = previous persona only, so the problem is really a bandit over 5 servable personas | `SessionScorer.process_session` |
| Result: v1 alternates ubuntu_22 ↔ centos_7 whatever the attacker does, and restarts Cowrie almost every decision | simulation below; real rotations 2026-11-12 |

## 2. Candidates compared (SIMULATED)

`ai-engine/evaluation/persona_policy_sim.py` drives the real code unchanged (v1 learner, `calc_reward`, v2 class) against the Deception Arena's **simulated** attacker, which has assumed persona preferences.
- **Decisions:** one persona per rotation epoch of 4 sessions, with learning after every session.
- **Pairing:** for each seed, every policy faces the same attacker random stream.
- **Tuning:** seeds 0–9. **Reported:** held-out seeds **100–129** (30 runs), as mean ± 95% CI.

Scenarios:
- **S1:** the attacker prefers raspberry_pi (the seed disagrees).
- **S2:** prefers centos_7 (the seed agrees).
- **S3:** persona-blind scripted attacker.
- **S4:** preference flips raspberry_pi → centos_7 at epoch 75.

Columns:
- **Regret:** per session, against an oracle that always serves the best persona.
- **Identify:** whether the best persona was found and then served for 10 epochs in a row; after the flip for S4.
- **Switches:** Cowrie restarts per 100 decisions.

| Policy | S1 regret | S1 identified | S2 regret | S4 regret | S4 identified after flip | Switches/100 |
|---|---|---|---|---|---|---|
| A seeded Q-learning (current v1) | 2.75 ± 0.01 | 0/30 | 0.92 ± 0.02 | 1.82 ± 0.02 | 2/30 | 92–99 |
| B cold-start Q-learning | 2.38 ± 0.15 | 20/30 | 2.37 ± 0.18 | 2.46 ± 0.20 | 12/30 | 5 |
| C rescaled seed ×0.1, ε from real | 1.93 ± 0.13 | 6/30 | 1.41 ± 0.25 | 1.93 ± 0.10 | 6/30 | 13–14 |
| D seeded Q, ε from real episodes | 2.74 ± 0.01 | 0/30 | 0.96 ± 0.02 | 1.80 ± 0.02 | 4/30 | 91–99 |
| E1 UCB1 (existing v1 option) | 1.94 ± 0.02 | 0/30 | 1.97 ± 0.02 | 2.02 ± 0.02 | 0/30 | 91–100 |
| E2 UCB + switch margin, no discount | **0.61 ± 0.19** | 27/30 | **0.49 ± 0.21** | 2.10 ± 0.07 | **1/30** | 3–5 |
| F discounted UCB, no switch margin | 1.02 ± 0.06 | 30/30 | 1.01 ± 0.08 | 1.20 ± 0.09 | 26/30 | 38–40 |
| **G v2: discounted UCB + margin + weak prior** | 1.00 ± 0.08 | **30/30** | 1.00 ± 0.10 | **1.20 ± 0.09** | **30/30** | **17–18** |

**Sensitivity to the synthetic prior's weight** (v2, S1). Weight is "how many real sessions the 12,087 synthetic episodes count as":

| Weight | Regret | Identified | Switches/100 |
|---|---|---|---|
| 0 | 1.01 | 30/30 | 20 |
| **1 (default)** | 1.00 | 30/30 | 17 |
| 10 | 1.27 | 30/30 | 11 |
| 100 | 1.61 | 25/30 | 5 |
| 12,087 | 1.77 | **0/30** | 0 (one persona forever) |

The last row reproduces v1's lock-in inside v2. This confirms the *weight* given to synthetic data is the cause.

**Reading the results.**
- D ≈ A: counting ε from real episodes alone does not help.
- The seed's inflated values are the problem; when the seed happens to be right (S2), A looks good.
- E2 is best when preferences never change, but almost never re-identifies after a flip (1/30).
- G gives up about 0.4–0.5 regret per session versus E2 in stationary cases, but is the **only** policy that identifies the best persona in every run of every scenario, including after the flip.
- G cuts Cowrie restarts by about 80% versus A.
- Overhead: ~0.1 ms per decision or update, the same for all policies.

**Selected: G**, robust over best-case. We do not know whether real attackers' preferences are stationary, and E2's failure mode under change is severe.

## 3. Implementation

`ai-engine/rl_engine/persona_policy_v2.py`: `PersonaPolicyV2`, `POLICY_VERSION = "persona-ducb-v2"`.

- **Arms:** the servable personas (`windows_srv` is never recommended). Rewards are `calc_reward` normalised to [0, 1] with v1's bounds.
- **Discounted UCB:** each real session multiplies every arm's count N and sum S by 0.99, then adds itself. Index = mean + 0.15·√(ln ΣN / N).
- **Switching margin 0.04:** the served persona is kept unless another one's index is higher by 0.04, because each switch restarts Cowrie.
- **Weak prior:** the seed's relative preference, at weight 1 (= one real session), decaying like data. Synthetic and real episodes are counted separately: `prior.syntheticEpisodesRepresented`, `realEpisodes`.
- **Exactly-once learning:** the last 2,000 session IDs are kept, so a retried or re-sent session is not learned twice.
- **Own state file:** `persona_policy_v2.json` next to the v1 runtime table (`DECEPTION_V2_STATE_PATH` overrides). It is versioned, saved atomically under a lock, and refused inside `models/`. **v1's table is never touched.**
- **Deterministic:** no randomness, so the same inputs give the same recommendations.
- **Defaults** (tuned in simulation): `discount 0.99, exploration 0.15, switch_margin 0.04, prior_weight 1`.

### Flags (AI engine environment)

| `DECEPTION_V2` | Effect |
|---|---|
| `shadow` (default) | v2 learns from every scored session (the same inputs v1 sees). Its pick appears as `shadow` in `/deception/recommendation` and as `policyV2` in `/deception/score`. Its pick is **never** applied: the backend reads only `nextProfile`, `policy` and `explored`. |
| `active` | `/deception/recommendation` returns v2's pick (`policy: persona-ducb-v2`). v1's pick is still reported as `policyV1`, and v1 keeps learning. |
| `off` | v2 is not created. |

Other variables: `DECEPTION_V2_PRIOR_WEIGHT` (default 1) and `DECEPTION_V2_STATE_PATH`.

Failure isolation: any v2 error is logged and v1 continues; in `active` mode the endpoint falls back to v1.

**Rollback** from `active`: unset `DECEPTION_V2`, or set it to `shadow`, and restart the engine. v1 has learned every session meanwhile, so nothing needs migrating. Deleting `persona_policy_v2.json` resets only v2.

## 4. Shadow evaluation so far (2026-11-12)

- **Offline replay of the 18 real Cowrie sessions in `sentinel-demo`.** These are all **operator-generated**: the owner's demo attacks and verification sessions, not attacker data.
  - The two policies agree on 16/18 recommendations.
  - After centos_7 was served, v1 went back to ubuntu_22 (its seed loop), while v2 recommended `aws_ec2`, the next persona with no real data.
  - All 18 sessions were learned once; 18/18 deliberate replays were rejected as duplicates.
- **Live, on the real engine with the demo Q-table.**
  - `/deception/recommendation` returns v1's decision plus `shadow: {applied: false, …}`.
  - One real session was scored once: v1 went from 12,105 to 12,106 episodes, and v2 has `realEpisodes: 1`, in separate files.
  - Every rotator decision is still `policy: q_learning`.

## 5. Real-session evidence: what exists and how to collect more

**Tool:** `ai-engine/evaluation/real_session_report.py`. It reads the backend's sessions and decisions read-only and never writes to the database, the Q-tables or the rotator.

```powershell
cd ai-engine
.\.venv\Scripts\python.exe evaluation\real_session_report.py report --mongo-uri mongodb://127.0.0.1:27017/sentinel-demo `
  --q-table $env:USERPROFILE\.sentinelai\demo\q_table.json --v2-state $env:USERPROFILE\.sentinelai\demo\persona_policy_v2.json `
  --operator-sessions <file of session ids you generated> --json-out report.json
```

**What it does:**
- Counts each closed, analysed session once (de-duplicated by `sessionId`).
- Classifies it:
  - **simulated:** `demo-*`;
  - **operator:** loopback, private or link-local sources, `--operator-ip`, `--operator-cidr` or `--operator-sessions`. Cowrie is not internet-facing here, so every private source is the operator;
  - **external:** anything else. Only this class can count as real-attacker evidence.
- Recomputes each session's reward with the learner's own `calc_reward`.
- Reports per served persona: n, mean, sd and 95% t-interval for reward, duration and commands, with a warning below 30.
- Reconstructs the policy in force at each session and the switch history.
- Replays v1 and v2 on the same observed sequence. This is an offline reconstruction from the seed and prior, not the live learners' state.
- Prints the counterfactual limit: for a session, only the served persona's outcome is ever observed.
- **Live evidence** (sessions scored from 2026-11-12 on): the backend stores, with each scored session, the deciding policy (`deceptionPolicy`) and v2's shadow pick at that moment (`shadowPolicy`: version, mode, recommendation, learned). The report counts these live v1/v2 disagreements separately from the offline replay.

The 12,087 synthetic warm-start episodes are shown separately and never counted.

**Findings on 2026-11-12:**
- 19 sessions, **all operator**: 16 served ubuntu_22 and 3 centos_7.
- **0 external sessions for every persona.**
- 8 applied switches, all `q_learning`.
- v1 and v2 agree on 16/19 picks.

**The deployment cannot produce real-attacker evidence as it stands.** Cowrie listens only on 127.0.0.1 or the WSL NAT address, which is unreachable from the internet by design, so every session is the operator's. Collecting gate-1 data needs a **separately authorised, isolated internet-facing honeypot**:
- its own VM or host, not the development machine;
- egress filtering as in `honeypot/docker/egress-rules.sh`;
- no credentials or data from other systems on it;
- compliance with the hosting network's rules.

That decision is the owner's. Nothing here exposes Cowrie.

**Prospective assignment protocol** (on such a deployment):
1. **Schedule.** `real_session_report.py plan --start <ISO> --interval-hours 6 --blocks 60 --seed <s> --out schedule.json` writes randomised permuted blocks: each block serves every servable persona once, in random order, so the assignment probability is 1/5 and time of day is balanced. Neither policy chooses during collection.
2. **Applying it.** Use the verified switch path: each slot's persona through the rotator's checked restart. Driving the rotator from a schedule is a separate, owner-approved change; it is not part of this repository yet.
3. **Adherence.** `report --schedule schedule.json` reports the share of external sessions served the scheduled persona. Gate 2 needs at least 0.9.
4. **Outcome and exclusions.** Primary outcome: `calc_reward`. Secondary: duration, commands, login, the fingerprint flag. Exclusions fixed in advance: simulated and operator sessions, the Deception Arena, and sessions starting within 60 s of a restart.
5. **Sample size.** Gate 1 needs at least 30 external sessions per persona.
   - That detects only large differences: about 2.2 reward units at the observed sd ≈ 3.1.
   - Gate 2 must bound a 0.5-unit loss, and at that spread its CI is narrow enough only at about **300 sessions per persona** when the true difference is small.
   - The readiness tool reports "too uncertain" until then. This is a property of the data, not a reason to relax the gate.

## 6. Promotion gates (`shadow` → `active`)

Activate only when **all** of these hold, and record them:
1. Protocol §5 has at least 30 eligible **external** sessions per servable persona.
2. Offline evaluation on that randomised data shows v2's estimated reward ≥ v1's, and the 95% CI of the difference excludes a meaningful loss (> 0.5 reward units).
3. v2 has run in shadow for at least 2 weeks, with no `Persona policy v2 … failed` lines and consistent exactly-once accounting.
4. A live rollback rehearsal has been done and recorded (§7).

Simulated superiority is **not** a gate.

**Automated assessment.** `ai-engine/evaluation/v2_readiness.py` scores six categories, each with its evidence: engineering readiness, simulation performance (labelled SIMULATED), real-session coverage (gate 1), real-world effectiveness (gate 2), operational safety (gate 3) and rollback readiness (gate 4).
- It prints **READY** only if all six pass; otherwise **NOT READY FOR PRODUCTION PROMOTION** and exit code 2.
- It reads copies of state, never the live file in place.
- It queries the engine read-only.
- The gates are constants in the script, not command-line options.

```powershell
.\.venv\Scripts\python.exe evaluation\persona_policy_sim.py --json-out sim.json          # SIMULATED evidence, ~4 min
$env:SENTINEL_KEY = (Select-String ..\backend\.env -Pattern '^SENTINEL_KEY=(.*)$').Matches[0].Groups[1].Value
.\.venv\Scripts\python.exe evaluation\v2_readiness.py --report-json report.json --sim-json sim.json `
  --v2-state $env:USERPROFILE\.sentinelai\demo\persona_policy_v2.json --engine-url http://127.0.0.1:8000 --current <served persona>
```

**Result on 2026-11-12: NOT READY FOR PRODUCTION PROMOTION.**

| Category | Result | Why |
|---|---|---|
| Engineering | PASS | Shipped defaults equal the simulation-evaluated ones; the live state loads; accounting 1/1 |
| Simulation | **FAIL** | SIMULATED. On held-out scenario S5 (never used for tuning; aws_ec2 preferred, narrow gaps), v2 found the best persona in 28/30 runs. Regret was 0.77 vs v1's 1.40, and restarts 17 vs 98 per 100 decisions |
| Gate 1 | NOT MET | 0 external sessions |
| Gate 2 | NOT MET | Not evaluable |
| Gate 3 | NOT MET | 0 days of shadow; the engine decides with `q_learning` |
| Gate 4 | NOT MET | Automated rollback tests pass, but no live rehearsal is recorded |

## 7. Activation and rollback procedure (prepared, NOT executed)

**Use this only after §6 reports READY and the owner approves.** Since the Rank 6 corrections the engine also
enforces this: `DECEPTION_V2=active` serves nothing unless the newest readiness evidence is READY (§10).

On Windows, with the demo stack running:

```powershell
# 0. Evidence and backups (timestamped copies, never overwritten)
$ts = Get-Date -Format yyyyMMdd-HHmmss; $b = "$env:USERPROFILE\.sentinelai\backups\v2-activation-$ts"; New-Item -ItemType Directory $b | Out-Null
Copy-Item "$env:USERPROFILE\.sentinelai\demo\q_table.json", "$env:USERPROFILE\.sentinelai\demo\persona_policy_v2.json" $b

# 1. Activate: restart only the engine window with v2 deciding (v1 keeps learning in parallel)
powershell -ExecutionPolicy Bypass -File scripts\demo\restart-engine.ps1 -DeceptionV2 active

# 2. Verify: decisions drawn from now on carry policy persona-ducb-v2
mongosh --quiet mongodb://127.0.0.1:27017/sentinel-demo --eval "db.deceptiondecisions.find({}, {_id:0,policy:1,status:1,createdAt:1}).sort({createdAt:-1}).limit(3)"
```

**Notes:**
- A decision already PENDING from v1 is still applied once, or expires after `DECEPTION_DECISION_TTL_MINUTES`. Only new decisions come from v2.
- The rotator, its checks and the dashboard need no change. The panel labels v2 picks "Persona policy v2 (discounted UCB)".

**Rollback**, to be done at any time, and done once as the gate-4 rehearsal:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo\restart-engine.ps1 -DeceptionV2 shadow
mongosh --quiet mongodb://127.0.0.1:27017/sentinel-demo --eval "db.deceptiondecisions.find({}, {_id:0,policy:1}).sort({createdAt:-1}).limit(2)"
```

New draws should show `q_learning` again. v1 never stopped learning, so no state migration is needed. At most one PENDING v2 decision may still be applied after rollback; the same TTL rule applies.

Record the rehearsal for gate 4 as JSON and pass it with `--rollback-rehearsal`:
`{"date": "...", "activeObservedPolicy": "persona-ducb-v2", "rolledBackObservedPolicy": "q_learning"}`

**Full removal of v2:** use `-DeceptionV2 off`. Its state file is kept; delete `persona_policy_v2.json` only to reset v2.

## 8. Independent evaluation and isolated rollback rehearsal (2026-11-13)

**Simulation: S6–S11, seeds 200–229, pre-declared** (`evaluation/persona_policy_independent_eval.py`, committed
before its full run).
- **Not used:** S5 and seeds 0–129. The S5 result (28/30) stands unchanged, and no parameter was tuned.
- **Design:** v1 runs in its deployed seeded configuration, v2 with its shipped defaults. Both policies face the
  same attacker and application-failure draws.
- **Results:** `ai-engine/experiments/persona_policy_independent_20261113/results.json`. Every figure is SIMULATED.

| Scenario | Best identified v1 / v2 | Regret v1 / v2 (paired diff, 95 % CI) | Switches /100 v1 / v2 | Application failures v1 / v2 |
|---|---|---|---|---|
| S6 debian_11, medium gaps | 0 / 30 | 1.55 / 0.90 (−0.65, −0.71 to −0.58) | 96.8 / 17.2 | — |
| S7 raspberry_pi, frequent fingerprinting | 0 / 30 | 1.09 / 0.71 (−0.38) | 98.6 / 18.3 | — |
| S8 persona-blind | n/a | 0 / 0 | 97.5 / 16.5 | — |
| S9 drift ubuntu_22 → aws_ec2 | 0 / 29 | 1.88 / 1.00 (−0.88) | 97.8 / 17.3 | — |
| S10 two close leaders | 2 / 30 | 1.14 / 0.69 (−0.45) | 93.0 / 17.7 | — |
| S11 centos_7, 20 % application failures | 0 / 30 | 0.76 / **0.98 (+0.22, +0.15 to +0.28)** | 75.7 / 16.5 | 30.3 / 7.3 |

Decision latency is about 5–13 µs for both policies. Neither ever recommended an unsupported persona.

**Criteria:**
- **Passed:** C1 (identification), C3 (switching) and C4 (unsupported personas).
- **Failed:** C2. With 20 % failed switches, v2's regret exceeds v1's, because v1's constant switching happens to
  land on the preferred `centos_7` often.

**Simulation verdict: NOT READY.** The failure under unreliable application is a genuine weakness, not a tuning
target.

**Rollback rehearsal: isolated, not live.** `honeypot/rollback_rehearsal.py` drives the real `rotate_once` against
a disposable `cowrie.cfg` and a loopback banner server.

| Scenario | Outcome |
|---|---|
| success | APPLIED, persona recorded |
| failed application (restart exits non-zero) | FAILED, cfg restored |
| timeout (no banner after restart) | FAILED, cfg restored |
| invalid persona (`windows_srv`) | FAILED, cfg untouched |
| restart that does not restart | FAILED, cfg restored |
| wrong SSH banner | FAILED, cfg restored |

All six pass (`tests/test_rollback_rehearsal.py`). This prepares gate 4; it does not satisfy it. Gate 4 still needs
the live rehearsal in §7, done and recorded by the owner.

**Readiness on 2026-11-13: NOT READY FOR PRODUCTION PROMOTION.**

| Gate | Status |
|---|---|
| Simulation | FAIL (C2, S11) |
| Gate 1 | not met (0 external sessions) |
| Gate 2 | not met (not evaluable) |
| Gate 3 | not met (shadow period not recorded) |
| Gate 4 | not met (isolated rehearsal only) |

`DECEPTION_V2` was not changed. v2 remains shadow-only and never applies a decision.

## 9. Shadow verification and V1/V2 comparison (Rank 6, 2026-11-14)

**Call paths (unchanged).**
- **Production:** session closes → backend `closeSession` → engine `/deception/score` → `SessionScorer.process_session`:
  1. V1 learns the session (`DeceptionQLearner.update`, Q-table write).
  2. V1 picks `nextProfile`.
  3. The backend stores `recommendedProfile`, and the rotator later applies V1's pick from
     `/deception/recommendation`.
- **Shadow:** after step 2, in a `try`, V2 observes the same (session id, served persona, reward) and computes its own
  pick, saved in its own file. It is returned as `policyV2` and stored as `HoneypotSession.shadowPolicy`. The served
  persona (`servedProfile`) and V1's pick (`recommendedProfile`) are separate fields.
- **Active mode:** `DECEPTION_V2=active` (a manual owner switch, default `shadow`) is the only way V2's pick reaches
  `nextProfile`. Rank 6 did not change it or use it. The Rank 6 corrections made it fail-closed (§10).

**Safeguards added.** These close gaps found in the audit; none changes V1:
- **Validated picks.** Every V2 pick is checked with `persona_policy_v2.validate_recommendation`. Only a servable
  persona is reported, stored or (in `active` mode) applied; `windows_srv`, unknown or malformed picks become `status:
  INVALID_RECOMMENDATION` with no persona. In `active` mode, V1's pick then stands.
- **Errors are recorded.** A V2 failure was a missing record; it is now shadow evidence (`status: ERROR`,
  `errorCode` = exception type).
- **Backend storage.** The backend used to accept `windows_srv` as a shadow pick. `backend/utils/shadowPolicy.js`
  now stores servable personas only, plus `status`, `errorCode` and `schemaVersion` (`shadow-v2/1`).
- **Separate state file.** `DECEPTION_V2_STATE_PATH` pointing at the V1 Q-table or the shipped seed is refused
  (V2 stays off) so V2's saves can never overwrite V1's learning.

**Persona registry.** The engine, V2, backend, switcher, log parser and honeyfs builder all list the same six
personas. Five are servable (`ubuntu_22`, `debian_11`, `centos_7`, `aws_ec2`, `raspberry_pi`), each with a switcher
config, banner and 11 honeyfs overrides. `windows_srv` is unsupported everywhere. There is no `alpine_3`.

**Read-only evaluation** (`ai-engine/evaluation/rank6_v2_shadow_eval.py`; evidence in
`audit/rank6_persona_policy_v2/run_20261114T144642Z/`):
- **Safety.** All production policy artifacts are hashed before and after (unchanged). Learners run on temporary
  copies with saving disabled. Sessions are read with `mongosh find` and a projection (the existing
  `real_session_report.load`). Evidence records carry no IP address, command, credential or session id.
- **Isolation self-checks.** V1's decisions and learned Q-table content are identical with V2 healthy, raising,
  timing out on save, returning `windows_srv` or returning garbage; a V2 state path on the V1 table is refused.
- **Replay** (production order: learn, then recommend), on 19 recorded sessions (all *labelled* operator, inferred from a
  private source address; their original provenance is untracked, see §10; served ubuntu_22 16, centos_7 3):

  | | Value |
  |---|---|
  | Successful decisions | V1 19/19, V2 19/19 |
  | V2 errors | 0 |
  | V2 invalid or unsupported picks | 0 |
  | Agreement | 16/19 (84.2 %) |
  | V1 picks | centos_7 16, ubuntu_22 3 |
  | V2 picks | centos_7 17, aws_ec2 2 |
  | Personas never picked by V1 | debian_11, aws_ec2, raspberry_pi |
  | Personas never picked by V2 | ubuntu_22, debian_11, raspberry_pi |
  | Median decision time | V1 5 µs, V2 30 µs |
  | Two runs | identical |
  | Live shadow records in `sentinel-demo` | 0 |

  A different persona mix says nothing about which policy deceives better: for each session only the served
  persona's outcome is observed.

**Readiness gates** (`readiness_status.json`):

| # | Gate | Status |
|---|---|---|
| 1 | Shadow isolation | PASS |
| 2 | Persona compatibility | PASS |
| 3 | Invalid-action handling | PASS |
| 4 | Failure isolation | PASS |
| 5 | Evidence schema and provenance | PASS |
| 6 | Reproducible evaluation | PASS |
| 7 | Adequate session evidence (≥ 30 per servable persona) | INSUFFICIENT_DATA (16 / 0 / 3 / 0 / 0) |
| 8 | Independent evidence (≥ 30 external per persona) | INSUFFICIENT_DATA (0 everywhere) |
| 9 | Decision stability (SIMULATED, §8) | FAIL (C2, S11) |
| 10 | Documented acceptance criteria (§6) | NOT_MET |

**Overall: NOT_READY.** The shadow pipeline is verified; V2's effectiveness is not.

**Evidence, kept apart:**
- 12,087 synthetic seed episodes: a warm start, not attacker data.
- 19 session-driven V1 updates with untracked provenance (Rank 3 report).
- 19 recorded sessions labelled operator by source address; provenance untracked (§10).
- 0 independent external sessions.

Nothing promotes V2 automatically: even an all-PASS file only reports READY, and activation stays the owner's §7
procedure.

Reproduce:

```bash
cd ai-engine
.venv/Scripts/python evaluation/rank6_v2_shadow_eval.py --mongo-uri mongodb://127.0.0.1:27017/sentinel-demo
```

Tests:

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_rank6_v2_shadow.py tests/test_persona_policy_v2.py -q
```

```bash
cd backend
npx jest --runInBand tests/rank6PersonaPolicyV2.test.js
```

## 10. Fail-closed activation and session provenance (Rank 6 corrections, 2026-11-14)

**The bypass.** Before this change, `DECEPTION_V2=active` alone made `/deception/recommendation` serve V2's pick
(if it was a servable persona). Readiness was documented (§6, §9) but nothing in the engine checked it.

**The guard** (`ai-engine/rl_engine/v2_activation.py`, called by `/deception/recommendation` in
`inference/main.py`). V2's pick replaces V1's only when **all** of these hold:
1. The owner's existing switch is set: `DECEPTION_V2=active`. Nothing in the code sets it.
2. The newest run in `audit/rank6_persona_policy_v2/` has a readable, valid `readiness_status.json`. An older READY
   run never stands in for a newer invalid one.
3. `overall` is exactly `READY` and `shadow_engineering` is `PASS`.
4. All ten mandatory gates are present and `PASS`.
5. It is a production run: known `rank6_version`, a `mongosh read-only find` data source, no `smoke`/`fixture` flag,
   a valid past `generated_at`, and `artifact_integrity.json` says the production artifacts were unchanged.
6. It is current: its `policy_version` and `v2_defaults` equal the running V2's. Evidence for other parameters is stale.
7. V2's pick passes `validate_recommendation` (a servable persona).

Anything else keeps V1 authoritative: NOT_READY, NOT_VERIFIED, LIMITED, INSUFFICIENT_DATA, FAILED, a missing or
unreadable file, invalid JSON, missing or failed gates, stale or smoke evidence, an unsupported pick, a V2 exception
or a crash in the guard itself. The response carries `v2Activation` (`requested`, `allowed`, `readiness`, `reason`,
`failedGates`, `evidence`); `/deception/stats` reports the same. A blocked request is logged once per reason as a
warning. The guard only reads files: it never writes evidence, the Q-table or V2's state.

READY never activates V2 by itself: without the owner's switch the result is `NOT_REQUESTED`. There is no expiry
age for evidence in this project; the guard's currency rule is the policy version and parameters.

**Current result:** active mode would be blocked with `READINESS_NOT_READY` (failed gates 7, 8, 9, 10). The
deployment stays in shadow mode with V1 deciding.

**Session provenance** (`provenance_reconciliation.json` in
`audit/rank6_persona_policy_v2/run_20261114T151206Z/`, read-only `mongosh find` with a projection):

| Category | Sessions |
|---|---|
| Historical sessions evaluated in the replay | 19 |
| Labelled operator in the replay (inferred: private source address, `real_session_report.classify`) | 19 |
| With a recorded source (`HoneypotSession.evidenceSource`) | 0 |
| With recorded and verified provenance (admin-confirmed `evidenceLabel`) | 0 |
| With untracked or unverifiable provenance | 19 |
| Independently verified external attacker sessions | 0 |
| Scored by the engine (`deceptionScoredAt`) | 7 (12 never scored) |

The Q-table's 19 session-driven updates (Rank 3) are untracked and have no learned-session index. They **cannot be
linked** to these 19 sessions; the equal count is not a match. Only 7 of the replayed sessions were ever scored.

So: 19 historical sessions were evaluated in the replay. They are labelled as operator sessions in the evaluation
context, but their original source provenance remains untracked. They are not counted as independently verified
external attacker sessions. Gate 8 now counts only sessions whose recorded provenance is external; an
address-inferred label never counts. Gate thresholds are unchanged (30 per servable persona).

Tests:

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_v2_activation_guard.py tests/test_rank6_v2_shadow.py tests/test_persona_policy_v2.py -q
```

## Note: retrospective test correction (recorded in Rank 8, 2026-11-19)

Rank 6 changed the stored shadow record (`utils/shadowPolicy.js`: `schemaVersion`, `status`, `errorCode`, and V2
errors recorded as `status: ERROR` instead of dropped). `backend/tests/deceptionProfile.test.js` was not run in Rank 6
and kept the old expectations, so two of its assertions failed until they were corrected during Rank 7 to the
intended Rank 6 behaviour. The Rank 6 report's test summary did not include that suite. The full backend run in
Rank 8 (all 123 suites) includes it and passes.
