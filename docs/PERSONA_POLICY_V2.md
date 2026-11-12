# Persona policy v2: fixing synthetic-seed dominance (shadow by default)

**Status:** implemented and running in **shadow** mode. The deployed decisions still come from the v1 Q-learner.
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

## 5. What real data exists, and what is needed

All 19 real sessions so far are operator-generated, and 16 were served ubuntu_22. **There is no real-attacker evidence for any persona policy**, v1 or v2.

**Prospective data-collection protocol** (needed before claiming real-world benefit):
1. **Assignment.** Serve personas in randomised blocks: each block is a random permutation of the 5 servable personas, one persona per rotation interval. Use fixed intervals (e.g. 6 h) so time of day is balanced, and don't let either policy choose during collection. The rotator can apply a fixed schedule through the same verified switch path.
2. **Unit and outcome.** One real attacker session, with `calc_reward` as the primary outcome. Secondary outcomes: duration, number of commands, login success, the fingerprint flag, and whether the attacker reconnected within 24 h.
3. **Exclusions,** fixed before looking at the data:
   - `demo-*` sessions;
   - sessions from the operator's own addresses (WSL address, Windows host, loopback);
   - the Deception Arena;
   - sessions that started within 60 s of a restart.
4. **Size.** At least 30 sessions per persona. With the observed sd ≈ 3.1, that detects a mean difference of about 2.2 reward units (α = 0.05, power 0.8, two-sided).
5. **Analysis.** Per-persona mean reward with a 95% CI, plus a permutation test across personas. Then replay v1 and v2 offline on the randomised data using inverse-propensity weighting, since the propensities are known (1/5).

## 6. Promotion gates (`shadow` → `active`)

Activate only when **all** of these hold, and record them:
1. Protocol §5 has at least 30 eligible real-attacker sessions per servable persona.
2. Offline evaluation on that data shows v2's estimated reward ≥ v1's, and the 95% CI of the difference excludes a meaningful loss (> 0.5 reward units).
3. v2 has run in shadow for at least 2 weeks with no `policyV2.error` and no duplicate `realEpisodes`.
4. A rollback rehearsal has been done (set `active`, restart, see `policy: persona-ducb-v2` in decisions; unset, restart, see `q_learning`).

Simulated superiority is **not** a gate.
