# Deception Arena: profiles and batch evaluation (SIMULATED)

Every result here comes from scripted or simulated attackers with **assumed** behaviour. It shows how the learner
behaves under those assumptions. It says nothing about real attackers, and a stronger simulator does not change
that.

## Attacker profiles (`demo/deception_arena.py`, kind SIMULATED)

Each profile is a stochastic phase model: phases in order, each with its own command pool, number of commands,
think time and chance of moving on. Leaving and persona recognition (fingerprinting) depend on the persona through
assumed parameters. Logins can fail.

| Profile | Behaviour |
|---|---|
| `profile_recon_scanner` | automated, fast, shallow reconnaissance |
| `profile_credential_bruteforcer` | many login attempts, little shell activity |
| `profile_interactive_explorer` | human-paced, deep discovery, credential hunting |
| `profile_persistence_seeker` | cron, SSH keys, services |
| `profile_cautious_fingerprinter` | checks for virtualisation, leaves early |
| `profile_opportunistic_dropper` | downloads and runs a payload |

The original `scripted_recon`, `scripted_dropper` and `persona_sensitive_sim` are unchanged.

## Batch evaluation (`evaluation/arena_batch.py`)

**Design:**
- 4 replications × 50 paired trials per profile, through the real runner.
- The learner is a temporary copy of the seed and is never saved.
- The runner checks the seed and runtime tables by hash, and the script also checks the operator's live demo
  Q-table and v2 state.

**Analysis** (pre-declared):
- the paired difference (adaptive − static) with a 95 % bootstrap interval
- the effect size dz
- statistically meaningful when the interval excludes 0; practically meaningful when the difference is also
  ≥ 10 % of the static mean (5 points for rates)

**Metrics:**
- **Engagement:** duration, command depth, interaction diversity.
- **Recognition:** persona recognition (fingerprinting).
- **Learner behaviour:** reward, switches per 100, and decision overhead.

### Results (2026-11-13, 200 pairs per profile, static = `centos_7`)

`ai-engine/experiments/arena_profiles_20261113/results.json`:

| Profile | Command depth static → adaptive (95 % CI of diff) | Verdict |
|---|---|---|
| interactive explorer | 2.66 → 3.20 (+0.36 to +0.75) | statistically and practically meaningful |
| persona-sensitive sim | 2.16 → 3.07 (+0.64 to +1.22) | statistically and practically meaningful |
| persistence seeker | 2.79 → 2.87 (+0.01 to +0.17) | statistically meaningful, not practically |
| recon scanner | 1.54 → 1.57 (+0.005 to +0.075) | statistically meaningful, not practically |
| credential brute-forcer | 0.44 → 0.44 | no difference |
| cautious fingerprinter | 1.25 → 1.27 (0 to +0.05) | no difference |
| opportunistic dropper | 2.92 → 2.78 (−0.24 to −0.07) | **worse** under adaptive |

The pattern follows the assumptions:
- **Better:** adaptive helps where the assumed preferences disfavour the static persona.
- **Worse:** it hurts where they favour it.
- **Switching:** the seeded v1 learner switches about 99 times per 100 trials.
- **Overhead:** about 13 µs per decision.

**No claim of improved real attacker engagement follows from these numbers.**

## UI

- **Banner:** the Arena page carries a permanent "SIMULATED EVIDENCE — NOT ATTACKER INTELLIGENCE" banner.
- **Labels:** each experiment shows its kind (Scripted / Simulated attacker).
- **Real sessions:** real sessions are shown separately, as observational data.
- **Personas:** unsupported personas cannot be a baseline.
