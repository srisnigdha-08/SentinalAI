# Capability status (2026-11-13)

This is the single reference for what SentinelAI does today. The dashboard's **Capability Status** page
(`/dashboard/capabilities`, `GET /api/system/capabilities`) reads the runtime parts of it from the running system.

Labels: **Implemented and tested** · **Implemented, not enabled** · **Simulated** · **Shadow only** ·
**Experimental** · **Blocked** (missing infrastructure or evidence) · **Not implemented**.
A limitation is marked resolved only when tests or independent evidence support it.

| # | Original limitation | What exists now | Label | Resolved? | What is still needed |
|---|---|---|---|---|---|
| 1 | Detector does not generalise (98.97 % is in-distribution) | Protocol v4 pre-registered and run: domain-balanced candidates C5/C5E on the frozen D17/D18 folds, with bootstrap CIs; baselines reproduced exactly ([results](../audit/ML_DEV_RESULTS.md#protocol-v4)) | Experimental | **No.** Candidates not eligible; the deployed model is unchanged | Independently labelled traffic from new networks; the one-shot protected-day test (owner approval) |
| 2 | No live capture; Demo B is replayed | `ai-engine/capture`: header-only PCAP replay and opt-in live passive capture of one named interface; capture source stored per prediction; dashboard chip ([CAPTURE.md](CAPTURE.md)) | Implemented and tested (replay); Implemented, not enabled (live) | **Partly.** Replay is implemented and tested. Live mode is not verified on this laptop: no Npcap, and WSL needs CAP_NET_RAW | Install Npcap (Windows) or grant capture rights in WSL, then run a live session (owner) |
| 3 | Host-firewall containment is simulated | Windows Firewall and Linux iptables adapters; host-bound confirmation gate; every applied rule is verified, or the action fails and the rule is removed ([CONTAINMENT_ENFORCEMENT.md](CONTAINMENT_ENFORCEMENT.md)) | Implemented, not enabled | **No** (on purpose). Tested with mocked commands only; no real rule has been created | Owner authorisation and a lab host to verify a real block |
| 4 | Q-learning evidence is mostly synthetic | Per-update provenance (operator / external / simulated / unknown), v1 dedupe, an evidence report, consent-aware labelling ([QLEARNING_EVIDENCE.md](QLEARNING_EVIDENCE.md)) | Experimental | **No.** 19 real updates against 12,087 seed episodes; real data changes 0 of 6 greedy decisions | Independent external sessions collected under the consent procedure |
| 5 | `windows_srv` configured but not servable | Removed from every selectable and active list; refused by the learner, switcher, backend, rotator and Arena; served banner tested per persona ([PERSONAS.md](PERSONAS.md)) | Not implemented (Windows persona) | **Yes, by removal.** No Windows honeypot exists | An isolated Windows VM, if a genuine Windows target is wanted |
| 6 | V2 shadow-only, S5 28/30, no external sessions, no rollback rehearsal | Pre-declared S6–S11 (seeds 200–229) paired evaluation; isolated rollback rehearsal (6 scenarios, real rotator code) ([PERSONA_POLICY_V2.md §8](PERSONA_POLICY_V2.md)) | Shadow only | **No.** Simulation criterion C2 fails (S11). External sessions: 0. Live rehearsal: not done | External sessions; a live rollback rehearsal recorded by the owner |
| 7 | Arena uses scripted/simulated attackers | Six stochastic attacker profiles, replicated paired trials, bootstrap CIs, effect sizes, isolation checks, a SIMULATED banner ([DECEPTION_ARENA.md](DECEPTION_ARENA.md)) | Simulated | **Improved, still simulated.** Results reflect the assumed parameters | Real attacker sessions (limitation 4) |
| 8 | Single-flow auto-block, single host | Correlation: ≥ 3 suspicious flows in 300 s from one source, ≥ 2 at the block line; trusted lists, cooldown, dedupe, fail-closed; every decision explained on the threat | Implemented and tested | **Yes** for single-flow blocking. Still single-host | Multi-node correlation would need a distributed deployment |
| 9 | Session classification is rule-based only | `ai-engine/session_ml`: features, label provenance, a time- and attacker-aware split, a readiness gate, a shadow harness ([SESSION_ML.md](SESSION_ML.md)) | Blocked | **No.** 27 closed sessions, all rule-labelled, 0 verified | ≥ 30 independent labels per class over ≥ 14 days |

No model was promoted, no Q-table or v2 state was modified, and real firewall enforcement and live capture stay
disabled by default.
