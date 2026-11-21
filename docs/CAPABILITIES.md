# Capability status (2026-11-13)

This is the single reference for what SentinelAI does today. The dashboard's **Capability Status** page
(`/dashboard/capabilities`, `GET /api/system/capabilities`) reads the runtime parts of it from the running system.

Labels: **Implemented and verified** (a named automated end-to-end test suite covers the whole workflow) · **Implemented and tested** · **Implemented and tested (simulated)** · **Implemented, not enabled** · **Simulated** · **Shadow only** ·
**Experimental** · **Blocked** (missing infrastructure or evidence) · **Not implemented**.
A limitation is marked resolved only when tests or independent evidence support it.

| # | Original limitation | What exists now | Label | Resolved? | What is still needed |
|---|---|---|---|---|---|
| 1 | Detector does not generalise (98.97 % is in-distribution) | Protocol v4 pre-registered and run: domain-balanced candidates C5/C5E on the frozen D17/D18 folds, with bootstrap CIs; baselines reproduced exactly ([results](../audit/ML_DEV_RESULTS.md#protocol-v4)). Rank 5: read-only evaluation of the frozen model on its random split, 2.29 M unseen 2017 rows and 5.55 M rows of six later 2018 days, with leakage checks, per-class / per-day metrics and drift diagnostics ([ML_GENERALISATION.md](ML_GENERALISATION.md)) | Evaluation tooling: Implemented and verified. Generalisation: Experimental (independent generalisation NOT VERIFIED). Two separate dashboard entries | **No.** On the later 2018 traffic the frozen model is no better than predicting benign (accuracy 0.729 vs 0.730, macro F1 0.11, 15 % attack recall at the alert line); candidates not eligible; the deployed model is unchanged | Independently labelled traffic from new networks; the one-shot protected-day test (owner approval) |
| 2 | No live capture; Demo B is replayed | `ai-engine/capture`: header-only PCAP replay and opt-in live passive capture of one named interface; capture source stored per prediction; dashboard chip ([CAPTURE.md](CAPTURE.md)) | Implemented and verified (offline PCAP replay); Implemented, not enabled (live). Two separate dashboard entries | **Partly.** Offline replay is verified end to end by automated tests ([How it is verified](CAPTURE.md#how-it-is-verified)). Live mode is not verified on this laptop: no Npcap, and WSL needs CAP_NET_RAW | Install Npcap (Windows) or grant capture rights in WSL, then run a live session (owner) |
| 3 | Host-firewall containment is simulated | Windows Firewall and Linux iptables adapters; host-bound confirmation gate; every applied rule is verified, failed applications are cleaned up and releases confirmed ([CONTAINMENT_ENFORCEMENT.md](CONTAINMENT_ENFORCEMENT.md)) | Adapters: Implemented and verified (mocked commands). Real enforcement: Implemented, not enabled. Mock adapter: Implemented and tested (simulated, the default). Three separate dashboard entries | **No** (on purpose). Verified with mocked commands only; no real rule has been created | Owner authorisation and a lab host to verify a real block |
| 4 | Q-learning evidence is mostly synthetic | Per-update provenance (operator / external / simulated / unknown; missing and invalid labels counted), v1 dedupe (replays, concurrent writers, failed saves, id-less sessions), a bounded update log, a reproducible read-only evidence report, consent-aware labelling ([QLEARNING_EVIDENCE.md](QLEARNING_EVIDENCE.md)) | Evidence management: Implemented and verified. Policy effectiveness: Experimental (insufficient independent evidence). Persona policy v2: Shadow only, not ready. Three separate dashboard entries | **No** for effectiveness: 19 session-driven updates (untracked; operator-generated per the session records) against 12,087 seed episodes; real data changes 0 of 6 greedy decisions; 0 external sessions | Independent external sessions collected under the consent procedure |
| 5 | `windows_srv` configured but not servable | Removed from every selectable and active list; refused by the learner, switcher, backend, rotator and Arena; served banner tested per persona ([PERSONAS.md](PERSONAS.md)). Rank 7: a Windows-like shell SIMULATION over Cowrie (honeypot/windows_persona: allowlisted cmd/PowerShell-style commands, isolated in-memory filesystem, nothing executed on the host), tested in-process inside Cowrie 3.1.3; experimental, not production-eligible, not deployed; its sessions are scored but never learned ([PERSONAS.md](PERSONAS.md#simulated-windows-persona-rank-7-2026-11-14)) | Not implemented (Windows persona) | **Yes, by removal.** No Windows honeypot exists | An isolated Windows VM, if a genuine Windows target is wanted |
| 6 | V2 shadow-only, S5 28/30, no external sessions, no rollback rehearsal | Pre-declared S6–S11 (seeds 200–229) paired evaluation; isolated rollback rehearsal (6 scenarios, real rotator code) ([PERSONA_POLICY_V2.md §8](PERSONA_POLICY_V2.md)). Rank 6: shadow isolation verified (V1 identical with V2 healthy, failing or invalid), picks validated against the servable personas, V2 errors recorded as evidence, V2 state cannot share the V1 table; read-only V1/V2 replay on 19 recorded sessions, 16/19 agreement ([PERSONA_POLICY_V2.md §9](PERSONA_POLICY_V2.md)). Rank 6 corrections: `DECEPTION_V2=active` is fail-closed (V2 serves only with valid, current, all-PASS READY evidence; today blocked, V1 serves); the 19 replayed sessions are labelled operator by address but have untracked provenance, 0 verified external ([PERSONA_POLICY_V2.md §10](PERSONA_POLICY_V2.md)) | Shadow pipeline: Implemented and verified. Policy: Shadow only, NOT READY. Two separate dashboard entries | **No.** Simulation criterion C2 fails (S11). External sessions: 0. Live rehearsal: not done | External sessions; a live rollback rehearsal recorded by the owner |
| 7 | Arena uses scripted/simulated attackers | Six stochastic attacker profiles, replicated paired trials, bootstrap CIs, effect sizes, isolation checks, a SIMULATED banner ([DECEPTION_ARENA.md](DECEPTION_ARENA.md)) | Simulated | **Improved, still simulated.** Results reflect the assumed parameters | Real attacker sessions (limitation 4) |
| 8 | Single-flow auto-block, single host | Correlation: ≥ 3 suspicious flows in 300 s from one source, ≥ 2 at the block line; trusted lists, cooldown, dedupe, fail-closed; every decision explained on the threat | Implemented and tested | **Yes** for single-flow blocking. Still single-host | Multi-node correlation would need a distributed deployment |
| 9 | Session classification is rule-based only | `ai-engine/session_ml`: versioned 46-feature session schema (`session_v2`), safe JSON model loading with hash and schema checks, shadow-only inference beside the unchanged rules, backend storage, dashboard display, a gated time- and source-aware training/evaluation export, a read-only label audit ([SESSION_ML.md](SESSION_ML.md)) | Pipeline: Implemented and verified. Model: Blocked (shadow only, insufficient labelled data). Effectiveness: Experimental. Three separate dashboard entries | **No.** Audit of 119 sessions in 8 SentinelAI databases: 0 independently labelled (68 rule labels, 48 simulated ids, few lab sources); no model trained | ≥ 30 independent labels per class over ≥ 14 days, then shadow evaluation against the rules |

No model was promoted, no Q-table or v2 state was modified, and real firewall enforcement and live capture stay
disabled by default.

## Rank 8 remediation (2026-11-19)

**Fixed and verified by tests:**
- **Q-learning (F1):** a session served right after the experimental Windows persona can no longer reach the V1
  table; `DeceptionQLearner.update` refuses unsupported personas.
- **Reverse-shell classification (F5):** encoded PowerShell is a reverse shell only with an explicit
  `-enc`/`-EncodedCommand` flag and a reverse-shell payload.
- **Windows simulator:**
  - `cmd /c` quoting (F3) and nested-shell environment isolation (F4)
  - a crash on a lone `"`
  - per-line event cap and per-session storage cap
  - persona-gated ATT&CK
- **ATT&CK:** techniques and tactics verified against v20.1; on-host reconnaissance is no longer mapped to T1595.
- **Engine body limit:** 2 MB counted on received bytes, for every route.
- **Model status:** class support, Data Exfiltration as `unmodeled`, time-of-day limitations, and a reproducible
  reference global SHAP summary.
- **Naming:** XGBoost named as such, legacy fields kept.
- **Test isolation:** Python predictor reload removed; backend logs and audit sinks isolated; all 123 Jest suites run.

**Measured, no target:** Socket.IO latency baseline (docs/ARCHITECTURE.md); an owner-approved SLO is still needed.

**Unchanged limitations:**
- Live capture and real host-firewall enforcement remain disabled and untested live.
- Q-learning V2 is shadow-only and NOT_READY.
- The Windows persona is an undeployed, experimental simulation.
- Session ML has no trained model.
- Cross-network generalisation is not verified (Rank 5, E3).
- Data Exfiltration needs an approved training cycle with labelled data.
