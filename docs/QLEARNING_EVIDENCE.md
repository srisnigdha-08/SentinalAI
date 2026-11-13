# Q-learning evidence and provenance

## What the learner has learned from (2026-11-13, demo table, read from a copy)

`ai-engine/experiments/qlearning_evidence_20261113/report.json` (`evaluation/qlearning_evidence_report.py`):

| | Value |
|---|---|
| Episodes in the table | 12,106 |
| Synthetic seed (warm start) | **12,087 (99.84 %)** |
| Session-driven updates | 19, recorded before provenance existed (**untracked**; operator-generated per the session records) |
| Independent external sessions | **0** |
| Personas with real sessions | `ubuntu_22` (16), `centos_7` (3) |
| Servable personas with none | `debian_11`, `aws_ec2`, `raspberry_pi` |
| Greedy decisions changed by real data | **0 of 6** states (the seed-only table chooses the same persona everywhere) |
| Seed weight left in the Q-values | `ubuntu_22`: 0.76 typical (0.19 best case); `centos_7`: 0.95 (0.73) |

**Conclusion: synthetic initialisation dominates.** No claim about real-world adaptive deception is supported.

Simulation shows the seeded v1's greedy choice depends on the previous persona and alternates between `ubuntu_22`
and `centos_7`. That is why v1 switches about 97 times per 100 epochs in `persona_policy_independent_eval.py`.

## Provenance (implemented)

- **Learner.** Every session-driven update records its source and is traced in a bounded update log
  (`rl_engine/deception_scorer.py`):
  - **Sources:** `operator`, `external`, `simulated` or `unknown`, counted overall and per persona.
  - **Update log:** session id, source, state, persona, reward and time.
  - **Dedupe:** a session already learned is refused, with the count reported. Learned ids persist and merge
    across concurrent writers.
- **Seed.** The synthetic seed stays as it is: it is neither deleted nor rescaled to improve the real share.
- **Session labels.** Sessions get `evidenceSource` (`backend/utils/evidenceSource.js`):
  - `operator`: sources in `SENTINEL_OPERATOR_SOURCES`
  - `simulated`: `demo-`, `arena-` or `sim-` ids
  - `external`: **only** with `HONEYPOT_EXTERNAL_COLLECTION=authorized` and `HONEYPOT_COLLECTION_NOTICE`
  - `unknown`: everything else
  - Admins can correct a label with `PATCH /api/honeypot/sessions/:id/evidence-source`, which needs a reason and
    is audited. A session cannot be relabelled `external` without authorised collection.
- **Read-only access.** `GET /deception/stats` (engine) and `GET /api/honeypot/evidence` report this without drawing
  a decision.

## Isolated real-evidence evaluation

`evaluation/qlearning_evidence_report.py` reads a **copy** of a table and checks the live file's hash before and
after. Evaluating a learner on real sessions without touching the deployed table:
1. Export closed sessions with `evidenceSource=external`.
2. Replay them into a temporary `DeceptionQLearner` (`save` disabled), as `evaluation/persona_policy_sim.py` does.
3. Compare its decisions with the deployed table's.

## Consent-aware collection procedure (for future authorised sessions)

Only an owner can start this. Until then, every session counts as `operator` or `unknown`.

1. **Authorisation.** Get written permission for the network and address space the honeypot is exposed on (your
   institution or ISP), and confirm it is lawful where you are. Never expose the honeypot from a network you do
   not control.
2. **Notice.** Publish a collection notice: what is recorded (connection metadata, commands, credentials typed),
   why (research), retention (`honeypot/retention.sh`), and a contact. Put its reference in
   `HONEYPOT_COLLECTION_NOTICE`.
3. **Minimise.**
   - Credentials are already redacted on ingest.
   - Do not store payload files beyond their hashes.
   - Keep source IPs only as long as the retention period.
4. **Enable.** Set `HONEYPOT_EXTERNAL_COLLECTION=authorized`, and list your own addresses in
   `SENTINEL_OPERATOR_SOURCES` so your tests are never counted as external.
5. **Label and review.**
   - Spot-check `external` sessions.
   - Relabel your own or simulated traffic through the audited endpoint.
   - Never relabel operator sessions as external.
6. **Randomise.** For persona evaluation, assign personas by a randomised schedule, not by the learner (gate 1 of
   [PERSONA_POLICY_V2.md](PERSONA_POLICY_V2.md)).
