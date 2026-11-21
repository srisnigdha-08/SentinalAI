# Q-learning evidence and provenance

## Dashboard status, and what it does and does not mean

| Capability Status entry | Label | Meaning |
|---|---|---|
| Q-learning evidence management | **Implemented and verified** | Provenance, duplicate-session protection, the bounded update log, source-specific counts and the read-only report are verified by automated tests on isolated copies |
| Q-learning policy effectiveness | **Experimental** (insufficient independent evidence) | Nothing shows the policy works on real attackers (figures below) |
| Persona policy v2 | **Shadow only**, not ready (unchanged) | Learns and reports in shadow; never applied ([PERSONA_POLICY_V2.md](PERSONA_POLICY_V2.md)) |

A verified evidence system only means the counts are trustworthy. It is not evidence that the policy works.

## What the learner has learned from (operator demo table, read from a copy)

Reports:
- `ai-engine/experiments/qlearning_evidence_20261113/report.json`: the original audit, unchanged.
- `ai-engine/experiments/qlearning_evidence_v2_20261113/report.json`: the same table measured again with report
  version 2.

Both come from `evaluation/qlearning_evidence_report.py`. Both have table SHA-256 `99cf9af1…849fcf`, so they
measured the same, unchanged file. The seed is `models/q_table.json`, SHA-256 `bf9b46a1…90ff`.

| | Value |
|---|---|
| Episodes in the table | 12,106 |
| Synthetic seed (warm start) | **12,087 (99.84 %)** |
| Session-driven updates | 19. All are **untracked**: they were learned before provenance existed, so the table does not record their source. The session records attribute them to operator-generated traffic. |
| By recorded source | operator 0, external 0, simulated 0, unknown 0 |
| Independent external sessions | **0** |
| Personas with real sessions | `ubuntu_22` (16), `centos_7` (3) |
| Servable personas with none | `debian_11`, `aws_ec2`, `raspberry_pi` |
| Greedy decisions changed by real data | **0 of 6** states (the seed-only table chooses the same persona everywhere) |
| Seed weight left in the Q-values | `ubuntu_22`: 0.76 typical (0.19 best case); `centos_7`: 0.95 (0.73) |
| Duplicates rejected / id-less sessions refused | 0 / 0 (neither was recorded before these counters existed) |
| Update log | 0 entries (all 19 updates predate the log), limit 200 |

**Conclusion: synthetic initialisation dominates.** No claim about real-world adaptive deception is supported.

Simulation shows the seeded v1's greedy choice depends on the previous persona and alternates between `ubuntu_22`
and `centos_7`. That is why v1 switches about 97 times per 100 epochs in `persona_policy_independent_eval.py`.

## Evidence architecture (implemented and verified)

```
honeypot session closes (backend)
  -> evidenceSource label (utils/evidenceSource.js; stored on the session, never silently changed)
  -> demo- sessions stop here: never sent to the learner
  -> POST /deception/score (engine; one lock serialises scoring) -> SessionScorer.process_session
     -> no session id: scored and answered, NOT learned (missingSessionIdRejected)
     -> id already learned: NOT learned (duplicatesRejected)
     -> otherwise: one TD update, traced by session id and source -> saved atomically
GET /deception/stats, GET /api/honeypot/evidence, evaluation/qlearning_evidence_report.py: read only
```

### Sources

The backend (`backend/utils/evidenceSource.js`) labels each session; the learner (`rl_engine/deception_scorer.py`)
keeps the same four sources.

| Source | Meaning | Real? | Independent? |
|---|---|---|---|
| `operator` | the project's own operators' test traffic (`SENTINEL_OPERATOR_SOURCES`) | real traffic, not synthetic | **no** |
| `external` | an independent party; **only** with `HONEYPOT_EXTERNAL_COLLECTION=authorized` and a `HONEYPOT_COLLECTION_NOTICE` | yes | **yes**, the only independent source |
| `simulated` | `demo-`, `arena-`, `sim-` session ids | no | no |
| `unknown` | everything else, or a missing or unrecognised label | not claimed | **never** |
| synthetic seed | the shipped warm start (`models/q_table.json`) | no; reported separately as `seedEpisodes` | no |
| untracked | updates learned before provenance tracking | source not recorded | not claimed |

- There is no "analyst-verified" learning source. An admin can only **correct** a session's label with
  `PATCH /api/honeypot/sessions/:id/evidence-source`, which needs a reason and is audited. It refuses `external`
  without authorised collection.
- An unrecognised label (for example `real`, `analyst`) is stored as `unknown` and counted under
  `provenanceIssues.invalid`. A missing label is counted under `provenanceIssues.missing`.
- Historical records are never relabelled. Sessions stored before labelling show as `unlabelled` in the backend
  summary, and pre-provenance learner updates as `untracked`.

### Duplicate-session protection

- **Same session again:** a session id already learned is refused. There is no TD update, episode, arm sample,
  count or log entry, and the refusal is counted (`duplicatesRejected`). The learned ids persist in the table (the
  most recent 20,000 ids form the dedupe window).
- **Concurrent processes:** when two processes learn the same session before either saves, the merge drops the
  second update entirely. It used to replay the TD update anyway, so the Q-values moved twice while the evidence was
  counted once.
- **Concurrent requests to one engine** are serialised by the scoring lock; exactly one is learned.
- **Missing session id:** the session is scored and answered as before, but not learned (it could be neither
  deduplicated nor traced), and counted under `missingSessionIdRejected`.
- **Failed saves:** if the write fails, the in-memory state is restored and the error is returned (HTTP 500). The
  backend keeps the session pending and retries, and the retry is learned once. Before this fix, a failed save left
  the session marked as learned in memory, so the retry was refused as a duplicate and the update was never saved.
- **Backend side:** a session already credited (`deceptionScoredAt`) is never sent again.
- **Rejection counters:** these are saved when the rejection happens, and survive another process's save. They used
  to be kept only in memory until the next learned update, and a merge could overwrite them.

### Bounded update log

- **Contents:** each learned update records `sessionId`, `source`, `state`, `persona`, `reward` and a UTC
  timestamp `at`, plus `sourceIssue` when the label was missing or invalid. It records no IP address, command,
  credential or payload.
- **Size:** the last 200 entries are kept, oldest dropped first. Counts by source and per persona are kept in full,
  so trimming the log never changes them.

### Evidence report (read-only, reproducible)

```bash
cd ai-engine
.venv/Scripts/python evaluation/qlearning_evidence_report.py --table "%USERPROFILE%/.sentinelai/demo/q_table.json" --label "operator demo table" --json out.json
```

- **Read-only.**
  - The report copies the table to a temporary file and parses only the copy.
  - It checks the live file's SHA-256 before and after, and fails if the file changed while it was being read.
  - It refuses `--json` pointing at the table or the seed, and never opens either for writing.
- **Reproducible:** the same inputs give byte-identical output (no clock, no randomness).
- **Contents:**
  - definitions of every category
  - totals; synthetic vs session-driven; by source; untracked
  - `realNotSynthetic`, `realOperatorGenerated`, `realIndependent`
  - per persona (sessions, mean normalised reward, remaining seed weight, by source)
  - learning eligibility; duplicates and id-less sessions rejected
  - provenance quality (unknown, untracked, missing, invalid)
  - update-log size, limit, retention and time span; dedupe-window size and limit
  - greedy decisions (seed only vs current) and how many changed
  - limitations derived from the figures

### How it is verified

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_qlearning_evidence_management.py tests/test_qlearning_provenance.py -q
```

```bash
cd backend
npx jest --runInBand tests/qlearningEvidenceCapability.test.js tests/limitationRemediation.test.js
```

```bash
cd frontend
node --test tests/modelHealth.test.mjs tests/capabilities.test.mjs
```

All learners in these tests write to temporary directories. They assert that the shipped seed's hash is unchanged,
and they never touch the operator demo table.

Covered:
- source classification, including missing and invalid labels
- provenance from session to log to disk
- the API keeping the label
- the seed reported separately
- historical tables loading without relabelling
- replays, same-id variants, id-less sessions, similar sessions with different ids
- concurrent processes and 8 concurrent API requests
- failed saves (three error types) with a successful retry, also through the endpoint
- the bounded log, with exact counts after trimming
- log entries holding no IP address, credential or command
- the dedupe window
- the report:
  - read-only on a write-protected file, and reproducible
  - accurate decision-change counts, both 0 and 1
  - refusing a table that changes while read, and refusing to write over the table or seed
  - a synthetic-only table
  - the committed v2 report matching the audit
- the dashboard entries matching the committed report
- backend labelling never producing `external` without authorisation

### Why policy effectiveness stays experimental

- The table is 99.84 % synthetic.
- The 19 real updates are operator-generated and untracked, and they changed none of the 6 greedy decisions.
- Three servable personas have never been served to a real session, and there are no independent sessions.

Verifying that evidence is counted correctly cannot change any of this.

### Why persona policy v2 stays shadow only

Its readiness gates in [PERSONA_POLICY_V2.md](PERSONA_POLICY_V2.md) are unchanged and not met: there are no
external sessions, and the live rollback rehearsal has not been done. Nothing in this work changes its mode, state or
prior.

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

## Rank 8: learning eligibility of both personas of a transition (F1, 2026-11-19)

A V1 update learns the transition *previous persona -> served persona*.

**Before:** Rank 7 excluded sessions *served* by the experimental `windows_srv`. But the next Linux session still
had `previousProfile: windows_srv`, and was learned into the `windows_srv` state row. Confirmed on a temporary copy:
one Q-value changed from 48.65 to 56.49.

**Now (`ai-engine/rl_engine/deception_scorer.py`):**
- `SessionScorer.process_session` scores such a session but does not learn it
  (`notLearnedReason: UNSUPPORTED_PREVIOUS_PERSONA`, `experimentalPreviousPersona: true`); V2 does not observe it.
- `DeceptionQLearner.update` refuses any state, action or next state outside the servable personas, before any side
  effect. No Q-value, counter, log entry or file write happens, so no caller can route an experimental persona into V1.

**Unchanged:**
- A missing or unknown previous persona keeps the existing fallback (the learner's last servable state).
- Linux-to-Linux learning is unchanged.
- No production Q-table, reward or parameter was modified.

**Tests:** `ai-engine/tests/test_windows_persona.py`, all `test_f1_*` tests (on temporary Q-table copies).
