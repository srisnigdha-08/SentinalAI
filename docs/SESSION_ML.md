# Honeypot-session ML (separate from network-flow ML)

## Status (2026-11-13)

| Capability Status entry | Label | Meaning |
|---|---|---|
| Honeypot-session ML pipeline | **Implemented and verified** | Feature contract, safe model loading, shadow inference, backend storage and dashboard display are covered by automated tests |
| Honeypot-session ML model | **Blocked**: *shadow only, insufficient labelled data* | No model is trained or shipped: 0 independently labelled sessions exist |
| Classifier effectiveness | **Experimental** | Not evaluated: there is no model and no independent test set |

Sessions are classified by the rule-based MITRE classifier (`honeypot_rules`), exactly as before. The ML path runs
beside it in **shadow**: it currently reports `MODEL_UNAVAILABLE` for every session, together with neutral reason
codes describing what was observed. No ML output can change a rule verdict, threat score, alert or containment.

| | Network-flow ML | Honeypot-session ML |
|---|---|---|
| Input | 53 flow features (`utils.features`, schema `v2.1_53feat`) | Cowrie session (`session_ml.features`, schema `session_v2`, 46 features) |
| Model | `xgb_cicids_v1` + Isolation Forest (unchanged) | none shipped; format `sentinel-session-logreg/1` (JSON) |
| Location | `ai-engine/models/*.pkl`, `registry.json` | `ai-engine/models/session_ml/` (does not exist), or `SESSION_ML_MODEL_DIR` |
| Serving | `/predict/internal` | `sessionML` block on `/predict/honeypot/internal`, shadow only |

No code is shared between the two paths. The session modules never import the flow predictor or `utils.features`,
and a test asserts this.

## Architecture: where a Cowrie session reaches the engine

```
Cowrie JSON log -> honeypot/parsers/log_parser.py -> POST /api/honeypot/ingest/* (honeypot key; event-id dedupe)
  -> honeypot/collectors/session_collector.js -> HoneypotSession (MongoDB)
session close -> honeypotService.closeSession: compare-and-set claim (one analysis per session; 409 on a repeat)
  -> analyseClosure builds the payload: sessionId, durationSeconds, loginSucceeded, failedLogins,
     recentFailedLogins, commands[command, intent, timestamp], iocCount, deceptionProfile (served persona),
     previousProfile, evidenceSource. No passwords or usernames are sent.
  -> aiEngineService.predictHoneypotSession -> POST /predict/honeypot/internal (X-API-Key, 10 s timeout, breaker)
       engine: result     = predictor.predict_from_honeypot (rules: classify_honeypot_session)   UNCHANGED
               sessionML  = session_ml.classifier.default_classifier().classify(session)       SHADOW
  -> backend: aiClassification / aiThreatScore / threat / alert / auto-block from "result" only (unchanged)
              session.sessionMl = utils/sessionMl.sanitizeSessionMl(sessionML)  (stored, informational)
  -> GET /api/honeypot/sessions (role redaction) -> Honeypot Analytics: "RULES:" and "ML (SHADOW):" side by side
```

The deception scorer and Q-learner (`/deception/score`) are a separate call and are not affected.

## Training-data audit (read-only)

Evidence: `ai-engine/experiments/session_ml_data_audit_20261113/audit.json`. Script:
`scripts/session_ml_data_audit.js`. It uses only `listDatabases`, `listCollections`, `countDocuments`, `aggregate`
and `find(limit 1)`, on SentinelAI databases only, and reproduces no IP address, command or credential.

| | Value |
|---|---|
| Sessions | 119 in 8 databases (116 closed; 79 with commands; 348 commands) |
| Independent labels (analyst or external) | **0**; there is no field or collection for them, and `trainingsamples` is empty everywhere |
| Rule labels (`aiClassificationMethod=honeypot_rules`) | 68; every other session has no class |
| Class labels present (rule-based or absent) | BENIGN 29, SSH Brute Force 21, SSH Intrusion Attempt 16, RCE Attempt 8, Port Scan 2, null 43 |
| Simulated session ids (`demo-`/`arena-`/`sim-`) | 48 |
| Sources | a handful of lab IPs (two databases: one IP for all sessions); campaigns cannot be separated |
| Near-duplicates | identical command sequences are common (14 of 19 sessions in one database) |
| Personas served | centos_7 32, ubuntu_22 36, null 51; debian_11, aws_ec2 and raspberry_pi: none |

**Decision: no model was trained.**
- Rule labels are not ground truth: a model trained on them would only imitate the rules, and its "accuracy" would
  measure agreement with the rules.
- The readiness gate needs at least 30 independent labels in at least 2 classes, spanning at least 14 days. It has
  0 labels.
- No synthetic session was generated or presented as attacker data.

## Feature schema `session_v2` (46 features)

`session_ml/features.py`:
- **Deterministic and versioned.** Names and order are fixed and pinned by a test fingerprint. `session_v1` features
  keep their definitions; `pipeline.extract_features` uses the same extractor, so training, evaluation and inference
  cannot diverge.
- **Text only.** Commands are read as text: never executed, evaluated or passed to a shell.
- **Bounded input.** At most 5000 commands of at most 4096 characters each are read. The
  excess is counted.
- **Malformed input never raises.** A non-object session, a non-list command list, non-object items, non-numeric,
  negative, NaN or infinite numbers, and bad timestamps all count as 0 and are reported in a `quality` block. Every
  value is a finite float.
- **No credentials.** Usernames and passwords never appear in features or output, only their counts. The backend
  does not send them today, so `distinct_usernames` is 0 in production.
- **Command categories are observations, not intent.** Each `;`, `&&` or `|` segment's program, with the path
  stripped, and a few path markers are matched against fixed lists.

| # | Feature | Group | Definition | Missing / invalid |
|---|---|---|---|---|
| 1 | `n_commands` | commands | number of commands (bounded to MAX_COMMANDS) | 0 |
| 2 | `unique_command_ratio` | commands | distinct command strings / commands; 0 with no commands | 0 |
| 3 | `distinct_programs` | commands | distinct first words of the commands | 0 |
| 4 | `bigram_diversity` | sequence | distinct consecutive first-word pairs / (commands - 1) | 0 |
| 5 | `duration_seconds` | session | session duration in seconds; negative or non-numeric -> 0 | 0 |
| 6 | `login_succeeded` | authentication | 1 if a login succeeded, else 0 | 0 |
| 7 | `failed_logins` | authentication | failed logins (max of failedLogins and failed credentials[] entries) | 0 |
| 8 | `gap_mean_s` | sequence | mean seconds between consecutive timestamped commands | 0 |
| 9 | `gap_median_s` | sequence | median seconds between consecutive timestamped commands | 0 |
| 10 | `gap_std_s` | sequence | population std of those gaps (needs 2+ gaps) | 0 |
| 11 | `max_command_length` | commands | longest command, in characters (after truncation) | 0 |
| 12 | `pipes_and_redirects` | commands | count of | and > characters across commands | 0 |
| 13 | `downloads` | file_and_network | commands invoking wget / curl / tftp / ftpget | 0 |
| 14 | `executes_downloaded` | execution | 1 if any command matches 'chmod +x' or './' | 0 |
| 15 | `fingerprint_commands` | reconnaissance | commands probing for a VM / honeypot (systemd-detect-virt, ...) | 0 |
| 16 | `ioc_count` | file_and_network | indicator count reported for the session (iocCount) | 0 |
| 17 | `intent_reconnaissance` | intent | commands the existing command-intent classifier tagged RECONNAISSANCE | 0 |
| 18 | `intent_credential_harvest` | intent | commands the existing command-intent classifier tagged CREDENTIAL_HARVEST | 0 |
| 19 | `intent_malware_download` | intent | commands the existing command-intent classifier tagged MALWARE_DOWNLOAD | 0 |
| 20 | `intent_persistence` | intent | commands the existing command-intent classifier tagged PERSISTENCE | 0 |
| 21 | `intent_privilege_escalation` | intent | commands the existing command-intent classifier tagged PRIVILEGE_ESCALATION | 0 |
| 22 | `intent_reverse_shell` | intent | commands the existing command-intent classifier tagged REVERSE_SHELL | 0 |
| 23 | `login_attempts` | authentication | credentials[] entries, or loginSucceeded + failed_logins when absent | 0 |
| 24 | `distinct_usernames` | authentication | distinct usernames tried (the names themselves are never output) | 0 |
| 25 | `cmd_recon_system` | command_category | commands with a segment in category recon_system (observation, not intent) | 0 |
| 26 | `cmd_recon_user` | command_category | commands with a segment in category recon_user (observation, not intent) | 0 |
| 27 | `cmd_recon_network` | command_category | commands with a segment in category recon_network (observation, not intent) | 0 |
| 28 | `cmd_recon_filesystem` | command_category | commands with a segment in category recon_filesystem (observation, not intent) | 0 |
| 29 | `cmd_credential_access` | command_category | commands with a segment in category credential_access (observation, not intent) | 0 |
| 30 | `cmd_privilege_escalation` | command_category | commands with a segment in category privilege_escalation (observation, not intent) | 0 |
| 31 | `cmd_persistence` | command_category | commands with a segment in category persistence (observation, not intent) | 0 |
| 32 | `cmd_file_modification` | command_category | commands with a segment in category file_modification (observation, not intent) | 0 |
| 33 | `cmd_upload` | command_category | commands with a segment in category upload (observation, not intent) | 0 |
| 34 | `cmd_network_tools` | command_category | commands with a segment in category network_tools (observation, not intent) | 0 |
| 35 | `cmd_shell_execution` | command_category | commands with a segment in category shell_execution (observation, not intent) | 0 |
| 36 | `category_diversity` | command_category | categories observed / number of categories | 0 |
| 37 | `event_count` | session | login attempts + commands | 0 |
| 38 | `events_per_minute` | session | event_count / (duration / 60); 0 when duration is 0 | 0 |
| 39 | `timestamp_coverage` | session | commands with a valid timestamp / commands; 0 with no commands | 0 |
| 40 | `recon_before_download` | sequence | 1 if a reconnaissance-category command precedes the first download | 0 |
| 41 | `persona_ubuntu_22` | persona | 1 if the served persona was ubuntu_22 | 0 |
| 42 | `persona_debian_11` | persona | 1 if the served persona was debian_11 | 0 |
| 43 | `persona_centos_7` | persona | 1 if the served persona was centos_7 | 0 |
| 44 | `persona_aws_ec2` | persona | 1 if the served persona was aws_ec2 | 0 |
| 45 | `persona_raspberry_pi` | persona | 1 if the served persona was raspberry_pi | 0 |
| 46 | `persona_unknown` | persona | 1 if the persona is missing, unsupported (windows_srv) or unrecognised | 0 |

**Reason codes** (`features.reason_codes`) are neutral observations, for example `REPEATED_FAILED_LOGINS`,
`OBSERVED_RECON_SYSTEM`, `DOWNLOAD_ATTEMPT`, `RECON_BEFORE_DOWNLOAD` and `PERSONA_UNKNOWN`. They are reported with or
without a model, and they never say "malicious", "attack" or "benign".

## Classifier, artifact and safety

`session_ml/classifier.py`.

**Algorithm.** Standardised logistic regression (`class_weight=balanced`, `random_state=0`). It suits small,
tabular data, is already a dependency (scikit-learn), and is explainable by its coefficients. It is exported to
JSON.

**Artifact.** `manifest.json` plus `model.json`.
- The manifest records the name, version, status (`shadow`, or `test_only`), format, feature-schema version,
  artifact SHA-256, label definitions, training-data manifest, training date, evaluation and `calibrated`.
- **Safe loading:**
  - No pickle, joblib or eval is ever used.
  - The SHA-256 must match the manifest.
  - The schema version and the exact feature-name list must match.
  - Every number must be finite, shapes must agree, scaler scales must be positive, and classes must be distinct.
  - Label definitions must cover the classes; the file name must be plain (no path).
  - The artifact must be under 2 MB; `test_only` artifacts are refused.
- **On failure:** `MODEL_UNAVAILABLE`, `INVALID_ARTIFACT` or `INCOMPATIBLE_SCHEMA`, with a reason. There is
  **no fallback** to another model.

**Output** (`classify`):
- `status`: `OK`, `MODEL_UNAVAILABLE`, `INVALID_ARTIFACT`, `INCOMPATIBLE_SCHEMA`, `INVALID_INPUT`,
  `INFERENCE_ERROR` or `DISABLED`
- `prediction` and `score`: only when `OK`
- `scores`, `calibrated` (false: the score is a model output, not a probability of being correct)
- `modelName`, `modelVersion`, `featureSchemaVersion`, `reasonCodes`, `quality` counts
- `evidenceSource`, `sessionId`, `mode`, `shadowOnly: true`, `inferredAt`

Non-finite scores, scores outside [0, 1] or scores that do not sum to 1 give `INFERENCE_ERROR` with no prediction.

**Modes.** `SESSION_ML_MODE=shadow` (default) or `off`. There is no active mode, and any other value is treated as
shadow.

**Gated training and evaluation.** `export_model` refuses unless the readiness gate passes. It trains on the earlier
sessions of a time-aware, source-disjoint split (`pipeline.time_aware_split`); the test set is never used for fitting
or selection. It reports, on the test set:
- per-class precision, recall and F1, and macro F1
- confusion matrix, balanced accuracy and class distribution
- sample count, and ROC-AUC and PR-AUC when binary
- the same figures for the rule baseline and a majority-class baseline

It writes only to `models/session_ml/`, never elsewhere in `models/`. Forced (test) exports are marked `test_only`
and refused there.

## API

- `POST /predict/honeypot/internal` (engine key):
  - The response is `{ success, result, sessionML }`. `result` is unchanged; `sessionML` is the block above.
  - A failure in the session classifier returns `sessionML.status=INFERENCE_ERROR` and never fails the rule result.
  - Requests over 2 MB on `/predict/honeypot*` and `/deception/score` are refused with 413 (`SESSION_TOO_LARGE`),
    and pydantic still validates the fields.
  - Rank 8: the limit is enforced on the bytes actually received (`BodySizeLimit` in `inference/main.py`), not on
    `Content-Length` alone. Chunked bodies, a false small `Content-Length` and multi-byte UTF-8 are all counted.
    Reading stops at the limit; a malformed or conflicting `Content-Length` gets 400. Every other engine route has
    the same 2 MB ceiling (`REQUEST_TOO_LARGE`); they had none before.
- `GET /session-ml/status` (engine key): mode, schema, feature count, model status and reason. Used by the backend's
  Capability Status (`aiEngineService.getSessionMlStatus`, 3 s timeout).
- **Backend storage.**
  - `HoneypotSession.sessionMl` is a whitelisted copy written once per closure. The claim makes duplicate and
    concurrent closures analyse once; a reclassification replaces the same field.
  - A block for another session, one not marked shadow-only, an unknown status, or `OK` without a valid label,
    score in [0, 1] and model version is stored as `INVALID_RESULT`, without a prediction.
  - When the engine is down the block is `ENGINE_UNAVAILABLE`; an older engine without the block gives
    `NOT_REPORTED`.
  - The block holds no IP address, command or credential, so viewer redaction leaves it as it is.
  - Historical sessions simply lack the field; no record was migrated.

## Dashboard

- **Honeypot Analytics**, per session:
  - `RULES: <class> <score>% (rule-based) · persona <served>`
  - `ML (SHADOW): <state>`. Today this is "NO MODEL (insufficient labelled data)". With a valid model it would be
    `<prediction> · <n>% model score (uncalibrated, not a probability of being correct)`, plus model, schema,
    source, time and observed reason codes.
  - The two are never combined into one number.
- **Capability Status:** the three entries above. A loaded model could only ever be reported as *Shadow only*; the
  infrastructure tests never upgrade the model or its effectiveness.

## How it is verified

```bash
cd ai-engine
.venv/Scripts/python -m pytest tests/test_session_ml_classifier.py tests/test_session_ml.py tests/test_honeypot_rules.py -q
```

```bash
cd backend
npx jest --runInBand tests/sessionMlIntegration.test.js tests/honeypotAuditFixes.test.js
```

```bash
cd frontend
node --test tests/sessionMl.test.mjs
```

- **Engine:**
  - schema version, order and fingerprint
  - every feature group; command-category cases; unknown personas, including `windows_srv`
  - malformed inputs; hostile command text, with process creation patched to fail
  - artifact loading: missing, corrupt, pickled, wrong hash, wrong schema, wrong names, NaN, shapes, path traversal,
    another model's name, test-only
  - valid, invalid and erroring predictions; modes; the export gate, models-directory guard and metrics
  - the endpoint: rule result unchanged, classifier failure isolated, 422, 413, missing id, status auth
  - the 53-feature flow contract untouched, and the flow model never called
- **Backend:**
  - sanitising
  - storage beside unchanged rule results
  - an alarming ML prediction changing no threat, alert or containment
  - rule-based auto-block unchanged
  - engine down, model unavailable, older engine, wrong session
  - duplicate and concurrent closures
  - historical records
  - viewer redaction
  - capability labels for every engine state
- **Frontend:** every state, invalid results, missing confidence, rule/ML separation, reason codes, redaction,
  labels.

All test artifacts are synthetic, built in temporary directories and marked `test_only`. A fixture asserts that
`ai-engine/models` is byte-identical after every test and that `models/session_ml/` was never created.

## Before a model may be trained or promoted

1. **Labels.** Collect independent labels with `pipeline.make_label`: an analyst review (`manual`, naming the
   labeller), or an external labelled corpus (`external`, with its reference). Only use sessions collected under the
   consent procedure in [QLEARNING_EVIDENCE.md](QLEARNING_EVIDENCE.md).
2. **Readiness.** Reach the gate: at least 30 independent labels in each of at least 2 classes, spanning at least
   14 days, from more than a handful of sources, and covering the personas actually served.
3. **Train and evaluate.** Run `export_model` into `models/session_ml/`. Review its time-aware, source-disjoint test
   metrics against the rule and majority baselines, and record the manifest's SHA-256.
4. **Run in shadow.** Keep it in shadow, compare it with the rules on new sessions over time, and have an analyst
   review the disagreements.
5. **Promotion.** Promotion beyond shadow would need a new, reviewed mode. None exists, and the rules stay in place
   until an independent evaluation shows a candidate is better.
