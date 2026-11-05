# SentinelAI AI Engine — High-Priority Fixes Report (H1–H6)

Date: 2026-10-21, branch `db-fixes`. The issues are defined in `docs/AI_ENGINE_STUDY_GUIDE.md`, Phase 4. This is separate from `docs/HIGH_PRIORITY_FIXES_REPORT.md`, which covers the earlier backend audit.

| ID | Issue | Status |
|---|---|---|
| H1 | The paper contradicts the code | **Addressed.** Replacement text for every contradicted sentence is in `docs/PAPER_CORRECTIONS.md`. The PDF itself is yours to edit |
| H2 | Class names overstate or misdescribe the training data | **Fixed without a rename.** Class provenance is published, and low-data classes are flagged (rationale in §2) |
| H3 | No de-duplication | Fixed with C2 (`docs/CRITICAL_FIXES_REPORT.md`) |
| H4 | CSV-named fields silently replaced by defaults | **Fixed** |
| H5 | The Isolation Forest cannot raise an alert; the "zero-day" claim is unsupported | **Fixed:** REVIEW action, analyst queue, and measured honestly |
| H6 | Degenerate Q-learning: collapsed exploration, no penalty, no convergence check | **Fixed:** ε floor, fingerprint penalty, convergence signal |

## H2 — Class taxonomy

**Why no rename:**
- The 11 class names are a contract shared by the engine, the MongoDB enums (`backend/utils/canonicalClasses.js`, used by `AIPrediction.actualClass`), the MITRE mapping, the UI, and about 20 backend test files.
- Renaming would require migrating your existing database records. I won't run that on your data unasked.
- The MITRE mapping is already right: "RCE Attempt" maps to T1190 (exploit of a public-facing application) and "Credential Stuffing" to T1110 (brute force). Only the display names are imprecise.

**What changed:**
- `utils/features.py` `LABEL_SOURCES` records, for each class, the CICIDS labels it is trained on and a plain description. For example:
  - "Credential Stuffing" = FTP and HTTP password brute force, not replay of breached credentials;
  - "RCE Attempt" = Heartbleed only;
  - "DDoS" = the DDoS capture plus four DoS tools, including slow-rate DoS.
  - Import-time assertions keep it in step with the label map.
- `GET /model/info` returns `classProvenance`: sources, meaning, training rows, and `sufficientTrainingData` (at least `MIN_TRAINING_ROWS` = 100).
  - On the served model, SQL Injection (17), RCE Attempt (9) and Lateral Movement (29) are flagged.
  - Data Exfiltration is not a flow class at all. It comes only from honeypot rules.
- Every flow prediction now carries `lowTrainingDataClass`.
- Training metadata records `label_sources`.
- In `day_holdout_eval.py`, each per-class metric carries `reliable` (at least 30 test rows).
- If you later want the rename, the plan is: change the display names in the UI first, then run a DB migration that maps old values to new ones, together with `canonicalClasses.js` and `LABEL_MAP`.

## H4 — CSV-named fields

`inference/main.py`:
- `_record_payload` drops a `Record` default when the caller sent the same field under a recognised alias. Matching is case-, space-, underscore- and slash-insensitive, as in the feature extractor. So `"Flow Duration": 24` now reaches the model as `flow_duration = 24`. It used to become 1000.
- A schema-named value still wins if both are sent.
- `defaultedFeatures` no longer lists aliased fields.
- Non-finite values under an alias (e.g. `"Flow Bytes/s": "Infinity"`) are now rejected with 422. They used to be silently defaulted.
- Applies to `/predict`, `/predict/internal`, `/predict/eval` and `/predict/batch`.

## H5 — Isolation Forest and the review queue

**Engine** (`inference/predictor.py`):
- A flow the classifier calls BENIGN but the Isolation Forest flags still becomes `"Unknown"`.
- When its anomaly signal is at least `REVIEW_MIN_SIGNAL` (0.55), the action is now **`REVIEW`**: no threat, no block.
- The level is published in `/model/info` `thresholds.reviewMinAnomalySignal`, and can be overridden with `REVIEW_MIN_ANOMALY_SIGNAL`.

**Backend:**
- `aiEngineService.runFullPipeline` keeps `REVIEW` instead of recomputing the action from the score.
- `AIPrediction.needsReview` (new, default false) is set from it.
- `GET /api/ai/predictions?review=true` lists unverified review items.
- Verifying a prediction clears `needsReview`. Verified predictions already feed the training-sample workflow, so the existing verify-and-label path is the queue.

**How 0.55 was chosen:** `evaluation/day_holdout_eval.py --protocols review` (`experiments/c2_dedup_eval/review_validation/`).
- It uses the chronological fit/validation/test split.
- It picks the lowest anomaly signal at which at most 0.5% of benign validation flows would be queued.
- It then measures that level once on test.

**Selection result (level 0.55, chronological test):**
- 0.033% of benign flows are queued.
- The queue holds 55 flows, of which 3.6% are attacks.
- It recovers **2 of the 2,254** attacks the classifier missed.

**What the Isolation Forest does on its own** (`experiments/c2_dedup_eval/isolation_forest/`). This run used review level 0.50, because it started before 0.55 was set. "Flags" means a signal above 0.

| Protocol | IF flags benign | IF flags attacks | Review queue size | Attacks in queue | Missed attacks recovered |
|---|---|---|---|---|---|
| Chronological | 2.0% | 29.6% | 161 | 0.6% | 1 / 2,484 |
| Leave out Tuesday (FTP/SSH brute force) | 4.0% | 0.0% | 43 | 0% | 0 / 9,147 |
| **Leave out Wednesday (DoS, Heartbleed)** | 4.6% | **75.7%** | 1,089 | **87.4%** | **952 / 9,907** |
| Leave out Thursday (web attacks, infiltration) | 3.7% | 2.0% | 171 | 4.1% | 7 / 1,820 |
| Leave out Friday (DDoS, PortScan, Bot) | 8.4% | 13.9% | 2,295 | 1.0% | 24 / 11,677 |

**The honest conclusion:**
- The anomaly tier does **not** detect novel attacks in general.
- For brute force, web attacks, port scans and botnet traffic it adds almost nothing.
- For unseen **DoS** traffic it is a useful *analyst-review* signal: about 10% of the missed DoS flows reach a queue that is mostly attacks.
- It still raises no alert by itself, and that is now explicit in the code (action `REVIEW`) and in the paper wording.

## H6 — Q-learning

`rl_engine/deception_scorer.py`:

| Change | Before | After |
|---|---|---|
| Exploration | ε = 0.2 / (1 + 0.01·episodes), which is about 0.0016 at the seed's 12,087 episodes | Same decay with a **floor of 0.05** (`EPSILON_MIN`); `current_epsilon()` is used by both `choose_action` and the stats |
| Honeypot identification | No penalty, despite what the paper says | **−5** when a session runs a fingerprinting command (`systemd-detect-virt`, `virt-what`, `dmidecode`, `/proc/1/cgroup`, `hypervisor`, `cowrie`, `/sys/class/dmi/id/`). Rewards are bounded to **[−10, 20]**. `process_session` returns `fingerprintDetected` |
| Convergence | None | Each TD update's error is recorded. The last 100 are persisted with the table and replayed in the cross-process merge. `get_stats().convergence` reports the mean |TD error| and `converged` (≥ 100 updates and mean < 0.5) |

**Not changed:** the seed `models/q_table.json`. It is a protected artifact: its SHA-256 is pinned in `GATE1_CONTRACT.md` and in `tests/test_gate1_ml_remediation.py`. Its 12,087 episodes look scripted (the reward pattern repeats). Describe it as a "development warm start", or reset it deliberately together with the contract.

The state design (s′ = the persona just served) is unchanged. The honest framing for the viva is "a contextual bandit over personas", already given in the study guide.

## H1 — Paper

See `docs/PAPER_CORRECTIONS.md`. It has line-referenced replacements for the abstract, Table II, Sections VI-A/VI-B/VIII/IX/XII and a new Table IV. The main items:
- 53 features, not 46;
- 8 files, not 4;
- 10 of 11 classes have real data;
- no SGD learner exists;
- XGBoost was trained on real data but is not deployed;
- de-duplicated and chronological results;
- the anomaly tier is a review signal, not zero-day detection;
- the fingerprint penalty and the ε floor now exist.

## Verification

| Check | Result |
|---|---|
| New engine tests | `tests/test_high_priority_ml.py` (16: CSV aliases, alias NaN → 422, batch, REVIEW/ALLOW/BLOCK paths, class provenance, low-data flag, IF report). `tests/test_q_learning_h6.py` (16: fingerprint patterns, penalty and bounds, ε floor, convergence, TD-error persistence) |
| New backend test | `tests/reviewQueue.test.js` (4: schema default, REVIEW kept and stored with no threat, ordinary predictions not queued, `?review=true` filter) |
| Full AI-engine pytest | **447 passed**, 0 failed |
| Full backend Jest | **1029 passed**, 13 skipped, 0 failed |
| Live engine (`scripts/ai_engine_endpoint_check.py`) | **22/22 checks pass**. The CSV-header check now passes (`Flow Duration=24` → `flow_duration=24`). `/model/info` thresholds: monitor 0.90, block 0.92, review 0.55 |
| ESLint (changed backend files) | No errors apart from the repository-wide CRLF line-ending noise |

**Not changed here:**
- the paper PDF;
- the seed Q-table (protected);
- the class names (they need a DB migration);
- the M- and L-issues from the study guide.
