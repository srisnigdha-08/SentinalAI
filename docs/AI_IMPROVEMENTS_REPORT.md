# SentinelAI AI Engine — Phase 5 Improvements Report

Date: 2026-10-21, branch `db-fixes`. The items are the Phase 5 list in `docs/AI_ENGINE_STUDY_GUIDE.md`. This is separate from the older `docs/IMPROVEMENTS_REPORT.md`.

## Status of every item

| # | Improvement | Status | Where |
|---|---|---|---|
| Q1 | Threat counter follows the alert line | Done earlier (M1) | `inference/main.py` |
| Q2 | Raise on unmapped labels | Done earlier (M5) | `utils/features.py` |
| Q3 | Single canonical model path | Registry mandatory (M4). Duplicates kept, because they are preserved assets | `inference/predictor.py`, `models/README.md` |
| Q4 | Remove dead code | Done earlier (L5, L6) | — |
| Q5 | Pin dependencies | Done earlier (L9) | `requirements.txt` |
| Q6 | ε floor and convergence signal | Done earlier (H6) | `rl_engine/deception_scorer.py` |
| Q7 | Sanitise the shadow endpoint | Done earlier (L1, L2) | `inference/main.py` |
| **Q8** | **New scripts in CI** | **Done.** `ai_engine_endpoint_check.py --skip-dataset` runs in the `model-integrity` CI job: every endpoint, CSV aliases, honeypot, deception, reload. The CICIDS CSVs are not in git, so the dataset reproduction scripts stay manual | `.github/workflows/ci.yml`, `scripts/ai_engine_endpoint_check.py` |
| M-1…M-4, M-6 | Retrain honestly, honeypot, CSV skew, paper sheet, IF reframing | Done earlier (C1, C2, H1, H4, H5) | — |
| **M-5** | **Decide on XGBoost** | **Done: XGBoost is now the served model** (§1) | `models/xgb_classifier_xgb_cicids_v1.pkl`, `registry.json` |
| M-7 | Seed Q-table | Documented as a development warm start. Bytes unchanged, because they are hash-pinned in `GATE1_CONTRACT.md` | `models/README.md` |
| **U1** | **Run the retraining loop end to end** | **Partly.** The offline pipeline was run (§5). The analyst-labelling step needs your live MongoDB and real verified predictions, which I did not touch | `training/retrain_from_samples.py` |
| **U2** | **Drift-triggered retraining** | **Done.** Sustained drift raises an admin-only "Retraining recommended" alert with the commands. A human still runs and approves them | `backend/services/driftMonitorService.js` |
| **U3** | **Registry history** | **Done.** `models/registry_history.jsonl` is append-only; `/model/info.lineage` shows it | `inference/model_checks.py`, `training/register_model.py`, `retrain_from_samples.py` |
| **U4** | **Honeypot feedback into training data** | **Done** (semi-automatic, §4) | `backend/services/aiService.js`, `models/AIPrediction.js` |
| **U5** | **SHAP in the UI and a global summary** | **Done.** Engine `GET /model/explain/global`, backend `GET /api/ai/engine/explain-global`, and an "AI Analytics → Model Health" panel | `inference/main.py`, `backend/routes/aiEngine.js`, `frontend/src/pages/AIAnalytics.jsx` |
| **U6** | **Bandit before DQN** | **Done, opt-in.** `DECEPTION_POLICY=ucb1` gives UCB1 over personas. Per-persona statistics are always kept; Q-learning stays the default (paper and contract) | `rl_engine/deception_scorer.py` |
| **U7** | **Probability calibration** | **Measured** (§6). Not deployed | `evaluation/day_holdout_eval.py --protocols calibration` |
| **P1** | **Hardened container** | **Done in Compose:** `read_only`, `tmpfs /tmp`, `no-new-privileges`, `cap_drop: ALL`; no host port. **Not run:** Docker isn't installed on this machine | `docker-compose.yml` |
| P2 | Preprocessing tests | Covered by the C1/H4/M2/M5 test files | `tests/` |
| **P3** | **One reproducible training entry point** | **Done**, and used to produce the new served model | `training/pipeline.py` |
| **P4** | **Prediction-distribution monitoring** | **Done.** `/metrics` gains action counts, a threatScore histogram and an incomplete-input counter. Two Prometheus alerts: class-mix shift and saturated scores | `inference/main.py`, `deployment/prometheus/alerts.yml` |
| **P5** | **Golden-set startup check** | **Done.** At registration, 20 fixed vectors are scored and pinned; the engine refuses to serve if they don't reproduce | `inference/model_checks.py`, `inference/predictor.py` |

## 1. M-5 — XGBoost is now the served model

`evaluation/day_holdout_eval.py --classifier xgboost` trains XGBoost under exactly the protocols used for the Random Forest. The fit is wrapped in `training/estimators.EncodedXGB`, so a leave-one-day-out fold with missing classes still works (`experiments/m5_xgboost_eval/`).

| De-duplicated, alert line 0.90 | Random Forest (`cicids_v3`) | **XGBoost (`xgb_cicids_v1`)** |
|---|---|---|
| Random split: accuracy / macro F1 (train.py) | 0.9847 / 0.842 | **0.9897 / 0.874** |
| Chronological: macro F1 | 0.750 | **0.772** |
| Chronological test: attack detection / benign alert rate (threshold-validation run) | 78.6% / 0.154% | **91.0% / 0.134%** |
| Alert line the validation procedure selects | 0.90 | 0.87 point rule / **0.90 Wilson rule** (kept) |
| Leave-one-day-out detection: Tue / Wed / Thu / Fri | 0.0 / 0.3 / 0.4 / 0.4% | 0.2 / 6.9 / **80.2** / 10.3% (Thursday benign alert rate 1.4%) |

XGBoost dominates on every honest measure, so it was produced and registered with the new pipeline:

```bash
python training/pipeline.py --version xgb_cicids_v1 --model xgboost --register --note "M-5 ..."
```

- `models/registry.json` now pins `xgb_classifier_xgb_cicids_v1.pkl` and `isolation_forest_xgb_cicids_v1.pkl`, plus the golden set.
- SHAP works through the wrapper.
- Low-data classes are still flagged.
- The alert line stays 0.90.
- Rollback: `register_model.py --classifier rf_classifier_cicids_v3.pkl --type rf --anomaly isolation_forest_cicids_v3.pkl`, then `POST /model/reload`.
- The backend records these predictions as `modelType: "ensemble"`, its existing mapping for XGBoost model versions.
- `retrain_from_samples.py` now retrains the family the registry serves (`--classifier` overrides).

## 2. U3 / P5 — Model lineage and golden-set check

- **History.** `models/registry_history.jsonl` is append-only, written by `register_model.py` and by `retrain_from_samples.py --promote`. Each entry records time, source, files, hashes, versions, metrics and a note. It was backfilled from git with the August RF and `cicids_v3`. `GET /model/info` returns the last 5 entries as `lineage`.
- **Golden set.** At registration, 20 fixed vectors (seeded, heavy-tailed, plus an all-zero row) are scored and their classes, probabilities and anomaly scores are stored in `models/golden_set.json`, which is SHA-256-pinned in the registry.
  - At startup the engine re-scores them. Any class change, or a probability/score difference above 1e-6, means it serves nothing (`/ready` 503).
  - `register_model.py --check` also verifies the golden file.
  - This catches the right pickle under a different numpy/scikit-learn/xgboost build, which hashes alone cannot.

## 3. P4 — Prediction-distribution monitoring

`/metrics` now also exports:
- `sentinel_ai_actions_total{action}`;
- the `sentinel_ai_threat_score` histogram (bucket edges 0.1, 0.3, 0.5, 0.7, 0.9, 0.92, 0.99);
- `sentinel_ai_incomplete_input_total`.

New Prometheus alerts:
- **`SentinelAIPredictionMixShift`:** the 15-minute share of non-BENIGN verdicts is more than 3× the 6-hour share and above 2%, with real traffic.
- **`SentinelAIScoresSaturated`:** more than half of recent flows score at or above the block line.

promtool isn't installed here, so the rules were checked as YAML only; CI runs promtool.

## 4. U2 / U4 — The self-evolving loop, with a human in it

- **U2:** the backend drift monitor counts consecutive drift reports. After `DRIFT_RETRAIN_AFTER_CHECKS` (default 3, i.e. 90 minutes of sustained drift) it raises one admin-only *"Retraining recommended"* alert per cooldown, containing the export and retrain commands. A clean report resets the streak.
- **U4:** when a network flow's source IP attacked the honeypot within `HONEYPOT_CORROBORATION_DAYS` (default 7):
  - the prediction is marked `honeypotCorroborated`;
  - if it was classified BENIGN or Unknown (a likely missed attack), it joins the analyst review queue (`needsReview`, `GET /api/ai/predictions?review=true`);
  - an analyst's verification then turns it into a training sample through the existing path.
  - The lookup runs only on an open MongoDB connection; a buffered query would stall predictions during an outage.
- **The loop:** honeypot or anomaly signal → review queue → analyst label → `exportTrainingSamples.js` → `retrain_from_samples.py` (gated) → `--promote` (history and golden set) → `POST /model/reload`. Drift tells you when.

## 5. U1 — Running the retraining loop

- `retrain_from_samples.py` was run end to end with **no analyst samples** and no `--promote` (`experiments/retraining/u1_dry_run/`). Baseline and candidate are the XGBoost recipe: macro F1 0.772, 91.1% detection, benign 0.159%.
- **It exposed a real defect.** The gate's absolute "benign alert rate ≤ 0.1%" check failed even for an unchanged model, because no honest candidate can meet it on de-duplicated data. The loop could never have promoted anything.
- Fixed: the gate now requires the candidate's alert rate to be **no worse than the baseline + 0.02 percentage points**, together with the macro-F1 check. The 0.1% target is still reported (`meets_alert_fpr_target`).
- Re-run with the fixed gate (`experiments/retraining/u1_dry_run_relative_gate/`): **gate passed**. Both checks are true; `meets_alert_fpr_target` is still reported as false.
- **Not done:** the analyst-labelling step. It needs your live MongoDB and real verified predictions; I didn't touch your database or fabricate labels. With the backend running: verify predictions in the UI → `node backend/utils/exportTrainingSamples.js --out samples.jsonl` → `python ai-engine/training/retrain_from_samples.py --samples samples.jsonl` → review the gate → `--promote`.

## 6. U7 — Calibration (measured, not deployed)

`day_holdout_eval.py --protocols calibration --classifier xgboost` (`experiments/u7_calibration/`) fits on the chronological fit split, calibrates on validation, and scores the test.

| P(attack) = 1 − P(BENIGN) on later traffic | Brier | Expected calibration error |
|---|---|---|
| XGBoost as served | **0.0081** | **0.0059** |
| After isotonic calibration on the validation split | 0.0111 | 0.0120 |

The served probabilities are already well calibrated: in the 0.9–1.0 bin the mean prediction is 0.997 and 99.0% of those flows are attacks. Isotonic calibration overfits the validation split and makes it worse. **Decision: not deployed.**

## 7. U5 — Global explanations

- `GET /model/explain/global` (engine) gives the mean |SHAP|, for each flow's assigned class, over the last 200 scored flows, overall and per class.
- `GET /api/ai/engine/explain-global` (backend, admin/analyst) proxies it.
- "AI Analytics → Model Health" shows a bar list of the top features. The same panel's drift table now shows PSI values; it had been reading the old mean/variance fields.

## 8. U6 — Bandit policy

- `DECEPTION_POLICY=ucb1` recommends personas by UCB1 on mean normalised engagement reward: every persona is tried once, then the best mean plus an exploration bonus.
- Per-persona arm statistics are kept, persisted, merged across processes and reported (`armStats`, `policy`) under both policies.
- The UI names the active policy. Q-learning remains the default because the paper and the protected-artifact contract describe it.
- In a 206-session simulation, UCB1 put more than half the sessions on the best persona and still kept trying the others.

## 9. P1 / Q8 / P3

- **P1:** the engine runs read-only in Compose, with only `/data` (Q-table) and a `/tmp` tmpfs writable, `no-new-privileges`, all capabilities dropped, and no host port. **Not run:** Docker isn't installed here.
- **Q8:** CI's `model-integrity` job now starts the engine and runs `ai_engine_endpoint_check.py --skip-dataset` (19 checks without the CICIDS CSVs).
- **P3:** `training/pipeline.py` runs train → random/chronological/leave-one-day-out → threshold validation → summary → optional `--register`. It writes to `experiments/pipeline/<version>/` and never into `models/` without `--register`. The candidate pickles there are git-ignored.

## Verification

| Check | Result |
|---|---|
| New tests | ai-engine `tests/test_phase5_improvements.py` (11): golden set written/verified/tampered, history, metrics histogram, global SHAP, UCB1, arm-stat persistence, calibration report, EncodedXGB. Backend: U2 drift streak (`improvements.test.js`), U4 corroboration (`reviewQueue.test.js`, 3), the explain-global route in the role matrix. Frontend: PSI rows, SHAP rows, UCB1 wording |
| Updated tests | promote test uses real tiny models (golden set) and checks history; gate test covers the relative rule; served-model pin is now XGBoost |
| AI-engine pytest | **483 passed**, 0 failed |
| Backend Jest | **1046 passed**, 13 skipped, 0 failed |
| Frontend | **45 tests passed**; production build OK |
| Live engine (`ai_engine_endpoint_check.py`, real CICIDS rows) | **22/22 pass**. Serves `xgb_classifier_xgb_cicids_v1.pkl` (sha256 verified); benign rows 95% BENIGN, attack rows 99% non-BENIGN |
| `--skip-dataset` mode (as in CI) | 19/19 pass |
| `register_model.py --check` | classifier, anomaly and golden set OK |

**Not verified here:** Docker (P1 read-only container) and promtool (the new alert rules). Neither tool is installed on this machine; CI runs promtool.

**Not done:** labelling real analyst samples for U1 (needs your live MongoDB); deploying calibration (U7, measured as harmful); replacing Q-learning as the default policy (U6 is opt-in).

