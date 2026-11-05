# ML generalisation: root causes, options and experiment plan (2026-11-02)

Status: **analysis and plans only.** Measured facts are marked *(measured)*; everything else is a proposal. No model
was trained for this document; the deployed models are unchanged (sha256 re-checked 2026-11-02: classifier
`6d08ef19…`, anomaly `46b16b74…`, golden set `c8d72dd9…`, all equal to `ai-engine/models/registry.json`).

## 0. Baseline (measured, `ML_EVAL_PLAN.md` §5–5c)

| Protocol | Attack recall (classifier decision) | Benign FPR | Note |
|---|---|---|---|
| P5 random split (served model) | 99.81 % | 0.359 % | 95.22 % / 0.230 % at the 0.90 line with the full served score |
| P3 Mon–Wed → Thu+Fri | 50.6 % | 0.118 % | 12.1 % recall at 0.90 (classifier term only — lower bound) |
| P4 day folds (Tue/Wed/Thu/Fri) | 3.1 / 33.4 / 17.3 / 23.4 % | 0.38 / 0.24 / 4.12 / 2.71 % | 5 attack classes unseen in P3; 1–3 per P4 fold |
| Earlier: CSE-CIC-IDS2018 holdouts, RF v2 (Phase 7) | 0 % infiltration, brute force, botnet, DDoS; 1.4 % web | 0.02 % | `ai-engine/experiments/gate1_phase7_cse2018_validation/` |

## 1. Full-hybrid evaluation (approved and run 2026-11-02 — results in `ML_EVAL_PLAN.md` §5c-2)

Scoring path (`ai-engine/inference/predictor.py`): `rf_s` = confidence (1 − confidence for BENIGN); Isolation
Forest `score_samples` → `anomaly_signal` (fixed boundary −0.55, span 0.20); `combine_threat_score` =
max(rf_s, 0.7·rf_s + 0.3·signal) for attack predictions, plain blend for BENIGN; BENIGN with IF score < −0.55 →
"Unknown", score ≥ 0.55, REVIEW if signal ≥ 0.55; MONITOR ≥ 0.90, BLOCK ≥ 0.92.

Fold-safe procedure, implemented as `xgb_holdout_eval.py --with-if` (tested on synthetic data; not run on CICIDS):
1. Same frozen manifests (sha256 checked against `plan.json` before any fit); train/test disjoint asserted.
2. Re-fit the six XGBoost fold models with the served recipe and seed; the run **stops** unless each reproduces the
   earlier argmax metrics exactly (`--expect results.json`) — the earlier fold models were not saved.
3. Fit `StandardScaler + IsolationForest(n_estimators 200, contamination 0.1, random_state 42)` (`training/train.py
   IF_PARAMS`) on the fold's **benign training rows only**.
4. Score held-out rows with the predictor's own functions; report alert/block-line recall, FPR, precision, F1 (95 %
   CIs), Unknown overrides and REVIEW-queue counts by true class.
5. The constants (−0.55, 0.20, 0.55, 0.90, 0.92) are **not** re-derived on any fold; nothing on the held-out day is
   used for fitting, calibration or selection.

```powershell
cd ai-engine
.venv\Scripts\python evaluation\xgb_holdout_eval.py --run --approved --with-if --approved-if --protocols P3,P4 `
  --out experiments\xgb_holdout_hybrid_<date> --expect experiments\xgb_holdout_20261102\results.json
```

Cost: 6 XGBoost re-fits (3.7–11.2 s each, measured) + 6 IF fits on 52k–112k benign rows (seconds each, est.).
Expected difference from the classifier-only result: alert-line recall can only rise (IF raises attack scores); some
benign rows predicted as attacks with low confidence may cross the line (FPR may rise); BENIGN-predicted attacks can
only reach the REVIEW queue, never an alert — so the IF cannot recover the 49–97 % of attacks the classifier labels
BENIGN. Earlier RF-recipe evidence: the review tier recovered 2 of 2,254 missed attacks.

**Result (measured):** all six classifiers reproduced exactly; the hybrid score's alert-line recall equals the
classifier-only lower bound (P3 12.14 %, P4 0.2–10.4 %) and FPR is unchanged. The anomaly model flags 46 % of
Wednesday's unseen DoS attacks as anomalous, but only as "Unknown"/REVIEW, never as alerts — evidence for options
4/6 (use the anomaly tier as a review input), not for alerting on it (4.8 % benign "Unknown" rate).

## 2. Root causes of poor cross-day performance (evidence)

| Cause | Evidence *(measured)* | Category |
|---|---|---|
| **Attack-tool fingerprints, not benign drift** | Benign traffic per day vs the rest: mean KS 0.02–0.05, max 0.15 (`experiments/shift_analysis_20261102/shift.json`). Same class, other tool: mean KS 0.42 (DDoS: DoS tools vs LOIC), 0.52 ("Credential Stuffing": FTP-Patator vs HTTP brute force) | data |
| TCP initial-window fields encode the attacking host | KS 0.87 / 1.00 for `init_win_bytes_backward` across tools; Phase 8: 2017 attacker VM used fixed windows (259, −1) vs AWS defaults in 2018 | feature |
| One tool per class per day | 7 of 10 classes on a single day; DDoS LOIC → DoS tools 0 % recall, web brute force → FTP-Patator 0 % (P4) | data |
| Taxonomy merges unrelated clusters | "Credential Stuffing" = FTP-Patator (99.9 % self-neighbours) + HTTP brute force; XSS 5-NN are 57.5 % HTTP brute force | labelling |
| Flow features cannot see payloads | XSS / SQLi / HTTP brute force are form posts to one server; Phase 7: payload rules (L7 prototype) reached 95 % on 2018 web attacks where flows reached 1.4 % | feature limit |
| Scarcity | SQLi 21, RCE 11, Lateral 36 flows in total; Port Scan 354 unique | data |
| Dead features | 6 of 53 constant in the pool: `bwd_psh_flags`, `bwd_urg_flags`, `fwd_avg_bytes_per_bulk`, `bwd_avg_bytes_per_bulk`, `time_of_day_sin/cos` | feature |
| Label noise | 33 vectors carry two labels (27 BENIGN/Port Scan); 28–29 cross-day test rows per Thu/Fri fold repeat a training vector with another label | labelling |
| Confidence collapses out of distribution | P3: 50.6 % at argmax → 12.1 % at 0.90 | model/policy |

Conclusion: the classifier learns *which tool on which testbed* produced a flow. More of the same CICIDS2017 data
cannot fix that; more **diverse tools/networks** and **testbed-independent features** can.

## 3. Improvement options, ranked by expected value per effort

| # | Option | Hypothesis | Complexity | Data | Success criterion (on the experiment splits of §5, never P5 test) | Failure modes |
|---|---|---|---|---|---|---|
| 1 | **Testbed-robust features** (drop `init_win_bytes_*` and the 6 constant features; log1p timing/rates; per-packet header lengths — Phase 8 "Schema F") | removes fingerprints, forces behaviour features | low (feature transform + retrain) | existing | P4 binary recall ↑ ≥ 10 points on ≥ 3 of 4 attack days with benign FPR not worse; Exp. A recall ↑ | in-distribution F1 drops; may not help DDoS (Phase 8: still 0 %) |
| 2 | **Multi-dataset training** (2017 + permitted 2018 days) | more tools per class → transfer | medium (loader exists: `gate1_phase8…/build_multicorpus_pipeline.py`) | 2018 (6 days local, 4 to download) | Exp. B untouched-day recall ≥ 50 % per class family at FPR ≤ 0.1 % (Wilson upper bound) | gains only on classes present in both; new testbed bias |
| 3 | **Taxonomy fix** (split "Credential Stuffing" into FTP / web brute force, or merge XSS + SQLi + web brute force into "Web Attack"; drop Data Exfiltration) | removes an impossible distinction | low | existing | macro F1 ↑ on P5 and P4 Thursday on identical manifests; no binary-recall loss | UI/MITRE mapping changes; fewer, coarser classes |
| 4 | **Binary-first decision** (attack vs benign gate, then multiclass for labelling only) | decision quality depends only on the binary task | medium | existing | binary recall/FPR at a validation-chosen line ≥ current on P3/P4 | multiclass labels still wrong out of distribution |
| 5 | **Calibration on held-out days** (isotonic on P4 validation folds, then nested test) | confidence out of distribution is mis-scaled | medium (nested CV) | existing | Brier/ECE ↓ on untouched folds; alert line meets FPR target on validation and test | over-fits with few attack days |
| 6 | **Conservative policy** (keep auto-block off by default; per-source aggregation before alerting; REVIEW for low-confidence attacks) | operational FPR ↓ without model change | low | none | FPR per source-hour ↓ on replay; no missed blocks the current policy would make | slower response; not a detection improvement |
| 7 | Compare RF / IF-only / XGB on the same manifests | model family is not the bottleneck | low | existing | report only; choose the simplest within CI of the best | — |
| 8 | Payload (L7) detector for web attacks | flows cannot separate XSS/SQLi | high (needs HTTP payloads; Phase 7 prototype exists) | PCAP / HTTP logs | ≥ 90 % recall on 2018 web attacks at 0 FP on benign HTTP | not available on flow-only deployments |

Not recommended now: deep/sequence models (no evidence the model family is the limit; the data is), dataset-identity
features (time of day, capture day, testbed constants), tuning on P5 test rows.

## 4. CSE-CIC-IDS2018 suitability (checked 2026-11-02)

| Question | Finding |
|---|---|
| Availability / terms | Public, anonymous: `aws s3 sync --no-sign-request --region ca-central-1 "s3://cse-cic-ids2018/" …` (no AWS account). Redistribution allowed; **every use must cite** Sharafaldin, Lashkari, Ghorbani, ICISSP 2018 and link the AWS page (unb.ca/cic/datasets/ids-2018.html; registry.opendata.aws/cse-cic-ids2018) |
| Already on disk | 6 of 10 processed CSVs in `D:\sentinelai_datasets\cse_cic_ids2018\` (14-02, 15-02, 21-02, 23-02, 01-03, 02-03), sizes equal to the S3 objects |
| **Already used** | Phase 7 evaluated RF v2 on hash-sealed holdouts from those 6 days; Phase 8 **trained** a candidate on the other rows of those 6 days and evaluated on the same holdouts. These 6 days are therefore **not untouched**: usable for training/validation, not as an external test |
| Untouched | 16-02 (DoS SlowHTTPTest, Hulk; 333.7 MB), 20-02 (DDoS LOIC-HTTP, LOIC-UDP; **4,054.9 MB**), 22-02 (web brute force, XSS, SQLi; 382.6 MB), 28-02 (infiltration; 209.2 MB) — 4.98 GB; D: has 189 GB free |
| Feature schema | CICFlowMeter-V3, 80 columns (`Dst Port`, `Protocol`, `Timestamp`, 76 flow features, `Label`); 20-02 additionally has `Flow ID`, `Src IP`, `Src Port`, `Dst IP` (must be dropped). Existing mapping to the 53 features: `FEATURE_MAPPING_2018` (Phase 8). `payload_entropy` is derived from byte lengths (no payload), computed identically for both; time-of-day must stay constant (dataset identity) |
| Tool differences | 2018 used CICFlowMeter-V3; the 2017 CSVs come from an earlier CICFlowMeter release and contain overflow artefacts (negative values, noted in Phase 7); different testbed (on-prem LAN vs AWS 400 victims / 50 attackers): timing and TCP windows differ by construction |
| Labels → project classes | FTP-BruteForce → Credential Stuffing (FTP) · SSH-Bruteforce → SSH Brute Force · DoS GoldenEye/Slowloris/SlowHTTPTest/Hulk, DDoS LOIC-HTTP/LOIC-UDP/HOIC → DDoS · Brute Force-Web → Credential Stuffing (web) · Brute Force-XSS → XSS · SQL Injection → SQL Injection · Infilteration → Lateral Movement · Bot → Malware Beacon |
| Missing in 2018 | Port Scan, RCE/Heartbleed, Data Exfiltration; UDP floods (LOIC-UDP) have no 2017 counterpart |
| Quality | 4 of 6 local files have exactly 1,048,575 rows (spreadsheet row limit, upstream); `Thursday-01-03` has 25 repeated header lines inside the file (drop non-numeric rows); labels were assigned by attack schedule, IPs, ports and protocol (UNB page), so label noise inside attack windows is possible and not measured here |
| Memory | 20-02 (≈ 7.9 M rows per community reports, not verified here) must be streamed in chunks on this 7.7 GB machine; per-class caps as in train.py |
| Duplicates / leakage | de-duplicate within and across corpora on the 53-vector; hash-exclude every external-test vector from training (Phase 8 hash-index method); never use `Timestamp`, IPs, ports or `Flow ID` |

## 5. Experiments (plans; nothing downloaded or trained)

**Experiment A — external generalisation of the served model (inference only).**
Train: nothing new — the deployed `xgb_cicids_v1` + IF were trained on CICIDS2017 only. Test: the **4 untouched
days**, mapped to the 53 features, de-duplicated, never inspected before the single evaluation run. Report per day
and per class family: binary recall, benign FPR (Wilson CI), precision, F1, PR-AUC, full served score at 0.90/0.92,
confusion matrix, unseen-family flags (UDP flood). Also run the refitted served recipe on all 2017 rows if a training
comparison is wanted (1 fit). Needs approval: **download 4.98 GB**.

**Experiment B — multi-dataset training.**
- Training pool: CICIDS2017 (all 8 files) + the **6 local 2018 days minus their sealed Phase-7 holdout rows**.
- Validation (all selection, calibration and line choice): leave-one-2018-day-out inside the 6 local days, plus the
  P4 2017 day folds.
- Final test, evaluated **once** after the candidate is frozen: the **4 untouched 2018 days**. They are never used
  for fitting, calibration or selection, so only they may be called an external holdout — **not** "2018" as a whole.
- Candidates (same manifests, same preprocessing): B0 served recipe on 53 features; B1 = option 1 features; B2 = B1 +
  taxonomy fix (option 3); optional B3 = B2 binary-first (option 4).
- Acceptance before recommending deployment: on the untouched days, every class family present in training ≥ 50 %
  recall *and* the best candidate beats B0 by ≥ 10 points binary recall, at benign FPR Wilson upper bound ≤ 0.10 %
  with the line chosen on validation only; P4 2017 results not worse than B0; p95 single-flow latency ≤ 50 ms;
  model ≤ 2× current size; golden-set and protected-hash checks pass. Otherwise report "no improvement" — the
  served model stays.
- Cost (estimates): pool ≈ 2017 124k + 2018 capped ~150k rows; ~20 XGB fits for validation folds + 1 final per
  candidate ≈ 15–40 min CPU; RAM fine with caps; disk 5 GB for the download.

**Integrity rules for every experiment:** no tuning on P5 test rows; nested validation for any selection; frozen
manifests with sha256; identical preprocessing per candidate; seeds and library versions recorded; unseen classes
reported only as "flagged as attack"; supports and CIs for every per-class figure.

## 6. Approval requests

1. Full-hybrid P3/P4 (§1): 6 XGBoost re-fits (reproduction-checked) + 6 Isolation Forest fits.
2. Experiment A: download the 4 untouched 2018 days (4.98 GB to `D:\sentinelai_datasets\cse_cic_ids2018\`) and run
   the served models on them (inference only).
3. Experiment B: candidate training as above (after A).
