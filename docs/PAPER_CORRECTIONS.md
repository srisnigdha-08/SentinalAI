# Paper Corrections (H1)

Every place where the paper (`IMPLIMENTATION.pdf`; line numbers below refer to its text extraction `paper_text.txt`) says something the code or the shipped artifacts now contradict. Each row gives:
- the claim;
- replacement text you can paste;
- the evidence.

Numbers are for the served model `xgb_classifier_xgb_cicids_v1` (XGBoost, registered 2026-10-21 after it beat the Random Forest under chronological evaluation; Phase 5 M-5). See `docs/CRITICAL_FIXES_REPORT.md` and `docs/AI_HIGH_PRIORITY_FIXES_REPORT.md`.

I have not edited the PDF or `paper_text.txt`.

## 1. Abstract and conclusion

| Line | Paper says | Replace with | Evidence |
|---|---|---|---|
| 18 | "Engine combining Random Forest, XGBoost, 1D-CNN, and Isolation Forest" | "Engine designed to combine Random Forest, XGBoost, 1D-CNN and Isolation Forest models (XGBoost and Isolation Forest are deployed; the 1D-CNN tier is future work)" | `models/registry.json` pins an RF and an IF only; no deep-learning code exists |
| 31–33 | "a Random Forest classifier trained on real CICIDS2017 traffic achieves 98.43% accuracy and 0.9862 weighted F1" | "an XGBoost classifier trained on de-duplicated CICIDS2017 traffic reaches 98.97% accuracy (0.874 macro F1) on a random split and 0.772 macro F1 under chronological evaluation, where it raises an alert for 91.0% of attack flows at a 0.13% benign alert rate" | `models/rf_classifier_cicids_v3_meta.json`; `experiments/c2_dedup_eval/` |
| 1021–1022, 1234 | "98.43% accuracy and 0.9862 weighted F1" | Same replacement as lines 31–33 | same |

## 2. Table II (implementation status)

| Row | Paper says | Replace with | Evidence |
|---|---|---|---|
| Multi-Model Threat Detection | "Random Forest (RF), XGBoost, Isolation Forest, and an SGD-based online learner are implemented and trained. RF is validated on CICIDS2017 data, achieving 98.43% accuracy and 0.9862 weighted F1." | "Random Forest, XGBoost, a stacking ensemble and an Isolation Forest are implemented and trained on CICIDS2017. The deployed pair is XGBoost and the Isolation Forest, pinned by SHA-256 in a model registry with a startup golden-set check. XGBoost was selected over the Random Forest by chronological evaluation (91.0% vs 78.6% attack detection at the alert line; benign alert rate 0.134% vs 0.154%)." | `training/train.py`; `models/registry.json`. **No SGD code exists** in `ai-engine/` |
| Self-Evolution Module | "An SGD-based classifier and operator-feedback path support incremental learning through partial_fit … the supplied SGD artifact currently fails to deserialize …" | "Analyst-verified predictions can be exported and used to retrain a candidate model offline. The candidate is promoted only if it passes gates on a sealed chronological test (macro F1 not worse by more than 0.005; benign alert rate ≤ 0.1%), and is then hot-reloaded. A drift monitor flags when inputs depart from the training distribution. GAN augmentation and EWC are future work." | `training/retrain_from_samples.py`, `monitoring/drift.py`, `POST /model/reload`. Not yet run end to end: say "implemented", not "demonstrated" |
| Adaptive Honeypot Intelligence | "The recommendation is persisted … but the active Cowrie configuration is not automatically modified at runtime." | "… The engine only recommends; an optional rotator (`honeypot/deception_rotator.py`) can apply the recommended persona to Cowrie, but was not used in the reported evaluation." | `honeypot/deception_rotator.py` |
| Cross-Domain Threat Intelligence (line 552) | "An IP-reputation enrichment service based on AbuseIPDB has also been integrated." | "… integrated as asynchronous enrichment in the backend (it is not on the inference path)." | `predictor.predict` sets `ipReputationScore=None`; the enrichment runs in the backend's `threatIntelService` |

## 3. Section VI-A (detection engine)

| Line | Paper says | Replace with | Evidence |
|---|---|---|---|
| 581–586 | Tier 3 "enabling detection of zero-day and previously unseen attacks … The Isolation Forest component is implemented and integrated" | "The Isolation Forest is implemented and trained on benign traffic only. Its output raises the threat score of flows the classifier already labels as attacks. A flow the classifier labels benign but the Isolation Forest flags strongly is sent to an analyst-review queue; it never raises an alert or a block on its own. On leave-one-day-out evaluation, attacks from an unseen day are essentially not detected (≤ 0.4%), so the system does not detect novel attacks." | `inference/predictor.py` (`REVIEW` action); `experiments/c2_dedup_eval/` LODO rows; review numbers in `docs/AI_HIGH_PRIORITY_FIXES_REPORT.md` |
| 588–597 | thresholds τ_low / τ_high | "τ_high is the alert line (0.90) and the block line is 0.92. Both were chosen on a chronological validation split for a benign alert rate of at most 0.1%. Auto-block requires an administrator setting." | `predictor.py` `MONITOR_THRESHOLD`, `BLOCK_THRESHOLD` |

## 4. Section VI-B (honeypot learner)

| Line | Paper says | Replace with | Evidence |
|---|---|---|---|
| 618–620 | "The reward function R_HP assigns positive rewards for extended attacker engagement and negative rewards for detected honeypot identification events." | Keep the sentence. It is now true: commands that check for virtualisation or honeypots (e.g. `systemd-detect-virt`, `/proc/1/cgroup`, `dmidecode`) cost 5 reward points, and rewards are bounded to [−10, 20]. | `rl_engine/deception_scorer.py` `calc_reward`, `FINGERPRINT_PATTERNS` |
| 639–641 | "tabular Q-learning with an ε-greedy exploration policy and ε-decay" | "… and ε-decay with a floor of 0.05, so personas keep being re-tried as attacker behaviour changes. Convergence is monitored as the mean absolute TD error over the last 100 updates." | `EPSILON_MIN`, `convergence()` |
| add | — | "Because the next state is the persona just served, the learner behaves like a contextual multi-armed bandit over personas; its Q-values approach the mean engagement reward divided by (1−γ)." | `SessionScorer.process_session` (s′ = a) |

## 5. Section VIII (dataset and preprocessing)

| Line | Paper says | Replace with | Evidence |
|---|---|---|---|
| 846–852 | "four of the eight official CICIDS2017 capture files are integrated … covering six of the eleven attack classes" | "All eight CICIDS2017 MachineLearningCVE capture files are used (Monday–Friday). Ten of the eleven target classes have real labelled flows. Data Exfiltration has none and is produced only by honeypot session rules. SQL Injection, RCE Attempt and Lateral Movement have fewer than 100 training rows each, and their verdicts are flagged as low-data." | `train.py:42` (glob `*.csv`); `rf_classifier_cicids_v3_meta.json` `class_counts`; `/model/info` `classProvenance` |
| add (label mapping) | "Label harmonisation, mapping each dataset's raw attack labels onto the platform's eleven-class target taxonomy." | Add: "Several target classes merge different CICIDS attacks: 'DDoS' covers the DDoS capture and four DoS tools, including slow-rate DoS; 'Credential Stuffing' covers FTP and HTTP password brute force; 'RCE Attempt' is trained only on Heartbleed (an exploit of a public-facing service, MITRE T1190); 'Lateral Movement' is CICIDS 'Infiltration'." | `utils/features.py` `LABEL_SOURCES` |
| 889–897 | "SMOTE-based minority-class oversampling has not yet been applied" | Keep. It is true for the deployed model (the August artifact had used SMOTE; the current one does not). Add: "Exact duplicate flows (22% of the dataset; 98.8% of PortScan rows) are removed before any train/test split." | `train.py` `drop_duplicate_rows`; `rf_classifier_cicids_v3_meta.json` `"smote": false` |
| 902 | "a fixed, manually engineered 46-feature subset" | "53 features: 49 CICFlowMeter statistics, payload entropy, and two time-of-day features. The time features are constant in CICIDS2017 and receive zero importance." | `utils/features.py:12-33` |
| 904–905 | "partitioned using stratified sampling" | "… a stratified random 80/20 split after de-duplication, plus chronological and leave-one-day-out evaluation." | `evaluation/day_holdout_eval.py` |

## 6. Section IX (results), Table IV

| Line | Paper says | Replace with |
|---|---|---|
| 919 | "held-out stratified split of the four integrated CICIDS2017 capture files" | "held-out splits of the de-duplicated eight-file CICIDS2017 data, under three protocols" |
| 927–931 | "the XGBoost and secondary Isolation Forest variants reported here are trained on the platform's synthetic data generator … False-positive rate … not yet been instrumented" | "XGBoost was also trained on real CICIDS2017 data but is not deployed. The benign false-positive rate is reported with 95% Wilson intervals." |
| 938–944 (Table IV) | RF real 98.43% / 0.9862; RF synthetic 93.20%; XGB synthetic 83.67% | Replace with the table below |
| 950–953 | "only six of the eleven target classes currently have real CICIDS2017 training examples" | "ten of the eleven classes have real examples, but three have fewer than 100 training rows; their per-class figures rest on 2–7 test flows and are not statistically meaningful" |

**Replacement Table IV.** De-duplicated CICIDS2017. Alert = threat score ≥ 0.90 and a class other than BENIGN. The deployed model is XGBoost; the Random Forest is shown because the paper's original results are RF.

| Model | Protocol | Accuracy | Weighted F1 | Macro F1 | Attack flows alerted | Benign alert rate [95% CI] |
|---|---|---|---|---|---|---|
| **XGBoost (deployed)** | Stratified random 80/20 (train.py) | 98.97% | 0.991 | 0.874 | — | — |
| **XGBoost (deployed)** | Chronological within each capture | 98.9% | 0.990 | 0.772 | 91.0% | 0.134% [0.118, 0.154] |
| **XGBoost (deployed)** | Leave-one-day-out (Tue / Wed / Thu / Fri held out) | 67–93% | 0.55–0.94 | 0.20–0.31 | 0.2% / 6.9% / 80.2% / 10.3% | 0.04–1.41% |
| Random Forest | Stratified random 80/20 (train.py) | 98.47% | 0.986 | 0.842 | — | — |
| Random Forest | Chronological within each capture | 97.6% | 0.979 | 0.750 | 78.6% | 0.154% [0.136, 0.174] |
| Random Forest | Leave-one-day-out | 66–93% | 0.53–0.92 | 0.19–0.30 | ≤ 0.4% | 0.02–0.16% |

In the chronological row, accuracy and F1 come from the chronological protocol (`experiments/c2_dedup_eval/results.json`). The alert rates come from the threshold-validation run on the same test rows, where the model is fitted on 80% of that training portion (`threshold_validation/results.json`).

The old XGBoost figures (99.13% accuracy, 0.907 macro F1) come from the random split with duplicates. Use the de-duplicated rows above instead. XGBoost generalises somewhat better to unseen days than the RF (it detects 80% of attacks when Thursday's web attacks/infiltration are held out, at a 1.4% benign alert rate), but it still does not detect novel attacks in general.

## 7. Section XII (future work)

| Line | Paper says | Replace with |
|---|---|---|
| 1213 | "The SGD-based continual-learning mechanism will subsequently be extended toward …" | "The gated offline retraining pipeline will subsequently be extended toward …" |
