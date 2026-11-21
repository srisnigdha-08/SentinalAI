# Paper Corrections (H1)

Every place where the paper (`IMPLIMENTATION.pdf`; line numbers below refer to its text extraction `paper_text.txt`) says something the code or the shipped artifacts now contradict. Each row gives:
- the claim;
- replacement text you can paste;
- the evidence.

Numbers are for the served model `xgb_classifier_xgb_cicids_v1` (XGBoost, registered 2026-10-21 after it beat the Random Forest under chronological evaluation; Phase 5 M-5). See `docs/CRITICAL_FIXES_REPORT.md` and `docs/AI_HIGH_PRIORITY_FIXES_REPORT.md`.

I have not edited the PDF or the body of `paper_text.txt`. On 2026-11-21 a one-line notice pointing here was added at the top of `paper_text.txt`; the PDF's LaTeX source is not in this repository.

**Section 9 (2026-11-21) is newer than sections 1–8.** It adds the cross-dataset (CSE-CIC-IDS2018) result, the Q-learning and session-ML evidence audits, and the Isolation Forest's measured contribution. Where a replacement text in sections 1–8 differs from section 9 (abstract, Table II, Tier 3, Table IV, conclusion), use section 9 and keep the extra detail from 1–8 that it does not contradict, such as the chronological and leave-one-day-out rows.

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
| Adaptive Honeypot Intelligence | "The recommendation is persisted … but the active Cowrie configuration is not automatically modified at runtime." | "… The engine only recommends; an optional rotator (`honeypot/deception_rotator.py`, authenticated with the honeypot's API key only) applies the recommended persona by rewriting Cowrie's configuration and restarting it. This loop was validated once on a live Cowrie; it was not part of the reported evaluation." | `honeypot/deception_rotator.py`; `docs/HONEYPOT_LIVE_EVIDENCE.md` |
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

## 8. Honeypot claims (added after the honeypot audit and live Cowrie run)

Line numbers are approximate positions in `paper_text.txt`. Evidence: `docs/HONEYPOT_STUDY_GUIDE.md` (Phase 4 and 3.6) and `docs/HONEYPOT_LIVE_EVIDENCE.md`.

| Line | Paper says | Replace with | Evidence |
|---|---|---|---|
| 31–34 | "a tabular Q-learning agent recommends adaptive honeypot profiles based on live attacker engagement" | "a tabular Q-learning agent recommends honeypot personas from an engagement reward; it was exercised with local test sessions against a real Cowrie instance, not with internet attackers, and its shipped starting table is a synthetic warm start" | `ai-engine/models/q_table.json` (12,087 scripted episodes); learner stats `provenance` |
| ~449–450 | The honeypot engine is "redirecting suspected attacker traffic to decoy nodes and feeding interaction logs back to the Detection Engine for retraining" | "Cowrie receives traffic addressed to it (port 22 can be redirected to it on the honeypot host); interaction data is stored per session. Redirecting other traffic to decoys and retraining detection models from honeypot data are future work." | No redirection or retraining code reads honeypot data |
| ~426 | Objective: "increase average attacker engagement duration … by ≥40% compared to static honeypot baselines" | Keep it as an objective, and add: "This has not yet been measured; doing so needs an A/B comparison against a static persona on internet-facing traffic." | No experiment exists |
| ~628 | The MDP state "encodes the attacker behaviour fingerprint (commands issued, tools used, and probing patterns), interaction duration, fingerprinting attempt count, and current honeypot configuration" | "In the implementation the state is the persona served in the previous session; attacker behaviour (duration, commands, malicious intents, IOCs, login, fingerprinting) enters through the reward. An attacker-aware state (contextual bandit) is future work." | `rl_engine/deception_scorer.py` `SessionScorer.process_session` |
| ~620 | Actions: "OS profile switching, service banner rotation, timing jitter injection, and artifact planting" | "Implemented actions switch among five Linux personas, each a consistent SSH banner, hostname, kernel strings and fake filesystem (os-release, issue, motd, accounts, home directory, decoy credential files). Timing jitter is future work. A Windows persona exists in the table but is never recommended, because Cowrie emulates only a Linux shell." | `honeypot/switch_profile.py`, `honeypot/build_honeyfs.py`, `servable_profiles()` |
| ~598 | "a pool of honeypot nodes" | "one SSH honeypot node (Cowrie; Telnet is not enabled); further protocols (e.g. Dionaea) are future work" | `honeypotService.getNodeStatus` |
| add | — | "Honeypot sessions are classified by transparent rules over the login outcome, the programs run and IOC counts, not by the flow models, because Cowrie records no packet-flow features." | `utils/features.py` `classify_honeypot_session` (rules v2) |
| add | — | "Blocks derived from honeypot sessions are enforced by a Cowrie plugin that refuses connections from deny-listed IPs; host firewall enforcement uses a mock adapter unless explicitly enabled, honeypot-originated blocks are capped per hour, and they can be set to require analyst approval." | `sentinelblocker.py`, `adapterFactory.js`, `HONEYPOT_AUTOBLOCK_MODE` |

## 9. November 2026 update: cross-dataset evaluation and evidence audits (2026-11-21)

These corrections bring the paper in line with `docs/ML_GENERALISATION.md`, `docs/QLEARNING_EVIDENCE.md` and `docs/SESSION_ML.md`. Apply them to the LaTeX source, recompile, then re-extract `paper_text.txt`. Line numbers refer to `paper_text.txt` without the notice line added at its top.

Every figure below was checked against these sources:

| Figure | Source |
|---|---|
| 98.97 % accuracy, macro F1 0.874, random split, `independent_holdout: false` | `ai-engine/models/xgb_classifier_xgb_cicids_v1_meta.json`; `audit/rank5_network_flow_generalisation/run_20261114T123741Z/metrics.json` (E1) |
| CICIDS2018: recall 14.98 % at the 0.90 line, ROC-AUC 0.655, accuracy 72.94 % vs 72.96 % majority, macro F1 0.115, benign FPR 0.39 %, 5,549,447 flows | same `metrics.json` (E3) |
| Training rows SQLi 17, RCE 9 (Heartbleed), Lateral Movement 29, Data Exfiltration 0 | model meta `class_counts`, `label_sources` |
| Isolation Forest review tier: 2 of 2,254 missed attacks recovered | `docs/AI_HIGH_PRIORITY_FIXES_REPORT.md` (chronological CICIDS2017 test, review level 0.55) |
| Q-learning: 12,106 episodes, 12,087 seed (99.84 %), 0 independent external, 0 of 6 greedy choices changed | `ai-engine/experiments/qlearning_evidence_v2_20261113/report.json` |
| Session ML: 0 independent labels, no model | `ai-engine/experiments/session_ml_data_audit_20261113/audit.json`; `docs/SESSION_ML.md` |
| RF 98.43 %, weighted F1 0.9862, macro F1 0.8448 (earlier model, not served) | paper Table IV; `docs/C1_EVALUATION_PLAN_AND_RESULTS.md` |


### 9.1 Abstract (lines 29–42)

**Replace** from "validated end-to-end: a Random Forest classifier …" to "… in place of the originally proposed PPO
policy for the current, discrete-action-space phase of the system." **with:**

> integrated end-to-end. The served XGBoost classifier, trained on real CICIDS2017 traffic, achieves 98.97 % accuracy
> (macro F1 0.874) on a stratified random split of that dataset. This is in-distribution performance: on six days of
> the later CSE-CIC-IDS2018 dataset the same frozen model detects about 15 % of attack flows (ROC-AUC 0.65), no
> better than always predicting benign, so it does not generalise beyond its training data. A tabular Q-learning
> agent, used in place of the originally proposed PPO policy for the current discrete action space, recommends
> honeypot profiles and is applied by a rotator. Its effectiveness has not been demonstrated: 99.8 % of its
> experience is a synthetic warm start, and no independent attacker sessions have been collected.

### 9.2 Index terms (lines 43–46)

**Replace** with:

> Index Terms—SentinelAI, Cyber Defence, Adaptive Honeypot, Reinforcement Learning, Intrusion Detection,
> Explainable AI, Cross-Dataset Generalisation, Threat Intelligence, Security Orchestration

"Zero-Day Attack", "Deep Learning", "Autonomous Cyber Defence" and "Self-Evolving Security" are removed because no
implemented component provides them.

### 9.3 Contributions, last bullet (lines 107–114)

**Replace** "including a Random Forest detection model validated on real CICIDS2017 traffic and a Q-learning-based
honeypot profile recommendation mechanism with a persistent, auditable policy." **with:**

> including an XGBoost detection model trained on real CICIDS2017 traffic and evaluated both in-distribution and on
> CSE-CIC-IDS2018, and a Q-learning-based honeypot profile recommendation mechanism with a persistent, auditable
> policy whose effectiveness is not yet demonstrated.

Add one bullet after it:

> • A negative cross-dataset result: high random-split accuracy on CICIDS2017 does not carry over to another
> network, which shows that random-split accuracy alone cannot establish intrusion-detection capability.

### 9.4 Table II, "Multi-Model Threat Detection" row (page 6)

**Replace** the "Current Realisation" cell with:

> XGBoost (served), Isolation Forest, and earlier Random Forest models are implemented. The served XGBoost model
> reaches 98.97 % accuracy (macro F1 0.874) on a random CICIDS2017 split but about 15 % attack recall on
> CSE-CIC-IDS2018. The Isolation Forest provides an anomaly signal of limited measured value. The 1D-CNN/LSTM tier,
> the autoencoder and a learned meta-learner are not implemented; fusion is a fixed weighted rule.

### 9.5 Table II, "Adaptive Honeypot Intelligence" row

**Replace** from "The recommendation is persisted …" to the end of the cell with:

> The recommendation is persisted and applied to Cowrie between sessions by a rotator. The state is the previously
> served persona. 12,087 of 12,106 learning episodes are a synthetic warm start, and real sessions changed none of
> the six per-state greedy choices, so adaptive deception is implemented but not demonstrated.

### 9.6 Tier 3 — Anomaly Detection (lines 576–582)

**Replace** "Isolation Forest [27] and an autoencoder independently produce anomaly scores for traffic that does not
conform to known attack or benign signatures, enabling detection of zero-day and previously unseen attacks [3]." **with:**

> In the proposed design, Isolation Forest [27] and an autoencoder produce anomaly scores for traffic that does not
> conform to the training data, intended to help with previously unseen attacks [3]. In the implementation only the
> Isolation Forest exists. Its signal can raise a threat score or queue a flow the classifier calls benign for
> analyst review, but it never raises an alert on its own. On a chronological CICIDS2017 test the review tier
> recovered only 2 of 2,254 attacks the classifier missed, so it does not provide zero-day detection.

### 9.7 Section VIII-A, dataset paragraph (lines 849–865)

**Replace** from "In the current implementation, four of the eight official CICIDS2017 capture files are integrated" to
"… is the immediate next step identified in the roadmap." **with:**

> In the current implementation, all eight official CICIDS2017 capture files are integrated. Several classes remain
> almost unrepresented: the training split contains 17 SQL Injection, 9 RCE Attempt (all Heartbleed, a memory
> disclosure mapped to this class for lack of other data, which is a label-quality limitation), 29 Lateral Movement
> and no Data Exfiltration flows, so Data Exfiltration cannot be predicted and results for the other three are not
> meaningful. CSE-CIC-IDS2018 has been used for cross-dataset evaluation of the frozen model (Section IX-A), not
> for training.

In Table III, change the CICIDS2018 status to "Evaluation only (six development days)".

### 9.8 Section IX-A, Measured Detection Performance (lines 916–958)

**Replace** the opening paragraph, Table IV and both caveats with:

> Table IV reports the served classifier on two evaluation sets that are kept apart. On a stratified random 80/20
> split of de-duplicated CICIDS2017 data, flows from the same capture sessions appear in both training and test, so
> this measures in-distribution performance only (the model metadata records `independent_holdout: false`). The
> same frozen model was then scored, without any refitting, on every flow of six CSE-CIC-IDS2018 development days
> recorded on a different network. These days were used in developing other candidate models, so they are not a
> sealed holdout. Four further 2018 days are reserved for a one-shot external test that has not been run.
>
> TABLE IV — MEASURED DETECTION PERFORMANCE OF THE SERVED XGBOOST MODEL
>
> | Evaluation set | Flows | Accuracy | Macro F1 | Attack recall (0.90 line) | Benign FPR (0.90 line) | ROC-AUC |
> |---|---|---|---|---|---|---|
> | CICIDS2017 random split | 24,907 | 98.97 % | 0.874 | 95.2 % | 0.23 % | 0.9998 |
> | CSE-CIC-IDS2018, six days | 5,549,447 | 72.94 % (always-benign baseline 72.96 %) | 0.115 | 15.0 % | 0.39 % | 0.65 |
>
> The 2018 result shows the model does not generalise to another network: it is no better than always predicting
> benign. The feature distributions of the two datasets differ strongly (covariate shift between networks, tools and
> flow-extractor builds). The earlier Random Forest figure (98.43 % accuracy, 0.9862 weighted F1, 0.8448 macro F1)
> came from a random split before de-duplication, and that model is not served. Per-class results for SQL
> Injection, RCE Attempt and Lateral Movement are not meaningful, and Data Exfiltration is not modelled
> (Section VIII-A).

Also delete the sentence "False-positive rate, AUC-ROC, and end-to-end response latency have not yet been
instrumented …", or reduce it to "End-to-end response latency has not yet been measured."

### 9.9 Section IX-C, Adaptive Honeypot (lines 967–986)

**Replace** from "implemented and running against live honeypot sessions …" to "… it does not automatically modify the
active Cowrie configuration at runtime." **with:**

> implemented, with a persistent Q-table that records the source of every learning update. A rotator applies the
> recommended persona to Cowrie between sessions. The available evidence does not show that the policy works:
> 12,087 of the table's 12,106 episodes (99.84 %) are a synthetic warm start, the 19 session-driven updates came
> from operator-generated traffic, no independent attacker sessions exist, and real data changed none of the six
> per-state greedy choices. The state is only the previously served persona.

Keep the following paragraph (the static-honeypot comparison has not been run). Append: "A comparison on scripted and
simulated attackers (Deception Arena) found no difference."

### 9.10 Section XI-H, Discussion (lines 1153–1162)

**Replace** "The honeypot intelligence component also processes real interaction data to generate adaptive profile
recommendations rather than relying solely on a fixed policy. However, the active Cowrie configuration remains
unchanged automatically in the current implementation; runtime application of the recommended deception profile is
reserved for future work." **with:**

> The honeypot intelligence component scores each session and applies a learned profile recommendation between
> sessions, but its benefit over a fixed persona has not been demonstrated. A honeypot-session ML pipeline is also
> implemented in shadow mode; no model has been trained, because no independently labelled sessions exist.

### 9.11 Section XIII, Conclusion (lines 1229–1235)

**Replace** "a Random Forest detection model validated on real CICIDS2017 traffic at 98.43% accuracy and 0.9862
weighted F1, a Q-learning-based honeypot profile recommendation mechanism with a persistent, auditable policy," **with:**

> an XGBoost detection model with 98.97 % accuracy on a random CICIDS2017 split but about 15 % attack recall on
> CSE-CIC-IDS2018, a Q-learning-based honeypot profile recommendation mechanism whose effectiveness is not yet
> demonstrated,

Add this sentence before "Closing the autonomous-response loop …":

> The central empirical finding is negative: in-distribution accuracy did not transfer to another dataset, so
> cross-dataset evaluation, not random-split accuracy, must be the acceptance test for future models.

### 9.12 Section IV-B, objective 1 (line 307)

No change is needed, because it is stated as a design target. If you keep it, add: "(met in-distribution on
CICIDS2017; not met on CSE-CIC-IDS2018)."

### 9.13 Out of scope here

These are outdated non-ML statements, not changed by this page:
- the containment wording in Table II
- §XI-G, which mentions four Jest test files; the project now has more than 2,000 automated tests
- "the active Cowrie configuration is not automatically modified"
