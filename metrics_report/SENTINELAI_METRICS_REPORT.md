# SentinelAI: Metrics and Performance Evaluation

Audit date: 22–23 Oct 2026 · Branch `db-fixes` at `347af80` (with the uncommitted working-tree changes present at audit time) · Auditor: Claude Code

**Ground rule.** Every number below comes from a file in this repository, a database record on this machine, or a measurement I ran during this audit. Each number names its source. Where nothing measured exists, the report says **NOT MEASURED**. It does not estimate.

**Where everything is**

| What | Path |
|---|---|
| This report | `metrics_report/SENTINELAI_METRICS_REPORT.md` |
| New raw outputs (JSON, logs, CSV) | `metrics_report/raw/` |
| Scripts I wrote for this audit (all read-only with respect to the project) | `metrics_report/scripts/` |
| Charts (drawn only from the JSON files above) | `metrics_report/charts/` |
| Pre-existing evidence that I reused | `ai-engine/experiments/m5_xgboost_eval/`, `ai-engine/experiments/c2_dedup_eval/`, `docs/CRITICAL_FIXES_REPORT.md`, `docs/C1_EVALUATION_PLAN_AND_RESULTS.md`, `docs/HONEYPOT_LIVE_EVIDENCE.md`, `docs/PAPER_CORRECTIONS.md`, `audit/REPORT.md` |

**What I did not change:** no production code, no model files, no registry entries, no existing databases. The real Q-table was not touched (the benchmark used a scratch copy), and no firewall or system settings were changed. The only database I wrote to is a new, isolated `sentinel-metrics-bench-20261023`, which I created for the latency benchmark.

---

## 0. Test environment

| Item | Value |
|---|---|
| CPU | Intel Core i5-12500H, 12 cores / 16 logical processors |
| RAM | 7.7 GB |
| OS | Windows 11 Home Single Language 10.0.26200 |
| Python (AI engine venv) | 3.11.9, scikit-learn 1.4.0, xgboost 2.0.3, numpy 1.26.4, pandas 2.2.0 |
| Node.js | v24.14.0 |
| MongoDB | local `mongod`, 127.0.0.1:27017 |
| Network | all services on loopback; no external traffic was generated |

---

## 1. What is actually implemented (inventory)

| Component | Status | Evidence |
|---|---|---|
| **XGBoost classifier `xgb_cicids_v1`** | **ACTIVE (served)** | `ai-engine/models/registry.json` pins it by SHA-256 `6d08ef19…` |
| **Isolation Forest `isolation_forest_xgb_cicids_v1`** | **ACTIVE (served)**. It can only raise the score of a flow the classifier already calls an attack; flows the classifier calls benign but the IF flags go to a review queue | `registry.json`; `inference/predictor.py` `combine_threat_score` |
| Random Forest v3, v2, v1; old XGBoost; stacking ensemble | **Archived, not loaded** | `ai-engine/models/README.md` |
| `rf_classifier_v2.1`, `xgb_classifier.pkl`, `isolation_forest_v1.4` | Archived. Trained on **synthetic** data | `models/README.md` |
| SGD online learner, 1D-CNN | **Not implemented** (no code exists) | `docs/PAPER_CORRECTIONS.md` §1–2 |
| SHAP explanations | Active (`?explain=true`) | measured below |
| Drift monitor | Implemented (`monitoring/drift.py`); no production drift run recorded | — |
| Gated retraining | Implemented (`training/retrain_from_samples.py`); dry runs only (`experiments/retraining/u1_dry_run*`) | — |
| Honeypot session classifier | **Rule-based, not ML** (`classificationMethod: honeypot_rules`) | `predictor.py` `HONEYPOT_RULE_SCORES` |
| Q-learning deception engine | Active. The shipped seed is a **synthetic** warm start | `ai-engine/models/q_table.json` |
| Deception rotator (applies persona to Cowrie) | Implemented; validated **once** on a live local Cowrie | `docs/HONEYPOT_LIVE_EVIDENCE.md` |
| Containment | Active with the **mock adapter** by default. Auto-block is **off** by default | `backend/services/containment/adapterFactory.js` |
| Windows Firewall adapter | Implemented and gated behind two settings. **Never executed** | `audit/REPORT.md` F4 |
| Cowrie deny-list plugin (`sentinelblocker.py`) | Implemented; one refused connection observed in the live run (deny-list served from a local stub) | `docs/HONEYPOT_LIVE_EVIDENCE.md` |
| Live packet capture | **Not implemented**; input is flow records (posted or replayed) | README |

---

## 2. AI/ML model performance

### 2.1 Dataset

| Item | Value | Source |
|---|---|---|
| Dataset | CICIDS2017 MachineLearningCVE, all 8 CSVs (Monday–Friday) | `ai-engine/datasets/cicids2017/` |
| Rows after dropping NaN/inf | 2,827,876 | `docs/C1_EVALUATION_PLAN_AND_RESULTS.md` |
| Exact duplicate rows removed | 628,877 (22.2%). Port Scan: 98.8% duplicates | `ml_eval.json` B; `CRITICAL_FIXES_REPORT.md` §2.3 |
| Rows after de-duplication | 2,198,999 | `ml_eval.json` B |
| Features | 53: 49 CICFlowMeter statistics, payload entropy, and 2 time-of-day features (always 0 in CICIDS2017) | model meta |
| Target classes | 11 defined. 10 have real data; Data Exfiltration has **none** | meta `class_counts` |
| Class imbalance (served model's training split) | BENIGN 74,682 · DDoS 14,440 · Credential Stuffing 5,921 · SSH 2,575 · Beacon 1,149 · XSS 522 · Port Scan 283 · Lateral Movement 29 · SQLi 17 · RCE 9 | `xgb_classifier_xgb_cicids_v1_meta.json` |
| Imbalance handling | `class_weight`/XGBoost defaults, **no SMOTE** | meta `"smote": false` |
| Label merging | DDoS = DDoS + 4 DoS tools; Credential Stuffing = FTP-Patator + Web Brute Force; RCE = Heartbleed only; Lateral Movement = Infiltration; Malware Beacon = Bot | meta `label_sources` |

**Binary vs multiclass.** The model is an 11-class classifier. "Binary intrusion detection" below means *any attack class* vs BENIGN, derived from the same predictions.

### 2.2 Leakage checks

| Check | Finding |
|---|---|
| Exact duplicates across the train/test split | Before the C2 fix, 17.3% of test rows had an identical twin in train. After de-duplication I measured **15 of 24,907 test rows (0.06%)** with an identical feature vector in train; these carry a different label (`ml_eval.json` A). |
| Burst leakage (random row split) | **Present.** A random split puts flows from the same attack burst on both sides. This is why the random split scores higher than the chronological split (macro F1 0.874 vs 0.772). |
| Chronological split | First 70% of every (file, class) is used for training, a 1% purge gap is skipped, and the last 29% is the test set. Caveat: row order is used as time order, because the CSVs have no timestamp column. |
| Constant features | The 2 time-of-day features are always zero, so they carry no information and cannot leak. |
| Threshold chosen on the test set? | The 0.90 alert line was chosen on a **validation** split of the Random Forest run (`CRITICAL_FIXES_REPORT.md` §2.5). For XGBoost, the same validation procedure selects **0.87** (`experiments/pipeline/xgb_cicids_v1/summary.md`), so 0.90 is not tuned on the XGBoost test rows. |
| Ground-truth label in API payloads | Never sent; `replay_cicids.py` asserts this. |

### 2.3 Results: three evaluation protocols

**Protocol A: served artifact on its own held-out split.** The test set is the stratified random 80/20 split after de-duplication: 24,907 test rows (6,236 attack, 18,671 benign). This is optimistic, not independent. Source: `metrics_report/raw/ml_eval.json` → `A_served_random_split`.

**Protocol B: chronological.** The served recipe (XGBoost + benign-only Isolation Forest) is retrained on earlier flows and tested on later ones: 184,280 test flows (24,280 attack, 160,000 benign), 150,309 training rows. This is the **honest headline**. Source: `ml_eval.json` → `B_chronological`. My run reproduces the existing `m5_xgboost_eval` figures exactly (detection 91.13%, benign alert rate 0.1587%), which cross-checks both runs.

**Protocol C: leave-one-day-out.** Each capture day is held out in turn: an entire day of attacks is never seen in training. Existing evidence from `ai-engine/experiments/m5_xgboost_eval/results.json`.

#### Multiclass

| Metric | A: random (served artifact) | **B: chronological** | C: unseen day (Tue / Wed / Thu / Fri) |
|---|---|---|---|
| Accuracy | 98.97% | **98.91%** | 68.5% / 66.5% / 93.4% / 84.0% |
| Macro F1 | 0.874 | **0.772** | 0.272 / 0.274 / 0.198 / 0.308 |
| Weighted F1 | 0.991 | **0.990** | 0.561 / 0.548 / 0.937 / 0.815 |
| Macro one-vs-rest ROC-AUC | 0.9949 | **0.9988** | NOT MEASURED |

#### Binary (attack vs benign): classifier alone, Isolation Forest alone, combined system

Protocol B (chronological, 24,280 attack / 160,000 benign):

| System | Accuracy | Precision | Recall (Detection rate) | F1 | FPR [95% CI] | FNR | ROC-AUC | PR-AUC | TP / FN / FP / TN |
|---|---|---|---|---|---|---|---|---|---|
| XGBoost classifier alone | 99.29% | 97.66% | 96.96% | 97.31% | 0.353% [0.325, 0.383] | 3.04% | 0.9985 | 0.9937 | 23,543 / 737 / 564 / 159,436 |
| Isolation Forest alone (score < −0.55) | 89.00% | 69.40% | 29.59% | 41.49% | 1.98% [1.91, 2.05] | 70.41% | 0.8464 | 0.4543 | 7,184 / 17,096 / 3,167 / 156,833 |
| Classifier OR Isolation Forest | 97.67% | 86.41% | 97.63% | 91.68% | 2.33% | 2.37% | — | — | 23,705 / 575 / 3,728 / 156,272 |
| **SentinelAI alert (deployed rule, score ≥ 0.90)** | **98.69%** | **98.87%** | **91.13%** | **94.84%** | **0.159% [0.140, 0.180]** | **8.87%** | 0.9979 | 0.9901 | 22,127 / 2,153 / 254 / 159,746 |
| SentinelAI block line (score ≥ 0.92) | 98.63% | 98.96% | 90.56% | 94.58% | 0.144% [0.127, 0.164] | 9.44% | — | — | 21,989 / 2,291 / 231 / 159,769 |

Protocol A (served artifact, random split): classifier alone has precision 98.94%, recall 99.81%, F1 99.37%, FPR 0.359%, ROC-AUC 0.9998. The Isolation Forest alone has recall 24.84%, FPR 5.06%, ROC-AUC 0.786. The **combined alert** has precision 99.28%, recall 95.22%, F1 97.21%, FPR 0.230%, FNR 4.78%, ROC-AUC 0.9993, PR-AUC 0.9980 (5,938 / 298 / 43 / 18,628).

**What the comparison shows:**
- The **classifier does almost all the detection.** The Isolation Forest alone finds fewer than a third of attacks.
- OR-ing the IF into the classifier adds only 0.7 points of recall and raises false positives 6.6×.
- The deployed rule trades **5.8 points of recall for 2.2× fewer false alarms** (0.353% → 0.159%) compared with the classifier alone.
- Protocol C shows the IF does not rescue unseen attacks.

#### Confusion matrix (Protocol B, rows = true class, columns = predicted)

| True \ Pred | BENIGN | SSH | SQLi | PortScan | DDoS | RCE | XSS | Beacon | CredStuff | Lateral |
|---|---|---|---|---|---|---|---|---|---|---|
| BENIGN (160,000) | **159,436** | 2 | 2 | 6 | 160 | 0 | 11 | 329 | 51 | 3 |
| SSH Brute Force (934) | 3 | **931** | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| SQL Injection (7) | 3 | 0 | **4** | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Port Scan (568) | 40 | 0 | 0 | **499** | 2 | 0 | 5 | 0 | 22 | 0 |
| DDoS (20,000) | 651 | 0 | 29 | 351 | **18,923** | 0 | 1 | 0 | 45 | 0 |
| RCE (4) | 0 | 0 | 0 | 0 | 0 | **4** | 0 | 0 | 0 | 0 |
| XSS (190) | 7 | 0 | 0 | 1 | 0 | 0 | **130** | 0 | 52 | 0 |
| Malware Beacon (418) | 16 | 0 | 0 | 0 | 0 | 0 | 0 | **402** | 0 | 0 |
| Credential Stuffing (2,148) | 15 | 0 | 1 | 0 | 0 | 0 | 205 | 0 | **1,927** | 0 |
| Lateral Movement (11) | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **9** |

The main confusions are XSS ↔ Credential Stuffing (both are HTTP attacks against the same web application in the Thursday capture) and DDoS → BENIGN (651 flows).

#### Per-class performance (Protocol B)

| Class | Precision | Recall | F1 | Support | Alert raised (≥ 0.90) | Reliable? |
|---|---|---|---|---|---|---|
| BENIGN | 99.54% | 99.65% | 99.59% | 160,000 | — | yes |
| SSH Brute Force | 99.79% | 99.68% | 99.73% | 934 | 98.72% | yes |
| DDoS | 99.15% | 94.62% | 96.83% | 20,000 | 91.83% | yes |
| Credential Stuffing | 91.89% | 89.71% | 90.79% | 2,148 | 88.87% | yes |
| Port Scan | 58.23% | 87.85% | 70.04% | 568 | 90.14% | yes |
| Malware Beacon | 54.99% | 96.17% | 69.97% | 418 | 79.90% | yes |
| XSS Attempt | 36.93% | 68.42% | 47.97% | 190 | 35.79% | yes (weak) |
| Lateral Movement | 75.00% | 81.82% | 78.26% | 11 | 72.73% | **no (n < 30)** |
| SQL Injection | 11.11% | 57.14% | 18.60% | 7 | 57.14% | **no (n < 30)** |
| RCE Attempt (Heartbleed) | 100% | 100% | 100% | 4 | 100% | **no (n < 30)** |
| Data Exfiltration | — | — | — | 0 | — | no data |

#### Comparison with the Random Forest (existing evidence)

Both rows use the chronological protocol on de-duplicated data (`docs/PAPER_CORRECTIONS.md` Table IV, from `experiments/c2_dedup_eval` and `m5_xgboost_eval`).

| Model | Macro F1 | Attack flows alerted | Benign alert rate |
|---|---|---|---|
| XGBoost (served) | 0.772 | 91.0% | 0.134% [0.118, 0.154] (threshold-validation run) |
| Random Forest v3 | 0.750 | 78.6% | 0.154% [0.136, 0.174] |

#### Operational metrics of the model

| Metric | Value | Conditions / source |
|---|---|---|
| Model size | XGBoost **3.33 MB**, Isolation Forest **1.33 MB** | file sizes (`ml_eval.json`) |
| Model load time (unpickle only, warm interpreter) | 0.49–0.85 s (first load in the process 2.53 s) | `ml_eval.json` artifacts |
| Cold load (fresh interpreter, imports + unpickle) | 10.8–12.4 s (3 runs) | `raw/model_latency_quiet.json` |
| AI engine startup to `/ready` | 28.3 s (1 run, includes SHAP explainer and golden-set check) | benchmark log |
| In-process inference, 1 flow (XGB + IF) | mean 26.2 ms, **p50 18.0 ms**, p95 41.3 ms, p99 207 ms (n = 1,000) | `raw/model_latency_quiet.json`, quiet machine |
| In-process batch throughput | **27,465 flows/s** (20,000 rows in 0.73 s) | same |
| Engine-reported `inferenceTimeMs` over HTTP | mean 28.5 ms, p50 19.8 ms, p95 50.9 ms (n = 300) | `raw/api_bench.json` |
| Training time, XGB + IF on 150,309 rows | 97.3 s (1 run; another test suite was running at the time, so indicative only) | `ml_eval.json` B |

---

## 3. Threat detection metrics

Three kinds of evidence are kept separate here:

| Kind | What it is | Can it be called "detection performance"? |
|---|---|---|
| **Offline evaluation** (§2) | Labelled CICIDS2017 test splits | **Yes**. Protocol B is the defensible figure. |
| **Dataset replay through the live stack** (below) | Real CICIDS2017 rows posted to the running services | It demonstrates that the pipeline works end to end. **It is not an independent accuracy estimate**: the rows were curated by `load_curated_sample`, and they come from files whose rows were used in training. |
| **Seeded/demo DB records** | `backend/utils/seed.js` output in `sentinel-db` | **No.** Synthetic. |

### 3.1 Replay through the AI engine (`POST /predict/eval`, no persistence)

Source: `raw/api_bench.json`, run 1.

| Metric | Value |
|---|---|
| Flows replayed | 300 (150 attack: Credential Stuffing 50, DDoS 50, Port Scan 25, Malware Beacon 25; 150 benign) |
| Attack flows classified as an attack | 144 / 150 (96.0%) |
| Benign flows classified as an attack | 10 / 150 (6.7%). This is a curated, small sample and is **not a false-positive rate**; use §2 for that |
| Actions | BLOCK 121 · MONITOR 3 · ALLOW 176 |
| Request errors | 0 / 300 |

### 3.2 Replay through the backend (`POST /api/ai/analyze`, stored in MongoDB)

Source: `raw/api_bench.json` and `raw/e2e_db_latency.json`, isolated bench DB.

| Metric | Value |
|---|---|
| Flows processed | 120 (60 attack: DDoS 25, Port Scan 25, Credential Stuffing 10; 60 benign) |
| Benign vs malicious classification | 60/60 attacks classified as attack; 0/60 benign flagged |
| Threats created (alert line 0.90) | 56 (93.3% of attack flows); 4 attack flows scored below the line |
| Missed attacks (no threat created) | 4 |
| False alarms | 0 |
| Severity of created threats | CRITICAL 54 · HIGH 2 |
| Threats with a MITRE ATT&CK technique attached | 56 / 56 |
| Predictions stored | 120 / 120 |
| **Alert-generation latency** (flow sent → ThreatLog stored in MongoDB) | mean 75 ms, **p50 65 ms**, p95 123 ms, p99 204 ms, max 299 ms (n = 56) |
| Flow sent → prediction stored | p50 57 ms, p95 229 ms (n = 120) |

### 3.3 Other detection metrics

| Metric | Value | Source |
|---|---|---|
| Detection throughput, in process | 27,465 flows/s | §2 |
| Detection throughput over HTTP, sequential | ≈ 20 req/s (1 / 50 ms mean latency) | `api_bench.json` |
| Detection throughput over HTTP, 8 concurrent clients | **17.6 / 17.7 req/s** (2 runs); p50 375–399 ms | `api_bench.json`, `api_bench_run2.json` |
| Severity distribution of alerts (chronological test) | CRITICAL 22,220 · HIGH 161 | `ml_eval.json` B |
| MITRE ATT&CK mapping coverage | All 11 detection classes map to a technique. The mapping holds **32 distinct technique IDs**: class mappings, 8 intent groups and 19 per-command rules | `backend/utils/mitreMapping.js` |

**Finding on concurrency.** HTTP throughput does not increase with concurrent clients, and the engine's CPU peaked at only 23.9% of the machine. Likely causes are thread over-subscription (`n_jobs=-1` inside a threadpool) or lock contention in the engine. I have not verified the cause. This finding comes from a single machine.

---

## 4. Honeypot metrics

Only the **verification databases** contain sessions produced by a real Cowrie instance. Every session in them came from **local SSH clients** (paramiko, OpenSSH for Windows), run by the project team. None came from internet attackers. `sentinel-db` and `sentinelai_test` contain seeded/fixture sessions (for example, 3,397 "login attempts" from documentation IPs in `seed.js`); these are **excluded**.

Source: `raw/db_metrics.json`.

| Metric | honeypot-verify (21 Oct) | cowrie-verify (22 Oct) | runbook-verify (22 Oct) | demo (22 Oct) | **Total** |
|---|---|---|---|---|---|
| Sessions | 22 (12 live Cowrie + 10 API-injected test sessions) | 19 | 9 | 4 | **54** (44 from Cowrie) |
| Unique source IPs | 7 | 1 | 1 | 2 | 2 real client hosts (127.0.0.1, WSL host 172.29.32.1) + 6 injected test IPs |
| Login attempts | 33 | 19 | 9 | 3 | 64 |
| Successful / failed logins | 11 / 22 | 6 / 13 | 3 / 6 | 1 / 2 | 21 / 43 |
| Commands executed | 44 | 24 | 11 | 7 | 86 |
| Session duration, mean / max (s) | 17.1 / 284 | 7.2 / 20 | 2.8 / 12 | 44.3 / 120 | — |
| IOCs extracted (IPs / URLs / hashes) | 2 / 2 / 1 | 2 / 2 / 1 | 2 / 2 / 0 | 1 / 1 / 0 | 7 / 7 / 2 |
| Classification (rules) | SSH Brute Force 10, BENIGN 6, RCE 3, Port Scan 2, unclassified 1 | SSH Brute Force 9, SSH Intrusion 5, BENIGN 3, RCE 2 | SSH Intrusion 5, RCE 2, SSH Brute Force 2 | SSH Intrusion 3, RCE 1 | — |
| Sessions with ≥ 1 MITRE technique | 9 | 5 | 2 | 1 | 17 / 54 |
| Closure analysis completed | 21 / 22 | 19 / 19 | 9 / 9 | 4 / 4 | **53 / 54 (98.1%)** |
| Closure-analysis time, p50 / p95 (ms) | 67 / 425 | 87 / 519 | 73 / 195 | 320 / 880 | — |

| Metric | Value | Source |
|---|---|---|
| Honeypot ingestion latency (Cowrie log line → stored in MongoDB) | **144–490 ms, median 320 ms** (19 commands; the parser restart test is excluded) | `docs/HONEYPOT_LIVE_EVIDENCE.md` (existing) |
| Distinct MITRE techniques observed in sessions | 12 (T1003, T1003.008, T1033, T1053, T1057, T1082, T1105, T1222.002, T1543, T1548, T1552.001, T1595) | `db_metrics.json` |
| Persona changes applied by the rotator | 1 (centos_7 → ubuntu_22, live run) | `HONEYPOT_LIVE_EVIDENCE.md` |
| Sessions by served persona | centos_7 29, ubuntu_22 24, unknown 1 | `db_metrics.json` |

All of these are **functional verification** numbers. They show that the pipeline captures, classifies, maps and stores sessions correctly. They say nothing about real attacker behaviour.

---

## 5. Reinforcement learning (Q-learning deception)

| Item | Value | Source |
|---|---|---|
| States × actions | 6 × 6 = 36 Q-values (personas). 5 personas are servable; `windows_srv` is excluded | `rl_engine/deception_scorer.py` |
| Hyperparameters | α 0.1, γ 0.9, ε 0.2 decaying to a floor of 0.05; reward bounded to [−10, 20]; −5 penalty for fingerprinting commands | same |
| Formulation | The next state is the persona just served, so in effect this is a **contextual bandit over personas** | `PAPER_CORRECTIONS.md` §4 |
| Seed Q-table updates | 12,087 episodes, cumulative reward 121,458.32 (mean 10.05 per episode) | `ai-engine/models/q_table.json` |
| Nature of those episodes | **Synthetic/scripted warm start.** The last 100 rewards repeat the pattern 10.62, 19.73, 10.62 | same |
| Updates from real Cowrie sessions | 12 (live run) | `HONEYPOT_LIVE_EVIDENCE.md` |
| Runtime table in the repo (`ai-engine/runtime/q_table.json`) | 99 episodes, all Q-values 0, empty reward history (a test artifact) | file |
| Persona selection in verification runs | served: centos_7 29, ubuntu_22 24; recommended: mostly the other persona | `db_metrics.json` |
| Session Q-deception score (verification DBs) | mean 8.8–17.7 per DB; this is a reward-derived score, not an outcome measure | `db_metrics.json` |
| Convergence (mean \|TD error\| over the last 100 updates) | **NOT MEASURED** on real data (fewer than 100 real updates exist) | — |
| Comparison with a fixed or random persona baseline | **NOT MEASURED** | — |
| Engagement duration by persona | Recorded (for example, cowrie-verify centos_7 mean 12.9 s, n = 9; ubuntu_22 mean 2.0 s, n = 10). **Not interpretable**: the sessions are scripted test clients, not attackers | `db_metrics.json` |

**Verdict.** There is **no evidence** of RL policy improvement or convergence on real attacker data. The 12 real updates are not enough to support such a claim, and no baseline comparison exists. The RL component also has **no connection to detection accuracy**. Defensible claim: *"A tabular Q-learning recommender is implemented and integrated end to end, and was exercised on local test sessions. Its effect on attacker engagement is not yet measured."*

---

## 6. Autonomous response and containment

| Metric | Value | Source |
|---|---|---|
| Containment actions recorded (all local DBs) | 8: runbook-verify 6 (AI Auto-Block), sentinelai_test 2 (manual) | `db_metrics.json` |
| Policy decisions | 8 ALLOWED, 0 rejected (in DB records). Rejections are exercised only in unit tests (`containmentPolicy.test.js`, `containmentProtectedTargets.test.js`) | same |
| Enforcement backend | **8 / 8 `mock`** | same |
| Successful vs failed actions | 8 ACTIVE, 0 failed | same |
| Request → applied latency | p50 12 ms (10–17 ms, n = 6, runbook); 11–15 ms (n = 2, test) | same |
| Adapter execution time | 0 ms. The mock adapter does nothing | same |
| Auto-block trigger count | 11 ThreatLogs with `autonomousAction.taken` (runbook-verify), 1 (sentinelai_test); 6 + 3 BlockedIP rows | same |
| Threat → auto-block time | Recorded values range from −1 ms to 62.8 s. The procedure of that run is not documented, so I do **not** use them as decision latency | same |
| Rollbacks performed | 0 recorded in any DB. Rollback is covered only by unit tests | same |
| Incorrect containment decisions | **NOT MEASURABLE**. No ground truth; all targets were TEST-NET addresses | — |
| Real OS/network firewall enforcement | **Never executed.** `WindowsFirewallAdapter` exists but needs `CONTAINMENT_BACKEND=windows-firewall` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true`; `scripts/run-vm-firewall-tests.ps1` has never been run | `audit/REPORT.md` F4 |
| Application-level enforcement | The Cowrie deny-list plugin refused one connection in the live run, with the deny-list served from a local stub | `HONEYPOT_LIVE_EVIDENCE.md` |
| Auto-block in the benchmark | Off (default), so no containment happened in the bench DB | `e2e_db_latency.json` (`containmentactions: 0`) |

**What may be claimed:** "a policy-checked containment workflow with a pluggable adapter, demonstrated with a mock adapter (deny-list records only)". **What may not be claimed:** that any IP was blocked at the network or OS level.

---

## 7. System performance (local benchmark)

Conditions: everything ran on the hardware in §0, on loopback, with sequential requests unless stated. The AI engine was started with `uvicorn` (1 worker, no reload). The backend used the `node server.js` defaults and the isolated DB. Two full runs were made, about 10 minutes apart; values are given as run 1 / run 2.

Sources: `raw/api_bench.json`, `raw/api_bench_run2.json`, `raw/e2e_db_latency.json`, `raw/resources_summary.json`.

| Endpoint | n | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) | Errors |
|---|---|---|---|---|---|---|
| AI engine `GET /health` | 300 | 22.2 / 31.1 | 16.2 / 12.0 | 37.1 / 56.9 | 112 / 130 | 0 |
| AI engine `POST /predict/eval` | 300 | 50.0 / 50.5 | **35.6 / 41.4** | 95.5 / 92.8 | 271 / 282 | 0 |
| AI engine `POST /predict/eval?explain=true` (SHAP) | 100 | 117.9 / 104.9 | 74.4 / 78.1 | 328 / 358 | 400 / 421 | 0 |
| AI engine `/predict/eval`, 8 concurrent clients | 1,000 | 452 / 451 | 375 / 399 | 696 / 732 | 2,758 / 1,906 | 0 |
| Backend `GET /health` | 300 | 47.7 / 41.6 | 27.5 / 30.4 | 104 / 108 | 299 / 189 | 0 |
| Backend `GET /api/threats` (authenticated, MongoDB) | 200 | 48.5 / 47.9 | 36.4 / 33.7 | 128 / 127 | 236 / 258 | 0 |
| Backend `POST /api/ai/analyze` (full pipeline) | 120 | 98.0 / 98.3 | **83.1 / 82.2** | 253 / 246 | 367 / 366 | 0 |
| Flow sent → ThreatLog stored (end to end) | 56 | 75.4 | **65** | 123 | 204 | — |

| Metric | Value |
|---|---|
| Requests per second | 17.6 / 17.7 req/s (`/predict/eval`, 8 concurrent clients) |
| API error rate | **0%** (0 errors in 2 × 2,320 requests) |
| MongoDB query latency, measured from mongosh on the same host (bench DB, ≤ 206 docs) | ThreatLogs recent 20: p50 2 ms, p95 4 ms · ThreatLogs by severity aggregation: p50 3 ms, p95 10 ms · AIPredictions recent 50: p50 7 ms, p95 16 ms · HoneypotSessions recent 20: p50 7 ms, p95 16 ms (n = 200 each) |
| Backend startup to `/health` | 3.4 s |
| AI engine CPU (% of 16 logical CPUs, 1 sample/s) | mean 12.6%, p95 21.2%, max 23.9% |
| Backend CPU | mean 1.1%, max 6.3% |
| AI engine memory (committed private bytes) | **≈ 1,190–1,211 MB** |
| Backend memory (private bytes) | 111–194 MB |
| MongoDB memory (private bytes) | ≈ 200 MB. CPU could not be read without elevation |
| Frontend production build | Succeeds in 67 s; output 905 KB. Largest chunks: chart library 385.8 kB (106.0 kB gzip), app entry 235.3 kB (76.8 kB gzip) |
| Frontend runtime metrics (load time, Lighthouse) | **NOT MEASURED** |
| Socket.IO push latency to the dashboard | **NOT MEASURED** |

The working-set figures in `resources.csv` understate memory, because Windows trims process working sets. That is why the private-bytes figures are the ones reported.

---

## 8. Software quality and reliability

| Metric | Value | Source |
|---|---|---|
| Backend (Jest), suites | 75 total: 71 passed, 4 skipped | `raw/backend_jest.json` |
| Backend tests | **1,141 total: 1,128 passed, 0 failed, 13 skipped** | same |
| AI engine (pytest) | **594 passed, 0 failed** (259 s) | `raw/ai_pytest.xml`, `ai_pytest.log` |
| Frontend (`node --test`) | **49 passed, 0 failed** | `raw/frontend_test.log` |
| **Total automated tests** | **1,784: 1,771 passed, 0 failed, 13 skipped**. Pass rate 100% of executed tests (99.3% including skipped) | — |
| Skipped tests | 13. These suites need `AUTH_TEST_MONGO_URI` (auth persistence/browser tests) | `backend/tests/authPersistence.test.js`, `authBrowser.test.js` |
| Backend code coverage | Lines **81.04%**, statements 79.23%, branches 71.62%, functions 76.13% | `raw/backend_coverage/coverage-summary.json` |
| Lowest-covered backend files | `containmentController.js` 46%, `adapterInterface.js` 17%, `transactionHelper.js` 57%, `trainingSampleService.js` 64%, `threatService.js` 66%; `seed.js`/`clean.js` 0% | same |
| AI engine code coverage | **NOT MEASURED** (`pytest-cov` is not installed in the venv) | — |
| Frontend E2E (Playwright, 17 files in `frontend/e2e`) | **NOT RUN** in this audit | — |
| Endpoint availability during the benchmark | 100% (0 failed requests in 4,640) | §7 |
| Health checks | AI engine `/ready` → `{"status":"ok"}`; backend `/health` → `{"status":"ok"}` | benchmark |
| npm audit, backend | All dependencies: 23 (19 moderate, 4 high). **Production only: 1 high** (`follow-redirects`) | `raw/npm_audit_backend*.json` |
| npm audit, frontend | All dependencies: 15 (5 moderate, 10 high). **Production only: 4** (2 moderate; 2 high: `axios`, `follow-redirects`) | `raw/npm_audit_frontend*.json` |
| Python dependency scan | **NOT MEASURED** (`pip-audit` is not installed) | — |

**Areas without real integration coverage** (`audit/REPORT.md` TEST-003, confirmed by inspection):
- No CI job runs Express ↔ FastAPI ↔ MongoDB together.
- The firewall is tested only for refusal.
- Cowrie is tested only against offline contracts.
- The RL learner is tested only with synthetic sessions.

---

## 9. Charts

All charts are generated by `metrics_report/scripts/make_charts.py`, only from the JSON files named in each chart's footnote.

| File | Shows |
|---|---|
| `charts/01_model_comparison_chronological.png` | Accuracy, precision, recall and F1 for the classifier alone, the IF alone and the combined system (Protocol B) |
| `charts/02_confusion_matrix_chronological.png` | Confusion matrix (counts) |
| `charts/03_attack_category_detection.png` | Recall and alert rate per attack category, with sample sizes |
| `charts/04_split_protocol_comparison.png` | Random vs chronological vs unseen-day results |
| `charts/05_latency.png` | p50 and p95 for each endpoint, both runs, plus end-to-end latency |
| `charts/06_honeypot_sessions.png` | Cowrie verification sessions by classification and database |
| `charts/07_resource_usage.png` | CPU and private memory of the engine and backend |
| *(none)* RL reward progression | **Not drawn on purpose.** The only reward history is the synthetic seed; plotting it would look like learning that never happened |

---

## B. Master metrics table

Status key: **MEASURED** = reproduced in this audit · **EXISTING** = found in earlier evidence · **NOT MEASURED** · **N/A**

| Component | Metric | Measured value | Test conditions | Evidence | Status |
|---|---|---|---|---|---|
| ML | Accuracy (multiclass) | 98.91% | XGB recipe, chronological, 184,280 flows | raw/ml_eval.json B | MEASURED |
| ML | Accuracy (multiclass) | 98.97% | served artifact, random de-duplicated 80/20, 24,907 flows | raw/ml_eval.json A | MEASURED |
| ML | Macro F1 | 0.772 (chrono) / 0.874 (random) | as above | ml_eval.json | MEASURED |
| ML | Weighted F1 | 0.990 / 0.991 | as above | ml_eval.json | MEASURED |
| ML | Precision, deployed alert | 98.87% | chrono, alert ≥ 0.90 | ml_eval.json B | MEASURED |
| ML | Recall / detection rate, deployed alert | 91.13% | same | ml_eval.json B | MEASURED |
| ML | F1, deployed alert | 94.84% | same | ml_eval.json B | MEASURED |
| ML | FPR, deployed alert | 0.159% [0.140, 0.180] | same, 160,000 benign | ml_eval.json B | MEASURED |
| ML | FNR, deployed alert | 8.87% | same | ml_eval.json B | MEASURED |
| ML | Classifier-alone P / R / F1 / FPR | 97.66% / 96.96% / 97.31% / 0.353% | chrono | ml_eval.json B | MEASURED |
| ML | IF-alone P / R / F1 / FPR | 69.40% / 29.59% / 41.49% / 1.98% | chrono | ml_eval.json B | MEASURED |
| ML | ROC-AUC (binary) | classifier 0.9985 · IF 0.8464 · combined 0.9979 | chrono | ml_eval.json B | MEASURED |
| ML | PR-AUC (binary) | classifier 0.9937 · IF 0.4543 · combined 0.9901 | chrono | ml_eval.json B | MEASURED |
| ML | Macro OvR ROC-AUC (multiclass) | 0.9988 | chrono | ml_eval.json B | MEASURED |
| ML | Confusion matrix | §2.3 table | chrono | ml_eval.json B | MEASURED |
| ML | Per-class P/R/F1/support | §2.3 table | chrono | ml_eval.json B | MEASURED |
| ML | Unseen-day attack detection | Tue 0.2%, Wed 6.9%, Thu 80.2%, Fri 10.3% | leave-one-day-out | experiments/m5_xgboost_eval/results.json | EXISTING |
| ML | RF v3 chrono macro F1 / detection | 0.750 / 78.6% | chrono, threshold validation | docs/PAPER_CORRECTIONS.md | EXISTING |
| ML | Inference time (in process) | p50 18.0 ms, p95 41.3 ms | 1 flow, quiet machine, n = 1,000 | raw/model_latency_quiet.json | MEASURED |
| ML | Batch inference throughput | 27,465 flows/s | 20,000 rows | raw/model_latency_quiet.json | MEASURED |
| ML | Model load time | 0.49–0.85 s unpickle; 10.8–12.4 s cold incl. imports | warm / fresh interpreter | ml_eval.json, model_latency_quiet.json | MEASURED |
| ML | Model size | XGB 3.33 MB, IF 1.33 MB | files | ml_eval.json | MEASURED |
| ML | Training time | 97.3 s (XGB + IF, 150,309 rows) | 1 run, concurrent load | ml_eval.json B | MEASURED (indicative) |
| ML | Duplicate rows removed | 628,877 (22.2%) | full dataset | ml_eval.json B | MEASURED |
| ML | Seed variance | — | — | — | NOT MEASURED |
| Detection | Replay attack flows classified as attack (backend) | 60/60; 56 alerts | 120 curated CICIDS rows, bench DB | raw/api_bench.json | MEASURED (demo, not independent) |
| Detection | Alert-generation latency | p50 65 ms, p95 123 ms | sent → ThreatLog stored, n = 56 | raw/e2e_db_latency.json | MEASURED |
| Detection | HTTP detection throughput | 17.6–17.7 req/s | 8 concurrent clients | api_bench*.json | MEASURED |
| Detection | Alert severity distribution | CRITICAL 22,220 / HIGH 161 | chrono alerts | ml_eval.json B | MEASURED |
| Detection | MITRE mapping coverage | 11/11 classes; 32 technique IDs | static | backend/utils/mitreMapping.js | MEASURED |
| Detection | Live-network detection | — | no packet capture exists | — | N/A |
| Honeypot | Sessions (Cowrie verification) | 54 (44 Cowrie + 10 injected) | local test clients | raw/db_metrics.json | MEASURED |
| Honeypot | Unique real client hosts | 2 | same | db_metrics.json | MEASURED |
| Honeypot | Login attempts, success / fail | 64: 21 / 43 (includes the 10 injected sessions) | same | db_metrics.json | MEASURED |
| Honeypot | Commands executed | 86 | same | db_metrics.json | MEASURED |
| Honeypot | Max session duration | 120 s for Cowrie sessions (284 s if the injected sessions are included) | same | db_metrics.json | MEASURED |
| Honeypot | IOCs captured | 7 IPs, 7 URLs, 2 hashes | same | db_metrics.json | MEASURED |
| Honeypot | Ingestion latency | 144–490 ms, median 320 ms | live Cowrie run, 19 commands | docs/HONEYPOT_LIVE_EVIDENCE.md | EXISTING |
| Honeypot | Session processing success | 53/54 (98.1%) | closure analysis complete | db_metrics.json | MEASURED |
| Honeypot | Persona changes applied | 1 | live run | HONEYPOT_LIVE_EVIDENCE.md | EXISTING |
| Honeypot | Real-attacker statistics | — | no internet-facing deployment | — | NOT MEASURED |
| RL | States / actions | 6 / 6 (5 servable) | code | rl_engine/deception_scorer.py | MEASURED |
| RL | Training updates | 12,087 synthetic + 12 real | seed file + live run | q_table.json; HONEYPOT_LIVE_EVIDENCE.md | EXISTING |
| RL | Mean reward per episode (seed) | 10.05 | synthetic | q_table.json | EXISTING (synthetic) |
| RL | Improvement / convergence / vs baseline | — | — | — | NOT MEASURED |
| Containment | Actions / allowed / rejected | 8 / 8 / 0 | test and runbook DBs | db_metrics.json | MEASURED |
| Containment | Enforcement backend | 8/8 mock | same | db_metrics.json | MEASURED |
| Containment | Request → applied latency | p50 12 ms (10–17) | mock adapter, n = 6 | db_metrics.json | MEASURED |
| Containment | Rollback success rate | — | 0 rollbacks recorded | — | NOT MEASURED |
| Containment | Real firewall enforcement | never executed | — | audit/REPORT.md | NOT MEASURED |
| System | AI `/predict/eval` latency | p50 35.6–41.4 ms, p95 92.8–95.5 ms | sequential, n = 300 × 2 | api_bench*.json | MEASURED |
| System | SHAP explanation latency | p50 74–78 ms, p95 328–358 ms | n = 100 × 2 | api_bench*.json | MEASURED |
| System | Backend analyze latency | p50 82–83 ms, p95 246–253 ms | n = 120 × 2 | api_bench*.json | MEASURED |
| System | Backend threats list | p50 34–36 ms, p95 127–128 ms | n = 200 × 2 | api_bench*.json | MEASURED |
| System | MongoDB query | p50 2–7 ms | mongosh, bench DB | e2e_db_latency.json | MEASURED |
| System | API error rate | 0% | 4,640 requests | api_bench*.json | MEASURED |
| System | CPU (engine / backend) | mean 12.6% / 1.1%; max 23.9% / 6.3% | 1 Hz sampling | resources_summary.json | MEASURED |
| System | Memory (engine / backend / mongod) | ≈ 1.2 GB / 111–194 MB / ≈ 200 MB | private bytes | resources_summary.json | MEASURED |
| System | Socket.IO push latency | — | — | — | NOT MEASURED |
| System | Frontend load / render time | — | — | — | NOT MEASURED |
| Quality | Tests passed / failed / skipped | 1,771 / 0 / 13 | 3 suites | raw/*jest*, ai_pytest.xml, frontend_test.log | MEASURED |
| Quality | Backend line coverage | 81.04% | Jest | backend_coverage | MEASURED |
| Quality | AI-engine coverage | — | pytest-cov missing | — | NOT MEASURED |
| Quality | Prod dependency vulns (high) | backend 1, frontend 2 | npm audit --omit=dev | raw/npm_audit_*_prod.json | MEASURED |
| Quality | E2E UI tests | — | not run | — | NOT MEASURED |

---

## C. Presentation metrics (poster / slides)

Use only these, and keep the qualifier that goes with each one.

1. **98.9% accuracy, macro F1 0.77** on a *chronological* CICIDS2017 test: 184,280 flows the model never trained on, all later in time than its training data.
2. **91.1% of attack flows raise an alert at a 0.16% benign alert rate** (24,280 attack and 160,000 benign test flows).
3. **ROC-AUC 0.998** for attack-vs-benign (XGBoost classifier, chronological test).
4. **2.83 million flows processed; 22.2% exact duplicates removed** before any train/test split, so the scores are not inflated by duplicates.
5. **10 attack categories**; SSH brute force is detected at 99.7% recall and DDoS at 94.6% (chronological).
6. **18 ms median model inference per flow; 27,000+ flows/s in batch** (laptop CPU).
7. **65 ms median from a flow arriving to a stored, MITRE-tagged alert** (p95 123 ms; local stack, n = 56).
8. **0 errors in 4,640 API requests** across two benchmark runs.
9. **1,771 automated tests passing, 0 failing**; 81% backend line coverage.
10. **Compact models:** 3.3 MB classifier + 1.3 MB anomaly detector, pinned by SHA-256 in a model registry.
11. **Cowrie honeypot pipeline verified:** 44 real Cowrie sessions processed, 98% fully analysed, median 320 ms from log line to database (local test clients).
12. **32 MITRE ATT&CK techniques mapped**; all 11 threat classes are covered.
13. **Honest-evaluation panel (recommended):** random split macro F1 0.87 → chronological 0.77 → unseen capture day 0.20–0.31. This shows you measured generalisation instead of hiding it.

**Do not put on the poster:** "zero-day detection", "RL improves engagement", "autonomous firewall blocking", "sub-100 ms response" as an absolute claim (the p95 is above 100 ms), or any number from `sentinel-db` (seeded data).

---

## D. Draft IEEE results section

### VII. Experimental Evaluation

**A. Setup.** All experiments ran on a single laptop: Intel Core i5-12500H (16 logical CPUs), 7.7 GB RAM, Windows 11, Python 3.11.9, scikit-learn 1.4.0, XGBoost 2.0.3, Node.js 24, MongoDB, all services on loopback. We use the eight CICIDS2017 MachineLearningCVE files (2,827,876 flows after removing non-finite rows) and represent each flow with 53 features. Because 22.2% of flows are exact duplicates, and 98.8% of PortScan flows are, we remove duplicates before splitting, keeping the earliest copy. The detector is an XGBoost classifier (200 trees, depth 6, learning rate 0.1) with a benign-only Isolation Forest (200 trees). An alert is raised when the threat score, max(p, 0.7p + 0.3·s_IF) for attack classes, reaches 0.90. That line was selected on a chronological validation split for a ≤ 0.1% benign alert rate.

**B. Protocols.** We report three protocols:
- (i) a stratified random 80/20 row split, the split the deployed model was trained with;
- (ii) a chronological split inside every (capture file, class): the first 70% for training, a 1% purge gap, and the last 29% for testing (150,309 training and 184,280 test flows after per-file caps);
- (iii) leave-one-capture-day-out.

Protocol (ii) is our primary estimate. Random row splits on CICIDS2017 place flows of the same attack burst on both sides of the split.

**C. Detection results.** Under the chronological protocol the classifier reaches 98.91% accuracy, 0.990 weighted F1 and 0.772 macro F1 (Table V). For attack-vs-benign detection, the deployed alert rule reaches 98.87% precision, 91.13% recall and 94.84% F1, with a benign false-alarm rate of 0.159% (95% Wilson CI 0.140–0.180%) and ROC-AUC 0.998. The random split gives 98.97% accuracy and 0.874 macro F1. The 10-point drop in macro F1 under the chronological split comes mainly from the rare web-attack classes. XSS (F1 0.48) is confused with HTTP brute force, because both target the same web application. SQL injection, RCE (Heartbleed) and lateral movement have only 7, 4 and 11 test flows, so their per-class figures are not statistically meaningful.

**D. Ablation: supervised vs anomaly detection.** On the same chronological test the Isolation Forest alone detects 29.6% of attacks at a 1.98% false-positive rate (ROC-AUC 0.846). The classifier alone detects 96.96% at 0.353%. Taking the union of both raises recall by only 0.7 points while multiplying false positives by 6.6. The deployed rule uses the anomaly signal only to raise the confidence of classifier-detected attacks. It halves the false-alarm rate relative to the classifier alone (0.159% vs 0.353%), at a cost of 5.8 points of recall.

**E. Generalisation.** When a whole capture day is held out, attacks from that day are largely missed: alert rates are 0.2% (Tuesday), 6.9% (Wednesday), 10.3% (Friday) and 80.2% (Thursday), and macro F1 is 0.20–0.31. The detector should therefore be understood as recognising known attack types under similar network conditions, not as detecting novel attacks.

**F. System performance.** In process, scoring one flow (classifier + Isolation Forest) takes a median of 18.0 ms (p95 41.3 ms), and batch scoring sustains 27,465 flows/s. Through the REST API, the median latency is 35.6–41.4 ms, and 74–78 ms with SHAP explanations. Through the full backend pipeline it is 82–83 ms; that pipeline authenticates, scores, stores the prediction, creates a MITRE-tagged threat record and emits a dashboard event. From a flow being submitted to its threat record being stored took a median of 65 ms (p95 123 ms, n = 56). No request failed in 4,640 benchmark requests. With 8 concurrent clients, API throughput was 17.6 requests/s, below the in-process rate, which points to a serving-layer bottleneck that we leave to future work.

**G. Honeypot and deception.** A Cowrie SSH honeypot was connected through the log parser to the backend and exercised with local SSH clients. 44 Cowrie sessions (plus 10 injected test sessions) were captured; 53 of 54 completed automated closure analysis. Log-to-database latency had a median of 320 ms (range 144–490 ms). The Q-learning persona recommender was integrated and applied one persona change on the live honeypot. Its effect on attacker engagement was not evaluated, because no internet-facing deployment or static-persona baseline was run.

**H. Limitations.**
1. A single dataset (CICIDS2017), with no cross-dataset test.
2. A single random seed.
3. Row order is used as a time proxy.
4. Three classes have fewer than 30 test flows, and one class has no data.
5. Latency was measured on one laptop with all components co-located.
6. Containment was exercised only with a mock adapter; no OS firewall rule was applied.
7. Honeypot and RL results come from local test traffic, not real attackers.

**I. Conclusion.** On later, unseen traffic of known attack types, SentinelAI's detector raises alerts for 91% of attack flows at a 0.16% false-alarm rate, with sub-100 ms median end-to-end processing on commodity hardware. It does not generalise to attack campaigns absent from training, and the adaptive deception and autonomous containment components are functional prototypes whose effectiveness remains to be measured.

**Table V.** *Chronological CICIDS2017 test (184,280 flows).*

| System | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|
| Isolation Forest | 69.40 | 29.59 | 41.49 | 1.980 | 0.846 |
| XGBoost | 97.66 | 96.96 | 97.31 | 0.353 | 0.999 |
| SentinelAI (combined, τ = 0.90) | **98.87** | 91.13 | 94.84 | **0.159** | 0.998 |

---

## E. Viva preparation

For each metric: **what it means**, **how it was computed**, **why it matters**, **what your result shows**, **what to disclose**.

**Accuracy (98.91%).**
- Meaning: the share of all flows given the right class.
- Computed as: correct predictions ÷ all predictions on the chronological test.
- Why it matters: it is the first number anyone asks for.
- Your result: high.
- Disclose: 87% of the test set is benign, so a model that always answered "benign" would already score 86.8%. Point the examiner to macro F1 and recall instead.

**Precision (98.87% for alerts).**
- Meaning: of the flows we alerted on, how many really were attacks.
- Computed as: TP ÷ (TP + FP) = 22,127 ÷ 22,381.
- Why it matters: low precision floods analysts with false alarms.
- Your result: about 1 alert in 88 is a false alarm.
- Disclose: precision depends on the ratio of attacks to benign traffic. Real networks have far fewer attacks than this test set, so real-world precision would be lower.

**Recall / detection rate (91.13%).**
- Meaning: of the real attacks, how many we caught.
- Computed as: TP ÷ (TP + FN) = 22,127 ÷ 24,280.
- Why it matters: missed attacks are the costly error.
- Your result: about 9 in 100 attack flows are missed, mostly DDoS flows scored below the alert line.
- Disclose: recall is per flow, not per attack campaign, and it applies only to attack types seen in training.

**F1 (94.84%).**
- Meaning: the harmonic mean of precision and recall; one number that punishes being bad at either.
- Why it matters: it balances the two error types.

**Macro F1 (0.772).**
- Meaning: F1 averaged over classes, each class counting equally.
- Why it matters: it exposes weak rare classes that accuracy hides.
- Your result: strong on frequent classes, weak on XSS and SQLi.
- Disclose: 3 classes have fewer than 30 test samples.

**False-positive rate (0.159%).**
- Meaning: the share of benign flows that wrongly raise an alert.
- Computed as: FP ÷ (FP + TN) = 254 ÷ 160,000. The 95% Wilson confidence interval is 0.140–0.180%.
- Why it matters: SOC alert fatigue.
- Disclose: at a million benign flows a day, this would still be about 1,600 false alerts.

**False-negative rate (8.87%).**
- Meaning: 1 − recall, the share of attacks missed.

**ROC-AUC (0.998) and PR-AUC (0.990).**
- Meaning: how well the score ranks attacks above benign flows across all thresholds. 1.0 is perfect; 0.5 is random.
- Why both: PR-AUC is more honest when classes are imbalanced.
- Your result: the classifier ranks almost perfectly, while the Isolation Forest is much weaker (0.846 / 0.454).
- Disclose: AUC is threshold-free, but the deployed system uses one fixed threshold.

**Confusion matrix.**
- Meaning: a table of true class vs predicted class.
- Your result: the main errors are XSS ↔ Credential Stuffing (both HTTP attacks on the same web app) and 651 DDoS flows labelled benign.

**Random vs chronological vs leave-one-day-out.**
- What they are: three ways to split data for testing.
- Why it matters: a random split lets near-identical flows from one attack burst appear in both training and test, which inflates the score. A chronological split tests on later traffic. Leave-one-day-out tests on attack campaigns never seen.
- Your result: macro F1 0.874 → 0.772 → 0.20–0.31.
- If asked "so does it detect zero-days?", answer **no**, and that you measured this.

**Isolation Forest vs combined.**
- Meaning: an unsupervised anomaly detector trained only on benign traffic.
- Your result: on its own it catches 30% of attacks. In SentinelAI it only *boosts* confidence for attacks the classifier already found, which cuts false alarms in half.
- Disclose: it does not add detection of new attacks.

**Inference latency (18 ms median in process; 36–41 ms via API; 65 ms to a stored alert).**
- Computed as: wall-clock time over 1,000 / 300 / 56 real flows, reported as median and 95th percentile.
- Why percentiles: averages hide slow outliers.
- Disclose: one laptop, everything on localhost, no network hops; the p95 is above 100 ms.

**Throughput (27,465 flows/s batch; 17.6 req/s over HTTP with 8 clients).**
- Your result: the model is fast, but the web-serving layer is the bottleneck. This is a known improvement item.

**Tests (1,771 passed, 0 failed) and coverage (81%).**
- Coverage means the share of backend code lines executed by tests.
- Disclose: the tests mostly mock other services. No automated test runs the full stack together, and there is no AI-engine coverage figure.

**Honeypot numbers (44 Cowrie sessions, 320 ms ingest).**
- Meaning: they prove the capture → classify → store pipeline works.
- Disclose: the sessions came from your own SSH test clients, not attackers. Session classification is rule-based, not ML.

**RL.**
- What exists: a 6 × 6 Q-table that learns which persona to serve next; the reward favours longer, deeper sessions and penalises honeypot-detection commands.
- Disclose: the starting table is synthetic (12,087 scripted episodes); only 12 real updates exist; no comparison with a fixed persona was run. Say: "implemented and integrated; not yet evaluated."

**Containment.**
- What exists: a policy check plus an adapter.
- Disclose: every recorded action used the mock adapter. No firewall rule was ever applied, and auto-block is off by default. Say "simulated enforcement".

**Questions you should expect:**
- "Why is accuracy so high but macro F1 lower?" Class imbalance and rare classes.
- "Is there data leakage?" Duplicates were removed (0.06% residual identical vectors, all with conflicting labels). The chronological split prevents burst leakage, and the threshold was chosen on validation data, not test data.
- "Why XGBoost over Random Forest?" On the chronological protocol it detects 91.0% vs 78.6% of attacks at a similar false-alarm rate.

---

## F. Missing metrics and how to obtain them

Run all commands from the repository root unless a different directory is given. None of them changes production models.

| # | Missing metric | Procedure |
|---|---|---|
| 1 | **AI-engine code coverage** | `ai-engine\.venv\Scripts\pip install pytest-cov` (adds a dev dependency to the venv), then `cd ai-engine && .venv\Scripts\python -m pytest --cov=inference --cov=rl_engine --cov=utils --cov=training --cov-report=term` |
| 2 | **Frontend E2E pass rate** | `cd frontend && npx playwright test` (needs the backend, AI engine and a seeded test DB; see `frontend/e2e/global-setup.js`) |
| 3 | **Seed variance / confidence across runs** | Run `ai-engine/evaluation/day_holdout_eval.py --classifier xgboost --protocols temporal` with several seeds. The seed is fixed at 42 in `XGB_PARAMS`/`cap`, so add a `--seed` flag in a copy of the script; report mean ± std over at least 5 seeds |
| 4 | **XGBoost vs RF significance** | McNemar's test on the paired chronological predictions (both models scored on the same test rows inside `day_holdout_eval.py`) |
| 5 | **Cross-dataset generalisation** | Score the served recipe on CSE-CIC-IDS2018. Candidates and loaders exist under `ai-engine/experiments/gate1_phase7_cse2018_validation/`; I did not review them in this audit |
| 6 | **Re-validated alert line for XGBoost** | `cd ai-engine && .venv\Scripts\python evaluation/day_holdout_eval.py --classifier xgboost --protocols threshold --out experiments/metrics_threshold_xgb`. The existing run picks 0.87; decide whether to keep 0.90 |
| 7 | **Real attacker honeypot statistics** | Deploy Cowrie on an isolated, internet-facing VM (never on the dev machine), using `honeypot/docker-compose.honeypot.yml` and `redirect-ssh-port.sh`, for ≥ 2 weeks, then rerun `mongosh --quiet mongodb://HOST/DB metrics_report/scripts/db_metrics.js` |
| 8 | **RL vs baseline (engagement)** | On that deployment, alternate weeks (or randomise per session) between `DECEPTION_POLICY=q_learning` with the rotator on, and a fixed persona. Compare mean session duration, commands per session and fingerprint rate with a Mann-Whitney U test. You need hundreds of sessions per arm. Also log `learnerStats.convergence` |
| 9 | **Real firewall enforcement and rollback** | Only on a disposable Windows VM: `powershell -File scripts\run-vm-firewall-tests.ps1` with `CONTAINMENT_BACKEND=windows-firewall` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true`. Record `netsh` output, apply latency, rollback success, and verify blocking with a connection attempt from the blocked IP |
| 10 | **Containment rollback latency (mock)** | Against the bench DB, call the containment API to apply and then roll back actions on TEST-NET IPs (`backend/routes/containment.js`); time both calls |
| 11 | **Socket.IO push latency** | A small `socket.io-client` script (already in `frontend/node_modules`) subscribed to the dashboard events while `api_bench.py` runs; measure from POST to receipt |
| 12 | **Frontend performance** | `npx lighthouse http://localhost:3000/login --output json`, or Chrome DevTools performance traces of the dashboard |
| 13 | **Python dependency vulnerabilities** | `pip install pip-audit` (outside the project venv), then `pip-audit -r ai-engine/requirements.txt` |
| 14 | **MongoDB CPU** | Rerun `metrics_report/scripts/sample_resources.ps1` from an elevated PowerShell |
| 15 | **Serving throughput fix check** | Rerun `api_bench.py` with uvicorn `--workers 2` or `OMP_NUM_THREADS=1`, and compare req/s |

### Reproducing this audit

```bash
ai-engine/.venv/Scripts/python.exe metrics_report/scripts/ml_eval.py
```
```bash
ai-engine/.venv/Scripts/python.exe metrics_report/scripts/model_latency.py
```
```bash
mongosh --quiet mongodb://localhost:27017 metrics_report/scripts/db_metrics.js > metrics_report/raw/db_metrics.json
```
```bash
cd backend && npx jest --runInBand --coverage --json --outputFile=../metrics_report/raw/backend_jest.json
```
```bash
cd ai-engine && .venv/Scripts/python.exe -m pytest -q --junitxml=../metrics_report/raw/ai_pytest.xml
```
```bash
cd frontend && node --test tests/*.test.mjs
```

For the latency benchmark:
1. Seed an isolated DB: `MONGO_URI=mongodb://127.0.0.1:27017/<new-db> ADMIN_INITIAL_PASSWORD=<test> ADMIN_EMAIL=<test> node utils/seed.js --confirm=<new-db>`.
2. Start the AI engine (`uvicorn inference.main:app --host 127.0.0.1 --port 8000 --env-file ../backend/.env`, with `Q_TABLE_PATH` pointing to a scratch copy).
3. Start the backend with that `MONGO_URI`.
4. Set `SENTINEL_KEY`, `BENCH_EMAIL` and `BENCH_PASSWORD`, then run `ai-engine/.venv/Scripts/python.exe metrics_report/scripts/api_bench.py`.
5. Run `mongosh --quiet mongodb://127.0.0.1:27017/<new-db> metrics_report/scripts/e2e_and_db_latency.js`.
6. Run `python metrics_report/scripts/make_charts.py`.

### Housekeeping

The benchmark database `sentinel-metrics-bench-20261023` still exists. It holds only the seed data and benchmark records. Drop it when you no longer need it.
