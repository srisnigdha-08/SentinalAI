# Reference Repository Inventory & Technical Evaluation

**Date Inspected:** 2026-10-18  
**Audit Phase:** GATE-1 Phase 14 — Read-Only Reference-Guided Root-Cause Audit  
**Auditor Role:** Senior ML Evaluation Engineer & Security Code Reviewer  

---

## 1. Executive Summary

Four public reference repositories addressing intrusion detection, temporal stability, explainability, and multi-corpus evaluation on CIC-IDS2017 and CSE-CIC-IDS2018 were cloned, inspected at the source-code level, and evaluated against SentinelAI's GATE-1 acceptance criteria:

1. **`Vabnas/cicids-shap-stability`** (Commit: `9f7871c801f390348246ad9f14f7f89e8ed0fad7`, MIT License)
2. **`heraclitus0/TAD-IDS`** (Commit: `4586df5c25c37cf2d8fa02cda55803b5f47ab0a6`, MIT License)
3. **`LawrenceYH04/ML-IDS`** (Commit: `5a253fbbfb63c51d13827ddae99c620c30897b4a`, No License / All Rights Reserved)
4. **`YufengXin/network-attack-research`** (Commit: `106e39b289937e5c2a8703149bd5f49ad9c578b5`, No License / All Rights Reserved)

All repositories were cloned using shallow clones (`--depth 1`, `GIT_LFS_SKIP_SMUDGE=1`) into an isolated scratch area (`brain/scratch/repos/`). No untrusted code was executed in the SentinelAI production environment, no dependencies were installed, and no protected assets were modified.

---

## 2. Reference 1: `Vabnas/cicids-shap-stability`

### 2.1 Metadata & Provenance
- **URL:** `https://github.com/Vabnas/cicids-shap-stability`
- **Inspected Date:** 2026-10-18
- **HEAD Commit Hash:** `9f7871c801f390348246ad9f14f7f89e8ed0fad7`
- **Default Branch:** `main`
- **Repository Size:** ~47 KB (code and scripts only; datasets excluded)
- **License:** MIT License (Permissive open source; requires copyright notice and disclaimer preservation). Attribution required if code or logic is adapted.
- **Project Claim (from README):** Explainable AI (SHAP)-based analysis of network intrusion detection models with cross-model agreement, cross-dataset stability (2017 -> 2018), and data leakage evaluation. Highlights that CIC-IDS2017 contains ~21% exact duplicate rows causing ~23% test set leakage under naive splitting.

### 2.2 Key Files & Functions Examined
- [`check_data_validity.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/cicids-shap-stability/check_data_validity.py):
  - `check_duplicates(X, y)` (L30-48): Audits exact duplicate feature rows and differentiates true redundant flows from conflicting-label duplicates.
  - `check_split_leakage(X, y)` (L51-69): Hashes rows via `pd.util.hash_pandas_object(df, index=False)` and calculates the exact fraction of test rows present in the training partition.
  - `check_feature_leakage(X, y)` (L89-130): Evaluates single-feature directional AUC (`max(auc, 1 - auc)`) across classes to detect proxy labels (e.g., Destination Port).
- [`rq1_pipeline.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/cicids-shap-stability/rq1_pipeline.py):
  - `PHYSICAL_TIME_COLS` (L41-48): Defines timing columns where negative values are physically impossible (CICFlowMeter clock-desync defect: `Flow Duration`, `Fwd IAT Total`, `Bwd IAT Total`, `Flow IAT Mean`, `Fwd IAT Mean`, `Bwd IAT Mean`).
  - `clean(df, label_col, ...)` (L144-206): Explicitly drops non-feature identifiers: `Flow ID`, `Source IP`, `Src IP`, `Destination IP`, `Dst IP`, `Source Port`, `Src Port`, `Destination Port`, `Dst Port`, `Timestamp`, `Protocol`. Deduplicates exact rows before splitting (`X.duplicated(keep="first")`).
  - `stratified_splits(X, y)` (L208-220): Random stratified 70/15/15 split.
- [`rq3_cross_dataset.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/cicids-shap-stability/rq3_cross_dataset.py):
  - `normalize_feature_name(name)` (L51-107): Token-level abbreviation expansion (e.g., `cnt` -> `count`, `len` -> `length`, `byts` -> `bytes`, qualifier re-ordering) to align CIC-IDS2017 and CSE-CIC-IDS2018 column schemas.
  - `harmonize(X_train_df, test_raw, ...)` (L110-143): Intersects common features between 2017 and 2018 in identical training column order.

### 2.3 Split Methodology & Preprocessing
- **Split Type:** Seeded random stratified 70/15/15 (`train_test_split(..., stratify=y)`).
- **Split Independence Assessment:** Does **not** use a temporal or campaign-disjoint split. However, it enforces **deduplication prior to splitting**, eliminating row-exact test-set leakage.
- **Preprocessing Placement:** Cleaning (dropping negative time artifacts, inf/nan handling, deduplication) occurs globally before splitting. `StandardScaler` and class weighting are fitted on the training split only.
- **Handling of Time/Metadata:** Strips `Timestamp`, `Destination Port`, `Source IP`, and other network identifiers completely to prevent models from exploiting lab capture artifacts.

### 2.4 Leakage, Target Leakage & Test-Set Reuse
- **Source-Verified Fact:** Deduplication before splitting prevents test rows from being literal copies of training rows. Single-feature AUC auditing confirms whether individual columns act as proxy labels.
- **Limitation / Fact:** Because splitting is random stratified, flows from the same capture hour or session can appear in both train and test partitions.
- **Test-Set Reuse:** Evaluates once on the test split for final metrics.

---

## 3. Reference 2: `heraclitus0/TAD-IDS`

### 3.1 Metadata & Provenance
- **URL:** `https://github.com/heraclitus0/TAD-IDS`
- **Inspected Date:** 2026-10-18
- **HEAD Commit Hash:** `4586df5c25c37cf2d8fa02cda55803b5f47ab0a6`
- **Default Branch:** `main`
- **Repository Size:** ~862 KB (single Jupyter notebook + figures)
- **License:** MIT License. Attribution required if code or logic is adapted.
- **Project Claim (from README):** Investigates "Temporal Fragility in Network Intrusion Detection". Evaluates five model families under random vs temporal splits on CIC-IDS2017 (2.8M flows, 8 days). Reports that Random Forest drops from F1=0.9962 (random split) to F1=0.4349 (temporal split) — a collapse gap of 0.5613. Claims optimal decision thresholds under temporal shift range from 0.06 to 0.15 instead of 0.50.

### 3.2 Key Files & Functions Examined
- [`Addressing_Temporal_Fragility_in_Network_Intrusion_Detection_via_Structured_Feature_Modeling.ipynb`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/TAD-IDS/Addressing_Temporal_Fragility_in_Network_Intrusion_Detection_via_Structured_Feature_Modeling.ipynb):
  - **Cell 2:** Parquet conversion with `fillna(0)` instead of `dropna()`. Highlights that NaN/inf values in CIC-IDS2017 are heavily concentrated in attack rows; running `dropna()` silently deletes attack instances. Drops `Flow ID`, `Source IP`, `Destination IP`, `Timestamp`.
  - **Cell 2 (L78-80):** `binary_label = (df[label_col].str.strip() != "BENIGN").astype("int32")`. Converts all attacks to binary (1 = attack, 0 = benign).
  - **Cell 2 (L108-112):** Temporal split definitions:
    - Train: `Monday` (Benign), `Tuesday` (FTP/SSH Patator), `Wednesday` (DoS / Heartbleed) = 1,666,532 flows.
    - Test: `Thursday` (Web Attacks, Infiltration), `Friday` (Botnet, PortScan, DDoS) = 1,161,344 flows.
  - **Cell 3:** Semantic feature grouping into 6 groups: packet (20), timing (15), flag (12), flow (17), connection (12), remaining (2).
  - **Cell 4:** `StandardScaler` fitted strictly on Train files (`train_X.mmap`), applied to test.
  - **Cell 10:** Random split baseline (sampling from all 8 days combined) vs Temporal split.
  - **Cell 11:** `threshold_sweep(y_true, y_prob)` sweeping thresholds on `[0.05, 0.61]` in steps of 0.01.

### 3.3 Split Methodology & Preprocessing
- **Split Type:** Pure day-level temporal split: Days 1–3 (Train) vs Days 4–5 (Test).
- **Binary vs Multiclass Assumption:** **Critical discovery:** TAD-IDS evaluates **binary detection only** (Attack vs Benign). Because attack families in CIC-IDS2017 are scheduled on specific days, a pure day-based temporal split places Web Attacks, Infiltration, Botnet, PortScan, and DDoS **exclusively in the test set**. A multiclass model trained on Days 1–3 would have zero training instances for any Thursday/Friday attack classes.
- **Threshold Calibration Flaw in Reference:** Cell 11 executes `threshold_sweep(y_true_temp, y_prob_tad_temp)`, where `y_true_temp` is the **test set ground truth**. The reported optimal threshold $\theta^* \in [0.06, 0.15]$ was tuned **in-sample directly against the test set**.

### 3.4 Leakage, Target Leakage & Test-Set Reuse
- **Source-Verified Fact:** Temporal separation proves that random 80/20 splits severely overestimate real-world IDS performance due to time and campaign correlation.
- **Flaw / Non-Applicability:** In-sample threshold optimization on the test set is a test-leakage violation under `GATE1_CONTRACT.md`. Furthermore, binary evaluation cannot directly replace SentinelAI's 10-class multiclass requirement.

---

## 4. Reference 3: `LawrenceYH04/ML-IDS`

### 4.1 Metadata & Provenance
- **URL:** `https://github.com/LawrenceYH04/ML-IDS`
- **Inspected Date:** 2026-10-18
- **HEAD Commit Hash:** `5a253fbbfb63c51d13827ddae99c620c30897b4a`
- **Default Branch:** `main`
- **Repository Size:** ~13.8 MB (includes trained models, configs, result figures, FastAPI app)
- **License:** None (No license file; default copyright applies). Attribution required; do not copy source code directly.
- **Project Claim (from README):** Machine-learning IDS built and evaluated on **CSE-CIC-IDS2018** (16,232,943 flows, 15 classes, ~155,000:1 imbalance). Uses 40 mutual-information features + 16-dim autoencoder latent embedding. Reports Random Forest macro-F1 of 0.836 at an attack-vs-benign false positive rate of 0.63%. Scored with scikit-learn 1.7.2.

### 4.2 Key Files & Functions Examined
- [`notebooks/inference.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/ML-IDS/notebooks/inference.py):
  - `_ID_COLS` (L45): Strips `Flow ID`, `Src IP`, `Dst IP`, `Src Port`, `Dst Port`, `Timestamp`, `Label`.
  - `_FLAG_COUNT_COLS` (L52-54): Binarizes TCP flag counts (`FIN`, `SYN`, `RST`, `PSH`, `ACK`, `URG`, `CWE`, `ECE`) so live CICFlowMeter counts align with binary training encodings.
  - `_V4_RENAME` (L59-85): Comprehensive dictionary translating CICFlowMeter Java V4 output column names to the canonical 2018 training schema.
  - `_predict_calibrated(proba, thresholds)` (L155-160):
    ```python
    masked = np.where(proba >= thresholds, proba, -1.0)
    no_qualify = np.all(masked < 0, axis=1)
    result = np.argmax(masked, axis=1)
    result[no_qualify] = np.argmax(proba[no_qualify], axis=1)
    ```
- [`notebooks/model_training.ipynb`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/ML-IDS/notebooks/model_training.ipynb):
  - **Cell 1 / Cell 3:** `calibrate_thresholds(y_true, val_proba, n_cls)`: Scans 47 thresholds on `[0.04, 0.96]` in steps of 0.02. Chooses the threshold for each class that maximizes per-class F1 on the **validation set (`y_val`)**, completely isolated from the test set. Thresholds are saved to `models/thresholds_rf.npy`.
- [`notebooks/evaluation.ipynb`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/ML-IDS/notebooks/evaluation.ipynb):
  - **Cell 18 (Infiltration Deep-Dive):** Analyzes why Infiltration achieves the lowest F1 (0.25–0.30) across RF, XGBoost, and MLP. Runs t-SNE on 25,890 flows (Infiltration vs Benign vs Other attacks). Proves that Infiltration flows overlap heavily with Benign traffic in transport flow feature space; 75% of Infiltration flows (18,208 out of 24,290) are misclassified as Benign.
  - **Cell 19 (Temporal Split Analysis):** Computes class distributions across all 10 daily CSV files in CSE-CIC-IDS2018. Discloses that attack classes are scheduled on specific single days (e.g., Infiltration only on 02-28 and 03-01; DDoS HOIC only on 02-21; Botnet only on 03-02).

### 4.3 Split Methodology & Preprocessing
- **Split Type:** 70/15/15 stratified train/validation/test split.
- **Calibration Split:** Thresholds and scalers are fitted strictly on `train` and `validation` partitions. Held-out `y_test.npy` is touched only for final evaluation.
- **Handling of Imbalance & Preprocessing:** Uses capped SMOTE on training data + cost-sensitive balanced class weighting. Feature engineering combines mutual-information tabular features with autoencoder bottleneck embeddings.

### 4.4 Leakage, Target Leakage & Test-Set Reuse
- **Source-Verified Fact:** Threshold calibration is strictly leak-free with respect to the test set (fitted on validation).
- **Limitation for SentinelAI:** The threshold selection objective maximizes per-class F1 without an explicit constraint on total benign FPR $\le 0.100\%$. In SentinelAI, raising recall on overlapping classes (like Infiltration) via unconstrained calibration causes benign false alarms that violate Criterion A1.

---

## 5. Reference 4: `YufengXin/network-attack-research`

### 5.1 Metadata & Provenance
- **URL:** `https://github.com/YufengXin/network-attack-research`
- **Inspected Date:** 2026-10-18
- **HEAD Commit Hash:** `106e39b289937e5c2a8703149bd5f49ad9c578b5`
- **Default Branch:** `main`
- **Repository Size:** ~6.6 MB (comprehensive pipeline from raw PCAPs to models and evaluation)
- **License:** None (No license file; default copyright applies). Attribution required; do not copy source code directly.
- **Project Claim (from README):** Multi-class multi-tier network intrusion detection from raw CIC-IDS PCAPs. Compares tabular classification (flow statistics -> trees/deep tabular) and time-series classification (packet sequences -> transformers). Emphasizes exact 5-tuple ground-truth labeling and Distrinet-corrected CSE-CIC-IDS2018 cross-dataset evaluation.

### 5.2 Key Files & Functions Examined
- [`src/data/split.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/network-attack-research/src/data/split.py):
  - `make_splits(df, strategy="time_then_group", ...)` (L20-151): Implements two explicit split strategies:
    1. `time_then_group`: Sorts flows by `flow_start_time` and snaps split boundaries to `scenario_id` group edges (`_snap_to_group_boundaries`, L173-228). Enforces zero scenario-group overlap and strictly monotonic time order.
    2. `stratified_shuffle`: Seeded random stratified split by `attack_class`.
  - Section docstrings explicitly note the core IDS evaluation dilemma: temporal/group splits in CIC-IDS place entire attack families into a single partition, making full multiclass evaluation impossible without multi-day multi-corpus pooling.
- [`src/data/labeling.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/network-attack-research/src/data/labeling.py) & [`docs/LABELING_IMPLEMENTATION_SUMMARY.md`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/network-attack-research/docs/LABELING_IMPLEMENTATION_SUMMARY.md):
  - Validates exact attack ground truth against PCAP ground truth:
    - **Heartbleed:** 5-tuple exact match (Source port 45022, Destination port 444, TCP). Confirms Heartbleed has only ~11 flows in 2017 and is absent from 2018.
    - **Infiltration:** 5-tuple exact match (victim `192.168.10.8` -> `205.174.165.73:444`, TCP). Captures Cool Exploit Kit delivery and shell beaconing (~66 flows).
    - **Distrinet Relabeling:** "Attempted" attack flows (e.g., `Infiltration - Attempted`) are relabeled to `BENIGN` because failed connections contain no attack payload and corrupt benign flow baselines.
- [`src/evaluation/metrics.py`](file:///C:/Users/srisn/.gemini/antigravity/brain/09280792-7806-4f02-b14b-0b107f44fc41/scratch/repos/network-attack-research/src/evaluation/metrics.py):
  - `compute_hierarchical_metrics_v1(...)` (L131-205): Evaluates predictions at three granularity tiers simultaneously:
    1. `fine`: Original 15 granular classes (macro-F1).
    2. `coarse`: 9 family-level categories (e.g., Web Attacks collapsed; Brute Force collapsed).
    3. `binary`: BENIGN vs ATTACK.

### 5.3 Split Methodology & Preprocessing
- **Split Type:** Configurable: `time_then_group` (default) with scenario-group snapping, or `stratified_shuffle`.
- **Handling of Cross-Dataset:** Dedicated script `scripts/run_cross_dataset_eval.py` applies frozen 2017 preprocessing models directly onto 2018 CSV data using mapped label aliases.

### 5.4 Leakage, Target Leakage & Test-Set Reuse
- **Source-Verified Fact:** PCAP-level 5-tuple flow aggregation prevents port-proxy leakage and avoids synthetic labeling errors. Group snapping ensures flows from the same attack burst/session do not span across train/val/test splits.

---

## 6. Synthesis & Summary Table of References

| Dimension | `cicids-shap-stability` | `TAD-IDS` | `ML-IDS` | `network-attack-research` | SentinelAI Existing |
|---|---|---|---|---|---|
| **Primary Dataset** | CIC-IDS2017 (+ 2018 eval) | CIC-IDS2017 | CSE-CIC-IDS2018 | CIC-IDS2017 + CSE-2018 | Multi-corpus (2017 + 2018) |
| **Split Protocol** | Random stratified after dedup | Day-level temporal (Mon-Wed vs Thu-Fri) | 70/15/15 random stratified | `time_then_group` or stratified shuffle | Row-hash MD5 exclusion |
| **Task Framing** | Multiclass (tree + CNN) | Binary (Attack vs Benign) | Multiclass (15 classes) | Multiclass + Hierarchical (15/9/2) | Multiclass (10 classes) |
| **Time Features** | Dropped (`Timestamp` + clock desync rows) | Dropped (`Timestamp`); timing IAT kept | Dropped (`Timestamp` in `_ID_COLS`) | Dropped (`Timestamp` in non-features) | Engineered `time_of_day_sin/cos` (Phase 13 flagged) |
| **Calibration Target** | None (Argmax) | Test-set sweep ($\theta \in [0.06, 0.15]$) | Validation F1 grid search | Validation PR/ROC curve | Validation calibration (Phase 12/13) |
| **Deduplication** | Exact feature-row dedup before split | `fillna(0)` (no dropna / no dedup) | Imputer + Scaler | Flow-aggregator 5-tuple grouping | MD5 float-hash row filtering |
| **Heartbleed / Class 5** | Kept in granular, dropped in consolidation | Wednesday only (grouped in binary) | Not in 2018 dataset | 5-tuple exact match (N=11 in 2017, 0 in 2018) | Mapped to "RCE Attempt" (N=11; BLOCKED) |
| **Infiltration Status** | Included in 15 classes | Thursday afternoon (grouped in binary) | t-SNE shows 75% overlap with Benign | 5-tuple exact match; Attempted -> Benign | Mapped to Lateral Movement; ~0% recall |
| **License** | MIT License | MIT License | None (All Rights Reserved) | None (All Rights Reserved) | Internal / Proprietary |

---

## 7. Compliance & Safety Verification
- **Inspection Integrity:** All inspections conducted strictly read-only.
- **No Untrusted Execution:** No scripts from reference repositories were executed within SentinelAI's environment.
- **Attribution Policy:** When adapting methodologies from References 1 & 2 (MIT), copyright and license notices must be preserved. References 3 & 4 (No License) were studied purely as mathematical and architectural references; no code will be copied directly.
