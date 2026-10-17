# SentinelAI GATE-1 — Reference Method Comparison & Technical Analysis

**Audit Phase:** GATE-1 Phase 14 — Reference-Guided Root-Cause Audit  
**Author:** Senior ML Evaluation Engineer & Security Code Reviewer  
**Date:** 2026-10-18  

---

## 1. Overview & Comparative Methodology

This technical comparison evaluates SentinelAI's intrusion-detection pipeline against four authoritative reference repositories:
1. `Vabnas/cicids-shap-stability` (Ref 1)
2. `heraclitus0/TAD-IDS` (Ref 2)
3. `LawrenceYH04/ML-IDS` (Ref 3)
4. `YufengXin/network-attack-research` (Ref 4)

We analyze the five core GATE-1 failure modes:
- **A. Leakage and Split Independence**
- **B. Temporal Distribution Shift & Feature Schemas**
- **C. Benign False-Positive Rate & Threshold Calibration**
- **D. Infiltration Recall & Flow-Level Inseparability**
- **E. Class Coverage & Heartbleed Taxonomy (Class 5)**

---

## 2. Leakage and Split Independence Analysis

### 2.1 SentinelAI Existing Behavior
In Phases 10, 12, and 13, SentinelAI attempted to generate leak-free partitions using row-level MD5 hashing of float-formatted features:
```python
# build_clean_three_splits.py & build_final_test_v2.py
def hash_dataframe_rows(df: pd.DataFrame) -> list:
    mat = df[SORTED_FEATS].to_numpy(dtype=np.float32)
    return [hashlib.md5((",".join(f"{x:.4f}" for x in row)).encode("utf-8")).hexdigest() for row in mat]
```
Rows whose float hash matched any previously burned holdout, training split, or validation split were excluded.

### 2.2 Findings from Reference Repositories
1. **Deduplication vs Split Leakage (Ref 1 - `cicids-shap-stability`):**
   - Ref 1 proves that CIC-IDS datasets contain ~21% exact duplicate feature rows. In a naive random split, ~23% of test rows appear in training, artificially inflating tree model accuracy.
   - Ref 1 implements global deduplication (`df.drop_duplicates()`) *prior* to splitting, combined with automated split leakage auditing (`check_split_leakage()` using `pd.util.hash_pandas_object`).
2. **Temporal Collapse (Ref 2 - `TAD-IDS`):**
   - Ref 2 demonstrates that even after separating features, random splits yield F1=0.9962 on Random Forest, but collapsing to a pure temporal split causes F1 to plummet to 0.4349 (a 0.5613 drop).
   - This proves that random splitting allows models to exploit session-level and background-traffic correlations across identical capture days.
3. **Single-Day Attack Campaigns (Ref 3 - `ML-IDS`):**
   - Ref 3 audits the daily distribution across all 10 CSV files in CSE-CIC-IDS2018. It shows that virtually every attack category was executed during a single multi-hour window on one or two calendar days:
     - SSH/FTP Brute Force: 02-14 only
     - DoS GoldenEye / Slowloris: 02-15 only
     - DoS Hulk / SlowHTTPTest: 02-16 only
     - DDoS LOIC-HTTP: 02-20 only
     - DDoS HOIC: 02-21 only
     - Web Attacks: 02-22 & 02-23 only
     - Infiltration: 02-28 & 03-01 only
     - Botnet Ares: 03-02 only
4. **Group Boundary Snapping (Ref 4 - `network-attack-research`):**
   - Ref 4 implements `time_then_group` in `src/data/split.py` via `_snap_to_group_boundaries()`. Boundaries snap to `scenario_id` so that bursts belonging to the same attack run never cross split boundaries.

### 2.3 Synthesis for SentinelAI
- **The Core Dilemma:** In CSE-CIC-IDS2018 and CIC-IDS2017, a naive calendar-day temporal split (e.g. Days 1–7 Train, Days 8–10 Test) makes multiclass evaluation impossible because classes on Days 8–10 have zero training instances.
- **Why Row-Hash Disjointness Alone Failed:** Filtering by MD5 float hash guarantees that identical rows are not repeated, but does not prevent contiguous flows from the same 10-minute attack burst from entering both train and test partitions.
- **Recommended Split Protocol for SentinelAI:**
  1. Multi-day pooling combining CIC-IDS2017 and CSE-CIC-IDS2018 so that every required class has representation across multiple independent days.
  2. For classes appearing in only one corpus/day (e.g., HOIC on 02-21), partition using **time-ordered contiguous blocks with a mandatory time gap/buffer** (e.g., 30-minute blackout window between train and test blocks).
  3. Enforce global deduplication before splitting, followed by provenance verification (source file, date, scenario group).

---

## 3. Temporal Distribution Shift & Feature Schemas

### 3.1 SentinelAI Existing Behavior
SentinelAI's `features.py` defines a 53-feature vector that includes:
- `payload_entropy`
- `time_of_day_sin`
- `time_of_day_cos`

In `features.py`, `compute_time_of_day()` handles timestamp parsing:
```python
def compute_time_of_day(timestamp_val) -> tuple:
    if timestamp_val is None:
        dt = datetime.datetime.now()  # Wall-clock fallback!
    ...
```
In live inference (`predictor.py`), if an incoming flow packet lacks a timestamp, it falls back to current server wall-clock time (`datetime.now()`).

### 3.2 Findings from Reference Repositories
- **Every single reference repository explicitly rejects wall-clock features:**
  - **Ref 1 (`cicids-shap-stability`):** Strips `Timestamp` in `drop_candidates` (`rq1_pipeline.py`, L166). Features are strictly flow-internal statistics (durations, packet counts, byte counts, IATs, flags).
  - **Ref 2 (`TAD-IDS`):** Drops `Timestamp` (`DROP_COLS`, Cell 2). Restricts timing features strictly to inter-arrival times (IATs) and flow duration.
  - **Ref 3 (`ML-IDS`):** Explicitly classifies `Timestamp` under `_ID_COLS` (`inference.py`, L45), ensuring it is never passed to scalers, autoencoders, or classifiers.
  - **Ref 4 (`network-attack-research`):** Uses timestamp only to order flows for time-then-group partitioning; never includes absolute timestamp or time-of-day in the feature vector.
- **The Mechanism of Temporal Leakage:**
  Because attacks in CIC-IDS were executed during fixed lab hours (e.g., Infiltration at 2:00 PM, DDoS at 10:00 AM), models trained with `time_of_day_sin/cos` learn that the *clock time* is predictive of attacks. Adversarial validation in SentinelAI's Phase 13 revealed an AUC of 0.76–1.0 when time features were present.
  At runtime, when live benign traffic is processed at 2:00 PM, the classifier triggers false alarms; conversely, attacks executed outside laboratory hours escape detection.

### 3.3 Synthesis for SentinelAI
- Dropping `time_of_day_sin` and `time_of_day_cos` from the feature schema is **strictly justified and mandatory**.
- Network flow classifiers must classify traffic based on invariant transport and packet dynamics (IAT, packet lengths, TCP state transitions, window sizes), not wall-clock time.
- The feature vector must be frozen to 51 features (or an updated approved schema), with training and runtime using an identical schema without wall-clock fallbacks.

---

## 4. Benign False-Positive Rate & Threshold Calibration

### 4.1 SentinelAI Existing Behavior
- **Criterion A1:** Whole-pipeline Benign FPR $\le 0.100\%$ ($\le 25$ false positives out of 25,000 benign flows).
- **Phase 12 Result:** 26 false positives / 25,000 = 0.104% (FAIL).
- **Phase 13 Result:** 28 false positives / 25,000 = 0.112% (FAIL).
- In Phase 12, false alarms were concentrated: 20 on Lateral Movement (Infiltration), 6 on Malware Beacon (Botnet).

### 4.2 Findings from Reference Repositories
1. **Test-Set Reuse in Ref 2 (`TAD-IDS`):**
   - Ref 2 sweeps thresholds across `[0.05, 0.61]` directly on the test set (`y_true_temp`), discovering optimal thresholds at 0.06–0.15. While this demonstrates that 0.50 is suboptimal under shift, tuning on the test set is a direct test-leakage violation prohibited by SentinelAI's contract.
2. **Leak-Free Multiclass Threshold Calibration in Ref 3 (`ML-IDS`):**
   - Ref 3 provides a clean, leak-free calibration architecture (`model_training.ipynb Cell 1 & 3`):
     ```python
     def calibrate_thresholds(y_true, val_proba, n_cls):
         grid = np.linspace(0.04, 0.96, 47)
         thresholds = np.full(n_cls, 0.5)
         for c in range(n_cls):
             # Grid search threshold maximizing F1 on validation split
             ...
         return thresholds
     ```
   - Inference uses `_predict_calibrated(proba, thresholds)`:
     ```python
     masked = np.where(proba >= thresholds, proba, -1.0)
     no_qualify = np.all(masked < 0, axis=1)
     result = np.argmax(masked, axis=1)
     result[no_qualify] = np.argmax(proba[no_qualify], axis=1)
     ```
   - **Critical Difference / Limitation:** Ref 3 optimizes per-class thresholds to maximize validation F1 without an FPR constraint. In an environment with an extreme Benign FPR ceiling ($\le 0.100\%$), unconstrained F1 optimization lowers the threshold on difficult classes (like Infiltration), causing false alarms on benign flows that violate Criterion A1.

### 4.3 Synthesis for SentinelAI
- SentinelAI must adopt Ref 3's validation-split calibration architecture, but modify the optimization objective:
  Instead of unconstrained F1 maximization, the calibration search must optimize **per-class recall subject to the constraint that total validation Benign FPR $\le 0.100\%$**.
- Thresholds must be chosen on a frozen validation partition, serialized to `thresholds.json`, and evaluated on the holdout test set exactly once.

---

## 5. Infiltration Recall & Flow-Level Inseparability

### 5.1 SentinelAI Existing Behavior
- **Criterion E3:** Infiltration Recall $\ge 70\%$.
- **Phase 13 Result:** Evaluated on `final_test_v2.parquet`, Candidate V3 achieved **1 true positive out of 2,500 samples (Recall = 0.0004 = 0.04%)**.

### 5.2 Findings from Reference Repositories
1. **Feature-Space Inseparability (Ref 3 - `ML-IDS`):**
   - Ref 3 conducted a dedicated t-SNE investigation (`evaluation.ipynb Cell 18`, `infilteration_tsne.png`):
     - Evaluated Random Forest, XGBoost, MLP, and Autoencoders on 24,290 Infiltration flows from CSE-CIC-IDS2018.
     - **Result:** Infiltration clusters completely overlap with normal Benign desktop traffic.
     - Even with 40 mutual-information features and a 16-dimensional autoencoder latent representation, **XGBoost misclassified 18,208 out of 24,290 Infiltration flows (75%) as BENIGN**.
     - Calibrating thresholds raised precision slightly (0.33–0.36) but recall collapsed to 0.19–0.25 (well below 70%).
2. **Ground-Truth Exploit Delivery (Ref 4 - `network-attack-research`):**
   - Ref 4 audited the raw PCAP captures for Infiltration (victim `192.168.10.8` -> `205.174.165.73:444`, TCP).
   - Infiltration in the CIC testbed consists of a client downloading a malicious document/binary via HTTP/browser, followed by an outbound shell beacon.
   - Flow-level statistics (packet counts, IATs, TCP flags) during a document download or basic TCP session are virtually indistinguishable from legitimate web browsing or file transfers.
   - Ref 4 notes that the Distrinet benchmark relabels "Attempted" Infiltration flows as `BENIGN` because failed attempts contain only standard TCP handshakes.

### 5.3 Synthesis for SentinelAI
- The ~0% Infiltration recall is an **inherent dataset limitation of transport-layer flow features**, not a hyperparameter tuning bug.
- Attempting to force statistical Random Forest flow classifiers to achieve $\ge 70\%$ recall on Infiltration causes catastrophic benign false-positive rates ($\ge 8\%$, as seen in Phase 13 ablations), directly violating Criterion A1.
- In modern security architecture, Infiltration and Lateral Movement cannot be solved by stateless flow meters alone; they require:
  1. Host Telemetry / Endpoint Detection (EDR process trees, execution events).
  2. Layer 7 inspection of payload signatures and command-and-control protocols.
  3. Long-term session periodicity tracking.
- **GATE-1 Recommendation:** Mark Criterion E3 as **BLOCKED / ARCHITECTURALLY INSUFFICIENT FOR STATISTICAL FLOW MODELS**. Request an explicit owner decision to decouple Infiltration acceptance from tabular flow classifiers or augment with host telemetry adapters.

---

## 6. Class Coverage & Heartbleed (Class 5)

### 6.1 SentinelAI Existing Behavior
- **Criterion C2:** 10 required classes (`BENIGN`, `SSH Brute Force`, `SQL Injection`, `Port Scan`, `DDoS`, `RCE Attempt`, `XSS Attempt`, `Malware Beacon`, `Credential Stuffing`, `Lateral Movement`).
- `candidate_rf_multicorpus_v2_fixed.pkl` contains only 9 classes (`[0, 1, 2, 3, 4, 6, 7, 8, 9]`). Class 5 is entirely missing.
- In `features.py`, Class 5 is labeled "RCE Attempt" and mapped from the raw label `"Heartbleed"`.

### 6.2 Findings from Reference Repositories
1. **Semantic Taxonomy Mismatch (Ref 4 & Ref 1):**
   - Ref 4 (`label_maps_cicids2018.json`) and CVE-2014-0160 confirm that Heartbleed is an **Information Disclosure vulnerability** (buffer over-read in OpenSSL TLS heartbeat extension), NOT Remote Code Execution (RCE).
   - Classifying Heartbleed as "RCE Attempt" is an invalid domain mapping.
2. **Extreme Dataset Sparsity:**
   - Both Ref 1 and Ref 4 confirm that Heartbleed exists **only in CIC-IDS2017 `Wednesday-workingHours.pcap_ISCX.csv` with exactly 11 flows**, and is completely absent from CSE-CIC-IDS2018 (0 flows).
   - In Ref 1, Heartbleed is omitted from the consolidated publication classes because $N=11$ cannot support statistical training or validation.
   - In Ref 4, Heartbleed is labeled via 5-tuple exact match, but excluded from cross-dataset transfer due to zero target instances.

### 6.3 Synthesis for SentinelAI
- A statistical classifier cannot be reliably trained on 8 flows and evaluated on 3 flows. A single misclassification swings test recall by 33.3%, making statistical confidence intervals meaningless.
- Furthermore, Heartbleed is a TLS-layer protocol exploit that is trivially detected via a single packet check: `tls_heartbeat_payload_length > actual_record_length`.
- **GATE-1 Recommendation:** Maintain Class 5 as **BLOCKED**. Submit Decision 2 to the owner: formally re-scope Criterion C2 to 9 classes for statistical flow models, assigning Heartbleed inspection to a dedicated Layer 7 / signature rule.

---

## 7. Modular Detectors & Layer 7 Integration

### 7.1 Web Attacks (SQLi & XSS)
- Transport flow features do not inspect HTTP URIs, headers, or query parameters.
- In Phase 13, XSS recall was 82.7% but with a wide Wilson confidence interval ([0.7027, 0.9062]), making it INCONCLUSIVE against an 80% threshold.
- Ref 4 shows that web attacks in CIC-IDS require Layer 7 URI inspection or exact payload parsing. SentinelAI's modular WAF detector (`ai-engine/modular/` or Layer 7 rules) is the appropriate mechanism for Web Attacks.

### 7.2 Volumetric Floods (DDoS LOIC/HOIC)
- In Phase 13, Candidate V3 achieved 85.7% recall on DDoS.
- The shadow B2 Volumetric Flood Detector (`ai-engine/modular/volumetric_flood.py`) provides rate-based PPS tracking that complements tabular flow scoring without model drift.

---

## 8. Summary of Actionable Architectural Recommendations

1. **Feature Schema Freezing:** Permanently remove `time_of_day_sin` and `time_of_day_cos` from training and inference. Eliminate the `datetime.now()` wall-clock fallback in `features.py`. Freeze schema to 51 validated flow features.
2. **Threshold Calibration Architecture:** Adopt Ref 3's `_predict_calibrated` decision rule, but fit per-class thresholds on the validation set under an explicit constraint of total benign FPR $\le 0.100\%$.
3. **Partitioning Discipline:** Replace naive MD5 row hashing with provenance-backed temporal-gap partitioning across multi-corpus pools.
4. **Owner Scope Decisions:**
   - Formally re-scope Criterion C2 to 9 classes (disposition of Class 5 Heartbleed).
   - Formally determine Infiltration (Criterion E3) disposition: acknowledge flow-feature inseparability and route detection to endpoint telemetry.
