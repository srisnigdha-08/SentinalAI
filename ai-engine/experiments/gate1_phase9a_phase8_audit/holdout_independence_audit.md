# SentinelAI GATE-1 Phase 9A: Holdout Independence and Leakage Audit

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Master Independence & Leakage Verdict Table

To prevent treating zero identical row hashes as proof of complete dataset independence, the audit evaluated five distinct layers of data separation:

| Evaluation Dimension | Audited Finding | Independence Verdict | Impact on Evaluation Integrity |
| :--- | :--- | :---: | :--- |
| **Exact Row Duplication** | 40,774 unique feature row hashes indexed across 43,566 holdout rows. **Zero rows leaked** into training ($N=179,458$) or validation ($N=31,623$). | **CONFIRMED INDEPENDENT (PASS)** | Model was not trained on identical evaluation flows. |
| **Near-Duplicate Overlap** | High density of near-duplicate flows exists within high-rate attacks (DDoS and PortScan) due to repeated packet sizes and fixed TCP window sizes. | **PARTIALLY INDEPENDENT** | Synthetically elevated training accuracy if evaluated on the same capture day. |
| **Group-Level Independence (Day / Host / Campaign)** | - **Web Attacks**: 100% separated across corpora (trained on 2017, evaluated on 2018).<br>- **DDoS**: Separated across capture days (trained on 2018-02-15, evaluated on 2018-02-21).<br>- **Infiltration**: Single-day capture (2018-03-01).<br>- **Botnet**: Single-day capture (2018-03-02). | **CONDITIONAL / MIXED** | Full cross-campaign independence exists for Web and DDoS. Single-day capture limits Infiltration and Botnet. |
| **Label Leakage & Preprocessing Fit** | Pipeline `StandardScaler()` was fitted strictly on `X_train`. Zero mean/variance statistics from holdout leaked into the pipeline. | **CONFIRMED INDEPENDENT (PASS)** | Preprocessing statistics were strictly isolated. |
| **Benign Control Overlap** | - Infiltration Benign: 1,000 / 1,000 (**100.0% overlap** with 30k holdout).<br>- Web Attack Benign: 1,000 / 1,000 (**100.0% overlap** with 30k holdout).<br>- Botnet, SSH/FTP, DDoS Benign: 0 / 1,000 (**0.0% overlap**). | **CONTAMINATED ON 2 SLICES** | Infiltration and Web Attack slice FPRs duplicate the 30k holdout evaluation. |
| **Repeated Holdout Usage** | Sealed holdout benchmark has now been evaluated across Phase 7, Phase 7 Audit, Phase 8, and Phase 9A. | **RISK OF ADAPTATION (WARNING)** | Holdout is at risk of becoming a de facto validation set if hyperparameters are iteratively tuned against it. |

---

## 2. Cryptographic Verification of Exact Duplication

Every row in `partition_train_multicorpus.parquet` and `partition_validation_tuning.parquet` was evaluated against the hash set of all 43,566 rows on disk in `D:/sentinelai_datasets/cse_cic_ids2018/holdout_sets/*.parquet`:

```
Holdout Row Hashes Indexed: 40,774 unique MD5 vectors
Total Holdout Rows on Disk: 43,566 rows

Training Partition (N = 179,458):
- Matching Holdout Hashes: 0
- Exact Duplication Rate: 0.0000%

Validation Partition (N = 31,623):
- Matching Holdout Hashes: 0
- Exact Duplication Rate: 0.0000%
```

---

## 3. Benign Control Slice Redundancy Audit

The 1,000 benign control flows embedded inside each of the 5 attack parquets were audited against the primary 30,000-record benign holdout (`holdout_benign_30k.parquet`):

```
holdout_benign_30k.parquet: 30,000 unique benign flows

Slice Benign Control Overlap:
- holdout_infiltration.parquet:        1,000 / 1,000 (100.0% overlap) -> IDENTICAL DUPLICATE
- holdout_web_attacks.parquet:         1,000 / 1,000 (100.0% overlap) -> IDENTICAL DUPLICATE
- holdout_botnet.parquet:                  0 / 1,000 (  0.0% overlap) -> FULLY DISJOINT
- holdout_bruteforce_ssh_ftp.parquet:      0 / 1,000 (  0.0% overlap) -> FULLY DISJOINT
- holdout_ddos.parquet:                    0 / 1,000 (  0.0% overlap) -> FULLY DISJOINT
```

### Root Cause
In `preprocess_cse2018.py`, lines 212–215 and 264–267 sampled benign control records using `df_infil.sample(n=1000, random_state=42)` and `df_web.sample(n=1000, random_state=42)`. The large-scale 30k holdout sampled from the same dataframes using the same pseudo-random seed, leading to 100% duplicate selection for those two files.

---

## 4. Preprocessing Fit Scope & Transformation Isolation

A code inspection of `run_phase8_experiments.py` verified the fitting scope:

```python
pipe = Pipeline([
    ("scaler", StandardScaler()),
    ("rf", RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=20, random_state=42, n_jobs=-1))
])
# Scaler is fitted exclusively on training data:
pipe.fit(X_tr_cand, y_train)
```

The feature mean $\mu$ and standard deviation $\sigma$ were derived solely from the 179,458 training rows. The sealed holdout data was strictly passed through `pipe.predict()` and `pipe.predict_proba()`. Zero test distribution parameters leaked into the feature scaling.

---

## 5. Auditor Recommendation on Sealed Holdout Lifecycle

> [!WARNING]
> ### Freeze Evaluation on the 2018 Benchmark
> The CSE-CIC-IDS2018 holdout benchmark ($N = 38,566$) has now been evaluated across multiple consecutive phases. To preserve its validity as a final acceptance gate:
> 1. Future model iterations and Phase 9 detector tuning must use **only** the designated Validation Partition (`partition_validation_tuning.parquet`) or cross-validation splits.
> 2. The sealed holdout must be queried **only once** for final gate acceptance verification.
