# SentinelAI GATE-1 Phase 9A: Regularization and Feature Ablation Audit

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Feature Ablation Experiments Audit (A – F)

The Phase 8 experimental engine evaluated 6 feature configurations on the training partition ($N = 179,458$) and validation partition ($N = 31,623$):

| Config ID | Description | Dimension | Fit Time | Aggregate Val Recall | Val FPR | 95% Wilson FPR Upper Bound | Auditor Evaluation |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **A** | Original 53 Features (Baseline) | 53 | 5.61s | 99.44% | 0.3077% | 0.4032% | High validation recall, but overfits VM TCP window sizes on holdout. |
| **B** | TCP Windows Removed | 51 | 5.69s | 98.82% | 0.8875% | 1.0404% | Prunes VM stack memorization; slightly elevates raw argmax FPR. |
| **C** | Raw Destination Port Added | 54 | 5.76s | 99.44% | 0.2426% | 0.3289% | Artificially lowers FPR by memorizing standard ports (80/443). Discarded. |
| **D** | Timing Features Log1p-Transformed | 53 | 6.04s | 99.44% | 0.3077% | 0.4032% | Compresses microsecond testbed jitter while retaining burst dynamics. |
| **E** | Combined: No Windows + Log Timing | 51 | 5.93s | 98.82% | 0.9052% | 1.0596% | Simultaneously removes stack and timing hardware artifacts. |
| **F** | **Justified Candidate (Robust Schema)** | **51** | **5.66s** | **98.87%** | **0.9289%** | **1.0851%** | **Selected Schema**: Prunes windows, log-transforms timing/rates/lengths, normalizes header sizes. |

### 1.1 Per-Class Validation Breakdown (The Hidden Blind Spot)
Inspecting the granular per-class validation recall in `feature_ablation_results.json` revealed an essential empirical finding:

| Canonical Attack Class | Config A (Original) | Config B (No Windows) | Config C (Ports) | Config D (Log Timing) | Config E (Combined) | Config F (Candidate) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `SSH Brute Force` | 99.40% | 99.10% | 99.49% | 99.40% | 99.10% | **99.19%** |
| `Credential Stuffing` (FTP/Web BF) | 98.97% | 99.01% | 99.14% | 98.97% | 99.01% | **99.01%** |
| `Port Scan` | 99.66% | 99.58% | 99.66% | 99.66% | 99.58% | **99.62%** |
| `DDoS` | 99.73% | 99.73% | 99.81% | 99.73% | 99.73% | **99.75%** |
| `Malware Beacon` (Bot) | 98.79% | 93.61% | 98.79% | 98.79% | 93.61% | **93.66%** |
| `XSS Attempt` | 1.02% | 0.00% | 0.00% | 1.02% | 0.00% | **0.00%** |
| `SQL Injection` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | **0.00%** |
| `BENIGN` (Specificity) | 99.69% | 99.11% | 99.76% | 99.69% | 99.09% | **99.07%** |

#### Auditor Finding
Across **all 6 ablation conditions**, transport-layer Random Forest recall on `SQL Injection` was exactly **0.00%**, and recall on `XSS Attempt` was **0.00% to 1.02%**.  
Aggregate validation metrics (~99%) masked the total inability of transport flow statistics to detect web application exploits. This provides definitive empirical proof that a transport model cannot stand alone for Layer 7 threats.

---

## 2. Regularization Settings Comparison Audit

The 4 regularization configurations were evaluated on Candidate Schema F:

| Setting ID | Hyperparameters | Avg Tree Depth | Avg Leaves / Tree | Training Recall | Validation Recall | Generalization Gap | Status |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Setting 1** | Baseline (`max_depth=20`, `min_leaf=1`, `split=5`) | 20.0 | 789.7 | 99.39% | 99.23% | **+0.16%** | Overfit risk: deep leaves isolate single packets. |
| **Setting 2** | **Proposed (`max_depth=12`, `min_leaf=20`, `split=20`)** | **12.0** | **227.2** | **98.81%** | **98.87%** | **-0.06%** | **Selected**: Zero overfit gap, 71% leaf reduction. |
| **Setting 3** | Shallow (`max_depth=10`, `min_leaf=50`, `split=50`) | 10.0 | 141.1 | 98.57% | 98.59% | **-0.02%** | Under-fits minority attack clusters. |
| **Setting 4** | Moderate (`max_depth=15`, `min_leaf=10`, `split=10`) | 15.0 | 350.8 | 99.09% | 99.06% | **+0.03%** | Unnecessary depth without generalization gain. |

---

## 3. Audit of the "Overfit Gap" Definition

In `run_phase8_experiments.py`, the overfit gap was defined mathematically as:
$$\Delta_{\text{overfit}} = \left( \text{Recall}_{\text{train}} - \text{Recall}_{\text{val}} \right) \times 100$$

- For Setting 1: $99.39\% - 99.23\% = +0.16\%$ (training recall exceeded validation recall).
- For Setting 2: $98.81\% - 98.87\% = -0.06\%$ (validation recall slightly exceeded training recall).

### Critical Auditor Qualification
The Phase 8 report interpreted $\Delta_{\text{overfit}} = -0.06\%$ as "zero tree overfitting."  
While this correctly demonstrates that the tree did not overfit its *in-distribution validation partition*, **it does not guarantee out-of-distribution transfer to external testbeds**. When the model was subsequently evaluated on the authentic AWS 2018 holdout, recall dropped to 0.00% on DDoS and 0.15% on Infiltration.

In-distribution validation alignment must never be conflated with domain generalization.
