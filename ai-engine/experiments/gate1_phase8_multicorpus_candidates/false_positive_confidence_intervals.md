# SentinelAI GATE-1 Phase 8: Benign False Positive Rate & Confidence Interval Audit

**Auditor / ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Status**: Formal Audit Deliverable  
**Branch**: `feature/gate1-phase8-multicorpus-candidates`  

---

## 1. Executive Summary: Frozen Acceptance Criteria AC-01 & AC-02

In Phase 8, the multi-corpus candidate model (`candidate_rf_multicorpus_v1.pkl`) was evaluated against the large-scale sealed benign holdout benchmark (`holdout_benign_30k.parquet`, $N = 30,000$).

| Evaluation Criterion | Candidate Integer Counts | Point FPR | 95% Wilson Score CI | Frozen GATE-1 Threshold | Auditor Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **AC-01: Benign Point FPR** | $10 / 30,000$ | **0.0333%** | — | $\le 0.1000\%$ | **PASS** |
| **AC-02: Wilson CI Upper Bound** | $10 / 30,000$ | 0.0333% | **[0.0181%, 0.0614%]** | $< 0.1000\%$ | **PASS** |

Both AC-01 and AC-02 are strictly satisfied by the multi-corpus candidate model.

---

## 2. Mathematical Formulation & Reconciliation

### 2.1 Standard Two-Sided 95% Wilson Score Interval
For a binomial proportion with $k$ false positives out of $n$ benign trials:
$$\hat{p} = \frac{k}{n}, \quad z = 1.959964$$
$$\text{CI} = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1 - \hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

Substituting $k = 10, n = 30,000$:
$$\hat{p} = 0.00033333$$
$$\text{Denominator} = 1 + \frac{3.841459}{30,000} = 1.000128$$
$$\text{Centre} = \frac{0.00033333 + 0.00006402}{1.000128} = 0.0003973$$
$$\text{Margin} = \frac{1.959964 \times \sqrt{\frac{0.00033333 \times 0.99966667}{30,000} + \frac{3.841459}{3.6 \times 10^9}}}{1.000128} = 0.0002166$$
$$\text{Lower Bound} = 0.0003973 - 0.0002166 = \mathbf{0.0001807} \quad (\mathbf{0.0181\%})$$
$$\text{Upper Bound} = 0.0003973 + 0.0002166 = \mathbf{0.0006139} \quad (\mathbf{0.0614\%})$$

### 2.2 Continuity-Corrected Wilson Interval
Applying Yates continuity correction:
$$\text{Lower}_{\text{cc}} = \mathbf{0.0166\%}, \quad \text{Upper}_{\text{cc}} = \mathbf{0.0645\%}$$

Under all standard mathematical formulations, the upper bound is strictly below the required $0.1000\%$ ceiling.

---

## 3. Comparison Between Baseline and Candidate

| Model Architecture | Training Data | Evaluation Benign Population | False Positive Count | Point FPR | 95% Wilson Upper Bound | AC-01 / AC-02 Status |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **Phase 7 Baseline** (`rf_classifier_cicids_v2.pkl`) | Single-Corpus (CICIDS2017) | Sealed 30k Benign Holdout | 6 / 30,000 | **0.0200%** | **0.0436%** | **PASS** |
| **Phase 8 Candidate** (`candidate_rf_multicorpus_v1.pkl`) | Multi-Corpus (2017 + 2018) | Sealed 30k Benign Holdout | 10 / 30,000 | **0.0333%** | **0.0614%** | **PASS** |

The multi-corpus candidate experienced a negligible increase of 4 false alarms across 30,000 benign network flows ($+0.0133\%$) while gaining significant transfer recall on SSH, FTP, and Botnet traffic.
