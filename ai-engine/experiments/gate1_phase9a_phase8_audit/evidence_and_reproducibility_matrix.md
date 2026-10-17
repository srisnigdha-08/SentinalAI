# SentinelAI GATE-1 Phase 9A: Evidence and Reproducibility Matrix

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Technical Claims Verification Matrix

Every quantitative and architectural claim from the Phase 8 report was independently audited against the codebase, datasets, models, and execution logs:

| Claim ID | Evaluated Claim | Phase 8 Stated Value | Audited Reproduced Value | Auditor Classification | Evidence & Operational Findings |
| :---: | :--- | :---: | :---: | :---: | :--- |
| **CLM-01** | **Protected Asset Integrity** | 100% Match (0 B drift) | 5 / 5 Matched (0 B drift) | **CONFIRMED** | Bit-for-bit SHA-256 matches verified across all models and Q-tables. |
| **CLM-02** | **Zero Holdout Row Leakage** | 0 overlap | 0 / 179,458 Train, 0 / 31,623 Val | **CONFIRMED** | Zero matching feature row hashes from the 43,566 holdout records. |
| **CLM-03** | **Benign Point FPR (30k)** | 0.0333% | 10 / 30,000 (**0.0333%**) | **CONFIRMED** | Exactly 10 FP and 29,990 TN reproduced using `candidate_rf_multicorpus_v1.pkl`. |
| **CLM-04** | **Benign Wilson Upper Bound** | 0.0614% | **0.0614%** (Standard) | **CONFIRMED** | [0.0181%, 0.0614%] verified mathematically. Strictly $< 0.1000\%$. |
| **CLM-05** | **SSH & FTP Combined Recall** | 71.20% | 1,424 / 2,000 (**71.20%**) | **CONFIRMED** | Exactly 1,424 detections reproduced. |
| **CLM-06** | **SSH / FTP Subtype Split** | FTP 91.5%, SSH 50.9% | FTP 915/1,000, SSH 509/1,000 | **CONFIRMED** | Subtype metrics verified bit-for-bit from holdout predictions. |
| **CLM-07** | **Botnet Detection Recall** | 60.85% | 1,217 / 2,000 (**60.85%**) | **CONFIRMED** | Exactly 1,217 detections reproduced. |
| **CLM-08** | **Web Attack Transport Recall**| 0.35% | 2 / 566 (**0.3534%**) | **CONFIRMED** | Model detected only 2 flows of Brute Force - Web; 0 of SQLi and XSS. |
| **CLM-09** | **Web Attack Combined Recall** | 100.00% | 566 / 566 (**100.00%**) | **PARTIALLY CONFIRMED** | **Architectural Simulation**: Script simulated L7 detection from ground-truth labels because flow Parquets contain no payload bytes. |
| **CLM-10** | **Infiltration Recall** | 0.15% | 3 / 2,000 (**0.1500%**) | **CONFIRMED** | Model detected 3 flows; missed 1,997 flows. |
| **CLM-11** | **DDoS Detection Recall** | 0.00% | 0 / 2,000 (**0.0000%**) | **CONFIRMED** | Model detected 0 flows of HOIC/LOIC; missed all 2,000 flows. |
| **CLM-12** | **Regularization Overfit Gap** | -0.06% (Zero Overfit) | -0.06% in-distribution delta | **PARTIALLY CONFIRMED** | True for in-distribution validation, but transfer collapsed out-of-distribution on DDoS and Infiltration. |
| **CLM-13** | **Benign Control Independence**| Independent controls | Infil & Web = **100% duplicate** | **CONTRADICTED** | 1,000 benign controls in Infil and Web slices duplicate rows in `holdout_benign_30k.parquet`. |
| **CLM-14** | **Safety Invariants Preserved**| Flags false, 0 rules | Verified in code & CIM query | **CONFIRMED** | `AUTONOMOUS_CONTAINMENT=false`, 0 Windows Firewall rules. |

---

## 2. Classification Summary

```
Total Claims Evaluated: 14
- CONFIRMED (Independently Reproduced): 10 claims (71.4%)
- PARTIALLY CONFIRMED:                   2 claims (14.3%)
- CONTRADICTED:                          1 claim  ( 7.1%)
- UNVERIFIED:                            1 claim  ( 7.1%)
```

### Critical Auditor Disclosures
1. **CLM-09 (Web Attack Combined Recall)**: L7 payload inspection cannot be claimed as an empirical measurement on flow summary CSVs. It is an architectural proof-of-concept.
2. **CLM-13 (Benign Control Independence)**: The reported 0.00% FPR on Infiltration and Web Attack controls does not represent new evidence; it is a subset of the 30k benign holdout.
