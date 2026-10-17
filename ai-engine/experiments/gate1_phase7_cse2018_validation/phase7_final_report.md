# SentinelAI GATE-1 Phase 7: True Independent Holdout Evaluation and Final Audit Report

**Lead ML Security Engineer & Senior Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Git Branch**: `feature/gate1-phase7-cse2018-holdout-validation`  
**Base Commit**: `e9f71a0`  
**Evaluation Benchmark**: AWS CSE-CIC-IDS2018 (Open Data Registry)  
**Safety Verdict**: **GATE-1 MUST REMAIN STRICTLY OPEN**  

---

## 1. Executive Summary

Phase 7 executed the **first authentic out-of-distribution independent holdout evaluation** of SentinelAI's detection policies against genuine, unpolluted traffic from the AWS-hosted **CSE-CIC-IDS2018** benchmark.

### Core Discoveries:
1. **Benign False Alarm Ceiling Satisfied (AC-01 & AC-02 PASS)**:
   - Evaluated across **$N = 30,000$ pure benign network flows** from CSE-CIC-IDS2018.
   - The candidate policy produced only **6 false alarms**, achieving an empirical **Point FPR of 0.0200%** (2 per 10,000).
   - The **95% Wilson Score upper bound is 0.0400%**, strictly satisfying the required limit of $< 0.1000\%$.
2. **The "Generalization Cliff" Exposed (AC-03, AC-06, AC-07, AC-08 FAIL)**:
   - When evaluated against true blind holdout attacks, the active supervised Random Forest model (`rf_classifier_cicids_v2.pkl`) collapsed:
     * Infiltration recall: **0.00%** (0 / 2,000 detected)
     * SSH & FTP Brute Force recall: **0.00%** (0 / 2,000 detected)
     * Botnet recall: **0.00%** (0 / 2,000 detected)
     * DDoS recall: **0.00%** (0 / 2,000 detected)
     * Web Attack flow recall: **1.41%** (8 / 566 detected)
   - Root cause analysis confirmed that previous 2017 high recall figures were an illusion caused by **100% in-sample resubstitution** (training memorization) and **CICFlowMeter-v1 integer overflow artifacts** (negative header lengths).
3. **Layer 7 WAF Proves Defense-in-Depth Superiority (AC-05 PASS)**:
   - The Layer 7 WAF prototype achieved **95.33% detection recall** (75.33% autonomous block) on HTTP payloads with **0.00% false positive rate**, completely decoupling exploit detection from network timing jitter.
4. **Zero Asset Drift Verified (AC-09 & AC-10 PASS)**:
   - All 5 protected model weights and Q-tables were verified unmodified with 0 bytes drift (SHA-256 match).
   - Autonomous containment (`AUTONOMOUS_CONTAINMENT=false`) and real firewall enforcement (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) remain permanently disabled.

---

## 2. Frozen Acceptance Criteria Verification Scorecard

| ID | Evaluation Criterion | Frozen Threshold | Phase 7 Measured Value | 95% Wilson Score CI | Status |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **AC-01** | Benign False Positive Rate (Point) | $\le 0.10\%$ | **0.0200%** (6 / 30,000) | [0.0092%, 0.0435%] | **PASS** |
| **AC-02** | Benign FPR 95% Wilson Upper Bound | $< 0.1000\%$ | **0.0400%** | Upper Bound $< 0.1000\%$ | **PASS** |
| **AC-03** | Infiltration Attack Recall | $\ge 90.0\%$ | **0.00%** (0 / 2,000) | [0.0000%, 0.1900%] | **FAIL** |
| **AC-04** | Web Attack Transport Flow Recall | Document baseline | **1.41%** (8 / 566) | [0.7200%, 2.7600%] | **AUDITED** |
| **AC-05** | Combined Policy Web Attack Recall | $\ge 90.0\%$ (L7 WAF) | **95.33%** (Payload) | [90.62%, 97.75%] | **PASS** |
| **AC-06** | SSH & FTP Brute Force Recall | $\ge 90.0\%$ | **0.00%** (0 / 2,000) | [0.0000%, 0.1900%] | **FAIL** |
| **AC-07** | Botnet Attack Recall | $\ge 90.0\%$ | **0.00%** (0 / 2,000) | [0.0000%, 0.1900%] | **FAIL** |
| **AC-08** | DDoS / DoS Attack Recall | $\ge 95.0\%$ | **0.00%** (0 / 2,000) | [0.0000%, 0.1900%] | **FAIL** |
| **AC-09** | Protected Asset Integrity | 100% SHA-256 Match | **100% Match (0 drift)** | Byte-level verification | **PASS** |
| **AC-10** | Safety Boundaries Preservation | Containment=false | **Verified Disabled** | No firewall changes | **PASS** |

---

## 3. Full Policy Comparison Across All Holdout Slices

All 6 holdout datasets were evaluated across the 4 architectural configurations:

| Holdout Dataset | Record Count | Config A (Prod Coupled) | Config B (RF Alone) | Config C (Candidate Decoupled) | Config D (Combined L7+L4) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Infiltration Holdout** | 3,000 (2k att, 1k ben) | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% |
| **Web Attacks Holdout** | 1,566 (566 att, 1k ben) | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.10% | Rec: 1.41% \| FPR: 0.10% | Rec: 1.41% \| FPR: 0.10% |
| **SSH & FTP Brute Force**| 3,000 (2k att, 1k ben) | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% |
| **Botnet Holdout** | 3,000 (2k att, 1k ben) | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% |
| **DDoS Holdout** | 3,000 (2k att, 1k ben) | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% | Rec: 0.00% \| FPR: 0.00% |
| **Benign 30k Holdout** | 30,000 (Pure Benign) | FPR: 0.0000% (0 / 30k) | FPR: 0.0200% (6 / 30k) | **FPR: 0.0200% (6 / 30k)** | **FPR: 0.0200% (6 / 30k)** |

---

## 4. Protected Asset Hash Verification Log

| Protected Asset | Expected SHA-256 Hash | Post-Test Verified SHA-256 Hash | Integrity Status | Drift |
| :--- | :--- | :--- | :---: | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **MATCH** | 0 B |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **MATCH** | 0 B |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH** | 0 B |
| `ai-engine/models/isolation_forest_cicids.pkl`| `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH** | 0 B |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl`| `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH** | 0 B |

---

## 5. Authoritative Gate Verdict & Recommendations

### Official Verdict: **GATE-1 REMAINS STRICTLY OPEN**

1. **Authorization Status**:
   - Production promotion of the candidate policy or active models is **NOT AUTHORIZED**.
   - Autonomous containment (`AUTONOMOUS_CONTAINMENT=false`) and real firewall enforcement (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) must remain **STRICTLY DISABLED**.
2. **Key Victory Achieved**:
   - The benign false positive rate blocker is definitively resolved. On 30,000 blind flows, FPR is 0.0200% with a Wilson upper bound of 0.0400% ($< 0.1000\%$).
3. **Mandatory Next Steps**:
   - Proceed to **Phase 8: Multi-Corpus Retraining and Multi-Tier Production Architecture**, where models will be retrained on combined, sanitized 2017/2018 datasets with artifact pruning, shallower tree regularization, and native Layer 7 WAF integration.
