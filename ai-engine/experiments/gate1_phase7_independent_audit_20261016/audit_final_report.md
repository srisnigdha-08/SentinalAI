# SentinelAI GATE-1 Phase 7 Independent Audit: Master Audit Report

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Audited Branch**: `feature/gate1-phase7-cse2018-holdout-validation`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Audited Directory**: `ai-engine/experiments/gate1_phase7_cse2018_validation/`  
**Audit Output Directory**: `ai-engine/experiments/gate1_phase7_independent_audit_20261016/`  
**Authoritative Verdict**: **GATE-1 MUST REMAIN STRICTLY OPEN**  

---

## 1. Executive Summary

This independent, evidence-driven audit was conducted to rigorously verify the claims, methodologies, integer counts, and statistical intervals reported during **Phase 7: True Independent Holdout Evaluation (CSE-CIC-IDS2018)** prior to approving any Phase 8 planning or implementation.

### Key Audit Conclusions:
1. **Benign False Alarm Target Conclusively Satisfied (AC-01 & AC-02 PASS)**:
   - Evaluated on **30,000 pure benign network flows** from CSE-CIC-IDS2018.
   - Produced exactly **6 false alarms** (**Point FPR = 0.0200%**).
   - The unrounded standard two-sided **95% Wilson Score Confidence Interval is $[0.0092\%, 0.0436\%]$** (continuity-corrected: $[0.0081\%, 0.0459\%]$).
   - The upper bound of **$0.0436\%$ is strictly below the required $0.1000\%$ ceiling**, definitively resolving the false positive blocker that halted earlier phases.
2. **Generalization Collapse Confirmed on Out-of-Distribution Attacks (AC-03, AC-06, AC-07, AC-08 FAIL)**:
   - When exposed to true blind holdout traffic from AWS CSE-CIC-IDS2018, the active Random Forest classifier (`rf_classifier_cicids_v2.pkl`) collapsed:
     * Infiltration Recall: **0.00%** (0 / 2,000 detected)
     * SSH & FTP Brute Force Recall: **0.00%** (0 / 2,000 detected)
     * Botnet (Malware Beacon) Recall: **0.00%** (0 / 2,000 detected)
     * DDoS (HOIC/LOIC) Recall: **0.00%** (0 / 2,000 detected)
     * Web Attack Transport Flow Recall: **1.41%** (8 / 566 detected)
3. **Negative Header Length Overflow Myth Disproven**:
   - The auditor examined all 4,044 split nodes on `fwd_header_len` across all 200 trees in `rf_classifier_cicids_v2.pkl`.
   - **4,043 split nodes (99.98%) possess positive thresholds** (median +62.0 B). Only 1 node had a negative threshold.
   - The previous claim that the trees keyed on negative header values caused by 32-bit overflow was **factually disproven**.
4. **True Failure Driver Isolated: TCP Window Size & Timing Memorization**:
   - The #1 and #3 most influential features in the Random Forest are `init_win_bytes_backward` (Gini importance: 9.93%) and `init_win_bytes_forward` (4.98%).
   - Controlled offline ablation proved that restoring the 2017 Kali VM window stack values (`init_win_bytes_forward=259`, `backward=-1`) to a 2018 AWS flow increased attack confidence by **+13.2%**. The model memorized testbed TCP stacks rather than attack semantics.
5. **Layer 7 WAF Prototype Contextualized**:
   - WAF recall of **95.33%** (143/150) and simulated block rate of **75.33%** (113/150) were verified on the 300-record benchmark with **0.00% FPR** on benign HTTP ($N=120$) and non-HTTP ($N=30$).
   - Caveat: The 300 test payloads were authored in the same script as the regex rules, representing a functional unit test rather than an independent network capture. Furthermore, the WAF protects **HTTP only** and provides **zero defense** for SSH, FTP, Botnets, Infiltration, or DDoS.
6. **Zero Model Tampering & Safety Preservation Verified**:
   - Pre- and post-audit SHA-256 hashes of all 5 protected core ML assets match with **0 bytes drift**.
   - `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` remain strictly enforced. Zero system firewall rules exist.

---

## 2. Recomputed Scorecard from Raw Integer Counts

```mermaid
pie title Phase 7 Frozen Acceptance Criteria Status
    "PASS (AC-01, 02, 05, 09, 10)" : 5
    "FAIL (AC-03, 06, 07, 08)" : 4
    "AUDITED (AC-04)" : 1
```

| ID | Criterion | Raw Numerator / Denominator | Unrounded Metric | Percentage | 95% Wilson Score CI | Target Threshold | Verdict | Auditor Confidence |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **AC-01** | Benign Point FPR | 6 / 30,000 | 0.000200 | **0.0200%** | — | $\le 0.1000\%$ | **PASS** | **CONFIRMED** |
| **AC-02** | Benign FPR Wilson Upper Bound | 6 / 30,000 | 0.000436 | **0.0436%** | [0.0092%, 0.0436%] | $< 0.1000\%$ | **PASS** | **CONFIRMED** |
| **AC-03** | Infiltration Detection Recall | 0 / 2,000 | 0.000000 | **0.00%** | [0.0000%, 0.1900%] | $\ge 90.00\%$ | **FAIL** | **CONFIRMED** |
| **AC-04** | Web Attack Transport Flow Recall | 8 / 566 | 0.014134 | **1.41%** | [0.7200%, 2.7600%] | Baseline Audit | **AUDITED** | **CONFIRMED** |
| **AC-05** | Combined Policy Web Attack Recall | 143 / 150 | 0.953333 | **95.33%** | [90.62%, 97.75%] | $\ge 90.00\%$ | **PASS** | **PARTIALLY CONFIRMED** |
| **AC-06** | SSH & FTP Brute Force Recall | 0 / 2,000 | 0.000000 | **0.00%** | [0.0000%, 0.1900%] | $\ge 90.00\%$ | **FAIL** | **CONFIRMED** |
| **AC-07** | Botnet (Malware Beacon) Recall | 0 / 2,000 | 0.000000 | **0.00%** | [0.0000%, 0.1900%] | $\ge 90.00\%$ | **FAIL** | **CONFIRMED** |
| **AC-08** | DDoS / DoS Attack Recall | 0 / 2,000 | 0.000000 | **0.00%** | [0.0000%, 0.1900%] | $\ge 95.00\%$ | **FAIL** | **CONFIRMED** |
| **AC-09** | Protected Asset Integrity | 5 / 5 | 1.000000 | **100.00%** | Byte-level SHA-256 match | 100% (0 B drift) | **PASS** | **CONFIRMED** |
| **AC-10** | Safety Boundaries Preservation | 2 / 2 | 1.000000 | **100.00%** | Verified disabled | All Disabled | **PASS** | **CONFIRMED** |

---

## 3. Discrepancy Reconciliation

### 3.1 Arithmetic Resolution of the Wilson Score Discrepancy
- **The Reported Contradiction**: The Phase 7 report stated a Wilson interval of $[0.0092\%, 0.0435\%]$ in Section 2, but cited an upper bound of $0.0400\%$ in Section 1.
- **Auditor Resolution**: In `policy_comparison_metrics.json` lines 668–669, the metric array was serialized as `[0.0001, 0.0004]`. The author took the rounded $0.0004$ ($0.0400\%$) and juxtaposed it against the unrounded analytical formula ($0.0436\%$).
- **Formal Value**: Standard unrounded two-sided 95% Wilson upper bound is **$0.0436\%$** (continuity-corrected: **$0.0459\%$**). Under all mathematical formulations, the ceiling condition ($< 0.1000\%$) is strictly satisfied.

### 3.2 Population Count Reconciliation ($N = 38,566$ vs $N = 43,566$)
- **The Discrepancy**: The Phase 7 executive summary stated $N = 38,566$, while summing all Parquet file rows on Drive D: yields $43,566$ rows.
- **Auditor Resolution**:
  * Evaluated Attack Flows: $2,000 + 566 + 2,000 + 2,000 + 2,000 = \mathbf{8,566}$ flows.
  * Evaluated Pure Benign Holdout: $\mathbf{30,000}$ flows.
  * Sum: $8,566 + 30,000 = \mathbf{38,566}$ unique evaluation flows.
  * The remaining $5,000$ rows on disk represent the $1,000$ benign control flows embedded inside each of the 5 attack parquets for per-slice control testing.
  * Furthermore, hash analysis confirmed that $97.4\%$ of the Infiltration benign control rows and $100\%$ of the Web Attack benign control rows overlap with `holdout_benign_30k.parquet` due to identical pseudo-random seeds (`random_state=42`). The evaluation harness correctly avoided pooling them together.

---

## 4. Protected Asset Hash Verification Log

All 5 protected model weights and Q-tables were verified pre-audit and post-audit:

| Asset Name | Repository Path | Frozen Expected Hash | Post-Audit Computed Hash | Drift |
| :--- | :--- | :--- | :--- | :---: |
| Baseline Q-Table | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | 0 B |
| Runtime Q-Table | `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | 0 B |
| Active RF Model | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | 0 B |
| Active IF Model | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | 0 B |
| Candidate XGB | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | 0 B |

---

## 5. Phase 8 Readiness Assessment & Next Steps

### 5.1 Is Phase 8 Ready to be Planned?
**YES**. Phase 8 is technically ready to be planned. The empirical blockers are now fully understood:
- Benign false positive rates can be controlled ($0.0436\% < 0.1000\%$).
- The root cause of the transport model generalization failure has been isolated to TCP window size and microsecond timing memorization.
- The Layer 7 WAF architecture has been validated for application-layer exploit protection.

### 5.2 What Evidence Gates Phase 8 Execution?
Before Phase 8 retraining begins, the following gates must be formally satisfied:
1. **Feature Pruning Approval**: Formally authorize the replacement of raw TCP window sizes (`init_win_bytes_forward`/`backward`) with scale-invariant ratios.
2. **Multi-Corpus Dataset Manifest**: Harmonize and clean a balanced cross-dataset training corpus comprising both CICIDS2017 and CSE-CIC-IDS2018 with entire days reserved as sealed blind holdouts.
3. **Artifact Location Segregation**: Mandate that newly trained models be staged in `ai-engine/experiments/gate1_phase8_multicorpus_candidates/` without overwriting protected production models.

---

## 6. Official Gate Verdict

> [!CAUTION]
> ### Authoritative Decision: GATE-1 REMAINS STRICTLY OPEN
> 1. **Production Promotion Prohibited**: The active model (`rf_classifier_cicids_v2.pkl`) cannot be promoted to production or autonomous containment. Its detection recall across genuine out-of-distribution network attacks is near-zero.
> 2. **Autonomous Containment Prohibited**: `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` must remain permanently enforced.
> 3. **Mandatory Next Step**: Await user authorization to begin **Phase 8: Multi-Corpus Retraining and Multi-Tier Production Architecture** under the audited roadmap.
