# SentinelAI GATE-1 Phase 7: Preflight, Safety Invariants, and Evaluation Scope

**Auditor / Lead ML Safety Engineer**: Senior Machine Learning Security Engineer & Independent Auditor  
**Date**: 2026-10-16  
**Git Branch**: `feature/gate1-phase7-cse2018-holdout-validation`  
**Base Commit**: `e9f71a0`  
**Working Directory**: `c:\Users\srisn\Desktop\Projects\sentinelai-complete`  
**Secondary Dataset Storage**: `D:\sentinelai_datasets\cse_cic_ids2018\`  

---

## 1. Safety Preflight and Operational Boundaries

To ensure strict engineering discipline and prevent accidental harm to production or live systems, the following mandatory safety boundaries are enforced:

1. **Gate Status**: **GATE-1 REMAINS STRICTLY OPEN**. No promotion to production or release closure is authorized by this phase.
2. **Containment Invariants**:
   - `AUTONOMOUS_CONTAINMENT=false`
   - `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`
   - Real Windows Firewall rules MUST NOT be created, altered, or deleted.
3. **Protected Assets Invariant**:
   - No models or Q-tables may be retrained, overwritten, or modified.
   - Pre-experiment and post-experiment SHA-256 hashes must verify byte-level integrity:
     * `ai-engine/models/q_table.json` (`BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`)
     * `ai-engine/runtime/q_table.json` (`55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27`)
     * `ai-engine/models/rf_classifier_cicids_v2.pkl` (`CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1`)
     * `ai-engine/models/isolation_forest_cicids.pkl` (`17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4`)
     * `ai-engine/models/xgb_classifier_cicids_v2.pkl` (`A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D`)
4. **Live Services & Databases**:
   - No connection or write operations to live MongoDB (`sentinel-db`).
   - No interference with `D:\MongoPreservation` or `D:\MongoPreservation_Backup_20261015`.
   - Running background services must not be signaled, reconfigured, or interrupted.
5. **Storage Invariants**:
   - Drive `C:` has limited free capacity (~3 GB). All raw dataset CSV downloads, parquet extractions, and large intermediate tables MUST be stored on Drive `D:\sentinelai_datasets\cse_cic_ids2018\` (>215 GB free).
   - Only code, configs, and lightweight summary JSONs/markdowns (<10 MB total) may be committed or stored on Drive `C:`.

---

## 2. Objective of Phase 7

Phase 7 executes the **first true independent holdout evaluation** of SentinelAI's detection policies against genuine, unpolluted traffic from the AWS-hosted **CSE-CIC-IDS2018** benchmark.

### Critical Historical Flaws Being Resolved:
1. **The 100% In-Sample Resubstitution Flaw**: In CICIDS2017 evaluations, 100% of SSH-Patator, Web Attacks, Infiltration, and Botnet samples were present in the training corpus. Phase 7 evaluates against 100% unpolluted, out-of-distribution 2018 network traffic.
2. **The Infiltration Sample Deficiency**: CICIDS2017 contained only 36 Infiltration flows in total. CSE-CIC-IDS2018 provides **93,063 Infiltration flows**, enabling high-statistical-power validation.
3. **The Benign False Positive Upper Bound**: In Phase 4, candidate policy produced 7 false alarms in 10,000 flows (Wilson upper bound 0.1445% > 0.1000%). Phase 7 tests $N \ge 30,000$ benign session flows to rigorously bound the false alarm rate below the 0.10% threshold.

---

## 3. Evaluation Policies Compared

Four architectural policies are evaluated in parallel:

1. **Config A (Production Policy)**:
   - Supervised Random Forest + Isolation Forest Gatekeeper.
   - If Isolation Forest predicts inlier ($+1$), the supervised alert is suppressed to `BENIGN`, even if RF confidence is 1.00.
2. **Config B (Unconstrained RF Baseline)**:
   - Supervised Random Forest alone, ignoring Isolation Forest.
3. **Config C (Phase 3A Candidate Policy)**:
   - Two-tier priority logic: High-confidence RF ($\ge 0.85$ for high-risk attacks, $\ge 0.90$ for low-risk) bypasses IF suppression.
   - Low-to-moderate RF predictions require IF confirmation (anomaly score $\le -0.10$).
   - Explicit degraded state handling.
4. **Config D (Combined Defense-in-Depth: L7 WAF + Candidate Policy)**:
   - Priority 1: Layer 7 WAF payload inspection (regex/token-based AST analysis for SQLi, XSS, Path Traversal, Command Injection).
   - Priority 2: If L7 unavailable or benign flow, evaluate transport flows via Config C Candidate Policy.

---

## 4. Acceptance Criteria Frozen for Phase 7

| Criterion ID | Metric | Threshold | Scope |
| :--- | :--- | :--- | :--- |
| **AC-P7-01** | Benign False Positive Rate (FPR) | $\le 0.10\%$ (Point Estimate) | $\ge 30,000$ pure benign holdout flows |
| **AC-P7-02** | Benign FPR 95% Wilson Upper Bound | $< 0.10\%$ | $\ge 30,000$ pure benign holdout flows |
| **AC-P7-03** | Infiltration Attack Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $\ge 1,000$ holdout Infiltration flows |
| **AC-P7-04** | Web Attack Recall (Transport Flow) | Document baseline flow recall | 566 holdout Web Attack flows |
| **AC-P7-05** | Combined Policy Web Attack Recall | $\ge 90.0\%$ (with L7 payload inspection) | Payload-equipped holdout / benchmark |
| **AC-P7-06** | Brute Force (SSH/FTP) Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $\ge 1,000$ holdout Brute Force flows |
| **AC-P7-07** | Botnet Attack Recall | $\ge 90.0\%$ (Detection), $\ge 80.0\%$ (Sim. Block) | $\ge 1,000$ holdout Botnet flows |
| **AC-P7-08** | DDoS / DoS Attack Recall | $\ge 95.0\%$ (Detection), $\ge 85.0\%$ (Sim. Block) | $\ge 1,000$ holdout DDoS flows |
| **AC-P7-09** | Asset Integrity Verification | 100% SHA-256 match, 0 bytes drift | All 5 protected model & Q-table files |
