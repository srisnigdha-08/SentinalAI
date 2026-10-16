# GATE-1 Phase 2: Read-Only Policy Logic Audit Summary

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Scope**: Final audit synthesis of policy recall collapse, threshold attenuation, edge cases, and proposed acceptance specifications  
**GATE-1 Status**: **OPEN (IN PROGRESS — READ-ONLY INVESTIGATION COMPLETE)**

---

## 1. Executive Summary & Core Findings

This read-only audit conclusively resolved the architectural contradiction between SentinelAI’s high reported raw model recall and its low runtime policy recall:
1. **The Policy Recall Collapse is Confirmed**:
   - **PortScan Policy Recall**: **7.40%** ($74 / 1,000$ attack flows mitigated; $926$ allowed).
   - **DDoS Policy Recall**: **76.60%** ($766 / 1,000$ attack flows mitigated; $234$ allowed).
   - **Autonomous Blocking Recall**: **0.00%** on PortScan ($0 / 1,000$) and **0.50%** on DDoS ($5 / 1,000$).
2. **The Root Cause is In-Code Multiplicative Attenuation**:
   In [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L290-L302), threat score weighting is calculated as:
   $$\text{threatScore} = \text{round}(0.7 \cdot P_{RF} + 0.3 \cdot \text{if\_sig}, 4)$$
   For attacks with no volume anomaly (such as single-probe port scans), $\text{if\_sig} = 0.0$. This caps the threat score at $0.70 \cdot P_{RF} \le 0.70$. Since `MONITOR_THRESHOLD` is $0.70$, **any attack prediction with Random Forest confidence below 100% is mathematically forced to `action = "ALLOW"`**.
3. **Safety Posture Verification**:
   Zero policy false alarms on benign traffic was achieved because the policy engine aggressively suppresses scores below $0.70$. Zero false blocking is **not** evidence of robust containment safety when 92.6% of attack flows are allowed to pass unmitigated.
4. **Environment Invariance**:
   **Exactly zero production files, models, configurations, services, databases, Q-tables, or firewall rules were changed during this audit.**

---

## 2. Findings Register with Evidence and Confidence Levels

| Finding ID | Finding Description | Evidence Location | Observed Behavior | Confidence Level |
| :---: | :--- | :--- | :--- | :---: |
| **F-01** | Multiplicative formula attenuates supervised confidence | [`ai-engine/inference/predictor.py:292`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L292) | Confirmed `score = round(0.7*rf_s + 0.3*if_sig, 4)`. When `if_sig == 0`, max score is 0.70. | **CONFIRMED** |
| **F-02** | Anomaly signal is zero for stealthy attacks | [`ai-engine/inference/predictor.py:226`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L226) | `val >= offset` returns `0.0`. PortScan inliers return `if_sig = 0.0`. | **CONFIRMED** |
| **F-03** | 926 PortScan attack flows assigned `ALLOW` | [`ai-engine/experiments/gate1_evaluation/evaluation_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_evaluation/evaluation_results.json#L232) | Actions on 1,000 PortScans: `ALLOW: 926`, `MONITOR: 74`, `BLOCK: 0`. Recall = 7.40%. | **CONFIRMED** |
| **F-04** | 234 DDoS attack flows assigned `ALLOW` | [`ai-engine/experiments/gate1_evaluation/evaluation_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_evaluation/evaluation_results.json#L150) | Actions on 1,000 DDoS: `ALLOW: 234`, `MONITOR: 761`, `BLOCK: 5`. Recall = 76.60%. | **CONFIRMED** |
| **F-05** | `Unknown` labeled flows receive `ALLOW` | [`ai-engine/inference/predictor.py:294`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L294) | `score = max(score, 0.55)`. Since $0.55 < 0.70$, action is `ALLOW`. | **CONFIRMED** |
| **F-06** | Monday capture was sampled during model training | [`ai-engine/training/train.py:40-75`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py#L40-L75) | `data_path.glob("*.csv")` ingested Monday and sampled 15k flows. Monday re-classified as validation evidence. | **CONFIRMED** |
| **F-07** | Backend containment requires both score and autoBlock | [`backend/services/threatService.js:95`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/threatService.js#L95) | `shouldBlock = score >= blockThreshold && autoBlockEnabled`. Autonomous block is gated. | **CONFIRMED** |

---

## 3. Files Examined During Audit

1. [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) — Threshold constants (lines 88–90), anomaly signal logic (lines 205–230), threatScore formula (lines 290–294), and action arbitration (lines 301, 350).
2. [`ai-engine/inference/main.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/main.py) — FastAPI endpoint contracts (`/predict/internal`, `/model/info`, input validation).
3. [`ai-engine/training/train.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/training/train.py) — Multi-file CSV glob ingestion and subsampling loop (lines 40–135).
4. [`backend/services/threatService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/threatService.js) — Threat creation, threshold routing, auto-block status (lines 86–127).
5. [`backend/services/aiEngineService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/aiEngineService.js) — Backend threshold fetching and caching (`getBlockThreshold`, lines 113–132).
6. [`backend/services/containmentService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/containmentService.js) — Containment execution and compensating rollbacks (lines 778–847).
7. [`ai-engine/experiments/gate1_evaluation/evaluation_results.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_evaluation/evaluation_results.json) — Physical confusion matrices and flow counts.
8. [`ai-engine/models/rf_classifier_cicids_v2_meta.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/models/rf_classifier_cicids_v2_meta.json) — Production classifier training metadata.

---

## 4. Tests Run and Tests Deliberately Omitted

### Tests Run (Read-Only)
- Executed [`reconcile_and_audit.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_complete_remediation/final_reconciliation/reconcile_and_audit.py) to recalculate exact confusion matrices and Wilson intervals from immutable saved evaluation data.

### Tests Deliberately Omitted (In Strict Compliance with Safety Rules)
1. **Live Network Ingestion Tests**: Omitted to prevent modifying the live database on port 27017.
2. **Model Retraining or Threshold Mutation Tests**: Omitted to preserve production model artifacts and configurations.
3. **Real Windows Firewall Rule Tests**: Omitted to protect host network connectivity.
4. **Q-Table Write Tests**: Omitted to guarantee zero mutation of runtime Q-table state.

---

## 5. Explicit Invariant Affirmation

In strict conformance with user-specified safety constraints:
- **Application source code**: **0 files modified**
- **Model weights and metadata**: **0 models modified or replaced**
- **Environment and configuration files**: **0 files modified**
- **Running services (Node, Python, MongoDB, Vite)**: **0 restarts, 0 stops, 0 reconfigurations**
- **Live databases (`sentinel-db` on port 27017)**: **0 writes, 0 updates, 0 deletions**
- **Windows Firewall rules**: **Exactly 0 rules added or modified**
- **Active Q-tables**: **0 bytes modified**
- **Safety gates**: `AUTONOMOUS_CONTAINMENT=false` and `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false` remain permanently locked.

---

## 6. Recommended Next Steps (Phase 3 Planning)

1. **Phase 3 Implementation Scope**:
   Refactor [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) according to the proposed decision table in [`proposed_policy_acceptance_tests.md`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase2_policy_audit/proposed_policy_acceptance_tests.md):
   - Decouple supervised attack confidence from unsupervised anomaly attenuation so that confident attack classifications ($P_{RF} \ge 0.70$) trigger `MONITOR` or `BLOCK` regardless of whether Isolation Forest is anomalous.
   - Maintain the safe override: `Unknown` anomaly flows must remain locked at `threatScore = 0.55` and `action = "ALLOW"`.
2. **Regression Verification**:
   Execute the 6 proposed acceptance tests to verify that PortScan policy recall recovers from 7.4% to $\ge 90.0\%$ while keeping benign FPR bounded below $0.10\%$.
3. **Release Gate Status**:
   Keep **GATE-1 OPEN** until Phase 3 remediation is completed and validated.
