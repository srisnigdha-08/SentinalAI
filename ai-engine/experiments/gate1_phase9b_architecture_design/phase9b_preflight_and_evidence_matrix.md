# SentinelAI GATE-1 Phase 9B: Preflight and Evidence Classification Matrix

**Author / Senior Reviewer**: Senior Security Architect, Machine Learning Engineer & Independent Security-Systems Reviewer  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Architecture Design & Safety Review (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base / HEAD Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Gate Status**: **GATE-1 STRICTLY OPEN**  

---

## 1. Repository State & Preflight Audit

A read-only preflight inspection was conducted across repository state, active branches, commits, and protected assets:

```
Repository Root: C:\Users\srisn\Desktop\Projects\sentinelai-complete
Active Branch: feature/gate1-phase8-multicorpus-candidates
HEAD Commit: e9f71a0c12562eb7cb07e896b5aa9f6ee737be98
Tracked File Working Tree Status: Clean (0 modified tracked files)
Safety Invariants:
  AUTONOMOUS_CONTAINMENT = false (Enforced in configuration & code)
  ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = false (Enforced in containmentService.js & WindowsFirewallAdapter.js)
Active SentinelAI Windows Firewall Rules: 0 rules (Verified via Get-NetFirewallRule)
Live Database Connection: 0 (No connection to live MongoDB sentinel-db authorized)
```

### Protected Asset Integrity (Bit-for-Bit Verification)
All 5 protected models and Q-tables were verified bit-for-bit against historical authoritative baselines:

| Protected Asset Path | Expected SHA-256 Baseline | Audited SHA-256 Hash | Byte Drift | Status |
| :--- | :--- | :--- | :---: | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | 0 B | **CONFIRMED MATCH** |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | 0 B | **CONFIRMED MATCH** |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | 0 B | **CONFIRMED MATCH** |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | 0 B | **CONFIRMED MATCH** |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | 0 B | **CONFIRMED MATCH** |

Candidate Model Staged in Phase 8:  
`ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl`  
SHA-256: `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` (Confirmed match with Phase 8 manifest).

---

## 2. Phase 9A Findings Classification Matrix

Each conclusion and finding from Phase 9A was audited and categorized according to the required evidence standards:

| Finding ID | Phase 9A Reported Finding | Auditor Verdict | Classification | Evidence & Basis |
| :---: | :--- | :---: | :---: | :--- |
| **FND-01** | **Benign Point FPR = 0.0333% (10 / 30,000)** | Verified | **CONFIRMED** | Direct reproduction via `reproduce_phase8_metrics.py`: exactly 10 FP, 29,990 TN. |
| **FND-02** | **Benign FPR 95% Wilson Upper Bound = 0.0614%** | Verified | **CONFIRMED** | Mathematical recalculation of two-sided 95% Wilson interval yields [0.0181%, 0.0614%]. Strictly $< 0.1000\%$. |
| **FND-03** | **SSH & FTP Brute Force Recall = 71.20% (1,424 / 2,000)** | Verified | **CONFIRMED** | Directly reproduced on `holdout_bruteforce_ssh_ftp.parquet`: FTP = 91.50% (915/1,000), SSH = 50.90% (509/1,000). |
| **FND-04** | **Botnet Recall = 60.85% (1,217 / 2,000)** | Verified | **CONFIRMED** | Directly reproduced on `holdout_botnet.parquet`: 1,217 TP, 783 FN. |
| **FND-05** | **Transport-Only Web Attack Recall = 0.35% (2 / 566)** | Verified | **CONFIRMED** | Directly reproduced on `holdout_web_attacks.parquet`: candidate ML detected only 2 / 566 attacks. |
| **FND-06** | **Combined Web Attack Recall = 100.00% (566 / 566)** | Disclosed | **PARTIALLY CONFIRMED (SIMULATED)** | Source inspection of `run_phase8_experiments.py` proved detection was simulated from ground-truth labels. No actual HTTP payload inspection was performed. |
| **FND-07** | **Infiltration Recall = 0.15% (3 / 2,000)** | Verified | **CONFIRMED** | Directly reproduced on `holdout_infiltration.parquet`: 3 TP, 1,997 FN. |
| **FND-08** | **DDoS HOIC/LOIC Recall = 0.00% (0 / 2,000)** | Verified | **CONFIRMED** | Directly reproduced on `holdout_ddos.parquet`: 0 TP, 2,000 FN. |
| **FND-09** | **DDoS Morphology Shift Hypothesis** | Plausible | **INFERRED** | High plausibility: Training had connection-exhaustion DoS (Slowloris/GoldenEye); holdout had volumetric HTTP GET floods (HOIC). Needs empirical verification with HOIC training data. |
| **FND-10** | **SSH Daemon Cipher Hypothesis** | Unproven | **UNVERIFIED** | Plausible that Ubuntu vs Amazon Linux cipher suite differences altered initial handshake bytes, but not empirically proven against raw PCAPs. |
| **FND-11** | **Benign Control Independence in Infil/Web Slices** | Disproven | **CONTRADICTED** | 100% of benign controls in Infiltration and Web Attack slices duplicate rows in `holdout_benign_30k.parquet` due to identical `random_state=42`. |
| **FND-12** | **Zero Exact Holdout Row Leakage** | Verified | **CONFIRMED** | Evaluated 179,458 training and 31,623 validation rows against 40,774 holdout hashes: exactly 0 matching rows. |

---

## 3. Existing Architecture & Interface Inventory

The current codebase interfaces were inspected to ground the Phase 9B design in actual code realities:

1. **Inference Entry Point (`ai-engine/inference/predictor.py`)**:
   - `SentinelPredictor.predict(record: dict, explain: bool = False) -> dict`
   - Consumes a single flow dictionary, extracts 53 features via `extract_features_from_record()`, runs `rf.predict_proba()` and `ifo.score_samples()`.
   - Generates a single coupled threat score: `score = 0.7 * rf_s + 0.3 * if_sig`.
   - *Limitation*: Strictly assumes a single monolithic transport flow vector. Does not accept Layer 7 payloads, authentication event streams, or endpoint telemetry.
2. **Backend AI Engine Client (`backend/services/aiEngineService.js`)**:
   - Communicates with `http://localhost:8000/predict/internal` via Axios with timeout (10,000 ms) and `X-API-Key` authentication.
   - Handles HTTP 422 input validation errors, falling back to safe closed states.
3. **Threat Service & Policy Resolution (`backend/services/threatService.js`)**:
   - Consumes `aiScore` and `status` from AI Engine.
   - Evaluates:
     * `status === 'DEGRADED'` -> persists status as `DEGRADED`.
     * `score >= blockThreshold && autoBlockEnabled` -> status `BLOCKED`, triggers `containmentService.executeAutoBlock()`.
     * `score >= 0.70` -> status `MONITORING`.
     * Otherwise -> status `DETECTED`.
   - Populates MongoDB `ThreatLog` and emits Socket.IO event `threat:new`.
4. **Containment Service & Safety Boundary (`backend/services/containmentService.js`)**:
   - Checks `realEnforcementEnabled: process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'`.
   - When false, routes calls to simulated adapter logging without touching OS firewall.
5. **Feature Schema (`ai-engine/utils/features.py`)**:
   - Baseline: `v2.1_53feat` (53 features).
   - Phase 8 Candidate Schema F: 51 features (raw TCP window sizes dropped, microsecond timing and volume log1p-transformed, header lengths packet-normalized).
