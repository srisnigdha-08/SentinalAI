# SentinelAI GATE-1 Phase 5: Safety Preflight and Operational Scope

**Auditor / Implementation Engineer**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Date**: 2026-10-16  
**Active Working Branch**: `feature/gate1-phase5-layer7-prototype`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98` (Phase 4 candidate remediation)  
**Parent Baseline Commit**: `780619d` (Phase 3D backend safety patch) $\leftarrow$ `5ea7051` (`main` baseline)  
**Gate Status**: **GATE-1 REMAINS STRICTLY OPEN**  
**Autonomous Containment**: **DISABLED (`AUTONOMOUS_CONTAINMENT=false`)**  
**Host Firewall Enforcement**: **DISABLED (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`)**  

---

## 1. Safety and Preflight Verification

Before initiating any development, data analysis, or prototype execution in Phase 5, all operational invariants were audited against the repository state:

### 1.1. Working Directory and Git Status
- **Repository Root**: `c:\Users\srisn\Desktop\Projects\sentinelai-complete`
- **Current Branch**: `feature/gate1-phase5-layer7-prototype` (created directly from `feature/gate1-phase4-candidate-policy` at commit `e9f71a0`).
- **Isolation Policy**: No changes from Phase 5 will be merged into `main`, deployed to staging/production, or exposed to external networks.
- **Untracked Backups Preserved**: Pre-Phase 3D and Pre-Phase 4 backup snapshots (`*.orig-phase3d`) and previous experiment directories (`gate1_phase3d_backend_patch`, `gate1_phase3e_independent_verification`, `gate1_phase4_candidate_policy_validation`) remain untouched and intact.

### 1.2. Protected Runtime Asset Hashes (Pre-Phase 5 Verification)
All 5 protected machine-learning and reinforcement-learning assets were inspected using cryptographic SHA-256 hashing. All digests match the immutable repository baseline:

| Asset Name | Relative File Path | SHA-256 Digest | Status |
| :--- | :--- | :--- | :---: |
| **Baseline Q-Table** | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **MATCH VERIFIED** |
| **Runtime Q-Table** | `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | **MATCH VERIFIED** |
| **Random Forest Model** | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH VERIFIED** |
| **Isolation Forest Model** | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH VERIFIED** |
| **Candidate XGBoost Model** | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH VERIFIED** |

### 1.3. Service and Host System Safety
- **Network Ports Audited**: Local ports `5000` (Backend API), `8000` (AI Engine), `3000` (Frontend), and `27017` (MongoDB) were inspected via `Get-NetTCPConnection`. No live production services were running or altered.
- **Database Safety**: Zero read/write connections will be made to live `sentinel-db` or acceptance databases. All evaluations run offline against static CSV files and mock request streams.
- **Firewall Mutation Lock**: Zero Windows Firewall netsh/PowerShell rules will be created, modified, or deleted. All policy decisions in Phase 5 represent **simulated** classifications.
- **Secrets & Privacy Protection**: No API keys, credentials, tokens, or live session bodies will be recorded, logged, or exposed.

---

## 2. Mission Scope and Phase 5 Objectives

Phase 5 addresses the critical blockers identified at the conclusion of Phase 4:

1. **Reconciliation of Dataset Provenance**: Rigorously investigate and document the 19,036 vs. 23,036 evaluation entry counts, establishing a complete data manifest with explicit contamination status.
2. **Holdout Dataset Readiness Assessment**:
   - **Track A (CSE-CIC-IDS2018)**: Evaluate feasibility, provenance, schema mapping, and local availability. Document the missing-data limitation truthfully without fabrication.
   - **Track B (Authorized Canary Traffic)**: Design a compliant, passive capture and labeling framework addressing legal consent, TLS visibility, duplicate handling, and sample size requirements.
3. **Freezing Acceptance Criteria**: Formally establish and freeze the mathematical criteria for release gating (95% Wilson score upper bound $< 0.10\%$, per-attack recall $\ge 90.0\%$, $N \ge 30,000$ benign sample power) *before* prototype evaluation.
4. **Layer 7 Detection Prototype Development**: Build an isolated, HTTP-aware WAF/signature pre-filter to address the critical Web Attack detection blindspot observed in Layer 4 transport flow models.
5. **Multi-Configuration Evaluation**: Compare four distinct configurations on identical records:
   - **Configuration A**: Active Production Policy (Coupled RF + IF)
   - **Configuration B**: Phase 4 Candidate Flow Policy (Decoupled RF + IF)
   - **Configuration C**: Layer 7 Pre-Filter Alone (WAF signatures only)
   - **Configuration D**: Combined Layer 7 Pre-Filter + Flow Candidate Policy (Layered defense)
6. **Authoritative Gate Decision**: Deliver an evidence-backed audit report maintaining `GATE-1: OPEN`.
