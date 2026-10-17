# SentinelAI GATE-1 Phase 8: Preflight and Integrity Audit

**Auditor / ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Offline Experimental Candidate-Development (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  
**Gate Status**: **GATE-1 STRICTLY OPEN**  

---

## 1. Repository State & Working Tree Audit

A comprehensive preflight check was conducted prior to executing any candidate training, partitioning, or feature transformation.

```
Repository Root: c:\Users\srisn\Desktop\Projects\sentinelai-complete
Active Branch: feature/gate1-phase8-multicorpus-candidates (branched from e9f71a0)
Current HEAD: e9f71a0c12562eb7cb07e896b5aa9f6ee737be98
Parent Commit: e9f71a0c12562eb7cb07e896b5aa9f6ee737be98
Tracked File Status: 0 modified tracked files (Clean working tree)
```

No existing user files or previous experiment artifacts from Phases 1 through 7 were reset, cleaned, amended, or overwritten.

---

## 2. Protected Model & Q-Table Cryptographic Integrity (Pre-Training Baseline)

All active models, candidate models from earlier phases, and reinforcement learning Q-tables were hashed using SHA-256.

| Protected Asset Path | Expected SHA-256 Hash | Preflight Verified SHA-256 Hash | Byte Drift | Status |
| :--- | :--- | :--- | :---: | :---: |
| `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | 0 B | **VERIFIED MATCH** |
| `ai-engine/runtime/q_table.json` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27` | 0 B | **VERIFIED MATCH** |
| `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | 0 B | **VERIFIED MATCH** |
| `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | 0 B | **VERIFIED MATCH** |
| `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | 0 B | **VERIFIED MATCH** |

All protected model assets match historical authoritative baselines with 0 bytes drift.

---

## 3. Mandatory Safety Flags & System Boundary Verification

```
AUTONOMOUS_CONTAINMENT = false (Enforced in application configuration and services)
ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = false (Enforced in containmentService.js & WindowsFirewallAdapter.js)
Active SentinelAI Windows Firewall Rules = 0 (Confirmed via Get-NetFirewallRule)
Live Database Connection = 0 (No connection to live MongoDB sentinel-db authorized)
```

No network packets, firewall rules, or live service signals were generated or transmitted.

---

## 4. Storage & Dataset Preflight

A preflight check of storage volumes and dataset locations confirmed:
- **C: System Drive**: 198.84 GB used / 201.95 GB total (3.10 GB free).
- **D: Secondary Storage**: 36.00 GB used / 250.00 GB total (214.00 GB free).
- **Dataset Policy**: No external datasets will be downloaded. All training and holdout data are sourced exclusively from verified on-disk corpora:
  * CICIDS2017: `ai-engine/datasets/cicids2017/` (8 CSVs, 864.84 MB)
  * CSE-CIC-IDS2018: `D:/sentinelai_datasets/cse_cic_ids2018/` (6 CSVs, 1.82 GB; 6 holdout Parquets, 3.73 MB)
- **Candidate Staging Isolation**: All candidate models, scripts, partitions, metrics, and logs are strictly confined to:
  `ai-engine/experiments/gate1_phase8_multicorpus_candidates/`
