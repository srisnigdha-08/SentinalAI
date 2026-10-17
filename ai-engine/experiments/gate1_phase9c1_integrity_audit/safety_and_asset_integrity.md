# SentinelAI GATE-1 Phase 9C.1: Safety Boundaries & Asset Integrity Audit

**Auditor**: Senior Security Architect & Independent Security-Systems Reviewer  
**Date**: 2026-10-17  
**Execution Context**: Read-Only Cryptographic Asset Audit & Safety Invariants Check  

---

## 1. Safety Flag & Runtime Configuration Audit

The auditor inspected the operational configuration across the backend and AI Engine codebases:

| Safety Parameter | Required State | Observed Runtime State | Audit Verdict |
| :--- | :---: | :---: | :---: |
| `ENABLE_EXPERIMENTAL_MODULAR_DETECTORS` | `false` | `False` (Verified: `is_modular_enabled() == False`) | **LOCKED** |
| `AUTONOMOUS_CONTAINMENT` | `false` | `false` (Verified in backend env and controllers) | **LOCKED** |
| `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` | `false` | `false` (Verified in containment adapters) | **LOCKED** |
| **Active Windows Firewall Netsh Rules** | 0 rules | 0 rules (Verified via `Get-NetFirewallRule`) | **CONFIRMED** |
| **Active MongoDB Database Writes** | 0 writes | 0 writes (MongoDB not connected during audit) | **CONFIRMED** |
| **Active Service Process Mutations** | 0 restarts | Zero processes started, stopped, or signaled | **CONFIRMED** |

---

## 2. Cryptographic Asset Integrity Audit (SHA-256)

All protected machine learning models, baseline reinforcement tables, and experimental candidate models were audited against documented baselines:

| Component / Artifact | File Path | Baseline SHA-256 Hash | Audited SHA-256 Hash | Drift Status |
| :--- | :--- | :--- | :--- | :---: |
| **Baseline Q-Table** | `ai-engine/models/q_table.json` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | **MATCH (0 B drift)** |
| **Active Random Forest** | `ai-engine/models/rf_classifier_cicids_v2.pkl` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1` | **MATCH (0 B drift)** |
| **Active Isolation Forest** | `ai-engine/models/isolation_forest_cicids.pkl` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | `17BD08FFE105A3EA87DE85E0943761E7CB012ABD70537968E14D0A3394E19DA4` | **MATCH (0 B drift)** |
| **Candidate XGBoost** | `ai-engine/models/xgb_classifier_cicids_v2.pkl` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | `A5D630B471B0385BD270E579D44ADFEB628B1569284E5C821A282BDA0A7D210D` | **MATCH (0 B drift)** |
| **Phase 8 Candidate RF** | `ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | `71A1756E64FE1D1199BE03E5BA71105C9338294C977110DC0BA5EC8B31952020` | **MATCH (0 B drift)** |

---

## 3. Explanatory Note on `ai-engine/runtime/q_table.json`

- `ai-engine/runtime/q_table.json` is an unversioned, ignored file (listed in `.gitignore`).
- When the automated test `test_q_table_safety.py` runs, it tests whether unauthorized writes to `ai-engine/models/q_table.json` are intercepted. The intercept logic in `DeceptionQLearner.save()` redirects the write into `ai-engine/runtime/q_table.json` and embeds a live timestamp (`saved_at: datetime.now(timezone.utc).isoformat()`).
- Consequently, running the full test suite causes `runtime/q_table.json`'s hash to update dynamically.
- **Auditor Certification**: The protected baseline model `ai-engine/models/q_table.json` is completely immune to writes and matches its historical SHA-256 hash bit-for-bit.
