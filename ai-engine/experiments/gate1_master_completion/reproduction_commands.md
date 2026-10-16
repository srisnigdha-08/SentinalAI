# SentinelAI GATE-1 — Master Reproduction Commands and Verification Guide
**Phase:** Gate-1 Master Completion  
**Target Environment:** Windows PowerShell / Python 3.13 / Node.js 24  
**Working Directory:** `C:\Users\srisn\Desktop\Projects\sentinelai-complete`  

This document provides exact, deterministic commands to reproduce every test, audit, evaluation, and asset integrity verification executed during GATE-1 completion.

---

## 1. Protected Asset Integrity Check (5/5 Hashes)
Run this command from the repository root to verify that all baseline and candidate models have 0 bytes of drift:
```powershell
python -c "import hashlib; from pathlib import Path; assets = {'ai-engine/models/q_table.json': 'bf9b46a1d1cf1b283797a544e7e597900b4a042e6c87ac199a3cc709498990ff', 'ai-engine/models/rf_classifier_cicids_v2.pkl': 'ca0efb1fde8f9bdc430c3c511e32cd91822b0f3deeca845aa259bc8dd60023f1', 'ai-engine/models/isolation_forest_cicids.pkl': '17bd08ffe105a3ea87de85e0943761e7cb012abd70537968e14d0a3394e19da4', 'ai-engine/models/xgb_classifier_cicids_v2.pkl': 'a5d630b471b0385bd270e579d44adfeb628b1569284e5c821a282bda0a7d210d', 'ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl': '71a1756e64fe1d1199be03e5ba71105c9338294c977110dc0ba5ec8b31952020'}; [print(f'{Path(p).name}: MATCH' if hashlib.sha256(Path(p).read_bytes()).hexdigest().lower() == exp.lower() else f'{Path(p).name}: DRIFT') for p, exp in assets.items()]"
```
**Expected Output:** All 5 assets return `MATCH`.

---

## 2. Host Windows Firewall Invariant Check
Verify that zero SentinelAI firewall rules have been added to the host operating system:
```powershell
netsh advfirewall firewall show rule name=all | Select-String "SentinelAI"
```
**Expected Output:** Empty output (0 rules matched).

---

## 3. Modular Scaffold Tests (Remediations DEF-01 Through DEF-05)
Run the 43 modular scaffold unit and contract tests:
```powershell
python -m pytest ai-engine/tests/test_modular_scaffold.py -v
```
**Expected Output:** `43 passed in ~1.5s`.

---

## 4. Specialized Modular Detector Test Suites
### 4.1 B1 Volumetric Flood Detector (15 tests)
```powershell
python -m pytest ai-engine/tests/test_volumetric_flood.py -v
```
**Expected Output:** `15 passed in ~0.8s`.

### 4.2 E2 Auth Abuse & E4 Layer 7 WAF Detectors (14 tests)
```powershell
python -m pytest ai-engine/tests/test_auth_and_waf_detectors.py -v
```
**Expected Output:** `14 passed in ~1.0s`.

---

## 5. Comprehensive AI Engine Test Suite (226 Tests)
Run the full Python test suite across all engines, pipelines, honeypots, features, and safety wrappers:
```powershell
python -m pytest ai-engine/tests -v
```
**Expected Output:** `226 passed, 283 warnings in ~108s`.

---

## 6. Backend Safety and Integration Regression Suite (512 Tests)
Run the Node.js / Jest test suite from the `backend/` directory:
```powershell
cd backend
npm test
cd ..
```
**Expected Output:** `Test Suites: 42 passed, 42 total. Tests: 512 passed, 512 total in ~130s`.

---

## 7. Master Empirical Holdout Evaluation
Run the automated holdout evaluation against `D:\sentinelai_datasets\cse_cic_ids2018\holdout_sets\`:
```powershell
python ai-engine/experiments/gate1_master_completion/run_gate1_master_evaluation.py
```
**Expected Output:**
- 30k Benign FPR: `0.0333%` (10/30,000), 95% Wilson CI: `[0.0181%, 0.0614%]`.
- SSH Brute Force: `50.90%` (509/1000).
- FTP Brute Force: `91.50%` (915/1000).
- Botnet: `60.85%` (1217/2000).
- HOIC DDoS: `0.00%` (0/1996).
- Infiltration: `0.15%` (3/2000).
- Web Attacks (Transport ML): `0.3534%` (2/566).
- L7 WAF Exploit Recall (OWASP): `97.00%` (97/100).
- Structured output saved to `master_evaluation_metrics.json`.
