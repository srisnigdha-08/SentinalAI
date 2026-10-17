# SentinelAI GATE-1 Phase 9A: Web Attack Combined Policy Audit

**Auditor / Lead ML Evaluation Engineer**: Senior Machine Learning Security Engineer & Independent Security-Systems Auditor  
**Date**: 2026-10-16  
**Execution Context**: Read-Only Independent Technical Audit (Non-Production)  
**Dedicated Branch**: `feature/gate1-phase8-multicorpus-candidates`  
**Base Commit**: `e9f71a0c12562eb7cb07e896b5aa9f6ee737be98`  

---

## 1. Population Discrepancy & Comparability Reconciliation

The previous reports cite two distinct Web Attack evaluation results:
- **Phase 7 Report**: 143 detections across 150 attacks (**95.33% recall**), 113 simulated blocks (**75.33%**), and 0 false alarms on 150 controls (**0.00% FPR**).
- **Phase 8 Report**: 2 detections across 566 attacks on transport alone (**0.35% recall**), but 566 detections across 566 attacks on combined policy (**100.00% recall**), and 206 simulated blocks (**36.40%**).

### Auditor Reconciliation
These two evaluations were conducted on fundamentally different datasets and test environments:

| Evaluation Dimension | Phase 7 L7 Prototype Benchmark | Phase 8 Holdout Evaluation |
| :--- | :--- | :--- |
| **Data Artifact** | Synthetic HTTP payload corpus in `layer7_prototype.py` | Authentic CSV flow extraction in `holdout_web_attacks.parquet` |
| **Dataset Source** | Developer-authored test strings (OWASP patterns) | CSE-CIC-IDS2018 Friday-23-02-2018 capture |
| **Data Nature** | Raw application-layer HTTP URIs, headers, bodies | Network-layer flow statistical summaries (CICFlowMeter) |
| **Attack Population ($N$)** | $N = 150$ synthetic payloads | $N = 566$ network flow summary vectors |
| **Subtype Counts** | SQLi (30), XSS (30), Path Traversal (30), Command Inj (30), Auth BF (30) | Brute Force - Web (362), Brute Force - XSS (151), SQL Injection (53) |
| **Benign Controls ($N$)** | $N = 150$ synthetic normal HTTP requests | $N = 1,000$ benign network flows |

The two populations are **not directly comparable**. Phase 7 tested a regex payload engine on text strings. Phase 8 tested flow classifiers on network vectors.

---

## 2. Implementation Audit: How L7 Was Evaluated in Phase 8

A source-code audit of `run_phase8_experiments.py` (lines 339–358) revealed how the "Combined Policy" was actually calculated:

```python
# Extract from run_phase8_experiments.py:
# Tier 2: Layer 7 WAF (HTTP payload inspection)
t2_det = False
t2_blk = False
if "web_attacks" in fn and att:
    # Simulating L7 payload inspection on HTTP exploits
    if gt_lbl in ("SQL Injection", "XSS Attempt"):
        t2_det = True
        t2_blk = True
    elif gt_lbl == "Credential Stuffing":
        t2_det = True
        t2_blk = False

# Tier 3: Combined Defense Policy
t3_det = (t1_det or t2_det)
t3_blk = (t1_blk or t2_blk)
```

### Critical Auditor Finding
1. **Flow Parquets Do Not Contain HTTP Payloads**:
   `holdout_web_attacks.parquet` contains 53 numerical summary metrics (flow duration, packet lengths, inter-arrival times, header bytes). It does **not** contain HTTP request bodies, URIs, or headers.
2. **L7 Regex Engine Was Bypassed**:
   The Phase 8 evaluation script did **not** execute `Layer7PreFilter.inspect_payload()`. It could not, because there were no string payloads in the Parquet file to inspect.
3. **Simulated Ground-Truth Mapping**:
   Instead, the script assumed that *if* an attack is an SQL Injection or XSS, a functional Layer 7 WAF would detect and block it.
4. **Auditor Verdict**:
   The 566/566 (100.00%) combined Web Attack detection figure is an **architectural simulation based on ground-truth label presence**, not an empirical test of network packets passing through a live WAF!

---

## 3. Empirical Transport Model Performance on Web Attacks

Evaluating the actual candidate machine learning model ([`candidate_rf_multicorpus_v1.pkl`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase8_multicorpus_candidates/candidate_rf_multicorpus_v1.pkl)) on the 566 genuine web attack flows yielded:

```
Total Web Attack Flows: 566
- Brute Force - Web: 362 flows
- Brute Force - XSS: 151 flows
- SQL Injection: 53 flows

Actual Machine Learning Model Detections (Tier 1):
- Detected (TP): 2 flows (0.3534% recall)
- Missed (FN): 564 flows (99.6466% miss rate)
- Subtype breakdown:
  * Brute Force - Web: 2 detected / 362 (0.55%)
  * Brute Force - XSS: 0 detected / 151 (0.00%)
  * SQL Injection: 0 detected / 53 (0.00%)
```

### Technical Root Cause
HTTP web exploits (such as `' OR 1=1 --` or `<script>alert(1)</script>`) typically execute within a single normal-sized HTTP GET or POST request. At the transport layer, their packet count, inter-arrival time, and flow duration are identical to ordinary web browsing. Transport ML alone has near-zero capability to detect application-layer web exploits.

---

## 4. Control Slice Overlap & Contamination

The 1,000 benign control flows in `holdout_web_attacks.parquet` were audited against `holdout_benign_30k.parquet`:

```
holdout_web_attacks.parquet Benign Controls: 1,000 rows
Matching Rows in holdout_benign_30k.parquet: 1,000 rows
Overlap Rate: 100.00%
```

### Auditor Disclosure
Because `preprocess_cse2018.py` used the exact same pseudo-random seed (`random_state=42`) when sampling benign flows from Friday-23-02-2018, **every single benign flow in the Web Attack holdout is a duplicate of a row in the 30k benign holdout**. The 0 / 1,000 FPR is therefore redundant with the 30k evaluation, not an independent measurement.

---

## 5. Auditor Verdict & Evidence Classification

| Evaluated Claim | Verdict | Classification | Evidence |
| :--- | :---: | :---: | :--- |
| **Transport Model Web Recall = 0.35%** | **CONFIRMED** | Empirically Verified | 2 detections across 566 flows produced by `candidate_rf_multicorpus_v1.pkl`. |
| **Combined Policy Web Recall = 100.00%** | **UNVERIFIED EMPIRICALLY** | Architectural Simulation | Code audit proved L7 regex was not run on packet bytes; detection was simulated from ground-truth labels. |
| **Benign Web Control FPR = 0.00%** | **POTENTIALLY CONTAMINATED** | 100% Overlap | All 1,000 benign controls duplicate rows in `holdout_benign_30k.parquet`. |
| **Phase 7 (95.33%) vs Phase 8 (100.0%)** | **RESOLVED** | Distinct Populations | Phase 7 used 150 synthetic text payloads; Phase 8 used 566 flow summary vectors. |
