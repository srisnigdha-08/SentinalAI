# SentinelAI GATE-1 — Phase 14.2: Heartbleed & Class Coverage Forensic Audit

**Phase:** GATE-1 Phase 14.2 — Independent Incident Verification and Acceptance Contract Audit  
**Date:** October 18, 2026  
**Investigated Criterion:** Criterion C2 (Class Coverage: 10 Classes)  
**Investigated Class:** Class 5 ("RCE Attempt" / "Heartbleed")  
**Investigation Status:** **VERIFIED & AUDITED / BLOCKED ON OWNER DECISION 2**

---

## 1. Executive Summary & Verification Highlights

This audit verified the sample distribution, statistical generalization limits, taxonomy alignment, and architectural alternatives for Heartbleed (Class 5) under Criterion C2.

```
┌───────────────────────────────────────┬────────────────────────────────────────────────────────────┐
│ Audit Item                            │ Verified Fact & Technical Finding                          │
├───────────────────────────────────────┼────────────────────────────────────────────────────────────┤
│ 1. Population Across Corpora          │ Exactly 11 flows in 2017 Wednesday; 0 flows in 2018. Total=11│
│ 2. Test Sample Count (80/20 Split)    │ 8 train / 3 test samples. Single error swings recall 33.3%.│
│ 3. Wilson 95% Confidence Interval     │ k=3, n=3: [0.4385, 1.0000] (Width = 56.15 percentage pts). │
│ 4. Taxonomy & Label Mismatch          │ Heartbleed is CVE-2014-0160 Info Disclosure; NOT RCE.      │
│ 5. Proposed Layer 7 Alternative       │ Protocol sound (RFC 6520), but NOT YET IMPLEMENTED in code.│
│ 6. System vs Model Coverage           │ Tabular model has 9 classes; 10-class system needs L7 rule.│
│ 7. Contract Governance                │ Contract Sec 7: Class 5 cannot be silently dropped/remapped│
└───────────────────────────────────────┴────────────────────────────────────────────────────────────┘
```

---

## 2. Verification of Sample Counts and Dataset Provenance

### 2.1 Complete Corpus Census
Every file in both public benchmark corpora was audited using SentinelAI's complete dataset census:
- **Primary Source 1:** [`ai-engine/experiments/gate1_phase13_shift_and_leakage/dataset_census_all_corpora.csv#L41`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/dataset_census_all_corpora.csv#L41):
  ```csv
  Corpus,File,Raw Label,Count,Target Label,Target Class
  CICIDS2017,Wednesday-workingHours.pcap_ISCX.csv,Heartbleed,11,RCE Attempt,5
  ```
- **Primary Source 2:** [`ai-engine/experiments/gate1_phase13_shift_and_leakage/class5_heartbleed_audit.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase13_shift_and_leakage/class5_heartbleed_audit.json) lines 6–14:
  - `CICIDS2017`: `Wednesday-workingHours.pcap_ISCX.csv` = **11 flows**.
  - `CSE-CIC-IDS2018`: Across all 10 CSVs = **0 flows**.
  - **Total Population across all corpora:** **11 flows**.

---

## 3. Mathematical Proof: Statistical Generalization on $N = 11$

### 3.1 Test Sample Count Under Standard Splitting
If the available 11 flows are partitioned using a standard 80% train / 20% test protocol:
- Training partition: $11 \times 0.80 = 8.8 \approx \mathbf{8 \text{ flows}}$.
- Test partition: $11 - 8 = \mathbf{3 \text{ flows}}$.

### 3.2 Sensitivity and Confidence Interval Width
With $n = 3$ test flows, statistical evaluation suffers from extreme discrete sensitivity:
- If all 3 flows are detected ($k = 3, n = 3$), measured recall is $100.0\%$.
- If 1 flow is missed ($k = 2, n = 3$), measured recall drops by **33.3 percentage points** to **66.7%**.
- If 2 flows are missed ($k = 1, n = 3$), measured recall drops to **33.3%**.

Evaluating the 95% Wilson score confidence interval:
$$\tilde{n} = n + z^2 = 3 + (1.95996)^2 = 6.8414$$
$$\tilde{p} = \frac{k + \frac{z^2}{2}}{\tilde{n}} = \frac{3 + 1.9208}{6.8414} = 0.7193$$
$$\text{Margin} = \frac{1.95996}{6.8414} \sqrt{\frac{3(0)}{3} + \frac{(1.95996)^2}{4(9)}} = 0.2807$$
$$\text{CI}_{95\%}(k=3, n=3) = [\mathbf{0.4385}, \mathbf{1.0000}]$$

- **Verified CI Width:** $1.0000 - 0.4385 = \mathbf{0.5615}$ (**56.15 percentage points**).
- If $k = 2, n = 3$:
  $$\text{CI}_{95\%}(k=2, n=3) = [\mathbf{0.2077}, \mathbf{0.9385}] \quad (\text{Width} = 73.08 \text{ percentage points})$$

### 3.3 Evaluation Verdict
- **Finding:** A statistical machine learning model cannot establish statistically significant generalization on $N = 3$ test samples.
- The 95% confidence interval for perfect test performance ($[0.4385, 1.0000]$) straddles the 50%, 70%, and 80% marks. It is statistically inconclusive whether true population recall is above or below random guessing.

---

## 4. Taxonomy & Semantic Alignment Audit

### 4.1 Vulnerability Specification: CVE-2014-0160
- **Official Vulnerability Type:** Information Disclosure (Buffer over-read in OpenSSL TLS Heartbeat Extension, RFC 6520).
- **Attack Mechanics:** The attacker sends a malicious TLS Heartbeat Request containing a 1-byte payload but declares the payload length field as $65,535$ bytes ($64$ KB). The vulnerable server allocates a $64$ KB buffer and `memcpy`s $64$ KB from the request buffer without bounds-checking, leaking private encryption keys, session cookies, and credentials from server memory.
- **RCE Capability:** It does **NOT** permit arbitrary code execution, instruction pointer overwrite, or remote shell execution.
- **SentinelAI Label Mapping Defect:**
  In `ai-engine/utils/features.py` lines 39 and 55:
  ```python
  LABEL_MAP = { ... "RCE Attempt": 5 ... }
  RAW_LABEL_TO_TARGET = { ... "Heartbleed": "RCE Attempt" ... }
  ```
  Classifying Heartbleed as `"RCE Attempt"` is a domain taxonomy defect inherited from early prototype label mappings.

---

## 5. Status of the Proposed Layer 7 Signature Alternative

### 5.1 Protocol-Level Soundness (RFC 6520)
At Layer 7, Heartbleed is deterministically detectable by inspecting the TLS record header:
- A TLS Heartbeat record has Content Type `0x18` (24).
- The heartbeat message specifies `Type` (1 byte, `0x01` for request) and `Payload Length` (2 bytes, 16-bit integer).
- **Detection Invariant:** If `TLS_Record_Length < Payload_Length + 3`, the request is mathematically guaranteed to be an exploit attempt. This enables 100% deterministic detection with 0% false positives, independent of packet flow statistics.

### 5.2 Current Implementation Status in Codebase
A comprehensive search across `ai-engine/modular/` and all Python source files confirms:
- **Finding:** **NO Layer 7 Heartbleed or TLS record inspection detector currently exists in the SentinelAI codebase.**
- The Layer 7 alternative was recommended in Phase 14 based on network security research, but it remains a **PROPOSED REMEDIATION**, not an existing implemented capability.

---

## 6. Distinguishing System-Level Coverage from Tabular Model Coverage

Under the authoritative acceptance contract:

1. **Tabular Flow Model Coverage (Current State):**
   - Both `candidate_rf_multicorpus_v2_fixed.pkl` and `candidate_rf_multicorpus_v3.pkl` possess `classes_ = [0, 1, 2, 3, 4, 6, 7, 8, 9]`.
   - The tabular model covers **9 classes**. Class 5 is entirely omitted from the tree structures.
2. **Whole-System Intrusion Detection Coverage:**
   - Criterion C2 mandates `Class coverage (10 classes)`.
   - To achieve full 10-class coverage across the SentinelAI platform, Heartbleed must be assigned to a dedicated modular detector (Layer 7 TLS Heartbeat Validator), while the statistical flow model handles the remaining 9 classes.
3. **Contract Constraint:**
   - Contract Section 7 strictly dictates:
     > *"Class 5 is not silently redefined or dropped. It stays FAIL/BLOCKED until the owner chooses."*
   - Therefore, the agent must NOT delete Class 5 from `features.py` or claim Criterion C2 has passed until the owner formally approves **Owner Decision 2**.

- **Criterion C2 Verdict:** **FAIL / BLOCKED ON OWNER DECISION 2**.
