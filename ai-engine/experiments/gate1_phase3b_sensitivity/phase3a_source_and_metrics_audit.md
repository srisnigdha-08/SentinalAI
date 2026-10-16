# SentinelAI GATE-1 Phase 3B: Phase 3A Source Code and Metrics Audit

**Audit Date:** October 16, 2026  
**Auditor / Roles:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Audit Target:** Phase 3A Candidate Policy Source (`candidate_policy.py`), Tests (`test_candidate_policy.py`), and Metrics (`baseline_vs_candidate_metrics.json`)  
**Status:** **AUTHORITATIVE RECONCILIATION COMPLETE**

---

## 1. Overview and Audit Purpose

The Phase 3A report demonstrated significant empirical improvements (PortScan policy recall recovering from 7.40% to 92.90%, and DDoS policy recall recovering from 76.60% to 99.70%). However, robust security engineering mandates that prior claims cannot be accepted simply because test scripts report a passing status.

This audit provides an independent, line-by-line inspection of the Phase 3A implementation, resolving 10 explicit discrepancies regarding decision rules, threshold boundaries, score transformations, statistical denominators, confidence intervals, and downstream integration contracts.

---

## 2. Explicit Reconciliation of the 10 Audit Items

### Item 1: Discrepancy Between 0.85 Hypothesis Threshold and 0.70 Attack Qualification
- **Question:** The report describes an experimental threshold of 0.85, but some decision descriptions use 0.70 as the qualifying attack-confidence threshold. Identify the exact executable rule for every branch.
- **Source Inspection:** In [`candidate_policy.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/candidate_policy.py#L138-L191):
  ```python
  if cname == "BENIGN":
      if is_anomaly:
          final_class = "Unknown"; score = 0.55  # Rule R-2
      else:
          score = 0.05                           # Rule R-1
  else:
      if p >= self.exp_conf_threshold:           # p >= 0.85
          if is_anomaly and sig > 0.0:
              score = min(p + 0.10 * sig, 0.99)  # Rule R-8
          else:
              score = p                          # Rule R-7
      elif p >= self.monitor_threshold:          # 0.70 <= p < 0.85
          if is_anomaly and sig > 0.0:
              score = min(p + 0.15 * sig, 0.919) # Rule R-6
          else:
              score = p                          # Rule R-5
      elif p >= 0.60:                            # 0.60 <= p < 0.70
          if is_anomaly and sig > 0.0:
              score = min(p + 0.20 * sig, 0.85)  # Rule R-4B
          else:
              score = round(p * 0.90, 4)         # Rule R-4A
      else:                                      # p < 0.60
          if is_anomaly and sig > 0.50:
              score = round(min(p + 0.25 * sig, 0.75), 4) # Rule R-3B
          else:
              score = round(p * 0.80, 4)         # Rule R-3A
  ```
- **Reconciliation:**
  - `0.70` (`MONITOR_THRESHOLD`) is the **containment qualification threshold**: any supervised attack with $P_{RF} \ge 0.70$ is guaranteed a threat score $S \ge 0.70$, ensuring at least a `MONITOR` action.
  - `0.85` (`EXPERIMENTAL_CONFIDENCE_THRESHOLD`) is the **autonomous block eligibility gate**: an attack flow must have $P_{RF} \ge 0.85$ before it is eligible to trigger `action = "BLOCK"`. Even if an attack with $P_{RF} \in [0.70, 0.85)$ exhibits maximum anomaly signal ($\sigma_{IF} = 1.0$), Rule R-6 explicitly caps its boosted score at `0.919`, strictly preventing it from crossing `BLOCK_THRESHOLD` ($0.920$).

---

### Item 2: Precise Treatment of Attack Confidence Slices
- **Question:** Specify what happens for attack predictions with confidence in `[0.70, 0.85)`, `[0.85, 0.92)`, and `>= 0.92`.
- **Executable Behavior:**
  1. **Slice 1: $P_{RF} \in [0.70, 0.85)$ (Medium-High Confidence)**
     - Inlier ($\sigma_{IF} = 0.0$): Rule R-5 executes. $S = P_{RF} \in [0.70, 0.85)$. Action is strictly **`MONITOR`**, status is `MONITORING`, severity is `HIGH`.
     - Outlier ($\sigma_{IF} > 0.0$): Rule R-6 executes. $S = \min(P_{RF} + 0.15 \cdot \sigma_{IF}, 0.919)$. Action is strictly **`MONITOR`** (capped at 0.919), status is `MONITORING`, severity is `HIGH`.
     - *Simulated BLOCK Eligibility:* **0.0%**.
  2. **Slice 2: $P_{RF} \in [0.85, 0.92)$ (High Confidence, Sub-Block)**
     - Inlier ($\sigma_{IF} = 0.0$): Rule R-7 executes. $S = P_{RF} \in [0.85, 0.92)$. Action is strictly **`MONITOR`**, status is `MONITORING`, severity is `HIGH`.
     - Outlier ($\sigma_{IF} > 0.0$): Rule R-8 executes. $S = \min(P_{RF} + 0.10 \cdot \sigma_{IF}, 0.99)$. If $P_{RF} + 0.10 \cdot \sigma_{IF} \ge 0.920$, action escalates to simulated **`BLOCK`**; otherwise remains **`MONITOR`**.
  3. **Slice 3: $P_{RF} \ge 0.92$ (Critical Supervised Confidence)**
     - Inlier ($\sigma_{IF} = 0.0$): Rule R-7 executes. $S = P_{RF} \ge 0.920$. Action is simulated **`BLOCK`**, status is `BLOCKED`, severity is `CRITICAL`, `autonomousBlockEligible: True`.
     - Outlier ($\sigma_{IF} > 0.0$): Rule R-8 executes. $S = \min(P_{RF} + 0.10 \cdot \sigma_{IF}, 0.99) \ge 0.920$. Action is simulated **`BLOCK`**, severity is `CRITICAL`.

---

### Item 3: Isolation Forest Transformation Mechanism
- **Question:** Explain precisely how the Isolation Forest output is transformed into the candidate's anomaly signal. Do not assume a raw Isolation Forest score is already a probability or a value between zero and one.
- **Source Inspection:** In [`candidate_policy.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/candidate_policy.py#L72-L91):
  ```python
  def calculate_if_anomaly_signal(if_score: Optional[float], offset: float = IF_DEFAULT_OFFSET) -> float:
      if if_score is None: return 0.0
      val = float(if_score)
      if np.isnan(val) or np.isinf(val): return 0.0
      if val >= offset:
          return 0.0
      deflection = offset - val
      return round(float(min(deflection / IF_ANOMALY_SPAN, 1.0)), 4)
  ```
- **Mathematical Specification:**
  - Raw scikit-learn `IsolationForest.score_samples(X)` outputs negative real values, typically centered around $-0.45$ to $-0.55$. It is **not a probability** and is **not bounded in $[0, 1]$**.
  - `IF_DEFAULT_OFFSET = -0.47402357424116837` represents the decision boundary trained on 10% contamination (`offset_`).
  - `IF_ANOMALY_SPAN = 0.20` defines the linear scaling interval down to the extreme saturation floor at $-0.6740$.
  - When $\text{val} \ge -0.4740$ (inlier / normal geometry): signal is strictly **`0.0000`**.
  - When $\text{val} < -0.4740$ (outlier): $\text{signal} = \min\left(\frac{-0.4740 - \text{val}}{0.20}, 1.0\right)$.
  - Saturated at **`1.0000`** for all $\text{val} \le -0.6740$.

---

### Item 4: Definitional Taxonomy of Telemetry, Scoring, and Action Terms
- **Question:** Distinguish predicted class, supervised attack probability, anomaly signal, composite score, telemetry status, policy action, and actual enforcement.
- **Authoritative Taxonomy:**
  1. **Predicted Class (`predictedClass`):** The categorical output label (`BENIGN`, `Port Scan`, `DDoS`, `Unknown`, etc.).
  2. **Supervised Attack Probability ($P_{RF}$ / `confidence`):** $\max_k P(Y=k \mid X) \in [0.0, 1.0]$ from Random Forest `predict_proba(X)`.
  3. **Anomaly Signal ($\sigma_{IF}$ / `anomalySignal`):** Bounded float in $[0.0, 1.0]$ representing normalized deflection below the contamination boundary.
  4. **Composite Threat Score ($S$ / `threatScore`):** Scalar in $[0.0, 1.0]$ output by the candidate decision rules.
  5. **Telemetry Status (`status`):** Operational state emitted to the backend database/UI: `ALLOW` ($S < 0.50$), `DETECTED` (informational telemetry, $0.50 \le S < 0.70$ or `Unknown`), `MONITORING` ($0.70 \le S < 0.92$), `BLOCKED` (simulated block decision, $S \ge 0.92$), `DEGRADED` (service failure), `INPUT_ERROR` (validation rejection).
  6. **Policy Action (`action`):** Recommendation tier: `ALLOW` ($S < 0.70$), `MONITOR` ($0.70 \le S < 0.92$), or `BLOCK` ($S \ge 0.92$).
  7. **Actual Enforcement:** Real host network interface blocking via Windows Firewall netsh commands. **Completely disabled** in local development (`AUTONOMOUS_CONTAINMENT=false`).

---

### Item 5: Simulated Policy Decisions vs. Actual Enforcement
- **Question:** Check whether the reported `BLOCK` metrics represent simulated policy decisions or actual enforcement. Use terminology consistent with the evidence.
- **Verification:**
  - In Phase 3A, `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` was verified as `False`.
  - The `test_safety_invariants_no_side_effects` test confirmed that zero firewall rules were created in Windows Defender Firewall.
  - Therefore, all reported `BLOCK` metrics represent **simulated policy decisions** (block-eligibility recommendations), NOT real network containment.
  - **Audit Requirement:** The term "Containment" must be qualified as "Simulated Policy Containment", and `BLOCK` recall must be labeled as **"Simulated Block-Decision Recall"**.

---

### Item 6: Flow Counts and Denominator Reconciliation
- **Question:** Verify that the 14,000-flow total and every confusion matrix reconcile to the exact underlying counts and denominators.
- **Inspection of [`baseline_vs_candidate_metrics.json`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/baseline_vs_candidate_metrics.json):**
  - **Monday Capture:** $N = 10,000$ (Negative: 10,000, Positive: 0).
    - Baseline: $\text{TN} = 10,000, \text{FP} = 0 \implies \text{Total} = 10,000$.
    - Candidate: $\text{TN} = 9,993, \text{FP} = 7 \implies \text{Total} = 10,000$.
  - **Friday DDoS Capture:** $N = 2,000$ (Negative: 1,000, Positive: 1,000).
    - Baseline: $\text{TN} = 1,000, \text{FP} = 0, \text{FN} = 234, \text{TP} = 766 \implies 1,000 + 1,000 = 2,000$.
    - Candidate: $\text{TN} = 1,000, \text{FP} = 0, \text{FN} = 3, \text{TP} = 997 \implies 1,000 + 1,000 = 2,000$.
  - **Friday PortScan Capture:** $N = 2,000$ (Negative: 1,000, Positive: 1,000).
    - Baseline: $\text{TN} = 1,000, \text{FP} = 0, \text{FN} = 926, \text{TP} = 74 \implies 1,000 + 1,000 = 2,000$.
    - Candidate: $\text{TN} = 991, \text{FP} = 9, \text{FN} = 71, \text{TP} = 929 \implies 1,000 + 1,000 = 2,000$.
  - **Grand Total:** $10,000 + 2,000 + 2,000 = 14,000$ flows.
  - **Status:** **Reconciled exactly** down to single-flow counts.

---

### Item 7: Recomputation of Wilson Score Confidence Intervals
- **Question:** Recompute all reported confidence intervals from the raw counts.
- **Formula:**
  For $k$ successes in $n$ trials with $z = 1.95996$:
  $$p = \frac{k}{n}, \quad \text{center} = \frac{p + \frac{z^2}{2n}}{1 + \frac{z^2}{n}}, \quad \text{margin} = \frac{z \sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
- **Recomputation Table:**

| Metric Slice | Raw Counts ($k / n$) | Point Estimate | Reported 95% Wilson CI | Recomputed 95% Wilson CI | Discrepancy |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Monday Candidate FPR | $7 / 10,000$ | 0.070% | [0.034%, 0.144%] | [0.0339%, 0.1445%] | None |
| Monday Baseline FPR | $0 / 10,000$ | 0.000% | [0.000%, 0.038%] | [0.0000%, 0.0384%] | None |
| Friday DDoS Cand. Recall | $997 / 1,000$ | 99.700% | [99.122%, 99.898%] | [99.122%, 99.898%] | None |
| Friday DDoS Base. Recall | $766 / 1,000$ | 76.600% | [73.877%, 79.119%] | [73.877%, 79.119%] | None |
| Friday PortScan Cand. Recall | $929 / 1,000$ | 92.900% | [91.139%, 94.333%] | [91.139%, 94.333%] | None |
| Friday PortScan Base. Recall | $74 / 1,000$ | 7.400% | [5.936%, 9.191%] | [5.936%, 9.191%] | None |
| Friday PortScan Cand. FPR | $9 / 1,000$ | 0.900% | [0.474%, 1.702%] | [0.474%, 1.702%] | None |

All reported confidence intervals recompute exactly.

---

### Item 8: Monday FPR 95% Wilson Upper Bound Acceptance Discrepancy
- **Question:** Check the Monday result: 7/10,000 is 0.07%, but the reported 95% Wilson upper bound is 0.144%. Explicitly state that it does not satisfy an acceptance rule requiring the upper bound to be below 0.10%.
- **Authoritative Audit Finding:**
  - Point estimate: $\hat{p} = 7 / 10,000 = 0.07\% < 0.10\%$.
  - 95% Wilson Upper Bound: **$0.1445\%$ ($> 0.10\%$)**.
  - **Verdict:** If an acceptance criterion strictly requires that the **95% Wilson upper confidence bound** must be strictly below 0.10%, the Monday evaluation **FAILS** that requirement.
  - To achieve an upper bound $< 0.10\%$ with a true false-positive rate of $0.07\%$, a minimum sample size of $N \ge 35,000$ independent benign flows would be required, or the false positive count on $N = 10,000$ would need to be $k \le 3$ (where $k=3 \implies \text{CI: } [0.010\%, 0.088\%]$).

---

### Item 9: Reconciliation of PortScan Benign FPR (0.90%) vs. Monday FPR (0.07%)
- **Question:** Reconcile the PortScan benign policy-action FPR of 0.90% with the separate Monday policy-action FPR of 0.07%. Do not combine distinct datasets or denominators.
- **Root-Cause Reconciliation:**
  1. **Distinct Denominators & Capture Contexts:**
     - Monday capture ($N = 10,000$) contains purely idle/routine enterprise traffic recorded on Monday morning.
     - Friday afternoon capture ($N = 1,000$ benign) contains ambient web and application server traffic active while PortScan attacks were simultaneously targeted at victim hosts.
  2. **Upstream Supervised Model Disparity:**
     - On Monday benign traffic: Raw Random Forest generated 45 false positives ($45 / 10,000 = 0.45\%$). Only 7 of these 45 reached $P_{RF} \ge 0.70$.
     - On Friday ambient benign traffic: Raw Random Forest generated 17 false positives ($17 / 1,000 = 1.70\%$). 9 of these 17 reached $P_{RF} \ge 0.70$.
  3. **Policy Action Attenuation in Both Environments:**
     - On Monday: Candidate policy reduced false alarms from $0.45\%$ (raw RF) down to $0.07\%$ (candidate policy).
     - On Friday: Candidate policy reduced false alarms from $1.70\%$ (raw RF) down to $0.90\%$ (candidate policy).
  4. **Prohibition of Pooling:**
     These two datasets must **never be pooled** into an aggregate denominator ($16 / 11,000 = 0.145\%$), because doing so masks the severe environment-specific variance of background network features.

---

### Item 10: Downstream Backend Interpretation and Audit Gap
- **Question:** Determine whether any existing tests assert only candidate outputs without testing downstream interpretation and audit behaviour.
- **Identified Defect:**
  In `test_candidate_policy.py`, `test_backend_schema_compatibility` verified dictionary keys and types, but did not test downstream consumption in `backend/services/threatService.js`:
  - In `backend/services/threatService.js` (lines 98–103):
    ```javascript
    let status = 'DETECTED'
    if (shouldBlock) {
      status = 'BLOCKED'
    } else if (score >= 0.7) {
      status = 'MONITORING'
    }
    ```
  - When the candidate policy handles an inference failure with `threatScore = 0.50` and `status = "DEGRADED"`, `threatService.js` overwrites this with `status = "DETECTED"`, completely hiding the degraded status from SOC operators!
  - Furthermore, `threatService.js` does not record `failureType`, `isFailSafe`, or `requiresHumanReview`.
  - This gap is formally analyzed and tested in Phase 3B.
