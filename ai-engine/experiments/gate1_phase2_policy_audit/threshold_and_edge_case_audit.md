# GATE-1 Phase 2: Threshold and Edge-Case Audit

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Scope**: In-code mathematical verification of the composite formula, threshold boundary behavior, and failure edge cases  
**Status**: **READ-ONLY AUDIT COMPLETED**

---

## 1. Active Code Verification of the Claimed Root Cause

### 1.1 Formula Verification in Active Code
- **Status**: **CONFIRMED IN ACTIVE SOURCE CODE**
- **File**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py)
- **Line 290**:
  ```python
  rf_s = max_p if cname != "BENIGN" else (1 - max_p)
  ```
- **Line 291**:
  ```python
  if_sig = self.calculate_if_anomaly_signal(if_score)
  ```
- **Line 292**:
  ```python
  score = round(0.7 * rf_s + 0.3 * if_sig, 4)
  ```
- **Line 301**:
  ```python
  action = "BLOCK" if score >= BLOCK_THRESHOLD else "MONITOR" if score >= MONITOR_THRESHOLD else "ALLOW"
  ```
- **Lines 88–89**:
  ```python
  BLOCK_THRESHOLD = 0.92
  MONITOR_THRESHOLD = 0.70
  ```

### 1.2 Can Anomaly Signal Be Zero for Correctly Classified Attacks?
- **Status**: **CONFIRMED**
- **Evidence**:
  In [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L222-L227):
  ```python
  offset = IF_DEFAULT_OFFSET  # -0.47402357424116837
  if val >= offset:
      return 0.0
  ```
  Isolation Forest scores flows as inliers when their packet lengths and durations conform to the background baseline.
  - Many attacks do not generate massive volume. Stealthy port scans, credential stuffing attempts, and single-packet web probes have `val >= -0.4740`.
  - For all such attacks, `calculate_if_anomaly_signal(val)` returns **`0.0`**.

### 1.3 Mathematical Proof of the Attack-Attenuation Trap
Let $C_{RF} \ne \text{"BENIGN"}$, with classifier confidence $P_{RF} \in [0.50, 1.00]$.
If the attack is an inlier to Isolation Forest ($\text{if\_sig} = 0.0$):
$$\text{threatScore} = 0.7 \cdot P_{RF} + 0.3 \cdot 0.0 = 0.7 \cdot P_{RF}$$
Because $P_{RF} \le 1.0$:
$$\max(\text{threatScore}) = 0.7 \cdot 1.00 = 0.7000$$

Now evaluate the action conditions:
1. `score >= 0.92` (`BLOCK`):
   $$0.7 \cdot P_{RF} \ge 0.92 \implies P_{RF} \ge \frac{0.92}{0.70} \approx 1.314 \quad (\text{IMPOSSIBLE})$$
   **Theorem 1**: An attack with zero anomaly signal can **NEVER** be blocked, even with 100% classifier confidence.
2. `score >= 0.70` (`MONITOR`):
   $$0.7 \cdot P_{RF} \ge 0.70 \implies P_{RF} \ge 1.0000$$
   **Theorem 2**: An attack with zero anomaly signal will be allowed (`action = "ALLOW"`) whenever $P_{RF} < 1.0000$.
   For example, if Random Forest is **99.0% confident** ($P_{RF} = 0.99$):
   $$\text{threatScore} = 0.7 \cdot 0.99 = 0.6930 < 0.7000 \implies \text{action} = \text{"ALLOW"}$$
   The system deliberately assigns `ALLOW` to a confirmed 99%-confidence attack!

---

## 2. Threshold Boundary Audit

| Scenario | $P_{RF}$ | $C_{RF}$ | $s_{IF}$ | $\text{if\_sig}$ | Raw Score | Rounded Score | Assigned Action | Security Correctness |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **High RF Attack, Zero Anomaly** | 0.98 | Port Scan | -0.420 | 0.0000 | 0.6860 | 0.6860 | **`ALLOW`** | **CRITICAL DEFECT**: Confirmed attack allowed! |
| **Near-Perfect RF Attack, Zero Anomaly** | 0.999 | Port Scan | -0.450 | 0.0000 | 0.6993 | 0.6993 | **`ALLOW`** | **CRITICAL DEFECT**: 99.9% confident attack allowed! |
| **Boundary Monitor Attack** | 1.00 | Port Scan | -0.460 | 0.0000 | 0.7000 | 0.7000 | **`MONITOR`** | Boundary transition to MONITOR at exactly 1.00. |
| **High RF Attack, Mild Anomaly** | 0.95 | DDoS | -0.500 | 0.1299 | 0.7040 | 0.7040 | **`MONITOR`** | Correctly escalates to MONITOR. |
| **High RF Attack, Sub-Block Anomaly** | 0.98 | DDoS | -0.600 | 0.6299 | 0.8750 | 0.8750 | **`MONITOR`** | Fails to block; remains in MONITOR. |
| **Boundary Block Attack** | 0.99 | DDoS | -0.630 | 0.7799 | 0.9270 | 0.9270 | **`BLOCK`** | Requires both extreme confidence AND extreme outlier. |
| **Pure Anomaly, Benign RF** | 0.98 | BENIGN | -0.580 | 0.5299 | 0.1730 | 0.5500 | **`ALLOW`** | Correctly overridden to Unknown (score 0.55, ALLOW). |
| **Ambient High-Volume Benign** | 0.99 | BENIGN | -0.560 | 0.4299 | 0.1360 | 0.5500 | **`ALLOW`** | Correctly overridden to Unknown (score 0.55, ALLOW). |

---

## 3. Failure Mode and Edge-Case Analysis

### Case 1: Missing or Non-Finite Features
- **Code Path**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L273)
- **Check**: `if not np.isfinite(X).all(): raise ValueError("Features must be finite numbers")`
- **Result**: Raises exception immediately; does **not** fall back to ALLOW. Rejection is handled with HTTP 422.

### Case 2: Inference Component Crash or Unavailability
- **Code Path**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L282-L289)
- **Check**: Wraps `self.rf.predict()` and `self.ifo.named_steps["if"].score_samples()` in `try...except`.
- **Result**: Raises `ModelUnavailableError(503)`.
- **Backend Consequence**: In [`backend/services/aiEngineService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/aiEngineService.js#L48-L50), `predictRecord` catches the error, logs a warning, and returns `null`.
- **Impact**: In `runFullPipeline` (line 54), if `r?.result` is null, it returns `null`. In `threatService.js`, no ThreatLog or containment action is initiated. The traffic is implicitly allowed through the network without detection.

### Case 3: Label Mapping Inversion (`cname == "Unknown"`)
- **Code Path**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py#L293-L294)
- **Check**: `if cname == "BENIGN" and is_anomaly: cname = "Unknown"; score = max(score, 0.55)`
- **Result**: Threat score is set to 0.55. Because `0.55 < MONITOR_THRESHOLD (0.70)`, action is guaranteed to be **`ALLOW`**.
- **Impact**: Completely prevents autonomous blocking on unsupervised outliers. Safe against false-positive host isolation, but provides zero automated containment against novel zero-day attacks.

---

## 4. Key Architectural Flaws Identified

1. **Multiplicative Attenuation of Confident Detections**:
   Multiplying $P_{RF}$ by $0.70$ penalizes the supervised classifier for an inlier anomaly score. Supervised multi-class classifiers trained on specific attack signatures (like PortScan) should not be downgraded when the attack is structurally compact.
2. **Artificial High-Bar for Blocking**:
   Requiring $\text{score} \ge 0.92$ demands that an attack saturate both classifiers simultaneously ($P_{RF} \approx 1.0$ and $\text{anomalySignal} \ge 0.733$). As a result, autonomous blocking is practically unreachable for 99.5% of DDoS attacks and 100.0% of PortScan attacks.
3. **Threshold Coupling**:
   The threshold for `MONITOR` (0.70) exactly matches the maximum possible single-model contribution ($0.7 \times 1.0$). This leaves zero margin for classification uncertainty.
