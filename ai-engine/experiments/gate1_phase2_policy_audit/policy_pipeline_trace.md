# GATE-1 Phase 2: Complete Policy Pipeline Trace and Architecture Audit

**Audit Date**: October 16, 2026  
**Auditor**: Senior Machine Learning Security Engineer & Independent Software Auditor  
**Scope**: In-depth trace of the SentinelAI end-to-end decision pipeline from input features to firewall containment  
**Status**: **READ-ONLY AUDIT COMPLETED**

---

## 1. End-to-End Pipeline Architecture Diagram

```
                        Raw Input Record (JSON / Network Packet)
                                        │
                                        ▼
                  Feature Ingestion & Vector Construction (53 Features)
                      [ai-engine/utils/features.py:170-248]
                                        │
                         Float Sanitization & Dimension Check
                          [predictor.py:272-275]
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
           Random Forest Model                    Isolation Forest Model
       [rf_classifier_cicids_v2.pkl]           [isolation_forest_cicids.pkl]
             (Supervised Class)                    (Unsupervised Outlier)
                     │                                     │
             Predicted Class $C_{RF}$                 Raw Outlier Score
         & Confidence $P_{RF} = \max P$              $s_{IF} = \text{score\_samples}(X)$
         $rf\_s = P_{RF} \text{ if } C_{RF} \ne 0$         [predictor.py:286]
               else $1 - P_{RF}$                           │
             [predictor.py:277-290]                        ▼
                     │                       Anomaly Signal Transformation
                     │                       $\text{if\_sig} \in [0.0, 1.0]$
                     │                       $s_{IF} \ge -0.4740 \implies \text{if\_sig} = 0.0$
                     │                       [predictor.py:205-230]
                     │                                     │
                     └──────────────────┬──────────────────┘
                                        ▼
                         Composite Threat Score Synthesis
                    $\text{score} = \text{round}(0.7 \cdot rf\_s + 0.3 \cdot \text{if\_sig}, 4)$
                    Branch: if $C_{RF} == \text{"BENIGN"}$ and $s_{IF} < -0.55$:
                            $cname = \text{"Unknown"}; score = \max(score, 0.55)$
                    [predictor.py:290-294]
                                        │
                                        ▼
                            Action Arbitration Branch
                   $\text{score} \ge 0.92 \implies \text{"BLOCK"}$
                   $0.70 \le \text{score} < 0.92 \implies \text{"MONITOR"}$
                   $\text{score} < 0.70 \implies \text{"ALLOW"}$
                   [predictor.py:301]
                                        │
                                        ▼
                         Backend API Pipeline Ingestion
                       [backend/services/threatService.js:86-127]
                       $autoBlockEnabled = \text{SystemSetting} == \text{true}$
                       $shouldBlock = \text{score} \ge 0.92 \land autoBlockEnabled$
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
        Status: 'MONITORING' (if score >= 0.70)      Status: 'BLOCKED' (if shouldBlock)
        Status: 'DETECTED' (if score < 0.70)         (Locked: autoBlockEnabled = false)
        Emits WebSocket Telemetry                   [threatService.js:98-103]
        Dispatches Async Threat Intel                      │
                                                           ▼
                                               Containment Adapter Factory
                                           [MockContainmentAdapter.js (SAFE)]
                                           netsh Windows Firewall BANNED by gate
```

---

## 2. Step-by-Step Code Execution Path and Exact Line References

### Step 1: Feature Extraction and Ingestion
- **File**: [`ai-engine/utils/features.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/utils/features.py) (Lines 170–248).
- **Function**: `extract_features_from_record(record: dict) -> np.ndarray`
- **Behavior**:
  - Maps candidate network field names to the canonical 53-feature vector using `CANDIDATES` alias dictionary.
  - Dynamically computes Shannon payload entropy `compute_payload_entropy(fwd_len, bwd_len)` (lines 130–141).
  - Dynamically computes 24-hour cyclic time features `compute_time_of_day(timestamp)` (lines 143–165).
  - Returns `np.ndarray` of shape `(53,)`, `dtype=np.float64`.
- **Validation**: In [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) (lines 272–274):
  ```python
  X = extract_features_from_record(record).reshape(1, -1)
  if not np.isfinite(X).all():
      raise ValueError("Features must be finite numbers")
  ```
  If any input feature contains NaN, Infinity, or cannot be parsed, inference terminates immediately with `ValueError(422)`.

### Step 2: Random Forest Classification
- **File**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) (Lines 276–284).
- **Execution**:
  ```python
  cls = self.rf.predict(X)[0]
  proba = self.rf.predict_proba(X)[0]
  cname = LABEL_NAMES.get(int(cls), "BENIGN")
  probs = {LABEL_NAMES.get(i, f"c{i}"): round(float(p), 4) for i, p in enumerate(proba)}
  max_p = float(max(proba))
  ```
- **Semantics**:
  - `cls`: Multiclass integer in $\{0, 1, \dots, 10\}$. Class 0 is `BENIGN`. Classes 1–10 are attack categories.
  - `max_p`: Probability assigned to the winning class, $P_{RF} \in [0.0, 1.0]$.
  - `rf_s` (line 290): If $C_{RF} \ne \text{"BENIGN"}$, $rf\_s = max\_p$. If $C_{RF} == \text{"BENIGN"}$, $rf\_s = 1.0 - max\_p$.

### Step 3: Isolation Forest Anomaly Scoring
- **File**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) (Lines 285–289 and 205–230).
- **Execution**:
  ```python
  if_score = float(self.ifo.named_steps["if"].score_samples(self.ifo.named_steps["scaler"].transform(X))[0])
  is_anomaly = if_score < ANOMALY_THRESHOLD  # ANOMALY_THRESHOLD = -0.55
  if_sig = self.calculate_if_anomaly_signal(if_score)
  ```
- **Mathematical Transformation in `calculate_if_anomaly_signal`**:
  ```python
  offset = IF_DEFAULT_OFFSET  # -0.47402357424116837 (10th percentile decision boundary)
  if val >= offset:
      return 0.0
  deflection = offset - val
  return round(float(min(deflection / IF_ANOMALY_SPAN, 1.0)), 4)  # IF_ANOMALY_SPAN = 0.20
  ```
  - **Inlier Behavior**: When raw `if_score >= -0.4740`, `if_sig = 0.0`.
  - **Outlier Behavior**: When `if_score < -0.4740`, `if_sig` increases linearly from $0.0$ to $1.0$, saturating at $1.0$ when `if_score <= -0.6740`.

### Step 4: Composite Threat Score Calculation
- **File**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) (Lines 290–294).
- **Formula**:
  ```python
  rf_s = max_p if cname != "BENIGN" else (1 - max_p)
  if_sig = self.calculate_if_anomaly_signal(if_score)
  score = round(0.7 * rf_s + 0.3 * if_sig, 4)
  if cname == "BENIGN" and is_anomaly:
      cname = "Unknown"
      score = max(score, 0.55)
  ```
- **Threshold Constants** (lines 88–90):
  - `BLOCK_THRESHOLD = 0.92`
  - `MONITOR_THRESHOLD = 0.70`
  - `ANOMALY_THRESHOLD = -0.55`

### Step 5: Action Arbitration
- **File**: [`ai-engine/inference/predictor.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/inference/predictor.py) (Line 301).
- **Code**:
  ```python
  action = "BLOCK" if score >= BLOCK_THRESHOLD else "MONITOR" if score >= MONITOR_THRESHOLD else "ALLOW"
  ```
- **Return Payload**:
  Returns dictionary containing `predictedClass`, `threatScore`, `severity`, `confidence`, `isAnomaly`, `anomalyScore`, `action`, `featureVector`.

### Step 6: Backend Consumption & Database Telemetry
- **File**: [`backend/services/threatService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/threatService.js) (Lines 86–127).
- **Execution**:
  ```javascript
  const setting = await SystemSetting.findOne({ key: 'autoBlockEnabled' });
  const autoBlockEnabled = setting ? setting.value === true : false;
  const blockThreshold = await aiEngineService.getBlockThreshold(); // returns 0.92

  const shouldBlock = score >= blockThreshold && autoBlockEnabled;
  const actionTaken = shouldBlock;

  let status = 'DETECTED';
  if (shouldBlock) {
    status = 'BLOCKED';
  } else if (score >= 0.7) {
    status = 'MONITORING';
  }

  const threat = await ThreatLog.create({ ...data, status, ... });
  ```
- **Asynchronous Threat Intel Enrichment** (lines 130–140):
  Triggered only if `threat.aiScore >= 0.7`. Any flow with `threatScore < 0.70` (including all `score = 0.55` Unknown flows) bypasses Threat Intel enrichment.

### Step 7: Host Containment and Safety Gating
- **File**: [`backend/services/containmentService.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/containmentService.js) (Lines 778–847) and [`backend/services/containment/adapterFactory.js`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/backend/services/containment/adapterFactory.js) (Lines 20–35).
- **Execution**:
  - `autoBlockEnabled` is forced to `false` in production configuration (`AUTONOMOUS_CONTAINMENT=false`).
  - Therefore, `shouldBlock` is always `false` during automated ingestion.
  - If manual containment is requested by a human operator, `AdapterFactory` checks `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT`. Because this environment variable is `false`, `AdapterFactory` falls back to `MockContainmentAdapter`. Exactly zero host Windows Firewall rules are modified.

---

## 3. Exception and Failure Fallback Matrix

| Component | Failure Mode | Trigger Condition | Exact Behavior | Safe Outcome? |
| :--- | :--- | :--- | :--- | :---: |
| **Model Loader** | Artifact Missing or Corrupt | `models/rf_classifier_cicids_v2.pkl` absent | `load()` logs error, sets `self._loaded = False`. Endpoints return `HTTP 503 ("Required models are not loaded")`. | **YES (Fail Closed)** |
| **Feature Extractor** | Non-Finite Features | Input contains `NaN`, `Infinity`, or string error | In `predictor.py` line 273: raises `ValueError("Features must be finite numbers")`. Returns `HTTP 422`. | **YES (Rejects Poisoned Data)** |
| **RF Classifier** | Inference Crash | Scikit-learn estimator raises internal error | Lines 282–284: catches error, logs, and raises `ModelUnavailableError("Classifier inference failed")`. | **YES (Service Guarded)** |
| **IF Detector** | Anomaly Failure | Scaler or `score_samples` raises error | Lines 288–289: raises `ModelUnavailableError("Anomaly inference failed")`. | **YES (Service Guarded)** |
| **Backend AI Client** | AI Engine Unreachable | Port 8000 down or connection refused | In `aiEngineService.predictRecord` lines 42–50: catches error, logs warning, returns `null`. Backend degrades gracefully. | **YES (Prevents Cascading Crash)** |
| **Auto-Block DB** | BlockedIP write fails | Database connection drop during block | In `containmentService.js` lines 803–825: catches error, executes compensating rollback on ThreatLog status. | **YES (Atomic Consistency)** |
