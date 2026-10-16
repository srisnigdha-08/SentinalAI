# Pipeline Architecture and Label Semantics Specification

## 1. Feature Preprocessing Pipeline

The SentinelAI ML pipeline transforms raw network flow records into a fixed 53-dimensional float64 feature vector $\mathbf{x} \in \mathbb{R}^{53}$ adhering to `FEATURE_SCHEMA_VERSION = "v2.1_53feat"`.

### 1.1 Ingestion and Sanitization
1. **Candidate Aliasing**: Handles heterogeneous column formats across CICIDS2017 raw CSVs, Honeypot JSON payloads, and live Windows network flow captures.
2. **Dynamic Feature Derivation**:
   - `payload_entropy`: Evaluated as Shannon entropy over forward and backward packet lengths:
     $$H = - \sum_{i \in \{fwd, bwd\}} p_i \log_2(p_i) \quad \text{where } p_i = \frac{L_i}{L_{fwd} + L_{bwd}}$$
   - `time_of_day_sin` / `time_of_day_cos`: Cyclic temporal encodings over a 24-hour window.
3. **Finite Value Sanitization**: Infinite (`inf`, `-inf`) and missing (`NaN`) float representations are replaced with `0.0`, preventing `ValueError` during matrix normalization in downstream `StandardScaler` transformations.

---

## 2. Model Decision Path

```
                      Raw Flow Record
                            │
                            ▼
               Feature Extraction (53 Features)
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
    Random Forest Classifier      Isolation Forest Detector
    (Supervised Multi-Class)     (Unsupervised Inlier/Outlier)
              │                           │
       Predicted Class                    │
     & Class Confidence                   │
              │                           ▼
              │                  Raw Decision Score
              │                 Threshold: s < -0.50
              │                           │
              └─────────────┬─────────────┘
                            ▼
               SentinelPredictor Arbitration
```

### 2.1 Arbitration Rules

Let $C_{RF} \in \{0, 1, \dots, K-1\}$ be the supervised class index, $P_{RF} = \max_k P(Y=k|\mathbf{x})$ be the classifier confidence, and $s_{IF}$ be the raw Isolation Forest decision score ($s_{IF} < 0$ implies outlier).

1. **Supervised Attack Branch ($C_{RF} \ne 0$)**:
   $$\text{predictedClass} = \text{LABEL\_NAMES}[C_{RF}]$$
   $$\text{threatScore} = P_{RF}$$
   $$\text{action} = \begin{cases} \text{BLOCK} & \text{if } \text{threatScore} \ge 0.85 \\ \text{MONITOR} & \text{if } 0.60 \le \text{threatScore} < 0.85 \\ \text{ALLOW} & \text{otherwise} \end{cases}$$

2. **Unsupervised Anomaly Branch ($C_{RF} = 0 \land s_{IF} < -0.50$)**:
   $$\text{predictedClass} = \text{"Unknown"}$$
   $$\text{threatScore} = 0.55$$
   $$\text{isAnomaly} = \text{True}$$
   $$\text{action} = \text{"ALLOW"}$$
   > **Critical Safety Guarantee**: High-entropy or bursty flows flagged by Isolation Forest are labeled as `"Unknown"` with an elevated anomaly score ($0.55$), but their runtime containment action is strictly `ALLOW`. They are never blocked autonomously.

3. **Benign Flow Branch ($C_{RF} = 0 \land s_{IF} \ge -0.50$)**:
   $$\text{predictedClass} = \text{"BENIGN"}$$
   $$\text{threatScore} = 0.05$$
   $$\text{action} = \text{"ALLOW"}$$

---

## 3. Label Semantics and Metric Inversion Defect

### 3.1 Historical Defect in `evaluate_model.py`
In previous evaluation routines, binary metrics were calculated using:
```python
def is_pos(lbl):
    return str(lbl).strip().upper() not in ["BENIGN", "0"]
```
Because the arbitration pipeline assigned `predictedClass = "Unknown"` whenever Isolation Forest detected a distribution shift, the evaluation script treated `"Unknown"` as a **malicious positive attack prediction**.

### 3.2 Consequence
During Friday afternoon DDoS captures, background benign flows share high-volume and bursty characteristics with DDoS traffic. Isolation Forest appropriately flagged ~40% of these benign flows as out-of-distribution anomalies. However, because `is_pos("Unknown") == True`, the evaluation pipeline incorrectly tallied these as **attack false positives**, reporting a catastrophic **33%–40% DDoS FPR**.

### 3.3 Semantic Separation
Under proper evaluation semantics:
1. **Raw Classifier Evaluation**: Measures the accuracy of the multi-class classifier directly:
   $$\text{Positive} \iff C_{RF} \ne \text{"BENIGN"}$$
2. **Containment Policy Evaluation**: Measures whether a benign flow suffers disruptive mitigation:
   $$\text{Disruptive Positive} \iff \text{Action} \in \{\text{BLOCK}, \text{MONITOR}\}$$
3. **Anomaly Discovery Evaluation**: Measures outlier detection sensitivity, independent of malicious classification.
