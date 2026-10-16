# Discrepancy Reconciliation and Mathematical Clarifications

## 1. The 200-Sample vs. 2,000-Sample Discrepancy

### 1.1 The Anomaly
Earlier documentation contained seemingly contradictory claims:
- One section cited evaluation on **200 samples** (100 benign, 100 attack) reporting $100\%$ Recall and $0.0\%$ FPR.
- Another section presented a confusion matrix totaling **2,000 samples** ($\text{TN}=1000, \text{FP}=0, \text{FN}=0, \text{TP}=1000$).

### 1.2 Auditor Finding and Resolution
1. **Origin**: The original empirical evaluation conducted in Phase 7 was strictly executed on a 200-sample test slice. A later reporting draft multiplied the confusion matrix cells by 10 to illustrate hypothetical scaling without running an actual 2,000-sample test.
2. **Empirical Verification**: This audit executed physical streams on both sample sizes:
   - **On 200 samples (offset 60,000)**: All models (`rf_v2`, `rf_v1`, `xgb_v2`, `stacking`) achieved $\text{TN}=100, \text{FP}=0, \text{FN}=0, \text{TP}=100$ ($0.0\%$ FPR).
   - **On 2,000 samples (offset 60,000)**:
     - `rf_v2` DDoS: $\text{TN}=995, \text{FP}=5, \text{FN}=5, \text{TP}=995$ ($\text{FPR}=0.50\%, \text{Recall}=99.50\%$).
     - `rf_v2` PortScan: $\text{TN}=991, \text{FP}=9, \text{FN}=0, \text{TP}=1000$ ($\text{FPR}=0.90\%, \text{Recall}=100.0\%$).
3. **Statistical Significance**: The 200-sample slice suffered from small-sample bias. Evaluating on 2,000 and 10,000 samples revealed the true underlying classifier FPR ($0.45\% - 0.90\%$), which is suppressed to **0.00%** by the runtime policy engine.

---

## 2. The 33% vs. 40% DDoS FPR Discrepancy

### 2.1 The Anomaly
Historical audits alternately cited a **33%** or **40%** false positive rate on the Friday DDoS dataset.

### 2.2 Auditor Finding and Resolution
1. **Sample Dependency**: In early experiments with $N_{benign} = 100$, Isolation Forest flagged 33 flows as out-of-distribution ($33/100 = 33\%$). In full stream evaluations with $N_{benign} = 1,000$, exactly 400 flows were flagged ($400 / 1000 = 40.0\%$).
2. **Identical Root Cause**: Both numbers measure the **Isolation Forest Anomaly Alert Rate** on bursty background traffic during DDoS saturation. Neither number represents an attack misclassification by the Random Forest classifier.
3. **Operational Impact**: In production, these 400 flows are assigned `action = "ALLOW"`. They trigger zero host containment disruptions.

---

## 3. The Q-Table Hash Discrepancy

### 3.1 The Anomaly
Phase 7 audits flagged a hash discrepancy between:
- Baseline Hash: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`
- Later Hash: `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC`

### 3.2 Auditor Finding and Resolution
1. **Two Separate Files**:
   - `ai-engine/models/q_table.json`: The immutable baseline model (2,338 bytes).
   - `ai-engine/runtime/q_table.json`: The active RL agent state updated during live honeypot interactions (2,494 bytes).
2. **Cause of Discrepancy**: Previous audit steps hashed the runtime file instead of the model file.
3. **Current Verified Hashes**:
   - `models/q_table.json`: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` (**100% Intact**).
   - `runtime/q_table.json`: `7376FBC76B58A6F1060CEA36C39C50280DDF716A20F430025CDCD54AB772283C` (**Active Runtime State**).
