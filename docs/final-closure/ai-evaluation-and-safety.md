# SentinelAI Final Closure: AI Model Evaluation and Safety Governance

**Date**: October 15, 2026  
**Auditor**: Machine Learning Security & MLOps Engineer  
**Component**: AI Inference Engine, Feature Engineering Pipeline, Evaluation Metrics, and Safety Governance  
**Status**: **VERIFIED & POLICY LOCKED**

---

## 1. Feature Engineering & Preprocessing Pipeline

The SentinelAI machine learning engine (`ai-engine/`) employs a standardized 53-feature extraction pipeline (`utils/features.py`) engineered to process network flows and system telemetry:

### 1.1 Schema Alignment & Versioning
- **Feature Vector Length**: Exactly **53 features** (`EXPECTED_FEATURE_COUNT = 53`).
- **Schema Version**: `v2.1_53feat`. An in-code assertion (`assert len(FEATURE_NAMES) == EXPECTED_FEATURE_COUNT`) strictly prevents silent feature drift or dimension mismatches between training scripts and real-time inference.
- **Header & Column Normalization**: Implements robust candidate lookups (`CANDIDATES` dictionary in `features.py`) supporting both raw CICIDS2017 whitespace-padded CSV headers (e.g., `' Total Fwd Packets'`, `'Flow Duration'`) and normalized snake_case representations (`total_fwd_packets`, `flow_duration`).
- **Data Sanitization**: Replaces non-finite values (`+inf`, `-inf`) with maximum float boundaries and replaces missing numerical values (`NaN`) with column medians or zero defaults, logging any anomalous sanitization events.

---

## 2. Independent Evaluation Reproduction

### 2.1 Dataset Provenance & Leakage Prevention
To ensure rigorous evaluation without data leakage:
- Evaluated against official CICIDS2017 benchmark PCAP flow captures:
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
- **Leakage Prevention**: Evaluation flows were extracted starting at **offset row 60,000**, guaranteeing zero overlap with training subsets located in the initial row partitions.
- **Model Under Evaluation**: `models/rf_classifier_cicids_v2.pkl` (SHA-256: `CA0EFB1FDE8F9BDC430C3C511E32CD91822B0F3DEECA845AA259BC8DD60023F1`).

### 2.2 Quantitative Evaluation Results

#### PortScan Attack Evaluation (200 Held-Out Samples: 100 PortScan, 100 Benign)
```
                  PREDICTED BENIGN    PREDICTED ATTACK
ACTUAL BENIGN           92 (TN)              8 (FP)
ACTUAL PORTSCAN          4 (FN)             96 (TP)
```
- **Accuracy**: 94.0%
- **Sensitivity / Recall**: 96.0%
- **Precision**: 92.3%
- **F1-Score**: 94.1%
- **False Positive Rate (FPR)**: **8.0%**
- **False Negative Rate (FNR)**: **4.0%**

#### DDoS Attack Evaluation (200 Held-Out Samples: 100 DDoS, 100 Benign)
```
                  PREDICTED BENIGN    PREDICTED ATTACK
ACTUAL BENIGN           67 (TN)             33 (FP)
ACTUAL DDOS              2 (FN)             98 (TP)
```
- **Accuracy**: 82.5%
- **Sensitivity / Recall**: 98.0%
- **Precision**: 74.8%
- **F1-Score**: 84.9%
- **False Positive Rate (FPR)**: **33.0%**
- **False Negative Rate (FNR)**: **2.0%**

---

## 3. Generalization Limitations & Autonomous Containment Ban

### 3.1 Operational Risk of the 33.0% DDoS FPR
While detection sensitivity is exceptional (98.0% Recall on DDoS, 96.0% Recall on PortScan), the **33.0% False Positive Rate on DDoS traffic** constitutes an intolerable operational risk:
1. In a live enterprise or datacenter environment, a 33% FPR means that **1 out of every 3 legitimate, benign network flows** would be classified as malicious.
2. If autonomous containment were permitted to execute host or firewall blocking based solely on model confidence scores, SentinelAI would rapidly block legitimate internal hosts, application servers, and user workstations, creating an immediate, severe self-inflicted Denial of Service.
3. In addition, tests against synthetic test fixtures exhibiting protocol variations produced a 100% False Negative Rate, showing that the model's feature weights are tightly coupled to the CICIDS2017 distribution.

### 3.2 Autonomous Containment Policy Determination
> [!CAUTION]
> **Policy Decision: Autonomous Containment is Strictly Prohibited.**  
> `AUTONOMOUS_CONTAINMENT` must remain configured to `false`. All containment decisions (IP blocking, process isolation, host quarantine) must require explicit manual authorization by an authenticated Security Analyst or Administrator through the SentinelAI management console.

---

## 4. Reinforcement Learning State Integrity & Q-Table Protection

### 4.1 Reconciliation of Baseline vs. Runtime Hashes
Independent cryptographic verification resolves the historical hash discrepancy:
- **Protected Baseline Reference Model**:  
  `ai-engine/models/q_table.json` (2,338 bytes)  
  SHA-256: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`  
  *Status: 100% unaltered reference asset.*
- **Mutable Active Runtime Table**:  
  `ai-engine/runtime/q_table.json` (1,224 bytes)  
  SHA-256: `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC`  
  *Status: Valid mutable runtime state updated dynamically by live AI process.*

### 4.2 In-Code Path Safeguards
In this final closure phase, `DeceptionQLearner.save()` in `ai-engine/rl_engine/deception_scorer.py` was reinforced with an explicit path-resolution guard:
```python
target = Path(self.q_table_path).resolve()
models_baseline = (Path(__file__).parent.parent / "models" / "q_table.json").resolve()
if target == models_baseline:
    log.warning("Write to protected baseline models/q_table.json blocked! Redirecting to runtime/q_table.json")
    self.q_table_path = str(Path(__file__).parent.parent / "runtime" / "q_table.json")
    target = Path(self.q_table_path).resolve()
```
This guard resolves symlinks, path aliases (`../../models/q_table.json`), and relative paths, guaranteeing that even direct learner calls cannot overwrite the reference baseline. Automated tests in `test_q_table_safety.py` verify this invariant.
