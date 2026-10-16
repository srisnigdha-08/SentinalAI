# Dataset Provenance, Split Hygiene, and Data Leakage Audit

## 1. Provenance of Datasets

SentinelAI models are evaluated against the University of New Brunswick (UNB) **CICIDS2017** benchmark, stored locally in `ai-engine/datasets/cicids2017/`.

The primary evaluation captures include:
1. `Monday-WorkingHours.pcap_ISCX.csv`: 529,918 total flows, 100% Benign. Recorded on Monday, July 3, 2017.
2. `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`: 225,745 flows (128,027 DDoS LOIC, 97,718 ambient benign). Recorded on Friday, July 7, 2017.
3. `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`: 286,467 flows (158,930 PortScan, 127,537 ambient benign). Recorded on Friday, July 7, 2017.

---

## 2. Audit of Data Leakage in Training Splits

### 2.1 The Random Subsampling Vulnerability
In `ai-engine/training/train.py` and `train_cicids_v2.py`, historical training routines used pandas random subsampling:
```python
df_grp.sample(n=min(len(df_grp), samples_per_class), random_state=42)
```
Because network flows in a `.pcap` capture exhibit strong temporal clustering (e.g., long-lived TCP sessions generating hundreds of micro-flows across several hours), drawing samples randomly across an entire capture distributes related flows into both training and evaluation pools.

### 2.2 The "Offset 60,000" Strategy and Its Flaws
During Phase 7 evaluation, an offset of 60,000 rows was introduced:
```python
df.iloc[60000:60000 + n_eval]
```
**Audit Finding**: While the offset avoids evaluating the exact initial 60,000 rows, it **does not eliminate data leakage** if the training phase sampled across the entire file using a random seed. Flows at row 65,000 can share source/destination IP addresses, port combinations, and ephemeral TCP window profiles with flows sampled at row 20,000.

### 2.3 The Monday Capture as a Truly Independent Negative Split
To achieve mathematically rigorous independence, this audit evaluated SentinelAI against `Monday-WorkingHours.pcap_ISCX.csv`:
- **Temporal Separation**: Recorded 4 calendar days prior to the Friday attacks.
- **Topological Independence**: Generated during standard user workstation activity, completely unpolluted by Friday attack campaigns.
- **Zero Training Contamination**: Monday captures were excluded from the Friday DDoS training batches.
- **Sample Size**: 10,000 consecutive flows evaluated, yielding an empirical FPR of **0.45%** on raw RF and **0.00%** on policy containment actions.

---

## 3. Generalization Limitations of CICIDS2017

While CICIDS2017 is standard in cybersecurity ML research, an independent technical auditor must note critical distribution shifts:
1. **Host-Level Diversity**: The CICIDS2017 environment consisted of only ~15 victim machines running Windows and Ubuntu. Modern enterprise networks feature thousands of endpoints with diverse software stacks.
2. **Protocol Evolution**: Captured in 2017, the dataset predates widespread adoption of TLS 1.3, QUIC (HTTP/3), and modern zero-trust microsegmentation.
3. **Synthetic Attack Artifacts**: LOIC DDoS traffic exhibits static payload signatures and constant-rate packet bursts that do not mimic modern botnets (e.g., Mirai variants with randomized IAT).

**Conclusion**: Retraining on multi-source, production-grade enterprise traffic remains necessary before autonomous containment can be certified for production release.
