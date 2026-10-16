# Remaining Risks and Technical Limitations

## 1. Academic Dataset Generalization Gap

### 1.1 The Evaluation Boundary
SentinelAI’s machine learning models are evaluated against the University of New Brunswick (UNB) **CICIDS2017** benchmark dataset. While CICIDS2017 is an accepted academic baseline, it exhibits severe distribution shifts when contrasted with modern enterprise production environments:
1. **Network Topology**: CICIDS2017 was recorded in a small simulated network with ~15 victim systems. Enterprise environments span thousands of endpoints across multiple hybrid cloud zones and micro-segmented VPCs.
2. **Modern Protocols**: The dataset predates pervasive TLS 1.3 encrypted Server Name Indication (ESNI/ECH), HTTP/3 (QUIC over UDP), and WebSocket-based enterprise Collaboration tools (Slack, Teams, Zoom).
3. **Traffic Volume & Jitter**: Modern cloud-native telemetry, CI/CD runners, and background software updates produce bursty traffic profiles that trigger elevated anomaly scores in unsupervised models.

---

## 2. Cross-Split Correlation Risk in Historical Training

### 2.1 Subsampling Artifacts
Historical training routines in `train.py` utilized unstratified random subsampling across entire day-long captures. Because network traffic naturally clusters into multi-flow sessions (e.g. repeated TCP connections from a single IP pair), random subsampling leaks session-level covariance between training and evaluation pools.

### 2.2 Residual Risk
While this audit successfully utilized the **Monday Pure Benign Capture** (recorded 4 days prior, completely unpolluted by Friday training data) to establish an independent 10,000-flow negative baseline, historical attack evaluation splits on Friday DDoS and PortScan files retain some degree of session correlation. Full confidence in multi-class attack recall requires temporal group-based splitting during future model retrainings.

---

## 3. Host and Endpoint Context Limitations

The current 53-dimensional feature space (`FEATURE_SCHEMA_VERSION = "v2.1_53feat"`) operates exclusively at the network flow layer (IP/TCP/UDP packet headers, inter-arrival times, payload byte entropy).

**Identified Blind Spots**:
- **Host Process Lineage**: The model cannot correlate a flow with the spawning executable (e.g., distinguishing `svchost.exe` from a reverse shell spawned by `powershell.exe`).
- **In-Memory Attacks**: Process hollowing, reflective DLL injection, and credential dumping (mimikatz against LSASS) generate minimal immediate network flow anomalies.
- **Encrypted Payloads**: High-entropy payloads look identical whether they represent legitimate AES-encrypted backups or active ransomware exfiltration.

---

## 4. Operational Alert Fatigue from Anomaly Detection

In `inference/predictor.py`, the Isolation Forest detector flags out-of-distribution traffic as `"Unknown"` with `threatScore = 0.55` and `action = "ALLOW"`.

**Operational Risk**:
- In high-throughput network environments, Isolation Forest flags between **13% and 40%** of ambient flows as anomalous.
- While this configuration is completely safe against disruptive containment (`ALLOW` action prevents false firewall blocks), forwarding these raw alerts directly to SOC analysts would result in severe alert fatigue.
- Mitigation: Prior to enterprise production deployment, alerts for `"Unknown"` flows must be routed to a deduplication and behavioral aggregation queue rather than generating immediate Tier-1 SOC tickets.

---

## 5. Containment Safety Invariants

Until the enterprise generalization gap is bridged through multi-datacenter data collection and human governance sign-off:
1. `AUTONOMOUS_CONTAINMENT` must remain locked at `false`.
2. `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` must remain locked at `false`.
3. All containment decisions must require human-in-the-loop confirmation via the SentinelAI security dashboard.
