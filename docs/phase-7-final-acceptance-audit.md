# SentinelAI — Phase 7 Final Evidence-Based Acceptance Audit
**Date**: October 15, 2026  
**Auditor**: Senior Application Security Engineer, ML-Security Integration Engineer, Windows Systems Architect  
**Project**: SentinelAI Security Monitoring & Threat Detection Platform  
**Target Environment**: Windows 11 Native Development & Verification Environment  
**Final Verdict**: **PASS WITH LIMITATIONS**

---

## Executive Summary

This audit report delivers the independent, evidence-based final acceptance review of the SentinelAI platform following Phase 7 implementation, defect remediation, and model verification. The audit directly resolves historical discrepancies, reproduces machine learning evaluation metrics against held-out datasets, stress-tests the hardened outbox persistence layer, reviews production dependency risks, and validates platform invariants across the native Windows runtime environment.

### Core Audit Outcomes
1. **Q-Table Discrepancy Resolved**: Verified that baseline model hash `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` corresponds to the frozen, protected reference model (`ai-engine/models/q_table.json`, 2,338 bytes), which has remained 100% unaltered. Hash `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC` belongs to the mutable runtime artifact (`ai-engine/runtime/q_table.json`, 1,224 bytes) dynamically updated by the running reinforcement learning engine.
2. **AI Evaluation Independently Reproduced**: Validated model inference against held-out CICIDS2017 network traffic slices (offset by 60,000 samples to prevent training leakage). PortScan detection demonstrated 96.0% Recall and 8.0% FPR. DDoS detection demonstrated 98.0% Recall but exhibited a 33.0% False Positive Rate (FPR), establishing conclusively that **autonomous containment must remain strictly disabled**.
3. **Outbox Durability Hardened & Stress-Tested**: Hardened `FileOutboxStore` with atomic temporary-file swaps, corrupted payload quarantine (`.corrupt.<timestamp>`), retention pruning (retaining up to 100 delivered events while preserving pending items), and structured error tracking. Outbox stress tests passed 7/7 scenarios under simulated crashes, poisoned payloads, and concurrent emissions.
4. **Production Dependency Audit Completed**: Analyzed 12 vulnerability advisories from `npm audit --omit=dev --json` across 221 production packages. Documented reachability, mitigation through loopback isolation, Winston log sanitization, and outlined the Express v5 migration path required to eliminate legacy transitives (`qs`, `proxy-addr`).
5. **Runtime Invariants Preserved**: Verified 100% process stability across all 4 core services (MongoDB PID 28468, AI Engine PID 35672, Backend PID 39136, Frontend PID 35704). Confirmed zero mutation of the development database (`sentinel-db` on port 27017) and verified 0 unauthorized firewall rules on the Windows host.

---

## Section 1: Resolution of the Q-Table Checksum Discrepancy

### 1.1 Root Cause Analysis & Path Reconciliation
During prior review cycles, two disparate SHA-256 hashes were reported for `q_table.json`:
- `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`
- `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC`

An exhaustive filesystem and execution inspection reveals that these hashes belong to **two distinct files** serving separate architectural functions in the SentinelAI design:

| Attribute | Protected Baseline Asset | Mutable Runtime Artifact |
| :--- | :--- | :--- |
| **Absolute Path** | `C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\models\q_table.json` | `C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json` |
| **File Size** | 2,338 bytes | 1,224 bytes |
| **Last Modified** | 2026-10-05 20:59:06 UTC | 2026-10-15 17:25:55 UTC (Dynamic) |
| **SHA-256 Hash** | `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF` | `05791820B7C49BD9C07C5B6CE71B8671DFE27FCC1EE2A1D37C8484B1417000CC` |
| **Architectural Role** | Frozen reference model baseline; immutable deployment seed | Dynamic reinforcement learning state cache; active live agent policy |
| **Active Writer** | None (Static reference) | Live AI Engine daemon (`uvicorn` PID 35672) via `$env:Q_TABLE_PATH` |
| **Integrity Status** | **UNALTERED & PRESERVED** | **VALID RUNTIME STATE** |

### 1.2 Separation Mechanism
In Phase 5 Remediation Finding #1, the static model artifacts in `ai-engine/models/` were permanently decoupled from dynamic runtime state by configuring the AI process environment:
```powershell
$env:Q_TABLE_PATH = 'C:\Users\srisn\Desktop\Projects\sentinelai-complete\ai-engine\runtime\q_table.json'
```
When live inference requests occur, the Q-learning agent (`inference/defense_agent.py`) updates state-action values in the runtime file specified by `Q_TABLE_PATH`. An earlier reporting script hashed the file residing in `ai-engine/runtime/` instead of `ai-engine/models/`, creating the appearance of an unexpected hash mutation. 

**Conclusion**: The baseline model was never altered or corrupted. The baseline hash `BF9B...` remains the definitive reference hash, while `0579...` is the verified active runtime hash.

---

## Section 2: Independent AI Model Evaluation Reproduction

### 2.1 Methodology & Leakage Prevention
To evaluate the true detection quality of the Random Forest classifier (`rf_classifier_cicids_v2.pkl`) and Isolation Forest anomaly detector (`isolation_forest_cicids.pkl`), tests were executed using `ai-engine/evaluation/evaluate_model.py` and `ai-engine/tests/test_model_evaluation.py`.

To strictly prevent data leakage and evaluate real-world generalization:
1. Evaluation samples were drawn from the official CICIDS2017 CSV captures.
2. The initial 60,000 samples were explicitly skipped to avoid any overlap with training subsets.
3. Feature alignment was verified against `data_loader.py` (78 numerical features, dropping non-feature IP/timestamp metadata, handling NaN/inf replacements).
4. Confusion matrix calculations were independently validated against standard ground-truth formulas:
   $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}, \quad \text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}, \quad \text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}}, \quad \text{FNR} = \frac{\text{FN}}{\text{TP} + \text{FN}}$$

### 2.2 Quantitative Evaluation Results

#### PortScan Attack Evaluation (200 Held-Out Samples: 100 PortScan, 100 Benign)
- **Confusion Matrix**:
  - True Negatives (TN): **92**
  - False Positives (FP): **8**
  - False Negatives (FN): **4**
  - True Positives (TP): **96**
- **Performance Metrics**:
  - Accuracy: **94.0%**
  - Recall (Sensitivity): **96.0%**
  - Precision: **92.3%**
  - F1-Score: **94.1%**
  - False Positive Rate (FPR): **8.0%**
  - False Negative Rate (FNR): **4.0%**

#### DDoS Attack Evaluation (200 Held-Out Samples: 100 DDoS, 100 Benign)
- **Confusion Matrix**:
  - True Negatives (TN): **67**
  - False Positives (FP): **33**
  - False Negatives (FN): **2**
  - True Positives (TP): **98**
- **Performance Metrics**:
  - Accuracy: **82.5%**
  - Recall (Sensitivity): **98.0%**
  - Precision: **74.8%**
  - F1-Score: **84.9%**
  - False Positive Rate (FPR): **33.0%**
  - False Negative Rate (FNR): **2.0%**

### 2.3 Generalization Limits & Autonomous Containment Policy Decision
While the model demonstrates high sensitivity (>96% Recall) across both attack categories, the **33.0% False Positive Rate on DDoS traffic** represents an insurmountable operational hazard for autonomous containment:
- In a production network, a 33% FPR implies that 1 out of every 3 benign traffic bursts or standard multi-connection flows would be misclassified as DDoS.
- If autonomous host-level containment (e.g., automated Windows Firewall outbound/inbound blocking) were enabled, SentinelAI would systematically block legitimate users and critical infrastructure, triggering an immediate self-inflicted Denial of Service.
- Furthermore, tests against out-of-distribution synthetic traffic fixtures exhibited a 100% False Negative Rate, showing that the model's feature weights are heavily specialized to CICIDS2017 packet representations and lack invariant robustness to synthetic protocol variations.

**Policy Determination**:
> [!IMPORTANT]
> **Autonomous Containment MUST REMAIN DISABLED (`AUTONOMOUS_CONTAINMENT=false`).**
> All containment actions (IP isolation, process termination, firewall modification) must strictly require human-in-the-loop approval by an authenticated Administrator or Security Analyst via the SentinelAI Console.

---

## Section 3: Stress-Testing the File-Backed Outbox

### 3.1 Architecture and Hardening Overview
To ensure telemetry, alert notifications, and audit records survive backend crashes, network disconnects, or sudden power disruptions, SentinelAI implements a durable, file-backed Outbox pattern (`backend/utils/securityEventBus.js`). 

During this audit cycle, `FileOutboxStore` was hardened with production-grade reliability primitives:
1. **Atomic Write Guarantee**: Payloads are serialized and written to an isolated temporary file (`.tmp.<timestamp>_<rand>`) and atomically renamed (`fs.renameSync` with `fs.copyFileSync` fallback) to eliminate the risk of partial/truncated JSON writes during sudden shutdowns.
2. **Corrupted File Forensics Quarantine**: When `_readAll()` detects invalid or corrupted JSON (e.g., from disk sector corruption), it automatically copies the corrupted file to `.corrupt.<timestamp>` for security forensics before initializing a clean state, preventing fatal crash loops.
3. **Retention & Pruning Management**: An automatic pruning routine (`_prune()`) maintains bounded disk utilization by truncating delivered events once the outbox exceeds 300 entries, retaining the 100 most recent delivered records. **Pending and failed events are never pruned**.
4. **Structured Error Tracking**: The store records specific subscriber exception messages (`err.message`) in `lastError`, and marks events as `FAILED` (poison pill quarantine) once retry attempts reach 3.

### 3.2 Outbox Stress Test Suite (`backend/tests/outboxStress.test.js`)
A comprehensive stress test suite was developed and executed to validate the outbox under adverse failure conditions. All 7 test scenarios passed:

| Test Scenario | Condition Tested | Observed Behavior | Status |
| :--- | :--- | :--- | :--- |
| **Crash & Recovery** | Simulated process termination while events are pending. New instance boots. | New `FileOutboxStore` instance loads existing file; pending event `e1` is detected and re-emitted. | **PASS** |
| **Ack Persistence** | Event successfully handled by subscriber. | `markDelivered('e2')` persists `DELIVERED` status and ISO timestamp to disk immediately. | **PASS** |
| **Corrupted Record Handling** | Outbox file injected with malformed, partial JSON string (`{"incomplete":`). | Store catches JSON parse error, copies corrupted artifact to `.corrupt.<timestamp>`, and initializes cleanly without crashing. | **PASS** |
| **Retry Exhaustion (Poison Pills)** | Consumer throws fatal exception across 3 consecutive replay attempts. | Store captures subscriber error string, increments `attempts` to 3, and transitions event to `FAILED` status. | **PASS** |
| **Concurrent Event Delivery** | 10 events simultaneously emitted across asynchronous handlers. | All 10 events safely persisted, processed, and marked delivered without file lock contention or data loss. | **PASS** |
| **Retention Pruning** | Outbox flooded with 350 delivered events and 1 pending event. | Pruning routine reduces delivered events to 100 while preserving the active pending event intact. | **PASS** |
| **Delivery Semantics Verification** | Subscriber completes operation but crashes prior to outbox acknowledgment. | Unacknowledged event is replayed on restart, verifying **At-Least-Once** delivery semantics. | **PASS** |

### 3.3 Delivery Guarantee & Downstream Contract
The SentinelAI Outbox guarantees **At-Least-Once** delivery. If a service worker executes an action (e.g., writing an external SIEM record) but the process crashes before `markDelivered` commits to disk, the event will be re-emitted upon engine recovery. Consequently, downstream consumers must implement idempotency based on `envelope.eventId`.

---

## Section 4: Production Dependency Audit & Vulnerability Inventory Closure

A dependency security audit was conducted using `npm audit --omit=dev --json` on the backend service, evaluating 221 production dependencies. A total of 12 vulnerability advisories (spanning 6 distinct packages) were analyzed:

### 4.1 Dependency Vulnerability Inventory

```
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| Package Name  | Advisory  | Severity | CVSS / CWE            | Architectural Reachability & Risk Analysis                  |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| proxy-addr    | GHSA-jqcg | CRITICAL | 9.1                   | Transitive via express@4.21.2. IP spoofing via IPv4-mapped  |
| (1.1.0-2.0.7) | -44mw-7w3h|          | CWE-290, 348, 697     | IPv6 subnets. Backend runs on 127.0.0.1; reverse-proxy      |
|               |           |          |                       | trust is not enabled. Not exploitable in current setup.     |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| fast-uri      | GHSA-8v4j | HIGH     | 7.5                   | Transitive via AJV schema validator. SSRF and host          |
| (3.0.0-3.1.7) | -7jgf-552f|          | CWE-20, 918           | confusion via repeated percent-decoding. Schemas in use     |
|               | (5 total) |          |                       | validate internal JSON payloads; no external URL fetching.  |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| js-yaml       | GHSA-2883 | HIGH     | 7.5                   | Transitive via json-schema-ref-parser (Swagger). CPU DoS via|
| (4.0.0-4.3.1) | -xcg3-v3hh|          | CWE-400, 407          | merge keys. SentinelAI swagger schemas are static, not user-|
|               |           |          |                       | supplied. No untrusted YAML parsing occurs at runtime.      |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| morgan        | GHSA-jxfw | MODERATE | 5.3                   | Direct dependency. Log forging via unescaped Unicode line   |
| (<=1.12.0)    | -x594-9x9m|          | CWE-117               | separators and quotes. Backend uses Winston logPrivacy      |
|               | (2 total) |          |                       | sanitization pipeline. Morgan is auxiliary HTTP logger.     |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| qs            | GHSA-x5fp | MODERATE | 5.3                   | Transitive via body-parser / express@4. Denial of service   |
| (2.2.5-6.15.3)| -wj9c-mxmx|          | CWE-770, 248          | via bracket-key comma parsing and attacker isBuffer.        |
|               | (2 total) |          |                       | Express body limit capped at 100kb; impact low.             |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
| uuid          | GHSA-w5hq | MODERATE | 7.5                   | Direct dependency. Missing buffer bounds check in v3/v5/v6. |
| (<11.1.1)     | -g745-h8pq|          | CWE-787, 1285         | SentinelAI strictly uses uuid.v4() for random GUIDs;        |
|               |           |          |                       | vulnerable buffer-based v3/v5/v6 methods are never invoked. |
+---------------+-----------+----------+-----------------------+-------------------------------------------------------------+
```

### 4.2 Remediation Roadmaps & Express v5 Migration Analysis
- **Direct Dependencies**: `morgan` and `uuid` can be updated directly via semver bumps (`npm install morgan@latest uuid@latest`).
- **Transitive Express v4 Lock-in**: The critical advisory on `proxy-addr` and moderate advisory on `qs` originate inside Express 4.x core (`express > body-parser > qs` and `express > proxy-addr`). Resolving these without dependency overrides requires migrating to Express v5 (`express@5.x`).
- **Express v5 Migration Requirements**:
  1. *Router Signature Changes*: Express v5 removes legacy wildcard routing syntax `app.get('/api/resource/*')`.
  2. *Promise Error Handling*: Express v5 automatically forwards rejected promises to error middleware, which requires reviewing existing async wrapper middleware.
  3. *Query Parser Defaults*: Express v5 alters default query parser behavior from `extended` (`qs`) to `simple` (`querystring`), requiring explicit configuration in `server.js`.
- **Accepted Residual Risk**: Because the backend is strictly bound to `127.0.0.1`, does not ingest untrusted YAML files, sanitizes logs via Winston, and never calls `uuid.v3/v5/v6`, these vulnerabilities pose zero immediate exploitability in the local Windows environment. Upgrades are scheduled for the next major milestone.

---

## Section 5: Regression Testing, Invariants & Final Verdict

### 5.1 Comprehensive Test Suite Execution Summary
All primary test suites across backend, AI engine, and frontend were executed. Zero test failures were observed:

| Test Suite / Scope | Command Line Executed | Total Tests | Passed | Failed | Duration |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Backend Outbox & Observability** | `npm test -- tests/outboxStress.test.js tests/securityObservability.test.js` | 15 | 15 | 0 | 0.899s |
| **Backend Core Security & Policy** | `npm test -- tests/windowsFirewallSafety.test.js tests/nativeSafety.test.js tests/containmentPolicy.test.js tests/aiDependencyContract.test.js tests/authHardening.test.js tests/rateLimit.test.js tests/logPrivacy.test.js tests/mitreMapping.test.js` | 96 | 96 | 0 | 5.783s |
| **AI Model Evaluation Suite** | `.\.venv\Scripts\python.exe -m pytest tests/test_model_evaluation.py -v` | 15 | 15 | 0 | 20.35s |
| **Frontend Authentication & State** | `npm test` (in `frontend/`) | 34 | 34 | 0 | 0.414s |
| **Total Test Verification** | **All Configured Acceptance Test Suites** | **160** | **160** | **0** | **27.45s** |

### 5.2 Native Platform Invariant Verifications

1. **Process Liveness**: All 4 long-running services remained active without interruption or PID churn throughout the entire audit:
   - MongoDB: PID **28468** (Listening on `127.0.0.1:27017`)
   - AI Engine (`uvicorn`): PID **35672** (Listening on `127.0.0.1:8000`)
   - Backend (`node`): PID **39136** (Listening on `127.0.0.1:5000`)
   - Frontend (`vite`): PID **35704** (Listening on `127.0.0.1:3000`)

2. **Live Database Invariance**: Inspected the primary development database (`mongodb://127.0.0.1:27017/sentinel-db`). Confirmed that baseline data was strictly preserved with **zero unauthorized mutations**:
   - `users`: **1**
   - `authsessions`: **2**
   - `systemsettings`: **1**
   - `aipredictions`, `containmentactions`, `threatlogs`, `campaigns`, `trainingsamples`, `honeypotsessions`, `alerts`, `blockedips`: **0**

3. **Host Firewall Cleanliness**: Queried Windows Advanced Firewall via `Get-NetFirewallRule -DisplayName 'SentinelAI*'`. Confirmed that exactly **0** host firewall rules exist. The mock adapter safety gate was verified active and preventing unintended OS mutations on the developer workstation.

---

## Final Acceptance Verdict

### **PASS WITH LIMITATIONS**

The SentinelAI platform satisfies all functional, architectural, and security acceptance criteria for Phase 7. The system is structurally sound, resilient against event and outbox failures, and verified against native Windows platform constraints.

### Explicit Operational Limitations:
1. **Autonomous Containment Disabled**: Autonomous containment must remain disabled (`AUTONOMOUS_CONTAINMENT=false`) due to the 33.0% False Positive Rate observed on DDoS traffic distributions. All containment actions require human-in-the-loop analyst authorization.
2. **Real Windows Firewall Gating**: Real Windows Firewall enforcement (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true`) must remain restricted to dedicated, isolated Windows Server testbeds running under WinSW service supervision with elevated credentials.
3. **At-Least-Once Delivery**: Downstream consumers of the outbox security bus must handle idempotent deliveries using the `eventId` envelope field.
4. **Dependency Hardening Milestone**: Before external network deployment or public Internet exposure, Express v5 migration and direct package upgrades (`uuid`, `morgan`) must be completed to eliminate legacy transitives.
