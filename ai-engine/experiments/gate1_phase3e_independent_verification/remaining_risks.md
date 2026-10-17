# SentinelAI GATE-1 Phase 3E: Remaining Technical Risks and Release Blockers

**Auditor**: Independent Software Auditor & ML Security Engineer  
**Date**: 2026-10-16  
**Status**: **Authoritative Risk Assessment**  
**Gate 1 Verdict**: **MUST REMAIN OPEN**

---

## 1. Executive Summary

While the Phase 3D backend patch successfully resolved several critical failure-handling defects, this independent verification demonstrates that **GATE-1 cannot be closed**. 

The fundamental security mission of SentinelAI depends upon reliable machine-learning classification and sound containment decisions. Multiple critical risks remain unaddressed in the ML models, runtime inference, log management, and frontend operators' interface.

---

## 2. Detailed Technical Risk Matrix

| Risk ID | Subsystem | Severity | Description | Current State | Blocker for GATE-1? |
| :--- | :--- | :---: | :--- | :--- | :---: |
| **RISK-01** | AI Model Policy | **CRITICAL** | PortScan policy recall collapse (7.4%) and DDoS false-positive vulnerability. | Baseline policy in `predictor.py` suppresses high-confidence supervised attack predictions when Isolation Forest signals inlier. | **YES (Primary Blocker)** |
| **RISK-02** | AI Policy Integration | **CRITICAL** | Phase 3A candidate policy is not deployed to runtime `predictor.py`. | Phase 3A candidate policy remains isolated in experiment directories; production runtime is unmodified. | **YES** |
| **RISK-03** | Backend Score Clamping | **MEDIUM** | Non-finite / `NaN` threat scores evaluate to `ALLOW`. | `Number(result.threatScore || 0)` produces `NaN` for non-numeric strings, which evaluates to `false` in comparisons and falls through to `ALLOW`. | **YES (Must be patched)** |
| **RISK-04** | Reinforcement Learning | **HIGH** | Runtime Q-table diverged from Baseline Q-table (`55C3...` vs `BF9B...`). | Runtime Q-table exhibits drift from baseline; reward convergence and containment stability not validated. | **YES** |
| **RISK-05** | Emergency Audit Storage | **MEDIUM** | Unbounded timestamped log file accumulation on disk. | `checkRotation()` creates `emergency_audit.<timestamp>.log` without deleting older rotations; risks disk exhaustion during extended outages. | **NO (Hardening recommendation)** |
| **RISK-06** | Multi-Process Logging | **LOW** | Lack of OS file locking on Windows NTFS. | In multi-process worker configurations, concurrent writes during DB outages could encounter `EBUSY` file contention. | **NO (Single-process safe)** |
| **RISK-07** | Frontend UI Filter | **LOW** | `ThreatLogs.jsx` attack-type filter dropdown lacks `'UNINSPECTED_TRAFFIC'`. | Uninspected flows display in table and match text search, but cannot be filtered via the category dropdown. | **NO (UI refinement)** |
| **RISK-08** | Containment Governance | **CRITICAL** | Autonomous containment and real firewall enforcement cannot be enabled. | Enforcing containment while PortScan recall is 7.4% and DDoS FP rate is unverified would disrupt benign traffic and fail attacks. | **YES** |

---

## 3. Deep-Dive on Remaining Primary Blockers

### 3.1 Primary Blocker: Supervised Model Recall & Policy Gate Failure (RISK-01 & RISK-02)
- In Phase 2 and Phase 3B audits, it was proven that the production policy in `ai-engine/inference/predictor.py` escalates only **7.40% of PortScan attacks** and **76.60% of DDoS attacks** to `MONITOR` or `BLOCK`.
- This occurs because the baseline policy gates supervised predictions behind an Isolation Forest anomaly check (`anomaly_score > 0.0`). Because PortScan attacks closely mimic normal TCP handshake patterns, the Isolation Forest classifies them as inliers (`anomaly_score = -0.05`), which the baseline policy maps to `ALLOW`.
- Although Phase 3A formulated an isolated candidate policy remediation, that candidate **has not yet been integrated into production runtime**, nor has it been validated against live, real-world network traffic.

### 3.2 Backend Logic Gap: Non-Finite Score Flaw (RISK-03)
- Discovered during Phase 3E verification of Case 8:
  ```javascript
  const score = Math.max(0, Math.min(1, Number(result.threatScore || 0)))
  ```
  If `result.threatScore` is a non-numeric string (e.g. `'NaN'`, `'null'`, `'undefined'`), `Number` returns `NaN`. `Math.max(0, Math.min(1, NaN))` returns `NaN`.
  The pipeline evaluates:
  ```javascript
  action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  ```
  Because `NaN >= 0.7` is `false`, **the flow is classified as `ALLOW`**, permitting uninspected or corrupt traffic through without hold or alarm.

### 3.3 Q-Table Drift & Autonomous Enforcement Danger (RISK-04 & RISK-08)
- Baseline Q-table SHA-256: `BF9B46A1D1CF1B283797A544E7E597900B4A042E6C87AC199A3CC709498990FF`
- Runtime Q-table SHA-256: `55C37D38B3006AC53FD3D741AC186C265C47E2B528560EEF4209BCACF4A35B27`
- The runtime Q-table has drifted by $100\%$ from the baseline. Enabling autonomous containment (`AUTONOMOUS_CONTAINMENT=true`) before reward convergence is mathematically established risks erratic automated firewall blocks.

---

## 4. Safest Next Steps

1. **Keep GATE-1 strictly OPEN.**
2. **Apply surgical patch to `aiEngineService.js` L85**:
   ```javascript
   const rawScore = Number(result.threatScore)
   const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(1, rawScore)) : 0.5
   ```
3. **Advance to Phase 4 (Candidate Policy Integration & Multi-Attack Evaluation)**:
   - Carefully promote the Phase 3A candidate policy into a testable runtime environment.
   - Benchmark the candidate policy against the full 19,036-flow multi-attack evaluation dataset to verify that PortScan recall recovers without inflating the benign false-positive rate.
4. **Audit Q-Table Convergence**: Perform an offline reward convergence study on `ai-engine/runtime/q_table.json` against simulated state transitions.
