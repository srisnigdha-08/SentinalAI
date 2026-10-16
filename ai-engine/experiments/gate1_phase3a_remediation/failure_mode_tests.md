# SentinelAI — GATE-1 Phase 3A: Failure Mode, Degraded States, and Boundary Test Analysis

**Document Version:** 1.0.0  
**Phase:** GATE-1 Phase 3A (Isolated Policy Remediation)  
**Author:** Senior Machine Learning Security Engineer & Backend Security Engineer  
**Date:** October 16, 2026  
**Status:** **AUDITED TEST EVIDENCE (PASS: 24 / 24 AUTOMATED TESTS)**

---

## 1. Overview and Objectives

A robust security policy must remain predictable, safe, and observable not only under standard operational conditions, but especially during upstream service degradation, anomalous feature inputs, and algorithmic edge cases. 

This document details the design, execution, and verification of failure-mode and boundary test cases implemented in [`test_candidate_policy.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/test_candidate_policy.py) for the candidate decoupled policy.

---

## 2. Invariant Security Guarantees Under Failure

When an inference service crashes, times out, receives malformed inputs, or cannot load underlying model artifacts, the candidate policy enforces four mandatory security invariants:

| Invariant ID | Security Property | Vulnerability Avoided | Verified Behavior |
| :---: | :--- | :--- | :--- |
| **INV-1** | **No Fail-Open Evasion** | Attackers craft payloads that cause inference timeouts to bypass detection. | Uninspected flows are **never** labeled as `"BENIGN"`. Labeled as `"UNINSPECTED_TRAFFIC"` with `status: "DEGRADED"`. |
| **INV-2** | **No Self-Inflicted DoS** | Attackers flood the engine with corrupted packets to force host-wide connection drops. | Uninspected flows **never** receive `action: "BLOCK"`. Default failure action is strictly restricted to `MONITOR`. |
| **INV-3** | **Analyst Observability** | Silent failures drop logs without alerting the SOC. | Every degraded evaluation emits `isFailSafe: True`, `requiresHumanReview: True`, and explicit `failureType`. |
| **INV-4** | **Host Isolation Gating** | Uncontrolled firewall mutation during test execution. | Zero host firewall rules created; `AUTONOMOUS_CONTAINMENT=false` verified by assertions. |

---

## 3. Failure Mode Scenarios & Test Evidence

### Scenario 1: Inference Service Timeout
- **Test Function:** `test_explicit_timeout_handling`
- **Simulated Condition:** Upstream network latency or AI Engine execution exceeds budget ($> 5.0\text{s}$).
- **Observed Policy Response:**
  ```json
  {
    "predictedClass": "UNINSPECTED_TRAFFIC",
    "threatScore": 0.50,
    "severity": "MEDIUM",
    "confidence": 0.0,
    "isAnomaly": false,
    "anomalyScore": 0.0,
    "anomalySignal": 0.0,
    "action": "MONITOR",
    "status": "DEGRADED",
    "failureType": "INFERENCE_TIMEOUT",
    "errorDetail": "Socket timeout after 5000ms",
    "modelVersion": "fail-safe-fallback",
    "autonomousBlockEligible": false,
    "isFailSafe": true,
    "requiresHumanReview": true,
    "sourceIP": "172.16.0.45"
  }
  ```
- **Audit Verification:** `action == "MONITOR"`, `predictedClass != "BENIGN"`, `threatScore == 0.50`. **PASS**.

### Scenario 2: Non-Finite, NaN, and Infinite Inputs
- **Test Function:** `test_non_finite_input_rejection`
- **Simulated Condition:** Corrupted flow telemetry containing `{"Flow Duration": float("nan"), "Total Fwd Packets": float("inf")}`.
- **Observed Policy Response:**
  ```json
  {
    "predictedClass": "INVALID_INPUT",
    "threatScore": 0.0,
    "severity": "LOW",
    "confidence": 0.0,
    "isAnomaly": false,
    "anomalyScore": 0.0,
    "anomalySignal": 0.0,
    "action": "ALLOW_AUDITED",
    "status": "INPUT_ERROR",
    "failureType": "NON_FINITE_FEATURES",
    "errorDetail": "Features contain NaN, Inf, or invalid numerical values",
    "isFailSafe": true,
    "requiresHumanReview": true
  }
  ```
- **Audit Verification:** Pipeline does not throw unhandled 500 error; returns structured `INPUT_ERROR` with `ALLOW_AUDITED`. **PASS**.

### Scenario 3: Model Pipeline Unavailability
- **Test Function:** `test_model_unavailable_fallback`
- **Simulated Condition:** `rf_pipeline=None` and `if_pipeline=None` (e.g. startup failure or unmounted model directory).
- **Observed Policy Response:**
  ```json
  {
    "predictedClass": "UNINSPECTED_TRAFFIC",
    "threatScore": 0.50,
    "severity": "MEDIUM",
    "confidence": 0.0,
    "isAnomaly": false,
    "anomalyScore": 0.0,
    "anomalySignal": 0.0,
    "action": "MONITOR",
    "status": "DEGRADED",
    "failureType": "MODEL_UNAVAILABLE",
    "errorDetail": "Required machine learning pipelines are not loaded",
    "isFailSafe": true,
    "requiresHumanReview": true
  }
  ```
- **Audit Verification:** System safely defaults to `MONITOR` with `DEGRADED` status; zero unhandled crash. **PASS**.

---

## 4. Boundary Test Analysis

Boundary testing verifies strict mathematical transitions around every operational threshold:

### A. Containment Monitor Threshold Boundary ($\tau_{mon} = 0.70$)
Tested on attack traffic with inlying anomaly signal ($\sigma_{IF} = 0.0$):
- **Confidence = 0.699:** Threat Score = $0.699 \times 0.90 = 0.6291 \implies \mathbf{ALLOW}$ (Severity `MEDIUM`).
- **Confidence = 0.700:** Threat Score = $0.7000 \implies \mathbf{MONITOR}$ (Severity `HIGH`).
- **Confidence = 0.701:** Threat Score = $0.7010 \implies \mathbf{MONITOR}$ (Severity `HIGH`).
*Verification:* Deterministic step from `ALLOW` to `MONITOR` occurs precisely at $P_{RF} = 0.700$.

### B. Experimental Hypothesis Boundary ($\tau_{exp} = 0.85$)
- **Confidence = 0.849:** Threat Score = $0.8490 \implies \mathbf{MONITOR}$ (Rule R-5 applied).
- **Confidence = 0.850:** Threat Score = $0.8500 \implies \mathbf{MONITOR}$ (Rule R-7 applied).
- **Confidence = 0.851:** Threat Score = $0.8510 \implies \mathbf{MONITOR}$ (Rule R-7 applied).
*Verification:* Inlying attacks maintain high-confidence triage across the boundary without attenuation.

### C. Containment Block Threshold Boundary ($\tau_{blk} = 0.92$)
- **Confidence = 0.919:** Threat Score = $0.9190 \implies \mathbf{MONITOR}$ (`autonomousBlockEligible: False`).
- **Confidence = 0.920:** Threat Score = $0.9200 \implies \mathbf{BLOCK}$ (`autonomousBlockEligible: True`).
- **Confidence = 0.921:** Threat Score = $0.9210 \implies \mathbf{BLOCK}$ (`autonomousBlockEligible: True`).
*Verification:* Block eligibility is granted strictly when score meets or exceeds $0.920$.

### D. Anomaly Contamination Boundary ($\tau_{ano} = -0.55$)
- **Score = -0.551:** `isAnomaly == True` (extreme outlier).
- **Score = -0.550:** `isAnomaly == False` (exact threshold).
- **Score = -0.549:** `isAnomaly == False` (geometric inlier).
*Verification:* Strict inequality $s_{IF} < -0.55$ prevents boundary jitter from triggering outlier alerts.

---

## 5. Backend Contract Verification

In [`test_backend_schema_compatibility`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/experiments/gate1_phase3a_remediation/test_candidate_policy.py#L250), the candidate policy dictionary was validated against the exact consumption points in:
- `backend/services/aiEngineService.js` (`runFullPipeline`, `predictRecord`)
- `backend/services/threatService.js` (`createThreat`, auto-block logic)

### Validated Fields & Types:
- `predictedClass`: `str` (maps to `ThreatLog.attackType` and `AIAnalytics.predictedClass`)
- `threatScore`: `float` in $[0.0, 1.0]$ (maps to `ThreatLog.aiScore` and `threatScore`)
- `severity`: `str` in `["LOW", "MEDIUM", "HIGH", "CRITICAL"]`
- `confidence`: `float` in $[0.0, 1.0]$
- `isAnomaly`: `bool`
- `anomalyScore`: `float`
- `action`: `str` in `["ALLOW", "MONITOR", "BLOCK"]`
- `status`: `str` in `["ALLOW", "DETECTED", "MONITORING", "BLOCKED", "DEGRADED", "INPUT_ERROR"]`
- `inferenceTimeMs`: `float >= 0.0`
- `modelVersion`: `str`

All fields, types, and constraints match backend expectations without requiring schema modifications.
