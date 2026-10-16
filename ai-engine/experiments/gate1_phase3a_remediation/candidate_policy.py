"""SentinelAI — GATE-1 Phase 3A: Candidate Policy Module
Location: ai-engine/experiments/gate1_phase3a_remediation/candidate_policy.py

Pure, isolated candidate implementation for remediating the policy recall collapse.
Preserves production code in ai-engine/inference/predictor.py unchanged.
"""

import sys
import time
import math
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import numpy as np

# Ensure ai-engine is in python path for feature definitions
CURRENT_DIR = Path(__file__).resolve().parent
AI_ENGINE_DIR = CURRENT_DIR.parent.parent
if str(AI_ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_DIR))

try:
    from utils.features import FEATURE_NAMES, LABEL_NAMES, extract_features_from_record
except ImportError:
    FEATURE_NAMES = [f"f_{i}" for i in range(53)]
    LABEL_NAMES = {0: "BENIGN", 1: "SSH Brute Force", 2: "Port Scan", 3: "DDoS", 4: "Malware Beacon", 5: "XSS Attempt", 6: "SQL Injection", 7: "Credential Stuffing"}

log = logging.getLogger("sentinel.candidate_policy")

# Operational and Experimental Thresholds
BLOCK_THRESHOLD = 0.92
MONITOR_THRESHOLD = 0.70
ANOMALY_THRESHOLD = -0.55
EXPERIMENTAL_CONFIDENCE_THRESHOLD = 0.85

# Isolation Forest Boundary Constants (from CICIDS2017 training)
IF_DEFAULT_OFFSET = -0.47402357424116837
IF_ANOMALY_SPAN = 0.20


class PolicyException(Exception):
    """Base exception for policy evaluation."""
    pass


class NonFiniteFeatureError(PolicyException):
    """Raised when feature vector contains NaN, Inf, or unparseable numbers."""
    pass


class InferenceTimeoutError(PolicyException):
    """Raised when inference latency exceeds operational budget."""
    pass


class CandidateModelUnavailableError(PolicyException):
    """Raised when required models are not loaded or accessible."""
    pass


def score_to_severity(s: float) -> str:
    """Standardized threat score to severity mapping."""
    if s >= 0.90:
        return "CRITICAL"
    if s >= 0.70:
        return "HIGH"
    if s >= 0.50:
        return "MEDIUM"
    return "LOW"


def calculate_if_anomaly_signal(if_score: Optional[float], offset: float = IF_DEFAULT_OFFSET) -> float:
    """
    Transforms raw Isolation Forest score_samples() output to a bounded anomaly score in [0.0, 1.0].
    - Inliers (score_samples >= offset): returns 0.0
    - Outliers (score_samples < offset): returns normalized deflection in (0.0, 1.0]
    """
    if if_score is None:
        return 0.0
    try:
        val = float(if_score)
        if np.isnan(val) or np.isinf(val):
            return 0.0
    except (ValueError, TypeError):
        return 0.0

    if val >= offset:
        return 0.0

    deflection = offset - val
    return round(float(min(deflection / IF_ANOMALY_SPAN, 1.0)), 4)


class CandidateSentinelPolicy:
    """
    Decoupled decision policy for SentinelAI.
    
    Eliminates the multiplicative attenuation trap (0.7 * rf + 0.3 * if) while:
    1. Preserving zero false positive actions on benign flows (FPR <= 0.10%).
    2. Elevating high-confidence supervised attack detections directly to MONITOR or BLOCK.
    3. Handling inference timeouts and failures with an explicit, observable, non-blocking fail-safe.
    """

    def __init__(
        self,
        block_threshold: float = BLOCK_THRESHOLD,
        monitor_threshold: float = MONITOR_THRESHOLD,
        anomaly_threshold: float = ANOMALY_THRESHOLD,
        experimental_confidence_threshold: float = EXPERIMENTAL_CONFIDENCE_THRESHOLD,
    ):
        self.block_threshold = block_threshold
        self.monitor_threshold = monitor_threshold
        self.anomaly_threshold = anomaly_threshold
        self.exp_conf_threshold = experimental_confidence_threshold

    def evaluate_signals(
        self,
        cname: str,
        confidence: float,
        is_anomaly: bool,
        anomaly_signal: float,
        anomaly_score: float = 0.0,
        inference_time_ms: float = 0.0,
        model_version: str = "candidate-v3.0",
    ) -> Dict[str, Any]:
        """
        Pure decision function that maps raw model signals to operational action and threat score.
        """
        cname = str(cname).strip() if cname else "BENIGN"
        p = float(confidence) if confidence is not None else 0.0
        p = max(0.0, min(1.0, p))
        sig = float(anomaly_signal) if anomaly_signal is not None else 0.0
        sig = max(0.0, min(1.0, sig))

        final_class = cname
        rule_applied = ""

        # Case 1: Supervised Classifier predicts BENIGN
        if cname == "BENIGN":
            if is_anomaly:
                # Novelty / Outlier discovery on normal traffic
                # Emits telemetry alert under 'Unknown' label without containment disruption
                final_class = "Unknown"
                score = 0.55
                rule_applied = "R-2: Benign Outlier (Telemetry Only)"
            else:
                # Normal legitimate traffic
                score = 0.05
                rule_applied = "R-1: Normal Benign"

        # Case 2: Supervised Classifier predicts Confirmed Attack
        else:
            if p >= self.exp_conf_threshold:
                # High-confidence attack prediction (Hypothesis threshold: >= 0.85)
                # Anomaly detector acts as an ADDITIVE BOOSTER, not an attenuator
                if is_anomaly and sig > 0.0:
                    score = min(p + 0.10 * sig, 0.99)
                    rule_applied = "R-8: High-Confidence Attack with Anomaly Boost"
                else:
                    # Inlying attack (e.g. stealthy PortScan)
                    score = p
                    rule_applied = "R-7: High-Confidence Attack (Inlier Preserved)"

            elif p >= self.monitor_threshold:
                # Medium-high confidence attack (0.70 <= p < 0.85)
                if is_anomaly and sig > 0.0:
                    score = min(p + 0.15 * sig, 0.919)
                    rule_applied = "R-6: Medium-High Attack with Anomaly Boost"
                else:
                    score = p
                    rule_applied = "R-5: Medium-High Attack (Inlier Preserved)"

            elif p >= 0.60:
                # Borderline attack confidence (0.60 <= p < 0.70)
                if is_anomaly and sig > 0.0:
                    score = min(p + 0.20 * sig, 0.85)
                    rule_applied = "R-4B: Borderline Attack with Anomaly Consensus"
                else:
                    # Low anomaly, suppress below monitor threshold
                    score = round(p * 0.90, 4)
                    rule_applied = "R-4A: Borderline Attack Suppressed"

            else:
                # Low confidence detection (p < 0.60)
                if is_anomaly and sig > 0.50:
                    score = round(min(p + 0.25 * sig, 0.75), 4)
                    rule_applied = "R-3B: Low-Confidence with Strong Anomaly"
                else:
                    score = round(p * 0.80, 4)
                    rule_applied = "R-3A: Low-Confidence Suppressed"

        # Round final score
        score = round(float(score), 4)

        # Operational Action Mapping
        if score >= self.block_threshold:
            action = "BLOCK"
        elif score >= self.monitor_threshold:
            action = "MONITOR"
        else:
            action = "ALLOW"

        # Severity
        severity = score_to_severity(score)

        return {
            "predictedClass": final_class,
            "threatScore": score,
            "severity": severity,
            "confidence": round(p, 4),
            "isAnomaly": bool(is_anomaly),
            "anomalyScore": round(float(anomaly_score), 4),
            "anomalySignal": round(sig, 4),
            "action": action,
            "ruleApplied": rule_applied,
            "inferenceTimeMs": round(float(inference_time_ms), 2),
            "modelVersion": model_version,
            "autonomousBlockEligible": (action == "BLOCK"),
            "status": "BLOCKED" if action == "BLOCK" else "MONITORING" if action == "MONITOR" else "DETECTED" if final_class == "Unknown" else "ALLOW",
            "isFailSafe": False,
        }

    def handle_inference_failure(
        self,
        failure_type: str,
        error_detail: str,
        source_ip: str = "UNKNOWN",
        inference_time_ms: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Explicit, observable fail-safe policy for inference service failures.
        
        Guarantees:
        - Never claims uninspected traffic is BENIGN.
        - Never automatically blocks traffic as a default fallback.
        - Emits action=MONITOR, status=DEGRADED for analyst visibility.
        """
        log.warning(f"Inference failure encountered ({failure_type}): {error_detail}")
        return {
            "predictedClass": "UNINSPECTED_TRAFFIC",
            "threatScore": 0.50,
            "severity": "MEDIUM",
            "confidence": 0.0,
            "isAnomaly": False,
            "anomalyScore": 0.0,
            "anomalySignal": 0.0,
            "action": "MONITOR",
            "status": "DEGRADED",
            "failureType": failure_type,
            "errorDetail": str(error_detail),
            "inferenceTimeMs": round(float(inference_time_ms), 2),
            "modelVersion": "fail-safe-fallback",
            "autonomousBlockEligible": False,
            "isFailSafe": True,
            "requiresHumanReview": True,
            "sourceIP": source_ip,
        }

    def evaluate_flow_record(
        self,
        record: Dict[str, Any],
        rf_pipeline: Any,
        if_pipeline: Any,
        timeout_sec: float = 5.0,
    ) -> Dict[str, Any]:
        """
        End-to-end evaluation of a raw network flow record using the candidate policy.
        """
        t0 = time.perf_counter()
        source_ip = record.get("sourceIP", record.get("Source IP", "0.0.0.0"))

        if rf_pipeline is None or if_pipeline is None:
            return self.handle_inference_failure(
                failure_type="MODEL_UNAVAILABLE",
                error_detail="Required machine learning pipelines are not loaded",
                source_ip=source_ip,
            )

        # 1. Feature extraction & input validation
        try:
            # Check for non-finite values in raw record
            has_invalid_num = False
            for k, v in record.items():
                if isinstance(v, (float, int)) and (np.isnan(v) or np.isinf(v)):
                    has_invalid_num = True
                    break

            X = extract_features_from_record(record).reshape(1, -1)
            if has_invalid_num or not np.isfinite(X).all():
                return {
                    "predictedClass": "INVALID_INPUT",
                    "threatScore": 0.0,
                    "severity": "LOW",
                    "confidence": 0.0,
                    "isAnomaly": False,
                    "anomalyScore": 0.0,
                    "anomalySignal": 0.0,
                    "action": "ALLOW_AUDITED",
                    "status": "INPUT_ERROR",
                    "failureType": "NON_FINITE_FEATURES",
                    "errorDetail": "Features contain NaN, Inf, or invalid numerical values",
                    "inferenceTimeMs": round((time.perf_counter() - t0) * 1000, 2),
                    "isFailSafe": True,
                    "requiresHumanReview": True,
                    "sourceIP": source_ip,
                }
        except Exception as e:
            return self.handle_inference_failure(
                failure_type="FEATURE_EXTRACTION_ERROR",
                error_detail=str(e),
                source_ip=source_ip,
                inference_time_ms=(time.perf_counter() - t0) * 1000,
            )

        # 2. Supervised Classification
        try:
            cls_idx = int(rf_pipeline.predict(X)[0])
            proba = rf_pipeline.predict_proba(X)[0]
            cname = LABEL_NAMES.get(cls_idx, "BENIGN")
            max_p = float(np.max(proba))
        except Exception as e:
            return self.handle_inference_failure(
                failure_type="SUPERVISED_INFERENCE_ERROR",
                error_detail=str(e),
                source_ip=source_ip,
                inference_time_ms=(time.perf_counter() - t0) * 1000,
            )

        # 3. Unsupervised Anomaly Detection
        try:
            scaler = if_pipeline.named_steps["scaler"]
            ifo = if_pipeline.named_steps["if"]
            X_scaled = scaler.transform(X)
            if_score = float(ifo.score_samples(X_scaled)[0])
            offset = float(getattr(ifo, "offset_", IF_DEFAULT_OFFSET))
            is_anomaly = bool(if_score < self.anomaly_threshold)
            anomaly_signal = calculate_if_anomaly_signal(if_score, offset=offset)
        except Exception as e:
            return self.handle_inference_failure(
                failure_type="ANOMALY_INFERENCE_ERROR",
                error_detail=str(e),
                source_ip=source_ip,
                inference_time_ms=(time.perf_counter() - t0) * 1000,
            )

        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Check latency budget
        if elapsed_ms > (timeout_sec * 1000):
            return self.handle_inference_failure(
                failure_type="INFERENCE_TIMEOUT",
                error_detail=f"Inference latency ({elapsed_ms:.1f}ms) exceeded budget ({timeout_sec*1000:.1f}ms)",
                source_ip=source_ip,
                inference_time_ms=elapsed_ms,
            )

        decision = self.evaluate_signals(
            cname=cname,
            confidence=max_p,
            is_anomaly=is_anomaly,
            anomaly_signal=anomaly_signal,
            anomaly_score=if_score,
            inference_time_ms=elapsed_ms,
        )
        decision["sourceIP"] = source_ip
        return decision
