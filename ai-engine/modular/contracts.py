"""
SentinelAI Modular Threat Detection Architecture - Shared Common Contracts
Phase 9C Implementation Milestone: Staged Modular Scaffold & Safety Contracts

This module defines the typed JSON-serializable contracts, strict numerical validation,
explicit operational statuses, and fail-safe policy consensus types specified in Phase 9B.
"""

from __future__ import annotations
import math
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class DetectorStatus(str, Enum):
    """
    Explicit operational status representing inspection fidelity.
    An uninspected, timed out, or failing detector MUST never silently report HEALTHY.
    """
    HEALTHY = "HEALTHY"            # Full inspection completed normally
    DEGRADED = "DEGRADED"          # Partial inspection completed; fidelity impaired
    TIMEOUT = "TIMEOUT"            # Execution exceeded allotted time limit
    UNAVAILABLE = "UNAVAILABLE"    # Required model, dependency, or socket is unreachable
    UNSUPPORTED = "UNSUPPORTED"    # Input protocol/payload not supported by this detector
    INCOMPLETE = "INCOMPLETE"      # Telemetry missing required fields for full inspection
    ERROR = "ERROR"                # Unhandled internal exception encountered during execution


class PolicyDecision(str, Enum):
    """
    Detection decision representing threat identification.
    Separated strictly from physical mitigation or containment enforcement.
    """
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    DETECTED = "DETECTED"
    SIMULATED_BLOCK = "SIMULATED_BLOCK"


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MitigationAction(str, Enum):
    """
    Simulated mitigation recommendation.
    NOTE: Real host firewall enforcement remains locked. Real network mutation is prohibited.
    """
    NONE = "NONE"
    SIMULATED_BLOCK = "SIMULATED_BLOCK"
    SIMULATED_RATE_LIMIT = "SIMULATED_RATE_LIMIT"


def validate_finite_score(score: Any, field_name: str = "confidence") -> float:
    """
    Strictly validates that a score is a finite real number in [0.0, 1.0].
    Rejects NaN, +Inf, -Inf, None, booleans, strings, or out-of-range floats.
    """
    if score is None:
        raise ValueError(f"Invalid {field_name}: score cannot be None")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise TypeError(f"Invalid {field_name}: score must be a real number, got {type(score).__name__}")
    val = float(score)
    if not math.isfinite(val):
        raise ValueError(f"Invalid {field_name}: non-finite score rejected (got {val})")
    if val < 0.0 or val > 1.0:
        raise ValueError(f"Invalid {field_name}: score {val} outside required bounds [0.0, 1.0]")
    return round(val, 6)


class EvidenceRecord(BaseModel):
    """Structured audit evidence explaining why a detector reached its verdict."""
    trigger_rule: str = Field(..., description="Signature ID, threshold rule, or invariant violated")
    summary: str = Field(..., description="Human-readable explanation of the finding")
    extracted_features: Dict[str, Any] = Field(default_factory=dict, description="Key features or metrics observed")


class SimulatedMitigation(BaseModel):
    """
    Explicit simulated mitigation recommendation.
    Enforces separation between detection and physical containment.
    """
    action: MitigationAction = Field(default=MitigationAction.NONE)
    simulated: bool = Field(default=True, description="Strictly True; real firewall mutation is prohibited")
    watermark: str = Field(default="[SIMULATED BLOCK]", description="Operator dashboard display watermark")

    @model_validator(mode="after")
    def enforce_simulation(self) -> SimulatedMitigation:
        if not self.simulated:
            raise ValueError("Safety Violation: Real firewall containment cannot be enabled in this milestone.")
        return self


class DetectorResult(BaseModel):
    """
    Unified typed contract for all specialized modular detectors.
    Adheres strictly to Phase 9B JSON Schema specification.
    """
    detector_id: str = Field(..., min_length=1, description="Unique identifier for detector module")
    version: str = Field(..., min_length=1, description="Semantic version of detector")
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Trace correlation UUID")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of inspection"
    )
    status: DetectorStatus = Field(..., description="Operational status of inspection")
    decision: PolicyDecision = Field(..., description="Detection decision")
    confidence: float = Field(..., description="Confidence score in [0.0, 1.0]")
    severity: SeverityLevel = Field(..., description="Severity level")
    execution_time_ms: float = Field(default=0.0, ge=0.0, description="Execution elapsed time in ms")
    evidence: EvidenceRecord = Field(..., description="Structured audit evidence")
    mitigation_recommendation: SimulatedMitigation = Field(
        default_factory=SimulatedMitigation,
        description="Simulated mitigation action"
    )

    @field_validator("confidence")
    @classmethod
    def check_confidence_finite(cls, v: Any) -> float:
        return validate_finite_score(v, "confidence")

    @field_validator("execution_time_ms")
    @classmethod
    def check_execution_time_finite(cls, v: Any) -> float:
        if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
            raise TypeError("execution_time_ms must be a non-negative finite number")
        val = float(v)
        if not math.isfinite(val) or val < 0.0:
            raise ValueError("execution_time_ms must be a non-negative finite number")
        return round(val, 3)

    @model_validator(mode="after")
    def validate_invariants(self) -> DetectorResult:
        # Invariant 1: If status is non-HEALTHY, confidence cannot indicate high-fidelity certainty
        if self.status != DetectorStatus.HEALTHY and self.decision == PolicyDecision.ALLOW:
            # An error or degraded detector cannot claim verified ALLOW
            raise ValueError(
                f"Contract Violation: Detector '{self.detector_id}' reported status={self.status.value} "
                f"but claimed decision=ALLOW. Uninspected or failed traffic cannot silently pass."
            )
        return self


def create_degraded_result(
    detector_id: str,
    status: DetectorStatus,
    reason: str,
    correlation_id: Optional[str] = None,
    execution_time_ms: float = 0.0
) -> DetectorResult:
    """
    Factory helper to generate a standardized DEGRADED/ERROR/TIMEOUT DetectorResult.
    Guarantees fail-safe behavior: decisions default to MONITOR, confidence to 0.0, never ALLOW.
    """
    if status == DetectorStatus.HEALTHY:
        raise ValueError("Cannot create a degraded result with HEALTHY status")
    
    cid = correlation_id or str(uuid.uuid4())
    return DetectorResult(
        detector_id=detector_id,
        version="fail-safe-1.0",
        correlation_id=cid,
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=status,
        decision=PolicyDecision.MONITOR,
        confidence=0.0,
        severity=SeverityLevel.MEDIUM if status in (DetectorStatus.TIMEOUT, DetectorStatus.ERROR) else SeverityLevel.LOW,
        execution_time_ms=max(0.0, float(execution_time_ms)),
        evidence=EvidenceRecord(
            trigger_rule="FAIL_SAFE_DEGRADATION",
            summary=f"Detector entered {status.value} state: {reason}",
            extracted_features={"degradation_reason": reason, "raw_status": status.value}
        ),
        mitigation_recommendation=SimulatedMitigation(
            action=MitigationAction.NONE,
            simulated=True,
            watermark="[INSPECTION DEGRADED - MONITOR]"
        )
    )


class EnsembleResult(BaseModel):
    """
    Unified multi-tier ensemble consensus result produced by the Modular Orchestrator.
    """
    correlation_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ensemble_status: DetectorStatus
    overall_decision: PolicyDecision
    max_threat_confidence: float
    simulated_block: bool
    requires_triage: bool
    is_duplicate: bool = False
    detector_results: Dict[str, DetectorResult]
    degraded_detectors: List[str] = Field(default_factory=list)
    summary_evidence: str
