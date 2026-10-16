"""
SentinelAI Modular Threat Detection Package
Phase 9C Implementation Milestone: Staged Modular Scaffold & Safety Contracts
"""

from modular.contracts import (
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    EvidenceRecord,
    SimulatedMitigation,
    DetectorResult,
    EnsembleResult,
    validate_finite_score,
    create_degraded_result,
)
from modular.sanitizer import (
    sanitize_telemetry,
    assert_isolated_from_ground_truth,
    detect_ground_truth_keys,
)
from modular.state import (
    BoundedConnectionStateTable,
    ConnectionStateEntry,
    StateMetrics,
)
from modular.base import BaseDetector
from modular.orchestrator import (
    ModularOrchestrator,
    is_modular_enabled,
)

__all__ = [
    "DetectorStatus",
    "PolicyDecision",
    "SeverityLevel",
    "MitigationAction",
    "EvidenceRecord",
    "SimulatedMitigation",
    "DetectorResult",
    "EnsembleResult",
    "validate_finite_score",
    "create_degraded_result",
    "sanitize_telemetry",
    "assert_isolated_from_ground_truth",
    "detect_ground_truth_keys",
    "BoundedConnectionStateTable",
    "ConnectionStateEntry",
    "StateMetrics",
    "BaseDetector",
    "ModularOrchestrator",
    "is_modular_enabled",
]
