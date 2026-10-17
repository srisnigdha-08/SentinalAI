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
from modular.volumetric_flood import VolumetricFloodDetector
from modular.auth_abuse import AuthAbuseDetector
from modular.layer7_waf import Layer7WAFDetector
from modular.auth_event_adapter import (
    AuthEventDetector,
    AuthEvent,
    AuthEventType,
    parse_auth_event,
)
from modular.host_telemetry_adapter import (
    HostTelemetryDetector,
    HostTelemetryEvent,
    HostEventType,
    parse_host_telemetry,
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
    "VolumetricFloodDetector",
    "AuthAbuseDetector",
    "Layer7WAFDetector",
    "AuthEventDetector",
    "AuthEvent",
    "AuthEventType",
    "parse_auth_event",
    "HostTelemetryDetector",
    "HostTelemetryEvent",
    "HostEventType",
    "parse_host_telemetry",
]
