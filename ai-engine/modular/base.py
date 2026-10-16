"""
SentinelAI Modular Base Detector Interface
Phase 9C Implementation Milestone: Staged Modular Scaffold & Safety Contracts

Defines the abstract base class and contract enforcement wrapper for all specialized detectors.
"""

from __future__ import annotations
import abc
import time
import logging
from typing import Any, Dict, Optional
from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    create_degraded_result,
    validate_finite_score
)
from modular.sanitizer import sanitize_telemetry

log = logging.getLogger("sentinel.modular.base")


class BaseDetector(abc.ABC):
    """
    Abstract base class for all specialized threat detectors.
    Enforces standardized contract schemas, ground-truth blinding, and error isolation.
    """

    def __init__(self, detector_id: str, version: str):
        if not detector_id or not isinstance(detector_id, str):
            raise ValueError("detector_id must be a non-empty string")
        if not version or not isinstance(version, str):
            raise ValueError("version must be a non-empty string")

        self.detector_id = detector_id
        self.version = version

    @abc.abstractmethod
    def health_check(self) -> DetectorStatus:
        """Verifies operational readiness of models, memory structures, or dependencies."""
        pass

    @abc.abstractmethod
    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        """
        Internal inspection routine implemented by specialized detectors.
        Receives pre-sanitized telemetry guaranteed to contain no ground-truth labels.
        """
        pass

    def evaluate(self, raw_telemetry: Dict[str, Any], correlation_id: Optional[str] = None) -> DetectorResult:
        """
        Public evaluation entrypoint.
        - Sanitizes telemetry to prevent label leakage.
        - Times execution accurately.
        - Catches unexpected internal exceptions and fails safe to DEGRADED/ERROR.
        - Validates that returned results satisfy the common contract.
        """
        t0 = time.perf_counter()
        cid = correlation_id or "auto-" + str(int(t0 * 1000))

        try:
            # 1. Blind the detector: strip any dataset labels from incoming telemetry
            clean_telemetry = sanitize_telemetry(raw_telemetry, raise_on_ground_truth=False)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            log.warning(f"Detector {self.detector_id} failed telemetry sanitization: {e}")
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason=f"Telemetry sanitization failure: {str(e)}",
                correlation_id=cid,
                execution_time_ms=elapsed_ms
            )

        try:
            # 2. Invoke subclass inspection
            result = self._inspect(clean_telemetry, cid)

            # 3. Enforce contract validity on output
            if not isinstance(result, DetectorResult):
                raise TypeError(f"Detector must return DetectorResult instance, got {type(result).__name__}")

            # Re-validate confidence score is finite and within range
            validate_finite_score(result.confidence, "confidence")

            # Update actual measured execution time
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            result.execution_time_ms = round(elapsed_ms, 3)

            return result

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            log.error(f"Detector {self.detector_id} encountered unhandled inspection exception: {exc}", exc_info=True)
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.ERROR,
                reason=f"Internal inspection error: {type(exc).__name__}: {str(exc)}",
                correlation_id=cid,
                execution_time_ms=elapsed_ms
            )
