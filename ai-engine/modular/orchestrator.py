"""
SentinelAI Modular Policy Orchestrator & Isolated Shadow Scaffold
Phase 9C.3 Remediation Milestone: DEF-05 (Bounded In-Flight Capacity & Timed-Out Worker Management)

This module orchestrates specialized detectors in an isolated shadow mode.
Enforces concurrent dispatch, bounded timeout isolation, fail-safe degraded states,
empty-pipeline fail-closed handling, alert de-duplication, strictly bounded
in-flight task capacity (DEF-05), and explicit simulated mitigation watermarks.

Architectural Design Notes & Concurrency Guarantees:
1. DEF-01 Remediated: When zero detectors are registered, evaluate_shadow() returns
   status=UNAVAILABLE and decision=MONITOR (never silent ALLOW on uninspected traffic).
2. DEF-04 Remediated: Detectors are dispatched in parallel via ThreadPoolExecutor.
   Waiting is performed concurrently via concurrent.futures.wait(timeout=self.detector_timeout).
   Total latency is bounded by the detector timeout rather than cumulative sequential sum.
3. DEF-05 Remediated:
   a. Strictly Bounded Capacity: Total outstanding tasks (actively executing on OS worker
      threads plus waiting in queue) are capped at `max_pending_tasks` (default 16).
   b. Fast-Fail on Saturation: When active in-flight tasks + required tasks exceed capacity,
      new work is rejected immediately without submitting to the executor queue. Returns
      fail-safe status=UNAVAILABLE, decision=MONITOR, and reason=WORKER_POOL_SATURATED.
   c. Cancellation of Unstarted Tasks: For timed-out futures, `fut.cancel()` is attempted.
      If the task was queued and not yet running, it is cancelled and capacity is freed immediately.
   d. Exactly-Once Capacity Accounting: Each task's capacity slot is tracked by TaskSlot
      and released exactly once upon true completion or cancellation. A caller timeout does NOT
      release capacity for an OS thread that is still actively running.
4. CPython ThreadPoolExecutor Limitation:
   In CPython, running OS threads cannot be forcibly killed or preempted without process
   termination. If a detector has already begun execution when the caller's timeout expires,
   fut.cancel() returns False, and the thread continues until completion. The orchestrator:
   - Holds capacity for running tasks until the OS thread truly finishes.
   - Bounds admission to prevent unbounded queued work and thread pool starvation.
   - Discards late worker results safely upon return so they cannot overwrite finalized decisions.
5. Thread Safety: Deduplication cache is guarded by self._dedup_lock. Capacity accounting
   is guarded by self._capacity_lock. Individual task slots are guarded by TaskSlot._lock.
"""

from __future__ import annotations
import os
import sys
import time
import uuid
import logging
import threading
import concurrent.futures
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    EnsembleResult,
    MitigationAction,
    PolicyDecision,
    SeverityLevel,
    SimulatedMitigation,
    create_degraded_result,
    validate_finite_score,
)
from modular.sanitizer import sanitize_telemetry
from modular.base import BaseDetector

log = logging.getLogger("sentinel.modular.orchestrator")


def is_modular_enabled() -> bool:
    """
    Checks master feature flag for modular detectors.
    Must default to False to guarantee zero runtime regression risk.
    """
    return os.getenv("ENABLE_EXPERIMENTAL_MODULAR_DETECTORS", "false").lower() == "true"


class TaskSlot:
    """
    Thread-safe tracker for an individual detector task capacity slot (DEF-05).
    Guarantees that capacity is released EXACTLY ONCE, regardless of whether
    completion occurs via normal return, exception, cancellation before execution,
    or late execution following a caller timeout.
    """

    def __init__(self, orchestrator: "ModularOrchestrator", det_id: str, correlation_id: str):
        self.orchestrator = orchestrator
        self.det_id = det_id
        self.correlation_id = correlation_id
        self._released = False
        self._lock = threading.Lock()
        self.started = False
        self.completed = False
        self.cancelled = False

    def mark_started(self) -> None:
        with self._lock:
            self.started = True

    def mark_completed(self) -> None:
        with self._lock:
            self.completed = True

    def mark_cancelled(self) -> None:
        with self._lock:
            self.cancelled = True

    def release(self, reason: str = "done") -> bool:
        """
        Releases the capacity slot exactly once.
        Returns True if this invocation performed the release, False if already released.
        """
        with self._lock:
            if self._released:
                return False
            self._released = True

        self.orchestrator._release_capacity(self.det_id, reason)
        return True


class ModularOrchestrator:
    """
    Shadow-mode multi-tier detector orchestrator.
    Executes modular detectors with concurrent timeout isolation, consensus policy,
    and strictly bounded in-flight capacity (DEF-05).
    """

    def __init__(
        self,
        detector_timeout_seconds: float = 0.05,  # 50 ms per detector/batch
        dedup_window_seconds: float = 60.0,
        max_threads: int = 4,
        max_pending_tasks: int = 16,  # Bound on all in-flight tasks (running + queued)
    ):
        if detector_timeout_seconds <= 0:
            raise ValueError(f"detector_timeout_seconds must be positive, got {detector_timeout_seconds}")
        if dedup_window_seconds <= 0:
            raise ValueError(f"dedup_window_seconds must be positive, got {dedup_window_seconds}")
        if max_threads <= 0:
            raise ValueError(f"max_threads must be positive, got {max_threads}")
        if max_pending_tasks <= 0:
            raise ValueError(f"max_pending_tasks must be positive, got {max_pending_tasks}")
        if max_pending_tasks < max_threads:
            raise ValueError(
                f"max_pending_tasks ({max_pending_tasks}) cannot be less than max_threads ({max_threads})"
            )

        self.detector_timeout = detector_timeout_seconds
        self.dedup_window = dedup_window_seconds
        self.max_threads = max_threads
        self.max_pending_tasks = max_pending_tasks

        self._detectors: Dict[str, BaseDetector] = {}
        self._dedup_cache: Dict[Tuple[str, str], float] = {}  # (src_ip, threat_type) -> last_seen
        self._dedup_lock = threading.Lock()

        # DEF-05: Capacity & In-Flight Accounting
        # Covers all submitted but unfinished tasks (both actively executing and queued).
        self._in_flight_tasks: int = 0
        self._capacity_lock = threading.Lock()
        self._metrics: Dict[str, int] = {
            "submitted_tasks": 0,
            "completed_tasks": 0,
            "cancelled_tasks": 0,
            "rejected_events": 0,
        }

        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_threads,
            thread_name_prefix="mod_det_"
        )

    @property
    def in_flight_tasks(self) -> int:
        """Returns the current number of in-flight (running + queued) tasks."""
        with self._capacity_lock:
            return self._in_flight_tasks

    def get_metrics(self) -> Dict[str, Any]:
        """Returns snapshot of executor and capacity metrics."""
        with self._capacity_lock:
            wq = getattr(self._executor, "_work_queue", None)
            qsize = getattr(wq, "qsize", lambda: len(getattr(wq, "queue", [])))() if wq is not None else 0
            return {
                "in_flight_tasks": self._in_flight_tasks,
                "queued_tasks": qsize,
                "max_pending_tasks": self.max_pending_tasks,
                "max_threads": self.max_threads,
                "submitted_tasks": self._metrics["submitted_tasks"],
                "completed_tasks": self._metrics["completed_tasks"],
                "cancelled_tasks": self._metrics["cancelled_tasks"],
                "rejected_events": self._metrics["rejected_events"],
            }

    def _release_capacity(self, det_id: str, reason: str) -> None:
        """
        Thread-safe decrement of in-flight capacity.
        Guaranteed to be called at most once per task slot.
        """
        with self._capacity_lock:
            if self._in_flight_tasks <= 0:
                self._safe_log(
                    logging.ERROR,
                    "Underflow in capacity accounting on release for %s (reason: %s)",
                    det_id, reason
                )
                return
            self._in_flight_tasks -= 1
            if reason.startswith("cancel"):
                self._metrics["cancelled_tasks"] += 1
            else:
                self._metrics["completed_tasks"] += 1

    def _prune_cancelled_tasks(self) -> int:
        """
        Removes cancelled _WorkItem entries from the internal executor queue.
        In Python's ThreadPoolExecutor, cancelled tasks remain in the SimpleQueue until
        worker threads pop them. Pruning them proactively prevents physical queue accumulation.
        """
        wq = getattr(self._executor, "_work_queue", None)
        if wq is None or wq.empty():
            return 0

        pruned = 0
        items = []
        with self._capacity_lock:
            while not wq.empty():
                try:
                    item = wq.get_nowait()
                except Exception:
                    break
                if item is None:
                    # Shutdown sentinel; preserve and exit
                    items.append(item)
                    break
                fut = getattr(item, "future", None)
                if fut is not None and fut.cancelled():
                    pruned += 1
                else:
                    items.append(item)
            for it in items:
                wq.put_nowait(it)

        return pruned

    def _run_detector_with_slot(
        self,
        detector: BaseDetector,
        clean_telemetry: Dict[str, Any],
        cid: str,
        slot: TaskSlot
    ) -> DetectorResult:
        """
        Worker execution wrapper (DEF-05).
        Marks slot started and guarantees slot release upon worker termination or exception.
        """
        slot.mark_started()
        try:
            return detector.evaluate(clean_telemetry, cid)
        finally:
            slot.mark_completed()
            slot.release(reason="worker_finished")

    def register_detector(self, detector: BaseDetector) -> None:
        """Registers a detector instance into the orchestrator."""
        if not isinstance(detector, BaseDetector):
            raise TypeError(f"Detector must inherit from BaseDetector, got {type(detector).__name__}")
        self._detectors[detector.detector_id] = detector
        log.info(f"Registered modular detector: {detector.detector_id} (version {detector.version})")

    def unregister_detector(self, detector_id: str) -> None:
        """Removes a detector from the orchestrator."""
        if detector_id in self._detectors:
            del self._detectors[detector_id]
            log.info(f"Unregistered modular detector: {detector_id}")

    def list_detectors(self) -> List[str]:
        """Returns list of registered detector IDs."""
        return list(self._detectors.keys())

    def _safe_log(self, level: int, msg: str, *args) -> None:
        """
        Resilient logging helper. If standard logging fails (e.g. disk full, pipe error),
        falls back to sys.stderr so the failure cannot silently break the pipeline.
        """
        try:
            log.log(level, msg, *args)
        except Exception as log_err:
            try:
                sys.stderr.write(f"[FALLBACK LOG FAILURE] {msg % args if args else msg}: {log_err}\n")
            except Exception:
                pass  # Ultimate fail-safe

    def _check_and_update_dedup(self, source_ip: str, threat_type: str, now: float) -> bool:
        """
        Thread-safe check if an alert for (source_ip, threat_type) occurred within the deduplication window.
        Returns True if this alert is a duplicate and should be throttled.
        """
        if not source_ip or not threat_type or threat_type in ("BENIGN", "UNKNOWN", "NONE"):
            return False

        key = (source_ip, threat_type)
        is_dup = False

        with self._dedup_lock:
            last_seen = self._dedup_cache.get(key)
            if last_seen and (now - last_seen < self.dedup_window):
                is_dup = True

            # Update cache timestamp
            self._dedup_cache[key] = now

            # Prune expired keys if cache exceeds 1,000 entries
            if len(self._dedup_cache) > 1000:
                pruned = {k: ts for k, ts in self._dedup_cache.items() if now - ts < self.dedup_window}
                self._dedup_cache = pruned

        return is_dup

    def evaluate_shadow(
        self,
        raw_telemetry: Dict[str, Any],
        correlation_id: Optional[str] = None,
        force_shadow: bool = False
    ) -> Optional[EnsembleResult]:
        """
        Executes modular detection pipeline in shadow mode.
        
        If ENABLE_EXPERIMENTAL_MODULAR_DETECTORS is false and force_shadow is false,
        this method returns None immediately without executing detectors.
        """
        if not is_modular_enabled() and not force_shadow:
            return None

        cid = correlation_id or str(uuid.uuid4())
        now_ts = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: Sanitize input telemetry (strip any ground-truth keys)
        try:
            clean_telemetry = sanitize_telemetry(raw_telemetry, raise_on_ground_truth=False)
        except Exception as e:
            self._safe_log(logging.ERROR, "Shadow orchestration telemetry sanitization failed: %s", e)
            clean_telemetry = {}

        # Step 2: Empty Pipeline Handling (DEF-01 Remediation)
        # An empty detector pipeline MUST NEVER return a clean ALLOW on uninspected traffic!
        if len(self._detectors) == 0:
            return EnsembleResult(
                correlation_id=cid,
                timestamp=now_iso,
                ensemble_status=DetectorStatus.UNAVAILABLE,
                overall_decision=PolicyDecision.MONITOR,
                max_threat_confidence=0.0,
                simulated_block=False,
                requires_triage=True,
                is_duplicate=False,
                detector_results={},
                degraded_detectors=["pipeline:NO_DETECTORS_REGISTERED"],
                summary_evidence=(
                    "Zero modular detectors registered. Traffic is UNINSPECTED; "
                    "fail-safe MONITOR applied (traffic cannot be verified as ALLOW)."
                )
            )

        # Step 3: Admission Control & Capacity Bound Check (DEF-05 Remediation)
        # Verify that submitting tasks for all registered detectors will not exceed
        # the strictly bounded in-flight capacity limit (max_pending_tasks).
        self._prune_cancelled_tasks()
        num_detectors = len(self._detectors)
        with self._capacity_lock:
            if self._in_flight_tasks + num_detectors > self.max_pending_tasks:
                self._metrics["rejected_events"] += 1
                current_in_flight = self._in_flight_tasks
                max_tasks = self.max_pending_tasks
                self._safe_log(
                    logging.WARNING,
                    "Worker pool saturated: in-flight tasks (%d) + requested (%d) > limit (%d)",
                    current_in_flight, num_detectors, max_tasks
                )
                return EnsembleResult(
                    correlation_id=cid,
                    timestamp=now_iso,
                    ensemble_status=DetectorStatus.UNAVAILABLE,
                    overall_decision=PolicyDecision.MONITOR,
                    max_threat_confidence=0.0,
                    simulated_block=False,
                    requires_triage=True,
                    is_duplicate=False,
                    detector_results={
                        det_id: create_degraded_result(
                            detector_id=det_id,
                            status=DetectorStatus.UNAVAILABLE,
                            reason="Worker pool saturated: task capacity exceeded (WORKER_POOL_SATURATED)",
                            correlation_id=cid,
                            execution_time_ms=0.0
                        )
                        for det_id in self._detectors
                    },
                    degraded_detectors=["orchestrator:WORKER_POOL_SATURATED"],
                    summary_evidence=(
                        f"Worker pool saturated: in-flight tasks ({current_in_flight}) + "
                        f"requested ({num_detectors}) exceeds limit ({max_tasks}). "
                        f"Fast-fail policy applied: decision set to MONITOR (WORKER_POOL_SATURATED)."
                    )
                )

            # Atomically acquire capacity slots for all registered detectors
            self._in_flight_tasks += num_detectors
            self._metrics["submitted_tasks"] += num_detectors

        # Step 4: Parallel Dispatch with TaskSlot Capacity Management (DEF-04 & DEF-05)
        t_start = time.perf_counter()
        futures: Dict[concurrent.futures.Future, Tuple[str, TaskSlot]] = {}

        for det_id, detector in list(self._detectors.items()):
            slot = TaskSlot(self, det_id, cid)
            fut = self._executor.submit(
                self._run_detector_with_slot,
                detector,
                clean_telemetry,
                cid,
                slot
            )
            # Fail-safe callback ensuring capacity is released on cancellation or completion
            fut.add_done_callback(
                lambda f, s=slot: s.release(reason="cancelled_in_queue" if f.cancelled() else "future_done_callback")
            )
            futures[fut] = (det_id, slot)

        done, not_done = concurrent.futures.wait(
            futures.keys(),
            timeout=self.detector_timeout
        )
        elapsed_all_ms = (time.perf_counter() - t_start) * 1000.0

        detector_results: Dict[str, DetectorResult] = {}

        # Collect finished results
        for fut in done:
            det_id, slot = futures[fut]
            try:
                res = fut.result()
                detector_results[det_id] = res
            except Exception as exc:
                self._safe_log(logging.ERROR, "Detector '%s' worker exception: %s", det_id, exc)
                detector_results[det_id] = create_degraded_result(
                    detector_id=det_id,
                    status=DetectorStatus.ERROR,
                    reason=f"Worker exception: {type(exc).__name__}: {str(exc)}",
                    correlation_id=cid,
                    execution_time_ms=elapsed_all_ms
                )

        # Handle timed-out detectors and attempt cancellation (DEF-05 Remediation)
        any_cancelled = False
        for fut in not_done:
            det_id, slot = futures[fut]
            cancelled = fut.cancel()
            if cancelled:
                any_cancelled = True
                # Task was in queue and successfully cancelled before execution started
                slot.mark_cancelled()
                slot.release(reason="cancelled_in_queue")
                status_reason = f"Execution timed out and cancelled before start ({self.detector_timeout * 1000.0:.1f}ms)"
            else:
                # Task is already actively running on a worker thread.
                # In CPython, running threads cannot be asynchronously terminated.
                # Capacity remains held until the worker thread actually finishes execution!
                status_reason = f"Execution exceeded timeout limit ({self.detector_timeout * 1000.0:.1f}ms); worker still executing"

            self._safe_log(
                logging.WARNING,
                "Detector '%s' timed out (threshold: %.2f ms, cancelled_before_run: %s)",
                det_id, self.detector_timeout * 1000.0, cancelled
            )
            detector_results[det_id] = create_degraded_result(
                detector_id=det_id,
                status=DetectorStatus.TIMEOUT,
                reason=status_reason,
                correlation_id=cid,
                execution_time_ms=elapsed_all_ms
            )

        if any_cancelled:
            self._prune_cancelled_tasks()

        # Step 5: Compute Consensus & Enforce Fail-Safe Invariants
        any_degraded = False
        degraded_list: List[str] = []
        any_threat = False
        max_threat_conf = 0.0
        threat_detector_id: Optional[str] = None
        threat_type: Optional[str] = None

        for det_id, res in detector_results.items():
            # Validate confidence score strictly
            try:
                conf = validate_finite_score(res.confidence, f"{det_id}.confidence")
            except Exception as score_err:
                self._safe_log(logging.ERROR, "Detector %s returned non-finite confidence: %s", det_id, score_err)
                res = create_degraded_result(
                    detector_id=det_id,
                    status=DetectorStatus.DEGRADED,
                    reason=f"Non-finite confidence rejected: {score_err}",
                    correlation_id=cid,
                    execution_time_ms=res.execution_time_ms
                )
                detector_results[det_id] = res
                conf = 0.0

            if res.status != DetectorStatus.HEALTHY:
                any_degraded = True
                degraded_list.append(f"{det_id}:{res.status.value}")

            if res.decision in (PolicyDecision.DETECTED, PolicyDecision.SIMULATED_BLOCK) or (
                res.mitigation_recommendation and res.mitigation_recommendation.action == MitigationAction.SIMULATED_BLOCK
            ):
                any_threat = True
                if conf > max_threat_conf:
                    max_threat_conf = conf
                    threat_detector_id = det_id
                    threat_type = res.evidence.trigger_rule

        # Enforce Consensus Invariants:
        # 1. Threat detected: Recommend SIMULATED_BLOCK. Status is DEGRADED if any detector degraded.
        # 2. No threat detected, but 1+ detectors degraded: Decision is MONITOR (never silent ALLOW).
        # 3. All detectors healthy with no threats: Decision is ALLOW.
        if any_threat:
            ensemble_decision = PolicyDecision.SIMULATED_BLOCK
            ensemble_status = DetectorStatus.DEGRADED if any_degraded else DetectorStatus.HEALTHY
            simulated_block = True
            requires_triage = any_degraded
            threat_desc = f" ({threat_type})" if threat_type else ""
            summary = (
                f"Threat detected by [{threat_detector_id}]{threat_desc} with confidence {max_threat_conf:.4f} "
                f"([SIMULATED BLOCK] recommended)."
            )
            if any_degraded:
                summary += f" Partial pipeline degradation: {', '.join(degraded_list)}."
        elif any_degraded:
            ensemble_decision = PolicyDecision.MONITOR
            # If ALL detectors are unavailable/timed-out, status is UNAVAILABLE
            all_unavailable = all(
                res.status in (DetectorStatus.UNAVAILABLE, DetectorStatus.TIMEOUT, DetectorStatus.ERROR)
                for res in detector_results.values()
            )
            ensemble_status = DetectorStatus.UNAVAILABLE if all_unavailable else DetectorStatus.DEGRADED
            simulated_block = False
            requires_triage = True
            summary = (
                f"Inspection degraded across {len(degraded_list)} detector(s): {', '.join(degraded_list)}. "
                f"Fail-safe policy applied: decision set to MONITOR (unverified traffic)."
            )
        else:
            ensemble_decision = PolicyDecision.ALLOW
            ensemble_status = DetectorStatus.HEALTHY
            simulated_block = False
            requires_triage = False
            summary = f"All {len(detector_results)} registered detector(s) reported healthy with no threats."

        # Step 6: Alert De-Duplication Check
        src_ip = str(clean_telemetry.get("sourceIP", clean_telemetry.get("source_ip", "0.0.0.0")))
        is_dup = False
        if any_threat and threat_type:
            is_dup = self._check_and_update_dedup(src_ip, threat_type, now_ts)

        ensemble_result = EnsembleResult(
            correlation_id=cid,
            timestamp=now_iso,
            ensemble_status=ensemble_status,
            overall_decision=ensemble_decision,
            max_threat_confidence=round(max_threat_conf, 4),
            simulated_block=simulated_block,
            requires_triage=requires_triage,
            is_duplicate=is_dup,
            detector_results=detector_results,
            degraded_detectors=degraded_list,
            summary_evidence=summary
        )

        return ensemble_result

    def shutdown(self, wait: bool = False) -> None:
        """Shuts down internal thread pool gracefully."""
        self._executor.shutdown(wait=wait)
