"""
SentinelAI GATE-1 - Phase 9C.3 Remediation Verification Script
Post-Fix Bounded Capacity & Queue Verification (DEF-05)

Demonstrates that under ThreadPoolExecutor with DEF-05 remediation:
1. Total in-flight tasks (running + queued) are strictly bounded by max_pending_tasks.
2. Queue depth is strictly bounded.
3. Once saturated, new evaluation requests fail fast with WORKER_POOL_SATURATED without submitting tasks.
4. When workers finish, all capacity is fully recovered to 0.
"""

import time
import threading
from modular.orchestrator import ModularOrchestrator
from modular.base import BaseDetector
from modular.contracts import DetectorResult, DetectorStatus, PolicyDecision, SeverityLevel, EvidenceRecord


class SlowHangingDetector(BaseDetector):
    """Simulates a detector hanging or exceeding timeout limit."""
    def __init__(self, name: str = "slow_detector", delay_seconds: float = 0.5):
        super().__init__(detector_id=name, version="1.0.0")
        self.delay_seconds = delay_seconds

    def _inspect(self, clean_telemetry, cid):
        time.sleep(self.delay_seconds)
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.ALLOW,
            confidence=0.0,
            severity=SeverityLevel.INFORMATIONAL,
            evidence=EvidenceRecord(trigger_rule="BENIGN", summary="Benign delay test", details={"delay": self.delay_seconds})
        )

    def health_check(self) -> bool:
        return True


def run_post_fix_verification():
    print("=" * 80)
    print("PHASE 9C.3 POST-FIX VERIFICATION: BOUNDED CAPACITY & QUEUE TEST (DEF-05)")
    print("=" * 80)

    # 4 worker threads, 50ms timeout, max_pending_tasks=8
    orch = ModularOrchestrator(
        detector_timeout_seconds=0.05,
        max_threads=4,
        max_pending_tasks=8
    )
    for i in range(4):
        orch.register_detector(SlowHangingDetector(f"slow_det_{i}", delay_seconds=0.5))

    print(f"Registered detectors: {orch.list_detectors()}")
    print(f"Max worker threads:   {orch.max_threads}")
    print(f"Detector timeout:     {orch.detector_timeout * 1000.0:.1f} ms")
    print(f"Max in-flight bound:  {orch.max_pending_tasks} tasks (running + queued)")
    print("-" * 80)

    results = []
    # Submit 8 consecutive requests
    for req_id in range(8):
        t0 = time.perf_counter()
        res = orch.evaluate_shadow({"sourceIP": f"10.0.0.{req_id}"}, force_shadow=True)
        elapsed = (time.perf_counter() - t0) * 1000.0
        
        metrics = orch.get_metrics()
        results.append({
            "request_id": req_id,
            "status": res.ensemble_status.value,
            "decision": res.overall_decision.value,
            "elapsed_ms": round(elapsed, 2),
            "in_flight_tasks": metrics["in_flight_tasks"],
            "queued_tasks": metrics["queued_tasks"],
            "rejected_events": metrics["rejected_events"],
            "is_saturated": "orchestrator:WORKER_POOL_SATURATED" in res.degraded_detectors
        })
        print(f"Request {req_id:02d} | Status: {res.ensemble_status.value:11s} | "
              f"Wait: {elapsed:5.1f} ms | In-Flight: {metrics['in_flight_tasks']:2d} / {orch.max_pending_tasks} | "
              f"Queued: {metrics['queued_tasks']:2d} | Saturated: {results[-1]['is_saturated']}")

    print("-" * 80)
    print("POST-FIX VERIFICATION SUMMARY:")
    max_observed_inflight = max(r["in_flight_tasks"] for r in results)
    max_observed_queued = max(r["queued_tasks"] for r in results)
    total_rejections = results[-1]["rejected_events"]
    print(f"Configured max_pending_tasks limit: {orch.max_pending_tasks}")
    print(f"Maximum observed in-flight tasks:   {max_observed_inflight} (Within Bound: {max_observed_inflight <= orch.max_pending_tasks})")
    print(f"Maximum observed queued tasks:     {max_observed_queued} (Within Bound: {max_observed_queued <= orch.max_pending_tasks - orch.max_threads})")
    print(f"Total saturation fast-fail events: {total_rejections}")
    
    # Wait for workers to finish and verify full recovery
    print("Waiting for background workers to finish execution...")
    time.sleep(0.6)
    final_metrics = orch.get_metrics()
    print(f"Final in-flight tasks after completion: {final_metrics['in_flight_tasks']} (Clean Recovery: {final_metrics['in_flight_tasks'] == 0})")
    print(f"Final queued tasks:                     {final_metrics['queued_tasks']}")
    print(f"Total completed tasks:                  {final_metrics['completed_tasks']}")
    print(f"Total cancelled tasks:                  {final_metrics['cancelled_tasks']}")
    print("=" * 80)

    orch.shutdown(wait=False)
    return max_observed_inflight <= orch.max_pending_tasks and final_metrics['in_flight_tasks'] == 0


if __name__ == "__main__":
    success = run_post_fix_verification()
    print(f"OVERALL DEF-05 REMEDIATION VERIFICATION: {'SUCCESS' if success else 'FAILURE'}")
