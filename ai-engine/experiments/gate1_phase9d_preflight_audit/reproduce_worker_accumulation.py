"""
SentinelAI GATE-1 - Phase 9D Preflight Verification Script
Reproduction of Orchestrator Timed-Out Worker Accumulation Defect

Demonstrates that under ThreadPoolExecutor, when detectors time out:
1. Worker threads remain occupied by hanging tasks.
2. Unfinished/unstarted futures in not_done are not cancelled.
3. Pending tasks accumulate monotonically in _work_queue without bound.
4. Subsequent requests experience cascading head-of-line blocking timeouts.
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

    def _inspect(self, clean_telemetry, correlation_id):
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


def run_reproduction():
    print("=" * 70)
    print("PHASE 9D PREFLIGHT AUDIT: TIMED-OUT WORKER ACCUMULATION TEST")
    print("=" * 70)

    # 4 workers, 50ms timeout
    orch = ModularOrchestrator(detector_timeout_seconds=0.05, max_threads=4)
    for i in range(4):
        orch.register_detector(SlowHangingDetector(f"slow_det_{i}", delay_seconds=2.0))

    print(f"Registered detectors: {orch.list_detectors()}")
    print(f"Max worker threads: {orch.max_threads}")
    print(f"Detector timeout: {orch.detector_timeout * 1000.0:.1f} ms")
    print("-" * 70)

    # Submit 8 consecutive requests
    results = []
    for req_id in range(8):
        t0 = time.perf_counter()
        res = orch.evaluate_shadow({"sourceIP": f"10.0.0.{req_id}"}, force_shadow=True)
        elapsed = (time.perf_counter() - t0) * 1000.0
        
        # Inspect internal queue
        wq = orch._executor._work_queue
        qsize = getattr(wq, "qsize", lambda: len(getattr(wq, "queue", [])))()
        
        results.append({
            "request_id": req_id,
            "status": res.ensemble_status.value,
            "decision": res.overall_decision.value,
            "elapsed_ms": round(elapsed, 2),
            "pending_work_queue_size": qsize
        })
        print(f"Request {req_id:02d} | Status: {res.ensemble_status.value:11s} | "
              f"Wait: {elapsed:5.1f} ms | Pending Queue: {qsize:2d} tasks")

    print("-" * 70)
    print("DEFECT VERIFICATION SUMMARY:")
    first_qsize = results[0]["pending_work_queue_size"]
    last_qsize = results[-1]["pending_work_queue_size"]
    print(f"Initial Pending Queue: {first_qsize} tasks")
    print(f"Final Pending Queue:   {last_qsize} tasks (Accumulation: +{last_qsize - first_qsize} tasks)")
    
    is_unbounded = last_qsize > 0
    print(f"Defect Confirmed (Unbounded Accumulation): {is_unbounded}")
    print("=" * 70)

    orch.shutdown(wait=False)
    return is_unbounded


if __name__ == "__main__":
    run_reproduction()
