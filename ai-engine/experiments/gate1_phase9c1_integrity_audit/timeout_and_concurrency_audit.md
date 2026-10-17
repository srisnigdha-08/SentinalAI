# SentinelAI GATE-1 Phase 9C.1: Timeout & Concurrency Safety Audit

**Auditor**: Senior Security Architect & Independent Security-Systems Reviewer  
**Date**: 2026-10-17  
**Execution Context**: Concurrency & Resource Lifecycle Inspection of `ai-engine/modular/orchestrator.py`  

---

## 1. Timeout Architecture & Thread Lifecycle

[`ai-engine/modular/orchestrator.py`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/orchestrator.py#L90-L130) implements a 50 ms per-detector timeout using `concurrent.futures.ThreadPoolExecutor`:

```python
def _execute_detector_with_timeout(
    self,
    detector: BaseDetector,
    telemetry: Dict[str, Any],
    correlation_id: str
) -> DetectorResult:
    t0 = time.perf_counter()
    future = self._executor.submit(detector.evaluate, telemetry, correlation_id)
    try:
        result = future.result(timeout=self.detector_timeout)
        return result
    except FutureTimeoutError:
        ...
        return create_degraded_result(
            detector_id=detector.detector_id,
            status=DetectorStatus.TIMEOUT,
            reason=f"Execution exceeded timeout limit ({self.detector_timeout * 1000.0:.1f}ms)",
            correlation_id=correlation_id,
            execution_time_ms=elapsed_ms
        )
```

### Critical Concurrency Findings

### 1. Worker Thread Leak & Non-Interruptibility
- In standard Python `ThreadPoolExecutor`, `future.result(timeout=...)` raises `TimeoutError` in the caller thread, but **does not cancel or terminate the underlying thread worker**.
- If a detector enters an infinite loop or hangs on a blocked I/O socket, the thread continues running in the background.
- Because `max_workers` is fixed (default `max_threads=4`), 4 hanging detector calls will permanently exhaust the pool. Subsequent detector executions will sit queued in the executor, causing cascade timeouts across healthy detectors.
- **Severity**: **HIGH** (Resource Exhaustion / Thread Starvation).
- **Status**: **CONFIRMED**.
- **Required Fix**: When developing specialized detectors, detectors must not perform blocking socket I/O without native socket timeouts. Future orchestrator architecture should utilize asyncio task cancellation or bounded process workers.

### 2. Sequential vs. Parallel Dispatch Loop
In [`ModularOrchestrator.evaluate_shadow()`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/orchestrator.py#L190-L198):
```python
detector_results: Dict[str, DetectorResult] = {}
for det_id, detector in list(self._detectors.items()):
    res = self._execute_detector_with_timeout(detector, clean_telemetry, cid)
    detector_results[det_id] = res
```
- **Finding**: Detectors are executed sequentially one after another in a loop, each waiting up to 50 ms.
- If SentinelAI runs 4 detectors, worst-case latency is $4 \times 50\text{ ms} = 200\text{ ms}$.
- **Recommendation**: Dispatch all detector futures simultaneously via `executor.map()` or `concurrent.futures.wait(timeout=...)`, allowing all detectors to execute concurrently within a single 50 ms window.

### 3. Thread Safety of Alert Deduplication Cache
In [`_check_and_update_dedup()`](file:///c:/Users/srisn/Desktop/Projects/sentinelai-complete/ai-engine/modular/orchestrator.py#L140-L165):
```python
if len(self._dedup_cache) > 1000:
    pruned = {k: ts for k, ts in self._dedup_cache.items() if now - ts < self.dedup_window}
    self._dedup_cache = pruned
```
- `self._dedup_cache` is accessed across multiple threads without a mutex or `threading.Lock`.
- If pruning occurs concurrently with a lookup or insertion, dictionary iteration can raise `RuntimeError: dictionary changed size during iteration`.
- **Severity**: **LOW-MEDIUM**.
- **Status**: **CONFIRMED**.
- **Required Fix**: Guard `_dedup_cache` access with a `threading.Lock`.

---

## 2. Late Result & Stale Data Isolation

The auditor analyzed what happens when a timed-out worker finishes long after the timeout:
- Because `_execute_detector_with_timeout` immediately returns a `TIMEOUT` `DetectorResult` to the caller, the caller builds the `EnsembleResult` and finishes processing.
- The late result produced by the worker is ignored and discarded upon function exit.
- It cannot overwrite subsequent decisions or inject stale alerts into active telemetry.
- **Classification**: **CONFIRMED (Zero Overwrite Risk)**.
