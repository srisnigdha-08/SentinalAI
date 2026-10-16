# SentinelAI Final Closure: Outbox Architecture and Reliability Review

**Date**: October 15, 2026  
**Auditor**: Backend and Systems Reliability Engineer  
**Component**: Security Event Bus (`backend/utils/securityEventBus.js`), FileOutboxStore, and Event Durability  
**Status**: **HARDENED & STRESS-TESTED**

---

## 1. Outbox Architecture Overview

The SentinelAI platform employs a durable, transactional Outbox pattern to decouple critical security telemetry, alert broadcasts, and audit logging from synchronous HTTP request lifecycles.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              APPLICATION LOGIC (CONTROLLER)                            │
│                                                                                        │
│   1. State Mutation (e.g. Save ThreatLog to MongoDB)                                  │
│   2. bus.publishDurable({ eventType, payload }, commitCallback)                        │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                       SECURITY EVENT BUS (FileOutboxStore)                              │
│                                                                                        │
│   ┌────────────────────────────────────────────────────────────────────────────────┐   │
│   │ 1. Atomic Disk Persistence:                                                    │   │
│   │    - Serialize envelope with status: 'PENDING'                                 │   │
│   │    - Write to isolated temporary file: event_outbox.json.tmp.<ts>_<rand>       │   │
│   │    - Atomic rename / copy-fallback to: event_outbox.json                       │   │
│   └────────────────────────────────────────┬───────────────────────────────────────┘   │
│                                            │                                           │
│   ┌────────────────────────────────────────▼───────────────────────────────────────┐   │
│   │ 2. Asynchronous Subscriber Dispatch:                                           │   │
│   │    - Execute registered handler (WebSocket push, SIEM export, audit log)      │   │
│   │    - On Success: markDelivered(eventId) -> persists status: 'DELIVERED'        │   │
│   │    - On Failure: markFailed(eventId, err) -> increments attempts count         │   │
│   │    - Poison Pill Quarantine: attempts >= 3 -> status: 'FAILED'                │   │
│   └────────────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Hardened Production Features in `FileOutboxStore`

1. **Atomic Temporary-File Swaps**:
   - Direct writes to shared JSON files risk truncating or corrupting data if the host process terminates abruptly during write.
   - `_writeAll()` writes the serialized buffer to an isolated file path (`${this.filePath}.tmp.${Date.now()}_${random}`), flushes to disk, and executes `fs.renameSync` (with an automatic `fs.copyFileSync` fallback for Windows file locks).

2. **Corrupted File Forensics Quarantine**:
   - If an unexpected hardware failure or abnormal termination leaves the outbox file unparseable, `_readAll()` traps the `SyntaxError`.
   - Instead of discarding data or crashing, it creates an archived forensic backup (`${this.filePath}.corrupt.${Date.now()}`) and initializes a clean, operable state, enabling post-incident investigation without service outage.

3. **Disk Retention Pruning**:
   - To prevent unbounded disk growth, `_prune()` monitors total records.
   - When the outbox exceeds 300 entries, it trims delivered events down to the 100 most recent records.
   - **Critical Invariant**: Active `PENDING` and quarantined `FAILED` events are never pruned under any circumstance.

4. **Structured Error Capture & Poison Pill Handling**:
   - `markFailed(eventId, err)` captures the actual exception string (`err.message`) in `lastError`.
   - If a malformed payload or buggy subscriber repeatedly throws an error, the event transitions from `PENDING` to `FAILED` on the 3rd attempt, preventing retry loops from starving valid events.

---

## 3. Stress-Testing Evidence (`backend/tests/outboxStress.test.js`)

A dedicated stress test suite validated the outbox under failure scenarios:

| Test Scenario | Failure Injected | Observed System Behavior | Verdict |
| :--- | :--- | :--- | :--- |
| **Crash & Recovery** | Simulated process termination while event is pending. | New process instance initializes, inspects file, and replays pending event. | **PASS** |
| **Ack Persistence** | Service restarts after successful delivery. | Event status remains `DELIVERED`; no duplicate emission on startup. | **PASS** |
| **Corrupted JSON Handling** | Malformed, partial JSON string written to disk. | Error caught cleanly; forensic copy created; clean state initialized without crash. | **PASS** |
| **Poison Pill Quarantine** | Subscriber throws fatal error on 3 consecutive runs. | Error captured in `lastError`; event marked `FAILED`; removed from pending queue. | **PASS** |
| **Concurrent Emissions** | 20 parallel asynchronous publish operations. | All 20 persisted and delivered without file lock contention or data loss. | **PASS** |
| **Retention Pruning** | Injected 350 delivered and 2 pending records. | Delivered records pruned to 100; both pending records preserved intact. | **PASS** |
| **Delivery Semantics** | Subscriber crashes before outbox acknowledgment. | Event re-emitted on subsequent startup, verifying At-Least-Once delivery. | **PASS** |

---

## 4. Contract and Operational Boundaries

1. **Delivery Guarantee**: **At-Least-Once Delivery**. If a consumer performs an external action (e.g., transmitting an alert) and the process dies before `markDelivered` commits to disk, the event will be re-emitted upon reboot. All downstream event subscribers must enforce idempotency using `envelope.eventId`.
2. **Process Concurrency Model**: Designed strictly for a **Single-Writer Process**. Multi-process clustering sharing the same outbox JSON file is unsupported; multi-node architectures require Redis or MongoDB-backed outbox stores.
3. **Power Loss Resilience**: Atomic file renames guarantee filesystem consistency against OS-level process crashes. Full durability against raw physical power loss requires host write-cache flushing (`fsync`).
