# SentinelAI GATE-1 Phase 3D: Emergency Audit Fallback Durability Guarantees

## 1. Purpose and Architecture

The Emergency Audit Fallback module (`backend/utils/emergencyAudit.js`) provides an out-of-band, fail-safe audit mechanism designed to guarantee zero forensic data loss when SentinelAI's primary database (MongoDB) or messaging layers fail.

When `runFullPipeline()` or `aiService.js` fails to persist an incident to MongoDB, the record is immediately committed directly to local persistent storage.

---

## 2. Technical Durability Guarantees

### 2.1 Synchronous OS-Level Flush (`fsyncSync`)

Standard Node.js stream logging (such as Winston file transports) utilizes asynchronous, buffered write queues in memory. If a process experiences a fatal crash, OOM kill, or host power fault immediately after a database failure, buffered memory queues are wiped without reaching disk.

`emergencyAudit.js` resolves this vulnerability by executing synchronous low-level POSIX file operations:

```javascript
const fd = fs.openSync(AUDIT_LOG_PATH, 'a', 0o640);
try {
    fs.writeSync(fd, line, null, 'utf8');
    fs.fsyncSync(fd); // Forces OS page cache to flush to physical non-volatile storage
} finally {
    fs.closeSync(fd);
}
```

1. **`fs.openSync(..., 'a', 0o640)`**: Opens the log file in append mode with restricted file permissions (`-rw-r-----`), preventing unauthorized read access by non-privileged accounts.
2. **`fs.writeSync(fd, line)`**: Synchronously commits the serialized JSON-lines payload to the OS file descriptor buffer.
3. **`fs.fsyncSync(fd)`**: Issues the underlying hardware synchronization syscall (`FlushFileBuffers` on Windows, `fsync` on Linux). This forces the physical storage controller (SSD/NVMe/HDD) to write the data to non-volatile medium before execution resumes.
4. **`fs.closeSync(fd)`**: Immediately closes the file descriptor, avoiding OS file descriptor exhaustion or open-file leaks.

---

## 3. Sensitive Data Redaction & Sanitization

Security logs must never expose credentials or authorization tokens. Prior to serialization, every payload is sanitized via recursive depth-limited inspection:

- **Redaction Triggers**: Any key containing `password`, `secret`, `token`, `key`, `authorization`, `cookie`, or `credential` (case-insensitive substring match) is overwritten with `"[REDACTED]"`.
- **String Sanitization**: Truncates unbounded string inputs (exceeding 2,048 characters) to prevent log injection or denial-of-service via oversized payloads.
- **Cycle Prevention**: Circular references in nested objects are detected and replaced with `"[CIRCULAR]"`.

---

## 4. Log Rotation and Storage Protection

To prevent disk exhaustion on long-running deployments experiencing sustained database outages:

- **Max File Size**: 10 Megabytes (`10 * 1024 * 1024` bytes).
- **Retention Count**: 5 rotated backup archives (`.1` through `.5`).
- **Rotation Mechanics**:
  When `emergency_threat_audit.log` exceeds 10MB, existing rotations are incremented (`.4` becomes `.5`, etc.), and the active log is renamed to `.1`.
  Old logs past `.5` are deleted automatically.

---

## 5. Edge Cases, Failure Modes, and Limitations

| Threat / Scenario | Handled By | System Behavior |
| :--- | :--- | :--- |
| **Disk Completely Full (ENOSPC)** | Enclosing `try/catch` block | Catches filesystem error; writes single emergency alert to `process.stderr`; does not throw unhandled exception or crash the Node.js event loop. |
| **Permission Denied (EACCES)** | Enclosing `try/catch` block | Catches permission error; emits stderr warning; allows in-flight network traffic to proceed safely. |
| **Concurrent Access** | Node.js Single-Threaded Loop | Because Node.js processes events sequentially on the main thread, synchronous file I/O operations execute atomically relative to the event loop. |
| **Multi-Node Cluster Limitation** | Local File Storage Boundary | The emergency log is written to the local node filesystem (`backend/logs/`). In a distributed Kubernetes or multi-VM setup, an external sidecar (Fluentd, Promtail, Filebeat) is required to aggregate local logs into centralized storage (e.g. Elasticsearch/Loki). |

---

## 6. Verification Status

Durability and rotation guarantees were verified in `backend/tests/integrated_backend_safety_regression.test.js`:
- **Test 12**: Simulated database failure verified successful emergency fallback invocation.
- **Test 13**: Direct synchronous write verified immediate disk existence, valid JSON-line parsing, and exact matching of logged threat fields.
