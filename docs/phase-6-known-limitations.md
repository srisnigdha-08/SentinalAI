# SentinelAI Phase 6 — Known Limitations & Architectural Boundaries

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Auditor / Engineering Role:** Senior Application Security & Windows Platform Engineer  
**Status:** Approved Baseline Architecture Reference  

---

## 1. Executive Summary

Phase 6 established comprehensive security hardening across SentinelAI, implementing server-authoritative session inactivity timeouts, graceful shutdown request draining, an in-memory security event distribution bus, sanitized honeypot ingestion, and a fail-closed isolated Windows Firewall test harness.

This document formally records the architectural boundaries, operational constraints, and intentional tradeoffs inherent in the Phase 6 baseline. These limitations are documented to prevent false assumptions during production deployments, enterprise scaling, or automated vulnerability assessments.

---

## 2. Matrix of Known Architectural Boundaries

| Component | Limitation / Boundary | Root Cause / Rationale | Production Remediation / Path Forward |
| :--- | :--- | :--- | :--- |
| **Cowrie Honeypot Telemetry** | Live telemetry marked `NOT IMPLEMENTED / BLOCKED` on Windows host | Cowrie is a Python/Twisted SSH/Telnet honeypot designed for Linux; no daemon is installed on the host workstation. | Deploy an external Linux sensor VM running Cowrie with forwarder shipping logs over HTTPS/mTLS to `/api/honeypot/logs`. |
| **Host Windows Firewall Enforcement** | Live host firewall mutation disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`) | Mutating host workstation firewall rules poses operational risks to network stability and IDE connectivity. | Execute real netsh firewall mutations exclusively in dedicated ephemeral Windows sandbox VMs via `run-vm-firewall-tests.ps1`. |
| **SecurityEventBus Distribution** | Single-process in-memory pub/sub; bounded to local Node.js heap | Uses Node.js `EventEmitter` with a 200-event ring buffer outbox and 1,000-ID deduplication cache. | Implement a pluggable broker adapter (Redis Pub/Sub, RabbitMQ, or NATS) for multi-node cluster deployments. |
| **Session Inactivity Precision** | 60-second database update throttle allows up to ~16m effective idle | Throttling prevents MongoDB write amplification on rapid API requests; `lastActiveAt` is touched at most once per minute. | Acceptable tradeoff for web platform scalability. If sub-second revocation is required, maintain session heartbeat in Redis. |
| **Windows Process Lifecycle** | `Stop-Process` bypasses graceful shutdown handlers | Windows kernel `TerminateProcess()` API abruptly halts processes without delivering POSIX signals or triggering Node.js event loop callbacks. | Supervise backend with WinSW (`docs/templates/winsw-sentinelai-backend.xml`), NSSM, or native Windows Services sending `CTRL_C_EVENT`. |
| **Client/Server Idle Clock Skew** | Frontend idle timer and backend server timer may desynchronize | Browser tabs suspended in background, client system sleep/wake, or client clock drift can misalign client timers. | Server-authoritative validation: Backend `authSessionService.load()` enforces absolute expiration and inactivity regardless of frontend timer state. |

---

## 3. Detailed Component Boundaries

### 3.1 Cowrie Honeypot Ingestion & Telemetry

#### Architectural Reality
The SentinelAI codebase features dedicated backend ingest controllers (`backend/routes/honeypotIngest.js`) and AI engine log parsing pipelines (`ai-engine/inference/cowrie_parser.py`). However, **no live Cowrie honeypot daemon exists on the host Windows workstation**.

#### Hardening Implemented in Phase 6
- Bounded input payloads: Commands and URLs strictly capped at 2,048 characters to prevent buffer exhaustion and ReDoS attacks.
- Sensitive credential redaction: Captured passwords in authentication attempts are replaced with `***REDACTED***` prior to database persistence and event emission.
- Ingestion telemetry status endpoint: `GET /api/honeypot/status` truthfully returns:
  ```json
  {
    "telemetryStatus": "IDLE / NO RECENT TELEMETRY",
    "integrationStatus": "NOT IMPLEMENTED / BLOCKED ON WINDOWS HOST",
    "liveSensorPresent": false
  }
  ```
- AI parser verification: Pytest suite `ai-engine/tests/test_cowrie_parser.py` exercises parsing using synthetic RFC-compliant JSON fixtures.

#### Deployment Requirement
In an enterprise deployment, a dedicated Linux virtual machine or containerized honeypot sensor must be provisioned. The sensor forwards JSON logs to the SentinelAI ingest endpoint over an authenticated, TLS-encrypted channel using dedicated API keys.

---

### 3.2 Host Windows Firewall vs. Isolated VM Enforcement

#### Architectural Reality
Modifying host Windows Defender Firewall rules during development or automated CI/CD exposes host workstations to network isolation, dropped management sessions, and credential leakage. On the host workstation, `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT` is strictly set to `false`, defaulting containment actions to the memory/mock adapter.

#### Hardening Implemented in Phase 6
- Fail-Closed VM Test Harness: `backend/tests/helpers/vmFirewallHarness.js` checks for:
  1. Environment variable: `SENTINELAI_ISOLATED_TEST_VM=1`
  2. Physical filesystem marker: `C:\sentinelai_vm_marker.txt`
  3. Strict IP address boundary: RFC 5737 `TEST-NET-1` range (`192.0.2.0/24`) ONLY.
- Safe Test Execution Script: `scripts/run-vm-firewall-tests.ps1` mandates Administrator privileges, interactive confirmation, pre-flight and post-flight rule inventorying, and atomic cleanup verification.
- Unit Safety Verification: `backend/tests/windowsFirewallSafety.test.js` guarantees that command-injection attempts, rule naming collisions, and unauthorized subnets are rejected at the policy engine level without calling the OS.

#### Deployment Requirement
Real Windows Firewall automated containment must only be enabled in production environments where the host is an isolated Windows Server endpoint or endpoint agent with dedicated service accounts and explicit network egress rules.

---

### 3.3 Security Event Bus (SecurityEventBus)

#### Architectural Reality
The `SecurityEventBus` implemented in `backend/utils/securityEventBus.js` operates strictly **in-memory** within the Node.js backend process:
- Maximum payload limit: 32,768 bytes (32 KB). Payloads exceeding this size are rejected.
- Deduplication cache: Sliding window of 1,000 UUIDv4 event IDs.
- Outbox ring buffer: Circular buffer retaining the last 200 published events for reconnection and diagnostic inspection.

#### Operational Limitations
1. **Process Restarts**: Because state is stored in memory, queued outbox events are cleared when the backend restarts.
2. **Horizontal Scaling**: In a multi-instance backend deployment (e.g., behind an NGINX load balancer or Kubernetes ingress), an event published on Instance A will not be received by subscribers connected to Instance B.

#### Deployment Path
For multi-node clustering:
- Replace or back the in-memory bus with a distributed pub/sub broker (Redis Streams, RabbitMQ, or Apache Kafka).
- Retain the standardized event envelope, sanitization rules, and payload bounding at the broker ingress boundary.

---

### 3.4 Session Inactivity Timeout & Throttle Granularity

#### Architectural Reality
To protect MongoDB from excessive write load, user activity touches are throttled:
- `INACTIVITY_TIMEOUT_SECONDS`: 900 seconds (15 minutes).
- `ACTIVITY_UPDATE_THROTTLE_SECONDS`: 60 seconds (1 minute).

#### Throttle Behavior & Overshoot
When an authenticated user makes multiple HTTP requests:
1. First request at $T_0$: `lastActiveAt` updated in MongoDB to $T_0$.
2. Subsequent requests between $T_0 + 1\text{s}$ and $T_0 + 59\text{s}$: Evaluated against memory/request context; MongoDB write is skipped.
3. Request at $T_0 + 60\text{s}$: MongoDB `lastActiveAt` updated to $T_0 + 60\text{s}$.

**Maximum Idle Overshoot:** If a user makes a request at $T_0 + 59\text{s}$ (which is throttled) and then stops all activity, the stored `lastActiveAt` remains $T_0$. The session will expire at $T_0 + 900\text{s}$, which is 841 seconds (14m 1s) from their last physical action. Conversely, if their last action touched at $T_0 + 60\text{s}$, expiration occurs at $T_0 + 960\text{s}$. This $\pm 60$-second window is an intentional performance design tradeoff.

---

### 3.5 Windows Process Termination vs. Graceful Draining

#### Architectural Reality
On Microsoft Windows, the PowerShell cmdlet `Stop-Process -Id <PID>` calls the Win32 API `TerminateProcess()`. This causes immediate kernel-level termination of the target process without:
- Emitting POSIX signals (`SIGINT`, `SIGTERM`).
- Triggering Node.js `process.on('SIGINT')` or `process.on('exit')` listeners.
- Allowing in-flight HTTP requests or Socket.IO frames to drain.

#### Graceful Shutdown Constraints
The `GracefulShutdownManager` in `backend/utils/gracefulShutdown.js` executes its sequential shutdown sequence (reject new requests with 503 $\rightarrow$ drain in-flight requests $\rightarrow$ close WebSockets $\rightarrow$ close HTTP server $\rightarrow$ disconnect MongoDB) **only** when signaled via:
1. Console `Ctrl+C` in an interactive PowerShell window (delivering `SIGINT`).
2. Programmatic invocation of `shutdownManager.shutdown('REASON')`.
3. A Windows Service Supervisor (such as WinSW or NSSM) configured to send `CTRL_C_EVENT` or a graceful shutdown message before terminating.

---

## 4. Summary & Verification Reference

All six boundaries outlined above have been verified in the Phase 6 test suite:
- Inactivity throttle and idle checks: `backend/tests/sessionInactivity.test.js` (11 tests passed).
- Graceful shutdown lifecycle: `backend/tests/gracefulShutdown.test.js` (7 tests passed).
- Security event bounding and deduplication: `backend/tests/securityEventBus.test.js` (9 tests passed).
- Honeypot input bounds and status reporting: `backend/tests/cowrieIngest.test.js` (6 tests passed) & `ai-engine/tests/test_cowrie_parser.py` (3 tests passed).
- Fail-closed VM firewall isolation: `backend/tests/windowsFirewallSafety.test.js` (8 tests passed).

No undocumented side-effects, bypasses, or security regressions were observed.
