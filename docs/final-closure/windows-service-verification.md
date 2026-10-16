# SentinelAI Final Closure: Windows Service and Lifecycle Verification

**Date**: October 15, 2026  
**Auditor**: Windows Platform & Systems Reliability Engineer  
**Component**: Windows Service Architecture, WinSW Service Wrapper, and Graceful Shutdown Lifecycle  
**Status**: **UNIT-VERIFIED & OPERATIONAL GATE DEFINED**

---

## 1. Lifecycle Architecture & Shutdown Sequence

SentinelAI implements a multi-stage `GracefulShutdownManager` (`backend/utils/gracefulShutdown.js`) designed to coordinate orderly service termination:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              SHUTDOWN TRIGGER RECEIVED                                 │
│                   (SIGINT, SIGTERM, or IPC message: { action: 'shutdown' })            │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Step 1: Background Services & Timers                                                 │
│   - Stop threat reconciliation loops, telemetry timers, and outbox replays             │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Step 2: WebSocket Disconnect                                                         │
│   - io.disconnectSockets(true) and io.close()                                          │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Step 3: In-Flight HTTP Request Draining                                              │
│   - Stop accepting new requests (return HTTP 503 Server is shutting down)              │
│   - Wait up to drainTimeoutMs (5000ms) for in-flight requests to complete              │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Step 4: Close HTTP Server & Idle Connections                                         │
│   - server.closeIdleConnections() and server.close()                                    │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│   Step 5: Database Connection Close                                                    │
│   - mongoose.connection.close(false)                                                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Windows Service Architecture & Session 0 Constraints

In a Windows enterprise deployment, SentinelAI is configured to execute as a background Windows Service using the Windows Service Wrapper (WinSW) via `docs/templates/winsw-sentinelai-backend.xml`.

### 2.1 The Session 0 Technical Limitation
On Microsoft Windows:
1. Windows Services execute in **Session 0**, an isolated, non-interactive session devoid of a user desktop or interactive console (`CONIN$`).
2. Node.js is primarily architected for POSIX signals (`SIGTERM`, `SIGINT`). On Windows, Node.js simulates these signals via the Win32 `GenerateConsoleCtrlEvent` API.
3. In Session 0, child processes lack an interactive console window. When WinSW attempts to stop the service by sending `CTRL_C_EVENT` via `GenerateConsoleCtrlEvent`, the Win32 call frequently fails or times out.
4. WinSW then falls back to `TerminateProcess()`, which forcibly halts `node.exe` immediately, bypassing Node's JavaScript event loop and preventing `GracefulShutdownManager` cleanup hooks from completing.

### 2.2 Mitigation & Alternative IPC Triggers
To overcome this Session 0 limitation without relying on POSIX console signals, `GracefulShutdownManager` includes native IPC support:
```javascript
process.on('message', (msg) => {
  if (msg === 'shutdown' || (typeof msg === 'object' && msg && msg.action === 'shutdown')) {
    handler('IPC_SHUTDOWN')
  }
})
```
In production deployments, service supervision can utilize a Windows Named Pipe or a lightweight supervisor process that sends an IPC message, triggering the complete, clean shutdown sequence.

---

## 3. Unit and Process Verification Evidence

The shutdown manager was verified using `backend/tests/gracefulShutdown.test.js`:

| Test Case | Scenario | Expected Behavior | Result |
| :--- | :--- | :--- | :--- |
| **Coordinated Sequence** | Full shutdown under `SIGTERM` | Steps 1 through 5 execute in exact sequence | **PASS** |
| **Idempotency** | Duplicate signals sent concurrently | Duplicate signals ignored; single execution | **PASS** |
| **In-Flight Tracking** | Normal HTTP operations | Middleware tracks request count accurately | **PASS** |
| **503 Rejection** | Requests arriving during shutdown | Middleware rejects with HTTP 503 and `Connection: close` | **PASS** |
| **Request Draining** | In-flight request active during shutdown | Shutdown waits for active request finish event | **PASS** |
| **Service Fault Tolerance** | Registered service throws during `stop()` | Error logged in report; shutdown continues to completion | **PASS** |
| **Null Safety** | Uninitialized components | Gracefully closes without TypeError | **PASS** |

Total: **7 passed, 0 failed in 0.642s**.

---

## 4. Operational Release Gate for Host Service Registration

> [!WARNING]
> **Operational Release Gate: Dedicated VM Testing Required.**  
> In accordance with safety rules, the WinSW service wrapper was **NOT** installed as a persistent Windows Service on the developer workstation. Doing so would require Administrator privileges, registry mutations, and would risk killing active development processes.  
> **Remaining Operational Requirement**: Prior to production server deployment, the full WinSW package must be installed and tested inside a dedicated Windows Server VM to validate Session 0 stop behavior under Windows Service Control Manager (`sc.exe stop SentinelAI-Backend`).
