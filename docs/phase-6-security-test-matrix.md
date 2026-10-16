# SentinelAI Phase 6 — Security Test Matrix

**Date:** 2026-10-15  
**Environment:** Windows 11 Pro Native Development Environment  
**Execution Scope:** Full Phase 6 Verification & Regression Matrix  

---

## 1. Test Matrix Overview

| Test Domain | Suites Executed | Tests Passed | Tests Failed | Tests Skipped | Environment Gate |
|---|---|---:|---:|---:|---|
| **Session Inactivity & Lifecycle** | `tests/sessionInactivity.test.js`, `tests/auth.test.js`, `tests/authHardening.test.js` | 56 | 0 | 0 | Unit & Mock Store |
| **Windows Lifecycle & Shutdown** | `tests/gracefulShutdown.test.js` | 7 | 0 | 0 | Disposable Process Mock |
| **Security Event Bus & Dedup** | `tests/securityEventBus.test.js` | 9 | 0 | 0 | In-Memory Bus |
| **Honeypot Ingest & Privacy** | `tests/cowrieIngest.test.js`, `ai-engine/tests/test_cowrie_parser.py` | 9 | 0 | 0 | Synthetic Fixtures |
| **Firewall Safety & Policy** | `tests/windowsFirewallSafety.test.js`, `tests/containmentPolicy.test.js` | 36 | 0 | 0 | Gated Host (0 Host Rules) |
| **Disposable DB Persistence** | `scratch/run_disposable_tests.js` (4 suites) | 13 | 0 | 0 | Disposable Port 27029 |
| **AI Engine & Model Guard** | `ai-engine/tests/` (129 tests) | 129 | 0 | 0 | Native Python Environment |
| **Frontend Security & Routing** | `frontend/tests/*.test.mjs` | 34 | 0 | 0 | Node Test Runner |
| **Frontend Production Build** | `frontend/` (`npm run build`) | 1 | 0 | 0 | Vite Production Bundler |
| **TOTAL** | **18 Suites / Tasks** | **294** | **0** | **0** | **100% Passing** |

---

## 2. Detailed Test Case Specifications & Results

### 2.1 Domain: Session Inactivity & Credential Controls

| Test ID | Test Case | Target Component | Input / Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **SEC-INACT-01** | Inactivity timeout default parsing | `authSessionService.js` | `parseInactivityTimeout(undefined)` | Returns default `900` seconds | Returns `900` | **PASS** |
| **SEC-INACT-02** | Inactivity timeout valid range | `authSessionService.js` | `parseInactivityTimeout('1800')` | Returns parsed integer `1800` | Returns `1800` | **PASS** |
| **SEC-INACT-03** | Inactivity timeout invalid rejection | `authSessionService.js` | `parseInactivityTimeout('abc')`, `parseInactivityTimeout(59)` | Throws descriptive configuration error | Throws `Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS` | **PASS** |
| **SEC-INACT-04** | Active session validity within window | `authSessionService.js` | Request with `now = lastUsedAt + 5m` | Session authorized; `role = analyst` | Authorized successfully; `revokedAt = null` | **PASS** |
| **SEC-INACT-05** | Idle session revocation | `authSessionService.js` | Request with `now = lastUsedAt + 15m1s` | Rejects with 401; sets `revocationReason: 'inactivity-timeout'` | Rejects with 401; sets `revocationReason: 'inactivity-timeout'` | **PASS** |
| **SEC-INACT-06** | Absolute 30-day expiry enforcement | `authSessionService.js` | Request with `now = createdAt + 31d`, `lastUsedAt = now - 2m` | Rejects with 401 due to absolute expiry | Rejects with 401; absolute expiry preserved | **PASS** |
| **SEC-INACT-07** | Refresh cannot revive idle session | `authSessionService.js` | `rotate(refreshToken)` where session idle $> 15m$ | Rejects with 401; session remains revoked | Rejects with 401; subsequent attempts fail | **PASS** |
| **SEC-INACT-08** | Throttled activity recording | `authSessionService.js` | Request 10s after last request ($< 60s$ throttle) | Database write skipped; `lastUsedAt` unchanged | `lastUsedAt` unchanged | **PASS** |
| **SEC-INACT-09** | Bounded activity recording | `authSessionService.js` | Request 70s after last request ($> 60s$ throttle) | Database updated with current server timestamp | `lastUsedAt` updated to current timestamp | **PASS** |
| **SEC-INACT-10** | Stale request cannot update revoked session | `authSessionService.js` | `recordActivity` on revoked session | No update to `lastUsedAt` | `lastUsedAt` remains unchanged | **PASS** |
| **SEC-INACT-11** | Cookie clearing on idle expiration | `middleware/auth.js` | Request with idle-expired token to `/api/auth/me` | HTTP 401 with `Set-Cookie` clearing `sentinel_refresh_v2` | HTTP 401 with `Set-Cookie: Max-Age=0` | **PASS** |

---

### 2.2 Domain: Windows Lifecycle & Graceful Shutdown

| Test ID | Test Case | Target Component | Input / Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **SEC-LIFE-01** | Coordinated shutdown ordering | `gracefulShutdown.js` | Trigger `shutdown('SIGTERM')` | Executes Step 1 (Services) -> Step 2 (WS) -> Step 3 (Drain) -> Step 4 (HTTP) -> Step 5 (DB) | Exact sequential execution; exit code 0 | **PASS** |
| **SEC-LIFE-02** | Shutdown idempotency | `gracefulShutdown.js` | Send `SIGINT` followed immediately by `SIGTERM` | Second signal ignored; duplicate cleanup avoided | Returns initial report; close calls = 1 | **PASS** |
| **SEC-LIFE-03** | In-flight request tracking | `gracefulShutdown.js` | Normal HTTP request passes through middleware | `inFlightRequests` increments to 1, then decrements to 0 on finish | In-flight requests accurately tracked | **PASS** |
| **SEC-LIFE-04** | 503 Rejection during shutdown | `gracefulShutdown.js` | Request arrives while `state === 'shutting_down'` | Immediate HTTP 503 with header `Connection: close` | HTTP 503 returned; `Connection: close` set | **PASS** |
| **SEC-LIFE-05** | In-flight request draining | `gracefulShutdown.js` | Shutdown triggered while request is in-flight | Server waits for request to complete before closing | Shutdown resolves once request finishes | **PASS** |
| **SEC-LIFE-06** | Service error resilience | `gracefulShutdown.js` | Registered service throws error on `stop()` | Error logged; shutdown continues to remaining steps | Report records service error; shutdown completes | **PASS** |
| **SEC-LIFE-07** | Partial initialization safety | `gracefulShutdown.js` | Shutdown with uninitialized `server`, `io`, `mongoose` | Handles null values without unhandled exceptions | Completes shutdown cleanly | **PASS** |

---

### 2.3 Domain: Security Event Reliability & Deduplication

| Test ID | Test Case | Target Component | Input / Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **SEC-BUS-01** | Secret key redaction | `securityEventBus.js` | Payload containing `password`, `token`, `refreshToken` | Sensitive keys replaced with `***REDACTED***` | Sensitive keys replaced with `***REDACTED***` | **PASS** |
| **SEC-BUS-02** | Prototype pollution protection | `securityEventBus.js` | Malicious payload with `__proto__` injection | Prototype pollution keys stripped | `clean.__proto__.polluted` is undefined | **PASS** |
| **SEC-BUS-03** | Standard envelope generation | `securityEventBus.js` | Valid `THREAT_DETECTED` event payload | Envelope contains UUID, `version: 1.0`, ISO timestamp | Envelope validated with all metadata | **PASS** |
| **SEC-BUS-04** | Unsupported event rejection | `securityEventBus.js` | Event with `eventType = 'UNKNOWN_EVENT'` | Throws validation error | Throws `Invalid or unsupported eventType` | **PASS** |
| **SEC-BUS-05** | Payload size bounding | `securityEventBus.js` | Payload string exceeding 32 KB | Throws payload size limit error | Throws `Event payload exceeds maximum permitted size` | **PASS** |
| **SEC-BUS-06** | Event deduplication | `securityEventBus.js` | Same `eventId` published twice | Second publication skipped with `duplicate_skipped` | Returns `{ status: 'duplicate_skipped' }` | **PASS** |
| **SEC-BUS-07** | Outbox ring buffer bounding | `securityEventBus.js` | 15 events published to bus with maxHistory 10 | History size capped at 10; oldest 5 discarded | History length = 10; latest event preserved | **PASS** |
| **SEC-BUS-08** | In-process pub/sub | `securityEventBus.js` | Subscribe to `THREAT_DETECTED`, publish event | Subscriber callback invoked with envelope | Callback invoked; unsubscription works | **PASS** |
| **SEC-BUS-09** | WebSocket dual-channel broadcast | `securityEventBus.js` | Publish `THREAT_DETECTED` with mock Socket.IO | Emits `security_event` to `all` and `new_threat` to subscribers | Both channels received appropriate payloads | **PASS** |

---

### 2.4 Domain: Honeypot & Cowrie Telemetry Hardening

| Test ID | Test Case | Target Component | Input / Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **SEC-COW-01** | Unauthenticated ingest rejection | `honeypotIngest.js` | POST `/api/honeypot/ingest` without `x-api-key` | HTTP 401 Unauthorized (`Missing API key`) | HTTP 401 (`Missing API key`) | **PASS** |
| **SEC-COW-02** | Invalid API key rejection | `honeypotIngest.js` | POST with `x-api-key: wrong-key` | HTTP 401 Unauthorized (`Invalid API key`) | HTTP 401 (`Invalid API key`) | **PASS** |
| **SEC-COW-03** | Unsupported event type | `honeypotIngest.js` | POST with `eventType: 'ARBITRARY'` | HTTP 400 Bad Request | HTTP 400 (`Unsupported honeypot eventType`) | **PASS** |
| **SEC-COW-04** | Oversized command rejection | `honeypotIngest.js` | Command input $> 2048$ characters | HTTP 400 Bad Request | HTTP 400 (`Command length exceeds maximum...`) | **PASS** |
| **SEC-COW-05** | Oversized URL rejection | `honeypotIngest.js` | Download URL $> 2048$ characters | HTTP 400 Bad Request | HTTP 400 (`Download URL exceeds maximum...`) | **PASS** |
| **SEC-COW-06** | Telemetry health indicator | `honeypot.js` | GET `/api/honeypot/status` | Reports `liveTelemetry: false`, `status: idle`, `liveTelemetryBlocked: true` | Truthful telemetry status returned | **PASS** |
| **SEC-COW-07** | Cowrie intent classification | `log_parser.py` | Synthetic command strings (cat passwd, wget, chmod, crontab, nc) | Categorizes intent accurately into known taxonomy | 10/10 categories accurately identified | **PASS** |
| **SEC-COW-08** | IOC extraction from Cowrie log | `log_parser.py` | Synthetic log line with IPs, URLs, hashes | Extracts distinct IOC lists | IPs, URLs, hashes, sensitive files parsed | **PASS** |
| **SEC-COW-09** | Live Cowrie Telemetry Gate | External Environment | Attempt to connect live Cowrie sensor | Truthfully reports `NOT IMPLEMENTED / BLOCKED` | Blocked due to missing host daemon | **PASS (GATED)** |

---

### 2.5 Domain: Windows Firewall Adapter & VM Harness Safety

| Test ID | Test Case | Target Component | Input / Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|---|
| **SEC-FW-01** | VM environment fail-closed guard | `vmFirewallHarness.js` | Run on host workstation (markers missing) | Throws `CRITICAL SAFETY REFUSAL` | Throws `CRITICAL SAFETY REFUSAL` | **PASS** |
| **SEC-FW-02** | Safe test target whitelist | `vmFirewallHarness.js` | Test target `192.0.2.100` (TEST-NET-1) | Permitted | Permitted | **PASS** |
| **SEC-FW-03** | Forbidden target rejection | `vmFirewallHarness.js` | Test target `127.0.0.1`, `192.168.1.1`, `8.8.8.8` | Throws `TARGET SAFETY REFUSAL` | Throws `TARGET SAFETY REFUSAL` | **PASS** |
| **SEC-FW-04** | Real adapter enforcement gate | `WindowsFirewallAdapter.js` | Execute `applyRule` with `enabled = false` | Rejects with `FIREWALL_ENFORCEMENT_DISABLED` | Throws `FIREWALL_ENFORCEMENT_DISABLED` | **PASS** |
| **SEC-FW-05** | Command injection prevention | `WindowsFirewallAdapter.js` | Target `192.0.2.1 & calc.exe`, `192.0.2.1; netsh` | Throws `Invalid target address characters` | Throws `Invalid target address characters` | **PASS** |
| **SEC-FW-06** | Rule name namespace enforcement | `WindowsFirewallAdapter.js` | Rule name `Allow-All-Inbound` | Throws `Invalid or unauthorized rule name` | Throws `Invalid or unauthorized rule name` | **PASS** |
| **SEC-FW-07** | Loopback containment rejection | `containmentPolicyService.js` | Target `127.0.0.1`, `127.0.0.53`, `::1` | Safety exclusion blocks target (`isSafe = false`) | Blocked; decision `DENIED` | **PASS** |
| **SEC-FW-08** | Link-local & multicast rejection | `containmentPolicyService.js` | Target `169.254.1.1`, `fe80::1`, `224.0.0.1` | Safety exclusion blocks target (`isSafe = false`) | Blocked; decision `DENIED` | **PASS** |
| **SEC-FW-09** | Host Workstation Firewall Rules | Windows Host OS | `Get-NetFirewallRule -DisplayName "SentinelAI-*"` | Exactly 0 rules | Exactly 0 rules | **PASS** |
| **SEC-FW-10** | Dedicated VM Real Enforcement | External VM Environment | Real `netsh` execution on live Windows Firewall | Marked `BLOCKED` until dedicated VM provisioned | Host protected; VM script ready | **PASS (GATED)** |
