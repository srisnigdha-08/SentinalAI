# SentinelAI Phase 7 — Known Limitations, Architectural Boundaries & Production Blockers

**Document Version:** 1.0.0  
**Date:** October 15, 2026  
**Author:** Senior Application Security Engineer & Systems Architect  
**Project:** SentinelAI Enterprise Security Platform  

---

## 1. Executive Summary

This document establishes the definitive inventory of known limitations, architectural boundaries, and unresolved production blockers in the SentinelAI platform following the completion of Phase 7. Transparently documenting these constraints prevents false assumptions regarding external infrastructure readiness, horizontal scalability, and operating-system-level containment enforcement.

---

## 2. Matrix of Known Limitations & Blockers

| Limitation / Blocker | Category | Current Status | Operational Impact | Exact Next Action Required to Close |
| :--- | :--- | :--- | :--- | :--- |
| **1. Live Cowrie Telemetry** | External Telemetry | **BLOCKED — SENSOR UNAVAILABLE** | Ingestion pipeline is hardened and verified, but no live Cowrie daemon is installed on the Windows host. | Provision a dedicated Linux VM or Docker container running Cowrie with forwarder shipping logs over mTLS to `/api/honeypot/logs`. |
| **2. Host Windows Firewall Real Enforcement** | Endpoint Containment | **BLOCKED ON HOST / GATED** | Host workstation enforcement is permanently disabled (`ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`). | Provision a dedicated, disposable Windows 11 sandbox VM with `SENTINELAI_ISOLATED_TEST_VM=1` and execute `run-vm-firewall-tests.ps1`. |
| **3. SecurityEventBus Scalability** | Event Reliability | **SINGLE-PROCESS BOUNDED** | Event bus uses Node.js in-memory ring buffer (200 events). Does not distribute events across multi-instance clusters. | Author a pluggable Redis Streams or RabbitMQ broker adapter implementing `SecurityEventBus` interface for multi-node deployments. |
| **4. Session Inactivity Throttle Overshoot** | Authentication | **BOUNDED TO $\pm 60$ SECONDS** | 60-second database touch throttle prevents MongoDB write amplification but allows up to 15m 59s effective idle. | Acceptable performance tradeoff. If sub-second revocation is strictly required, maintain session heartbeat in in-memory cache. |
| **5. Windows Signal Delivery Limitations** | Lifecycle | **SUPERVISED MODE REQUIRED** | Windows `Stop-Process` triggers kernel `TerminateProcess`, bypassing Node.js cleanup handlers. | Supervise backend with WinSW using `docs/templates/winsw-sentinelai-backend.xml` which delivers native `CTRL_C_EVENT` before stopping. |
| **6. Synthetic Evaluation Domain Shift** | AI Quality | **REAL VS SYNTHETIC SHIFT** | Model trained on CICIDS2017 real network flows flags synthetic attack vectors as inliers/benign (FNR 100% on synthetic). | Evaluate exclusively against real held-out PCAP slices (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`). |

---

## 3. Detailed Technical Analysis of Primary Blockers

### 3.1 Blocker 1: Live External Cowrie Honeypot Sensor

#### Root Cause
Cowrie is a specialized Python/Twisted SSH and Telnet honeypot designed for Linux POSIX environments. The Windows 11 host workstation does not have a Cowrie daemon installed, nor does it expose open port 22/2222 SSH listening sockets.

#### Safe Preparation Implemented in Phase 6/7
- Defensive validation: Inputs bounded to $\le 2048$ characters.
- Privacy preservation: Passwords automatically redacted to `***REDACTED***`.
- Status endpoint: `GET /api/honeypot/status` truthfully returns `liveTelemetryBlocked: true`, `status: 'idle'`.
- Parsing unit tests: Verified with synthetic RFC-compliant JSON fixtures.

#### Next Action to Close
1. Deploy an Ubuntu 24.04 LTS VM or container with Cowrie installed.
2. Configure `cowrie.cfg` with output plugin `output_https` or a filebeat shipper pointing to `https://<sentinel-host>/api/honeypot/logs`.
3. Provide an authorized API key in the `X-Honeypot-Key` header.

---

### 3.2 Blocker 2: Host Windows Firewall Real Enforcement

#### Root Cause
Mutating host Windows Defender Firewall rules during local development exposes the developer's workstation to severe operational hazards, including dropped RDP/SSH sessions, network isolation, and corruption of host firewall tables. Host enforcement is permanently gated.

#### Safe Preparation Implemented in Phase 6/7
- Dual-marker fail-closed check in `backend/tests/helpers/vmFirewallHarness.js`:
  1. `SENTINELAI_ISOLATED_TEST_VM === 'true'`
  2. Physical marker file: `C:\sentinelai_vm_marker.txt`
- RFC 5737 `TEST-NET-1` address restriction (`192.0.2.0/24` only).
- Pre/post rule reconciliation script: `scripts/run-vm-firewall-tests.ps1`.
- Verified that the PowerShell test runner immediately refuses execution on the host workstation with exit code 1.

#### Next Action to Close
1. Create a dedicated Hyper-V or VirtualBox Windows 11 sandbox VM.
2. Take a clean baseline hypervisor snapshot.
3. Create `C:\sentinelai_vm_marker.txt` inside the VM.
4. Set `$env:SENTINELAI_ISOLATED_TEST_VM = "true"` and `$env:ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = "true"`.
5. Execute `scripts/run-vm-firewall-tests.ps1 -ConfirmExecution` as Administrator.
6. Verify rule inventory reconciliation and revert to hypervisor snapshot.

---

### 3.3 Blocker 3: Horizontal Clustering & Durable Event Distribution

#### Root Cause
`SecurityEventBus` operates entirely in memory within the single Node.js backend process. While ideal for native standalone Windows development, running multiple Node.js backend instances behind an external load balancer will isolate events between instances.

#### Next Action to Close
1. Deploy a Redis 7+ instance on the private management network.
2. Author `RedisSecurityEventBus` implementing `publish()`, `publishDurable()`, and `subscribe()`.
3. Retain the existing envelope structure, sanitization rules, and payload bounding.
