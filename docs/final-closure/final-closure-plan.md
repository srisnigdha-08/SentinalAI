# SentinelAI Final Closure: Master Execution Plan & Finite Issue Register

**Date**: October 15, 2026  
**Status**: **EXECUTING & DEFENDING**  
**Auditor**: Senior Application Security Engineer & Systems Architect  

---

## 1. Plan Overview & Prioritization Strategy

This document establishes the finite, comprehensive closure register for SentinelAI. In strict accordance with the master execution instructions, work is prioritized across 10 core technical domains:

1. Data Integrity and Secret Exposure
2. Authentication and Session Authorization
3. Containment Policy & Operating-System Safety
4. Dependency & Supply-Chain Security
5. Machine Learning Evaluation, Robustness & Containment Policy
6. Security Event Bus & Outbox Durability
7. Graceful Shutdown & Windows Service Reliability
8. API, Query Security & Frontend Correctness
9. Regression Testing & Integration Verification
10. Acceptance Documentation & Operational Runbooks

---

## 2. Finite Issue & Requirement Register

### Priority 1: Data Integrity & Secret Protection

#### ISSUE-001: Separation of Frozen Baseline Model from Mutable RL State
- **Severity**: HIGH (Integrity)
- **Impact**: Inadvertent overwriting of baseline reference model `q_table.json` during reinforcement learning policy updates.
- **Evidence**: Two conflicting hashes reported historically (`BF9B...` vs `0579...`). Baseline model located in `models/`, dynamic state located in `runtime/`.
- **Root Cause**: Earlier reporting script hashed the mutable runtime table instead of the reference model directory.
- **Affected Components**: `ai-engine/models/q_table.json`, `ai-engine/runtime/q_table.json`, `ai-engine/rl_engine/deception_scorer.py`.
- **Planned Fix**: Add in-code path resolution safeguards in `DeceptionQLearner.save()` that explicitly detect if `target.resolve()` matches the baseline reference path and automatically redirect to `runtime/q_table.json`. Add regression tests in `test_q_table_safety.py`.
- **Verification Procedure**: `.\.venv\Scripts\python.exe -m pytest tests/test_q_table_safety.py -v`.
- **Rollback Approach**: Revert changes in `deception_scorer.py` using git checkout or atomic diff.
- **Status**: **RESOLVED & VERIFIED**.
- **Remaining Limitation**: Dynamic runtime updates continue writing to `runtime/q_table.json`.

#### ISSUE-002: Live MongoDB Development Database Protection
- **Severity**: CRITICAL (Data Loss)
- **Impact**: Mutation of baseline development database on port 27017 (`sentinel-db`).
- **Evidence**: Development database contains 1 user, 2 authsessions, 1 systemsettings, 0 in other collections.
- **Root Cause**: Test runners attempting to connect to default localhost port 27017 without isolated credentials.
- **Affected Components**: `backend/tests/helpers/dbHandler.js`, `backend/tests/`.
- **Planned Fix**: Enforce disposable in-memory or ephemeral databases (port 27029 or mock fixtures) for all test runs. Block writes to port 27017 during automated testing.
- **Verification Procedure**: Query collection counts on `mongodb://127.0.0.1:27017/sentinel-db` before and after test execution.
- **Rollback Approach**: Invariant violation triggers immediate test halt; restore data from native-integration snapshot if needed.
- **Status**: **VERIFIED INVARIANT (0 MUTATIONS)**.
- **Remaining Limitation**: Live database must not be subjected to integration test writes.

---

### Priority 2: Authentication, Authorization & Session Management

#### ISSUE-003: Session Idle Timeout & Activity Throttling
- **Severity**: HIGH (Session Hijacking)
- **Impact**: Stale sessions remaining authenticated indefinitely without user activity.
- **Evidence**: `authSessionService.js` implements 15-minute idle timeout (`INACTIVITY_TIMEOUT_SECONDS=900`) with activity write throttling (`ACTIVITY_UPDATE_THROTTLE_SECONDS=60`).
- **Root Cause**: Need to prevent database write exhaustion on every authenticated HTTP request while guaranteeing bounded session inactivity.
- **Affected Components**: `backend/services/authSessionService.js`, `backend/middleware/auth.js`.
- **Planned Fix**: Ensure `protect` middleware touches `recordActivity` with timestamp throttling. Validate idle expiration during token refresh and authorization checks.
- **Verification Procedure**: `npm test -- tests/authHardening.test.js tests/sessionInactivity.test.js`.
- **Rollback Approach**: Revert throttling logic to direct timestamp updates.
- **Status**: **VERIFIED (48/48 PASS)**.
- **Remaining Limitation**: Activity updates are throttled to 60-second intervals to preserve database write performance.

#### ISSUE-004: Refresh Token Replay & Race Condition Prevention
- **Severity**: HIGH (Credential Theft)
- **Impact**: Stolen refresh tokens being reused after rotation.
- **Evidence**: `rotate()` in `authSessionService.js` compares `claims.gen` against `session.generation` and immediately revokes the session family upon replay detection.
- **Root Cause**: Distributed or multi-tab refresh races can cause concurrent refresh attempts.
- **Affected Components**: `backend/services/authSessionService.js`, `frontend/src/context/AuthContext.jsx`.
- **Planned Fix**: Verify that server rejects stale generations with `refresh-replay` revocation and Web Locks serialize browser refresh calls.
- **Verification Procedure**: `npm test` in `frontend/` (34 tests) and `backend/tests/authHardening.test.js`.
- **Rollback Approach**: Revert concurrency controls.
- **Status**: **VERIFIED (PASS)**.
- **Remaining Limitation**: Browser tabs without Web Locks support fall back to memory-only single-flight locks.

---

### Priority 3: Containment Policy & Operating-System Safety

#### ISSUE-005: Unsafe Autonomous Containment Prevention
- **Severity**: CRITICAL (Operational Availability)
- **Impact**: Unattended blocking of benign network traffic or critical infrastructure.
- **Evidence**: Model evaluation revealed a **33.0% False Positive Rate on DDoS traffic**, meaning 1 in 3 benign connections are classified as DDoS.
- **Root Cause**: Complex distribution shift and feature overlaps in CICIDS2017 flow representations.
- **Affected Components**: `backend/services/containmentPolicyService.js`, `backend/services/containmentService.js`.
- **Planned Fix**: Enforce `AUTONOMOUS_CONTAINMENT=false` across all configurations. Require explicit human-in-the-loop analyst review for all containment actions. Ensure self-lockout, loopback, and gateway IPs fail closed in policy validation.
- **Verification Procedure**: `npm test -- tests/containmentPolicy.test.js tests/windowsFirewallSafety.test.js`.
- **Rollback Approach**: Policy engine fails closed by default.
- **Status**: **VERIFIED & POLICY LOCKED**.
- **Remaining Limitation**: Autonomous containment is permanently banned until a dedicated ML re-training and validation program achieves <0.1% FPR.

#### ISSUE-006: Host Windows Firewall Protection
- **Severity**: CRITICAL (Host Safety)
- **Impact**: Automated addition of blocking rules to the developer's physical host firewall.
- **Evidence**: Host firewall currently contains 0 `SentinelAI*` rules. `ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=false`.
- **Root Cause**: Need to test firewall logic without disrupting the development workstation.
- **Affected Components**: `backend/services/containment/WindowsFirewallAdapter.js`, `backend/services/containment/adapterFactory.js`.
- **Planned Fix**: Maintain adapter factory fallback to `MockContainmentAdapter`. Ensure `WindowsFirewallAdapter` throws `FIREWALL_ENFORCEMENT_DISABLED` unless safety gate is explicitly true.
- **Verification Procedure**: Verify 0 rules via `Get-NetFirewallRule -DisplayName 'SentinelAI*'`.
- **Rollback Approach**: Safety gate defaults to disabled.
- **Status**: **VERIFIED & GATED**.
- **Remaining Limitation**: Real firewall enforcement is restricted to isolated VMs under WinSW supervision.

---

### Priority 4: Dependency & Supply-Chain Security

#### ISSUE-007: Production Vulnerability Disposition Closure
- **Severity**: MEDIUM-HIGH (Supply Chain)
- **Impact**: 12 vulnerability advisories reported by `npm audit --omit=dev --json` across 6 production packages (`proxy-addr`, `fast-uri`, `js-yaml`, `morgan`, `qs`, `uuid`).
- **Evidence**: Complete audit inventory parsed and analyzed.
- **Root Cause**: Express 4.x core pins older transitive versions (`proxy-addr@2.0.7`, `qs@6.13.0`).
- **Affected Components**: `backend/package.json`, `backend/package-lock.json`.
- **Planned Fix**: Document reachability analysis, architectural mitigations (loopback binding, Winston log sanitization, exclusive `uuid.v4()` usage), and establish the Express v5 migration roadmap as a concrete release gate.
- **Verification Procedure**: `npm audit --omit=dev --json` in `backend/`.
- **Rollback Approach**: Keep current lockfile pinned to prevent breaking changes.
- **Status**: **DEFENSIBLE DISPOSITION & RELEASE GATE DEFINED**.
- **Remaining Limitation**: Express v5 upgrade requires router syntax updates before public network deployment.

---

### Priority 5: Machine Learning Validation & Robustness

#### ISSUE-008: AI Model Evaluation Reproducibility & Leakage Prevention
- **Severity**: HIGH (Model Integrity)
- **Impact**: Overly optimistic performance claims due to training/evaluation data leakage.
- **Evidence**: Evaluation script `evaluate_model.py` and pytest suite `test_model_evaluation.py`.
- **Root Cause**: Need to verify metrics against genuinely held-out data slices.
- **Affected Components**: `ai-engine/evaluation/evaluate_model.py`, `ai-engine/tests/test_model_evaluation.py`.
- **Planned Fix**: Offset evaluation slices by 60,000 samples to avoid training data overlap. Calculate confusion matrices, precision, recall, F1, FPR, and FNR independently.
- **Verification Procedure**: `.\.venv\Scripts\python.exe -m pytest tests/test_model_evaluation.py -v`.
- **Rollback Approach**: Maintain original evaluation scripts as baseline.
- **Status**: **VERIFIED (15/15 PASS, 20.35s)**.
- **Remaining Limitation**: Model exhibits high sensitivity to synthetic protocol variations (100% FNR on synthetic test fixtures).

---

### Priority 6: Event Bus & Outbox Durability

#### ISSUE-009: File-Backed Outbox Atomicity & Crash Recovery
- **Severity**: HIGH (Reliability)
- **Impact**: Loss or corruption of telemetry and security events during sudden backend crashes or power disruptions.
- **Evidence**: `FileOutboxStore` writes directly to `logs/event_outbox.json`.
- **Root Cause**: Potential for partial JSON writes during abrupt process kill.
- **Affected Components**: `backend/utils/securityEventBus.js`, `backend/tests/outboxStress.test.js`.
- **Planned Fix**: Implement atomic temporary-file writes (`.tmp` + rename/copy), corrupted JSON quarantine (`.corrupt.<timestamp>`), retention pruning (100 delivered events kept, pending never pruned), and error capture.
- **Verification Procedure**: `npm test -- tests/outboxStress.test.js tests/securityObservability.test.js`.
- **Rollback Approach**: Revert to in-memory store or simple file write.
- **Status**: **RESOLVED & VERIFIED (15/15 PASS)**.
- **Remaining Limitation**: Delivery semantics are strictly **At-Least-Once**; downstream subscribers must be idempotent.

---

### Priority 7: Graceful Shutdown & Windows Service Reliability

#### ISSUE-010: Windows Service Session 0 Shutdown Limitation
- **Severity**: MEDIUM (Operational)
- **Impact**: WinSW falling back to `TerminateProcess()` on Windows service stop if console signals fail.
- **Evidence**: Windows services run in Session 0 without interactive consoles. Node.js POSIX signal emulation (`SIGTERM`/`SIGINT`) relies on Win32 `GenerateConsoleCtrlEvent`, which can fail in non-interactive sessions.
- **Root Cause**: Windows architecture constraint regarding Session 0 process groups.
- **Affected Components**: `backend/utils/gracefulShutdown.js`, `docs/templates/winsw-sentinelai-backend.xml`.
- **Planned Fix**: `GracefulShutdownManager` supports IPC shutdown messages (`process.on('message')`). Update WinSW template and operational runbook to document this limitation and define named-pipe or IPC shutdown procedures for production VM deployments.
- **Verification Procedure**: `npm test -- tests/gracefulShutdown.test.js`.
- **Rollback Approach**: N/A (Documentation and test validation).
- **Status**: **VERIFIED & GATED**.
- **Remaining Limitation**: Actual WinSW supervision cannot be executed on the developer workstation without admin elevation and service registration; remains an operational release gate.

---

### Priority 8: API Security & Frontend Controls

#### ISSUE-011: Mandatory First-Login Password Change Enforcement
- **Severity**: HIGH (Authentication Bypass)
- **Impact**: Provisioned users accessing protected features before changing temporary credentials.
- **Evidence**: `auth.js` middleware enforces `mustChangePassword` check with an explicit allowlist for password-change and logout endpoints.
- **Root Cause**: Need to allow users to change passwords while blocking access to dashboards and APIs.
- **Affected Components**: `backend/middleware/auth.js`, `frontend/src/routes/ChangePasswordRoute.jsx`.
- **Planned Fix**: Verify that all non-lifecycle API routes return HTTP 403 `PASSWORD_CHANGE_REQUIRED` and frontend redirects to `/change-password`.
- **Verification Procedure**: `npm test` in `frontend/` (Tests 1-8).
- **Rollback Approach**: Maintain strict allowlist.
- **Status**: **VERIFIED (PASS)**.
- **Remaining Limitation**: None.

---

## 3. Execution Schedule & Verification Gate

| Stage | Activity | Key Deliverables | Status |
| :--- | :--- | :--- | :--- |
| **Phase 0** | Baseline Discovery & Freeze | `baseline-and-safety-invariants.md` | **COMPLETED** |
| **Phase 1** | Finite Register & Plan | `final-closure-plan.md` | **COMPLETED** |
| **Phase 2** | Code Hardening & Safeguards | `deception_scorer.py`, `securityEventBus.js` | **COMPLETED** |
| **Phase 3** | Targeted & Regression Testing | Pytest (17 tests), Jest (111 tests), Node (34 tests) | **COMPLETED (162 PASS)** |
| **Phase 4** | Documentation & Runbooks | 10 closure documents in `docs/final-closure/` | **IN PROGRESS** |
| **Phase 5** | Final Evidence Audit & Verdict | Executive report & formal acceptance package | **PENDING** |
