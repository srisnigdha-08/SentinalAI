# SentinelAI End-to-End (E2E) Test Suite

Comprehensive Playwright test automation suite for the SentinelAI SOC cybersecurity platform.

---

## 🛡️ Non-Negotiable Safety Rules & Guarantees

1. **Host Firewall Dry-Run Lock**:
   - `WindowsFirewallAdapter.js` and `adapterFactory.js` enforce a hard lock:
     ```javascript
     if (process.env.NODE_ENV === 'test' || process.env.CONTAINMENT_DRY_RUN === 'true') {
       // All netsh advfirewall and PowerShell firewall mutations are strictly bypassed
     }
     ```
   - Tests execute safely in-memory against mock/dry-run adapters without ever mutating the Windows host network or firewall rules.

2. **Dedicated Test Database Isolation (`sentinelai_test`)**:
   - Both `start-test-backend.cjs` and `global-setup.js` enforce fail-fast validation:
     ```javascript
     if (!mongoUri.toLowerCase().includes('test')) {
       throw new Error(`CRITICAL SAFETY VIOLATION: Database name in MONGO_URI must contain "test"`);
     }
     ```
   - Dev and production databases (`sentinelai`, `sentinelai_prod`) are strictly protected from accidental test runs.

3. **Zero Secrets Committed**:
   - `.env.test` is strictly listed in `.gitignore`.
   - Ephemeral testing tokens, JWT secrets, and CSRF nonces are injected dynamically via test runners.

---

## 👥 Seed Data (`global-setup.js`)

Prior to test execution, `global-setup.js` purges test collections and deterministically seeds accounts across all RBAC tiers:

| Role | Email | Password | Permissions / Status |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@sentinel.test` | `AdminPassword123!` | Full governance, users, firewall rules, telemetry |
| **Analyst** | `analyst@sentinel.test` | `AnalystPassword123!` | Incident triage, active containment, model verification |
| **Viewer** | `viewer@sentinel.test` | `ViewerPassword123!` | Read-only observation, telemetry monitoring |
| **Restricted** | `restricted@sentinel.test` | `TempPassword123!` | `mustChangePassword: true` forced credential reset flow |

### Seeded Telemetry & Intelligence:
- **5 ThreatLogs**: SSH Brute Force, SQL Injection, DDoS, Port Scan, RCE Attempt (Critical/High/Medium).
- **1 Honeypot Node**: `SSH-COWRIE-01` (the only implemented node; one seeded session uses the label `HTTP-LURE-02` as plain session data).
- **2 Honeypot Sessions**: Live Cowrie and HTTP lure attacker sessions with extracted credentials.
- **2 Security Alerts**: Critical perimeter breach and high-priority SQL injection alert.
- **1 Attack Campaign**: Coordinated multi-source credential rotation cluster.
- **1 Blocked IP**: Pre-contained malicious scanner (`185.220.101.5`).

---

## 🏗️ Architecture & Page Object Model (POM)

Located in `frontend/e2e/fixtures/`:
- **`auth.fixture.js`**: Extended Playwright test fixture providing authenticated pages (`adminPage`, `analystPage`, `viewerPage`, `mustChangePage`) and POM injection.
- **`pom/LoginPage.js`**: Login credentials submission, error toasts, and navigation.
- **`pom/DashboardPage.js`**: KPI metrics, charts, live feed, and panel error boundaries.
- **`pom/ThreatLogsPage.js`**: Telemetry tables, filters, pagination, triage and containment triggers.
- **`pom/SettingsPage.js`**: Auto-blocking engine toggles, manual IP enforcement, and audit logs.
- **`pom/UserManagementPage.js`**: Operator provisioning form, RBAC roles, and account deletion.
- **`pom/ChangePasswordPage.js`**: Forced credential rotation, validation, and match checks.
- **`pom/ModalComponent.js`**: Accessible modal dialog assertions (`role="dialog"`, `aria-modal="true"`, focus trap).

---

## 🧪 Test Suites Overview (13 Spec Files)

1. **`auth.spec.js`**: Successful login per role, invalid credentials, logout, cookie session restoration on reload, transparent refresh on 401 retry, BroadcastChannel cross-tab logout, and double-submit prevention.
2. **`password-change.spec.js`**: Forced redirect for restricted users, input validation (length, mismatch, duplicate current), success redirect to `/dashboard`, single-flight PUT.
3. **`rbac.spec.js`**: Route access restrictions, sidebar visibility matching role, unauthorized access redirection with toast.
4. **`landing.spec.js`**: Unauthenticated visit produces ZERO 401 errors, animated metric showcase counters, no fatal console errors.
5. **`dashboard.spec.js`**: KPIs and telemetry charts render, IP block displays success toast and reloads queue, panel-level error boundary isolates render crash while keeping rest of dashboard operational.
6. **`threat-logs.spec.js`**: Severity and vector filtering, disabled CSV export, Triage modal PATCH verification, Containment modal POST payload verification with safety rules.
7. **`modal-a11y.spec.js`**: WAI-ARIA compliance (`role="dialog"`, `aria-modal="true"`), focus trap (Tab/Shift+Tab wrapping), Escape key dismissal, body scroll locking, and focus restoration.
8. **`realtime.spec.js`**: Live WebSocket threat emission (`new_threat`), unread alert bell badge update (`new_alert`), socket disconnect resilience (`ConnectionStatus` pill appears and clears).
9. **`error-states.spec.js`**: 500 API simulation across Campaigns, Honeypot, AI Analytics, Users, and Settings; assert `role="alert"` and Retry button; verify Campaigns omits "No security events" on failure.
10. **`settings.spec.js`**: Toggle autonomous auto-block engine, manual blocklist IP format validation (rejecting `999.1.1.1` and `abc`), unblock IP, and audit trail inspection.
11. **`user-management.spec.js`**: Provision new operator, assert row appears in table, delete operator with window.confirm handling, assert 403 on non-admin access.
12. **`responsive.spec.js`**: Breakpoint testing across Desktop (1280px), Tablet (768px), and Mobile (375px); KPI grid column collapse; table horizontal scrolling inside `.sentinel-table-scroll`; `scrollWidth <= innerWidth`.
13. **`smoke.spec.js`**: Comprehensive route smoke sweep across public, operator, and administrator views with zero console or page errors.

---

## 🚀 Running the Tests

From the `frontend/` directory:

```bash
# Run complete test suite (Chromium)
npm run test:e2e

# Run with interactive Playwright UI mode
npm run test:e2e:ui

# Run in headed browser mode
npm run test:e2e:headed

# Open HTML test report
npm run test:e2e:report

# Run specific suite
npx playwright test e2e/auth.spec.js

# Run across all configured browsers (Chromium, Firefox, WebKit, Mobile, Tablet)
npx playwright test
```
