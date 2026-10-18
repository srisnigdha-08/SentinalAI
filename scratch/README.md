# SentinelAI Verification Suite & Demonstration Guide

This directory contains end-to-end browser and API verification scripts used to validate Role-Based Access Control (RBAC), WebSocket stream redaction, live role revocation, and UI control gating against SentinelAI.

---

## 1. Prerequisites

1. **MongoDB**: Running locally at `mongodb://localhost:27017/sentinel-db`.
2. **Frontend UI**: Running at `http://localhost:3000` (`cd frontend && npm run dev`).
3. **Backend Server**: Started with the evaluation demo profile:
   ```powershell
   $env:DOTENV_CONFIG_PATH = "deployment/.env.demo"
   node backend/server.js
   ```

---

## 2. Environment Configuration

All scripts enforce strict zero-credential hardcoding. Required credentials must be set in your environment prior to launching tests. If any required variable is missing, the script will abort immediately with an error message.

### Required Environment Variables
```powershell
# User Passwords
$env:VERIFY_ADMIN_PASSWORD   = "<YOUR_ADMIN_PASSWORD>"
$env:VERIFY_ANALYST_PASSWORD = "<YOUR_ANALYST_PASSWORD>"
$env:VERIFY_VIEWER_PASSWORD  = "<YOUR_VIEWER_PASSWORD>"

# Ingestion API Key (read from backend/.env or deployment/.env.demo)
$env:HONEYPOT_API_KEY        = "<YOUR_HONEYPOT_API_KEY>"

# Optional Overrides
$env:VERIFY_EPHEMERAL_PASSWORD = "Ephemeral@Pass123!"  # Defaults to Ephemeral@Auth123! if unset
$env:MONGO_URI                = "mongodb://localhost:27017/sentinel-db"
```

---

## 3. How to Run Each Verification Script

### A. Viewer Redaction & Audit (`verify_viewer_audit.mjs`)
Validates that a Viewer session receiving live REST responses and WebSocket frames receives **zero** unmasked attacker IPs, **zero** raw honeypot commands/passwords, and encounters **zero** 403 network failures.
```powershell
node scratch/verify_viewer_audit.mjs
```
- **Requirements**: `VERIFY_VIEWER_PASSWORD`, `HONEYPOT_API_KEY`.
- **Outputs**: `scratch/evidence/viewer_network.json`, `scratch/evidence/viewer_ws_frames.json`.
- **Cleanup**: Automatically removes ephemeral test session and threat by ObjectId in `finally`.

### B. Analyst Feed Verification (`verify_analyst_feed.mjs`)
Validates that an Analyst session receives full unmasked source IPs and raw honeypot commands across real-time WebSocket feeds.
```powershell
node scratch/verify_analyst_feed.mjs
```
- **Requirements**: `VERIFY_ANALYST_PASSWORD`, `HONEYPOT_API_KEY`.
- **Outputs**: `scratch/evidence/analyst_ws_frames.json`.
- **Cleanup**: Automatically removes ephemeral test session and threat by ObjectId in `finally`.

### C. Live Demotion & Session Revocation (`verify_live_demotion.mjs`)
Validates immediate real-time session termination without requiring a page refresh:
1. Analyst session downgraded by Admin to Viewer is terminated in real time (HTTP 401 on subsequent requests, WebSocket disconnected).
2. Deactivated user cannot authenticate (HTTP 403).
```powershell
node scratch/verify_live_demotion.mjs
```
- **Requirements**: `VERIFY_ADMIN_PASSWORD`, `VERIFY_ANALYST_PASSWORD`.
- **Cleanup**: Restores original user roles and destroys the dynamically provisioned ephemeral user.

### D. Browser RBAC Navigation Guard (`verify_browser_rbac.mjs`)
Verifies client-side route guards and navigation menus across Analyst, Viewer, and Admin roles.
```powershell
node scratch/verify_browser_rbac.mjs
```
- **Requirements**: `VERIFY_ADMIN_PASSWORD`, `VERIFY_ANALYST_PASSWORD`, `VERIFY_VIEWER_PASSWORD`.

### E. Role-Specific Action Controls (`verify_ui_controls.mjs`)
Verifies that action buttons (`Block IP`, `Triage`, `Takedown`) and Observation Mode badges render strictly according to backend-enforced RBAC.
```powershell
node scratch/verify_ui_controls.mjs
```
- **Requirements**: `VERIFY_ADMIN_PASSWORD`, `VERIFY_ANALYST_PASSWORD`, `VERIFY_VIEWER_PASSWORD`.

---

## 4. Safety & Invariant Guarantees

All verification scripts include built-in safeguards:
- **Environment Gating**: Cleanups check the backend's actual `NODE_ENV` (queried via `/health` or `/api/system/health`) and refuse execution if targeted at `production` or a non-local database.
- **Strict ID Deletions**: Ephemeral records are deleted solely by exact captured MongoDB `_id`, never by `sourceIP` pattern.
- **Unmasked Error Propagation**: If a test assertion fails, the `finally` cleanup block will never mask the original test exception.

---

## 5. Repository Commit Safety Audit

| Script | Status | Safe to Commit? | Notes |
| :--- | :--- | :--- | :--- |
| `scratch/verify_viewer_audit.mjs` | Untracked | **YES** | 100% credential-free. Reads `VERIFY_VIEWER_PASSWORD` and `HONEYPOT_API_KEY` from env. |
| `scratch/verify_analyst_feed.mjs` | Untracked | **YES** | 100% credential-free. Reads `VERIFY_ANALYST_PASSWORD` and `HONEYPOT_API_KEY` from env. |
| `scratch/verify_live_demotion.mjs` | Untracked | **YES** | 100% credential-free. Reads `VERIFY_ADMIN_PASSWORD` and `VERIFY_ANALYST_PASSWORD` from env. |
| `scratch/verify_browser_rbac.mjs` | Untracked | **YES** | 100% credential-free. Reads role passwords from env. |
| `scratch/verify_ui_controls.mjs` | Untracked | **YES** | 100% credential-free. Reads role passwords from env. |
| `scratch/README.md` | Untracked | **YES** | Documentation only. |
| `scratch/evidence/*` | Gitignored | **NO (Ignored)** | Network dumps and frame logs ignored via `.gitignore:56`. |
| One-off scratch scripts (`backup_*`, `dump_*`, `execute_cleanup.mjs`, `test_*`) | Untracked | **NO** | Ephemeral maintenance scripts; recommend keeping untracked or moving to a dedicated tooling folder. |
