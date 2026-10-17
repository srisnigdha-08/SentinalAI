# SentinelAI GATE-1 Phase 3D: Rollback and Recovery Plan

## 1. Overview

This document provides deterministic, step-by-step procedures to revert the Phase 3D backend safety patch in the event of an operational anomaly, regression, or deployment rejection.

Because Phase 3D was developed on an isolated Git branch (`feature/gate1-phase3d-backend-safety`) with pristine pre-patch backups (`.orig-phase3d`), rollback can be completed within 60 seconds with zero downtime.

---

## 2. Git-Based Rollback (Recommended Primary Path)

The clean baseline state of the repository prior to Phase 3D is preserved on `main` at commit `5ea7051`.

### Step 1: Switch back to `main`
```bash
git checkout main
```

### Step 2: Verify Working Tree Cleanliness
```bash
git status
```
*Expected Output: `On branch main`, `nothing to commit, working tree clean` (except untracked `.orig-phase3d` backups and experiment directories).*

### Step 3: Run Full Regression Test Suite on `main`
```bash
cd backend
npx jest tests/aiDependencyContract.test.js \
         tests/containmentPolicy.test.js \
         tests/querySecurity.test.js \
         tests/securityEventBus.test.js --verbose
```
*Expected Output: All 61 baseline tests pass.*

---

## 3. File Backup Restoration (Alternative Direct Path)

If Git is unavailable or disconnected, all 6 target files can be restored directly from their pre-patch `.orig-phase3d` backup files:

### Windows PowerShell Restoration Command:
```powershell
Copy-Item -Path "backend\controllers\threatController.js.orig-phase3d" -Destination "backend\controllers\threatController.js" -Force
Copy-Item -Path "backend\models\Alert.js.orig-phase3d" -Destination "backend\models\Alert.js" -Force
Copy-Item -Path "backend\models\ThreatLog.js.orig-phase3d" -Destination "backend\models\ThreatLog.js" -Force
Copy-Item -Path "backend\services\aiEngineService.js.orig-phase3d" -Destination "backend\services\aiEngineService.js" -Force
Copy-Item -Path "backend\services\aiService.js.orig-phase3d" -Destination "backend\services\aiService.js" -Force
Copy-Item -Path "backend\services\threatService.js.orig-phase3d" -Destination "backend\services\threatService.js" -Force
```

### Verification Diff:
```bash
git diff backend/
```
*Expected Output: Empty diff against `main` (commit `5ea7051`).*

---

## 4. Database Recovery & Data Sanitization

Because Phase 3D was executed with database isolation guards (zero writes to `sentinel-db`), **no database remediation is required for this phase**.

In the event that Phase 3D code was run in a staging environment connected to a live database where documents were persisted with `status: 'DEGRADED'` or `attackType: 'UNINSPECTED_TRAFFIC'`, execute the following safe MongoDB cleanup script:

```javascript
// Connect to staging MongoDB
use sentinel-db;

// Migrate DEGRADED status to MONITORED to satisfy pre-patch Mongoose schema validation:
db.threatlogs.updateMany(
    { status: "DEGRADED" },
    { $set: { status: "MONITORED", notes: "Migrated from DEGRADED during Phase 3D rollback" } }
);

// Migrate UNINSPECTED_TRAFFIC attackType to Unknown:
db.threatlogs.updateMany(
    { attackType: "UNINSPECTED_TRAFFIC" },
    { $set: { attackType: "Unknown", notes: "Migrated from UNINSPECTED_TRAFFIC during Phase 3D rollback" } }
);
```

---

## 5. Protected Asset Verification Post-Rollback

Following any rollback action, re-verify the cryptographic hashes of all 5 protected assets to confirm that no model weights or Q-tables were modified:

```powershell
Get-FileHash -Algorithm SHA256 @(
  "ai-engine\models\q_table.json",
  "ai-engine\runtime\q_table.json",
  "ai-engine\models\rf_classifier_cicids_v2.pkl",
  "ai-engine\models\isolation_forest_cicids.pkl",
  "ai-engine\models\xgb_classifier_cicids_v2.pkl"
) | Format-Table -Property Path, Hash
```

All 5 hashes must strictly match the baseline values recorded in `protected_asset_hash_verification.json`.
