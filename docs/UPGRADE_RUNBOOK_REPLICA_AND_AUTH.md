# Production Upgrade Runbook: Single-Node Replica Set & Least-Privilege Database Auth

> [!CAUTION]
> **DO NOT RUN BEFORE THE VIVA**
> This procedure modifies the Windows MongoDB service configuration (`mongod.cfg`), enforces database authentication, and transitions storage engine topology to a replica set (`rs0`).
> Keep the current unauthenticated standalone instance active for the viva evaluation. Execute this runbook only in a maintenance window post-viva.

---

## 1. Executive Summary

This runbook provides the verified, step-by-step procedure to upgrade the primary host MongoDB instance (`port 27017`) from an unauthenticated standalone instance to an authenticated, single-node replica set with engine-enforced Role-Based Access Control (RBAC).

### Key Architectural Enhancements
1. **Multi-Document ACID Transactions (`rs0`)**: Enables `MONGO_USE_TRANSACTIONS=true` so that multi-collection operations (e.g., user provisioning with audit logging, threat blocking with containment actions) execute atomically, eliminating compensating rollbacks.
2. **Database-Level Least Privilege (`sentinel_app`)**: The application user receives full read/write privileges on operational collections, but is restricted to **find and insert ONLY** on `auditlogs`. Any attempt to update or delete audit records is rejected by MongoDB with error `code: 13` (`Unauthorized`).
3. **Dedicated Audit Role (`sentinel_audit`)**: An isolated worker identity possessing only read and insert capabilities on `auditlogs`, completely barred from reading or modifying domain collections (users, threatlogs, etc.).

---

## 2. Pre-Upgrade Checklist & Verification

Before modifying any configuration files:
1. Verify the current baseline backup exists:
   ```powershell
   Get-ChildItem -Path backups\pre-db-fixes-*
   ```
2. Confirm the 202-document baseline is intact:
   ```powershell
   node -e "const m = require('mongoose'); m.connect('mongodb://localhost:27017/sentinel-db').then(async () => { const c = await Promise.all(Object.values(m.connection.collections).map(col => col.countDocuments())); console.log('Total Docs:', c.reduce((a,b)=>a+b, 0)); process.exit(0); });"
   ```
   *Expected Output: `Total Docs: 202`*
3. Check the host MongoDB service status:
   ```powershell
   Get-Service MongoDB
   ```

---

## 3. Step-by-Step Upgrade Procedure

### Step 1: Generate Security Keyfile & Access Credentials
Create a secure internal communication keyfile for the replica set and restrict its file permissions to the current Windows administrator/SYSTEM account:

```powershell
# 1. Create secure keyfile directory
New-Item -ItemType Directory -Force -Path "C:\Program Files\MongoDB\Server\7.0\security"

# 2. Generate 756-byte cryptographically secure keyfile
$bytes = New-Object byte[] 756
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
[System.Convert]::ToBase64String($bytes) | Out-File -FilePath "C:\Program Files\MongoDB\Server\7.0\security\rs0-keyfile" -Encoding ascii

# 3. Restrict Windows ACLs (read-only for current user and SYSTEM)
icacls "C:\Program Files\MongoDB\Server\7.0\security\rs0-keyfile" /inheritance:r /grant:r "$($env:USERNAME):(R)" /grant:r "SYSTEM:(R)"
```

### Step 2: Initialize Users & Custom Roles (Before Enforcing Auth)
Execute `deployment/mongo-init.js` to define `sentinel_app_role`, `sentinel_audit_role`, and user credentials on `sentinel-db`:

```powershell
# Set strong passwords in your terminal session (do not hardcode in files)
$env:SENTINEL_APP_PASSWORD = "<GENERATE_STRONG_APP_PASSWORD_HERE>"
$env:SENTINEL_AUDIT_PASSWORD = "<GENERATE_STRONG_AUDIT_PASSWORD_HERE>"

# Run initialization script using node
node scratch/setup_test_auth.js
```
*(Alternatively, execute via mongosh: `mongosh localhost:27017/sentinel-db deployment/mongo-init.js`)*

### Step 3: Update `mongod.cfg` Configuration
Open `C:\Program Files\MongoDB\Server\7.0\bin\mongod.cfg` with administrative privileges. Append the `replication` and `security` sections:

```yaml
# mongod.cfg additions

replication:
  replSetName: "rs0"

security:
  authorization: "enabled"
  keyFile: "C:\\Program Files\\MongoDB\\Server\\7.0\\security\\rs0-keyfile"
```

### Step 4: Restart MongoDB Service & Initiate Replica Set
Restart the Windows service to apply the configuration changes:

```powershell
Restart-Service MongoDB
```

Initiate the replica set using the admin credentials:
```powershell
node -e "const { MongoClient } = require('mongodb'); const client = new MongoClient('mongodb://root_admin:<ADMIN_PASSWORD>@localhost:27017/?authSource=admin&directConnection=true'); client.connect().then(async () => { const res = await client.db('admin').command({ replSetInitiate: {} }); console.log('Replica Set Initiated:', res); await client.close(); });"
```

### Step 5: Pre-Flight Connection Verification (Test Before Switching)
Run the automated least-privilege verification script to verify authentication and RBAC before updating application environment files:

```powershell
node scratch/test_db_auth_verification.js
```

Verify that all checks display `[PASS]` and confirm that `updateOne` on `auditlogs` outputs:
`DENIED as expected (code: 13)`

### Step 6: Update Sentinel AI Backend Configuration
In `backend/.env`, update the database connection variables:

```ini
# Production Authenticated Replica Set with ACID Transactions
MONGO_URI=mongodb://sentinel_app:<STRONG_APP_PASSWORD>@localhost:27017/sentinel-db?replicaSet=rs0&authSource=sentinel-db
MONGO_USE_TRANSACTIONS=true
```

### Step 7: Restart Application & Run Full Test Suite
1. Restart the backend API server.
2. Run backend validation tests:
   ```powershell
   npm test -- transactionSupport.test.js
   ```
3. Verify health status in browser: `http://localhost:5000/api/health`

---

## 4. Emergency Rollback Runbook

If any issue arises during or after upgrade, perform the following rollback procedure to return immediately to the safe baseline state:

### Step R1: Revert `backend/.env`
Restore backend configuration to unauthenticated standalone mode:
```ini
MONGO_URI=mongodb://localhost:27017/sentinel-db
MONGO_USE_TRANSACTIONS=false
```

### Step R2: Revert `mongod.cfg`
Open `C:\Program Files\MongoDB\Server\7.0\bin\mongod.cfg` and comment out or remove the added blocks:
```yaml
# replication:
#   replSetName: "rs0"
# security:
#   authorization: "enabled"
#   keyFile: ...
```

### Step R3: Restart MongoDB Service
```powershell
Restart-Service MongoDB
```

### Step R4: Restore Database (If Data Corruption Occurred)
If data integrity was compromised during tests, restore from the baseline backup:
```powershell
mongorestore --drop --db sentinel-db backups/pre-db-fixes-<timestamp>/sentinel-db
```

### Step R5: Verify Rollback
Confirm the 202-document baseline:
```powershell
node -e "const m = require('mongoose'); m.connect('mongodb://localhost:27017/sentinel-db').then(async () => { const c = await Promise.all(Object.values(m.connection.collections).map(col => col.countDocuments())); console.log('Restored Total Docs:', c.reduce((a,b)=>a+b, 0)); process.exit(0); });"
```
