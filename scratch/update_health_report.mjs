import fs from 'fs';

let content = fs.readFileSync('docs/DATABASE_HEALTH_REPORT.md', 'utf8');

// 1. Check 3 updates
content = content.replace(
  `- \`alerts\`: Queries filtering by \`{ isRead: false }\` have no supporting index because \`isRead\` is the second field in \`{ severity: 1, isRead: 1 }\`.`,
  `- \`alerts\`: Real notification polling and unread counting execute \`Alert.countDocuments({ targetRoles: role, isRead: false })\` and \`Alert.find({ targetRoles: role, isRead: false }).sort({ createdAt: -1 })\`. Existing index \`{ severity: 1, isRead: 1 }\` cannot support these queries because \`targetRoles\` is not in the index prefix, resulting in a full collection scan (\`COLLSCAN\`). The required index is \`{ targetRoles: 1, isRead: 1, createdAt: -1 }\`.`
);

content = content.replace(
  `- alerts: { isRead: 1 } (causes COLLSCAN in alert bell polling)`,
  `- alerts: { targetRoles: 1, isRead: 1, createdAt: -1 } (causes COLLSCAN in alert bell polling)`
);

// 2. Check 4 Status
content = content.replace(
  `- **Status**: **PASS WITH OBSERVATION (Non-Breaking Orphans)**`,
  `- **Status**: **WARNING (Non-Breaking Orphans)**`
);

// 3. Check 9 text update
const oldCheck9 = `### Check 9: Audit Log Integrity & Immutability Verification
- **Verification Method**: Validated live audit log ordering and verified hook enforcement against an isolated transient test database (\`scratch/check_audit_immutability.mjs\`).
- **Status**: **PASS WITH DEPRECATION NOTE**
- **Findings**:
  1. All 105 live audit logs maintain strict chronological ordering (\`createdAt\`).
  2. Immutability hooks successfully intercept and block \`doc.save()\`, \`updateOne\`, \`updateMany\`, \`findOneAndUpdate\`, \`deleteOne\`, \`deleteMany\`, \`findOneAndDelete\`, \`doc.deleteOne()\`, and \`bulkWrite\`.
  3. **Mongoose 8 Deprecation**: In \`backend/models/AuditLog.js:38\`, \`AuditLogSchema.pre('findOneAndRemove', ...)\` never fires because \`Model.findOneAndRemove\` was completely removed in Mongoose 8.x.`;

const newCheck9 = `### Check 9: Audit Log Integrity & Immutability Verification
- **Verification Method**: Validated live audit log ordering and verified hook enforcement using \`scratch/check_audit_immutability.mjs\`.
- **Status**: **PASS WITH DEPRECATION NOTE**
- **Findings**:
  1. All 105 live audit logs maintain strict chronological ordering (\`createdAt\`).
  2. Immutability hooks successfully intercept and block \`doc.save()\`, \`updateOne\`, \`updateMany\`, \`findOneAndUpdate\`, \`deleteOne\`, \`deleteMany\`, \`findOneAndDelete\`, \`doc.deleteOne()\`, and \`bulkWrite\`.
  3. **Schema Isolation Verification**: \`scratch/check_audit_immutability.mjs\` imported the **REAL** AuditLog schema directly from \`backend/models/AuditLog.js:5-50\` bound to a transient test database. Live unit tests in \`backend/tests/\` (such as \`shapeAndAudit.test.js\` and \`roleMatrix.test.js\`) mock the \`AuditLog\` model with jest (\`jest.mock('../models/AuditLog')\`); no backend test suite currently runs immutability assertion tests against a live MongoDB connection or against the real schema directly.
  4. **Mongoose 8 Deprecation**: In \`backend/models/AuditLog.js:38\`, \`AuditLogSchema.pre('findOneAndRemove', ...)\` never fires because \`Model.findOneAndRemove\` was completely removed in Mongoose 8.x.`;

content = content.replace(oldCheck9, newCheck9);

// 4. Check 10 Explain table update
const oldCheck10 = `| # | Query Description | Real Filter / Pipeline | Winning Plan | Index Used | Total Keys Examined | Total Docs Examined | Docs Returned | Execution Time | Evaluation |
| :-: | :--- | :--- | :---: | :---: | :-: | :-: | :-: | :-: | :--- |
| 1 | Threat List Filter | \`{ severity: 'HIGH', status: 'MONITORING' }, sort: { createdAt: -1 }\` | \`SORT\` | None (in-memory sort) | 0 | 0 | 0 | 25 ms | In-memory sort stage required |
| 2 | Threat by Source IP | \`{ sourceIP: '172.18.0.1' }, sort: { createdAt: -1 }\` | \`FETCH\` | \`sourceIP_1_createdAt_-1\` | 1 | 1 | 1 | 0 ms | **Optimal index scan** |
| 3 | Dashboard Severity Group | Aggregation: \`$group: { _id: '$severity', count: { $sum: 1 } }\` | \`PROJECTION_SIMPLE\` | None | 0 | 10 | 10 | 41 ms | **COLLSCAN** (no \`$match\` filter) |
| 4 | Dashboard 24h Trend | Aggregation: \`$match: { createdAt: { $gte: ... } }, $group\` | \`PROJECTION_SIMPLE\` | None | 0 | 0 | 0 | 5 ms | Pipeline scan (not covered) |
| 5 | Honeypot Session Filter | \`{ honeypotNode: 'SSH-COWRIE-01', status: 'active' }, sort: { createdAt: -1 }\` | \`SORT\` | None (in-memory sort) | 0 | 0 | 0 | 2 ms | In-memory sort stage required |
| 6 | Alert Unread Count | \`{ isRead: false }\` | \`COLLSCAN\` | None | 0 | 5 | 3 | 0 ms | **COLLSCAN** (missing index on \`isRead\`) |
| 7 | Session Lookup (\`protect\`) | \`{ _id: 'ea23a31a-cb25-...' }\` | \`IDHACK\` | \`_id_\` | 1 | 1 | 1 | 1 ms | **Optimal clustered index lookup** |
| 8 | User Lookup (\`protect\`) | \`{ _id: ObjectId('6a9fc315...') }\` | \`IDHACK\` | \`_id_\` | 1 | 1 | 1 | 0 ms | **Optimal clustered index lookup** |
| 9 | Audit Log Pagination | \`{ action: 'LOGIN_SUCCESS' }, sort: { createdAt: -1 }, limit: 50\` | \`LIMIT\` | \`action_1_createdAt_-1\` | 50 | 50 | 50 | 3 ms | **Optimal indexed pagination scan** |
| 10 | Blocked IP Check | \`{ ip: '198.51.100.88' }\` | \`FETCH\` | \`ip_1\` | 0 | 0 | 0 | 0 ms | **Optimal index scan** |`;

const newCheck10 = `| # | Query Description | Real Filter / Pipeline | Winning Plan / Stage Chain | Index Used | Total Keys Examined | Total Docs Examined | Docs Returned | Execution Time | Evaluation |
| :-: | :--- | :--- | :---: | :---: | :-: | :-: | :-: | :-: | :--- |
| 1 | Threat List Filter | \`{ severity: 'HIGH', status: 'MONITORING' }, sort: { createdAt: -1 }\` | \`SORT -> FETCH -> IXSCAN\` | \`severity_1_status_1\` | 0 | 0 | 0 | 25 ms | Index scan on compound prefix followed by in-memory sort on \`createdAt\` |
| 2 | Threat by Source IP | \`{ sourceIP: '172.18.0.1' }, sort: { createdAt: -1 }\` | \`FETCH -> IXSCAN\` | \`sourceIP_1_createdAt_-1\` | 1 | 1 | 1 | 0 ms | Index scan matches both filter and sort order |
| 3 | Dashboard Severity Group | Aggregation: \`$group: { _id: '$severity', count: { $sum: 1 } }\` | \`PROJECTION_SIMPLE -> COLLSCAN\` | None | 0 | 10 | 10 | 41 ms | Collection scan required to aggregate entire collection without match filter |
| 4 | Dashboard 7-Day Trend | Aggregation: \`$match: { createdAt: { $gte: ISODate('2026-10-11T...') } }, $group\` | \`PROJECTION_SIMPLE -> FETCH -> IXSCAN\` | \`createdAt_-1\` | 10 | 10 | 10 | 1 ms | Index scan on \`createdAt\` bounds query window before aggregation |
| 5 | Honeypot Session Filter | \`{ honeypotNode: 'SSH-COWRIE-01', status: 'active' }, sort: { createdAt: -1 }\` | \`SORT -> FETCH -> IXSCAN\` | \`status_1\` | 8 | 8 | 8 | 2 ms | Index scan on \`status\` followed by in-memory sort on \`createdAt\` |
| 6 | Alert Unread Count | \`{ targetRoles: 'analyst', isRead: false }, sort: { createdAt: -1 }\` | \`SORT -> COLLSCAN\` | None | 0 | 5 | 3 | 0 ms | Collection scan; existing \`{ severity: 1, isRead: 1 }\` cannot index \`targetRoles\` |
| 7 | Session Lookup (\`protect\`) | \`{ _id: 'ea23a31a-cb25-...' }\` | \`IDHACK\` | \`_id_\` | 1 | 1 | 1 | 1 ms | Clustered primary key lookup |
| 8 | User Lookup (\`protect\`) | \`{ _id: ObjectId('6a9fc315...') }\` | \`IDHACK\` | \`_id_\` | 1 | 1 | 1 | 0 ms | Clustered primary key lookup |
| 9 | Audit Log Pagination | \`{ action: 'LOGIN_SUCCESS' }, sort: { createdAt: -1 }, limit: 50\` | \`LIMIT -> FETCH -> IXSCAN\` | \`action_1_createdAt_-1\` | 50 | 50 | 50 | 3 ms | Compound index scan satisfying filter, sort, and limit (\`docsExamined > 0\`) |
| 10 | Blocked IP Check | \`{ ip: '198.51.100.88' }\` | \`FETCH -> IXSCAN\` | \`ip_1\` | 0 | 0 | 0 | 0 ms | Index scan on unique IP field |

> [!NOTE]
> **Performance & Timing Note**: With only 202 total documents in \`sentinel-db\`, execution times (0ms to 41ms) reflect Node.js/V8 driver initialization overhead rather than database disk/index contention. However, at scale (100k+ records), unindexed operations (Queries 3 and 6) and in-memory sort operations (Queries 1 and 5) degrade severely.`;

content = content.replace(oldCheck10, newCheck10);

// 5. Check 11 label update
content = content.replace(
  `1. \`172.18.0.1\` (\`6aa3a28b3e9adbbeb9e3996f\`): **Real Cowrie Traffic**. Forwarded via Docker bridge network to honeypot session \`9b21e8e00dd7\` (which logged 3,383 credential attempts).`,
  `1. \`172.18.0.1\` (\`6aa3a28b3e9adbbeb9e3996f\`): **Locally Generated / Lab Traffic**. Forwarded via Docker bridge gateway (\`172.18.0.1\`) to honeypot session \`9b21e8e00dd7\` (which logged 3,383 automated credential attempts).`
);

// 6. Issues Register updates
content = content.replace(
  `| **ISS-04** | Missing Index on \`Alert.isRead\` (COLLSCAN on Polling) | **Medium** | \`alerts\` | Query: \`scratch/run_real_explain.mjs\`<br>\`Alert.find({ isRead: false })\` executes full \`COLLSCAN\` | Frontend bell notification polling scans the entire alerts collection on every cycle, causing CPU overhead at scale. | Low (Demo) / High (Prod) | **VERIFIED** |`,
  `| **ISS-04** | Missing Compound Index on \`Alert.targetRoles\` & \`isRead\` | **Medium** | \`alerts\` | \`Alert.countDocuments({ targetRoles: role, isRead: false })\`<br>\`Alert.find({ targetRoles: role, isRead: false })\` | Bell polling and unread counting execute full collection scans (\`COLLSCAN\`) because existing index \`{ severity: 1, isRead: 1 }\` lacks \`targetRoles\` prefix. | Low (Demo) / High (Prod) | **VERIFIED** |`
);

content = content.replace(
  `| **ISS-09** | Role-Gated Honeypot Credential Access (Masked at Live Ingest) | **Low** | \`backend/routes/honeypotIngest.js:118-125\` | \`data.credentials.map(c => ({ ...c, password: '***REDACTED***' }))\` | Passwords in live ingest are redacted before storage; sample passwords in DB are from static demo fixtures. | Low (Demo) / Low (Prod) | **VERIFIED** |`,
  `| **ISS-09** | Historical Plaintext Passwords in Honeypot Credential Telemetry | **Medium** | \`honeypotsessions\`, \`session_collector.js:13\`, \`honeypotService.js:114\`, \`seed.js:127\` | 3,397 plaintext passwords stored in DB across 8 sessions (3,383 in \`9b21e8e00dd7\`, 14 in demo fixtures) | Attacker passwords stored in plaintext at rest. Ingest route (\`honeypotIngest.js:118-125\`) redacts passwords, but \`session_collector.js\`, \`honeypotService.js\`, and \`seed.js\` store raw credentials. | Low (Demo) / High (Prod) | **VERIFIED** |`
);

// 7. Roadmap QW-1 & QW-3 & QW-4
const oldQW1 = `#### QW-1: Add Missing Indexes on \`Alert\` and Foreign Key Paths
- **Files**: \`backend/models/Alert.js\`, \`backend/models/HoneypotSession.js\`, \`backend/models/AuditLog.js\`
- **Change**: Add dedicated single-field and compound indexes:
  \`\`\`javascript
  // Alert.js
  AlertSchema.index({ isRead: 1 });
  AlertSchema.index({ "sourceRef.refId": 1 });
  
  // HoneypotSession.js
  HoneypotSessionSchema.index({ linkedThreatLog: 1 });
  
  // AuditLog.js
  AuditLogSchema.index({ "target.id": 1 });
  \`\`\`
- **Effort**: S (15 mins) | **Risk**: Very Low | **Priority**: P1`;

const newQW1 = `#### QW-1: Add Missing Compound Index on \`Alert\` and Foreign Key Paths
- **Files**: \`backend/models/Alert.js\`, \`backend/models/HoneypotSession.js\`, \`backend/models/AuditLog.js\`
- **Change**: Add dedicated compound and reference indexes:
  \`\`\`javascript
  // Alert.js - supports alert polling and unread counting
  AlertSchema.index({ targetRoles: 1, isRead: 1, createdAt: -1 });
  AlertSchema.index({ "sourceRef.refId": 1 });
  
  // HoneypotSession.js
  HoneypotSessionSchema.index({ linkedThreatLog: 1 });
  
  // AuditLog.js
  AuditLogSchema.index({ "target.id": 1 });
  \`\`\`
- **Effort**: S (15 mins) | **Risk**: Very Low | **Priority**: P1`;

content = content.replace(oldQW1, newQW1);

const oldQW3 = `#### QW-3: Remove Redundant Duplicate Indexes
- **Files**: \`backend/models/ThreatLog.js\`, \`backend/models/Alert.js\`, \`backend/models/AuditLog.js\`
- **Change**: Remove \`{ severity: 1 }\` from ThreatLog and Alert (covered by \`{ severity: 1, status: 1 }\` and \`{ severity: 1, isRead: 1 }\`). Remove \`{ action: 1 }\` from AuditLog (covered by \`{ action: 1, createdAt: -1 }\`).
- **Effort**: S (20 mins) | **Risk**: Very Low | **Priority**: P2`;

const newQW3 = `#### QW-3: Remove Redundant Duplicate Indexes
- **Files**: \`backend/models/ThreatLog.js\`, \`backend/models/Alert.js\`, \`backend/models/AuditLog.js\`
- **Change**: Remove \`{ severity: 1 }\` from ThreatLog and Alert (covered by \`{ severity: 1, status: 1 }\` and \`{ severity: 1, isRead: 1 }\`). Remove \`{ action: 1 }\` from AuditLog (covered by \`{ action: 1, createdAt: -1 }\`).
> [!IMPORTANT]
> **Operational Warning**: Removing an index definition from a Mongoose schema file does **NOT** drop the index from the live MongoDB database. Dropping is a separate operational step using \`db.collection.dropIndex("index_name")\`. Never run \`Model.syncIndexes()\` blindly in production as it can drop unmanaged operational indexes and lock collections during build.
- **Effort**: S (20 mins) | **Risk**: Very Low | **Priority**: P2`;

content = content.replace(oldQW3, newQW3);

// 8. Viva Questions
const oldViva = `#### 6. Why does \`Alert.find({ isRead: false })\` cause a collection scan (COLLSCAN) in MongoDB?
**Answer**: Because the compound index is declared as \`{ severity: 1, isRead: 1 }\`. Under MongoDB B-Tree index rules, an index can only be used if the query includes the leading prefix field (\`severity\`). Without \`severity\`, MongoDB must scan every document in the collection.

#### 7. How does the TTL (Time-To-Live) index work on the \`authsessions\` collection?
**Answer**: \`AuthSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })\`. MongoDB's background TTL thread scans the index once every 60 seconds and automatically deletes documents where \`expiresAt <= currentDate\`.

#### 8. Why are there orphaned alerts in the database, and how does the application handle them?
**Answer**: Two alerts reference a threat log deleted during testing. The backend query (\`alertService.findAlerts\`) does not populate \`sourceRef\`, and the frontend (\`AlertBell.jsx\`) renders only title, message, and severity. Furthermore, \`Alert.expiresAt\` has a 7-day TTL index, so orphaned alerts purge automatically without application crashes.

#### 9. What is the difference between \`authVersion\` and \`tokenVersion\` in the \`User\` schema?
**Answer**: Both are schema fields in \`User.js:13-14\`. \`authVersion\` is the active security version checked by \`protect\` middleware. \`tokenVersion\` is a compatibility field synchronized via \`User.pre('save')\` (\`tokenVersion = authVersion\`). Seed user \`admin@sentinel.local\` lacked \`tokenVersion\` because it was inserted directly without triggering Mongoose save hooks.

#### 10. Why is \`pre('findOneAndRemove')\` in \`AuditLog.js\` considered dead code?
**Answer**: SentinelAI runs Mongoose \`8.24.2\`. In Mongoose 8.x, \`Model.findOneAndRemove\` was completely deprecated and removed from the API in favor of \`Model.findOneAndDelete\`. Therefore, the hook never fires.

#### 11. What is the performance impact of storing raw honeypot credentials and payloads?
**Answer**: Live Cowrie ingest redacts passwords before storage (\`honeypotIngest.js:118-125\`). However, storing large arrays of commands and URLs causes document growth, which can trigger in-place document moves in WiredTiger and increase RAM working set size.`;

const newViva = `#### 6. Why does alert notification polling cause a collection scan (COLLSCAN) in MongoDB?
**Answer**: The real query executed during polling is \`Alert.countDocuments({ targetRoles: role, isRead: false })\`. The existing compound index is \`{ severity: 1, isRead: 1 }\`. Under B-Tree prefix rules, MongoDB cannot use an index that does not lead with the queried fields, forcing a full collection scan. A compound index on \`{ targetRoles: 1, isRead: 1, createdAt: -1 }\` is required.

#### 7. How does the TTL (Time-To-Live) index work on the \`authsessions\` collection?
**Answer**: \`AuthSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })\`. MongoDB's background TTL thread scans the index once every 60 seconds and automatically deletes documents where \`expiresAt <= currentDate\`.

#### 8. Why are there orphaned alerts in the database, and how does the application handle them?
**Answer**: Two alerts reference a threat log deleted during testing. The backend query (\`alertService.findAlerts\`) does not populate \`sourceRef\`, and the frontend (\`AlertBell.jsx\`) renders only title, message, and severity. Furthermore, \`Alert.expiresAt\` has a 7-day TTL index, so orphaned alerts purge automatically without application crashes.

#### 9. Why is \`tokenVersion\` missing on \`admin@sentinel.local\`?
**Answer**: In git commit \`5ea705144f\`, \`UserSchema\` only defined \`authVersion\`. \`tokenVersion\` was added subsequently. Because MongoDB is a schema-less document store, adding a field with a default to a Mongoose schema does **not** retroactively backfill existing documents on disk; it only initializes on new document saves.

#### 10. Why is \`pre('findOneAndRemove')\` in \`AuditLog.js\` considered dead code?
**Answer**: SentinelAI runs Mongoose \`8.24.2\`. In Mongoose 8.x, \`Model.findOneAndRemove\` was completely deprecated and removed from the API in favor of \`Model.findOneAndDelete\`. Therefore, the hook never fires.

#### 11. What is the performance impact of storing growing honeypot command arrays?
**Answer**: In WiredTiger, updates to growing arrays require rewriting the entire uncompressed BSON document in memory and writing it out to data pages. If a session records thousands of commands, it increases cache dirty pages and risks hitting MongoDB's hard **16 MB BSON document limit**.`;

content = content.replace(oldViva, newViva);

// Check if any absolute paths or file:// remain
const badPaths = content.match(/C:\\Users|file:\/\//g);
if (badPaths) {
  console.log('WARNING: Found bad paths in content:', badPaths);
}

fs.writeFileSync('docs/DATABASE_HEALTH_REPORT.md', content, 'utf8');
console.log('Successfully updated docs/DATABASE_HEALTH_REPORT.md');
