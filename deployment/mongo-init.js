/**
 * deployment/mongo-init.js
 *
 * Automated MongoDB Initialization & Least-Privilege RBAC Setup for Sentinel AI
 *
 * Implements Engine-Level Authorization Controls:
 * - ISS-06: Database-level authentication and access control.
 * - ISS-07: Least-privilege separation between general application workloads and audit logging.
 * - ISS-08: Append-only audit logs enforced at the database engine layer (code 13 on update/delete).
 *
 * ROLES & USERS CREATED:
 * 1. sentinel_app_role:
 *    - Full read/write on operational collections: users, threatlogs, blockedips, alerts,
 *      honeypotsessions, containmentactions, systemsettings, authsessions, aipredictions,
 *      backups, archive_threatlogs, archive_honeypotsessions.
 *    - Strict Read + Insert ONLY on 'auditlogs'. Updates and Deletes are DENIED at the DB engine layer.
 * 2. sentinel_audit_role:
 *    - Read + Insert ONLY on 'auditlogs'. Zero access to business collections.
 * 3. sentinel_app (User):
 *    - Assigned sentinel_app_role. Used by backend API server.
 * 4. sentinel_audit (User):
 *    - Assigned sentinel_audit_role. Used by dedicated audit ingestion or archival workers.
 *
 * USAGE:
 * - Docker: Mounted into /docker-entrypoint-initdb.d/mongo-init.js
 * - Standalone/Replica mongosh: mongosh --port 27017 -u admin -p <admin-pwd> < deployment/mongo-init.js
 *
 * SECURITY NOTICE:
 * NO REAL PASSWORDS ARE STORED IN THIS FILE.
 * Always supply strong secrets via environment variables or replace placeholder strings before execution.
 */

/* global db */

const targetDbName = 'sentinel-db';
const appDb = db.getSiblingDB(targetDbName);

const APP_USER_PASSWORD = (typeof process !== 'undefined' && process.env && process.env.SENTINEL_APP_PASSWORD)
  ? process.env.SENTINEL_APP_PASSWORD
  : 'CHANGE_ME_SENTINEL_APP_PASSWORD';

const AUDIT_USER_PASSWORD = (typeof process !== 'undefined' && process.env && process.env.SENTINEL_AUDIT_PASSWORD)
  ? process.env.SENTINEL_AUDIT_PASSWORD
  : 'CHANGE_ME_SENTINEL_AUDIT_PASSWORD';

print(`[mongo-init] Configuring least-privilege security roles on database '${targetDbName}'...`);

// Collections requiring read-write operational access
const operationalCollections = [
  'threatlogs',
  'blockedips',
  'alerts',
  'honeypotsessions',
  'containmentactions',
  'systemsettings',
  'authsessions',
  'aipredictions',
  'users',
  'campaigns',
  'trainingsamples',
  'outboxevents',
  'backups',
  // retentionService writes archived_* (the older archive_* names are kept for existing deployments)
  'archived_threatlogs',
  'archived_honeypotsessions',
  'archived_alerts',
  'archive_threatlogs',
  'archive_honeypotsessions',
  'reports'
];

// Define privileges for sentinel_app_role
const sentinelAppPrivileges = [
  // 1. Read access on all collections in sentinel-db, plus index management: Mongoose builds each model's
  //    indexes (unique, TTL) at startup and fails without these.
  {
    resource: { db: targetDbName, collection: '' },
    actions: ['find', 'listIndexes', 'createIndex', 'listCollections', 'createCollection']
  },
  // 2. Strict append-only privilege for auditlogs: INSERT only (no update, no remove)
  {
    resource: { db: targetDbName, collection: 'auditlogs' },
    actions: ['insert']
  },
  // 3. Full operational write privileges on application domain collections
  ...operationalCollections.map(col => ({
    resource: { db: targetDbName, collection: col },
    actions: ['insert', 'update', 'remove']
  }))
];

// Create or update sentinel_app_role
try {
  appDb.createRole({
    role: 'sentinel_app_role',
    privileges: sentinelAppPrivileges,
    roles: []
  });
  print(`[mongo-init] Created role 'sentinel_app_role'.`);
} catch (e) {
  if (e.code === 51002 || (e.message && e.message.includes('already exists'))) {
    appDb.updateRole('sentinel_app_role', {
      privileges: sentinelAppPrivileges,
      roles: []
    });
    print(`[mongo-init] Updated existing role 'sentinel_app_role'.`);
  } else {
    throw e;
  }
}

// Define privileges for sentinel_audit_role
const sentinelAuditPrivileges = [
  {
    resource: { db: targetDbName, collection: 'auditlogs' },
    actions: ['find', 'insert']
  }
];

// Create or update sentinel_audit_role
try {
  appDb.createRole({
    role: 'sentinel_audit_role',
    privileges: sentinelAuditPrivileges,
    roles: []
  });
  print(`[mongo-init] Created role 'sentinel_audit_role'.`);
} catch (e) {
  if (e.code === 51002 || (e.message && e.message.includes('already exists'))) {
    appDb.updateRole('sentinel_audit_role', {
      privileges: sentinelAuditPrivileges,
      roles: []
    });
    print(`[mongo-init] Updated existing role 'sentinel_audit_role'.`);
  } else {
    throw e;
  }
}

// Create or update sentinel_app user
try {
  appDb.createUser({
    user: 'sentinel_app',
    pwd: APP_USER_PASSWORD,
    roles: [
      { role: 'sentinel_app_role', db: targetDbName }
    ]
  });
  print(`[mongo-init] Created user 'sentinel_app'.`);
} catch (e) {
  if (e.code === 51003 || (e.message && e.message.includes('already exists'))) {
    appDb.updateUser('sentinel_app', {
      pwd: APP_USER_PASSWORD,
      roles: [
        { role: 'sentinel_app_role', db: targetDbName }
      ]
    });
    print(`[mongo-init] Updated user 'sentinel_app'.`);
  } else {
    throw e;
  }
}

// Create or update sentinel_audit user
try {
  appDb.createUser({
    user: 'sentinel_audit',
    pwd: AUDIT_USER_PASSWORD,
    roles: [
      { role: 'sentinel_audit_role', db: targetDbName }
    ]
  });
  print(`[mongo-init] Created user 'sentinel_audit'.`);
} catch (e) {
  if (e.code === 51003 || (e.message && e.message.includes('already exists'))) {
    appDb.updateUser('sentinel_audit', {
      pwd: AUDIT_USER_PASSWORD,
      roles: [
        { role: 'sentinel_audit_role', db: targetDbName }
      ]
    });
    print(`[mongo-init] Updated user 'sentinel_audit'.`);
  } else {
    throw e;
  }
}

print(`[mongo-init] Least-privilege database authentication configuration complete.`);
