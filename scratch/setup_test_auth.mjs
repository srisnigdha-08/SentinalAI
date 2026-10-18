import { MongoClient } from 'mongodb'

const URI = 'mongodb://127.0.0.1:27030/?directConnection=true'
const client = new MongoClient(URI)

async function setup() {
  await client.connect()
  console.log('Connected to mongod on port 27030')

  const adminDb = client.db('admin')
  const testDb = client.db('sentinel-db-test')

  // 1. Create root admin user if not exists
  try {
    await adminDb.command({
      createUser: 'root_admin',
      pwd: 'TestAdminPassword123!',
      roles: [{ role: 'root', db: 'admin' }],
    })
    console.log('Created root_admin user on admin db')
  } catch (err) {
    if (err.code === 51003 || err.message.includes('already exists')) {
      console.log('root_admin already exists')
    } else {
      console.error('Error creating root_admin:', err.message)
    }
  }

  // 2. Create custom roles on sentinel-db-test
  const targetDb = 'sentinel-db-test'
  const collections = [
    'threatlogs',
    'blockedips',
    'alerts',
    'honeypotsessions',
    'containmentactions',
    'systemsettings',
    'authsessions',
    'aipredictions',
    'users',
    'backups',
    'archive_threatlogs',
    'archive_honeypotsessions',
  ]

  const sentinelAppPrivileges = [
    {
      resource: { db: targetDb, collection: '' },
      actions: ['find'],
    },
    {
      resource: { db: targetDb, collection: 'auditlogs' },
      actions: ['insert'],
    },
    ...collections.map((col) => ({
      resource: { db: targetDb, collection: col },
      actions: ['insert', 'update', 'remove'],
    })),
  ]

  try {
    await testDb.command({
      createRole: 'sentinel_app_role',
      privileges: sentinelAppPrivileges,
      roles: [],
    })
    console.log('Created sentinel_app_role on sentinel-db-test')
  } catch (err) {
    if (err.code === 51002 || err.message.includes('already exists')) {
      console.log('sentinel_app_role already exists, updating...')
      await testDb.command({
        updateRole: 'sentinel_app_role',
        privileges: sentinelAppPrivileges,
        roles: [],
      })
      console.log('Updated sentinel_app_role')
    } else {
      console.error('Error creating sentinel_app_role:', err.message)
    }
  }

  const sentinelAuditPrivileges = [
    {
      resource: { db: targetDb, collection: 'auditlogs' },
      actions: ['find', 'insert'],
    },
  ]

  try {
    await testDb.command({
      createRole: 'sentinel_audit_role',
      privileges: sentinelAuditPrivileges,
      roles: [],
    })
    console.log('Created sentinel_audit_role on sentinel-db-test')
  } catch (err) {
    if (err.code === 51002 || err.message.includes('already exists')) {
      console.log('sentinel_audit_role already exists, updating...')
      await testDb.command({
        updateRole: 'sentinel_audit_role',
        privileges: sentinelAuditPrivileges,
        roles: [],
      })
      console.log('Updated sentinel_audit_role')
    } else {
      console.error('Error creating sentinel_audit_role:', err.message)
    }
  }

  // 3. Create users sentinel_app and sentinel_audit on sentinel-db-test
  try {
    await testDb.command({
      createUser: 'sentinel_app',
      pwd: 'TestAppPassword123!',
      roles: [{ role: 'sentinel_app_role', db: targetDb }],
    })
    console.log('Created sentinel_app user on sentinel-db-test')
  } catch (err) {
    if (err.code === 51003 || err.message.includes('already exists')) {
      console.log('sentinel_app user already exists')
    } else {
      console.error('Error creating sentinel_app user:', err.message)
    }
  }

  try {
    await testDb.command({
      createUser: 'sentinel_audit',
      pwd: 'TestAuditPassword123!',
      roles: [{ role: 'sentinel_audit_role', db: targetDb }],
    })
    console.log('Created sentinel_audit user on sentinel-db-test')
  } catch (err) {
    if (err.code === 51003 || err.message.includes('already exists')) {
      console.log('sentinel_audit user already exists')
    } else {
      console.error('Error creating sentinel_audit user:', err.message)
    }
  }

  await client.close()
  console.log('Setup completed successfully')
}

setup().catch((e) => {
  console.error('Setup failed:', e)
  process.exit(1)
})
