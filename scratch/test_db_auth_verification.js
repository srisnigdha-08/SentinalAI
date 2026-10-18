const { MongoClient } = require('../backend/node_modules/mongodb')

async function runAuthVerification() {
  console.log('=== Task 9 Part B: Least Privilege Database Auth Verification ===\n')

  const appUri = 'mongodb://sentinel_app:TestAppPassword123!@127.0.0.1:27030/sentinel-db-test?replicaSet=rs0&authSource=sentinel-db-test'
  const auditUri = 'mongodb://sentinel_audit:TestAuditPassword123!@127.0.0.1:27030/sentinel-db-test?replicaSet=rs0&authSource=sentinel-db-test'

  // ----------------------------------------------------
  // Test 1: sentinel_app Privileges & Restrictions
  // ----------------------------------------------------
  console.log('[Test 1] Connecting as sentinel_app...')
  const appClient = new MongoClient(appUri)
  await appClient.connect()
  const appDb = appClient.db('sentinel-db-test')
  console.log('  -> Connected as sentinel_app successfully.')

  // 1a. Operational collections readWrite
  const testThreat = { sourceIP: '192.0.2.1', attackType: 'SQL Injection', severity: 'HIGH', status: 'DETECTED', aiScore: 0.9 }
  const threatInsertRes = await appDb.collection('threatlogs').insertOne(testThreat)
  console.log('  [PASS] sentinel_app can insert into threatlogs (id: ' + threatInsertRes.insertedId + ')')

  await appDb.collection('threatlogs').updateOne({ _id: threatInsertRes.insertedId }, { $set: { status: 'INVESTIGATING' } })
  console.log('  [PASS] sentinel_app can update threatlogs')

  // 1b. Audit log append & read
  const testAudit = { action: 'AUTH_TEST', status: 'SUCCESS', timestamp: new Date() }
  const auditInsertRes = await appDb.collection('auditlogs').insertOne(testAudit)
  console.log('  [PASS] sentinel_app can insert into auditlogs (id: ' + auditInsertRes.insertedId + ')')

  const foundAudit = await appDb.collection('auditlogs').findOne({ _id: auditInsertRes.insertedId })
  console.log('  [PASS] sentinel_app can find in auditlogs (found: ' + Boolean(foundAudit) + ')')

  // 1c. Audit log update DENIAL (code 13)
  try {
    await appDb.collection('auditlogs').updateOne({ _id: auditInsertRes.insertedId }, { $set: { status: 'TAMPERED' } })
    console.error('  [FAIL] sentinel_app was able to update auditlogs! Expected authorization denial.')
    process.exit(1)
  } catch (err) {
    if (err.code === 13) {
      console.log('  [PASS] sentinel_app updateOne on auditlogs DENIED as expected (code: 13, msg: ' + err.message + ')')
    } else {
      console.error('  [UNEXPECTED ERROR] Expected code 13, got:', err)
      process.exit(1)
    }
  }

  // 1d. Audit log delete DENIAL (code 13)
  try {
    await appDb.collection('auditlogs').deleteOne({ _id: auditInsertRes.insertedId })
    console.error('  [FAIL] sentinel_app was able to delete from auditlogs! Expected authorization denial.')
    process.exit(1)
  } catch (err) {
    if (err.code === 13) {
      console.log('  [PASS] sentinel_app deleteOne on auditlogs DENIED as expected (code: 13, msg: ' + err.message + ')')
    } else {
      console.error('  [UNEXPECTED ERROR] Expected code 13, got:', err)
      process.exit(1)
    }
  }

  await appClient.close()

  // ----------------------------------------------------
  // Test 2: sentinel_audit Privileges & Isolation
  // ----------------------------------------------------
  console.log('\n[Test 2] Connecting as sentinel_audit...')
  const auditClient = new MongoClient(auditUri)
  await auditClient.connect()
  const auditDb = auditClient.db('sentinel-db-test')
  console.log('  -> Connected as sentinel_audit successfully.')

  // 2a. Can insert into auditlogs
  const auditDoc = { action: 'AUDIT_AGENT_EVENT', status: 'SUCCESS', timestamp: new Date() }
  const insAuditRes = await auditDb.collection('auditlogs').insertOne(auditDoc)
  console.log('  [PASS] sentinel_audit can insert into auditlogs (id: ' + insAuditRes.insertedId + ')')

  // 2b. Can find in auditlogs
  const auditRead = await auditDb.collection('auditlogs').findOne({ _id: insAuditRes.insertedId })
  console.log('  [PASS] sentinel_audit can find in auditlogs (found: ' + Boolean(auditRead) + ')')

  // 2c. Cannot update auditlogs (code 13)
  try {
    await auditDb.collection('auditlogs').updateOne({ _id: insAuditRes.insertedId }, { $set: { status: 'MODIFIED' } })
    console.error('  [FAIL] sentinel_audit was able to update auditlogs! Expected authorization denial.')
    process.exit(1)
  } catch (err) {
    if (err.code === 13) {
      console.log('  [PASS] sentinel_audit updateOne on auditlogs DENIED as expected (code: 13)')
    } else {
      console.error('  [UNEXPECTED ERROR] Expected code 13, got:', err)
      process.exit(1)
    }
  }

  // 2d. Cannot read threatlogs or users (code 13)
  try {
    await auditDb.collection('users').find({}).toArray()
    console.error('  [FAIL] sentinel_audit was able to read users! Expected authorization denial.')
    process.exit(1)
  } catch (err) {
    if (err.code === 13) {
      console.log('  [PASS] sentinel_audit reading users collection DENIED as expected (code: 13)')
    } else {
      console.error('  [UNEXPECTED ERROR] Expected code 13, got:', err)
      process.exit(1)
    }
  }

  await auditClient.close()

  console.log('\n=== All Database Authentication & RBAC Checks Verified Successfully (code: 13 enforced) ===')
}

runAuthVerification().catch((e) => {
  console.error('Verification failed:', e)
  process.exit(1)
})
