'use strict'

/**
 * tests/retentionPolicy.test.js
 *
 * Task 8: Data Retention Policy & Archival Test Suite
 *
 * Requirements Verified:
 * 1. Disabled by default: nothing is deleted when disabled unless explicitly forced.
 * 2. Dry-run simulation: counts match real apply counts exactly; zero mutations during dry-run.
 * 3. Exclusions: AuditLog records and demo-* sessions / threats are NEVER deleted.
 * 4. Archival: records are safely written to archived_* collections before deletion.
 * 5. Dependent cascading: dependent alerts and prediction links cleaned up consistently (Task 6 logic).
 * 6. Audit logging: records RETENTION_RUN audit event.
 * 7. Restoration: archive can be restored back into primary collections cleanly.
 */

const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

const ThreatLog = require('../models/ThreatLog')
const HoneypotSession = require('../models/HoneypotSession')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const AuditLog = require('../models/AuditLog')
const {
  dryRunRetention,
  applyRetention,
  restoreFromArchive,
} = require('../services/retentionService')

describe('Task 8: Data Retention Policy & Archival Engine', () => {
  let mongoServer
  const HOST_MONGOD_PATH =
    'C:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete.native-integration\\mongodb-acceptance-20261014\\binaries\\mongod.exe'

  beforeAll(async () => {
    // Start isolated in-memory MongoDB using host mongod binary
    mongoServer = await MongoMemoryServer.create({
      binary: {
        systemBinary: HOST_MONGOD_PATH,
      },
    })
    const uri = mongoServer.getUri()
    await mongoose.connect(uri)
  }, 30000)

  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) {
      await mongoServer.stop()
    }
  })

  beforeEach(async () => {
    // Clear collections before each test
    await ThreatLog.deleteMany({})
    await HoneypotSession.deleteMany({})
    await Alert.deleteMany({})
    await AIPrediction.deleteMany({})
    // Direct native drop for archive collections and auditlogs to bypass Mongoose immutability hook
    const db = mongoose.connection.db
    await db.collection('auditlogs').deleteMany({})
    await db.collection('archived_threatlogs').deleteMany({})
    await db.collection('archived_honeypotsessions').deleteMany({})
    await db.collection('archived_alerts').deleteMany({})
  })

  async function seedTestData() {
    const now = new Date()
    const days120Ago = new Date(now.getTime() - 120 * 86400000)
    const days10Ago = new Date(now.getTime() - 10 * 86400000)

    // 1. Old non-demo ThreatLog (ELIGIBLE for retention)
    const oldThreat = await ThreatLog.create({
      sourceIP: '203.0.113.10',
      attackType: 'SSH Brute Force',
      severity: 'HIGH',
      status: 'DETECTED',
      createdAt: days120Ago,
    })

    // 2. Recent ThreatLog (PROTECTED by age)
    const recentThreat = await ThreatLog.create({
      sourceIP: '203.0.113.20',
      attackType: 'Port Scan',
      severity: 'LOW',
      status: 'DETECTED',
      createdAt: days10Ago,
    })

    // 3. Old Demo ThreatLog linked to demo session (PROTECTED by demo exclusion)
    const demoThreat = await ThreatLog.create({
      sourceIP: '198.51.100.50',
      attackType: 'SQL Injection',
      severity: 'CRITICAL',
      status: 'DETECTED',
      createdAt: days120Ago,
    })

    // 4. Old Demo Seed Threat (PROTECTED by demo IP)
    const seedDemoThreat = await ThreatLog.create({
      sourceIP: '198.51.100.88',
      attackType: 'DDoS',
      severity: 'HIGH',
      status: 'BLOCKED',
      createdAt: days120Ago,
    })

    // 5. Old non-demo HoneypotSession (ELIGIBLE for retention)
    const oldSession = await HoneypotSession.create({
      sessionId: 'cowrie-prod-999',
      sourceIP: '203.0.113.10',
      createdAt: days120Ago,
      startTime: days120Ago,
      linkedThreatLog: oldThreat._id,
    })

    // 6. Old Demo HoneypotSession (PROTECTED by demo- prefix)
    const demoSession = await HoneypotSession.create({
      sessionId: 'demo-777',
      sourceIP: '198.51.100.50',
      createdAt: days120Ago,
      startTime: days120Ago,
      linkedThreatLog: demoThreat._id,
    })

    // 7. Recent HoneypotSession (PROTECTED by age)
    const recentSession = await HoneypotSession.create({
      sessionId: 'cowrie-recent-111',
      sourceIP: '203.0.113.30',
      createdAt: days10Ago,
      startTime: days10Ago,
    })

    // 8. Dependent Alert pointing to oldThreat (ELIGIBLE)
    const alertOnOldThreat = await Alert.create({
      title: 'Alert on Old Threat',
      message: 'Old threat detected',
      severity: 'HIGH',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: oldThreat._id },
      createdAt: days120Ago,
    })

    // 9. Dependent Alert pointing to demoThreat (PROTECTED)
    const alertOnDemoThreat = await Alert.create({
      title: 'Alert on Demo Threat',
      message: 'Demo alert',
      severity: 'CRITICAL',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: demoThreat._id },
      createdAt: days120Ago,
    })

    // 10. Dependent AIPrediction pointing to oldThreat (SHOULD BE UNLINKED)
    const predictionOnOldThreat = await AIPrediction.create({
      inputSource: 'network_traffic',
      predictedClass: 'SSH Brute Force',
      targetIP: '203.0.113.10',
      threatScore: 0.95,
      generatedThreat: oldThreat._id,
      threatId: oldThreat._id,
    })

    // 11. AuditLog record (MUST NEVER BE TOUCHED)
    const db = mongoose.connection.db
    await db.collection('auditlogs').insertOne({
      action: 'USER_LOGIN',
      eventType: 'AUTH_EVENT',
      status: 'SUCCESS',
      createdAt: days120Ago,
    })

    return {
      oldThreat,
      recentThreat,
      demoThreat,
      seedDemoThreat,
      oldSession,
      demoSession,
      recentSession,
      alertOnOldThreat,
      alertOnDemoThreat,
      predictionOnOldThreat,
    }
  }

  test('1. Disabled by default: nothing deleted when disabled', async () => {
    delete process.env.RETENTION_ENABLED
    const fixture = await seedTestData()

    const result = await applyRetention({ force: false })

    expect(result.applied).toBe(false)
    expect(result.reason).toMatch(/disabled by default/i)

    // Assert zero documents deleted from any collection
    const threatCount = await ThreatLog.countDocuments()
    const sessionCount = await HoneypotSession.countDocuments()
    const alertCount = await Alert.countDocuments()
    const auditCount = await mongoose.connection.db.collection('auditlogs').countDocuments()

    expect(threatCount).toBe(4)
    expect(sessionCount).toBe(3)
    expect(alertCount).toBe(2)
    expect(auditCount).toBe(1)
  })

  test('2. Dry-run simulation: counts match exactly without deleting records', async () => {
    const fixture = await seedTestData()

    const simulation = await dryRunRetention({ daysThreats: 90, daysSessions: 90 })

    expect(simulation.enabled).toBe(false)
    expect(simulation.dryRun).toBe(true)
    expect(simulation.counts.threatsEligible).toBe(1)
    expect(simulation.counts.sessionsEligible).toBe(1)
    expect(simulation.counts.dependentAlertsEligible).toBe(1)
    expect(simulation.counts.predictionsToUnlink).toBe(1)
    expect(simulation.safetyGuarantees.auditLogsTouched).toBe(0)
    expect(simulation.safetyGuarantees.demoSessionsExcluded).toBe(1)

    // Dry-run must leave all collections completely unchanged
    const threatCount = await ThreatLog.countDocuments()
    const sessionCount = await HoneypotSession.countDocuments()
    expect(threatCount).toBe(4)
    expect(sessionCount).toBe(3)
  })

  test('3. Demo data and AuditLogs are strictly excluded from retention', async () => {
    const fixture = await seedTestData()

    const result = await applyRetention({ force: true, dryRun: false, daysThreats: 90, daysSessions: 90 })

    expect(result.applied).toBe(true)
    expect(result.deleted.threats).toBe(1)
    expect(result.deleted.sessions).toBe(1)

    // Demo threat and seed threat must still exist
    const demoThreatCheck = await ThreatLog.findById(fixture.demoThreat._id)
    const seedThreatCheck = await ThreatLog.findById(fixture.seedDemoThreat._id)
    const recentThreatCheck = await ThreatLog.findById(fixture.recentThreat._id)
    expect(demoThreatCheck).not.toBeNull()
    expect(seedThreatCheck).not.toBeNull()
    expect(recentThreatCheck).not.toBeNull()

    // Demo session must still exist
    const demoSessionCheck = await HoneypotSession.findById(fixture.demoSession._id)
    const recentSessionCheck = await HoneypotSession.findById(fixture.recentSession._id)
    expect(demoSessionCheck).not.toBeNull()
    expect(recentSessionCheck).not.toBeNull()

    // Demo alert must still exist
    const demoAlertCheck = await Alert.findById(fixture.alertOnDemoThreat._id)
    expect(demoAlertCheck).not.toBeNull()

    // AuditLog count must be at least 1 (the original plus the RETENTION_RUN audit event)
    const auditLogs = await mongoose.connection.db.collection('auditlogs').find({}).toArray()
    expect(auditLogs.some((l) => l.action === 'USER_LOGIN')).toBe(true)
    expect(auditLogs.some((l) => l.action === 'RETENTION_RUN')).toBe(true)
  })

  test('4. Archive is written before delete and prediction references are unlinked', async () => {
    const fixture = await seedTestData()
    const db = mongoose.connection.db

    const result = await applyRetention({ force: true, dryRun: false, daysThreats: 90, daysSessions: 90 })

    expect(result.applied).toBe(true)

    // Verify archives exist in MongoDB
    const archivedThreats = await db.collection('archived_threatlogs').find({}).toArray()
    const archivedSessions = await db.collection('archived_honeypotsessions').find({}).toArray()
    const archivedAlerts = await db.collection('archived_alerts').find({}).toArray()

    expect(archivedThreats).toHaveLength(1)
    expect(archivedThreats[0]._originalId.toString()).toBe(fixture.oldThreat._id.toString())
    expect(archivedThreats[0].sourceIP).toBe(fixture.oldThreat.sourceIP)
    expect(archivedThreats[0]._archivedAt).toBeDefined()

    expect(archivedSessions).toHaveLength(1)
    expect(archivedSessions[0]._originalId.toString()).toBe(fixture.oldSession._id.toString())
    expect(archivedSessions[0].sessionId).toBe('cowrie-prod-999')

    expect(archivedAlerts).toHaveLength(1)
    expect(archivedAlerts[0]._originalId.toString()).toBe(fixture.alertOnOldThreat._id.toString())

    // Verify deleted from primary collections
    const deletedThreat = await ThreatLog.findById(fixture.oldThreat._id)
    const deletedSession = await HoneypotSession.findById(fixture.oldSession._id)
    const deletedAlert = await Alert.findById(fixture.alertOnOldThreat._id)
    expect(deletedThreat).toBeNull()
    expect(deletedSession).toBeNull()
    expect(deletedAlert).toBeNull()

    // Verify prediction threat reference was unlinked to null
    const updatedPrediction = await AIPrediction.findById(fixture.predictionOnOldThreat._id)
    expect(updatedPrediction.generatedThreat).toBeNull()
  })

  test('5. Restoration from archive re-populates purged records cleanly', async () => {
    const fixture = await seedTestData()

    // Apply retention (archives and deletes 1 threat, 1 session, 1 alert)
    await applyRetention({ force: true, dryRun: false, daysThreats: 90, daysSessions: 90 })

    expect(await ThreatLog.findById(fixture.oldThreat._id)).toBeNull()
    expect(await HoneypotSession.findById(fixture.oldSession._id)).toBeNull()
    expect(await Alert.findById(fixture.alertOnOldThreat._id)).toBeNull()

    // Restore from archive
    const restoreResult = await restoreFromArchive()

    expect(restoreResult.restored.threats).toBe(1)
    expect(restoreResult.restored.sessions).toBe(1)
    expect(restoreResult.restored.alerts).toBe(1)

    // Verify documents restored back into primary collections
    const restoredThreat = await ThreatLog.findById(fixture.oldThreat._id)
    const restoredSession = await HoneypotSession.findById(fixture.oldSession._id)
    const restoredAlert = await Alert.findById(fixture.alertOnOldThreat._id)

    expect(restoredThreat).not.toBeNull()
    expect(restoredThreat.sourceIP).toBe(fixture.oldThreat.sourceIP)
    expect(restoredSession).not.toBeNull()
    expect(restoredSession.sessionId).toBe('cowrie-prod-999')
    expect(restoredAlert).not.toBeNull()
    expect(restoredAlert.title).toBe('Alert on Old Threat')
  })
})
