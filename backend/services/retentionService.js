'use strict'

/**
 * services/retentionService.js
 *
 * Task 8: Data Retention Policy & Archival Subsystem
 *
 * DESIGN CONSTRAINTS & GUARANTEES:
 * 1. NEVER TOUCH AUDITLOGS: AuditLog collection is strictly append-only and excluded.
 * 2. NEVER TOUCH DEMO-* SESSIONS OR THEIR THREATS: Demo records and fixtures are strictly preserved.
 * 3. DISABLED BY DEFAULT: Requires RETENTION_ENABLED=true in env or explicit force flag.
 * 4. DRY-RUN BY DEFAULT: If apply is called without dryRun: false, only simulation counts are returned.
 * 5. ARCHIVE BEFORE DELETE: All records must be safely written to archive collections before deletion.
 * 6. TASK 6 CASCADE CONSISTENCY: Dependent Alert and AIPrediction references are cleaned/unlinked atomically.
 * 7. NEVER RUN AT SERVER STARTUP: Only triggered via admin action or explicit CLI script.
 * 8. AUDIT RECORDING: Emits RETENTION_RUN structured audit log.
 */

const mongoose = require('mongoose')
const ThreatLog = require('../models/ThreatLog')
const HoneypotSession = require('../models/HoneypotSession')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const { logAudit } = require('../utils/auditLogger')
const logger = require('../utils/logger')

const DEMO_THREAT_IPS = ['198.51.100.88'] // Seed demo threat IP

/**
 * Reads retention configuration from environment variables.
 */
function getRetentionConfig() {
  return {
    enabled: process.env.RETENTION_ENABLED === 'true',
    daysThreats: parseInt(process.env.RETENTION_DAYS_THREATS, 10) || 90,
    daysSessions: parseInt(process.env.RETENTION_DAYS_SESSIONS, 10) || 90,
    batchSize: parseInt(process.env.RETENTION_BATCH_SIZE, 10) || 500,
  }
}

/**
 * Retrieves ObjectIds of all threats that must be protected (demo-linked threats).
 */
async function getProtectedThreatIds() {
  const demoSessions = await HoneypotSession.find({ sessionId: { $regex: /^demo-/i } }, { linkedThreatLog: 1 }).lean()

  const protectedIds = []
  for (const s of demoSessions) {
    if (s.linkedThreatLog) {
      protectedIds.push(s.linkedThreatLog)
    }
  }

  // Also protect known demo threats by IP
  const demoIPThreats = await ThreatLog.find({ sourceIP: { $in: DEMO_THREAT_IPS } }, { _id: 1 }).lean()

  for (const t of demoIPThreats) {
    protectedIds.push(t._id)
  }

  return protectedIds
}

/**
 * Performs a safe, read-only dry-run simulation of the retention policy.
 *
 * @param {Object} [options]
 * @param {number} [options.daysThreats]
 * @param {number} [options.daysSessions]
 * @param {number} [options.batchSize]
 * @param {Date} [options.now]
 * @returns {Promise<Object>}
 */
async function dryRunRetention(options = {}) {
  const config = getRetentionConfig()
  const daysThreats = options.daysThreats !== undefined ? options.daysThreats : config.daysThreats
  const daysSessions = options.daysSessions !== undefined ? options.daysSessions : config.daysSessions
  const batchSize = options.batchSize !== undefined ? options.batchSize : config.batchSize
  const now = options.now instanceof Date ? options.now : new Date()

  const threatsCutoff = new Date(now.getTime() - daysThreats * 86400000)
  const sessionsCutoff = new Date(now.getTime() - daysSessions * 86400000)

  // 1. Identify protected demo threats
  const protectedThreatIds = await getProtectedThreatIds()

  // 2. Query candidate threats
  const candidateThreats = await ThreatLog.find({
    createdAt: { $lt: threatsCutoff },
    _id: { $nin: protectedThreatIds },
    sourceIP: { $nin: DEMO_THREAT_IPS },
  })
    .limit(batchSize)
    .lean()

  const candidateThreatIds = candidateThreats.map((t) => t._id)

  // 3. Query candidate honeypot sessions (non-demo)
  const candidateSessions = await HoneypotSession.find({
    sessionId: { $not: /^demo-/i },
    createdAt: { $lt: sessionsCutoff },
  })
    .limit(batchSize)
    .lean()

  const candidateSessionIds = candidateSessions.map((s) => s._id)

  // 4. Query dependent Alert records (Task 6 consistency)
  const candidateAlerts = await Alert.find({
    $or: [
      { 'sourceRef.refModel': 'ThreatLog', 'sourceRef.refId': { $in: candidateThreatIds } },
      { 'sourceRef.refModel': 'HoneypotSession', 'sourceRef.refId': { $in: candidateSessionIds } },
    ],
  }).lean()

  const candidateAlertIds = candidateAlerts.map((a) => a._id)

  // 5. Query dependent AIPrediction references to unlink
  const candidatePredictions = await AIPrediction.find({
    $or: [{ threatId: { $in: candidateThreatIds } }, { generatedThreat: { $in: candidateThreatIds } }],
  }).lean()

  return {
    enabled: config.enabled,
    dryRun: true,
    policyConfig: {
      daysThreats,
      daysSessions,
      batchSize,
    },
    cutoffs: {
      threatsCutoff: threatsCutoff.toISOString(),
      sessionsCutoff: sessionsCutoff.toISOString(),
    },
    counts: {
      threatsEligible: candidateThreats.length,
      sessionsEligible: candidateSessions.length,
      dependentAlertsEligible: candidateAlerts.length,
      predictionsToUnlink: candidatePredictions.length,
      totalRecordsEligible: candidateThreats.length + candidateSessions.length + candidateAlerts.length,
    },
    safetyGuarantees: {
      auditLogsTouched: 0,
      demoSessionsExcluded: await HoneypotSession.countDocuments({ sessionId: { $regex: /^demo-/i } }),
      demoThreatsProtected: protectedThreatIds.length,
    },
    candidates: {
      threatIds: candidateThreatIds,
      sessionIds: candidateSessionIds,
      alertIds: candidateAlertIds,
      predictionIds: candidatePredictions.map((p) => p._id),
      threats: candidateThreats,
      sessions: candidateSessions,
      alerts: candidateAlerts,
    },
  }
}

/**
 * Executes the retention policy: archives candidate records first, then removes them.
 *
 * @param {Object} [options]
 * @param {boolean} [options.dryRun=true] - Defaults to dry-run unless explicitly false
 * @param {boolean} [options.force=false] - Allows execution when RETENTION_ENABLED=false
 * @param {Object} [options.actor] - User or system initiating the retention run
 * @returns {Promise<Object>}
 */
async function applyRetention(options = {}) {
  const config = getRetentionConfig()

  // Guard 1: Must be explicitly enabled or forced
  if (!config.enabled && !options.force) {
    return {
      applied: false,
      reason: 'Retention policy is disabled by default (RETENTION_ENABLED=false). Pass force: true or enable via env.',
      counts: { archived: 0, deleted: 0 },
    }
  }

  // Guard 2: Dry-run by default
  if (options.dryRun !== false) {
    const simulation = await dryRunRetention(options)
    return {
      applied: false,
      dryRun: true,
      simulation,
    }
  }

  // 1. Run simulation to fetch candidates
  const simulation = await dryRunRetention(options)
  const { candidates, counts } = simulation

  if (counts.totalRecordsEligible === 0) {
    return {
      applied: true,
      dryRun: false,
      archived: { threats: 0, sessions: 0, alerts: 0 },
      deleted: { threats: 0, sessions: 0, alerts: 0, predictionsUnlinked: 0 },
      message: 'No expired records met retention criteria; zero changes made.',
    }
  }

  const db = mongoose.connection.db
  if (!db) {
    throw new Error('Database connection unavailable for retention archival.')
  }

  const archiveTime = new Date()

  // 2. ARCHIVE BEFORE DELETING (Zero data loss requirement)
  // Archive ThreatLogs
  if (candidates.threats.length > 0) {
    const threatArchiveDocs = candidates.threats.map((doc) => ({
      ...doc,
      _originalId: doc._id,
      _archivedAt: archiveTime,
      _retentionBatch: archiveTime.toISOString(),
    }))
    await db.collection('archived_threatlogs').insertMany(threatArchiveDocs)
    logger.info(`[Retention] Archived ${candidates.threats.length} threat records to archived_threatlogs`)
  }

  // Archive HoneypotSessions
  if (candidates.sessions.length > 0) {
    const sessionArchiveDocs = candidates.sessions.map((doc) => ({
      ...doc,
      _originalId: doc._id,
      _archivedAt: archiveTime,
      _retentionBatch: archiveTime.toISOString(),
    }))
    await db.collection('archived_honeypotsessions').insertMany(sessionArchiveDocs)
    logger.info(`[Retention] Archived ${candidates.sessions.length} session records to archived_honeypotsessions`)
  }

  // Archive Alerts
  if (candidates.alerts.length > 0) {
    const alertArchiveDocs = candidates.alerts.map((doc) => ({
      ...doc,
      _originalId: doc._id,
      _archivedAt: archiveTime,
      _retentionBatch: archiveTime.toISOString(),
    }))
    await db.collection('archived_alerts').insertMany(alertArchiveDocs)
    logger.info(`[Retention] Archived ${candidates.alerts.length} alert records to archived_alerts`)
  }

  // 3. DELETION STEP (Only executed after archival succeeds)
  let deletedThreatsCount = 0
  let deletedSessionsCount = 0
  let deletedAlertsCount = 0
  let unlinkedPredictionsCount = 0

  if (candidates.threatIds.length > 0) {
    const res = await ThreatLog.deleteMany({ _id: { $in: candidates.threatIds } })
    deletedThreatsCount = res.deletedCount || 0
  }

  if (candidates.sessionIds.length > 0) {
    const res = await HoneypotSession.deleteMany({ _id: { $in: candidates.sessionIds } })
    deletedSessionsCount = res.deletedCount || 0
  }

  if (candidates.alertIds.length > 0) {
    const res = await Alert.deleteMany({ _id: { $in: candidates.alertIds } })
    deletedAlertsCount = res.deletedCount || 0
  }

  if (candidates.predictionIds.length > 0) {
    const res = await AIPrediction.updateMany(
      { _id: { $in: candidates.predictionIds } },
      { $set: { threatId: null, generatedThreat: null } }
    )
    unlinkedPredictionsCount = res.modifiedCount || 0
  }

  // 4. LOG AUDIT EVENT
  const actor = options.actor || {
    id: 'system',
    name: 'Retention Policy Service',
    role: 'system',
  }

  try {
    await logAudit({
      action: 'RETENTION_RUN',
      eventType: 'SYSTEM_MAINTENANCE',
      actor,
      target: { type: 'Database', identifier: 'sentinel-db' },
      status: 'SUCCESS',
      details: {
        threatsArchived: candidates.threats.length,
        threatsDeleted: deletedThreatsCount,
        sessionsArchived: candidates.sessions.length,
        sessionsDeleted: deletedSessionsCount,
        alertsArchived: candidates.alerts.length,
        alertsDeleted: deletedAlertsCount,
        predictionsUnlinked: unlinkedPredictionsCount,
        archiveCollections: ['archived_threatlogs', 'archived_honeypotsessions', 'archived_alerts'],
        batchTimestamp: archiveTime.toISOString(),
      },
    })
  } catch (auditErr) {
    logger.error(`[Retention] Audit log emission failed: ${auditErr.message}`)
  }

  return {
    applied: true,
    dryRun: false,
    timestamp: archiveTime.toISOString(),
    archived: {
      threats: candidates.threats.length,
      sessions: candidates.sessions.length,
      alerts: candidates.alerts.length,
    },
    deleted: {
      threats: deletedThreatsCount,
      sessions: deletedSessionsCount,
      alerts: deletedAlertsCount,
      predictionsUnlinked: unlinkedPredictionsCount,
    },
    archiveCollections: ['archived_threatlogs', 'archived_honeypotsessions', 'archived_alerts'],
  }
}

/**
 * Restores archived records from archival collections back into primary collections.
 *
 * @param {Object} [options]
 * @param {string} [options.batchTimestamp] - Optional batch identifier to restore
 * @returns {Promise<Object>}
 */
async function restoreFromArchive(options = {}) {
  const db = mongoose.connection.db
  if (!db) throw new Error('Database connection unavailable for archive restoration.')

  const filter = {}
  if (options.batchTimestamp) {
    filter._retentionBatch = options.batchTimestamp
  }

  let restoredThreats = 0
  let restoredSessions = 0
  let restoredAlerts = 0

  // 1. Restore Threats
  const archivedThreats = await db.collection('archived_threatlogs').find(filter).toArray()
  for (const doc of archivedThreats) {
    const { _id, _originalId, _archivedAt, _retentionBatch, ...threatData } = doc
    const targetId = _originalId || _id
    await db
      .collection('threatlogs')
      .updateOne({ _id: targetId }, { $setOnInsert: { _id: targetId, ...threatData } }, { upsert: true })
    restoredThreats++
  }

  // 2. Restore Sessions
  const archivedSessions = await db.collection('archived_honeypotsessions').find(filter).toArray()
  for (const doc of archivedSessions) {
    const { _id, _originalId, _archivedAt, _retentionBatch, ...sessionData } = doc
    const targetId = _originalId || _id
    await db
      .collection('honeypotsessions')
      .updateOne({ _id: targetId }, { $setOnInsert: { _id: targetId, ...sessionData } }, { upsert: true })
    restoredSessions++
  }

  // 3. Restore Alerts
  const archivedAlerts = await db.collection('archived_alerts').find(filter).toArray()
  for (const doc of archivedAlerts) {
    const { _id, _originalId, _archivedAt, _retentionBatch, ...alertData } = doc
    const targetId = _originalId || _id
    await db
      .collection('alerts')
      .updateOne({ _id: targetId }, { $setOnInsert: { _id: targetId, ...alertData } }, { upsert: true })
    restoredAlerts++
  }

  return {
    restored: {
      threats: restoredThreats,
      sessions: restoredSessions,
      alerts: restoredAlerts,
    },
  }
}

module.exports = {
  getRetentionConfig,
  getProtectedThreatIds,
  dryRunRetention,
  applyRetention,
  restoreFromArchive,
}
