const { severityFor } = require('../utils/severity')
const reportTime = require('../utils/reportingTime')
const mongoose = require('mongoose')
const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
const logger = require('../utils/logger')
const { parsePagination } = require('../utils/querySecurity')
const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')

// While the AI engine is down every analysed flow is degraded. Each one is still recorded as a
// DEGRADED threat (held in MONITOR), but only one SYSTEM_HEALTH alert is raised per cooldown window.
const HONEYPOT_CORROBORATION_DAYS = parseFloat(process.env.HONEYPOT_CORROBORATION_DAYS) || 7
const DEGRADED_ALERT_COOLDOWN_MS = parseInt(process.env.DEGRADED_ALERT_COOLDOWN_MS, 10) || 5 * 60 * 1000
let lastDegradedAlertAt = 0
const resetDegradedAlertCooldown = () => {
  lastDegradedAlertAt = 0
}

const findPredictions = async ({ page = 1, limit = 20, minScore, verified, review } = {}) => {
  const {
    page: safePage,
    limit: safeLimit,
    skip,
  } = parsePagination({
    page,
    limit,
    defaultLimit: 20,
    maxLimit: 100,
  })
  const filter = {}
  if (minScore !== undefined && !isNaN(parseFloat(minScore))) {
    const parsed = parseFloat(minScore)
    if (parsed >= 0 && parsed <= 1) {
      filter.threatScore = { $gte: parsed }
    }
  }
  if (verified !== undefined) filter.verified = verified === true || verified === 'true'
  // Analyst-review queue: anomalous flows the classifier called BENIGN, not yet verified
  if (review === true || review === 'true') Object.assign(filter, { needsReview: true, verified: false })
  const total = await AIPrediction.countDocuments(filter)
  const data = await AIPrediction.find(filter)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(safeLimit)
    .populate('generatedThreat', 'status severity sourceIP')
    .populate('verifiedBy', 'name email role')
    .lean()
  return { data, total, page: safePage, limit: safeLimit }
}

const storePrediction = async (data) => {
  const payload = { ...data }
  payload.needsReview = data.action === 'REVIEW'
  // Honeypot feedback (U4): a network flow from an IP that attacked the honeypot recently but was classified
  // BENIGN/Unknown is a likely missed attack. It joins the analyst review queue; once verified it becomes a
  // training sample through the existing verification -> TrainingSample path. Never a threat or block by itself.
  // Only on an open connection: a buffered query would otherwise stall every prediction while Mongo is down
  if (data.inputSource === 'network_traffic' && data.sourceIP && module.exports.dbConnected()) {
    try {
      const since = new Date(Date.now() - HONEYPOT_CORROBORATION_DAYS * 24 * 3600 * 1000)
      const HoneypotSession = require('../models/HoneypotSession')
      if (await HoneypotSession.exists({ sourceIP: data.sourceIP, createdAt: { $gte: since } })) {
        payload.honeypotCorroborated = true
        if (['BENIGN', 'Unknown'].includes(data.predictedClass)) payload.needsReview = true
      }
    } catch (err) {
      logger.warn('[AI Persistence] Honeypot corroboration lookup failed (' + err.name + ')')
    }
  }

  if (data.featureVector !== undefined && data.featureVector !== null) {
    const isArr = Array.isArray(data.featureVector)
    const hasLen53 = isArr && data.featureVector.length === 53
    const allFinite = hasLen53 && data.featureVector.every((v) => typeof v === 'number' && Number.isFinite(v))

    if (isArr && hasLen53 && allFinite) {
      payload.featureVector = data.featureVector
      payload.featureSchemaVersion = data.featureSchemaVersion || 'v2.1_53feat'
    } else {
      logger.warn(
        `[AI Persistence] Invalid featureVector received (isArr=${isArr}, len=${isArr ? data.featureVector.length : 0}, allFinite=${allFinite}). Omitting featureVector from record.`
      )
      delete payload.featureVector
      delete payload.featureSchemaVersion
    }
  }

  const isDegraded =
    data.status === 'DEGRADED' || data.status === 'UNAVAILABLE' || data.predictedClass === 'UNINSPECTED_TRAFFIC'
  // Alert line shared with the AI engine (its MONITOR threshold, validated on held-out data).
  const alertThreshold = await require('./aiEngineService').getAlertThreshold()
  const willCreateThreat =
    !data.generatedThreat &&
    (isDegraded || (Number(data.threatScore) >= alertThreshold && data.predictedClass !== 'BENIGN'))
  // The threat's id is chosen before either write, so the prediction is stored already linked to it and no
  // follow-up save can leave a threat whose prediction does not point back (M3).
  const threatId = willCreateThreat ? new mongoose.Types.ObjectId() : null
  if (threatId) payload.generatedThreat = threatId
  const pred = await AIPrediction.create(payload)
  if (willCreateThreat) {
    // Authoritative Block Threshold & autoBlockEnabled setting
    const aiEngineService = require('./aiEngineService')
    const SystemSetting = require('../models/SystemSetting')

    const blockThreshold = await aiEngineService.getBlockThreshold()
    // Same scale as the engine's severity field (M1): CRITICAL >= block line, HIGH >= alert line
    const severity = isDegraded ? 'MEDIUM' : severityFor(pred.threatScore, { alertThreshold, blockThreshold })
    const setting = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
    const autoBlockEnabled = setting ? setting.value === true : false

    // Incomplete input (M2): many features were filled with defaults, so the score describes a partly
    // fabricated flow. It may still raise a threat for an analyst, but it never triggers an automatic block.
    const shouldBlock = !isDegraded && !data.incompleteInput && pred.threatScore >= blockThreshold && autoBlockEnabled
    const status = isDegraded ? 'DEGRADED' : shouldBlock ? 'BLOCKED' : 'MONITORING'

    const rawEventTime = data.eventTime || data.timestamp
    let eventTime = null
    if (rawEventTime) {
      const parsed = new Date(rawEventTime)
      if (!isNaN(parsed.getTime())) {
        eventTime = parsed
      }
    }

    const threatDoc = {
      _id: threatId,
      severity,
      sourceIP: pred.sourceIP,
      attackType: pred.predictedClass,
      aiScore: pred.threatScore,
      confidence: pred.threatScore,
      status,
      preBlockStatus: shouldBlock ? 'MONITORING' : isDegraded ? 'DEGRADED' : null,
      predictionId: pred._id,
      eventTime,
      autonomousAction: {
        taken: shouldBlock,
        actionType: shouldBlock ? 'IP_BLOCKED' : null,
        actionTime: shouldBlock ? new Date() : null,
      },
      notes: isDegraded
        ? data.notes ||
          (data.status === 'UNAVAILABLE'
            ? 'AI engine unavailable - held in MONITOR'
            : 'Explicit AI engine degraded fallback')
        : '',
    }
    let threat
    try {
      threat = await ThreatLog.create(threatDoc)
    } catch (threatErr) {
      // Compensate: the prediction must not reference a threat that was never written.
      await AIPrediction.updateOne({ _id: pred._id }, { $unset: { generatedThreat: 1 } }).catch((unlinkErr) =>
        logger.error(
          `[AI Persistence] Could not unlink prediction ${pred._id} from failed threat: ${unlinkErr.message}`
        )
      )
      throw threatErr
    }

    // If automatic block occurred, execute centralized autoBlock with compensating rollback support
    if (shouldBlock) {
      try {
        const containmentService = require('./containmentService')
        await containmentService.executeAutoBlock({
          threat,
          threatScore: pred.threatScore,
          source: 'AI Engine',
          sourceRef: { refModel: 'ThreatLog', refId: threat._id },
        })
      } catch (e) {
        logger.error(`[AI Auto-Block] Auto-block execution failed in storePrediction: ${e.message}`)
      }
    }

    // Real WebSocket emission: send genuine detection to live Attack Feed & Alert subscribers
    try {
      const socketManager = require('../websocket/socketManager')
      const alertService = require('./alertService')
      socketManager.emitNewThreat(threat)

      if (isDegraded && Date.now() - lastDegradedAlertAt < DEGRADED_ALERT_COOLDOWN_MS) {
        logger.debug('[AI] Degraded-state alert suppressed (cooldown active)')
      } else if (isDegraded) {
        lastDegradedAlertAt = Date.now()
        const alert = await alertService.createAlert({
          title: `System Alert: AI Engine ${data.status || 'DEGRADED'}`,
          message: `Traffic from ${threat.sourceIP} held in MONITOR due to uninspected/degraded state.`,
          severity: 'MEDIUM',
          type: 'SYSTEM_HEALTH',
          sourceRef: { refModel: 'ThreatLog', refId: threat._id },
          targetRoles: ['admin', 'analyst'],
        })
        socketManager.emitNewAlert(alert)
      } else if (['CRITICAL', 'HIGH'].includes(severity)) {
        const alert = await alertService.createAlertFromThreat(threat)
        socketManager.emitNewAlert(alert)
      }
    } catch (e) {
      logger.warn('[AI] Socket/Alert emission error: ' + e.message)
    }

    // Asynchronous Threat Intelligence Enrichment (Phase 2.4B - Option B)
    // Decoupled from detection and containment; runs in background and updates ThreatLog.threatIntel
    if (threat.aiScore >= alertThreshold) {
      try {
        const threatIntelService = require('./threatIntelService')
        setImmediate(() => {
          threatIntelService.enrichThreat(threat).catch((e) => {
            logger.debug('[AI] Background Threat Intel enrichment error: ' + e.message)
          })
        })
      } catch (e) {
        logger.debug('[AI] Failed to dispatch Threat Intel enrichment: ' + e.message)
      }
    }
  }

  // Broadcast AI prediction event for live AI Analytics tracking
  try {
    const socketManager = require('../websocket/socketManager')
    socketManager.emitAIPrediction(pred)
  } catch (e) {
    logger.debug('[AI] Socket emitAIPrediction error: ' + e.message)
  }

  logger.info(`AI prediction stored: ${pred.predictedClass} score=${pred.threatScore}`)
  return pred
}

const verifyPrediction = async (id, userId, actualClass) => {
  const trimmed = typeof actualClass === 'string' ? actualClass.trim() : ''
  if (!isValidCanonicalClass(trimmed)) {
    const err = new Error(`Invalid actualClass. Must be one of: ${CANONICAL_CLASSES.join(', ')}`)
    err.statusCode = 400
    throw err
  }

  const verifiedAt = new Date()
  const historyEntry = {
    verifiedBy: userId,
    actualClass: trimmed,
    verifiedAt,
  }

  const pred = await AIPrediction.findByIdAndUpdate(
    id,
    {
      $set: {
        verified: true,
        verifiedBy: userId,
        actualClass: trimmed,
        verifiedAt,
        needsReview: false,
      },
      $push: {
        verificationHistory: historyEntry,
      },
    },
    { new: true, runValidators: true }
  ).populate('verifiedBy', 'name email role')

  // Asynchronous Out-of-band TrainingSample quarantine sync (Phase 2.5C-6)
  // Decoupled from caller; ensures verified prediction with 53 features enters QUARANTINED
  if (pred) {
    setImmediate(() => {
      try {
        const trainingSampleService = require('./trainingSampleService')
        trainingSampleService.syncPredictionToQuarantine(pred._id).catch((e) => {
          logger.debug('[AI] Out-of-band TrainingSample sync error: ' + e.message)
        })
      } catch (e) {
        logger.debug('[AI] Failed to dispatch TrainingSample sync: ' + e.message)
      }
    })
  }

  return pred
}

// Score/class/anomaly/latency aggregates cover the last ANALYTICS_WINDOW_DAYS (default 30, max 90) instead of
// every prediction ever stored (M6). Total uses the collection count metadata; verified accuracy stays all-time
// (indexed on `verified`, a small subset).
const analyticsWindowDays = () => {
  const days = parseInt(process.env.ANALYTICS_WINDOW_DAYS, 10)
  return Number.isInteger(days) && days >= 1 && days <= 90 ? days : 30
}

const getModelStats = async (now = new Date()) => {
  const weekAgo = reportTime.filter(7, now)
  const windowDays = analyticsWindowDays()
  const inWindow = { $match: { createdAt: reportTime.filter(windowDays, now) } }
  const [total, weekPreds, avgScores, byClass, anomalyStats, verifiedAcc, inferPerf, scoreDistrib, dailyPreds] =
    await Promise.all([
      AIPrediction.estimatedDocumentCount(),
      AIPrediction.countDocuments({ createdAt: weekAgo }),
      AIPrediction.aggregate([
        inWindow,
        { $group: { _id: null, avg: { $avg: '$threatScore' }, max: { $max: '$threatScore' } } },
      ]),
      AIPrediction.aggregate([
        inWindow,
        { $group: { _id: '$predictedClass', count: { $sum: 1 }, avgScore: { $avg: '$threatScore' } } },
        { $sort: { count: -1 } },
      ]),
      AIPrediction.aggregate([
        inWindow,
        { $group: { _id: null, anomalies: { $sum: { $cond: ['$isAnomaly', 1, 0] } }, total: { $sum: 1 } } },
      ]),
      AIPrediction.aggregate([
        { $match: { verified: true, actualClass: { $exists: true } } },
        {
          $group: {
            _id: null,
            correct: { $sum: { $cond: [{ $eq: ['$predictedClass', '$actualClass'] }, 1, 0] } },
            total: { $sum: 1 },
          },
        },
      ]),
      AIPrediction.aggregate([
        inWindow,
        { $match: { inferenceTimeMs: { $exists: true } } },
        { $group: { _id: null, avg: { $avg: '$inferenceTimeMs' }, max: { $max: '$inferenceTimeMs' } } },
      ]),
      AIPrediction.aggregate([
        inWindow,
        {
          $bucket: {
            groupBy: '$threatScore',
            boundaries: [0, 0.3, 0.6, 0.9, 1.01],
            default: 'other',
            output: { count: { $sum: 1 } },
          },
        },
      ]),
      AIPrediction.aggregate([
        { $match: { createdAt: weekAgo } },
        {
          $group: {
            _id: reportTime.dayGroup(),
            count: { $sum: 1 },
            threats: { $sum: { $cond: [{ $gte: ['$threatScore', 0.7] }, 1, 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    ])
  const avg = avgScores[0] || { avg: 0, max: 0 }
  const anomaly = anomalyStats[0] || { anomalies: 0, total: 1 }
  const acc = verifiedAcc[0] || { correct: 0, total: 0 }
  const perf = inferPerf[0] || { avg: 0, max: 0 }

  const bucketMap = { 0: 0, 0.3: 0, 0.6: 0, 0.9: 0 }
  scoreDistrib.forEach((b) => {
    if (bucketMap[b._id] !== undefined) bucketMap[b._id] = b.count
  })
  const scoreDistribution = [
    { range: 'LOW (0-0.3)', count: bucketMap[0] },
    { range: 'MEDIUM (0.3-0.6)', count: bucketMap[0.3] },
    { range: 'HIGH (0.6-0.9)', count: bucketMap[0.6] },
    { range: 'CRITICAL (0.9-1.0)', count: bucketMap[0.9] },
  ]

  return {
    reporting: { ...reportTime.reporting(now), analyticsWindow: reportTime.metadata(windowDays, now) },
    summary: {
      totalPredictions: total,
      weekPredictions: weekPreds,
      avgThreatScore: avg.avg != null ? parseFloat(avg.avg.toFixed(3)) : 0,
      anomalyRate: parseFloat(((anomaly.anomalies / Math.max(anomaly.total, 1)) * 100).toFixed(1)),
      verifiedAccuracy: acc.total > 0 ? parseFloat(((acc.correct / acc.total) * 100).toFixed(1)) : null,
      avgInferenceMs: parseFloat((perf.avg || 0).toFixed(1)),
    },
    charts: {
      byClass,
      scoreDistribution,
      dailyPredictions: dailyPreds,
    },
  }
}

// Exported so tests can simulate an open connection (mongoose's readyState is not configurable)
const dbConnected = () => mongoose.connection.readyState === 1

module.exports = {
  findPredictions,
  storePrediction,
  verifyPrediction,
  getModelStats,
  resetDegradedAlertCooldown,
  dbConnected,
}
