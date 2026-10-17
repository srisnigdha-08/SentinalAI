const reportTime = require('../utils/reportingTime')
const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
const logger = require('../utils/logger')
const { parsePagination } = require('../utils/querySecurity')
const { CANONICAL_CLASSES, isValidCanonicalClass } = require('../utils/canonicalClasses')

const findPredictions = async ({ page = 1, limit = 20, minScore, verified } = {}) => {
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

  const pred = await AIPrediction.create(payload)
  if (!data.generatedThreat && pred.threatScore >= 0.7 && pred.predictedClass !== 'BENIGN') {
    const severity = pred.threatScore >= 0.9 ? 'CRITICAL' : pred.threatScore >= 0.75 ? 'HIGH' : 'MEDIUM'

    // Authoritative Block Threshold & autoBlockEnabled setting
    const aiEngineService = require('./aiEngineService')
    const BlockedIP = require('../models/BlockedIP')
    const SystemSetting = require('../models/SystemSetting')

    const blockThreshold = await aiEngineService.getBlockThreshold()
    const setting = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
    const autoBlockEnabled = setting ? setting.value === true : false

    const shouldBlock = pred.threatScore >= blockThreshold && autoBlockEnabled
    const status = shouldBlock ? 'BLOCKED' : 'MONITORING'

    const threat = await ThreatLog.create({
      severity,
      sourceIP: pred.sourceIP,
      attackType: pred.predictedClass,
      aiScore: pred.threatScore,
      confidence: pred.threatScore,
      status,
      preBlockStatus: shouldBlock ? 'MONITORING' : null,
      autonomousAction: {
        taken: shouldBlock,
        actionType: shouldBlock ? 'IP_BLOCKED' : null,
        actionTime: shouldBlock ? new Date() : null,
      },
    })
    pred.generatedThreat = threat._id
    await pred.save()

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

      if (['CRITICAL', 'HIGH'].includes(severity)) {
        const alert = await alertService.createAlertFromThreat(threat)
        socketManager.emitNewAlert(alert)
      }
    } catch (e) {
      logger.debug('[AI] Socket/Alert emission error: ' + e.message)
    }

    // Asynchronous Threat Intelligence Enrichment (Phase 2.4B - Option B)
    // Decoupled from detection and containment; runs in background and updates ThreatLog.threatIntel
    if (threat.aiScore >= 0.7) {
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

const getModelStats = async (now = new Date()) => {
  const weekAgo = reportTime.filter(7, now)
  const [total, weekPreds, avgScores, byClass, anomalyStats, verifiedAcc, inferPerf, scoreDistrib, dailyPreds] =
    await Promise.all([
      AIPrediction.countDocuments(),
      AIPrediction.countDocuments({ createdAt: weekAgo }),
      AIPrediction.aggregate([{ $group: { _id: null, avg: { $avg: '$threatScore' }, max: { $max: '$threatScore' } } }]),
      AIPrediction.aggregate([
        { $group: { _id: '$predictedClass', count: { $sum: 1 }, avgScore: { $avg: '$threatScore' } } },
        { $sort: { count: -1 } },
      ]),
      AIPrediction.aggregate([
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
        { $match: { inferenceTimeMs: { $exists: true } } },
        { $group: { _id: null, avg: { $avg: '$inferenceTimeMs' }, max: { $max: '$inferenceTimeMs' } } },
      ]),
      AIPrediction.aggregate([
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
    reporting: reportTime.reporting(now),
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

module.exports = { findPredictions, storePrediction, verifyPrediction, getModelStats }
