const axios = require('axios')
const logger = require('../utils/logger')
const apiKey = process.env.SENTINEL_KEY
if (!apiKey) {
  logger.error('CRITICAL CONFIG ERROR: SENTINEL_KEY environment variable is not defined. Failing closed.')
  throw new Error('Configuration error: SENTINEL_KEY environment variable is missing.')
}
const ai = axios.create({
  baseURL: process.env.AI_ENGINE_URL || 'http://localhost:8000',
  timeout: 10000,
  headers: {
    'X-API-Key': apiKey,
  },
})
const getHealth = async () => {
  try {
    const readiness = (await ai.get('/ready', { timeout: 1500 })).data
    if (readiness?.status !== 'ok') return { status: 'unreachable', error: 'Required AI models unavailable' }
    await ai.get('/model/info', { timeout: 1500 })
    return { ...readiness, authenticated: true }
  } catch {
    return { status: 'unreachable', error: 'AI readiness or service authentication unavailable' }
  }
}
const getModelInfo = async () => {
  try {
    return (await ai.get('/model/info')).data
  } catch {
    return null
  }
}
const getModelStats = async () => {
  try {
    return (await ai.get('/model/stats')).data
  } catch {
    return null
  }
}
const predictRecord = async (record) => {
  try {
    return (await ai.post('/predict/internal', record)).data
  } catch (e) {
    if (e.response?.status === 422) {
      const error = new Error('Invalid AI feature input')
      error.statusCode = 422
      throw error
    }
    logger.warn('[AI] predict failed (' + e.name + ')')
    return null
  }
}
const runFullPipeline = async (record, io = null) => {
  let r
  try {
    r = await module.exports.predictRecord(record)
  } catch (err) {
    if (err.statusCode === 422) throw err
    r = null
  }

  // Handle degraded or unavailable inference
  let result
  let isDegraded = false
  if (!r || !r.result) {
    isDegraded = true
    result = {
      predictedClass: 'UNINSPECTED_TRAFFIC',
      threatScore: 0.5,
      action: 'MONITOR',
      status: 'UNAVAILABLE',
      isAnomaly: false,
      anomalyScore: 0,
      classProbabilities: { UNINSPECTED_TRAFFIC: 1.0 },
      modelVersion: 'v2.1-fallback',
      featureSchemaVersion: 'v2.1_53feat',
      inferenceTimeMs: 0,
    }
  } else {
    result = r.result
    if (result.status === 'DEGRADED' || result.predictedClass === 'UNINSPECTED_TRAFFIC') {
      isDegraded = true
    }
  }

  // Validate raw threatScore before clamping (Reject non-finite / out-of-range scores)
  let score = 0.5
  if (!isDegraded) {
    const rawScore =
      result.threatScore !== undefined && result.threatScore !== null && result.threatScore !== ''
        ? Number(result.threatScore)
        : NaN

    if (!Number.isFinite(rawScore) || rawScore < 0 || rawScore > 1) {
      logger.warn(
        `[AI Pipeline] Invalid threatScore received (${result.threatScore}). Rejecting inference as invalid and falling back to degraded state.`
      )
      isDegraded = true
      result = {
        predictedClass: 'UNINSPECTED_TRAFFIC',
        threatScore: 0.5,
        action: 'MONITOR',
        status: 'DEGRADED',
        isAnomaly: false,
        anomalyScore: 0,
        classProbabilities: { UNINSPECTED_TRAFFIC: 1.0 },
        modelVersion: result.modelVersion || 'v2.1-fallback',
        featureSchemaVersion: result.featureSchemaVersion || 'v2.1_53feat',
        inferenceTimeMs: result.inferenceTimeMs || 0,
        notes: `Invalid inference threatScore: ${result.threatScore}`,
      }
      score = 0.5
    } else {
      score = rawScore
    }
  }

  const blockThreshold = await module.exports.getBlockThreshold()

  // Action Precedence Rule:
  // 1. Degraded / Unavailable inference must strictly enforce MONITOR
  // 2. Valid explicit MONITOR recommendation from candidate policy is honored
  // 3. Score-based threshold fallback:
  let action = 'ALLOW'
  if (
    isDegraded ||
    result.status === 'DEGRADED' ||
    result.status === 'UNAVAILABLE' ||
    result.predictedClass === 'UNINSPECTED_TRAFFIC'
  ) {
    action = 'MONITOR'
  } else if (result.action === 'MONITOR' || result.action === 'BLOCK') {
    action = result.action
  } else {
    action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  }

  logger.info(
    '[AI Pipeline] ' +
      record.sourceIP +
      ' -> ' +
      result.predictedClass +
      ' (' +
      Math.round(score * 100) +
      '%) -> ' +
      action +
      (isDegraded ? ' [' + (result.status || 'DEGRADED') + ']' : '')
  )

  const aiDbSvc = require('./aiService')
  let pred
  try {
    pred = await aiDbSvc.storePrediction({
      inputSource: 'network_traffic',
      sourceIP: record.sourceIP,
      targetIP: record.destinationIP || 'INTERNAL',
      predictedClass: result.predictedClass,
      classProbabilities: result.classProbabilities,
      threatScore: score,
      modelVersion: result.modelVersion || 'v2.1',
      modelType: result.modelVersion?.includes('xgb') ? 'ensemble' : 'random_forest',
      isAnomaly: result.isAnomaly || false,
      anomalyScore: result.anomalyScore || 0,
      inferenceTimeMs: result.inferenceTimeMs,
      rawFeatures: record,
      featureVector: result.featureVector,
      featureSchemaVersion: result.featureSchemaVersion,
      status: result.status,
      action,
    })
  } catch (err) {
    logger.error('[AI Pipeline] Failed to persist prediction: ' + err.name)
    // Emergency Audit Disk Fallback (Section 2.E)
    try {
      const { writeEmergencyAudit } = require('../utils/emergencyAudit')
      writeEmergencyAudit({
        event: 'PERSISTENCE_FAILURE_EMERGENCY_AUDIT',
        sourceIP: record.sourceIP,
        threatScore: score,
        predictedClass: result.predictedClass,
        action,
        status: result.status || 'PERSISTENCE_FAILED',
        error: err.message,
      })
    } catch (auditErr) {
      logger.error('[AI Pipeline] Emergency disk audit failed: ' + auditErr.message)
    }
    throw err
  }

  const { featureVector: _features, featureSchemaVersion: _schema, ...publicResult } = result
  return { ...publicResult, _id: pred ? pred._id : undefined, action, sourceIP: record.sourceIP }
}
const predictHoneypotSession = async (session) => {
  try {
    return (await ai.post('/predict/honeypot/internal', session)).data
  } catch (e) {
    logger.warn('[AI] honeypot predict failed: ' + e.message)
    return null
  }
}
const getDeceptionScore = async (session) => {
  try {
    return (await ai.post('/deception/score', session)).data
  } catch (e) {
    logger.warn('[AI] deception scoring failed: ' + e.message)
    return null
  }
}

let cachedBlockThreshold = 0.92 // Default fallback
let lastFetchedTime = 0
const CACHE_TTL_MS = 60000 // Cache for 1 minute

const getBlockThreshold = async () => {
  const now = Date.now()
  if (now - lastFetchedTime < CACHE_TTL_MS) {
    return cachedBlockThreshold
  }
  try {
    const info = await getModelInfo()
    if (info && info.thresholds && typeof info.thresholds.block === 'number') {
      cachedBlockThreshold = info.thresholds.block
      lastFetchedTime = now
    }
  } catch (e) {
    logger.debug('[AI] Failed to fetch threshold from AI engine, using cached value: ' + e.message)
  }
  return cachedBlockThreshold
}

module.exports = {
  getHealth,
  getModelInfo,
  getModelStats,
  predictRecord,
  runFullPipeline,
  predictHoneypotSession,
  getDeceptionScore,
  getBlockThreshold,
}
