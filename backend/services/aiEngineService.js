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
// Forward the caller's correlation id so one request can be followed in both services' logs.
ai.interceptors?.request.use((config) => {
  const requestId = require('../utils/requestContext').getRequestId()
  if (requestId) config.headers = { ...config.headers, 'X-Request-Id': requestId }
  return config
})

// Fail fast while the engine is down instead of waiting out a timeout per call, and retry fast transient
// failures. Only stateless calls retry: /deception/score updates the Q-table and must not run twice.
const { CircuitBreaker, withRetry } = require('../utils/circuitBreaker')
const breaker = new CircuitBreaker({
  failureThreshold: parseInt(process.env.AI_CIRCUIT_FAILURES, 10) || 5,
  resetTimeoutMs: parseInt(process.env.AI_CIRCUIT_RESET_MS, 10) || 30000,
})
const metrics = require('../utils/metrics')
const guarded = async (call, { retry = false } = {}) => {
  try {
    const result = await breaker.exec(() => (retry ? withRetry(call) : call()))
    metrics.inc('sentinel_ai_engine_calls_total', 'Calls to the AI engine by outcome', { outcome: 'ok' })
    return result
  } catch (err) {
    const outcome =
      err.code === 'CIRCUIT_OPEN' ? 'circuit_open' : err.response ? `http_${err.response.status}` : 'error'
    metrics.inc('sentinel_ai_engine_calls_total', 'Calls to the AI engine by outcome', { outcome })
    throw err
  }
}
const getHealth = async () => {
  try {
    const readiness = (await guarded(() => ai.get('/ready', { timeout: 1500 }))).data
    if (readiness?.status !== 'ok') return { status: 'unreachable', error: 'Required AI models unavailable' }
    await ai.get('/model/info', { timeout: 1500 })
    return { ...readiness, authenticated: true }
  } catch {
    return { status: 'unreachable', error: 'AI readiness or service authentication unavailable' }
  }
}
const getModelInfo = async () => {
  try {
    return (await guarded(() => ai.get('/model/info'), { retry: true })).data
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
    return (await guarded(() => ai.post('/predict/internal', record), { retry: true })).data
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
const runFullPipeline = async (record, _io = null) => {
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
  const alertThreshold = await module.exports.getAlertThreshold()

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
    action = score >= blockThreshold ? 'BLOCK' : score >= alertThreshold ? 'MONITOR' : 'ALLOW'
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
    return (await guarded(() => ai.post('/predict/honeypot/internal', session), { retry: true })).data
  } catch (e) {
    logger.warn('[AI] honeypot predict failed: ' + e.message)
    return null
  }
}
const getDeceptionScore = async (session) => {
  try {
    return (await guarded(() => ai.post('/deception/score', session))).data
  } catch (e) {
    logger.warn('[AI] deception scoring failed: ' + e.message)
    return null
  }
}

// Thresholds come from the AI engine (/model/info) so the engine and the backend use one alert line and
// one block line. Fallbacks apply only until the first successful fetch.
const DEFAULT_BLOCK_THRESHOLD = 0.92
const DEFAULT_ALERT_THRESHOLD = 0.85
let cachedBlockThreshold = DEFAULT_BLOCK_THRESHOLD
let cachedAlertThreshold = DEFAULT_ALERT_THRESHOLD
let lastFetchedTime = 0
const CACHE_TTL_MS = 60000 // Cache for 1 minute
const THRESHOLD_FETCH_TIMEOUT_MS = 1500

const refreshThresholds = async () => {
  const now = Date.now()
  if (now - lastFetchedTime < CACHE_TTL_MS) return
  // Back off on failure too: otherwise every call during an AI outage waits out a fresh timeout.
  lastFetchedTime = now
  try {
    const info = (await guarded(() => ai.get('/model/info', { timeout: THRESHOLD_FETCH_TIMEOUT_MS }))).data
    if (typeof info?.thresholds?.block === 'number') cachedBlockThreshold = info.thresholds.block
    if (typeof info?.thresholds?.monitor === 'number') cachedAlertThreshold = info.thresholds.monitor
  } catch (e) {
    logger.debug('[AI] Failed to fetch thresholds from AI engine, using cached values: ' + e.message)
  }
}

const getBlockThreshold = async () => {
  await refreshThresholds()
  return cachedBlockThreshold
}

/** Score at or above which a non-BENIGN prediction becomes a ThreatLog/alert (the engine's MONITOR line). */
const getAlertThreshold = async () => {
  await refreshThresholds()
  return cachedAlertThreshold
}

/** Forces the next threshold lookup to hit the engine (after a model reload). */
const invalidateThresholds = () => {
  lastFetchedTime = 0
}

/** Ask the engine to load the models pinned in its registry; it keeps the old model if that fails. */
const reloadModel = async () => {
  try {
    const data = (await ai.post('/model/reload', null, { timeout: 120000 })).data
    invalidateThresholds()
    return data
  } catch (e) {
    const error = new Error(e.response?.data?.detail || 'AI engine model reload failed')
    error.statusCode = e.response?.status === 409 ? 409 : 503
    throw error
  }
}

const getDrift = async () => {
  try {
    return (await guarded(() => ai.get('/model/drift'), { retry: true })).data
  } catch {
    return null
  }
}

const getDeceptionRecommendation = async (currentProfile) => {
  try {
    return (
      await guarded(() => ai.get('/deception/recommendation', { params: { current: currentProfile } }), { retry: true })
    ).data
  } catch {
    return null
  }
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
  getAlertThreshold,
  invalidateThresholds,
  reloadModel,
  getDrift,
  getDeceptionRecommendation,
  circuitState: () => breaker.state,
  resetCircuit: () => breaker.reset(),
}
