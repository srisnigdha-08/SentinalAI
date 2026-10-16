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
  const r = await predictRecord(record)
  if (!r?.result) return null
  const { result } = r
  const score = result.threatScore || 0
  const blockThreshold = await getBlockThreshold()
  const action = score >= blockThreshold ? 'BLOCK' : score >= 0.7 ? 'MONITOR' : 'ALLOW'
  logger.info(
    '[AI Pipeline] ' +
      record.sourceIP +
      ' -> ' +
      result.predictedClass +
      ' (' +
      Math.round(score * 100) +
      '%) -> ' +
      action
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
    })
  } catch (err) {
    logger.error('[AI Pipeline] Failed to persist prediction: ' + err.name)
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
