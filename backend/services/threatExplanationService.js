/**
 * On-demand SHAP explanation of one stored threat (XAI-001).
 *
 * The explanation is computed from the feature vector the AI engine returned for that prediction and the backend
 * stored with it (AIPrediction.featureVector, hidden from every API response). Nothing is taken from the client
 * and nothing new is stored. The engine re-scores the exact vector; the explanation is returned only when that
 * reproduces the stored prediction with the same model version. Otherwise the request is refused with a reason,
 * because an explanation of a different decision would be fabricated.
 */
const ThreatLog = require('../models/ThreatLog')
const AIPrediction = require('../models/AIPrediction')
const aiEngineService = require('./aiEngineService')

const VECTOR_LENGTH = 53
// The engine rounds threatScore to 4 decimals; anything beyond rounding means a different decision.
const SCORE_TOLERANCE = 1e-4

class ExplanationError extends Error {
  constructor(reason, statusCode, message) {
    super(message)
    this.reason = reason
    this.statusCode = statusCode
  }
}

const REASONS = {
  THREAT_NOT_FOUND: [404, 'Threat not found.'],
  NO_LINKED_PREDICTION: [
    409,
    'This threat was not produced by a scored network flow (for example a honeypot session or a manual record), so there is no model input to explain.',
  ],
  PREDICTION_MISSING: [409, 'The prediction this threat came from is no longer stored.'],
  NOT_A_FLOW: [409, 'Only network-flow predictions can be explained; this one was not scored from a flow vector.'],
  NO_STORED_VECTOR: [
    409,
    'No usable feature vector is stored for this prediction (stored before vectors were kept, or the engine was degraded when it was scored).',
  ],
  SCHEMA_MISMATCH: [409, 'The stored feature vector uses a different feature schema than the engine serves now.'],
  MODEL_VERSION_MISMATCH: [
    409,
    'The engine now serves a different model than the one that made this prediction; its explanation would not describe this decision.',
  ],
  NOT_REPRODUCED: [
    409,
    'Re-scoring the stored vector did not reproduce the stored prediction, so no explanation is shown.',
  ],
  ENGINE_UNAVAILABLE: [503, 'The AI engine is unavailable; try again when it is back.'],
  EXPLAINER_UNAVAILABLE: [503, 'The served model has no SHAP explainer loaded, so no explanation can be computed.'],
}

const fail = (reason, detail) => {
  const [status, message] = REASONS[reason]
  const err = new ExplanationError(reason, status, message)
  if (detail) err.detail = detail
  return err
}

const isUsableVector = (v) => Array.isArray(v) && v.length === VECTOR_LENGTH && v.every((x) => Number.isFinite(x))

async function explainThreat(threatId) {
  const threat = await ThreatLog.findById(threatId).select('predictionId').lean()
  if (!threat) throw fail('THREAT_NOT_FOUND')
  if (!threat.predictionId) throw fail('NO_LINKED_PREDICTION')

  const pred = await AIPrediction.findById(threat.predictionId)
    .select('+featureVector +featureSchemaVersion inputSource predictedClass threatScore modelVersion createdAt')
    .lean()
  if (!pred) throw fail('PREDICTION_MISSING')
  if (pred.inputSource !== 'network_traffic') throw fail('NOT_A_FLOW')
  if (!isUsableVector(pred.featureVector) || !pred.featureSchemaVersion) throw fail('NO_STORED_VECTOR')

  let r
  try {
    r = await aiEngineService.explainVector(pred.featureVector, pred.featureSchemaVersion)
  } catch (err) {
    const status = err.response?.status
    if (status === 409) throw fail('SCHEMA_MISMATCH')
    if (status === 422) throw fail('NO_STORED_VECTOR')
    throw fail('ENGINE_UNAVAILABLE')
  }
  if (!r) throw fail('ENGINE_UNAVAILABLE')
  if (r.explainerAvailable === false || !Array.isArray(r.contributions) || r.contributions.length === 0) {
    throw fail('EXPLAINER_UNAVAILABLE')
  }
  if (r.modelVersion !== pred.modelVersion) {
    throw fail('MODEL_VERSION_MISMATCH', { predictionModel: pred.modelVersion, engineModel: r.modelVersion })
  }
  if (
    r.predictedClass !== pred.predictedClass ||
    Math.abs(Number(r.threatScore) - pred.threatScore) > SCORE_TOLERANCE
  ) {
    throw fail('NOT_REPRODUCED')
  }

  return {
    threatId: String(threatId),
    predictionId: String(pred._id),
    predictedAt: pred.createdAt,
    modelVersion: pred.modelVersion,
    featureSchemaVersion: pred.featureSchemaVersion,
    predictedClass: pred.predictedClass,
    explainedClass: r.explainedClass,
    threatScore: pred.threatScore,
    confidence: r.confidence,
    classProbabilities: r.classProbabilities,
    isAnomaly: r.isAnomaly,
    baseValue: r.baseValue,
    units: r.units,
    contributions: r.contributions,
    reproduced: true,
  }
}

module.exports = { explainThreat, ExplanationError, REASONS, SCORE_TOLERANCE }
