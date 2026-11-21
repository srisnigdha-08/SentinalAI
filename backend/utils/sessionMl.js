'use strict'
/**
 * Honeypot-session ML (docs/SESSION_ML.md): the shadow-only "sessionML" block the AI engine returns next to the
 * rule-based classification on /predict/honeypot/internal.
 *
 * Only a whitelisted, type-checked subset is stored on the session (HoneypotSession.sessionMl). Nothing here reads
 * commands, credentials or IP addresses, and the stored record holds none. A block that claims a prediction it
 * cannot support (wrong session, non-OK status, invalid score) is stored as INVALID_RESULT with no prediction.
 * The stored record is informational: no containment, alert, threat or score path reads it.
 */
const STATUSES = Object.freeze([
  'OK',
  'DISABLED',
  'MODEL_UNAVAILABLE',
  'INVALID_ARTIFACT',
  'INCOMPATIBLE_SCHEMA',
  'INVALID_INPUT',
  'INFERENCE_ERROR',
  // set by the backend
  'ENGINE_UNAVAILABLE',
  'NOT_REPORTED',
  'INVALID_RESULT',
])
const EVIDENCE_SOURCES = ['operator', 'external', 'simulated', 'unknown']
const CODE = /^[A-Z][A-Z0-9_]{0,63}$/
const LABEL = /^[A-Za-z0-9 _./-]{1,64}$/

const str = (v, max) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null)
const score01 = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1 ? v : null)

function base(sessionId, status, reason) {
  return {
    status,
    reason: reason ? String(reason).slice(0, 200) : null,
    shadowOnly: true,
    mode: null,
    prediction: null,
    score: null,
    calibrated: false,
    modelName: null,
    modelVersion: null,
    featureSchemaVersion: null,
    reasonCodes: [],
    evidenceSource: null,
    sessionId: sessionId || null,
    inferredAt: new Date(),
  }
}

/** The engine was not reached (or answered without a result): the ML block is honestly absent. */
function engineUnavailable(sessionId) {
  return base(sessionId, 'ENGINE_UNAVAILABLE', 'AI engine unavailable; rule-based analysis pending as well')
}

/** Validate and reduce the engine's sessionML block for storage. */
function sanitizeSessionMl(raw, sessionId) {
  if (raw === undefined || raw === null) return base(sessionId, 'NOT_REPORTED', 'engine did not report sessionML')
  if (typeof raw !== 'object' || Array.isArray(raw)) return base(sessionId, 'INVALID_RESULT', 'not an object')
  const status = STATUSES.includes(raw.status) ? raw.status : null
  if (!status || ['ENGINE_UNAVAILABLE', 'NOT_REPORTED', 'INVALID_RESULT'].includes(raw.status))
    return base(sessionId, 'INVALID_RESULT', 'unknown status')
  if (raw.sessionId !== undefined && raw.sessionId !== null && raw.sessionId !== sessionId)
    return base(sessionId, 'INVALID_RESULT', 'result is for a different session')
  if (raw.shadowOnly !== true) return base(sessionId, 'INVALID_RESULT', 'result is not marked shadow-only')
  const out = base(sessionId, status, str(raw.reason, 200))
  out.mode = raw.mode === 'off' ? 'off' : 'shadow'
  out.modelName = str(raw.modelName, 64)
  out.modelVersion = str(raw.modelVersion, 64)
  out.featureSchemaVersion = str(raw.featureSchemaVersion, 32)
  out.calibrated = raw.calibrated === true
  out.evidenceSource = EVIDENCE_SOURCES.includes(raw.evidenceSource) ? raw.evidenceSource : 'unknown'
  out.reasonCodes = Array.isArray(raw.reasonCodes)
    ? [...new Set(raw.reasonCodes.filter((c) => typeof c === 'string' && CODE.test(c)))].slice(0, 40)
    : []
  const at = raw.inferredAt ? new Date(raw.inferredAt) : null
  if (at && !isNaN(at.getTime())) out.inferredAt = at
  if (status === 'OK') {
    const prediction = typeof raw.prediction === 'string' && LABEL.test(raw.prediction) ? raw.prediction : null
    const score = score01(raw.score)
    if (!prediction || score === null || !out.modelVersion)
      return { ...base(sessionId, 'INVALID_RESULT', 'OK result without a valid prediction, score or model version') }
    out.prediction = prediction
    out.score = score
  }
  return out
}

module.exports = { STATUSES, sanitizeSessionMl, engineUnavailable }
