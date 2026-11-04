'use strict'

/**
 * One severity scale for engine and backend (M1), anchored on the shared operating lines fetched from the
 * AI engine (/model/info): CRITICAL at/above the block line, HIGH at/above the alert line, MEDIUM from 0.50,
 * LOW below. Mirrors ai-engine/inference/predictor.py score_to_severity.
 */
const SEVERITY_MEDIUM = 0.5
// Defaults of the engine's ALERT_THRESHOLD / BLOCK_THRESHOLD, used until /model/info has been read (and by scripts
// such as utils/seed.js that run without the engine).
const DEFAULT_ALERT_THRESHOLD = 0.9
const DEFAULT_BLOCK_THRESHOLD = 0.92

const severityFor = (score, { alertThreshold, blockThreshold }) => {
  const s = Number(score)
  if (s >= blockThreshold) return 'CRITICAL'
  if (s >= alertThreshold) return 'HIGH'
  if (s >= SEVERITY_MEDIUM) return 'MEDIUM'
  return 'LOW'
}

// Last alert line read from /model/info. Kept here, not read from aiEngineService, so containment code and scripts
// that run without the engine configuration (SENTINEL_KEY) never load the engine client (THR-002).
let alertLine = DEFAULT_ALERT_THRESHOLD

/** Called by aiEngineService whenever /model/info reports the engine's alert line. */
const recordAlertLine = (value) => {
  if (Number.isFinite(value) && value > 0 && value <= 1) alertLine = value
}

/** The backend's current alert line without a network call. For unblock/rollback/expiry paths. */
const currentAlertLine = () => alertLine

/**
 * Status a BLOCKED threat returns to when it is released. Its saved preBlockStatus when there is one; otherwise
 * (seeded or legacy rows) the state the pipeline would have given that score: MONITORING at/above the alert line,
 * DETECTED below it. Was a fixed 0.70 before THR-002.
 */
const restoreStatusFor = (threat, alertThreshold = currentAlertLine()) =>
  threat.preBlockStatus || (Number(threat.aiScore) >= alertThreshold ? 'MONITORING' : 'DETECTED')

module.exports = {
  severityFor,
  restoreStatusFor,
  currentAlertLine,
  recordAlertLine,
  SEVERITY_MEDIUM,
  DEFAULT_ALERT_THRESHOLD,
  DEFAULT_BLOCK_THRESHOLD,
}
