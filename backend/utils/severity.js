'use strict'

/**
 * One severity scale for engine and backend (M1), anchored on the shared operating lines fetched from the
 * AI engine (/model/info): CRITICAL at/above the block line, HIGH at/above the alert line, MEDIUM from 0.50,
 * LOW below. Mirrors ai-engine/inference/predictor.py score_to_severity.
 */
const SEVERITY_MEDIUM = 0.5

const severityFor = (score, { alertThreshold, blockThreshold }) => {
  const s = Number(score)
  if (s >= blockThreshold) return 'CRITICAL'
  if (s >= alertThreshold) return 'HIGH'
  if (s >= SEVERITY_MEDIUM) return 'MEDIUM'
  return 'LOW'
}

module.exports = { severityFor, SEVERITY_MEDIUM }
