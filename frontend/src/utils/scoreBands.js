// Display bands for threat scores, on the same scale the backend uses for severity (backend/utils/severity.js):
// CRITICAL at/above the block line, HIGH at/above the alert line (where the pipeline raises a threat). These are the
// engine's ALERT_THRESHOLD / BLOCK_THRESHOLD defaults; a deployment that overrides them changes only the colours here.
// THR-002: the dashboard used a fixed 0.70 line.
export const ALERT_LINE = 0.9
export const BLOCK_LINE = 0.92

const RED = '#ff2d55'
const AMBER = '#ffaa00'
const BLUE = '#00d4ff'

export function scoreColor(score) {
  const s = Number(score) || 0
  return s >= BLOCK_LINE ? RED : s >= ALERT_LINE ? AMBER : BLUE
}

/** Inference-log line type ('err' | 'warn' | 'out') for a score. */
export function scoreLogType(score) {
  const s = Number(score) || 0
  return s >= BLOCK_LINE ? 'err' : s >= ALERT_LINE ? 'warn' : 'out'
}

export function isAlertScore(score) {
  return (Number(score) || 0) >= ALERT_LINE
}

/** Severity label for a live-feed AI prediction: the server's value, else the band the score falls in. */
export function liveSeverity(prediction) {
  return prediction?.severity || ((Number(prediction?.threatScore) || 0) >= BLOCK_LINE ? 'CRITICAL' : 'HIGH')
}
