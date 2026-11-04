// Display bands for threat scores, on the same scale the backend uses for severity (backend/utils/severity.js):
// CRITICAL at/above the block line, HIGH at/above the alert line (where the pipeline raises a threat).
// THR-002 replaced a fixed 0.70 line; THR-003: the lines come from GET /api/ai/score-lines (what the backend scores
// with, so an engine started with another ALERT_THRESHOLD/BLOCK_THRESHOLD is reflected). Until that answers, or if
// it answers nonsense, the engine defaults apply. Every helper takes the lines as an optional last argument.
export const ALERT_LINE = 0.9
export const BLOCK_LINE = 0.92
export const DEFAULT_LINES = Object.freeze({ alert: ALERT_LINE, block: BLOCK_LINE })

const RED = '#ff2d55'
const AMBER = '#ffaa00'
const BLUE = '#00d4ff'

/** Validated { alert, block } from the API (0 < alert <= block <= 1), else the defaults. */
export function normalizeLines(raw) {
  const alert = Number(raw?.alert)
  const block = Number(raw?.block)
  const valid = Number.isFinite(alert) && Number.isFinite(block) && alert > 0 && alert <= block && block <= 1
  return valid ? { alert, block } : { ...DEFAULT_LINES }
}

// Array.map passes an index as the second argument; anything that is not a lines object means "defaults".
const lines = (l) => (l && typeof l === 'object' ? l : DEFAULT_LINES)
const score = (s) => Number(s) || 0

export function scoreColor(s, l) {
  const { alert, block } = lines(l)
  return score(s) >= block ? RED : score(s) >= alert ? AMBER : BLUE
}

/** Inference-log line type ('err' | 'warn' | 'out') for a score. */
export function scoreLogType(s, l) {
  const { alert, block } = lines(l)
  return score(s) >= block ? 'err' : score(s) >= alert ? 'warn' : 'out'
}

export function isAlertScore(s, l) {
  return score(s) >= lines(l).alert
}

/** Severity label for a live-feed AI prediction: the server's value, else the band the score falls in. */
export function liveSeverity(prediction, l) {
  return prediction?.severity || (score(prediction?.threatScore) >= lines(l).block ? 'CRITICAL' : 'HIGH')
}
