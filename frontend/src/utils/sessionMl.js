// Honeypot-session ML presentation (docs/SESSION_ML.md). The ML block is SHADOW ONLY and separate from the
// rule-based classification: it is never merged into one score, and it is shown as a prediction only when the engine
// returned a valid one. Every other state is shown as what it is (no model, engine down, failed, invalid).

export const SESSION_ML_STATE = Object.freeze({
  OK: { label: 'SHADOW PREDICTION', color: '#b388ff' },
  MODEL_UNAVAILABLE: { label: 'NO MODEL (insufficient labelled data)', color: '#8ba3b5' },
  DISABLED: { label: 'ML OFF', color: '#8ba3b5' },
  ENGINE_UNAVAILABLE: { label: 'AI ENGINE UNAVAILABLE', color: '#ffaa00' },
  NOT_REPORTED: { label: 'NOT REPORTED', color: '#8ba3b5' },
  INVALID_ARTIFACT: { label: 'MODEL ARTIFACT INVALID', color: '#ff6b6b' },
  INCOMPATIBLE_SCHEMA: { label: 'MODEL INCOMPATIBLE', color: '#ff6b6b' },
  INVALID_INPUT: { label: 'SESSION NOT CLASSIFIABLE', color: '#ffaa00' },
  INFERENCE_ERROR: { label: 'INFERENCE FAILED', color: '#ff6b6b' },
  INVALID_RESULT: { label: 'RESULT REJECTED', color: '#ff6b6b' },
})

const SAFE_LABEL = /^[A-Za-z0-9 _./-]{1,64}$/
const finite01 = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0 && v <= 1

/**
 * What to show for one session's ML block. Returns { state, label, color, prediction, scoreText, details, title }.
 * A prediction is returned only for status OK with a safe label and a score in [0, 1]; otherwise prediction is null.
 */
export function sessionMlView(ml) {
  if (!ml || typeof ml !== 'object') {
    return {
      state: 'ABSENT',
      label: 'NOT CLASSIFIED BY ML',
      color: '#8ba3b5',
      prediction: null,
      scoreText: null,
      details: [],
      title: 'This session has no ML record (closed before session ML existed, or not yet analysed).',
    }
  }
  const known = Object.prototype.hasOwnProperty.call(SESSION_ML_STATE, ml.status) ? ml.status : 'INVALID_RESULT'
  let state = known
  let prediction = null
  let scoreText = null
  if (state === 'OK') {
    if (typeof ml.prediction === 'string' && SAFE_LABEL.test(ml.prediction) && finite01(ml.score) && ml.modelVersion) {
      prediction = ml.prediction
      // Logistic-regression output is not calibrated unless the artifact says so: say what the number is.
      scoreText = `${Math.round(ml.score * 100)}% model score${ml.calibrated === true ? ' (calibrated)' : ' (uncalibrated, not a probability of being correct)'}`
    } else {
      state = 'INVALID_RESULT'
    }
  }
  const meta = SESSION_ML_STATE[state]
  const details = []
  if (ml.modelVersion && prediction) details.push(`model ${ml.modelVersion}`)
  if (ml.featureSchemaVersion) details.push(`schema ${ml.featureSchemaVersion}`)
  if (ml.evidenceSource) details.push(`source ${ml.evidenceSource}`)
  const at = ml.inferredAt ? new Date(ml.inferredAt) : null
  if (at && !Number.isNaN(at.getTime())) details.push(`at ${at.toISOString().replace('T', ' ').slice(0, 19)}Z`)
  return {
    state,
    label: meta.label,
    color: meta.color,
    prediction,
    scoreText,
    details,
    title:
      'ML session classification, SHADOW ONLY: shown for comparison with the rule-based result and never used for alerts or containment.' +
      (ml.reason ? ` ${String(ml.reason).slice(0, 160)}` : ''),
  }
}

/** Observed behaviours behind a session's ML record (neutral reason codes, not a verdict). */
export function reasonCodeText(codes) {
  if (!Array.isArray(codes)) return []
  return codes
    .filter((c) => typeof c === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(c))
    .slice(0, 8)
    .map((c) => c.toLowerCase().split('_').join(' '))
}

/** The existing rule-based verdict, labelled as such (never mixed with the ML block). */
export function ruleVerdictText(session) {
  if (!session?.aiClassification) return null
  const score = Number.isFinite(session.aiThreatScore) ? ` ${Math.round(session.aiThreatScore * 100)}%` : ''
  return `${String(session.aiClassification).split('_').join(' ')}${score} (rule-based)`
}
