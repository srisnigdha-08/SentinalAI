// Display helpers for the per-threat SHAP explanation (GET /api/threats/:id/explanation, XAI-001).

const REASON_TEXT = {
  NO_LINKED_PREDICTION: 'This threat did not come from a scored network flow (for example a honeypot session), so there is no model input to explain.',
  PREDICTION_MISSING: 'The prediction behind this threat is no longer stored.',
  NOT_A_FLOW: 'Only network-flow predictions can be explained.',
  NO_STORED_VECTOR: 'No feature vector was stored for this prediction (older record, or the engine was degraded when it was scored).',
  SCHEMA_MISMATCH: 'The stored features use a different schema than the engine serves now.',
  MODEL_VERSION_MISMATCH: 'The engine now serves a different model than the one that made this decision, so its explanation would not describe it.',
  NOT_REPRODUCED: 'Re-scoring the stored features did not reproduce this prediction, so no explanation is shown.',
  ENGINE_UNAVAILABLE: 'The AI engine is unavailable. Try again when it is back.',
  EXPLAINER_UNAVAILABLE: 'The served model has no SHAP explainer loaded.',
}

/** { reason, message, retryable } for a failed explanation request (axios error). */
export function explanationError(err) {
  const status = err?.response?.status
  const reason = err?.response?.data?.errors?.reason || (status === 403 ? 'FORBIDDEN' : status ? `HTTP_${status}` : 'NETWORK')
  if (reason === 'FORBIDDEN') return { reason, message: 'Only analysts and admins can view model explanations.', retryable: false }
  const message = REASON_TEXT[reason] || err?.response?.data?.error || 'The explanation could not be loaded.'
  const retryable = reason === 'ENGINE_UNAVAILABLE' || reason === 'NETWORK' || (status >= 500 && reason !== 'EXPLAINER_UNAVAILABLE')
  return { reason, message, retryable }
}

/**
 * The `limit` contributions with the largest magnitude, as chart rows, plus how much the rest add up to.
 * direction: 'toward' pushes the model towards the explained class, 'away' pushes it away.
 */
export function contributionRows(contributions, limit = 10) {
  const all = (Array.isArray(contributions) ? contributions : [])
    .filter(c => c && typeof c.feature === 'string' && Number.isFinite(Number(c.contribution)))
    .map(c => ({ feature: c.feature, contribution: Number(c.contribution), value: c.value }))
    .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
  const rows = all.slice(0, limit).map(c => ({
    ...c,
    contribution: Number(c.contribution.toFixed(4)),
    direction: c.contribution >= 0 ? 'toward' : 'away',
  }))
  const rest = all.slice(limit)
  return { rows, restCount: rest.length, restSum: Number(rest.reduce((s, c) => s + c.contribution, 0).toFixed(4)) }
}

const pct = (x) => (Number.isFinite(Number(x)) ? `${(Number(x) * 100).toFixed(1)}%` : '—')

/** One plain-language sentence for the analyst. */
export function explanationSummary(exp) {
  if (!exp) return ''
  const { rows } = contributionRows(exp.contributions, 10)
  const toward = rows.filter(r => r.direction === 'toward').slice(0, 3).map(r => r.feature)
  const away = rows.filter(r => r.direction === 'away').slice(0, 2).map(r => r.feature)
  const cls = exp.explainedClass || exp.predictedClass
  let s = `The classifier chose ${cls} with ${pct(exp.confidence)} confidence.`
  if (exp.predictedClass && exp.explainedClass && exp.predictedClass !== exp.explainedClass) {
    s += ` The verdict shown on the threat (${exp.predictedClass}) also reflects the anomaly detector, which SHAP does not cover.`
  }
  if (toward.length) s += ` Features pushing hardest towards ${cls}: ${toward.join(', ')}.`
  if (away.length) s += ` Pushing against it: ${away.join(', ')}.`
  return s
}

export { pct as formatPercent }
