import test from 'node:test'
import assert from 'node:assert/strict'
import { contributionRows, explanationError, explanationSummary } from '../src/utils/threatExplanation.js'

const contributions = [
  { feature: 'flow_duration', contribution: -0.4, value: 1200 },
  { feature: 'init_win_bytes_forward', contribution: 2.1, value: 8192 },
  { feature: 'fin_flag_count', contribution: 0.05, value: 0 },
  { feature: 'bad', contribution: 'NaN' },
]

test('contribution rows are ranked by magnitude, signed, and summarise the rest', () => {
  const { rows, restCount, restSum } = contributionRows(contributions, 2)
  assert.deepEqual(rows.map(r => r.feature), ['init_win_bytes_forward', 'flow_duration'])
  assert.deepEqual(rows.map(r => r.direction), ['toward', 'away'])
  assert.equal(restCount, 1)
  assert.equal(restSum, 0.05)
  assert.deepEqual(contributionRows(null).rows, [])
})

test('refusal reasons map to analyst-readable messages; only outages are retryable', () => {
  const err = (status, reason) => ({ response: { status, data: { errors: reason ? { reason } : undefined, error: 'server text' } } })
  const notRepro = explanationError(err(409, 'NOT_REPRODUCED'))
  assert.equal(notRepro.reason, 'NOT_REPRODUCED')
  assert.match(notRepro.message, /did not reproduce/)
  assert.equal(notRepro.retryable, false)
  assert.equal(explanationError(err(503, 'ENGINE_UNAVAILABLE')).retryable, true)
  assert.equal(explanationError(err(503, 'EXPLAINER_UNAVAILABLE')).retryable, false)
  assert.match(explanationError(err(403)).message, /analysts and admins/)
  assert.equal(explanationError({}).reason, 'NETWORK')
  assert.equal(explanationError(err(400)).message, 'server text')
})

test('summary names the class, confidence and the strongest features, and flags the anomaly-only part', () => {
  const s = explanationSummary({ predictedClass: 'DDoS', explainedClass: 'DDoS', confidence: 0.973, contributions })
  assert.match(s, /chose DDoS with 97\.3% confidence/)
  assert.match(s, /towards DDoS: init_win_bytes_forward, fin_flag_count/)
  assert.match(s, /against it: flow_duration/)
  const unknown = explanationSummary({ predictedClass: 'Unknown', explainedClass: 'BENIGN', confidence: 0.9, contributions })
  assert.match(unknown, /anomaly detector, which SHAP does not cover/)
  assert.equal(explanationSummary(null), '')
})
