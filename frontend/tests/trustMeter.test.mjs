// AI Trust Meter presentation helpers: labels follow the backend assessment, missing data shows as unavailable,
// dataset-level metrics stay out of per-prediction text, and no trust percentage is computed anywhere.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { MODEL_LIMITATIONS, REASON_KIND, STATE_KEYS, STATE_META, anomalySummary, inputSummary, pct, stateSummary } from '../src/utils/trustMeter.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')

test('every backend state has a label, an icon and a description; none uses alarm red', () => {
  assert.deepEqual(STATE_KEYS.sort(), ['INCOMPLETE', 'INSUFFICIENT', 'NO_ISSUES', 'REVIEW', 'UNAVAILABLE'])
  for (const s of STATE_KEYS) {
    assert.ok(STATE_META[s].label && STATE_META[s].icon && STATE_META[s].description)
    assert.notEqual(STATE_META[s].color.toLowerCase(), '#ff2d55')
  }
  assert.match(STATE_META.NO_ISSUES.description, /does not establish that the prediction is correct/)
  assert.deepEqual(Object.keys(REASON_KIND).sort(), ['blocks', 'info', 'limits', 'unknown'])
})

test('pct formats real numbers and never invents a value', () => {
  assert.equal(pct(0.974), '97.4%')
  assert.equal(pct(0), '0.0%')
  for (const v of [null, undefined, NaN, Infinity, '0.9']) assert.equal(pct(v), 'Unavailable')
})

test('list summary names the first limiting reason, ignores context, and handles missing assessments', () => {
  assert.equal(stateSummary(null), 'Not assessed')
  assert.equal(stateSummary({ state: 'NO_ISSUES', reasons: [{ kind: 'info', title: 'Capture source not recorded' }] }), 'No identified issues')
  assert.equal(
    stateSummary({ state: 'INCOMPLETE', reasons: [{ kind: 'limits', title: '4 input features were missing' }, { kind: 'limits', title: 'Non-zero serving defaults were used' }, { kind: 'info', title: 'x' }] }),
    '4 input features were missing (+1 more)'
  )
  assert.equal(stateSummary({ state: 'REVIEW' }), 'Review recommended')
})

test('input summary distinguishes complete, incomplete (with or without the list) and unverifiable', () => {
  const base = { callerExpected: 50, engineDerived: 3, expectedFeatures: 53 }
  assert.equal(inputSummary({ ...base, status: 'complete', providedCount: 50 }), '50 of 50 caller features sent (+3 engine-derived = 53)')
  assert.equal(inputSummary({ ...base, status: 'incomplete', defaultedRecorded: true, defaultedCount: 4 }), '4 of 50 caller features missing (defaults used)')
  assert.match(inputSummary({ ...base, status: 'incomplete', defaultedRecorded: false }), /missing features not recorded/)
  assert.equal(inputSummary({ ...base, status: 'unverified' }), 'Completeness not recorded for this prediction')
  assert.equal(inputSummary(undefined), 'Unavailable')
})

test('anomaly summary never calls the signal a probability', () => {
  assert.equal(anomalySummary(undefined), 'Not recorded')
  assert.equal(anomalySummary({ status: 'unavailable' }), 'Not recorded')
  assert.match(anomalySummary({ status: 'uninterpretable', anomalyScore: -2 }), /not interpreted/)
  assert.equal(anomalySummary({ status: 'available', isAnomaly: true, anomalyScore: 0.4 }), 'Flagged as unusual (signal 0.4)')
  assert.match(anomalySummary({ status: 'available', isAnomaly: false, anomalyScore: 0 }), /Not flagged/)
  for (const s of [anomalySummary({ status: 'available', isAnomaly: true, anomalyScore: 1 })]) assert.doesNotMatch(s, /probab|%/)
})

test('model limitations: three separate documented evaluations, each with a source and caveat', () => {
  assert.equal(MODEL_LIMITATIONS.evaluations.length, 3)
  for (const e of MODEL_LIMITATIONS.evaluations) assert.ok(e.result && e.caveat && e.source)
  const text = JSON.stringify(MODEL_LIMITATIONS)
  assert.match(text, /98\.97%/)
  assert.match(text, /15\.2% attack recall/)
  assert.match(text, /0\.24% benign false-alarm/)
  assert.match(MODEL_LIMITATIONS.takeaway, /do not show that any single prediction is right or wrong/)
})

test('no trust percentage or reliability score is computed in the Trust Meter source', () => {
  const files = [join(SRC, 'utils', 'trustMeter.js'), join(SRC, 'pages', 'AITrustMeter.jsx'),
    ...readdirSync(join(SRC, 'components', 'trustMeter')).map((f) => join(SRC, 'components', 'trustMeter', f))]
  for (const f of files) {
    const src = readFileSync(f, 'utf8')
    assert.doesNotMatch(src, /trustScore|reliabilityScore|trustPercent|% trust/i, f)
    assert.doesNotMatch(src, /dangerouslySetInnerHTML/, f)
  }
})
