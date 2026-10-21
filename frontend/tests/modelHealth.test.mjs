import test from 'node:test'
import assert from 'node:assert/strict'
import { driftSummary, topShiftRows, classMixRows, recommendationSummary, globalShapRows } from '../src/utils/modelHealth.js'

test('missing drift report is shown as unavailable, never as healthy', () => {
  for (const report of [null, undefined, 'x']) assert.equal(driftSummary(report).label, 'UNAVAILABLE')
})
test('insufficient data reports progress toward the minimum sample count', () => {
  const s = driftSummary({ status: 'insufficient_data', samples: 40, min_samples: 200 })
  assert.equal(s.label, 'COLLECTING SAMPLES')
  assert.match(s.detail, /40 of 200/)
})
test('drift report states drifted feature count and fraction', () => {
  const s = driftSummary({ status: 'drift', samples: 2000, informative_features: 40, drifted_fraction: 0.125,
    drifted_features: ['a', 'b', 'c', 'd', 'e'] })
  assert.equal(s.badgeType, 'warn')
  assert.match(s.detail, /5 of 40 features .*12\.5%.*2000 flows/)
})
test('top shift rows flag only drifted features and respect the limit', () => {
  const rows = topShiftRows({ drifted_features: ['x'], top_shifts: [
    { feature: 'x', mean_shift_sd: 1.234, variance_ratio: 5 },
    { feature: 'y', mean_shift_sd: 0.1, variance_ratio: 1 },
    { feature: 'z', mean_shift_sd: 0.05, variance_ratio: 1 },
  ] }, 2)
  assert.deepEqual(rows.map(r => [r.feature, r.value, r.flagged]), [['x', '1.23 · 5.00×', true], ['y', '0.10 · 1.00×', false]])
})
test('class mix is sorted with percentages', () => {
  assert.deepEqual(classMixRows({ recent_class_mix: { BENIGN: 3, DDoS: 1 } }),
    [{ cls: 'BENIGN', count: 3, pct: '75.0' }, { cls: 'DDoS', count: 1, pct: '25.0' }])
  assert.deepEqual(classMixRows({}), [])
})
test('recommendation wording distinguishes keep, switch and exploration', () => {
  assert.equal(recommendationSummary(null), null)
  assert.equal(recommendationSummary({ activeProfile: 'centos_7', nextProfile: 'centos_7', explored: false }), 'Keep serving centos_7.')
  assert.match(recommendationSummary({ activeProfile: 'centos_7', nextProfile: 'aws_ec2', explored: true }), /centos_7 → aws_ec2 \(exploration pick\)/)
})

test('PSI drift rows show the PSI value', () => {
  const rows = topShiftRows({ drifted_features: ['a'], top_shifts: [{ feature: 'a', psi: 0.4123 }] })
  assert.deepEqual(rows, [{ feature: 'a', value: 'PSI 0.412', flagged: true }])
})

test('global SHAP rows scale bars to the largest contribution', () => {
  assert.deepEqual(globalShapRows(null), [])
  const rows = globalShapRows({ overall: [{ feature: 'a', mean_abs_shap: 0.2 }, { feature: 'b', mean_abs_shap: 0.05 }] })
  assert.deepEqual(rows, [{ feature: 'a', value: '0.2000', pct: 100 }, { feature: 'b', value: '0.0500', pct: 25 }])
})

test('UCB1 recommendations are not described as Q-values', () => {
  assert.match(recommendationSummary({ activeProfile: 'centos_7', nextProfile: 'aws_ec2', explored: false, policy: 'ucb1' }), /upper confidence bound/)
})
