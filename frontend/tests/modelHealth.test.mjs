import test from 'node:test'
import assert from 'node:assert/strict'
import { driftSummary, topShiftRows, classMixRows, recommendationSummary, globalShapRows, learnerProvenanceSummary, policyLabel } from '../src/utils/modelHealth.js'

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

test('PSI drift counts only benign-classified flows, as the engine does (UI-005)', () => {
  // 500 recent flows, 150 of them classified BENIGN: the engine needs 200 benign ones before it assesses drift
  const waiting = driftSummary({ method: 'psi_benign_quantiles', status: 'insufficient_data', samples: 500, benign_samples: 150, min_samples: 200 })
  assert.match(waiting.detail, /150 of 200 benign-classified flows/)
  const ok = driftSummary({ method: 'psi_benign_quantiles', status: 'ok', samples: 2000, benign_samples: 1800,
    informative_features: 40, drifted_fraction: 0, drifted_features: [] })
  assert.match(ok.detail, /over the last 1800 benign-classified flows/)
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

test('learner provenance never presents the synthetic seed as attacker data', () => {
  assert.equal(learnerProvenanceSummary(null), 'Training data origin unknown (Q-table predates provenance tracking).')
  assert.equal(learnerProvenanceSummary({ seedEpisodes: 12087, sessionEpisodes: 1, synthetic: true }),
    '1 update from scored sessions; 12087 inherited from a synthetic warm start, not attacker data.')
  assert.equal(learnerProvenanceSummary({ seedEpisodes: 0, sessionEpisodes: 4, synthetic: false }),
    '4 updates from scored sessions; started from an empty table.')
})

test('decision status names the persisted decision and says a refresh reuses it (RL-001)', async () => {
  const { decisionStatusSummary } = await import('../src/utils/modelHealth.js')
  assert.equal(decisionStatusSummary(null), null)
  assert.equal(decisionStatusSummary({ nextProfile: 'aws_ec2' }), null)
  const s = decisionStatusSummary({ decisionId: '6721a0c3f1e2d3c4b5a69788', decisionReused: true })
  assert.match(s, /…b5a69788 \(already pending\)/)
  assert.match(s, /until the rotator applies it or it expires/)
  assert.match(decisionStatusSummary({ decisionId: 'abc', decisionReused: false }), /just drawn/)
})

test('persona policy v2 recommendations are labelled as a confidence bound, not a Q-value', () => {
  const rec = { activeProfile: 'ubuntu_22', nextProfile: 'debian_11', explored: false, policy: 'persona-ducb-v2' }
  assert.match(recommendationSummary(rec), /upper confidence bound/)
  assert.doesNotMatch(recommendationSummary(rec), /Q-value/)
  assert.equal(policyLabel('persona-ducb-v2'), 'Persona policy v2 (discounted UCB)')
  assert.equal(policyLabel('q_learning'), 'Q-learner')
  assert.equal(policyLabel('ucb1'), 'Bandit (UCB1)')
})
