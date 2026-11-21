import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { SESSION_ML_STATE, sessionMlView, reasonCodeText, ruleVerdictText } from '../src/utils/sessionMl.js'
import { labelMeta } from '../src/utils/capabilities.js'

const OK = {
  status: 'OK',
  prediction: 'dropper',
  score: 0.91,
  calibrated: false,
  modelVersion: 'shadow-0.1',
  featureSchemaVersion: 'session_v2',
  evidenceSource: 'operator',
  inferredAt: '2026-11-13T10:00:00Z',
  shadowOnly: true,
  reasonCodes: ['DOWNLOAD_ATTEMPT', 'EXECUTION_MARKER'],
}

test('a valid shadow prediction is shown with its meaning, model, schema, source and time', () => {
  const v = sessionMlView(OK)
  assert.equal(v.state, 'OK')
  assert.equal(v.prediction, 'dropper')
  assert.match(v.scoreText, /91% model score \(uncalibrated, not a probability of being correct\)/)
  assert.deepEqual(v.details, ['model shadow-0.1', 'schema session_v2', 'source operator', 'at 2026-11-13 10:00:00Z'])
  assert.match(v.title, /SHADOW ONLY/)
  assert.match(v.title, /never used for alerts or containment/)
  assert.match(sessionMlView({ ...OK, calibrated: true }).scoreText, /\(calibrated\)/)
})

test('missing model, engine down and failures show their state, never a prediction', () => {
  for (const status of ['MODEL_UNAVAILABLE', 'ENGINE_UNAVAILABLE', 'INFERENCE_ERROR', 'INVALID_ARTIFACT',
    'INCOMPATIBLE_SCHEMA', 'INVALID_INPUT', 'DISABLED', 'NOT_REPORTED', 'INVALID_RESULT']) {
    const v = sessionMlView({ ...OK, status })
    assert.equal(v.prediction, null, status)
    assert.equal(v.scoreText, null, status)
    assert.equal(v.label, SESSION_ML_STATE[status].label)
    assert.ok(!v.details.some((d) => d.startsWith('model ')), status) // no model version without a prediction
  }
  assert.match(sessionMlView({ status: 'MODEL_UNAVAILABLE' }).label, /insufficient labelled data/)
  assert.match(sessionMlView({ status: 'INFERENCE_ERROR' }).label, /FAILED/)
})

test('an OK result without a valid confidence, label or model version is rejected, not shown', () => {
  for (const bad of [{ score: undefined }, { score: null }, { score: 1.2 }, { score: NaN }, { score: '0.9' },
    { prediction: '' }, { prediction: '<img src=x>' }, { prediction: 42 }, { modelVersion: null }]) {
    const v = sessionMlView({ ...OK, ...bad })
    assert.equal(v.state, 'INVALID_RESULT', JSON.stringify(bad))
    assert.equal(v.prediction, null)
  }
  assert.equal(sessionMlView({ ...OK, status: 'ACTIVE' }).state, 'INVALID_RESULT') // unknown status
})

test('sessions without an ML record say so', () => {
  for (const ml of [undefined, null, 'x', 5]) {
    const v = sessionMlView(ml)
    assert.equal(v.state, 'ABSENT')
    assert.equal(v.prediction, null)
  }
})

test('rule-based and ML results are separate strings; the rule one is labelled as rules', () => {
  assert.equal(ruleVerdictText({ aiClassification: 'SSH_Brute_Force', aiThreatScore: 0.7 }), 'SSH Brute Force 70% (rule-based)')
  assert.equal(ruleVerdictText({}), null)
  const page = readFileSync(new URL('../src/pages/HoneypotAnalytics.jsx', import.meta.url), 'utf8')
  assert.match(page, /data-testid="session-rule-verdict"/)
  assert.match(page, /data-testid="session-ml-verdict"/)
  assert.match(page, /ML \(SHADOW\):/)
  assert.match(page, /RULES:/)
  // no arithmetic combining the two scores
  assert.doesNotMatch(page, /aiThreatScore\s*[*+]\s*.*sessionMl|sessionMl[^\n]*score\s*[*+]\s*.*aiThreatScore/)
})

test('reason codes are shown as neutral observations, bounded and filtered', () => {
  assert.deepEqual(reasonCodeText(['DOWNLOAD_ATTEMPT', 'bad code', '<x>', 7]), ['download attempt'])
  assert.equal(reasonCodeText(Array.from({ length: 20 }, (_, i) => `C${i}`)).length, 8)
  assert.deepEqual(reasonCodeText(null), [])
})

test('viewer-redacted sessions still render: the ML block carries no IP, command or credential', () => {
  const redacted = { sessionId: 's', sourceIP: '203.0.x.x', commands: [{ command: '[REDACTED_COMMAND]' }], sessionMl: OK }
  const v = sessionMlView(redacted.sessionMl)
  const shown = [v.label, v.prediction, v.scoreText, ...v.details, ...reasonCodeText(OK.reasonCodes)].join(' ')
  assert.doesNotMatch(shown, /203\.0\.|REDACTED|password/i)
})

test('capability labels for the three session-ML entries are distinct', () => {
  const texts = ['implemented_and_verified', 'blocked', 'experimental', 'shadow_only'].map((l) => labelMeta(l).text)
  assert.equal(new Set(texts).size, 4)
})
