import test from 'node:test'
import assert from 'node:assert/strict'
import { ALERT_LINE, BLOCK_LINE, scoreColor, scoreLogType, isAlertScore, liveSeverity } from '../src/utils/scoreBands.js'

// THR-002: score colours and the live feed used a 0.70 line; the pipeline raises threats at the alert line (0.90)
// and blocks at 0.92 (backend utils/severity.js, engine ALERT_THRESHOLD / BLOCK_THRESHOLD defaults).
test('lines match the engine defaults', () => {
  assert.equal(ALERT_LINE, 0.9)
  assert.equal(BLOCK_LINE, 0.92)
})

test('colour bands follow the severity scale', () => {
  const red = '#ff2d55'
  const amber = '#ffaa00'
  const blue = '#00d4ff'
  for (const [score, colour] of [[0.69, blue], [0.7, blue], [0.85, blue], [0.89, blue], [0.9, amber], [0.91, amber], [0.92, red], [0.99, red]]) {
    assert.equal(scoreColor(score), colour, `score ${score}`)
  }
  assert.equal(scoreColor(undefined), blue)
})

test('inference log line types use the same lines', () => {
  assert.deepEqual([0.85, 0.9, 0.92].map(scoreLogType), ['out', 'warn', 'err'])
})

test('the live feed lists predictions from the alert line only, labelled by severity', () => {
  assert.deepEqual([0.69, 0.7, 0.89, 0.9, 0.92].map(isAlertScore), [false, false, false, true, true])
  assert.equal(liveSeverity({ threatScore: 0.95 }), 'CRITICAL')
  assert.equal(liveSeverity({ threatScore: 0.9 }), 'HIGH')
  assert.equal(liveSeverity({ threatScore: 0.9, severity: 'MEDIUM' }), 'MEDIUM') // server-provided value wins
})
