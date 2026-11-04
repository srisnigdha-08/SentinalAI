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

// THR-003: with ALERT_THRESHOLD/BLOCK_THRESHOLD overridden, the backend raises and blocks at the engine's lines but
// the dashboard kept colouring and filtering at the 0.90/0.92 defaults.
test('bands follow the lines the backend reports when they differ from the defaults', async () => {
  const { DEFAULT_LINES, normalizeLines } = await import('../src/utils/scoreBands.js')
  const lines = normalizeLines({ alert: 0.8, block: 0.85 })
  assert.deepEqual(lines, { alert: 0.8, block: 0.85 })
  assert.equal(scoreColor(0.82, lines), '#ffaa00') // a threat at this line: amber, not "below the alert line"
  assert.equal(scoreColor(0.86, lines), '#ff2d55')
  assert.equal(scoreColor(0.79, lines), '#00d4ff')
  assert.equal(scoreLogType(0.86, lines), 'err')
  assert.equal(isAlertScore(0.82, lines), true)
  assert.equal(liveSeverity({ threatScore: 0.86 }, lines), 'CRITICAL')
  assert.deepEqual(DEFAULT_LINES, { alert: 0.9, block: 0.92 })
})

test('invalid or missing lines fall back to the defaults', async () => {
  const { DEFAULT_LINES, normalizeLines } = await import('../src/utils/scoreBands.js')
  for (const bad of [null, {}, { alert: 0.95, block: 0.9 }, { alert: 0, block: 0.9 }, { alert: 0.9, block: 1.5 }, { alert: 'x', block: 0.92 }]) {
    assert.deepEqual(normalizeLines(bad), DEFAULT_LINES, JSON.stringify(bad))
  }
})

// THR-004: the provider keeps where the lines came from, and never labels invalid data as engine-confirmed.
test('linesFromResponse keeps the reported source, and invalid lines are the defaults', async () => {
  const { linesFromResponse, DEFAULT_LINES } = await import('../src/utils/scoreBands.js')
  assert.deepEqual(linesFromResponse({ alert: 0.8, block: 0.85, source: 'engine' }), { alert: 0.8, block: 0.85, source: 'engine' })
  assert.deepEqual(linesFromResponse({ alert: 0.8, block: 0.85, source: 'engine-cached' }).source, 'engine-cached')
  assert.deepEqual(linesFromResponse({ alert: 0.95, block: 0.9, source: 'engine' }), { ...DEFAULT_LINES, source: 'default' })
  assert.deepEqual(linesFromResponse({ alert: 0.8, block: 0.85, source: 'made-up' }).source, 'default')
  assert.deepEqual(linesFromResponse(null), { ...DEFAULT_LINES, source: 'default' })
})
