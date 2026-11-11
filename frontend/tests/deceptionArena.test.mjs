// Deception Arena presentation helpers: honest labels, raw per-trial chart rows, safe and auditable exports.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { KIND_META, STATUS_META, TERMINATION_LABEL, fmt, interval, trialRows, trialsCsv, evidenceJson } from '../src/utils/deceptionArena.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src')
const trial = (strategy, index, over = {}) => ({ strategy, index, persona: 'centos_7', durationSeconds: 60, commands: [{ command: 'id' }, { command: 'id' }], termination: 'completed', reward: 2, ...over })

test('status and scenario labels cover every backend value, with honest scope text', () => {
  assert.deepEqual(Object.keys(STATUS_META).sort(), ['CANCELLED', 'COMPLETED', 'CREATED', 'FAILED', 'RUNNING'])
  assert.match(KIND_META.SCRIPTED.help, /not attacker engagement/)
  assert.match(KIND_META.SIMULATED.help, /not real attackers/)
  assert.ok(TERMINATION_LABEL.not_recorded)
})

test('missing measurements show as Not measured; intervals only when the backend gave one', () => {
  assert.equal(fmt(null), 'Not measured')
  assert.equal(fmt(NaN, ' s'), 'Not measured')
  assert.equal(fmt(12, ' s'), '12 s')
  assert.equal(interval({ pairs: 0 }), 'No paired observations')
  assert.equal(interval({ pairs: 3, meanDifference: 1.5, ci95: null }), 'Mean 1.5 over 3 pairs; too few for an interval')
  assert.equal(interval({ pairs: 12, meanDifference: 0.4, ci95: [-0.2, 1] }), 'Mean 0.4 (95% CI -0.2 to 1), 12 pairs')
})

test('chart rows are raw per-trial values; missing stays null instead of becoming 0', () => {
  const rows = trialRows([trial('STATIC', 1), trial('ADAPTIVE', 0, { durationSeconds: null }), trial('STATIC', 0, { durationSeconds: 30 })], (t) => t.durationSeconds)
  assert.deepEqual(rows, [{ trial: 1, STATIC: 30, ADAPTIVE: null }, { trial: 2, STATIC: 60, ADAPTIVE: null }])
  assert.deepEqual(trialRows([], (t) => t.durationSeconds), [])
})

test('CSV export: one row per trial, provenance on each row, unique commands counted, formulas neutralised', () => {
  const exp = {
    experimentId: 'e1', scenario: 'scripted_recon', kind: 'SCRIPTED', seed: 7,
    trials: [trial('ADAPTIVE', 0, { persona: 'ubuntu_22', decision: { recommendedPersona: 'ubuntu_22', appliedPersona: 'ubuntu_22', explored: true }, commands: [{ command: '=HYPERLINK("x")' }] }), trial('STATIC', 0)],
  }
  const lines = trialsCsv(exp).trim().split('\r\n')
  assert.equal(lines.length, 3)
  assert.match(lines[0], /^"experimentId","scenario","scenarioKind","seed","strategy"/)
  assert.match(lines[1], /^"e1","scripted_recon","SCRIPTED","7","STATIC","1"/)
  assert.match(lines[1], /"2","1","completed"/) // 2 commands, 1 unique
  assert.match(lines[2], /"ADAPTIVE".*"ubuntu_22","ubuntu_22","ubuntu_22","true"/)
  assert.doesNotMatch(trialsCsv({ ...exp, name: '=cmd' }), /,"=/)
})

test('JSON export keeps observations separate from derived results', () => {
  const exp = { experimentId: 'e1', trials: [trial('STATIC', 0)], events: [{ type: 'EXPERIMENT_CREATED' }], status: 'COMPLETED' }
  const out = JSON.parse(evidenceJson(exp, { conclusion: { headline: 'x' } }))
  assert.deepEqual(Object.keys(out).sort(), ['configuration', 'derived', 'exportedAt', 'note', 'observations'])
  assert.equal(out.observations.trials.length, 1)
  assert.equal(out.configuration.trials, undefined)
  assert.equal(out.derived.conclusion.headline, 'x')
})

test('the Deception Arena UI never claims an adaptive improvement on its own and has no HTML sinks', () => {
  const files = [join(SRC, 'pages', 'DeceptionArena.jsx'), join(SRC, 'utils', 'deceptionArena.js'),
    ...readdirSync(join(SRC, 'components', 'deceptionArena')).map((f) => join(SRC, 'components', 'deceptionArena', f))]
  for (const f of files) {
    const src = readFileSync(f, 'utf8')
    assert.doesNotMatch(src, /dangerouslySetInnerHTML/, f)
    assert.doesNotMatch(src, /adaptive (is|was) better|improves engagement|% improvement/i, f)
  }
})
