import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { TECHNIQUE_TACTICS, tacticsOf, tacticText } from '../src/utils/mitreTactics.js'
import { classifierVersion, classifierMetrics, classSupportSummary, shapProvenanceText } from '../src/utils/modelHealth.js'

const require = createRequire(import.meta.url)
const { TECHNIQUES } = require('../../backend/utils/attackTechniques.js')

// Rank 8: the frontend tactic table mirrors the backend's verified ATT&CK v20.1 table exactly.
test('frontend tactics equal the backend verified table', () => {
  assert.deepEqual(Object.keys(TECHNIQUE_TACTICS).sort(), Object.keys(TECHNIQUES).sort())
  for (const [id, entry] of Object.entries(TECHNIQUES)) assert.deepEqual([...TECHNIQUE_TACTICS[id]], entry.tactics, id)
})

test('tactic text for stored {id, name} records, with a safe unknown', () => {
  assert.equal(tacticText({ id: 'T1082', name: 'System Information Discovery' }), 'Discovery')
  assert.equal(tacticText({ id: 'T1053.005' }), 'Execution, Persistence, Privilege Escalation')
  assert.equal(tacticText({ id: 'T1685.005' }), 'Defense Impairment')
  assert.equal(tacticText({ id: 'T9999' }), 'tactic not mapped')
  assert.deepEqual(tacticsOf({ id: 'T1082', tactics: ['Discovery'] }), ['Discovery'])
  assert.equal(tacticText(null), 'tactic not mapped')
})

test('canonical classifier fields win; legacy rf* fields still work', () => {
  assert.equal(classifierVersion({ classifierVersion: 'xgb_cicids_v1', rfVersion: 'old' }), 'xgb_cicids_v1')
  assert.equal(classifierVersion({ rfVersion: 'xgb_cicids_v1' }), 'xgb_cicids_v1')
  assert.equal(classifierVersion(null), null)
  assert.deepEqual(classifierMetrics({ rfMetrics: { accuracy: 0.99 } }), { accuracy: 0.99 })
  assert.deepEqual(classifierMetrics({ classifierMetrics: { accuracy: 0.98 }, rfMetrics: { accuracy: 0.1 } }), { accuracy: 0.98 })
})

test('class support never claims detection for unmodelled or low-support classes', () => {
  const s = classSupportSummary({
    classSupport: {
      'Data Exfiltration': { status: 'unmodeled', trainingRows: 0 },
      'RCE Attempt': { status: 'low_support', trainingRows: 9 },
      DDoS: { status: 'supported', trainingRows: 14440 },
    },
  })
  assert.deepEqual(s.unmodeled, ['Data Exfiltration'])
  assert.deepEqual(s.lowSupport, ['RCE Attempt'])
  assert.match(s.text, /Not modelled \(cannot be predicted\): Data Exfiltration/)
  assert.match(s.text, /RCE Attempt \(9 training rows\)/)
  assert.doesNotMatch(s.text, /DDoS/)
  assert.equal(classSupportSummary({}).text, '')
})

test('SHAP provenance text distinguishes the ephemeral and the reproducible views', () => {
  assert.match(shapProvenanceText({ scope: 'recent', provenance: { modelSha256: 'abc', featureSchemaVersion: 'v2.1_53feat' } }), /not persisted/)
  const ref = shapProvenanceText({ scope: 'reference', provenance: { modelSha256: '6d08ef19dad31bf6', featureSchemaVersion: 'v2.1_53feat',
    generatedAt: '2026-11-19T00:00:00Z', persisted: true, sample: { rows: 20, sha256: 'c8d72dd96dc3' } } })
  assert.match(ref, /Reproducible reference: 20 pinned golden vectors/)
  assert.match(ref, /cached/)
  assert.equal(shapProvenanceText(null), '')
})
