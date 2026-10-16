import test from 'node:test'
import assert from 'node:assert/strict'
import { threatEvidenceLabel } from '../src/utils/threatEvidence.js'

test('explicit new session-open annotation identifies heuristic rather than model inference', () => {
  assert.equal(threatEvidenceLabel({ notes: '[SESSION_OPEN_HEURISTIC] Fixed signal', aiScore: 0.75 }), 'Session-open heuristic; not an RF/IF prediction')
})
test('legacy/model/manual records are never guessed to be heuristic from score or attack type', () => {
  for (const threat of [undefined, {}, { aiScore: 0.75, attackType: 'SSH Brute Force' }, { notes: null }, { notes: {} }, { notes: 'Model prediction' }]) assert.equal(threatEvidenceLabel(threat), null)
})
test('embedded marker in unrelated notes is not a source annotation', () => {
  assert.equal(threatEvidenceLabel({ notes: 'Operator quoted [SESSION_OPEN_HEURISTIC]' }), null)
})
test('explicit reclassification marker distinguishes subsequent model inference', () => {
  assert.equal(threatEvidenceLabel({ notes: '[RF_IF_RECLASSIFIED] RF/IF inference replaced the initial signal' }), 'RF/IF reclassified after session-open heuristic')
})
