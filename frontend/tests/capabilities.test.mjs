import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { captureChip, labelMeta, LABEL_META, DECISION_TEXT } from '../src/utils/capabilities.js'

test('capture chip never calls a replay live', () => {
  assert.match(captureChip({ mode: 'pcap_replay', state: 'running' }).text, /recorded PCAP replay/)
  assert.doesNotMatch(captureChip({ mode: 'pcap_replay', state: 'running' }).text, /LIVE/)
  assert.match(captureChip({ mode: 'pcap_replay', state: 'finished' }).text, /finished/)
  assert.match(captureChip({ mode: 'live_passive', last: { interface: 'eth0' } }).text, /LIVE passive capture \(eth0\)/)
})

test('capture chip reports unavailable for missing or unavailable status', () => {
  assert.match(captureChip(null).text, /unavailable/)
  assert.equal(captureChip({ mode: 'unavailable', reason: 'no heartbeat' }).title, 'no heartbeat')
})

test('every backend capability label has presentation, unknown labels are not upgraded', () => {
  for (const k of ['implemented_and_tested', 'implemented_not_enabled', 'simulated', 'shadow_only', 'experimental', 'blocked', 'not_implemented'])
    assert.ok(LABEL_META[k], k)
  assert.equal(labelMeta('something_new').text, 'UNKNOWN')
})

test('containment decisions have readable explanations, including approval and suppression', () => {
  for (const d of ['AUTO_BLOCK', 'NEEDS_APPROVAL', 'SUPPRESSED_TRUSTED', 'SUPPRESSED_DUPLICATE', 'MONITOR', 'DISABLED'])
    assert.ok(DECISION_TEXT[d], d)
})

test('the Arena page carries the simulation banner and the capability page is routed', () => {
  const arena = readFileSync(new URL('../src/pages/DeceptionArena.jsx', import.meta.url), 'utf8')
  assert.match(arena, /SIMULATED EVIDENCE — NOT ATTACKER INTELLIGENCE/)
  const app = readFileSync(new URL('../src/App.jsx', import.meta.url), 'utf8')
  assert.match(app, /\/dashboard\/capabilities/)
})
