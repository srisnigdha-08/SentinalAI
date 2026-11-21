import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { captureChip, labelMeta, LABEL_META, DECISION_TEXT, captureSourceMeta, CAPTURE_SOURCE_META } from '../src/utils/capabilities.js'

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
  for (const k of ['implemented_and_verified', 'implemented_and_tested', 'implemented_and_tested_simulated', 'implemented_not_enabled', 'simulated', 'shadow_only', 'experimental', 'blocked', 'not_implemented'])
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

test('offline PCAP replay and live capture have distinct, non-upgrading presentation', () => {
  assert.equal(labelMeta('implemented_and_verified').text, 'IMPLEMENTED AND VERIFIED')
  assert.equal(labelMeta('implemented_not_enabled').text, 'IMPLEMENTED, NOT ENABLED')
  assert.notEqual(labelMeta('implemented_and_verified').text, labelMeta('implemented_and_tested').text)
})

test('a failed replay is shown as failed, never as live', () => {
  const chip = captureChip({ mode: 'pcap_replay', state: 'failed', reason: 'pcap: not a pcap file (bad magic number)' })
  assert.match(chip.text, /PCAP replay failed/)
  assert.match(chip.text, /live capture not enabled/)
  assert.doesNotMatch(chip.text, /LIVE/)
  assert.match(chip.title, /bad magic/)
  // a finished replay chip says it is recorded and points out live capture is separate
  assert.match(captureChip({ mode: 'pcap_replay', state: 'finished' }).title, /Live capture is a separate, disabled capability/)
})

test('prediction provenance: pcap_replay is labelled as a recording, unknown values are never live', () => {
  assert.equal(captureSourceMeta('pcap_replay').short, 'PCAP REPLAY')
  assert.match(captureSourceMeta('pcap_replay').text, /not live traffic/)
  assert.equal(captureSourceMeta('live_passive').short, 'LIVE CAPTURE')
  for (const v of [undefined, null, '', 'live', 'LIVE_PASSIVE', '__proto__', 'toString', 42])
    assert.equal(captureSourceMeta(v), CAPTURE_SOURCE_META.unknown, String(v))
})

test('the AI page and live feed display the capture source of each prediction', () => {
  const ai = readFileSync(new URL('../src/pages/AIAnalytics.jsx', import.meta.url), 'utf8')
  assert.match(ai, /data-testid="prediction-capture-source"/)
  assert.equal((ai.match(/captureSourceMeta\((data|p)\.captureSource\)\.short/g) || []).length >= 3, true)
  const feed = readFileSync(new URL('../src/hooks/useRealTimeFeed.js', import.meta.url), 'utf8')
  assert.match(feed, /captureSourceMeta\(data\.captureSource\)\.short/)
})

test('mock containment is shown as tested but simulated, distinct from verified and not-enabled', () => {
  assert.equal(labelMeta('implemented_and_tested_simulated').text, 'IMPLEMENTED AND TESTED — SIMULATED')
  assert.notEqual(labelMeta('implemented_and_tested_simulated').text, labelMeta('implemented_and_tested').text)
  assert.notEqual(labelMeta('implemented_and_tested_simulated').text, labelMeta('implemented_and_verified').text)
})

test('Q-learning evidence management and policy effectiveness are presented with different labels', () => {
  // Backend: qlearning_evidence -> implemented_and_verified, qlearning_effectiveness -> experimental,
  // persona_policy_v2 -> shadow_only. The page must never render them with the same wording.
  const texts = ['implemented_and_verified', 'experimental', 'shadow_only'].map((l) => labelMeta(l).text)
  assert.equal(new Set(texts).size, 3)
  assert.equal(labelMeta('experimental').text, 'EXPERIMENTAL')
  assert.equal(labelMeta('shadow_only').text, 'SHADOW ONLY')
})
