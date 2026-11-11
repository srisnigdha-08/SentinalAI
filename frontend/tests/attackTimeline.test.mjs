// Attack Time Machine: timeline normalisation, provenance, summary, playback engine and safe text rendering.
import test, { mock } from 'node:test'
import assert from 'node:assert/strict'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import {
  PROVENANCE, buildTimeline, enforcementProvenance, narrative, parseTime, provenanceOf, sessionDuration, summarize, techniqueIndex,
} from '../src/utils/attackTimeline.js'
import { createPlaybackEngine, stepDelay, MAX_STEP_MS, MIN_STEP_MS } from '../src/utils/playbackEngine.js'
import EvidenceText from '../src/components/attackTimeline/EvidenceText.js'

const T = (s) => `2026-11-01T10:30:${String(s).padStart(2, '0')}.000Z`
const ms = (s) => Date.parse(T(s))

const evidence = (over = {}) => ({
  session: {
    _id: 'a'.repeat(24), sessionId: 'sess-1', sourceIP: '203.0.113.9', protocol: 'SSH', status: 'closed',
    startTime: T(1), endTime: T(30), durationSeconds: 29, servedProfile: 'ubuntu_22',
    credentials: [{ username: 'root', success: false }, { username: 'root', success: true }],
    commands: [
      { index: 0, command: 'whoami', timestamp: T(12), techniques: [{ id: 'T1033', name: 'System Owner/User Discovery' }] },
      { index: 1, command: 'cat /etc/passwd', timestamp: T(17), output: 'root:x:0:0', techniques: [{ id: 'T1003.008', name: '/etc/passwd and /etc/shadow' }] },
    ],
    aiClassification: 'SSH Intrusion Attempt', aiThreatScore: 0.8, aiClassificationMethod: 'honeypot_rules',
    closureAnalysisCompletedAt: T(31), mitreTechniques: [{ id: 'T1033', name: 'System Owner/User Discovery' }, { id: 'T1003.008', name: '/etc/passwd and /etc/shadow' }],
    ...over.session,
  },
  threat: over.threat ?? null,
  prediction: over.prediction ?? null,
  alerts: over.alerts ?? [],
  containment: over.containment ?? [],
  blockedIPs: over.blockedIPs ?? [],
  access: { containmentVisible: true },
})

// 1. Timestamp normalisation
test('parseTime accepts ISO strings, Dates and epoch ms; rejects junk without inventing a time', () => {
  assert.equal(parseTime(T(5)), ms(5))
  assert.equal(parseTime(new Date(T(5))), ms(5))
  assert.equal(parseTime(ms(5)), ms(5))
  for (const bad of [null, undefined, '', 'not-a-date', NaN, Infinity, 42, true, {}, []]) assert.equal(parseTime(bad), null)
})

// 2. Chronological order
test('events are ordered by their recorded time regardless of input order', () => {
  const e = evidence({ session: { commands: [{ command: 'b', timestamp: T(20) }, { command: 'a', timestamp: T(10) }] } })
  const { events } = buildTimeline(e)
  assert.deepEqual(events.map((x) => x.kind + ':' + (x.command ?? '')), ['connection:', 'command:a', 'command:b', 'close:', 'classification:'])
})

// 3. Deterministic ties
test('equal timestamps break ties by session order, then source order, deterministically', () => {
  const e = evidence({ session: { startTime: T(10), commands: [{ command: 'x', timestamp: T(10) }, { command: 'y', timestamp: T(10) }] } })
  const a = buildTimeline(e).events.map((x) => x.id)
  const b = buildTimeline(structuredClone(e)).events.map((x) => x.id)
  assert.deepEqual(a, b)
  assert.deepEqual(a.slice(0, 3), ['connection', 'command-0', 'command-1'])
})

// 4. Missing / malformed fields
test('missing or malformed fields go to Unknown time instead of being given a time', () => {
  const e = evidence({ session: { endTime: undefined, closureAnalysisCompletedAt: 'garbage', commands: [{ command: 'ls', timestamp: 'nope' }, null, { timestamp: T(3) }] } })
  const { events, untimed } = buildTimeline(e)
  assert.ok(untimed.some((x) => x.id === 'command-0'))
  assert.ok(untimed.some((x) => x.kind === 'close'), 'closed session without endTime: close is untimed')
  assert.ok(untimed.some((x) => x.kind === 'classification'))
  assert.ok(events.every((x) => Number.isFinite(x.time)))
  assert.deepEqual(buildTimeline(null), { events: [], untimed: [] })
  assert.deepEqual(buildTimeline({ session: 'x' }), { events: [], untimed: [] })
})

test('login attempts keep their recorded outcome and are never placed on the clock', () => {
  const { events, untimed } = buildTimeline(evidence())
  assert.equal(events.filter((x) => x.kind === 'auth').length, 0)
  assert.deepEqual(untimed.filter((x) => x.kind === 'auth').map((x) => x.detail.outcome), ['failure', 'success'])
  assert.ok(!JSON.stringify(untimed).includes('password'))
})

// 5. Duration
test('duration uses the stored value, else start/end, else unavailable', () => {
  assert.equal(sessionDuration({ durationSeconds: 29 }), 29)
  assert.equal(sessionDuration({ startTime: T(1), endTime: T(35) }), 34)
  assert.equal(sessionDuration({ startTime: T(1) }), null)
  assert.equal(sessionDuration({ startTime: T(9), endTime: T(1) }), null)
  assert.equal(sessionDuration(null), null)
})

// 6. MITRE mapping from evidence
test('techniques stay attached to the command that produced them; session-level ones are kept', () => {
  const e = evidence({ session: { mitreTechniques: [{ id: 'T1033', name: 'x' }, { id: 'T1110', name: 'Brute Force' }] } })
  const { events } = buildTimeline(e)
  const idx = techniqueIndex(events, e.session)
  assert.deepEqual(idx.find((t) => t.id === 'T1033').eventIds, ['command-0'])
  assert.deepEqual(idx.find((t) => t.id === 'T1003.008').eventIds, ['command-1'])
  assert.deepEqual(idx.find((t) => t.id === 'T1110').eventIds, [])
})

test('techniques found only on the shared threat record are not counted as this session’s', () => {
  const e = evidence({ threat: { severity: 'HIGH', createdAt: T(32), mitreTechniques: [{ id: 'T1021', name: 'Remote Services' }, { id: 'T1033', name: 'x' }] } })
  const { events, untimed } = buildTimeline(e)
  const idx = techniqueIndex(events, e.session)
  assert.equal(idx.find((t) => t.id === 'T1021').threatOnly, true)
  assert.equal(idx.find((t) => t.id === 'T1033').threatOnly, false)
  assert.equal(summarize(e, events, untimed).techniques, 2)
})

// 7. Source classification labels
test('provenance labels: observed, derived, simulated, replayed only when explicit, unknown otherwise', () => {
  const { events } = buildTimeline(evidence({ containment: [{ containmentId: 'c', enforcementBackend: 'mock', requestedAt: T(40) }] }))
  const by = Object.fromEntries(events.map((x) => [x.kind, x.provenance]))
  assert.equal(by.connection, PROVENANCE.OBSERVED)
  assert.equal(by.command, PROVENANCE.OBSERVED)
  assert.equal(by.classification, PROVENANCE.DERIVED)
  assert.equal(by.containment, PROVENANCE.SIMULATED)
  assert.equal(enforcementProvenance('simulated'), PROVENANCE.SIMULATED)
  assert.equal(enforcementProvenance(undefined), PROVENANCE.UNKNOWN)
  assert.equal(provenanceOf({ inputSource: 'network_traffic' }), PROVENANCE.UNKNOWN, 'flow data is not assumed to be replay')
  assert.equal(provenanceOf({ inputSource: 'network_traffic', replayed: true }), PROVENANCE.REPLAYED)
  assert.equal(provenanceOf({ source: 'cicids2017-replay' }), PROVENANCE.REPLAYED)
  assert.equal(provenanceOf({ inputSource: 'honeypot_log' }), PROVENANCE.DERIVED)
  assert.equal(provenanceOf(null), PROVENANCE.UNKNOWN)
})

test('mock containment is never described as a host firewall block', () => {
  const { events } = buildTimeline(evidence({ containment: [{ containmentId: 'c', enforcementBackend: 'mock', appliedAt: T(41), requestedAt: T(40) }] }))
  const c = events.filter((x) => x.kind === 'containment')
  assert.deepEqual(c.map((x) => x.title), ['Containment requested', 'Containment applied'])
  assert.match(c[0].detail.enforcement, /Mock firewall adapter \(no host rule applied\)/)
})

test('rule-based classification never claims a SHAP explanation', () => {
  const cls = buildTimeline(evidence()).events.find((x) => x.kind === 'classification')
  assert.equal(cls.detail.ruleBased, true)
  assert.match(cls.detail.explanation, /no SHAP/)
  assert.equal(cls.basis, 'processing')
})

// 8 & 9. Correlation: only what the API linked; threat-level records are marked as such
test('records linked through the threat are marked; nothing is added beyond the evidence bundle', () => {
  const e = evidence({
    threat: { _id: 't', severity: 'HIGH', attackType: 'SSH Intrusion Attempt', createdAt: T(32) },
    alerts: [{ _id: 'a1', title: 'Session alert', createdAt: T(2), linkedVia: 'session' }, { _id: 'a2', title: 'Threat alert', createdAt: T(33), linkedVia: 'threat' }],
  })
  const { events } = buildTimeline(e)
  assert.equal(events.find((x) => x.id === 'alert-a1').link, 'session')
  assert.equal(events.find((x) => x.id === 'alert-a2').link, 'threat')
  assert.equal(events.find((x) => x.kind === 'threat').link, 'threat')
  assert.equal(buildTimeline(evidence()).events.filter((x) => ['alert', 'threat', 'containment', 'blocklist'].includes(x.kind)).length, 0)
})

// 10. Summary
test('summary metrics and narrative come only from recorded fields', () => {
  const e = evidence({ threat: { severity: 'MEDIUM', createdAt: T(32) }, alerts: [{ severity: 'HIGH', createdAt: T(33) }] })
  const { events, untimed } = buildTimeline(e)
  const s = summarize(e, events, untimed)
  assert.deepEqual({ ...s }, { durationSeconds: 29, commandsCaptured: 2, commandsStored: 2, techniques: 2, highestSeverity: 'HIGH', threatScore: 0.8, persona: 'ubuntu_22', status: 'closed', responseEvents: 0 })
  assert.equal(narrative(s), 'This session lasted 29s and contained 2 recorded commands. The recorded activity was mapped to 2 MITRE ATT&CK techniques. The highest linked severity was HIGH. The session was recorded as closed.')
  const bare = summarize({ session: { status: 'active', commands: [] } }, [], [])
  assert.equal(narrative(bare), 'This session contained 0 recorded commands; its duration is not recorded. No MITRE ATT&CK technique was mapped. The session is still recorded as active.')
  assert.equal(summarize({ session: { commandCount: 5, commands: [{}, {}] } }).commandsCaptured, 5)
})

// 11. Empty and single-event sessions
test('a session with no timed events and one with a single event are handled', () => {
  const empty = buildTimeline({ session: { sessionId: 'x', status: 'active' } })
  assert.deepEqual(empty.events, [])
  const one = buildTimeline({ session: { sessionId: 'x', status: 'active', startTime: T(1) } })
  assert.equal(one.events.length, 1)
})

// 12-17. Playback engine
const fakeTimers = () => {
  let id = 0
  const pending = new Map()
  return {
    setTimer: (fn, delay) => { pending.set(++id, { fn, delay }); return id },
    clearTimer: (t) => pending.delete(t),
    pending,
    fire() { const [[k, v]] = [...pending.entries()]; pending.delete(k); v.fn(); return v.delay },
  }
}
const evs = (n, gap = 1000) => Array.from({ length: n }, (_, i) => ({ id: `e${i}`, time: ms(0) + i * gap }))

test('play advances one event per tick, pause stops immediately, resume continues', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(4), t)
  p.play()
  assert.equal(p.getState().playing, true)
  t.fire()
  assert.equal(p.getState().index, 1)
  p.pause()
  assert.equal(t.pending.size, 0)
  assert.equal(p.getState().playing, false)
  p.play()
  t.fire()
  assert.equal(p.getState().index, 2)
})

test('reaching the last event stops cleanly; play at the end restarts from the beginning', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(3), t)
  p.play(); t.fire(); t.fire()
  assert.deepEqual([p.getState().index, p.getState().playing, t.pending.size], [2, false, 0])
  p.play()
  assert.equal(p.getState().index, 0)
})

test('restart, previous and next stay within bounds', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(3), t)
  p.prev(); assert.equal(p.getState().index, 0)
  p.next(); p.next(); p.next(); assert.equal(p.getState().index, 2)
  p.restart(); assert.equal(p.getState().index, 0)
})

test('speed scales the recorded gap and long gaps are compressed and flagged', () => {
  const e = evs(3, 2000)
  assert.equal(stepDelay(e, 0, 1).delay, 2000)
  assert.equal(stepDelay(e, 0, 2).delay, 1000)
  assert.equal(stepDelay(e, 0, 4).delay, 500)
  assert.deepEqual(stepDelay(e, 0, 0.5), { delay: MAX_STEP_MS, compressed: true })
  assert.equal(stepDelay(evs(2, 0), 0, 4).delay, MIN_STEP_MS)
  const t = fakeTimers()
  const p = createPlaybackEngine(e, t)
  p.setSpeed(4); p.play()
  assert.equal(t.fire(), 500)
  p.setSpeed(3)
  assert.equal(p.getState().speed, 4, 'unsupported speeds are ignored')
})

test('seek shows the requested event and clamps out-of-range values', () => {
  const p = createPlaybackEngine(evs(5), fakeTimers())
  p.seek(3); assert.equal(p.getState().index, 3)
  p.seek(99); assert.equal(p.getState().index, 4)
  p.seek(-2); assert.equal(p.getState().index, 0)
  p.seek('2'); assert.equal(p.getState().index, 2)
})

test('zero and one event: controls are no-ops and never schedule timers', () => {
  const t = fakeTimers()
  const zero = createPlaybackEngine([], t)
  zero.play(); zero.next(); zero.seek(3); zero.restart()
  assert.deepEqual(zero.getState(), { index: -1, playing: false, speed: 1, total: 0 })
  const one = createPlaybackEngine(evs(1), t)
  one.play()
  assert.deepEqual([one.getState().index, one.getState().playing], [0, false])
  assert.equal(t.pending.size, 0)
})

test('only one timer is ever pending; repeated play/next/speed changes do not stack timers', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(6), t)
  p.play(); p.play(); p.next(); p.setSpeed(2); p.seek(1); p.toggle(); p.toggle()
  assert.equal(t.pending.size, 1)
})

test('dispose (unmount / session switch) cancels the pending timer and stops playback', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(4), t)
  p.play()
  assert.equal(p.hasPendingTimer(), true)
  p.dispose()
  assert.equal(t.pending.size, 0)
  assert.equal(p.getState().playing, false)
})

test('a fired timer after pause never advances (no stale updates)', () => {
  const t = fakeTimers()
  const p = createPlaybackEngine(evs(4), t)
  p.play()
  const [[, stale]] = [...t.pending.entries()]
  p.pause()
  stale.fn()
  assert.equal(p.getState().index, 0)
})

test('live append keeps the position; a shrunk list clamps it', () => {
  const p = createPlaybackEngine(evs(3), fakeTimers())
  p.seek(2)
  p.setEvents(evs(5))
  assert.deepEqual([p.getState().index, p.getState().total], [2, 5])
  p.setEvents(evs(1))
  assert.deepEqual([p.getState().index, p.getState().total], [0, 1])
})

test('engine works with real timers and unsubscribes listeners', () => {
  mock.timers.enable({ apis: ['setTimeout'] })
  try {
    const p = createPlaybackEngine(evs(3, 1000))
    let calls = 0
    const off = p.subscribe(() => calls++)
    p.play()
    mock.timers.tick(1000)
    assert.equal(p.getState().index, 1)
    off()
    const before = calls
    mock.timers.tick(1000)
    assert.equal(p.getState().index, 2)
    assert.equal(calls, before)
  } finally {
    mock.timers.reset()
  }
})

// 18. Untrusted text
test('attacker-controlled command and output render as inert text', () => {
  for (const text of ['<img src=x onerror=alert(1)>', '"><script>alert(document.cookie)</script>', 'javascript:alert(1)']) {
    const html = renderToStaticMarkup(createElement(EvidenceText, { text }))
    assert.ok(!/<script|<img/i.test(html), html)
    assert.match(html, /^<code[^>]*>[^<]*<\/code>$/)
  }
  const block = renderToStaticMarkup(createElement(EvidenceText, { text: 'x'.repeat(5000), block: true }))
  assert.match(block, /^<pre/)
  assert.match(block, /truncated for display/)
  assert.equal(renderToStaticMarkup(createElement(EvidenceText, { text: null })).includes('null'), false)
})
