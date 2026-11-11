// Attack Time Machine: turns the read-only evidence bundle from GET /api/honeypot/sessions/:id/timeline into an
// ordered list of timeline events. Pure and deterministic. It never invents a timestamp, a login outcome or a link:
// a record without a usable time goes to `untimed`, and only records the API returned by reference are included.

export const PROVENANCE = Object.freeze({
  OBSERVED: 'OBSERVED',
  REPLAYED: 'REPLAYED',
  SIMULATED: 'SIMULATED',
  DERIVED: 'DERIVED',
  UNKNOWN: 'UNKNOWN',
})

export const PROVENANCE_META = Object.freeze({
  OBSERVED: { label: 'Observed', color: '#00ff88', icon: '●', help: 'Recorded directly by the Cowrie honeypot (connection, login attempt, command).' },
  REPLAYED: { label: 'Replayed', color: '#8b5cf6', icon: '↻', help: 'From a deliberate dataset replay (e.g. CICIDS2017), not live captured traffic.' },
  SIMULATED: { label: 'Simulated', color: '#ffaa00', icon: '◇', help: 'Mock or simulated enforcement: no real host firewall rule was applied.' },
  DERIVED: { label: 'Derived', color: '#00d4ff', icon: '◆', help: 'Computed by SentinelAI from the recorded evidence (classification, score, mapping, alert, record).' },
  UNKNOWN: { label: 'Source unknown', color: '#7ab3cc', icon: '?', help: 'The origin of this record could not be established reliably.' },
})

// What a timestamp means: when it happened, when a record was written, or when SentinelAI processed it.
export const TIME_BASIS = Object.freeze({
  event: 'Event time',
  record: 'Record created',
  processing: 'Processing time',
})

// Tie-break for equal timestamps: the natural order of a session, then source order, then id.
const KIND_RANK = { connection: 0, auth: 1, command: 2, close: 3, classification: 4, persona: 5, threat: 6, alert: 7, response: 8, containment: 9, blocklist: 10 }

/** Milliseconds since epoch for a valid date-like value, else null. Numbers below 1e11 and junk are rejected. */
export function parseTime(value) {
  if (value === null || value === undefined || value === '' || typeof value === 'boolean') return null
  if (typeof value === 'number' && (!Number.isFinite(value) || value < 1e11)) return null
  if (typeof value !== 'string' && typeof value !== 'number' && !(value instanceof Date)) return null
  const ms = new Date(value).getTime()
  return Number.isFinite(ms) ? ms : null
}

/**
 * Provenance of a non-honeypot record from explicit markers only. A record is REPLAYED only when it says so
 * (replayed flag or a replay/dataset source name); nothing is inferred from IP, class or timing.
 */
export function provenanceOf(record = {}) {
  if (!record || typeof record !== 'object') return PROVENANCE.UNKNOWN
  const source = [record.inputSource, record.source, record.origin].filter((s) => typeof s === 'string').join(' ')
  if (record.replayed === true || /replay|cicids|dataset/i.test(source)) return PROVENANCE.REPLAYED
  if (record.inputSource === 'honeypot_log') return PROVENANCE.DERIVED
  return PROVENANCE.UNKNOWN
}

/** Mock and simulated adapters are SIMULATED; a real adapter's outcome is an observed system action. */
export function enforcementProvenance(backend) {
  if (backend === 'mock' || backend === 'simulated') return PROVENANCE.SIMULATED
  if (backend === 'windows-firewall') return PROVENANCE.OBSERVED
  return PROVENANCE.UNKNOWN
}

export function enforcementLabel(backend) {
  if (backend === 'mock') return 'Mock firewall adapter (no host rule applied)'
  if (backend === 'simulated') return 'Simulated enforcement (no host rule applied)'
  if (backend === 'windows-firewall') return 'Windows host firewall'
  return 'Enforcement backend not recorded'
}

const isRuleBased = (session, prediction) =>
  /rule/i.test(String(session?.aiClassificationMethod || '')) || prediction?.modelType === 'rules'

const techniqueList = (list) =>
  (Array.isArray(list) ? list : []).filter((t) => t && typeof t.id === 'string').map((t) => ({ id: t.id, name: typeof t.name === 'string' ? t.name : '' }))

function push(out, ev) {
  out.push({ techniques: [], link: 'session', ...ev, time: parseTime(ev.rawTime) })
}

/** Builds { events, untimed } from an evidence bundle. events are sorted; untimed keep source order. */
export function buildTimeline(evidence) {
  const s = evidence?.session
  if (!s || typeof s !== 'object') return { events: [], untimed: [] }
  const all = []
  let seq = 0
  const next = () => seq++

  push(all, {
    id: 'connection', kind: 'connection', order: next(), rawTime: s.startTime, basis: 'event',
    provenance: PROVENANCE.OBSERVED, title: `${s.protocol || 'SSH'} connection opened`,
    detail: { sessionId: s.sessionId, sourceIP: s.sourceIP, sourcePort: s.sourcePort, honeypotNode: s.honeypotNode, clientVersion: s.clientVersion, hassh: s.hassh },
  })

  // Cowrie login attempts carry no per-attempt timestamp in the stored record: never place them on the clock.
  ;(Array.isArray(s.credentials) ? s.credentials : []).forEach((c, i) => {
    push(all, {
      id: `auth-${i}`, kind: 'auth', order: next(), rawTime: null, basis: 'event', provenance: PROVENANCE.OBSERVED,
      title: `Login attempt ${c?.success === true ? 'succeeded' : 'failed'}`,
      detail: { attempt: i + 1, username: typeof c?.username === 'string' ? c.username : undefined, outcome: c?.success === true ? 'success' : 'failure' },
    })
  })

  ;(Array.isArray(s.commands) ? s.commands : []).forEach((c, i) => {
    const index = Number.isInteger(c?.index) ? c.index : i
    push(all, {
      id: `command-${index}`, kind: 'command', order: next(), rawTime: c?.timestamp, basis: 'event',
      provenance: PROVENANCE.OBSERVED, title: 'Command executed',
      command: typeof c?.command === 'string' ? c.command : '',
      techniques: techniqueList(c?.techniques),
      detail: { index: index + 1, output: typeof c?.output === 'string' && c.output ? c.output : null, success: c?.success === true, intent: c?.intent || null },
    })
  })

  if (s.endTime || s.status === 'closed' || s.status === 'analysed') {
    push(all, {
      id: 'close', kind: 'close', order: next(), rawTime: s.endTime, basis: 'event', provenance: PROVENANCE.OBSERVED,
      title: 'Session closed', detail: { status: s.status, durationSeconds: s.durationSeconds },
    })
  }

  const prediction = evidence.prediction || null
  if (s.aiClassification || prediction) {
    const ruleBased = isRuleBased(s, prediction)
    push(all, {
      id: 'classification', kind: 'classification', order: next(),
      rawTime: s.closureAnalysisCompletedAt ?? prediction?.createdAt ?? null,
      basis: s.closureAnalysisCompletedAt ? 'processing' : 'record',
      provenance: PROVENANCE.DERIVED, title: `Session classified: ${s.aiClassification || prediction?.predictedClass || 'unavailable'}`,
      detail: {
        classification: s.aiClassification || prediction?.predictedClass || null,
        threatScore: Number.isFinite(s.aiThreatScore) && s.aiClassification ? s.aiThreatScore : prediction?.threatScore ?? null,
        method: s.aiClassificationMethod || null,
        modelVersion: prediction?.modelVersion || null,
        ruleBased,
        explanation: ruleBased
          ? 'Not applicable: rule-based honeypot classification (no ML model, so no SHAP explanation).'
          : 'No linked ML explanation is recorded for this session.',
      },
    })
  }

  if (s.deceptionScoredAt || s.servedProfile) {
    push(all, {
      id: 'persona', kind: 'persona', order: next(), rawTime: s.deceptionScoredAt, basis: 'processing',
      provenance: PROVENANCE.DERIVED, title: s.deceptionScoredAt ? 'Deception reward recorded for persona' : 'Persona served',
      detail: { servedProfile: s.servedProfile || null, recommendedProfile: s.recommendedProfile || null, deceptionScore: s.deceptionScore, qDeceptionScore: s.qDeceptionScore },
    })
  }

  const threat = evidence.threat
  if (threat) {
    push(all, {
      id: 'threat', kind: 'threat', order: next(), rawTime: threat.createdAt, basis: 'record', link: 'threat',
      provenance: PROVENANCE.DERIVED, title: `Threat record: ${threat.attackType || 'unknown type'}`,
      techniques: techniqueList(threat.mitreTechniques),
      detail: { severity: threat.severity, aiScore: threat.aiScore, status: threat.status, attackType: threat.attackType, note: 'Threat records are shared by sessions from the same source, so this record may also reflect other sessions.' },
    })
    if (threat.autonomousAction?.taken) {
      push(all, {
        id: 'threat-action', kind: 'response', order: next(), rawTime: threat.autonomousAction.actionTime, basis: 'record', link: 'threat',
        provenance: PROVENANCE.DERIVED, title: `Autonomous decision: ${threat.autonomousAction.actionType || 'recorded'}`,
        detail: { actionType: threat.autonomousAction.actionType, note: 'A recorded decision; enforcement, if any, appears as containment events.' },
      })
    }
  }

  ;(Array.isArray(evidence.alerts) ? evidence.alerts : []).forEach((a, i) => {
    push(all, {
      id: `alert-${a?._id || i}`, kind: 'alert', order: next(), rawTime: a?.createdAt, basis: 'record', link: a?.linkedVia === 'threat' ? 'threat' : 'session',
      provenance: PROVENANCE.DERIVED, title: `Alert: ${a?.title || a?.type || 'recorded'}`,
      detail: { severity: a?.severity, type: a?.type, message: a?.message },
    })
  })

  ;(Array.isArray(evidence.containment) ? evidence.containment : []).forEach((c, ci) => {
    const base = { kind: 'containment', basis: 'event', link: 'threat', provenance: enforcementProvenance(c?.enforcementBackend) }
    const common = { containmentId: c?.containmentId, backend: c?.enforcementBackend, enforcement: enforcementLabel(c?.enforcementBackend), actionType: c?.actionType, policyDecision: c?.policyDecision, currentStatus: c?.enforcementStatus, target: c?.target, rolledBackAt: c?.rolledBackAt || null, failureReason: c?.failureReason || null }
    const transitions = Array.isArray(c?.transitions) ? c.transitions : []
    if (transitions.length) {
      transitions.forEach((t, ti) => push(all, { ...base, id: `containment-${ci}-${t?.seq ?? ti}`, order: next(), rawTime: t?.occurredAt, title: `Containment ${String(t?.action || t?.enforcementStatus || 'event').toLowerCase().replace(/_/g, ' ')}`, detail: { ...common, transition: t?.action, status: t?.enforcementStatus } }))
    } else {
      // No audit trail stored: show the lifecycle timestamps the action record itself carries.
      const stamps = [['requested', c?.requestedAt, 'REQUESTED'], ['applied', c?.appliedAt, 'ACTIVE'], ['rolled back', c?.rolledBackAt, 'ROLLED_BACK']]
      stamps.filter(([, at]) => at).forEach(([label, at, status]) => push(all, { ...base, id: `containment-${ci}-${status}`, order: next(), rawTime: at, title: `Containment ${label}`, detail: { ...common, status } }))
    }
  })

  ;(Array.isArray(evidence.blockedIPs) ? evidence.blockedIPs : []).forEach((b, i) => {
    push(all, {
      id: `blocklist-${i}`, kind: 'blocklist', order: next(), rawTime: b?.blockedAt ?? b?.createdAt, basis: 'record', link: 'threat',
      provenance: PROVENANCE.DERIVED, title: 'Deny-list record created',
      detail: { reason: b?.reason, note: 'A deny-list entry; it does not by itself show that a connection was denied.' },
    })
  })

  const timed = all.filter((e) => e.time !== null)
  timed.sort((a, b) => a.time - b.time || (KIND_RANK[a.kind] ?? 99) - (KIND_RANK[b.kind] ?? 99) || a.order - b.order || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  return { events: timed, untimed: all.filter((e) => e.time === null) }
}

/**
 * Every technique with the events it came from; order of first appearance. threatOnly marks techniques that come
 * only from the linked threat record (shared by sessions from one source), not from this session's own evidence.
 */
export function techniqueIndex(events = [], session = null) {
  const map = new Map()
  const entry = (t) => {
    if (!map.has(t.id)) map.set(t.id, { id: t.id, name: t.name, eventIds: [], threatOnly: true })
    return map.get(t.id)
  }
  for (const ev of events) {
    for (const t of ev.techniques || []) {
      const e = entry(t)
      e.eventIds.push(ev.id)
      if (ev.link !== 'threat') e.threatOnly = false
    }
  }
  for (const t of techniqueList(session?.mitreTechniques)) entry(t).threatOnly = false
  return [...map.values()]
}

/** Seconds from stored duration, else from start and end, else null (never from processing timestamps). */
export function sessionDuration(session) {
  if (!session) return null
  const start = parseTime(session.startTime)
  const end = parseTime(session.endTime)
  if (Number.isFinite(session.durationSeconds) && session.durationSeconds > 0) return session.durationSeconds
  if (start !== null && end !== null && end >= start) return Math.round((end - start) / 1000)
  if (session.durationSeconds === 0 && end !== null) return 0
  return null
}

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

export function summarize(evidence, events = [], untimed = []) {
  const s = evidence?.session || {}
  const commands = Array.isArray(s.commands) ? s.commands.length : 0
  const all = [...events, ...untimed]
  const severities = [evidence?.threat?.severity, ...(evidence?.alerts || []).map((a) => a?.severity)].filter((v) => SEVERITY_ORDER.includes(v))
  const highest = severities.sort((a, b) => SEVERITY_ORDER.indexOf(b) - SEVERITY_ORDER.indexOf(a))[0] || null
  return {
    durationSeconds: sessionDuration(s),
    commandsCaptured: Number.isFinite(s.commandCount) && s.commandCount > commands ? s.commandCount : commands,
    commandsStored: commands,
    techniques: techniqueIndex(all, s).filter((t) => !t.threatOnly).length,
    highestSeverity: highest,
    threatScore: Number.isFinite(s.aiThreatScore) && s.aiClassification ? s.aiThreatScore : null,
    persona: s.servedProfile || null,
    status: s.status || null,
    responseEvents: all.filter((e) => e.kind === 'containment').length,
  }
}

export function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return 'Unavailable'
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  return m < 60 ? `${m}m ${seconds % 60}s` : `${Math.floor(m / 60)}h ${m % 60}m`
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`
const STATUS_TEXT = { active: 'The session is still recorded as active.', closed: 'The session was recorded as closed.', analysed: 'The session was closed and analysed.' }

/** Deterministic plain-language summary composed only from verified fields. */
export function narrative(summary) {
  const parts = []
  const d = summary.durationSeconds
  parts.push(Number.isFinite(d)
    ? `This session lasted ${formatDuration(d)} and contained ${plural(summary.commandsCaptured, 'recorded command')}.`
    : `This session contained ${plural(summary.commandsCaptured, 'recorded command')}; its duration is not recorded.`)
  if (summary.commandsCaptured > summary.commandsStored) parts.push(`${summary.commandsStored} of them are stored for replay.`)
  parts.push(summary.techniques
    ? `The recorded activity was mapped to ${plural(summary.techniques, 'MITRE ATT&CK technique')}.`
    : 'No MITRE ATT&CK technique was mapped.')
  if (summary.highestSeverity) parts.push(`The highest linked severity was ${summary.highestSeverity}.`)
  if (summary.responseEvents) parts.push(`${plural(summary.responseEvents, 'linked containment event')} ${summary.responseEvents === 1 ? 'is' : 'are'} recorded.`)
  parts.push(STATUS_TEXT[summary.status] || 'The final session status is not recorded.')
  return parts.join(' ')
}
