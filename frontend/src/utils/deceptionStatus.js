// Labels for the Honeypot Analytics "Adaptive Deception" panel (GET /honeypot/deception/status and friends).

const SOURCE_LABELS = {
  setting: 'recorded deception setting',
  env: 'environment default',
  latest_session: 'persona of the latest recorded session',
  default: 'built-in default; nothing recorded yet',
}

/** Where the serving persona comes from. It is the recorded value, never an SSH verification. */
export function profileSourceLabel(source) {
  return SOURCE_LABELS[source] || `source: ${source || 'unknown'}`
}

const shortId = (id) => (id ? `…${String(id).slice(-8)}` : '…')

/** One line about the most recent decision that is no longer pending. */
export function closedDecisionSummary(d) {
  if (!d) return 'No earlier decision has been applied, failed or expired yet.'
  const move = d.action === d.state ? `keep ${d.state}` : `${d.state} → ${d.action}`
  if (d.status === 'APPLIED') return `Last decision ${shortId(d.decisionId)}: APPLIED by the rotator (${move}).`
  if (d.status === 'FAILED')
    return `Last decision ${shortId(d.decisionId)}: FAILED (${move})${d.failureReason ? `: ${d.failureReason}` : ''}.`
  if (d.status === 'SUPERSEDED')
    return `Last decision ${shortId(d.decisionId)}: EXPIRED or superseded before it was applied (${move}).`
  return `Last decision ${shortId(d.decisionId)}: ${d.status} (${move}).`
}

/** Real (scored) versus synthetic session counts behind the learner. */
export function learningCountsSummary(l) {
  if (!l) return 'Session-learning counts unavailable.'
  const n = (v) => (Number.isFinite(v) ? v : 0)
  return (
    `Learning: ${n(l.scoredRealSessions)} real session${n(l.scoredRealSessions) === 1 ? '' : 's'} scored; ` +
    `${n(l.syntheticSessionsSkipped)} synthetic demo session${n(l.syntheticSessionsSkipped) === 1 ? '' : 's'} skipped; ` +
    `${n(l.sessionsAwaitingScoring)} awaiting scoring.`
  )
}

/** Persona policy v2 shadow evidence (recorded, never applied). */
export function shadowSummary(shadow) {
  if (!shadow || !shadow.sessionsWithEvidence) return 'Persona policy v2 (shadow): no evidence recorded yet.'
  const latest = shadow.latest
  const pick = latest?.recommendation ? `latest shadow pick ${latest.recommendation}` : 'no latest pick'
  const version = latest?.version ? ` (${latest.version})` : ''
  return (
    `Persona policy v2 (shadow, never applied): ${pick}${version}; agrees with the active policy in ` +
    `${shadow.agreementsWithActivePolicy} of ${shadow.sessionsWithEvidence} scored sessions.`
  )
}

/** Stable fingerprint of what the panel shows, to tell "updated" from "no change" after a refresh. */
export function deceptionSignature(profile, rec, status) {
  return JSON.stringify([
    profile?.profile ?? null,
    profile?.source ?? null,
    rec?.decisionId ?? null,
    rec?.nextProfile ?? null,
    rec?.policy ?? null,
    rec?.provenance?.sessionEpisodes ?? null,
    status?.lastClosedDecision?.decisionId ?? null,
    status?.lastClosedDecision?.status ?? null,
    status?.learning?.scoredRealSessions ?? null,
    status?.learning?.sessionsAwaitingScoring ?? null,
    status?.shadow?.sessionsWithEvidence ?? null,
  ])
}

/** Readable message for a failed API request. */
export function requestErrorMessage(err, prefix) {
  const status = err?.response?.status
  if (!err?.response) return `${prefix}: the server could not be reached.`
  if (status === 401) return `${prefix}: your session has expired. Sign in again.`
  if (status === 403) return `${prefix}: your role cannot view this.`
  if (status === 503) return `${prefix}: AI engine unreachable.`
  const msg = err.response?.data?.error
  return `${prefix}${msg ? `: ${msg}` : ` (HTTP ${status})`}.`
}
