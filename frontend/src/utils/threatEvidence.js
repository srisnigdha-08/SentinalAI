// This display annotation is not authenticated model provenance or an enforcement claim.
// [RF_IF_RECLASSIFIED] is the legacy spelling of the same honeypot marker; those sessions were also
// classified by rules, so both get the rule label.
const RULE_RECLASSIFIED_MARKERS = ['[HONEYPOT_RULES_RECLASSIFIED]', '[RF_IF_RECLASSIFIED]']

export function threatEvidenceLabel(threat) {
  if (typeof threat?.notes === 'string' && RULE_RECLASSIFIED_MARKERS.some((m) => threat.notes.startsWith(m)))
    return 'Rule-reclassified after session-open heuristic'
  return typeof threat?.notes === 'string' && threat.notes.startsWith('[SESSION_OPEN_HEURISTIC]')
    ? 'Session-open heuristic; not an RF/IF prediction'
    : null
}
