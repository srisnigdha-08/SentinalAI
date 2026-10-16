// This display annotation is not authenticated model provenance or an enforcement claim.
export function threatEvidenceLabel(threat) {
  if (typeof threat?.notes === 'string' && threat.notes.startsWith('[RF_IF_RECLASSIFIED]'))
    return 'RF/IF reclassified after session-open heuristic'
  return typeof threat?.notes === 'string' && threat.notes.startsWith('[SESSION_OPEN_HEURISTIC]')
    ? 'Session-open heuristic; not an RF/IF prediction'
    : null
}
