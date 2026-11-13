// Capability Status presentation helpers. Labels and facts come from GET /api/system/capabilities; this file only
// maps them to colours and wording. A label is never upgraded here.

export const LABEL_META = Object.freeze({
  implemented_and_tested: { text: 'IMPLEMENTED AND TESTED', color: '#00ff88' },
  implemented_not_enabled: { text: 'IMPLEMENTED, NOT ENABLED', color: '#7ab3cc' },
  simulated: { text: 'SIMULATED', color: '#ffaa00' },
  shadow_only: { text: 'SHADOW ONLY', color: '#b388ff' },
  experimental: { text: 'EXPERIMENTAL', color: '#ffd166' },
  blocked: { text: 'BLOCKED (INFRASTRUCTURE / EVIDENCE)', color: '#ff6b6b' },
  not_implemented: { text: 'NOT IMPLEMENTED', color: '#8ba3b5' },
})

export const labelMeta = (label) => LABEL_META[label] || { text: 'UNKNOWN', color: '#8ba3b5' }

// The dashboard's traffic-source chip. A replay is never called live.
export function captureChip(status) {
  if (!status || status.mode === 'unavailable')
    return { text: 'Traffic: capture unavailable', color: '#8ba3b5', title: status?.reason || 'No capture service is reporting.' }
  if (status.mode === 'live_passive')
    return { text: `Traffic: LIVE passive capture${status.last?.interface ? ` (${status.last.interface})` : ''}`, color: '#00ff88', title: 'Receive-only capture of one interface' }
  if (status.mode === 'pcap_replay')
    return { text: `Traffic: recorded PCAP replay${status.state === 'finished' ? ' (finished)' : ''}`, color: '#ffaa00', title: 'Recorded traffic, not live' }
  return { text: 'Traffic: unknown', color: '#8ba3b5', title: '' }
}

// Threat-level explanation of the automatic-containment decision.
export const DECISION_TEXT = Object.freeze({
  AUTO_BLOCK: 'Automatic containment requested (correlated evidence)',
  NEEDS_APPROVAL: 'Held for analyst approval (not enough correlated evidence)',
  SUPPRESSED_TRUSTED: 'Not contained: trusted or protected address',
  SUPPRESSED_DUPLICATE: 'Not contained again: already contained or recently requested',
  MONITOR: 'Below the block line',
  DISABLED: 'Auto-block is off',
})
