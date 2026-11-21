// Capability Status presentation helpers. Labels and facts come from GET /api/system/capabilities; this file only
// maps them to colours and wording. A label is never upgraded here.

export const LABEL_META = Object.freeze({
  implemented_and_verified: { text: 'IMPLEMENTED AND VERIFIED', color: '#00e5a0' },
  implemented_and_tested: { text: 'IMPLEMENTED AND TESTED', color: '#00ff88' },
  implemented_and_tested_simulated: { text: 'IMPLEMENTED AND TESTED — SIMULATED', color: '#ffaa00' },
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
  if (status.mode === 'pcap_replay' && status.state === 'failed')
    return { text: 'Traffic: PCAP replay failed (live capture not enabled)', color: '#ff6b6b', title: status.reason || 'The recorded PCAP could not be replayed.' }
  if (status.mode === 'pcap_replay')
    return { text: `Traffic: recorded PCAP replay${status.state === 'finished' ? ' (finished)' : ''}`, color: '#ffaa00', title: 'Recorded traffic, not live. Live capture is a separate, disabled capability.' }
  return { text: 'Traffic: unknown', color: '#8ba3b5', title: '' }
}

// Where one prediction's flow came from (AIPrediction.captureSource, also on the ai_prediction socket event).
// Missing or unrecognised values are shown as unknown, never as live.
export const CAPTURE_SOURCE_META = Object.freeze({
  pcap_replay: { short: 'PCAP REPLAY', text: 'Recorded PCAP replay (not live traffic)', color: '#ffaa00' },
  live_passive: { short: 'LIVE CAPTURE', text: 'Live passive capture', color: '#00ff88' },
  dataset_replay: { short: 'DATASET REPLAY', text: 'Dataset replay (not live traffic)', color: '#ffaa00' },
  manual: { short: 'MANUAL', text: 'Submitted manually', color: '#7ab3cc' },
  unknown: { short: 'SOURCE UNKNOWN', text: 'Capture source not recorded', color: '#8ba3b5' },
})

export const captureSourceMeta = (source) =>
  (typeof source === 'string' && Object.prototype.hasOwnProperty.call(CAPTURE_SOURCE_META, source)
    ? CAPTURE_SOURCE_META[source]
    : CAPTURE_SOURCE_META.unknown)

// Threat-level explanation of the automatic-containment decision.
export const DECISION_TEXT = Object.freeze({
  AUTO_BLOCK: 'Automatic containment requested (correlated evidence)',
  NEEDS_APPROVAL: 'Held for analyst approval (not enough correlated evidence)',
  SUPPRESSED_TRUSTED: 'Not contained: trusted or protected address',
  SUPPRESSED_DUPLICATE: 'Not contained again: already contained or recently requested',
  MONITOR: 'Below the block line',
  DISABLED: 'Auto-block is off',
})
