import { PROVENANCE_META } from '../../utils/attackTimeline.js'

// Icon + text + colour, so the evidence category never depends on colour alone.
export default function ProvenanceBadge({ provenance, compact = false }) {
  const meta = PROVENANCE_META[provenance] || PROVENANCE_META.UNKNOWN
  return (
    <span
      data-provenance={provenance}
      title={meta.help}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap',
        fontFamily: 'Share Tech Mono,monospace', fontSize: 10, letterSpacing: 1,
        padding: compact ? '1px 6px' : '2px 8px', borderRadius: 1,
        color: meta.color, border: `1px solid ${meta.color}55`, background: `${meta.color}14`,
      }}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label.toUpperCase()}
    </span>
  )
}
