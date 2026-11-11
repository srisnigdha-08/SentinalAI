import { STATE_META } from '../../utils/trustMeter.js'

// Icon + text + colour, so the state never depends on colour alone.
export default function TrustBadge({ state, large = false }) {
  const meta = STATE_META[state] || { label: 'Not assessed', icon: '–', color: '#7ab3cc' }
  return (
    <span
      data-trust-state={state}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap',
        fontFamily: 'Share Tech Mono,monospace', fontSize: large ? 12 : 10, letterSpacing: 1,
        padding: large ? '4px 10px' : '2px 7px', borderRadius: 1,
        color: meta.color, border: `1px solid ${meta.color}66`, background: `${meta.color}14`,
      }}
    >
      <span aria-hidden="true">{meta.icon}</span>
      {meta.label.toUpperCase()}
    </span>
  )
}
