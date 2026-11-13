import { useEffect, useState } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import { systemAPI } from '../services/api.js'
import { LABEL_META, labelMeta } from '../utils/capabilities.js'

const mono = { fontFamily: 'JetBrains Mono, monospace' }

function Facts({ facts }) {
  if (!facts || typeof facts !== 'object' || Object.keys(facts).length === 0) return null
  return (
    <details style={{ marginTop: 6 }}>
      <summary style={{ cursor: 'pointer', fontSize: 11, color: '#3a6a88', ...mono }}>FACTS</summary>
      <pre data-testid="capability-facts" style={{ fontSize: 11, color: '#7ab3cc', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', margin: '6px 0 0' }}>
        {JSON.stringify(facts, null, 2)}
      </pre>
    </details>
  )
}

export default function CapabilityStatus() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    let alive = true
    setLoading(true)
    systemAPI
      .capabilities()
      .then((r) => alive && (setData(r.data.data), setError(null)))
      .catch((e) => alive && setError(e?.response?.data?.error || 'Capability status is unavailable'))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [reload])

  return (
    <DashboardLayout>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700, margin: 0 }}>
          Capability <span style={{ color: '#00d4ff' }}>Status</span>
        </h1>
        <div style={{ ...mono, fontSize: 11, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
          What SentinelAI actually does right now, read from the running system. Simulated, shadow-only and experimental
          features are labelled as such and are never presented as production capability.
        </div>
        <div data-testid="capability-legend" style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
          {Object.entries(LABEL_META).map(([k, m]) => (
            <span key={k} style={{ fontSize: 10, ...mono, color: m.color, border: `1px solid ${m.color}`, borderRadius: 3, padding: '2px 6px' }}>{m.text}</span>
          ))}
        </div>
      </div>
      <Panel title="Capabilities" badge={data ? `${data.items.length}` : ''} badgeType="info">
        {loading && !data && <div style={{ fontSize: 13, color: '#7ab3cc' }}>Loading…</div>}
        {error && (
          <div role="alert" data-testid="capability-error" style={{ fontSize: 13, color: '#ffaa00' }}>
            {error}{' '}
            <button type="button" onClick={() => setReload((k) => k + 1)} style={{ background: 'none', border: '1px solid #ffaa00', color: '#ffaa00', borderRadius: 3, cursor: 'pointer' }}>Retry</button>
          </div>
        )}
        {data && (
          <ul data-testid="capability-list" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }}>
            {data.items.map((i) => {
              const m = labelMeta(i.label)
              return (
                <li key={i.id} data-testid={`capability-${i.id}`} style={{ borderLeft: `3px solid ${m.color}`, padding: '6px 10px', background: 'rgba(0,20,40,0.35)' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'baseline' }}>
                    <strong style={{ fontSize: 14 }}>{i.title}</strong>
                    <span data-testid={`capability-label-${i.id}`} style={{ fontSize: 10, ...mono, color: m.color }}>{m.text}</span>
                  </div>
                  <div style={{ fontSize: 13, color: '#c8dce8', marginTop: 4, lineHeight: 1.5 }}>{i.summary}</div>
                  <Facts facts={i.facts} />
                </li>
              )
            })}
          </ul>
        )}
        {data && <div style={{ fontSize: 11, color: '#3a6a88', marginTop: 10, ...mono }}>Generated {new Date(data.generatedAt).toLocaleString()}</div>}
      </Panel>
    </DashboardLayout>
  )
}
