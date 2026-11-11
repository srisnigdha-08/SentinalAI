import { useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import TrustBadge from '../components/trustMeter/TrustBadge.jsx'
import TrustDetails, { ModelLimitations, btn } from '../components/trustMeter/TrustDetails.jsx'
import { aiAPI } from '../services/api.js'
import { dateText, timeText } from '../utils/reportingTime.js'
import { STATE_KEYS, STATE_META, pct, stateSummary } from '../utils/trustMeter.js'

const OBJECT_ID = /^[a-f0-9]{24}$/i
const PAGE_SIZE = 15
const mono = { fontFamily: 'Share Tech Mono,monospace' }
const field = { background: '#020b18', border: '1px solid #1a4a6e', color: '#c8e6f5', borderRadius: 2, padding: '7px 10px', ...mono, fontSize: 12, minWidth: 0 }
const label = { display: 'flex', flexDirection: 'column', gap: 4, ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1 }
const dayBound = (day, end) => (day ? `${day}T${end ? '23:59:59.999' : '00:00:00.000'}Z` : undefined)
const errorText = (err, what) => (err?.response?.status === 404 ? err.response.data?.error || 'Not found.' : `${what} could not be loaded.`)

function Summary({ summary, active, onPick }) {
  if (!summary) return null
  const n = summary.inScope
  return (
    <div>
      <div className="trust-summary" role="group" aria-label="Predictions by assessment state">
        {STATE_KEYS.map((s) => (
          <button
            key={s} type="button" data-testid={`trust-count-${s}`} aria-pressed={active === s}
            onClick={() => onPick(active === s ? '' : s)}
            style={{ textAlign: 'left', cursor: 'pointer', background: '#081f35', border: `1px solid ${active === s ? STATE_META[s].color : '#0d3352'}`, padding: '0.8rem', color: '#c8e6f5', borderRadius: 2 }}
          >
            <TrustBadge state={s} />
            <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 22, margin: '8px 0 2px' }}>{summary.byState[s] ?? 0}</div>
            <div style={{ ...mono, fontSize: 10, color: '#3a6a88' }}>OF {n} IN SCOPE</div>
          </button>
        ))}
      </div>
      <div style={{ ...mono, fontSize: 10, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
        Scope: {n} stored ML flow predictions matching the filters (rule-based honeypot verdicts are not ML and are excluded).
        Input completeness was recorded for {summary.completenessRecorded} of {n}; the rest cannot be fully checked.
      </div>
    </div>
  )
}

export default function AITrustMeter() {
  const [params, setParams] = useSearchParams()
  const selected = OBJECT_ID.test(params.get('prediction') || '') ? params.get('prediction') : null
  const q = params.get('q') || ''
  const state = STATE_KEYS.includes(params.get('state')) ? params.get('state') : ''
  const cls = params.get('cls') || ''
  const ver = params.get('ver') || ''
  const from = params.get('from') || ''
  const to = params.get('to') || ''
  const sort = ['oldest', 'score'].includes(params.get('sort')) ? params.get('sort') : 'newest'
  const page = Math.max(1, parseInt(params.get('page'), 10) || 1)

  const [draft, setDraft] = useState(q)
  const [list, setList] = useState({ loading: true, error: null, rows: [], pagination: null, summary: null, facets: null })
  const [detail, setDetail] = useState({ loading: false, error: null, prediction: null })
  const [reload, setReload] = useState(0)
  const detailReq = useRef(0)

  useEffect(() => setDraft(q), [q])

  useEffect(() => {
    if (selected) return undefined
    let live = true
    setList((l) => ({ ...l, loading: true, error: null }))
    aiAPI
      .trustList({ page, limit: PAGE_SIZE, sort, q: q || undefined, state: state || undefined, predictedClass: cls || undefined, modelVersion: ver || undefined, from: dayBound(from, false), to: dayBound(to, true) })
      .then((r) => live && setList({ loading: false, error: null, rows: r.data?.data || [], pagination: r.data?.pagination || null, summary: r.data?.summary || null, facets: r.data?.facets || null }))
      .catch((err) => live && setList((l) => ({ ...l, loading: false, error: errorText(err, 'Predictions') })))
    return () => { live = false }
  }, [selected, page, sort, q, state, cls, ver, from, to, reload])

  useEffect(() => {
    const req = ++detailReq.current
    if (!selected) { setDetail({ loading: false, error: null, prediction: null }); return }
    setDetail({ loading: true, error: null, prediction: null })
    aiAPI.trustGet(selected)
      .then((r) => req === detailReq.current && setDetail({ loading: false, error: null, prediction: r.data?.data?.prediction || null }))
      .catch((err) => req === detailReq.current && setDetail({ loading: false, error: errorText(err, 'This prediction'), prediction: null }))
  }, [selected, reload])

  const update = (patch) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) (v ? next.set(k, v) : next.delete(k))
    if (!('page' in patch) && !('prediction' in patch)) next.delete('page')
    setParams(next)
  }
  const filtered = Boolean(q || state || cls || ver || from || to)

  return (
    <DashboardLayout>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700, margin: 0 }}>
          AI <span style={{ color: '#00d4ff' }}>Trust Meter</span>
        </h1>
        <div style={{ ...mono, fontSize: 11, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
          How far each stored prediction can be relied on, from the evidence SentinelAI recorded: input completeness, classifier output and the anomaly signal.
          There is no trust percentage. Classifier confidence is the model’s own output, not a measured chance of being right.
        </div>
      </div>

      {selected ? (
        detail.loading ? (
          <div role="status" style={{ ...mono, fontSize: 12, color: '#3a6a88' }}>Loading prediction…</div>
        ) : detail.error ? (
          <div role="alert" style={{ ...mono, fontSize: 12, color: '#ffaa00', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
            {detail.error}
            <button type="button" style={btn} onClick={() => setReload((k) => k + 1)}>Retry</button>
            <button type="button" style={btn} onClick={() => update({ prediction: '' })}>← Prediction history</button>
          </div>
        ) : detail.prediction ? (
          <TrustDetails prediction={detail.prediction} onBack={() => update({ prediction: '' })} />
        ) : null
      ) : (
        <>
          <div style={{ marginBottom: '1rem' }}>
            {list.summary && <Summary summary={list.summary} active={state} onPick={(s) => update({ state: s })} />}
          </div>

          <Panel title="Prediction history" badge={list.pagination ? `${list.pagination.total} SHOWN BY FILTER` : undefined} badgeType="info" style={{ marginBottom: '1rem' }}>
            <form role="search" aria-label="Filter predictions" onSubmit={(e) => { e.preventDefault(); update({ q: draft.trim() }) }}
              style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'flex-end', marginBottom: '1rem' }}>
              <label style={{ ...label, flex: '1 1 200px' }}>
                SOURCE IP OR CLASS
                <input data-testid="trust-search" style={field} value={draft} maxLength={64} onChange={(e) => setDraft(e.target.value)} placeholder="e.g. 198.51 or DDoS" />
              </label>
              <label style={label}>
                ASSESSMENT
                <select data-testid="trust-state" style={field} value={state} onChange={(e) => update({ state: e.target.value })}>
                  <option value="">All</option>
                  {STATE_KEYS.map((s) => <option key={s} value={s}>{STATE_META[s].label}</option>)}
                </select>
              </label>
              <label style={label}>
                CLASS
                <select data-testid="trust-class-filter" style={field} value={cls} onChange={(e) => update({ cls: e.target.value })}>
                  <option value="">All</option>
                  {(list.facets?.classes || []).map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </label>
              <label style={label}>
                MODEL VERSION
                <select style={field} value={ver} onChange={(e) => update({ ver: e.target.value })}>
                  <option value="">All</option>
                  {(list.facets?.modelVersions || []).map((v) => <option key={v} value={v}>{v}</option>)}
                </select>
              </label>
              <label style={label}>FROM (UTC)<input type="date" style={field} value={from} onChange={(e) => update({ from: e.target.value })} /></label>
              <label style={label}>TO (UTC)<input type="date" style={field} value={to} onChange={(e) => update({ to: e.target.value })} /></label>
              <label style={label}>
                ORDER
                <select style={field} value={sort} onChange={(e) => update({ sort: e.target.value === 'newest' ? '' : e.target.value })}>
                  <option value="newest">Newest first</option>
                  <option value="oldest">Oldest first</option>
                  <option value="score">Highest threat score</option>
                </select>
              </label>
              <button type="submit" style={btn}>Search</button>
              {filtered && <button type="button" style={btn} onClick={() => setParams(new URLSearchParams())}>Clear</button>}
            </form>

            {list.error ? (
              <div role="alert" style={{ ...mono, fontSize: 12, color: '#ffaa00' }}>
                {list.error} <button type="button" style={btn} onClick={() => setReload((k) => k + 1)}>Retry</button>
              </div>
            ) : list.loading ? (
              <div role="status" style={{ ...mono, fontSize: 12, color: '#3a6a88' }}>Loading predictions…</div>
            ) : list.rows.length === 0 ? (
              <div data-testid="trust-empty" style={{ padding: '2rem 1rem', textAlign: 'center', color: '#7ab3cc' }}>
                <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 13, marginBottom: 6 }}>NO PREDICTIONS</div>
                <div style={{ ...mono, fontSize: 11, color: '#3a6a88' }}>
                  {filtered ? 'No stored ML prediction matches these filters.' : 'No ML flow prediction has been stored yet. Predictions appear here once the AI engine scores network flows.'}
                </div>
              </div>
            ) : (
              <div className="sentinel-table-scroll">
                <table data-testid="trust-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
                  <caption style={{ position: 'absolute', left: -9999 }}>Stored ML predictions and their trust assessment</caption>
                  <thead>
                    <tr style={{ textAlign: 'left', ...mono, fontSize: 10, color: '#3a6a88', letterSpacing: 1 }}>
                      {['TIME', 'SOURCE', 'PREDICTED', 'CONFIDENCE', 'THREAT SCORE', 'ASSESSMENT', 'MAIN FINDING', ''].map((h) => (
                        <th key={h} scope="col" style={{ padding: '6px 8px', borderBottom: '1px solid #0d3352', whiteSpace: 'nowrap' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {list.rows.map((p) => {
                      const t = Date.parse(p.createdAt)
                      return (
                        <tr key={p._id} data-testid="trust-row" style={{ borderBottom: '1px solid rgba(13,51,82,.6)' }}>
                          <td style={{ padding: 8, whiteSpace: 'nowrap' }}>{Number.isFinite(t) ? `${dateText(t)} ${timeText(t)}` : 'Unknown'}</td>
                          <td style={{ padding: 8, ...mono }}>{p.sourceIP || '—'}</td>
                          <td style={{ padding: 8 }}>{p.predictedClass}</td>
                          <td style={{ padding: 8, ...mono }}>{pct(p.trust?.classifier?.confidence)}</td>
                          <td style={{ padding: 8, ...mono }}>{pct(p.trust?.threatScore)}</td>
                          <td style={{ padding: 8 }}>{p.trust ? <TrustBadge state={p.trust.state} /> : 'Not assessed'}</td>
                          <td style={{ padding: 8, color: '#7ab3cc' }}>{stateSummary(p.trust)}</td>
                          <td style={{ padding: 8, textAlign: 'right' }}>
                            <button type="button" style={{ ...btn, color: '#00d4ff', borderColor: '#00d4ff' }} onClick={() => update({ prediction: p._id })} aria-label={`Open trust assessment for ${p.predictedClass} prediction from ${p.sourceIP || 'unknown source'}`}>
                              Assess ›
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {list.pagination && list.pagination.pages > 1 && !list.error && (
              <nav aria-label="Prediction pages" style={{ display: 'flex', gap: 10, alignItems: 'center', justifyContent: 'flex-end', marginTop: 12 }}>
                <button type="button" style={btn} disabled={page <= 1} onClick={() => update({ page: String(page - 1) })}>‹ Prev</button>
                <span style={{ ...mono, fontSize: 11, color: '#7ab3cc' }}>PAGE {page} / {list.pagination.pages}</span>
                <button type="button" style={btn} disabled={page >= list.pagination.pages} onClick={() => update({ page: String(page + 1) })}>Next ›</button>
              </nav>
            )}
          </Panel>
          <ModelLimitations />
        </>
      )}
    </DashboardLayout>
  )
}
