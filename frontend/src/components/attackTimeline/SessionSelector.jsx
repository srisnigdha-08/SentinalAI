import { useEffect, useState } from 'react'
import Panel from '../Panel.jsx'
import SeverityBadge from '../SeverityBadge.jsx'
import { honeypotAPI } from '../../services/api.js'
import { dateText, timeText } from '../../utils/reportingTime.js'
import { formatDuration, parseTime } from '../../utils/attackTimeline.js'

const PAGE_SIZE = 10
const STATUSES = ['active', 'closed', 'analysed']
const field = {
  background: '#020b18', border: '1px solid #1a4a6e', color: '#c8e6f5', borderRadius: 2,
  padding: '7px 10px', fontFamily: 'Share Tech Mono,monospace', fontSize: 12, minWidth: 0,
}
const label = { display: 'flex', flexDirection: 'column', gap: 4, fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88', letterSpacing: 1 }
export const btn = {
  background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc', borderRadius: 2,
  fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: 1,
  padding: '7px 12px', cursor: 'pointer', textTransform: 'uppercase',
}

const when = (value) => {
  const t = parseTime(value)
  return t === null ? 'Unknown time' : `${dateText(t)} ${timeText(t)}`
}
// <input type="date"> gives yyyy-mm-dd; bound the whole day in UTC so the API filter is unambiguous.
const dayBound = (day, end) => (day ? `${day}T${end ? '23:59:59.999' : '00:00:00.000'}Z` : undefined)

export default function SessionSelector({ params, setParams, onOpen }) {
  const q = params.get('q') || ''
  const status = params.get('status') || ''
  const sort = params.get('sort') === 'oldest' ? 'oldest' : 'newest'
  const from = params.get('from') || ''
  const to = params.get('to') || ''
  const page = Math.max(1, parseInt(params.get('page'), 10) || 1)

  const [draft, setDraft] = useState(q)
  const [rows, setRows] = useState([])
  const [pagination, setPagination] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [reloadKey, setReloadKey] = useState(0)

  useEffect(() => setDraft(q), [q])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    honeypotAPI
      .sessions({ page, limit: PAGE_SIZE, sort, q: q || undefined, status: status || undefined, from: dayBound(from, false), to: dayBound(to, true) })
      .then((r) => {
        if (cancelled) return
        setRows(Array.isArray(r.data?.data) ? r.data.data : [])
        setPagination(r.data?.pagination || null)
      })
      .catch(() => !cancelled && setError('Recorded sessions could not be loaded.'))
      .finally(() => !cancelled && setLoading(false))
    return () => { cancelled = true }
  }, [page, sort, q, status, from, to, reloadKey])

  const update = (patch) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) (v ? next.set(k, v) : next.delete(k))
    if (!('page' in patch)) next.delete('page')
    setParams(next)
  }
  const filtered = Boolean(q || status || from || to)

  return (
    <Panel title="Recorded attack sessions" badge={pagination ? `${pagination.total} SESSIONS` : undefined} badgeType="info">
      <form
        role="search"
        aria-label="Filter recorded sessions"
        onSubmit={(e) => { e.preventDefault(); update({ q: draft.trim() }) }}
        style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'flex-end', marginBottom: '1rem' }}
      >
        <label style={{ ...label, flex: '1 1 220px' }}>
          SESSION ID OR SOURCE IP
          <input data-testid="atm-search" style={field} value={draft} maxLength={64} onChange={(e) => setDraft(e.target.value)} placeholder="e.g. cowrie-sess or 185.220" />
        </label>
        <label style={label}>
          STATUS
          <select data-testid="atm-status" style={field} value={status} onChange={(e) => update({ status: e.target.value })}>
            <option value="">All</option>
            {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label style={label}>
          FROM (UTC)
          <input type="date" style={field} value={from} onChange={(e) => update({ from: e.target.value })} />
        </label>
        <label style={label}>
          TO (UTC)
          <input type="date" style={field} value={to} onChange={(e) => update({ to: e.target.value })} />
        </label>
        <label style={label}>
          ORDER
          <select data-testid="atm-sort" style={field} value={sort} onChange={(e) => update({ sort: e.target.value === 'oldest' ? 'oldest' : '' })}>
            <option value="newest">Newest first</option>
            <option value="oldest">Oldest first</option>
          </select>
        </label>
        <button type="submit" style={btn}>Search</button>
        {filtered && <button type="button" style={btn} onClick={() => setParams(new URLSearchParams())}>Clear</button>}
      </form>

      {error && (
        <div role="alert" style={{ color: '#ff2d55', fontFamily: 'Share Tech Mono,monospace', fontSize: 12, marginBottom: 12 }}>
          {error}{' '}
          <button type="button" style={btn} onClick={() => setReloadKey((k) => k + 1)}>Retry</button>
        </div>
      )}

      {loading ? (
        <div role="status" style={{ color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>Loading recorded sessions…</div>
      ) : !error && rows.length === 0 ? (
        <div data-testid="atm-empty" style={{ padding: '2rem 1rem', textAlign: 'center', color: '#7ab3cc' }}>
          <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 13, marginBottom: 6 }}>NO RECORDED SESSIONS</div>
          <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88' }}>
            {filtered ? 'No recorded honeypot session matches these filters.' : 'The honeypot has not recorded any attack session yet. Sessions appear here once Cowrie captures a connection.'}
          </div>
        </div>
      ) : !error && (
        <div className="sentinel-table-scroll">
          <table data-testid="atm-session-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <caption style={{ position: 'absolute', left: -9999 }}>Recorded honeypot sessions; open one to replay its timeline</caption>
            <thead>
              <tr style={{ textAlign: 'left', fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88', letterSpacing: 1 }}>
                {['SESSION', 'SOURCE IP', 'STARTED', 'DURATION', 'STATUS', 'COMMANDS', 'SEVERITY / SCORE', 'PERSONA', ''].map((h) => (
                  <th key={h} scope="col" style={{ padding: '6px 8px', borderBottom: '1px solid #0d3352', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => {
                const commands = Number.isFinite(s.commandCount) && s.commandCount > 0 ? s.commandCount : (s.commands || []).length
                const severity = s.linkedThreatLog?.severity
                const score = s.aiClassification && Number.isFinite(s.aiThreatScore) ? `${Math.round(s.aiThreatScore * 100)}%` : null
                const duration = s.status === 'active' ? null : s.durationSeconds
                return (
                  <tr key={s._id} data-testid="atm-session-row" style={{ borderBottom: '1px solid rgba(13,51,82,.6)' }}>
                    <td style={{ padding: '8px', fontFamily: 'Share Tech Mono,monospace', color: '#00d4ff' }}>{s.sessionId}</td>
                    <td style={{ padding: '8px', fontFamily: 'Share Tech Mono,monospace' }}>{s.sourceIP || 'Not recorded'}</td>
                    <td style={{ padding: '8px', whiteSpace: 'nowrap' }}>{when(s.startTime)}</td>
                    <td style={{ padding: '8px' }}>{Number.isFinite(duration) ? formatDuration(duration) : s.status === 'active' ? 'In progress' : 'Unavailable'}</td>
                    <td style={{ padding: '8px', textTransform: 'uppercase', fontFamily: 'Share Tech Mono,monospace', fontSize: 11 }}>{s.status || 'unknown'}</td>
                    <td style={{ padding: '8px' }}>{commands}</td>
                    <td style={{ padding: '8px', whiteSpace: 'nowrap' }}>
                      {severity ? <SeverityBadge sev={severity} /> : <span style={{ color: '#3a6a88' }}>No linked threat</span>}
                      {score && <span style={{ marginLeft: 6, fontFamily: 'Share Tech Mono,monospace', fontSize: 11 }}>{score}</span>}
                    </td>
                    <td style={{ padding: '8px', fontFamily: 'Share Tech Mono,monospace', fontSize: 11 }}>{s.servedProfile || 'Not recorded'}</td>
                    <td style={{ padding: '8px', textAlign: 'right' }}>
                      <button type="button" style={{ ...btn, color: '#00d4ff', borderColor: '#00d4ff' }} onClick={() => onOpen(s._id)} aria-label={`Replay session ${s.sessionId}`}>
                        Replay ▶
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {pagination && pagination.pages > 1 && (
        <nav aria-label="Session pages" style={{ display: 'flex', gap: 10, alignItems: 'center', justifyContent: 'flex-end', marginTop: 12 }}>
          <button type="button" style={btn} disabled={page <= 1} onClick={() => update({ page: String(page - 1) })}>‹ Prev</button>
          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#7ab3cc' }}>PAGE {page} / {pagination.pages}</span>
          <button type="button" style={btn} disabled={page >= pagination.pages} onClick={() => update({ page: String(page + 1) })}>Next ›</button>
        </nav>
      )}
      <div style={{ marginTop: 10, fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88' }}>
        Severity comes from the threat record a session references; sessions without one show none. Severity filtering is not offered because it is not a stored session field.
      </div>
    </Panel>
  )
}
