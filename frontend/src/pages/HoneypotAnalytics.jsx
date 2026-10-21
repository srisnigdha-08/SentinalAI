import { useState, useEffect, useRef } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import KpiCard from '../components/KpiCard.jsx'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts'
import { honeypotAPI, threatAPI } from '../services/api.js'
import { useSocket } from '../hooks/useSocket.js'
import toast from 'react-hot-toast'
import { useAuth } from '../hooks/useAuth.js'
import { recommendationSummary, learnerProvenanceSummary } from '../utils/modelHealth.js'

const TT = ({ active, payload, label }) => active && payload?.length ? (
  <div style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2, padding:'8px 12px', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
    {label && <p style={{ color:'#7ab3cc', marginBottom:4 }}>{label}</p>}
    {payload.map(p=><p key={p.name} style={{ color:p.color||'#ffaa00' }}>{p.name||'Count'}: {p.value}</p>)}
  </div>
) : null

const RELOAD_COALESCE_MS = 1500
const HONEYPOT_METHOD_NOTE =
  'Session verdicts come from rule-based classification of Cowrie sessions (login, programs run, IOCs), not from the ML models. ' +
  'Blocks are enforced by the Cowrie blocker plugin; host firewall rules use a mock adapter unless real enforcement is enabled, ' +
  'and honeypot-originated blocks can require analyst approval.'
// Sessions invented by log_parser.py --demo (same convention as the backend's isSyntheticSession).
const isSyntheticSession = (sessionId) => /^demo-/i.test(String(sessionId || ''))

export default function HoneypotAnalytics() {
  const [analytics, setAnalytics] = useState(null)
  const [sessions,  setSessions]  = useState([])
  const [nodes,     setNodes]     = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [profile,   setProfile]   = useState(null)
  const [recommendation, setRecommendation] = useState(null)
  const [recError,  setRecError]  = useState(false)
  const { connected, on } = useSocket()
  const { user } = useAuth()
  const canSeeRecommendation = user?.role === 'admin' || user?.role === 'analyst'

  // The Q-learner's pick is applied on the honeypot host by honeypot/deception_rotator.py; this view is read-only.
  const loadDeception = () => {
    honeypotAPI.deceptionProfile().then(r => setProfile(r.data?.data || null)).catch(() => setProfile(null))
    if (!canSeeRecommendation) return
    honeypotAPI.deceptionRecommendation()
      .then(r => { setRecommendation(r.data?.data || null); setRecError(false) })
      .catch(() => { setRecommendation(null); setRecError(true) })
  }

  const load = async () => {
    setError(null)
    try {
      const [aRes, sRes, nRes] = await Promise.all([
        honeypotAPI.analytics(),
        honeypotAPI.sessions({ limit: 10 }),
        honeypotAPI.nodes(),
      ])
      setAnalytics(aRes.data.data)
      setSessions(sRes.data.data || [])
      setNodes(nRes.data.data?.nodes || [])
    } catch {
      setError('Honeypot telemetry is unavailable. Retry to load current sessions and nodes.')
      toast.error('Failed to load honeypot data')
    }
    finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    loadDeception()
  }, [])

  // Each event used to trigger three REST calls, so one busy session (a command per event) could exhaust
  // the per-IP rate limit. Events arriving within RELOAD_COALESCE_MS share one reload; a steady stream still
  // refreshes every RELOAD_COALESCE_MS instead of waiting for it to stop.
  const reloadTimer = useRef(null)
  useEffect(() => {
    if (!connected) return
    const scheduleReload = () => {
      if (reloadTimer.current) return
      reloadTimer.current = setTimeout(() => { reloadTimer.current = null; load() }, RELOAD_COALESCE_MS)
    }
    const unsubOpen = on('honeypot_session_opened', scheduleReload)
    const unsubClose = on('honeypot_session_closed', scheduleReload)
    const unsubCmd = on('honeypot_command', scheduleReload)
    return () => {
      unsubOpen?.(); unsubClose?.(); unsubCmd?.()
      clearTimeout(reloadTimer.current); reloadTimer.current = null
    }
  }, [connected, on])

  const kpis   = analytics?.kpis   || {}
  const charts = analytics?.charts || {}
  const intel  = analytics?.intelligence || {}

  const cmdData   = (charts.topCommands    || []).map(c=>({ cmd:c._id.length>20?c._id.slice(0,20)+'…':c._id, count:c.count }))
  const dailyData = (charts.dailySessions  || []).map(d=>({ date:d._id?.slice(5)||d._id, sessions:d.sessions }))

  const fmtDuration = (s) => { const m=Math.floor(s/60); return m>0?`${m}m ${s%60}s`:`${s}s` }

  return (
    <DashboardLayout>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'1.5rem' }}>
        <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700 }}>
          Honeypot <span style={{ color:'#00d4ff' }}>Analytics</span>
        </div>
        <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, background:'rgba(0,255,136,.1)',
          color:'#00ff88', border:'1px solid rgba(0,255,136,.3)', padding:'6px 14px', borderRadius:1 }}>
          {nodes.filter(n=>n.status==='active').length} NODES ACTIVE
        </span>
      </div>

      {/* Honest labelling (Phase 5): what the numbers on this page are and are not. */}
      <div data-testid="honeypot-method-note" style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', marginTop:'-1rem', marginBottom:'1.25rem', lineHeight:1.6 }}>
        {HONEYPOT_METHOD_NOTE}
      </div>

      {error && (
        <div
          role="alert"
          style={{
            padding: '12px 16px',
            marginBottom: '1.25rem',
            background: 'rgba(255, 170, 0, 0.1)',
            border: '1px solid #ffaa00',
            borderRadius: 2,
            fontFamily: 'Share Tech Mono, monospace',
            fontSize: 12,
            color: '#ffaa00',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <span>⚠ {error}</span>
          <button
            onClick={load}
            style={{
              background: '#ffaa00',
              border: 'none',
              color: '#020b18',
              fontFamily: 'Rajdhani, sans-serif',
              fontWeight: 700,
              fontSize: 12,
              padding: '4px 14px',
              borderRadius: 2,
              cursor: 'pointer',
              letterSpacing: 1,
              textTransform: 'uppercase',
            }}
          >
            Retry
          </button>
        </div>
      )}

      <div className="dashboard-grid dashboard-kpis" style={{ gap:'1rem', marginBottom:'1.5rem' }}>
        <KpiCard label="Sessions Today"    value={loading?'—':kpis.totalToday||0}              delta="today"             color="#00d4ff" />
        <KpiCard label="Unique Attackers"  value={loading?'—':kpis.uniqueIPsToday||0}          delta="distinct IPs"      color="#ffaa00" />
        <KpiCard label="Avg Engagement"    value={loading?'—':fmtDuration(kpis.avgDurationSecs||0)} delta="per session"  color="#00ff88" />
        <KpiCard label="Deception Score"   value={loading?'—':`${kpis.avgDeceptionScore||0}`}  delta="avg engagement heuristic"     color="#8b5cf6" />
      </div>

      <div className="dashboard-grid dashboard-grid-two" style={{ gap:'1rem', marginBottom:'1rem' }}>
        {/* Sessions list */}
        <Panel title="Attacker Sessions" badge="LIVE" badgeType="live">
          <div style={{ maxHeight:320, overflowY:'auto' }}>
            {loading ? (
              <div style={{ textAlign:'center', padding:'2rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>LOADING...</div>
            ) : sessions.map(s => (
              <div key={s._id} onClick={()=>toast.success(`Session ${s.sessionId}`)}
                style={{ background:'#041120', border:'1px solid #0d3352', borderRadius:2, marginBottom:8, padding:12, cursor:'pointer', transition:'border-color .2s' }}
                onMouseEnter={e=>e.currentTarget.style.borderColor='#1a4a6e'}
                onMouseLeave={e=>e.currentTarget.style.borderColor='#0d3352'}>
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
                  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88' }}>{s.sessionId}</span>
                  {isSyntheticSession(s.sessionId) && (
                    <span title="Generated by log_parser.py --demo, not a real attacker" style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, color:'#ffaa00', border:'1px solid #ffaa00', borderRadius:2, padding:'0 4px' }}>DEMO</span>
                  )}
                  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:13, color:'#00d4ff' }}>{s.sourceIP}</span>
                  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, background:'#041120', border:'1px solid #0d3352', padding:'2px 6px', color:'#7ab3cc' }}>
                    {s.geoLocation?.countryCode||'??'}
                  </span>
                  <span style={{ fontSize:11, color:'#3a6a88' }}>{s.honeypotNode}</span>
                  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88', marginLeft:'auto' }}>
                    {fmtDuration(s.durationSeconds||0)}
                  </span>
                </div>
                <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                  {(s.commands||[]).slice(0,5).map((c,i)=>(
                    <span key={i} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, background:'#041120',
                      border:'1px solid #0d3352', color:'#ffaa00', padding:'2px 8px' }}>
                      {c.command?.slice(0,20)||''}
                    </span>
                  ))}
                  {(s.commands||[]).length > 5 && (
                    <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', padding:'2px 4px' }}>
                      +{s.commands.length-5} more
                    </span>
                  )}
                </div>
                {s.mitreTechniques && s.mitreTechniques.length > 0 && (
                  <div style={{ display:'flex', flexWrap:'wrap', gap:4, marginTop:8, borderTop:'1px dashed #0d3352', paddingTop:8 }}>
                    {s.mitreTechniques.map((tech, i) => (
                      <span key={i} title={tech.name} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, background:'rgba(0, 212, 255, 0.1)',
                        border:'1px solid rgba(0, 212, 255, 0.3)', color:'#00d4ff', padding:'2px 6px', borderRadius:2 }}>
                        {tech.id} - {tech.name}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {!loading && sessions.length === 0 && (
              <div style={{ textAlign:'center', padding:'2.5rem 1rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12, display:'flex', flexDirection:'column', alignItems:'center', gap:8 }}>
                <div style={{ width:7, height:7, borderRadius:'50%', background:'#00ff88', animation:'pulseDot 2s ease-in-out infinite' }} />
                <span style={{ color:'#7ab3cc', fontSize:13 }}>No attacks detected yet</span>
                <span style={{ fontSize:11, color:'#274b68' }}>Waiting for live events...</span>
              </div>
            )}
          </div>
        </Panel>

        {/* Command frequency chart */}
        <Panel title="Top Commands Captured">
          {cmdData.length === 0 ? (
            <div style={{ textAlign:'center', padding:'4rem 1rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>
              No real data available. Waiting for live events...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={cmdData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
                <XAxis type="number" tick={{ fill:'#3a6a88', fontSize:10 }} />
                <YAxis type="category" dataKey="cmd" tick={{ fill:'#7ab3cc', fontSize:10 }} width={130} />
                <Tooltip content={<TT />} />
                <Bar dataKey="count" fill="#ffaa00" fillOpacity={0.8} name="Count" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>

      {/* Daily sessions trend */}
      <Panel title="Daily Session Volume — 7 IST Days" style={{ marginBottom:'1rem' }}>
        {dailyData.length === 0 ? (
          <div style={{ textAlign:'center', padding:'3rem 1rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>
            No real data available. Waiting for live events...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={160}>
            <LineChart data={dailyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
              <XAxis dataKey="date" tick={{ fill:'#3a6a88', fontSize:11 }} />
              <YAxis tick={{ fill:'#3a6a88', fontSize:11 }} />
              <Tooltip content={<TT />} />
              <Line type="monotone" dataKey="sessions" stroke="#00d4ff" strokeWidth={2} dot={false} name="Sessions" />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Panel>

      {/* Adaptive deception: persona being served and the Q-learner's next pick */}
      <Panel title="Adaptive Deception" badge={profile?.profile ? profile.profile.toUpperCase() : 'UNKNOWN'} badgeType="info" style={{ marginBottom:'1rem' }}>
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:12, fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#7ab3cc' }}>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            <span>Serving persona: <strong style={{ color:'#00d4ff' }}>{profile?.profile || '—'}</strong>
              {profile?.source && <span style={{ color:'#3a6a88', fontSize:10 }}> (from {profile.source})</span>}</span>
            {canSeeRecommendation && (
              recError
                ? <span style={{ color:'#ffaa00' }}>Recommendation unavailable: AI engine unreachable.</span>
                : <span>{recommendation?.policy === 'ucb1' ? 'Bandit (UCB1)' : 'Q-learner'} recommends: <strong style={{ color:'#00ff88' }}>{recommendationSummary(recommendation) || '—'}</strong></span>
            )}
            {canSeeRecommendation && !recError && recommendation && (
              <span data-testid="learner-provenance" style={{ color:'#3a6a88', fontSize:10 }}>{learnerProvenanceSummary(recommendation.provenance)}</span>
            )}
          </div>
          {canSeeRecommendation && (
            <button
              onClick={loadDeception}
              style={{ background:'transparent', border:'1px solid #00d4ff', color:'#00d4ff', padding:'3px 10px', borderRadius:2, fontSize:10, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
            >
              ASK AGAIN
            </button>
          )}
        </div>
        <div style={{ marginTop:10, fontSize:10, color:'#3a6a88' }}>
          The recommendation is epsilon-greedy, so asking again can return a different exploration pick. It is applied to Cowrie by the deception rotator on the honeypot host, not from this dashboard.
        </div>
      </Panel>

      {/* Node status grid */}
      <Panel title="Honeypot Nodes">
        <div className="dashboard-grid dashboard-kpis" style={{ gap:'1rem' }}>
          {nodes.map(hp=>(
            <div key={hp.name} style={{ background:'#041120', border:'1px solid #0d3352', borderRadius:2, padding:'1.25rem' }}>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:10, fontWeight:700, color:'#7ab3cc', letterSpacing:1, marginBottom:8 }}>{hp.name}</div>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
                <div style={{ width:8, height:8, borderRadius:'50%', background:hp.status==='active'?'#00ff88':'#ffaa00', animation:'pulseDot 1.5s ease-in-out infinite' }} />
                <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:hp.status==='active'?'#00ff88':'#ffaa00', textTransform:'uppercase' }}>{hp.status}</span>
              </div>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:24, fontWeight:700, color:'#00d4ff' }}>{hp.sessionsToday}</div>
              <div style={{ fontSize:11, color:'#3a6a88' }}>sessions today</div>
              <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', marginTop:4 }}>:{hp.port}</div>
            </div>
          ))}
        </div>
      </Panel>
    </DashboardLayout>
  )
}
