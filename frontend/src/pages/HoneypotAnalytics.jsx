import { useState, useEffect } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import KpiCard from '../components/KpiCard.jsx'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts'
import { honeypotAPI, threatAPI } from '../services/api.js'
import { useSocket } from '../hooks/useSocket.js'
import toast from 'react-hot-toast'

const TT = ({ active, payload, label }) => active && payload?.length ? (
  <div style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2, padding:'8px 12px', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
    {label && <p style={{ color:'#7ab3cc', marginBottom:4 }}>{label}</p>}
    {payload.map(p=><p key={p.name} style={{ color:p.color||'#ffaa00' }}>{p.name||'Count'}: {p.value}</p>)}
  </div>
) : null

export default function HoneypotAnalytics() {
  const [analytics, setAnalytics] = useState(null)
  const [sessions,  setSessions]  = useState([])
  const [nodes,     setNodes]     = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const { connected, on } = useSocket()

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
  }, [])

  useEffect(() => {
    if (!connected) return
    const unsubOpen = on('honeypot_session_opened', () => load())
    const unsubClose = on('honeypot_session_closed', () => load())
    const unsubCmd = on('honeypot_command', () => load())
    return () => { unsubOpen?.(); unsubClose?.(); unsubCmd?.() }
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
