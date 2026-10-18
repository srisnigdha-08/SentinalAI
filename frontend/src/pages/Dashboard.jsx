import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { threatEvidenceLabel } from '../utils/threatEvidence.js'
import { useState, useEffect } from 'react'
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import KpiCard   from '../components/KpiCard.jsx'
import Panel     from '../components/Panel.jsx'
import LiveFeed  from '../components/LiveFeed.jsx'
import StatusBar from '../components/StatusBar.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { threatAPI, honeypotAPI, systemAPI } from '../services/api.js'
import { useSocket } from '../hooks/useSocket.js'
import { useAuth } from '../hooks/useAuth.js'
import toast from 'react-hot-toast'

const SEV_COLORS = { CRITICAL:'#ff2d55', HIGH:'#ff6400', MEDIUM:'#ffaa00', LOW:'#00d4ff' }
const VECTOR_COLORS = {
  'SSH Brute Force':'#ff2d55','SQL Injection':'#ff6400','Port Scan':'#00d4ff',
  'DDoS':'#ffaa00','Malware Beacon':'#8b5cf6','RCE Attempt':'#00ff88',
  'XSS Attempt':'#7ab3cc','Credential Stuffing':'#ff9500','Data Exfiltration':'#ff2d55',
  'Lateral Movement':'#cc00ff',
}
const ATTACK_TYPES = Object.keys(VECTOR_COLORS)

const TT = ({ active, payload, label }) => active && payload?.length ? (
  <div style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2,
    padding:'8px 12px', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
    {label && <p style={{ color:'#7ab3cc', marginBottom:4 }}>{label}</p>}
    {payload.map(p => <p key={p.name} style={{ color:p.color||'#00d4ff' }}>{p.name}: {p.value}</p>)}
  </div>
) : null

export default function Dashboard() {
  const { user } = useAuth()
  const userRole = user?.role || 'viewer'
  const [analytics,    setAnalytics]    = useState(null)
  const [threats,      setThreats]      = useState([])
  const [nodes,        setNodes]        = useState([])
  const [vectorData,   setVectorData]   = useState([])
  const [systemHealth, setSystemHealth] = useState(null)
  const [error, setError] = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [threatCount,  setThreatCount]  = useState(0)
  const { connected, on } = useSocket()

  const load = async () => {
    setError(null)
    try {
      const isViewer = userRole === 'viewer'
      const requests = [
        threatAPI.analytics(),
        threatAPI.list({ limit: 8, sortBy: 'createdAt', sortOrder: 'desc' }),
        honeypotAPI.nodes(),
        threatAPI.vectorTrend(7),
      ]
      if (!isViewer) {
        requests.push(systemAPI.health())
      }
      const results = await Promise.all(requests)
      const analyticsRes = results[0]
      const threatsRes = results[1]
      const nodesRes = results[2]
      const vectorRes = results[3]
      const healthRes = !isViewer ? results[4] : null

      const a = analyticsRes.data.data
      setAnalytics(a)
      setThreatCount(a?.kpis?.totalToday || 0)
      setThreats(threatsRes.data.data || [])
      setNodes(nodesRes.data.data?.nodes || [])
      if (healthRes?.data?.data) {
        setSystemHealth(healthRes.data.data)
      } else if (isViewer) {
        setSystemHealth((prev) => prev || {
          mode: 'REAL_MODE',
          status: 'ok',
          database: { status: 'connected' },
          aiEngine: { status: 'connected' },
        })
      }


      // Build stacked bar chart data from vector trend
      const raw = vectorRes.data.data?.trend || []
      const dateMap = {}
      raw.forEach(({ _id }) => {
        if (_id?.date && !dateMap[_id.date]) dateMap[_id.date] = { day: _id.date.slice(5) }
      })
      raw.forEach(({ _id, count }) => {
        if (_id?.date && _id?.type) {
          if (!dateMap[_id.date]) dateMap[_id.date] = { day: _id.date.slice(5) }
          dateMap[_id.date][_id.type] = count
        }
      })
      setVectorData(Object.values(dateMap).slice(-7))
    } catch (err) {
      setSystemHealth(null)
      setError('Dashboard data is unavailable. Any displayed values may be stale.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 30000) // refresh every 30s
    return () => clearInterval(interval)
  }, [])

  // ── Real Socket.IO telemetry & threat events ──
  useEffect(() => {
    if (!connected) return

    const unsubThreat = on('new_threat', (t) => {
      setThreats(prev => [t, ...prev.filter(x => (x._id || x.id) !== (t._id || t.id))].slice(0, 8))
      setThreatCount(c => c + 1)
    })

    const unsubHealth = on('system_health', (h) => {
      setSystemHealth(prev => ({
        ...prev,
        memory: {
          ...prev?.memory,
          heapUsedMB: h.memory?.heapUsed,
          heapTotalMB: h.memory?.heapTotal,
          rssMB: h.memory?.rss,
          pct: h.memory?.heapPercent,
        },
        uptime: h.uptime,
        websocket: { connectedClients: h.connectedClients },
      }))
    })

    return () => { unsubThreat?.(); unsubHealth?.() }
  }, [connected, on])

  const kpis = analytics?.kpis || {}
  const charts = analytics?.charts || {}

  // Build 24h line chart — fill all 24 hours
  const hourly24 = Array.from({ length: 24 }, (_, i) => {
    const hour = `${String(i).padStart(2,'0')}:00`
    const found = charts.hourlyToday?.find(h => h.hour === hour)
    return { hour, threats: found?.count || 0, blocked: found?.blocked || 0 }
  })

  // Build severity donut data
  const sevData = (charts.bySeverityToday || []).map(s => ({
    name: s._id, value: s.count, color: SEV_COLORS[s._id] || '#7ab3cc',
  }))

  const activeNodeCount = nodes.filter(n => n.status === 'active').length

  // ── Role-Specific Sub-sections ──

  // Section 1: 24h chart + live feed
  const activityAndFeedSection = (
    <div key="activity-feed" className="dashboard-grid dashboard-grid-two" style={{ gap:'1rem', marginBottom:'1rem' }}>
      <Panel title="Threat Activity — Today (IST)" badge="● LIVE" badgeType="live">
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={hourly24}>
            <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
            <XAxis dataKey="hour" tick={{ fill:'#3a6a88', fontSize:10 }} interval={3} />
            <YAxis tick={{ fill:'#3a6a88', fontSize:10 }} />
            <Tooltip content={<TT />} />
            <Legend wrapperStyle={{ fontSize:11 }} />
            <Line type="monotone" dataKey="threats" stroke="#ff2d55" strokeWidth={2} dot={false} name="Threats" />
            <Line type="monotone" dataKey="blocked" stroke="#00d4ff" strokeWidth={1.5} dot={false} name="Blocked" />
          </LineChart>
        </ResponsiveContainer>
        {!hourly24.some(h => (h.threats || 0) > 0 || (h.blocked || 0) > 0) && !loading && (
          <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, paddingTop:'4px' }}>
            No live security events detected. Waiting for real telemetry...
          </div>
        )}
      </Panel>
      <Panel title="Live Attack Feed" badge="● STREAMING" badgeType="live">
        <LiveFeed />
      </Panel>
    </div>
  )

  // Section 2: Active threat queue table
  const threatQueueSection = (
    <Panel key="threat-queue" title="Active Threat Queue" badge={`${threats.length} active`} badgeType="live" style={{ marginBottom:'1rem' }}>
      <div className="sentinel-table-scroll" role="region" aria-label="Active threat queue" tabIndex={0}>
      <table style={{ width:'100%', minWidth: 680, borderCollapse:'collapse' }}>
        <thead>
          <tr>{['Severity','Source IP','Attack Type','Target','Detected','Score','Action'].map(h=>(
            <th key={h} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88',
              letterSpacing:2, padding:'8px 10px', borderBottom:'1px solid #0d3352', textAlign:'left' }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {threats.map(t => (
            <tr key={t._id}>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)' }}><SeverityBadge sev={t.severity} /></td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#00d4ff' }}>{t.sourceIP}</td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontSize:13 }}>
                {t.attackType}
                {threatEvidenceLabel(t) && <div style={{ color: '#ffaa00', fontSize: 10 }}>{threatEvidenceLabel(t)}</div>}
              </td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#7ab3cc' }}>{t.targetService}</td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88' }}>
                {new Date(t.createdAt).toLocaleTimeString('en-IN',{ timeZone: REPORT_TIME_ZONE,hour12:false})}
              </td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:12,
                color:t.aiScore>=0.9?'#ff2d55':t.aiScore>=0.7?'#ffaa00':'#00d4ff' }}>
                {((t.aiScore||0)*100).toFixed(0)}%
              </td>
              <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                {userRole === 'viewer' ? (
                  <span style={{
                    fontFamily: 'Share Tech Mono,monospace',
                    fontSize: 10,
                    color: '#3a6a88',
                    background: 'rgba(13,51,82,.3)',
                    border: '1px solid #0d3352',
                    padding: '3px 8px',
                    borderRadius: 1,
                    display: 'inline-block',
                    letterSpacing: 0.5,
                  }}>
                    OBSERVATION MODE
                  </span>
                ) : (
                  <button onClick={async()=>{
                    try{ await threatAPI.blockIP(t._id); toast.error(`IP ${t.sourceIP} blocked`) }
                    catch(e){ toast.error('Block failed') }
                  }} style={{ background:'none', border:'1px solid #0d3352', color:'#3a6a88',
                    fontSize:11, fontFamily:'Share Tech Mono,monospace', padding:'4px 10px',
                    cursor:'pointer', borderRadius:1 }}
                    onMouseEnter={e=>{e.target.style.borderColor='#ff2d55';e.target.style.color='#ff2d55'}}
                    onMouseLeave={e=>{e.target.style.borderColor='#0d3352';e.target.style.color='#3a6a88'}}
                  >Block IP</button>
                )}
              </td>
            </tr>
          ))}
          {!loading && threats.length === 0 && (
            <tr><td colSpan={7} style={{ padding:'2rem', textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>
              No attacks detected yet. Waiting for live events...
            </td></tr>
          )}
        </tbody>
      </table>
      </div>
    </Panel>
  )

  // Section 3: Honeypot + Top Attack Types + System Health
  const telemetryAndNodesSection = (
    <div key="telemetry-nodes" className="dashboard-grid dashboard-grid-three" style={{ gap:'1rem', marginBottom:'1rem' }}>
      <Panel title="Honeypot Nodes" badge={`${nodes.filter(n=>n.status==='active').length} ACTIVE`} badgeType="ok">
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
          {nodes.map(hp => (
            <div key={hp.name} style={{ background:'#041120', border:'1px solid #0d3352', borderRadius:2, padding:12 }}>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:10, fontWeight:700, color:'#7ab3cc', letterSpacing:1, marginBottom:6 }}>{hp.name}</div>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <div style={{ width:7, height:7, borderRadius:'50%', background:hp.status==='active'?'#00ff88':'#ffaa00', animation:'pulseDot 1.5s ease-in-out infinite' }} />
                <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:hp.status==='active'?'#00ff88':'#ffaa00' }}>{hp.status}</span>
              </div>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:20, fontWeight:700, color:'#00d4ff', marginTop:6 }}>{hp.sessionsToday}</div>
              <div style={{ fontSize:11, color:'#3a6a88' }}>sessions today</div>
            </div>
          ))}
          {nodes.length === 0 && !loading && (
            <div style={{ gridColumn:'1/-1', textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>
              Waiting for honeypot telemetry... No real data available
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Top Attack Types" badge="ALL TIME" badgeType="info">
        <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
          {(charts.byAttackType||[]).slice(0,4).map(a => {
            const max = charts.byAttackType?.[0]?.count || 1
            const pct = Math.round((a.count/max)*100)
            return (
              <div key={a._id}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:3 }}>
                  <span style={{ fontSize:12, color:'#c8e6f5' }}>{a._id}</span>
                  <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#7ab3cc' }}>{a.count}</span>
                </div>
                <div style={{ height:4, background:'#0d3352', borderRadius:2 }}>
                  <div style={{ height:'100%', width:`${pct}%`, background: VECTOR_COLORS[a._id]||'#00d4ff', borderRadius:2, transition:'width 1s ease' }} />
                </div>
              </div>
            )
          })}
          {(charts.byAttackType||[]).length === 0 && !loading && (
            <div style={{ color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem 0', textAlign:'center' }}>
              No attacks detected yet. Waiting for live events...
            </div>
          )}
        </div>
      </Panel>

      <Panel title="System Telemetry" badge={userRole === 'viewer' ? "MONITORING" : (systemHealth?.database?.status === 'connected' ? "NOMINAL" : "CONNECTING")} badgeType={userRole === 'viewer' ? "info" : (systemHealth?.database?.status === 'connected' ? "ok" : "warn")}>
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          {[
            {
              name: 'Heap Memory',
              statusText: userRole === 'viewer' ? 'RESTRICTED (OPERATOR ONLY)' : `${systemHealth?.memory?.heapUsedMB || 0}MB / ${systemHealth?.memory?.heapTotalMB || 0}MB`,
              pct: userRole === 'viewer' ? 0 : (systemHealth?.memory?.pct || 0),
              color: '#00d4ff'
            },

            {
              name: 'MongoDB',
              statusText: systemHealth?.database?.status === 'connected' ? 'CONNECTED' : (loading ? 'CHECKING...' : 'STANDBY'),
              pct: systemHealth?.database?.status === 'connected' ? 100 : 0,
              color: '#00ff88'
            },
            {
              name: 'AI Engine',
              statusText: systemHealth?.aiEngine?.status === 'connected' ? 'ONLINE' : (loading ? 'CHECKING...' : 'UNREACHABLE'),
              pct: systemHealth?.aiEngine?.status === 'connected' ? 100 : 0,
              color: systemHealth?.aiEngine?.status === 'connected' ? '#8b5cf6' : '#ffaa00'
            },
            {
              name: 'Honeypots',
              statusText: `${activeNodeCount} active / ${nodes.length} nodes`,
              pct: nodes.length > 0 ? Math.round((activeNodeCount / nodes.length) * 100) : 0,
              color: activeNodeCount > 0 ? '#00d4ff' : '#3a6a88'
            },
            {
              name: 'WebSocket',
              statusText: `${systemHealth?.websocket?.connectedClients ?? (connected ? 1 : 0)} client(s)`,
              pct: connected ? 100 : 0,
              color: connected ? '#00ff88' : '#ffaa00'
            },
            {
              name: 'Host Metrics',
              statusText: 'Unavailable',
              pct: 0,
              color: '#3a6a88'
            },
          ].map(h => (
            <div key={h.name} style={{ display:'flex', alignItems:'center', gap:10 }}>
              <span style={{ fontSize:12, color:'#7ab3cc', width:85, flexShrink:0 }}>{h.name}</span>
              <div style={{ flex:1, height:6, background:'#0d3352', borderRadius:3, overflow:'hidden' }}>
                <div style={{ height:'100%', width:`${h.pct}%`, background:h.color, borderRadius:3 }} />
              </div>
              <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#7ab3cc', minWidth:80, textAlign:'right' }}>
                {h.statusText}
              </span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )

  // Section 4: Severity donut + Weekly trend
  const chartsSection = (
    <div key="charts-row" className="dashboard-grid dashboard-grid-two" style={{ gap:'1rem', marginBottom:'1rem' }}>
      <Panel title="Threat Severity (Today)" badge="LIVE" badgeType="live">
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Pie data={sevData} cx="50%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
              {sevData.map(e => <Cell key={e.name} fill={e.color} />)}
            </Pie>
            <Tooltip content={<TT />} />
            <Legend wrapperStyle={{ fontSize:11 }} />
          </PieChart>
        </ResponsiveContainer>
        {sevData.length === 0 && !loading && (
          <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, paddingTop:'1rem' }}>
            No attacks detected yet. Waiting for live events...
          </div>
        )}
      </Panel>

      <Panel title="Threat Trend — 7 IST Days" badge="7-DAY" badgeType="live">
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={charts.weeklyTrend||[]}>
            <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
            <XAxis dataKey="_id" tick={{ fill:'#3a6a88', fontSize:10 }} tickFormatter={v=>v?.slice(5)||v} />
            <YAxis tick={{ fill:'#3a6a88', fontSize:10 }} />
            <Tooltip content={<TT />} />
            <Legend wrapperStyle={{ fontSize:11 }} />
            <Bar dataKey="critical" stackId="a" fill="#ff2d55" name="Critical" />
            <Bar dataKey="high"     stackId="a" fill="#ff6400" name="High" />
            <Bar dataKey="medium"   stackId="a" fill="#ffaa00" name="Medium" />
            <Bar dataKey="low"      stackId="a" fill="#00d4ff" name="Low" />
          </BarChart>
        </ResponsiveContainer>
        {(charts.weeklyTrend||[]).length === 0 && !loading && (
          <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, paddingTop:'1rem' }}>
            No real data available. Waiting for live events...
          </div>
        )}
      </Panel>
    </div>
  )

  // Section 5: Attack vector stacked
  const vectorTrendSection = (
    <Panel key="vector-trend" title="Attack Vector Distribution — 7 IST Days" badge="TREND" badgeType="live" style={{ marginBottom:'1rem' }}>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={vectorData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
          <XAxis dataKey="day" tick={{ fill:'#3a6a88', fontSize:11 }} />
          <YAxis tick={{ fill:'#3a6a88', fontSize:11 }} />
          <Tooltip content={<TT />} />
          <Legend wrapperStyle={{ fontSize:10 }} />
          {ATTACK_TYPES.slice(0,6).map(k => (
            <Bar key={k} dataKey={k} stackId="a" fill={VECTOR_COLORS[k]} />
          ))}
        </BarChart>
      </ResponsiveContainer>
      {vectorData.length === 0 && !loading && (
        <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>
          No real data available. Waiting for live events...
        </div>
      )}
    </Panel>
  )

  return (
    <DashboardLayout>
      {error && <div role="alert" style={{ color: '#ffaa00', padding: '1rem' }}>{error} <button onClick={load}>Retry</button></div>}
      {loading && <div role="status">Loading dashboard telemetry...</div>}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'1.5rem', flexWrap:'wrap', gap:'12px' }}>
        <div>
          <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700 }}>
            {userRole === 'admin' ? (
              <>ADMIN <span style={{ color:'#8b5cf6' }}>Control Centre</span></>
            ) : userRole === 'analyst' ? (
              <>SOC <span style={{ color:'#00d4ff' }}>Tactical Command</span></>
            ) : (
              <>SECURITY <span style={{ color:'#7ab3cc' }}>Observability Deck</span></>
            )}
          </div>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', marginTop:3, letterSpacing:1 }}>
            {userRole === 'admin'
              ? '// PLATFORM GOVERNANCE, INFRASTRUCTURE & NODE ORCHESTRATION'
              : userRole === 'analyst'
              ? '// INCIDENT TRIAGE, THREAT CONTAINMENT & VECTOR ANALYSIS'
              : '// TELEMETRY MONITORING, TREND OBSERVABILITY & AUDIT STREAM'}
          </div>
        </div>
        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          <span style={{
            fontFamily: 'Share Tech Mono,monospace', fontSize: 11,
            color: '#00ff88', border: '1px solid rgba(0,255,136,.3)',
            background: 'rgba(0,255,136,.08)', padding: '5px 12px', borderRadius: 2
          }}>
            ● REAL DATA MODE
          </span>
          {userRole !== 'viewer' ? (
            <button disabled title="Report export is not available yet" style={{
              background:'transparent', border:'1px solid #1a4a6e', color:'#7ab3cc',
              fontFamily:'Rajdhani,sans-serif', fontWeight:600, fontSize:11,
              letterSpacing:1, textTransform:'uppercase', padding:'7px 16px', borderRadius:2, cursor:'pointer',
            }}>Export Report</button>
          ) : (
            <span style={{
              fontFamily: 'Share Tech Mono,monospace', fontSize: 10,
              color: '#3a6a88', border: '1px solid #0d3352',
              background: 'rgba(13,51,82,.2)', padding: '6px 12px', borderRadius: 2,
              letterSpacing: 1,
            }}>
              READ ONLY
            </span>
          )}
        </div>
      </div>

      <StatusBar
        operational={connected && systemHealth?.database?.status === 'connected' && systemHealth?.aiEngine?.status === 'connected'}
        threatCount={threatCount}
        activeHoneypots={activeNodeCount}
        aiEngineStatus={systemHealth?.aiEngine?.status === 'connected' ? 'Running' : 'Unavailable'}
      />

      {/* Role-Specific KPIs */}
      <div className="dashboard-grid dashboard-kpis" style={{ gap:'1rem', marginBottom:'1.5rem' }}>
        {userRole === 'admin' ? (
          <>
            <KpiCard label="Honeypot Nodes"   value={loading ? '—' : `${activeNodeCount} / ${nodes.length || 0}`} delta="nodes active" color="#00ff88" />
            <KpiCard label="AI Engine Status" value={loading ? '—' : (systemHealth?.aiEngine?.status === 'connected' ? 'ONLINE' : 'UNAVAILABLE')} delta={systemHealth?.aiEngine?.status === 'connected' ? 'inference ready' : 'check service status'} color="#8b5cf6" />
            <KpiCard label="Threats Blocked"  value={loading ? '—' : kpis.blockedCount || 0} delta={`${kpis.blockRate || 0}% block rate`} color="#00d4ff" />
            <KpiCard label="Total Detections" value={loading ? '—' : kpis.totalAllTime || 0} delta="platform events" color="#ffaa00" />
          </>
        ) : userRole === 'analyst' ? (
          <>
            <KpiCard label="Threats Today"    value={loading ? '—' : kpis.totalToday || 0} delta="detected today" color="#ff2d55" />
            <KpiCard label="Threats Blocked"  value={loading ? '—' : kpis.blockedCount || 0} delta={`${kpis.blockRate || 0}% block rate`} color="#00ff88" />
            <KpiCard label="Avg Threat Score" value={loading ? '—' : `${((kpis.avgAIScore || 0) * 100).toFixed(1)}%`} delta="model and rule signals" color="#00d4ff" />
            <KpiCard label="Active Honeypots" value={loading ? '—' : `${activeNodeCount} Nodes`} delta="traps configured" color="#ffaa00" />
          </>
        ) : (
          <>
            <KpiCard label="Total Threats"    value={loading ? '—' : kpis.totalAllTime || 0} delta="all time" color="#00d4ff" />
            <KpiCard label="Threats Today"    value={loading ? '—' : kpis.totalToday || 0} delta="IST calendar day" color="#ffaa00" />
            <KpiCard label="Block Efficiency" value={loading ? '—' : `${kpis.blockRate || 0}%`} delta={`${kpis.blockedCount || 0} blocked`} color="#00ff88" />
            <KpiCard label="Avg Threat Score" value={loading ? '—' : `${((kpis.avgAIScore || 0) * 100).toFixed(1)}%`} delta="model and rule signals" color="#7ab3cc" />
          </>
        )}
      </div>

      {/* Role-tailored Panel Layout */}
      {userRole === 'admin' ? (
        <>
          {telemetryAndNodesSection}
          {threatQueueSection}
          {activityAndFeedSection}
          {chartsSection}
          {vectorTrendSection}
        </>
      ) : userRole === 'analyst' ? (
        <>
          {threatQueueSection}
          {activityAndFeedSection}
          {vectorTrendSection}
          {telemetryAndNodesSection}
          {chartsSection}
        </>
      ) : (
        <>
          {activityAndFeedSection}
          {chartsSection}
          {vectorTrendSection}
          {threatQueueSection}
          {telemetryAndNodesSection}
        </>
      )}
    </DashboardLayout>
  )
}
