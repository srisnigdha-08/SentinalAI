import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useState, useEffect } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import KpiCard from '../components/KpiCard.jsx'
import { BarChart, Bar, RadarChart, Radar, PolarGrid, PolarAngleAxis,
         XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, LineChart, Line } from 'recharts'
import { aiAPI, CANONICAL_CLASSES, trainingSampleAPI } from '../services/api.js'
import { useAuth } from '../hooks/useAuth.js'
import toast from 'react-hot-toast'

const TT = ({ active, payload, label }) => active && payload?.length ? (
  <div style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2, padding:'8px 12px', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
    {label && <p style={{ color:'#7ab3cc', marginBottom:4 }}>{label}</p>}
    {payload.map(p=><p key={p.name} style={{ color:p.color||'#00d4ff' }}>{p.name}: {typeof p.value==='number'&&p.value<=1?(p.value*100).toFixed(1)+'%':p.value}</p>)}
  </div>
) : null

import { useSocket } from '../hooks/useSocket.js'

export default function AIAnalytics() {
  const { user } = useAuth()
  const canVerify = user?.role === 'admin' || user?.role === 'analyst'
  const isAdmin = user?.role === 'admin'
  const [stats,     setStats]     = useState(null)
  const [preds,     setPreds]     = useState([])
  const [samples,   setSamples]   = useState([])
  const [modelInfo, setModelInfo] = useState(null)
  const [liveLogs,  setLiveLogs]  = useState([])
  const [loading,   setLoading]   = useState(true)
  const [verifyingId, setVerifyingId] = useState(null)
  const [selectedClass, setSelectedClass] = useState('')
  const [verifyLoading, setVerifyLoading] = useState(false)
  const { connected, on } = useSocket()

  const refreshSamples = () => {
    if (user?.role === 'viewer') return
    trainingSampleAPI.list({ limit: 6 })
      .then(r => setSamples(r.data?.data || []))
      .catch(() => {})
  }

  const handleVerify = async (id) => {
    if (!selectedClass) {
      toast.error('Please select an actual ground-truth class')
      return
    }
    setVerifyLoading(true)
    try {
      const res = await aiAPI.verify(id, selectedClass)
      const updated = res.data?.data?.prediction || res.data?.prediction
      if (updated) {
        setPreds(prev => prev.map(p => (p._id === id || p.id === id ? { ...p, ...updated } : p)))
      }
      toast.success('Prediction verified successfully')
      setVerifyingId(null)
      setSelectedClass('')
      aiAPI.stats().then(s => { if (s.data?.data) setStats(s.data.data) }).catch(() => {})
      setTimeout(refreshSamples, 800)
    } catch (err) {
      toast.error(err.response?.data?.error || 'Verification failed')
    } finally {
      setVerifyLoading(false)
    }
  }

  const handleValidateSample = async (sampleId) => {
    try {
      await trainingSampleAPI.validate(sampleId)
      toast.success('Training sample validated')
      refreshSamples()
    } catch (err) {
      toast.error(err.response?.data?.error || 'Validation failed')
    }
  }

  const handleRejectSample = async (sampleId) => {
    const reason = window.prompt('Enter rejection reason:')
    if (!reason) return
    try {
      await trainingSampleAPI.reject(sampleId, reason)
      toast.success('Training sample rejected')
      refreshSamples()
    } catch (err) {
      toast.error(err.response?.data?.error || 'Rejection failed')
    }
  }

  useEffect(() => {
    const load = async () => {
      try {
        const [sRes, pRes, mRes] = await Promise.all([
          aiAPI.stats(),
          aiAPI.predictions({ limit: 12 }),
          aiAPI.modelInfo().catch(() => ({ data: { data: null } })),
        ])
        setStats(sRes.data.data)
        const predictionList = pRes.data.data || []
        setPreds(predictionList)
        setModelInfo(mRes.data?.data || mRes.data)
        refreshSamples()
      } catch { toast.error('Failed to load AI analytics') }
      finally { setLoading(false) }
    }
    load()
  }, [])

  // ── Listen for genuine live AI prediction events ──
  useEffect(() => {
    if (!connected) return
    const unsub = on('ai_prediction', (data) => {
      setPreds(prev => [data, ...prev.filter(x => (x._id || x.id) !== (data._id || data.id))].slice(0, 12))
      setLiveLogs(prev => [
        {
          type: data.threatScore >= 0.9 ? 'err' : data.threatScore >= 0.7 ? 'warn' : 'out',
          text: `[INFER] ${data.sourceIP} → score=${((data.threatScore || 0) * 100).toFixed(0)}% → ${data.predictedClass} [${data.action || 'EVALUATED'}]`,
          ts: new Date().toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })
        },
        ...prev
      ].slice(0, 20))
      // Dynamically refresh KPI cards and aggregate charts when new prediction arrives
      aiAPI.stats().then(res => { if (res.data?.data) setStats(res.data.data) }).catch(() => {})
    })
    return () => unsub?.()
  }, [connected, on])

  const summary = stats?.summary || {}
  const charts  = stats?.charts  || {}

  // Class performance for bar chart
  const classData = (charts.byClass||[]).slice(0,7).map(c=>({
    cat:   c._id?.slice(0,12)||'Unknown',
    count: c.count,
    score: parseFloat(((c.avgScore||0)*100).toFixed(1)),
  }))

  // Score distribution for bar chart
  const scoreDistData = (charts.scoreDistribution||[]).map(s=>({
    range: s.range?.split(' ')[0]||s.range,
    count: s.count,
  }))

  // Daily volume line chart
  const dailyData = (charts.dailyPredictions||[]).map(d=>({
    date:    d._id?.slice(5)||d._id,
    total:   d.count,
    threats: d.threats,
  }))

  return (
    <DashboardLayout>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'1.5rem' }}>
        <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700 }}>
          AI <span style={{ color:'#00d4ff' }}>Analytics Engine</span>
        </div>
        <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, background:'rgba(0,255,136,.1)',
          color:'#00ff88', border:'1px solid rgba(0,255,136,.3)', padding:'6px 14px', borderRadius:1 }}>
          {modelInfo?.rfVersion ? `${modelInfo.rfVersion.toUpperCase()} ACTIVE` : 'ML PIPELINE ACTIVE'}
        </span>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:'1rem', marginBottom:'1.5rem' }}>
        <KpiCard label="Total Predictions" value={loading?'—':summary.totalPredictions||0}               delta="all time"        color="#00ff88" />
        <KpiCard label="Avg Threat Score"  value={loading?'—':`${((summary.avgThreatScore||0)*100).toFixed(1)}%`} delta="model output" color="#00d4ff" />
        <KpiCard label="Anomaly Rate"      value={loading?'—':`${summary.anomalyRate||0}%`}              delta="isolation forest" color="#ffaa00" />
        <KpiCard label="Avg Inference"     value={loading?'—':`${summary.avgInferenceMs||0}ms`}         delta="per request"      color="#ff2d55" />
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1rem', marginBottom:'1rem' }}>
        {/* Class volume chart */}
        <Panel title="Predictions by Attack Class">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={classData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
              <XAxis dataKey="cat" tick={{ fill:'#3a6a88', fontSize:9 }} angle={-15} textAnchor="end" height={40} />
              <YAxis tick={{ fill:'#3a6a88', fontSize:10 }} />
              <Tooltip content={<TT />} />
              <Bar dataKey="count" fill="#8b5cf6" fillOpacity={0.8} name="Count" />
            </BarChart>
          </ResponsiveContainer>
          {classData.length === 0 && !loading && (
            <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>No real data available. Waiting for live events...</div>
          )}
        </Panel>

        {/* Score distribution */}
        <Panel title="Threat Score Distribution">
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={scoreDistData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
              <XAxis dataKey="range" tick={{ fill:'#3a6a88', fontSize:10 }} />
              <YAxis tick={{ fill:'#3a6a88', fontSize:10 }} />
              <Tooltip content={<TT />} />
              <Bar dataKey="count" name="Predictions"
                fill="url(#scoreGrad)" fillOpacity={0.9} />
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0%"   stopColor="#00d4ff" />
                  <stop offset="50%"  stopColor="#ffaa00" />
                  <stop offset="100%" stopColor="#ff2d55" />
                </linearGradient>
              </defs>
            </BarChart>
          </ResponsiveContainer>
          {scoreDistData.length === 0 && !loading && (
            <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>No real data available. Waiting for live events...</div>
          )}
        </Panel>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'1rem', marginBottom:'1rem' }}>
        {/* Daily volume */}
        <Panel title="Daily Prediction Volume — 7 IST Days">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={dailyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0d3352" />
              <XAxis dataKey="date" tick={{ fill:'#3a6a88', fontSize:10 }} />
              <YAxis tick={{ fill:'#3a6a88', fontSize:10 }} />
              <Tooltip content={<TT />} />
              <Legend wrapperStyle={{ fontSize:11 }} />
              <Line type="monotone" dataKey="total"   stroke="#00d4ff" strokeWidth={2} dot={false} name="Predictions" />
              <Line type="monotone" dataKey="threats" stroke="#ff2d55" strokeWidth={1.5} dot={false} name="Threats" />
            </LineChart>
          </ResponsiveContainer>
          {dailyData.length === 0 && !loading && (
            <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>No real data available. Waiting for live events...</div>
          )}
        </Panel>

        {/* Predictions & analyst ground-truth verification panel */}
        <Panel title="Prediction Ground-Truth Verification" badge="ANALYST" badgeType="live">
          <div style={{ display:'flex', flexDirection:'column', gap:8, maxHeight: 260, overflowY:'auto' }}>
            {preds.slice(0,6).map(p=>{
              const id = p._id || p.id
              const isEditing = verifyingId === id
              const isVerified = Boolean(p.verified)
              return (
                <div key={id} style={{ background:'#041120', border:`1px solid ${isVerified ? '#00ff8844' : '#0d3352'}`, borderRadius:2, padding:'10px 12px' }}>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom: 4 }}>
                    <div style={{ flex:1 }}>
                      <span style={{ fontSize:13, fontWeight:600, color:'#e2f1ff', marginRight:8 }}>{p.predictedClass}</span>
                      <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88' }}>{p.sourceIP} · {p.modelType || 'RandomForest'}</span>
                    </div>
                    <div style={{ display:'flex', alignItems:'center', gap: 8 }}>
                      <div style={{ height:4, width:60, background:'#0d3352', borderRadius:2 }}>
                        <div style={{ height:'100%', width:`${(p.threatScore||0)*100}%`,
                          background:p.threatScore>=0.9?'#ff2d55':p.threatScore>=0.7?'#ffaa00':'#00d4ff', borderRadius:2 }} />
                      </div>
                      <span style={{ fontFamily:'Orbitron,sans-serif', fontSize:12, fontWeight:700,
                        color:p.threatScore>=0.9?'#ff2d55':p.threatScore>=0.7?'#ffaa00':'#00d4ff' }}>
                        {((p.threatScore||0)*100).toFixed(0)}%
                      </span>
                    </div>
                  </div>

                  {/* Verification metadata & action */}
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', paddingTop:4, borderTop:'1px solid #0d335244', fontSize:11 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
                      {isVerified ? (
                        <>
                          <span style={{ background:'rgba(0,255,136,.12)', color:'#00ff88', border:'1px solid rgba(0,255,136,.3)', padding:'1px 5px', borderRadius:2, fontSize:10, fontWeight:600 }}>
                            VERIFIED
                          </span>
                          <span style={{ color:'#00d4ff', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
                            Actual: <strong style={{ color:'#00ff88' }}>{p.actualClass}</strong>
                          </span>
                          <span style={{ color:'#7ab3cc', fontSize:10 }}>
                            By: {p.verifiedBy?.name || p.verifiedBy?.email || 'Analyst'}
                          </span>
                          {p.verifiedAt && (
                            <span style={{ color:'#3a6a88', fontSize:10 }}>
                              {new Date(p.verifiedAt).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })}
                            </span>
                          )}
                        </>
                      ) : (
                        <span style={{ background:'rgba(255,170,0,.12)', color:'#ffaa00', border:'1px solid rgba(255,170,0,.3)', padding:'1px 5px', borderRadius:2, fontSize:10, fontWeight:600 }}>
                          UNVERIFIED
                        </span>
                      )}
                    </div>

                    <div>
                      {canVerify ? (
                        !isEditing ? (
                          <button
                            onClick={() => { setVerifyingId(id); setSelectedClass(p.actualClass || p.predictedClass || '') }}
                            style={{ background:'transparent', border:'1px solid #00d4ff', color:'#00d4ff', padding:'2px 8px', borderRadius:2, fontSize:10, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
                          >
                            {isVerified ? 'RE-VERIFY' : 'VERIFY'}
                          </button>
                        ) : null
                      ) : (
                        <span style={{ color:'#3a6a88', fontSize:10, fontStyle:'italic' }}>Read-Only</span>
                      )}
                    </div>
                  </div>

                  {/* Inline verification form */}
                  {isEditing && (
                    <div style={{ marginTop:8, paddingTop:8, borderTop:'1px dashed #00d4ff44', display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
                      <label style={{ fontSize:11, color:'#7ab3cc', fontFamily:'Share Tech Mono,monospace' }}>Actual Ground Truth:</label>
                      <select
                        value={selectedClass}
                        onChange={(e) => setSelectedClass(e.target.value)}
                        style={{ background:'#081f35', border:'1px solid #00d4ff', color:'#e2f1ff', padding:'3px 8px', borderRadius:2, fontSize:11, fontFamily:'Share Tech Mono,monospace' }}
                      >
                        <option value="">-- Choose Canonical Class --</option>
                        {CANONICAL_CLASSES.map(cls => (
                          <option key={cls} value={cls}>{cls}</option>
                        ))}
                      </select>
                      <button
                        onClick={() => handleVerify(id)}
                        disabled={verifyLoading}
                        style={{ background:'#00d4ff', border:'none', color:'#041120', fontWeight:600, padding:'3px 10px', borderRadius:2, fontSize:11, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
                      >
                        {verifyLoading ? 'SAVING...' : 'CONFIRM'}
                      </button>
                      <button
                        onClick={() => { setVerifyingId(null); setSelectedClass('') }}
                        disabled={verifyLoading}
                        style={{ background:'transparent', border:'1px solid #3a6a88', color:'#7ab3cc', padding:'3px 8px', borderRadius:2, fontSize:11, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
                      >
                        CANCEL
                      </button>
                    </div>
                  )}
                </div>
              )
            })}
            {!loading && preds.length === 0 && (
              <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>No predictions available for verification.</div>
            )}
          </div>
        </Panel>
      </div>

      {/* Training Candidate Quarantine Pool: Governance & batch-retraining candidates */}
      <Panel title="Training Candidate Quarantine Pool" badge={`${samples.length} CANDIDATES`} badgeType="default">
        <div style={{ display:'flex', flexDirection:'column', gap:8, maxHeight:260, overflowY:'auto' }}>
          {samples.length === 0 ? (
            <div style={{ textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'1rem' }}>
              {user?.role === 'viewer'
                ? 'Model retraining telemetry and quarantine pool are restricted to Tier 2 Analyst & Root Admin operators.'
                : 'No candidates in quarantine. Verified predictions with valid 53-feature vectors are queued here automatically.'}
            </div>
          ) : (
            samples.map(s => {
              const statusColor = s.status === 'ELIGIBLE_FOR_TRAINING' ? '#00ff88' :
                                  s.status === 'VALIDATED' ? '#00d4ff' :
                                  s.status === 'QUARANTINED' ? '#ffaa00' :
                                  s.status === 'REJECTED' ? '#ff2d55' : '#7ab3cc'
              return (
                <div key={s._id} style={{ background:'#041120', border:`1px solid ${statusColor}44`, borderRadius:2, padding:'8px 12px', fontSize:11 }}>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:4 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
                      <span style={{ background:`${statusColor}18`, color:statusColor, border:`1px solid ${statusColor}44`, padding:'1px 6px', borderRadius:2, fontSize:10, fontWeight:700 }}>
                        {s.status}
                      </span>
                      <span style={{ color:'#e2f1ff', fontWeight:600 }}>
                        Ground Truth: <strong style={{ color:'#00ff88' }}>{s.groundTruthLabel}</strong>
                      </span>
                      <span style={{ color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:10 }}>
                        (Orig: {s.predictedClass} · {((s.threatScore||0)*100).toFixed(0)}%)
                      </span>
                    </div>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      {isAdmin && s.status === 'QUARANTINED' && (
                        <>
                          <button
                            onClick={() => handleValidateSample(s._id)}
                            style={{ background:'transparent', border:'1px solid #00ff88', color:'#00ff88', padding:'2px 8px', borderRadius:2, fontSize:10, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
                          >
                            VALIDATE
                          </button>
                          <button
                            onClick={() => handleRejectSample(s._id)}
                            style={{ background:'transparent', border:'1px solid #ff2d55', color:'#ff2d55', padding:'2px 8px', borderRadius:2, fontSize:10, cursor:'pointer', fontFamily:'Share Tech Mono,monospace' }}
                          >
                            REJECT
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', color:'#7ab3cc', fontSize:10, borderTop:'1px solid #0d335244', paddingTop:4 }}>
                    <span>Verified By: {s.verifiedBy?.name || s.verifiedBy?.email || 'Analyst'} · {new Date(s.verifiedAt).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })}</span>
                    <span>{s.validatedBy ? `Validated By: ${s.validatedBy?.name || s.validatedBy?.email}` : (s.rejectionReason || s.supersededReason ? `Note: ${s.rejectionReason || s.supersededReason}` : 'Pending Dual-Control Review')}</span>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </Panel>

      {/* Inference terminal: shows actual model inference events from detection pipeline */}
      <Panel title="Model Inference Log" badge="LIVE" badgeType="live">
        <div style={{ background:'#000', border:'1px solid #0d3352', borderRadius:2, padding:'1rem',
          fontFamily:'Share Tech Mono,monospace', fontSize:12, maxHeight:180, overflowY:'auto' }}>
          {liveLogs.length === 0 && preds.length === 0 ? (
            <div style={{ color:'#3a6a88', textAlign:'center', padding:'1.5rem' }}>
              No live security events detected. Waiting for real telemetry...
            </div>
          ) : (
            [
              ...liveLogs,
              ...preds.map(p => ({
                type: p.threatScore >= 0.9 ? 'err' : p.threatScore >= 0.7 ? 'warn' : 'out',
                text: `[INFER] ${p.sourceIP} → score=${((p.threatScore||0)*100).toFixed(0)}% → ${p.predictedClass} [${p.modelType || 'RandomForest'}]`,
                ts: new Date(p.createdAt || Date.now()).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })
              }))
            ].slice(0, 15).map((log, i) => (
              <div key={i} style={{ color: log.type==='warn'?'#ffaa00':log.type==='err'?'#ff2d55':'#7ab3cc', marginBottom:3 }}>
                <span style={{ color: '#3a6a88', marginRight: 8 }}>[{log.ts}]</span>
                {log.text}
              </div>
            ))
          )}
        </div>
      </Panel>
    </DashboardLayout>
  )
}
