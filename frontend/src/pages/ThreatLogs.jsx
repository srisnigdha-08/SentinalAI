import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { threatEvidenceLabel } from '../utils/threatEvidence.js'
import { useState, useEffect, useCallback } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ContainmentConfirmModal from '../components/ContainmentConfirmModal.jsx'
import TriageModal from '../components/TriageModal.jsx'
import { threatAPI, containmentAPI } from '../services/api.js'
import { useAuth } from '../hooks/useAuth.js'
import { usePermission } from '../hooks/usePermission.js'
import toast from 'react-hot-toast'
import { containmentOutcome } from '../utils/containmentLabels.js'

const STATUS_STYLES = {
  BLOCKED:        { background:'rgba(255,45,85,.15)',  color:'#ff2d55', border:'1px solid rgba(255,45,85,.3)'  },
  MONITORING:     { background:'rgba(255,170,0,.1)',   color:'#ffaa00', border:'1px solid rgba(255,170,0,.3)'  },
  DETECTED:       { background:'rgba(0,212,255,.1)',   color:'#00d4ff', border:'1px solid rgba(0,212,255,.25)' },
  RESOLVED:       { background:'rgba(0,255,136,.1)',   color:'#00ff88', border:'1px solid rgba(0,255,136,.3)'  },
  DEGRADED:       { background:'rgba(255,170,0,.15)',  color:'#ffaa00', border:'1px dashed rgba(255,170,0,.5)' },
  INVESTIGATING:  { background:'rgba(255,170,0,.15)',  color:'#ffaa00', border:'1px solid rgba(255,170,0,.4)'  },
  CONTAINED:      { background:'rgba(0,255,136,.15)',  color:'#00ff88', border:'1px solid rgba(0,255,136,.4)'  },
  FALSE_POSITIVE: { background:'rgba(160,160,160,.1)', color:'#888888', border:'1px solid rgba(160,160,160,.3)' },
}

const TYPES = ['SSH Brute Force','SQL Injection','Port Scan','DDoS','RCE Attempt',
               'XSS Attempt','Malware Beacon','Credential Stuffing','Lateral Movement','Data Exfiltration',
               'UNINSPECTED_TRAFFIC']

export default function ThreatLogs() {
  const { user } = useAuth()
  const { hasPermission } = usePermission()
  const canTriage = hasPermission('threats:triage')
  const canBlock = hasPermission('threats:block')

  const [threats, setThreats] = useState([])
  const [total,   setTotal]   = useState(0)
  const [page,    setPage]    = useState(1)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [search,  setSearch]  = useState('')
  const [sevFilter,  setSevFilter]  = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const LIMIT = 20

  const [containmentStatus, setContainmentStatus] = useState(null)
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedThreat, setSelectedThreat] = useState(null)
  const [submittingContainment, setSubmittingContainment] = useState(false)

  const [triageModalOpen, setTriageModalOpen] = useState(false)
  const [triageThreat, setTriageThreat] = useState(null)
  const [triageReadOnly, setTriageReadOnly] = useState(false)

  const loadContainmentStatus = async () => {
    if (user?.role === 'viewer') return
    try {
      const res = await containmentAPI.getStatus()
      setContainmentStatus(res.data?.data || null)
    } catch {
      // Non-critical, fallback to safe defaults
    }
  }

  useEffect(() => {
    loadContainmentStatus()
  }, [])

  const load = useCallback(async (p = page) => {
    setLoading(true)
    setError(null)
    try {
      const res = await threatAPI.list({
        page: p, limit: LIMIT,
        ...(sevFilter  && { severity: sevFilter }),
        ...(typeFilter && { type: typeFilter }),
        ...(search     && { search }),
      })
      setThreats(res.data.data || [])
      setTotal(res.data.pagination?.total || 0)
    } catch { setError('Threat logs are unavailable. Retry to load current data.') }
    finally { setLoading(false) }
  }, [page, sevFilter, typeFilter, search])

  useEffect(() => { setPage(1); load(1) }, [sevFilter, typeFilter])
  useEffect(() => { load(page) }, [page])

  const handleSearch = (e) => {
    if (e.key === 'Enter') { setPage(1); load(1) }
  }

  const openContainmentModal = (threat) => {
    setSelectedThreat(threat)
    setModalOpen(true)
  }

  const openTriageModal = (threat, readOnly = false) => {
    setTriageThreat(threat)
    setTriageReadOnly(readOnly)
    setTriageModalOpen(true)
  }

  const handleConfirmContainment = async ({ target, durationSeconds, isPermanent, reason }) => {
    setSubmittingContainment(true)
    try {
      const res = await containmentAPI.requestAction({
        target,
        actionType: 'block_ip',
        durationSeconds,
        isPermanent,
        reason,
        threatRef: selectedThreat?._id,
        metadata: {
          attackType: selectedThreat?.attackType,
          severity: selectedThreat?.severity,
        },
      })
      toast.success(containmentOutcome(target, res))
      setModalOpen(false)
      setSelectedThreat(null)
      load(page)
    } catch (err) {
      toast.error(err.response?.data?.error || 'Containment policy check failed')
    } finally {
      setSubmittingContainment(false)
    }
  }

  const inputStyle = { background:'#081f35', border:'1px solid #0d3352', borderRadius:2,
    padding:'8px 14px', color:'#c8e6f5', fontFamily:'Share Tech Mono,monospace', fontSize:12, outline:'none' }

  return (
    <DashboardLayout>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700 }}>
            Threat <span style={{ color:'#00d4ff' }}>Logs</span>
          </div>
          <span style={{
            fontFamily: 'Share Tech Mono,monospace',
            fontSize: 10,
            padding: '3px 8px',
            borderRadius: 2,
            background: containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled
              ? 'rgba(255, 45, 85, 0.15)'
              : 'rgba(0, 212, 255, 0.1)',
            border: `1px solid ${
              containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled
                ? 'rgba(255, 45, 85, 0.4)'
                : 'rgba(0, 212, 255, 0.3)'
            }`,
            color: containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled
              ? '#ff2d55'
              : '#00d4ff',
          }}>
            {containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled
              ? '● HOST FIREWALL ENFORCEMENT'
              : '○ SIMULATION / MOCK ADAPTER'}
          </span>
        </div>
        <button disabled title="CSV export is not available yet" style={{
          background:'transparent', border:'1px solid #1a4a6e', color:'#7ab3cc',
          fontFamily:'Rajdhani,sans-serif', fontWeight:600, fontSize:11,
          letterSpacing:1, textTransform:'uppercase', padding:'7px 14px', borderRadius:2, cursor:'pointer',
        }}>Export CSV</button>
      </div>

      <div style={{ display:'flex', gap:12, marginBottom:'1rem', alignItems:'center', flexWrap:'wrap' }}>
        <input style={{ ...inputStyle, width:260 }} type="text" placeholder="Search IP, type..."
          value={search} onChange={e => setSearch(e.target.value)} onKeyDown={handleSearch}
          onFocus={e=>e.target.style.borderColor='#00d4ff'}
          onBlur={e=>e.target.style.borderColor='#0d3352'} />
        <select style={{ ...inputStyle, cursor:'pointer' }} value={sevFilter} onChange={e=>{setSevFilter(e.target.value);setPage(1)}}>
          <option value="">All Severities</option>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s=><option key={s}>{s}</option>)}
        </select>
        <select style={{ ...inputStyle, cursor:'pointer' }} value={typeFilter} onChange={e=>{setTypeFilter(e.target.value);setPage(1)}}>
          <option value="">All Types</option>
          {TYPES.map(t=><option key={t}>{t}</option>)}
        </select>
        <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#3a6a88', marginLeft:'auto' }}>
          {total} events
        </span>
      </div>

      <Panel>
        {error ? <div role="alert" style={{ padding: '2rem', color: '#ffaa00' }}>{error} <button onClick={() => load(page)}>Retry</button></div> : loading ? (
          <div style={{ textAlign:'center', padding:'3rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>
            LOADING THREAT LOGS...
          </div>
        ) : (
          <div className="sentinel-table-scroll" role="region" aria-label="Threat logs" tabIndex={0}>
          <table style={{ width:'100%', minWidth: 780, borderCollapse:'collapse' }}>
            <thead><tr>
              {['Time','Severity','Source IP','Type','Target','Score','Status','Threat Intel','Action'].map(h=>(
                <th key={h} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88',
                  letterSpacing:2, padding:'8px 10px', borderBottom:'1px solid #0d3352', textAlign:'left' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {threats.map(l => (
                <tr key={l._id}
                  onMouseEnter={e=>e.currentTarget.style.background='rgba(0,212,255,.02)'}
                  onMouseLeave={e=>e.currentTarget.style.background=''}>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88' }}>
                    {new Date(l.createdAt).toLocaleTimeString('en-IN',{ timeZone: REPORT_TIME_ZONE,hour12:false})}
                  </td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)' }}><SeverityBadge sev={l.severity} /></td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#00d4ff' }}>{l.sourceIP}</td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontSize:13 }}>
                    <div>{l.attackType}</div>
                    {threatEvidenceLabel(l) && <div style={{ color: '#ffaa00', fontSize: 10 }}>{threatEvidenceLabel(l)}</div>}
                    {l.triageNotes && (
                      <div
                        onClick={() => openTriageModal(l, !canTriage)}
                        style={{
                          color: '#7ab3cc',
                          fontSize: 10,
                          fontFamily: 'Share Tech Mono,monospace',
                          cursor: 'pointer',
                          marginTop: 3,
                          opacity: 0.85,
                        }}
                        title={l.triageNotes}
                      >
                        📝 {l.triageNotes.length > 25 ? `${l.triageNotes.slice(0, 25)}...` : l.triageNotes}
                      </div>
                    )}
                    {l.mitreTechniques && l.mitreTechniques.length > 0 && (
                      <div style={{ display:'flex', flexWrap:'wrap', gap:4, marginTop:4 }}>
                        {l.mitreTechniques.map((tech, i) => (
                          <span key={i} title={tech.name} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:9, background:'rgba(0, 212, 255, 0.1)',
                            border:'1px solid rgba(0, 212, 255, 0.3)', color:'#00d4ff', padding:'1px 4px', borderRadius:2, display:'inline-block' }}>
                            {tech.id} - {tech.name}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#7ab3cc' }}>{l.targetService}</td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:12,
                    color:l.aiScore>=0.9?'#ff2d55':l.aiScore>=0.7?'#ffaa00':'#00d4ff' }}>
                    {((l.aiScore||0)*100).toFixed(0)}%
                  </td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, padding:'3px 8px', borderRadius:1, ...(STATUS_STYLES[l.status]||STATUS_STYLES.DETECTED) }}>
                      {l.status}
                    </span>
                  </td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11 }}>
                    {l.threatIntel?.status === 'SUCCESS' ? (
                      <div title={`Provider: AbuseIPDB | Reports: ${l.threatIntel.totalReports} | ISP: ${l.threatIntel.isp || 'N/A'}`}>
                        <span style={{
                          background: 'rgba(155, 89, 182, 0.15)',
                          border: '1px solid rgba(155, 89, 182, 0.4)',
                          color: '#c39bd3',
                          padding: '2px 6px',
                          borderRadius: 2,
                          fontSize: 10,
                          display: 'inline-block',
                          letterSpacing: 0.5,
                        }}>
                          AbuseIPDB: {l.threatIntel.abuseConfidenceScore}%
                        </span>
                        <div style={{ fontSize: 9, color: '#6c7a89', marginTop: 2 }}>
                          {l.threatIntel.totalReports} reports
                        </div>
                      </div>
                    ) : l.threatIntel?.status === 'PENDING' ? (
                      <span style={{ color: '#7ab3cc', fontSize: 10, opacity: 0.7 }}>
                        Querying...
                      </span>
                    ) : l.threatIntel?.status === 'UNAVAILABLE' ? (
                      <span style={{ color: '#4a6984', fontSize: 10 }}>
                        N/A ({l.threatIntel.errorCode === 'PRIVATE_IP' ? 'Internal' : l.threatIntel.errorCode === 'NO_API_KEY' ? 'No Key' : l.threatIntel.errorCode || 'Unavailable'})
                      </span>
                    ) : l.threatIntel?.status === 'FAILED' ? (
                      <span style={{ color: '#e74c3c', fontSize: 10 }}>
                        Lookup Failed
                      </span>
                    ) : (
                      <span style={{ color: '#3a5369', fontSize: 10 }}>—</span>
                    )}
                  </td>
                  <td style={{ padding:'9px 10px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                      {canTriage && (
                        <button
                          onClick={() => openTriageModal(l, false)}
                          style={{
                            background: 'rgba(0, 212, 255, 0.1)',
                            border: '1px solid rgba(0, 212, 255, 0.3)',
                            color: '#00d4ff',
                            fontSize: 10,
                            fontFamily: 'Share Tech Mono,monospace',
                            padding: '3px 8px',
                            cursor: 'pointer',
                            borderRadius: 1,
                          }}
                        >
                          Triage
                        </button>
                      )}
                      {l.status !== 'BLOCKED' && (
                        canBlock ? (
                          <button onClick={() => openContainmentModal(l)} style={{
                            background:'none', border:'1px solid #0d3352', color:'#3a6a88',
                            fontSize:10, fontFamily:'Share Tech Mono,monospace', padding:'3px 8px', cursor:'pointer', borderRadius:1,
                          }}>Block</button>
                        ) : (
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
                        )
                      )}
                      {!canTriage && l.triageNotes && (
                        <button
                          onClick={() => openTriageModal(l, true)}
                          style={{
                            background: 'none',
                            border: '1px solid #0d3352',
                            color: '#7ab3cc',
                            fontSize: 10,
                            fontFamily: 'Share Tech Mono,monospace',
                            padding: '3px 6px',
                            cursor: 'pointer',
                            borderRadius: 1,
                          }}
                        >
                          Dossier
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {threats.length === 0 && (
                <tr><td colSpan={9} style={{ padding:'2rem', textAlign:'center', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>
                  No live security events detected. Waiting for real telemetry...
                </td></tr>
              )}
            </tbody>
          </table>
          </div>
        )}

        {/* Pagination */}
        {total > LIMIT && (
          <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:'1rem' }}>
            <button onClick={()=>setPage(p=>Math.max(1,p-1))} disabled={page===1} style={{
              background:'transparent', border:'1px solid #1a4a6e', color:'#7ab3cc',
              fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'6px 14px',
              borderRadius:2, cursor: page===1?'not-allowed':'pointer', opacity:page===1?0.4:1,
            }}>← Prev</button>
            <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88', padding:'6px 12px' }}>
              {page} / {Math.ceil(total/LIMIT)}
            </span>
            <button onClick={()=>setPage(p=>p+1)} disabled={page>=Math.ceil(total/LIMIT)} style={{
              background:'transparent', border:'1px solid #1a4a6e', color:'#7ab3cc',
              fontFamily:'Share Tech Mono,monospace', fontSize:11, padding:'6px 14px',
              borderRadius:2, cursor:page>=Math.ceil(total/LIMIT)?'not-allowed':'pointer',
              opacity:page>=Math.ceil(total/LIMIT)?0.4:1,
            }}>Next →</button>
          </div>
        )}
      </Panel>

      <ContainmentConfirmModal
        isOpen={modalOpen}
        target={selectedThreat?.sourceIP}
        threatInfo={selectedThreat}
        backendInfo={containmentStatus}
        onClose={() => { setModalOpen(false); setSelectedThreat(null) }}
        onConfirm={handleConfirmContainment}
        loading={submittingContainment}
      />

      <TriageModal
        isOpen={triageModalOpen}
        threat={triageThreat}
        isReadOnly={triageReadOnly}
        onClose={() => { setTriageModalOpen(false); setTriageThreat(null) }}
        onSuccess={() => load(page)}
      />
    </DashboardLayout>
  )
}
