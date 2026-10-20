import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useState, useEffect } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import KpiCard from '../components/KpiCard.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import { campaignAPI } from '../services/api.js'
import toast from 'react-hot-toast'

export default function Campaigns() {
  const [campaigns, setCampaigns] = useState([])
  const [selectedCampaign, setSelectedCampaign] = useState(null)
  const [expandedSessionId, setExpandedSessionId] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadCampaigns = async (silent = false) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const res = await campaignAPI.list()
      const list = res.data.data || []
      setCampaigns(list)
      // If there is a selected campaign, refresh its data too
      if (selectedCampaign) {
        const refreshed = list.find(c => c._id === selectedCampaign._id)
        if (refreshed) setSelectedCampaign(refreshed)
      }
    } catch {
      setError('Campaign telemetry is unavailable. Retry to load current clusters.')
      toast.error('Failed to load campaigns')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadCampaigns()
  }, [])

  // Helper formatting functions
  const fmtDate = (dStr) => {
    if (!dStr) return 'N/A'
    const d = new Date(dStr)
    return d.toLocaleString('en-IN', { timeZone: REPORT_TIME_ZONE })
  }

  const fmtDuration = (s) => {
    const m = Math.floor(s / 60)
    return m > 0 ? `${m}m ${s % 60}s` : `${s}s`
  }

  // Calculate KPIs on the fly
  const totalCampaigns = campaigns.length
  const uniqueIPs = new Set(campaigns.flatMap(c => c.sourceIPs || [])).size
  const maxDeception = campaigns.length ? Math.max(...campaigns.map(c => c.maxDeceptionScore || 0)) : 0
  const avgSessions = campaigns.length
    ? (campaigns.reduce((acc, c) => acc + (c.sessions?.length || 0), 0) / campaigns.length).toFixed(1)
    : '0.0'

  return (
    <DashboardLayout>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div>
          <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700 }}>
            Attacker Campaign <span style={{ color: '#00d4ff' }}>Clustering</span>
          </div>
          <p style={{ color: '#7ab3cc', fontSize: 11, margin: '4px 0 0 0', fontFamily: 'Rajdhani,sans-serif' }}>
            SentinelAI groups honeypot sessions based on exact SSH Client Fingerprints (HASSH) or command sequence similarity.
          </p>
        </div>
        <button
          onClick={() => {
            loadCampaigns(true)
            toast.success('Campaign cache refreshed')
          }}
          style={{
            background: 'rgba(0,212,255,.08)',
            border: '1px solid #0d3352',
            color: '#00d4ff',
            fontFamily: 'Share Tech Mono,monospace',
            fontSize: 11,
            padding: '6px 14px',
            borderRadius: 1,
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
          onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,212,255,.15)'}
          onMouseLeave={e => e.currentTarget.style.background = 'rgba(0,212,255,.08)'}
        >
          REFRESH FEED
        </button>
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
            onClick={() => loadCampaigns()}
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

      {/* KPIs Grid */}
      <div className="dashboard-grid dashboard-kpis" style={{ gap: '1rem', marginBottom: '1.5rem' }}>
        <KpiCard label="Detected Campaigns" value={loading ? '—' : totalCampaigns} delta="clusters found" color="#00d4ff" />
        <KpiCard label="Clustered IPs" value={loading ? '—' : uniqueIPs} delta="coordinated nodes" color="#ffaa00" />
        <KpiCard label="Max Deception" value={loading ? '—' : maxDeception} delta="high reward triggers" color="#ff2d55" />
        <KpiCard label="Avg Sessions / Campaign" value={loading ? '—' : avgSessions} delta="persistence count" color="#00ff88" />
      </div>

      <div className={`dashboard-grid ${selectedCampaign ? 'dashboard-grid-two' : ''}`} style={{ gap: '1rem', transition: 'all 0.3s' }}>
        {/* Main Campaigns List Panel */}
        <Panel title="Active Attack Campaigns" badge={`${campaigns.length} Active`} badgeType="info">
          <div className="sentinel-table-scroll" role="region" aria-label="Active attack campaigns" tabIndex={0}>
            {loading ? (
              <div style={{ textAlign: 'center', padding: '3rem', color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>
                ANALYZING TRAFFIC DATA...
              </div>
            ) : error ? null : campaigns.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '3rem', color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>
                No live security events detected. Waiting for real telemetry...
              </div>
            ) : (
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #0d3352', fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88' }}>
                    <th style={{ padding: '8px 12px' }}>CAMPAIGN ID</th>
                    <th style={{ padding: '8px 12px' }}>THREAT</th>
                    <th style={{ padding: '8px 12px' }}>SESSIONS</th>
                    <th style={{ padding: '8px 12px' }}>SOURCE IPS</th>
                    <th style={{ padding: '8px 12px' }}>LAST SEEN</th>
                    <th style={{ padding: '8px 12px', textAlign: 'right' }}>ACTIONS</th>
                  </tr>
                </thead>
                <tbody>
                  {campaigns.map(c => {
                    const isSelected = selectedCampaign?._id === c._id
                    const rotated = c.sourceIPs?.length > 1
                    return (
                      <tr
                        key={c._id}
                        style={{
                          borderBottom: '1px solid #061c30',
                          background: isSelected ? 'rgba(0, 212, 255, 0.05)' : 'transparent',
                          transition: 'background 0.2s',
                          cursor: 'pointer'
                        }}
                        onClick={() => {
                          setSelectedCampaign(c)
                          setExpandedSessionId(null)
                        }}
                        onMouseEnter={e => !isSelected && (e.currentTarget.style.background = '#041526')}
                        onMouseLeave={e => !isSelected && (e.currentTarget.style.background = 'transparent')}
                      >
                        <td style={{ padding: '12px', fontFamily: 'Share Tech Mono,monospace', fontSize: 13, color: '#00d4ff', fontWeight: 'bold' }}>
                          {c.campaignId}
                        </td>
                        <td style={{ padding: '12px' }}>
                          <SeverityBadge sev={c.threatLevel} />
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'Share Tech Mono,monospace', fontSize: 12, color: '#c8e6f5' }}>
                          {c.sessions?.length || 0}
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>
                          {rotated ? (
                            <span
                              style={{
                                background: 'rgba(255,170,0,.1)',
                                border: '1px solid rgba(255,170,0,.3)',
                                padding: '2px 6px',
                                borderRadius: 2,
                                color: '#ffaa00',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                fontSize: 10,
                                fontWeight: 700
                              }}
                              title={c.sourceIPs.join(', ')}
                            >
                              🔄 {c.sourceIPs.length} IPs (Rotated)
                            </span>
                          ) : (
                            <span style={{ color: '#7ab3cc' }}>{c.sourceIPs?.[0] || 'N/A'}</span>
                          )}
                        </td>
                        <td style={{ padding: '12px', fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88' }}>
                          {fmtDate(c.lastSeen)}
                        </td>
                        <td style={{ padding: '12px', textAlign: 'right' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedCampaign(c)
                              setExpandedSessionId(null)
                            }}
                            style={{
                              background: 'transparent',
                              border: isSelected ? '1px solid #00d4ff' : '1px solid #1a4a6e',
                              color: isSelected ? '#00d4ff' : '#7ab3cc',
                              fontSize: 10,
                              fontFamily: 'Rajdhani,sans-serif',
                              fontWeight: 600,
                              padding: '4px 10px',
                              borderRadius: 1,
                              cursor: 'pointer'
                            }}
                          >
                            {isSelected ? 'ACTIVE' : 'ANALYZE'}
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
          </div>
        </Panel>

        {/* Campaign Drill-down Panel */}
        {selectedCampaign && (
          <Panel
            title={`Campaign Details: ${selectedCampaign.campaignId}`}
            badge="Detail View"
            badgeType="ok"
            style={{ borderLeft: '3px solid #00d4ff' }}
          >
            <div style={{ marginBottom: '1.25rem', borderBottom: '1px dashed #0d3352', paddingBottom: '1rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: 12, fontFamily: 'Rajdhani,sans-serif' }}>
                <div>
                  <span style={{ color: '#3a6a88' }}>First Seen:</span>{' '}
                  <span style={{ color: '#c8e6f5', fontFamily: 'Share Tech Mono,monospace' }}>{fmtDate(selectedCampaign.firstSeen)}</span>
                </div>
                <div>
                  <span style={{ color: '#3a6a88' }}>Last Seen:</span>{' '}
                  <span style={{ color: '#c8e6f5', fontFamily: 'Share Tech Mono,monospace' }}>{fmtDate(selectedCampaign.lastSeen)}</span>
                </div>
                <div>
                  <span style={{ color: '#3a6a88' }}>Max Deception Score:</span>{' '}
                  <span style={{ color: '#ff2d55', fontFamily: 'Share Tech Mono,monospace', fontWeight: 'bold' }}>{selectedCampaign.maxDeceptionScore || 0}/100</span>
                </div>
                <div>
                  <span style={{ color: '#3a6a88' }}>Max AI Threat Score:</span>{' '}
                  <span style={{ color: '#ffaa00', fontFamily: 'Share Tech Mono,monospace', fontWeight: 'bold' }}>
                    {((selectedCampaign.maxAiThreatScore || 0) * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
              <div style={{ marginTop: 10 }}>
                <span style={{ color: '#3a6a88', fontSize: 11, display: 'block', marginBottom: 4, fontFamily: 'Share Tech Mono,monospace' }}>IP ADDRESSES INVOLVED:</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {selectedCampaign.sourceIPs?.map(ip => (
                    <span key={ip} style={{ background: '#041120', border: '1px solid #0d3352', padding: '2px 8px', borderRadius: 2, fontSize: 11, color: '#00d4ff', fontFamily: 'Share Tech Mono,monospace' }}>
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            <h4 style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 11, color: '#7ab3cc', letterSpacing: 1, textTransform: 'uppercase', margin: '0 0 10px 0' }}>
              Member Sessions ({selectedCampaign.sessions?.length || 0})
            </h4>

            <div style={{ maxHeight: '420px', overflowY: 'auto', paddingRight: '4px' }}>
              {selectedCampaign.sessions?.map(s => {
                const isExpanded = expandedSessionId === s._id
                return (
                  <div key={s._id} style={{ background: '#041120', border: '1px solid #0d3352', borderRadius: 2, marginBottom: 8, padding: 10 }}>
                    <div
                      style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}
                      onClick={() => setExpandedSessionId(isExpanded ? null : s._id)}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 12, color: '#00d4ff', fontWeight: 600 }}>{s.sourceIP}</span>
                          <span style={{ fontSize: 9, background: '#061c30', border: '1px solid #0d3352', padding: '1px 4px', color: '#7ab3cc' }}>
                            {s.geoLocation?.countryCode || '??'}
                          </span>
                        </div>
                        <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88' }}>
                          ID: {s.sessionId} | Dur: {fmtDuration(s.durationSeconds || 0)}
                        </div>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ textAlign: 'right' }}>
                          <span style={{ fontSize: 9, fontFamily: 'Share Tech Mono,monospace', color: '#ff2d55', display: 'block' }}>Dec: {s.deceptionScore || 0}</span>
                          {s.aiClassification && (
                            <span style={{ fontSize: 9, fontFamily: 'Rajdhani,sans-serif', color: '#00ff88', display: 'block', fontWeight: 600 }}>
                              {s.aiClassification.split('_').join(' ')}
                            </span>
                          )}
                        </div>
                        <span style={{ fontSize: 10, color: '#3a6a88' }}>{isExpanded ? '▲' : '▼'}</span>
                      </div>
                    </div>

                    {/* Expandable Retro Console Commands List */}
                    {isExpanded && (
                      <div style={{ marginTop: 10, borderTop: '1px solid #0d3352', paddingTop: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88' }}>SSH CLIENT HASSH:</span>
                          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#ffaa00', fontWeight: 'bold' }}>
                            {s.hassh || 'NO HASSH (PRE-KEX CLOSED)'}
                          </span>
                        </div>
                        <div style={{
                          background: '#020b18',
                          border: '1px solid #0d3352',
                          padding: '10px',
                          fontFamily: 'Share Tech Mono, monospace',
                          color: '#00ff88',
                          fontSize: 11,
                          borderRadius: 2,
                          boxShadow: 'inset 0 0 8px rgba(0,255,136,0.1)',
                          maxHeight: '180px',
                          overflowY: 'auto'
                        }}>
                          {s.commands?.length === 0 ? (
                            <div style={{ color: '#3a6a88', fontSize: 10 }}>[NO COMMANDS EXECUTED]</div>
                          ) : (
                            s.commands.map((cmd, i) => (
                              <div key={i} style={{ marginBottom: 4, display: 'flex', gap: 6 }}>
                                <span style={{ color: '#3a6a88' }}>[{new Date(cmd.timestamp).toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })}]</span>
                                <span style={{ color: '#ffaa00' }}>$</span>
                                <span style={{ wordBreak: 'break-all' }}>{cmd.command}</span>
                                {cmd.intent && (
                                  <span style={{
                                    marginLeft: 'auto',
                                    fontSize: 8,
                                    background: 'rgba(0, 212, 255, 0.1)',
                                    color: '#00d4ff',
                                    border: '1px solid rgba(0, 212, 255, 0.25)',
                                    padding: '1px 4px',
                                    borderRadius: 1
                                  }}>
                                    {cmd.intent}
                                  </span>
                                )}
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </Panel>
        )}
      </div>
    </DashboardLayout>
  )
}
