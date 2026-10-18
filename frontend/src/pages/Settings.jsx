import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useState, useEffect } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import { threatAPI, containmentAPI, auditAPI } from '../services/api.js'
import ContainmentConfirmModal from '../components/ContainmentConfirmModal.jsx'
import toast from 'react-hot-toast'

export default function Settings() {
  const [autoBlockEnabled, setAutoBlockEnabled] = useState(false)
  const [blockedIPs, setBlockedIPs] = useState([])
  const [containmentStatus, setContainmentStatus] = useState(null)
  const [auditLogs, setAuditLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [ipInput, setIpInput] = useState('')
  const [reasonInput, setReasonInput] = useState('')
  const [submittingBlock, setSubmittingBlock] = useState(false)
  const [submittingToggle, setSubmittingToggle] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [modalTarget, setModalTarget] = useState('')
  const [modalReason, setModalReason] = useState('')

  const loadData = async () => {
    try {
      const [settingsRes, blockedRes, containmentRes, auditRes] = await Promise.all([
        threatAPI.getSettings(),
        threatAPI.getBlockedIPs(),
        containmentAPI.getStatus().catch(() => ({ data: { data: null } })),
        auditAPI.list({ limit: 20 }).catch(() => ({ data: { data: [] } })),
      ])
      setAutoBlockEnabled(settingsRes.data?.data?.autoBlockEnabled || false)
      setBlockedIPs(blockedRes.data?.data?.blockedIPs || [])
      setContainmentStatus(containmentRes.data?.data || null)
      setAuditLogs(auditRes.data?.data || [])
    } catch (err) {
      toast.error('Failed to load settings data')
    } finally {
      setLoading(false)

    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleToggleAutoBlock = async () => {
    if (submittingToggle) return
    setSubmittingToggle(true)
    const newValue = !autoBlockEnabled
    try {
      await threatAPI.updateSettings({ autoBlockEnabled: newValue })
      setAutoBlockEnabled(newValue)
      if (newValue) {
        toast.success('Autonomous Auto-Blocking Enabled')
      } else {
        toast.error('Autonomous Auto-Blocking Disabled')
      }
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update settings')
    } finally {
      setSubmittingToggle(false)
    }
  }

  const handleBlockManual = (e) => {
    e.preventDefault()
    if (!ipInput.trim()) {
      return toast.error('IP address is required')
    }
    setModalTarget(ipInput.trim())
    setModalReason(reasonInput.trim())
    setModalOpen(true)
  }

  const handleConfirmContainment = async ({ target, durationSeconds, isPermanent, reason }) => {
    setSubmittingBlock(true)
    try {
      await containmentAPI.requestAction({
        target,
        actionType: 'block_ip',
        durationSeconds,
        isPermanent,
        reason,
      })
      toast.success(`IP ${target} containment policy applied`)
      setIpInput('')
      setReasonInput('')
      setModalOpen(false)
      // Reload the list
      await loadData()
    } catch (err) {
      toast.error(err.response?.data?.error || 'Containment request failed')
    } finally {
      setSubmittingBlock(false)
    }
  }

  const handleUnblock = async (ip) => {
    try {
      await threatAPI.unblockIPManual({ ip })
      toast.success(`IP ${ip} unblocked successfully`)
      // Reload the list
      await loadData()
    } catch (err) {
      toast.error(err.response?.data?.error || 'Unblock request failed')
    }
  }

  return (
    <DashboardLayout>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700 }}>
            System <span style={{ color: '#00d4ff' }}>Settings</span>
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
      </div>

      <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88', letterSpacing: 2, marginBottom: '1.5rem' }}>
        // SYSTEM ENFORCEMENT CONFIGURATION & LAB FIREWALL CONTROL
      </div>

      {loading ? (
        <div style={{
          display: 'flex', justifyContent: 'center', alignItems: 'center', height: '200px',
          color: '#00ff88', fontFamily: 'Share Tech Mono,monospace', fontSize: 14
        }}>
          LOADING CONFIGURATION POOL...
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Host Containment Policy Engine Panel */}
          <Panel title="Host Containment & Response Policy Engine" badge={containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? 'Live Firewall' : 'Simulation Mode'} badgeType={containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? 'danger' : 'info'}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '0.5rem 0' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                <div>
                  <div style={{ fontFamily: 'Rajdhani,sans-serif', fontSize: 16, fontWeight: 600, color: '#00d4ff' }}>
                    Active Enforcement Adapter: {containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? 'WindowsFirewallAdapter (Host OS)' : 'MockContainmentAdapter (In-Memory Simulation)'}
                  </div>
                  <div style={{ color: '#7ab3cc', fontSize: 13, marginTop: '4px' }}>
                    {containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled
                      ? 'Inbound block rules are actively managed via Windows Advanced Firewall.'
                      : 'Containment actions execute safely in-memory against the SentinelAI policy engine without host network mutation.'}
                  </div>
                </div>
                <div style={{
                  padding: '6px 14px',
                  borderRadius: '2px',
                  background: containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? 'rgba(255, 45, 85, 0.15)' : 'rgba(0, 212, 255, 0.1)',
                  border: `1px solid ${containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? '#ff2d55' : '#00d4ff'}`,
                  fontFamily: 'Share Tech Mono,monospace',
                  fontSize: 11,
                  color: containmentStatus?.backend === 'windows-firewall' && containmentStatus?.realEnforcementEnabled ? '#ff2d55' : '#00d4ff',
                }}>
                  ACTIVE RULES: {containmentStatus?.activeContainmentCount || 0} | FAILED: {containmentStatus?.failedContainmentCount || 0}
                </div>
              </div>
              <div style={{ background: 'rgba(8, 31, 53, 0.5)', padding: '10px 12px', borderRadius: '2px', fontSize: 12, color: '#7ab3cc' }}>
                <strong style={{ color: '#00ff88' }}>Safety Policy Invariants:</strong> Loopback (<code style={{ color: '#00d4ff' }}>127.0.0.1</code>, <code style={{ color: '#00d4ff' }}>::1</code>), default gateway, and local services (<code style={{ color: '#00d4ff' }}>5000, 8000, 27017, 3000</code>) are protected against containment blackholing.
              </div>
            </div>
          </Panel>
          
          {/* AI Auto Blocking Config */}
          <Panel title="AI Autonomous Enforcement Engine" badge="Settings" badgeType="info">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '2rem', padding: '0.5rem 0' }}>
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'Rajdhani,sans-serif', fontSize: 16, fontWeight: 600, color: '#00d4ff', marginBottom: '0.5rem' }}>
                  AI Auto-Blocking (Honeypot Connections)
                </div>
                <p style={{ color: '#7ab3cc', fontSize: 13, lineHeight: '1.5', margin: 0 }}>
                  When enabled, qualifying AI predictions add source IPs to the honeypot blocklist
                  using the configured threat score threshold. Connection rejection requires a running
                  Cowrie instance with the SentinelAI blocker plugin connected to this backend.
                  This setting does not configure a host-wide firewall.
                </p>
              </div>

              {/* Toggle Switch */}
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: '120px' }}>
                <button 
                  onClick={handleToggleAutoBlock} 
                  disabled={submittingToggle}
                  style={{
                    background: autoBlockEnabled ? 'rgba(0, 255, 136, 0.15)' : 'rgba(255, 45, 85, 0.15)',
                    border: autoBlockEnabled ? '1px solid #00ff88' : '1px solid #ff2d55',
                    color: autoBlockEnabled ? '#00ff88' : '#ff2d55',
                    fontFamily: 'Share Tech Mono,monospace',
                    fontSize: 12,
                    fontWeight: 'bold',
                    padding: '8px 16px',
                    borderRadius: '2px',
                    cursor: submittingToggle ? 'not-allowed' : 'pointer',
                    transition: 'all 0.2s ease',
                    boxShadow: autoBlockEnabled ? '0 0 10px rgba(0, 255, 136, 0.2)' : 'none',
                    letterSpacing: '1px'
                  }}
                >
                  {autoBlockEnabled ? 'ACTIVE / ON' : 'DISABLED / OFF'}
                </button>
                <span style={{ 
                  fontSize: 10, 
                  fontFamily: 'Share Tech Mono,monospace', 
                  color: autoBlockEnabled ? '#00ff88' : '#ff2d55',
                  marginTop: '8px'
                }}>
                  {autoBlockEnabled ? '● AUTO-BLOCK ACTIVE' : '○ DEFENSIVE ONLY'}
                </span>
              </div>
            </div>
          </Panel>

          {/* Manual Blocking Form */}
          <Panel title="Manual Network Enforcement Action" badge="Blocklist Add" badgeType="live">
            <form onSubmit={handleBlockManual} style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', flexWrap: 'wrap', padding: '0.5rem 0' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: '1 1 250px' }}>
                <label style={{ fontSize: 10, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>Target IP Address</label>
                <input 
                  type="text" 
                  placeholder="e.g. 185.220.101.47" 
                  value={ipInput} 
                  onChange={e => setIpInput(e.target.value)}
                  style={{
                    background: '#041120', border: '1px solid #0d3352', color: '#c8e6f5',
                    padding: '8px 12px', fontSize: 13, fontFamily: 'Share Tech Mono,monospace',
                    outline: 'none', borderRadius: '2px'
                  }} 
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flex: '2 1 350px' }}>
                <label style={{ fontSize: 10, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>Reason / Threat Context</label>
                <input 
                  type="text" 
                  placeholder="e.g. Manual block of scanner IP" 
                  value={reasonInput} 
                  onChange={e => setReasonInput(e.target.value)}
                  style={{
                    background: '#041120', border: '1px solid #0d3352', color: '#c8e6f5',
                    padding: '8px 12px', fontSize: 13, fontFamily: 'Rajdhani,sans-serif',
                    outline: 'none', borderRadius: '2px'
                  }} 
                />
              </div>

              <button 
                type="submit" 
                disabled={submittingBlock}
                style={{
                  background: '#ff2d55', border: '1px solid #ff2d55', color: '#fff',
                  fontFamily: 'Rajdhani,sans-serif', fontWeight: 600, fontSize: 12,
                  letterSpacing: '1px', textTransform: 'uppercase', padding: '9px 24px',
                  borderRadius: '2px', cursor: submittingBlock ? 'not-allowed' : 'pointer',
                  transition: 'all 0.15s', height: '37px', flexShrink: 0
                }}
                onMouseEnter={e => { if(!submittingBlock) { e.target.style.background = '#e01b44'; e.target.style.borderColor = '#e01b44' } }}
                onMouseLeave={e => { if(!submittingBlock) { e.target.style.background = '#ff2d55'; e.target.style.borderColor = '#ff2d55' } }}
              >
                {submittingBlock ? 'Enforcing...' : 'Enforce IP Block'}
              </button>
            </form>
          </Panel>

          {/* Blocklist Table */}
          <Panel title="Enforced Honeypot Blocklist Queue" badge={`${blockedIPs.length} Blocked`} badgeType="live">
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {['Enforced IP', 'Blocked At', 'Triggered By / Author', 'Reason', 'Action'].map(h => (
                    <th key={h} style={{
                      fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88',
                      letterSpacing: 2, padding: '10px', borderBottom: '1px solid #0d3352', textAlign: 'left'
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {blockedIPs.map(b => (
                  <tr key={b._id}>
                    <td style={{ 
                      padding: '10px', borderBottom: '1px solid rgba(13,51,82,.4)', 
                      fontFamily: 'Share Tech Mono,monospace', fontSize: 13, color: '#ff2d55', fontWeight: 'bold'
                    }}>{b.ip}</td>
                    
                    <td style={{ 
                      padding: '10px', borderBottom: '1px solid rgba(13,51,82,.4)', 
                      fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#7ab3cc' 
                    }}>
                      {new Date(b.blockedAt).toLocaleString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })}
                    </td>
                    
                    <td style={{ 
                      padding: '10px', borderBottom: '1px solid rgba(13,51,82,.4)', 
                      fontFamily: 'Share Tech Mono,monospace', fontSize: 12, color: b.blockedBy ? '#00d4ff' : '#ffaa00'
                    }}>
                      {b.blockedBy ? b.blockedBy.name : 'AI Engine'}
                    </td>
                    
                    <td style={{ 
                      padding: '10px', borderBottom: '1px solid rgba(13,51,82,.4)', 
                      fontSize: 13, color: '#c8e6f5' 
                    }}>{b.reason}</td>
                    
                    <td style={{ padding: '10px', borderBottom: '1px solid rgba(13,51,82,.4)' }}>
                      <button 
                        onClick={() => handleUnblock(b.ip)} 
                        style={{
                          background: 'transparent', border: '1px solid #0d3352', color: '#7ab3cc',
                          fontSize: 11, fontFamily: 'Share Tech Mono,monospace', padding: '4px 10px',
                          cursor: 'pointer', borderRadius: '1px', transition: 'all 0.15s'
                        }}
                        onMouseEnter={e => { e.target.style.borderColor = '#00ff88'; e.target.style.color = '#00ff88' }}
                        onMouseLeave={e => { e.target.style.borderColor = '#0d3352'; e.target.style.color = '#7ab3cc' }}
                      >
                        Unblock IP
                      </button>
                    </td>
                  </tr>
                ))}

                {blockedIPs.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{
                      padding: '2rem', textAlign: 'center', color: '#3a6a88',
                      fontFamily: 'Share Tech Mono,monospace', fontSize: 12
                    }}>
                      No IP addresses are listed in the honeypot blocklist.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Panel>

          {/* Security Audit Trail Panel (Admin Only) */}
          <Panel title="Security & Compliance Audit Trail" badge="AUDIT" badgeType="info">
            <div style={{ marginBottom: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 12, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace' }}>
                Immutable security event history recording privileged operations and authorization decisions.
              </span>
              <button
                onClick={loadData}
                style={{
                  background: '#0d3352',
                  border: '1px solid #1a4a6e',
                  color: '#00d4ff',
                  padding: '4px 10px',
                  borderRadius: 2,
                  fontFamily: 'Share Tech Mono,monospace',
                  fontSize: 11,
                  cursor: 'pointer',
                }}
              >
                Refresh Log
              </button>
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #0d3352', color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', fontSize: 11 }}>
                  <th style={{ padding: '8px 10px' }}>TIMESTAMP</th>
                  <th style={{ padding: '8px 10px' }}>ACTION</th>
                  <th style={{ padding: '8px 10px' }}>ACTOR</th>
                  <th style={{ padding: '8px 10px' }}>TARGET</th>
                  <th style={{ padding: '8px 10px' }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.map((log, i) => (
                  <tr key={log._id || i} style={{ borderBottom: '1px solid rgba(13,51,82,.4)', fontSize: 12 }}>
                    <td style={{ padding: '10px', color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', fontSize: 11 }}>
                      {log.createdAt ? new Date(log.createdAt).toLocaleString('en-US', { timeZone: REPORT_TIME_ZONE }) : '-'}
                    </td>
                    <td style={{ padding: '10px', color: '#00d4ff', fontFamily: 'Share Tech Mono,monospace' }}>
                      {log.action}
                    </td>
                    <td style={{ padding: '10px', color: '#c8e6f5' }}>
                      {log.actor?.email || 'System'}
                      {log.actor?.role && (
                        <span style={{ marginLeft: 6, fontSize: 10, padding: '2px 6px', background: '#081f35', border: '1px solid #1a4a6e', color: '#7ab3cc', borderRadius: 2 }}>
                          {log.actor.role}
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '10px', color: '#c8e6f5', fontFamily: 'Share Tech Mono,monospace' }}>
                      {log.target?.identifier || log.target?.id || '-'}
                    </td>
                    <td style={{ padding: '10px' }}>
                      <span style={{
                        padding: '2px 8px',
                        fontSize: 10,
                        fontFamily: 'Share Tech Mono,monospace',
                        borderRadius: 2,
                        background: log.status === 'SUCCESS' || log.status === 'EXECUTED' ? 'rgba(0,255,136,.1)' : 'rgba(255,45,85,.1)',
                        border: `1px solid ${log.status === 'SUCCESS' || log.status === 'EXECUTED' ? '#00ff88' : '#ff2d55'}`,
                        color: log.status === 'SUCCESS' || log.status === 'EXECUTED' ? '#00ff88' : '#ff2d55',
                      }}>
                        {log.status || 'LOGGED'}
                      </span>
                    </td>
                  </tr>
                ))}
                {auditLogs.length === 0 && (
                  <tr>
                    <td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>
                      No audit events recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </Panel>
          
        </div>
      )}


      <ContainmentConfirmModal
        isOpen={modalOpen}
        target={modalTarget}
        threatInfo={{ attackType: modalReason }}
        backendInfo={containmentStatus}
        onClose={() => setModalOpen(false)}
        onConfirm={handleConfirmContainment}
        loading={submittingBlock}
      />
    </DashboardLayout>
  )
}
