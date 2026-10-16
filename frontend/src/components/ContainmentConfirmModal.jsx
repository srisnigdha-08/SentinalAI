import React, { useState } from 'react'

export default function ContainmentConfirmModal({
  isOpen,
  target,
  threatInfo,
  backendInfo,
  onClose,
  onConfirm,
  loading = false,
}) {
  const [duration, setDuration] = useState('3600')
  const [reason, setReason] = useState('')

  if (!isOpen) return null

  const handleConfirm = () => {
    const isPermanent = duration === 'permanent'
    const durationSeconds = isPermanent ? null : parseInt(duration, 10)
    onConfirm({
      target,
      durationSeconds,
      isPermanent,
      reason: reason.trim() || threatInfo?.attackType ? `Blocked for ${threatInfo?.attackType || 'threat activity'}` : 'Manual analyst containment',
    })
  }

  const isMock = !backendInfo || backendInfo.backend === 'mock' || !backendInfo.realEnforcementEnabled

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: 'rgba(2, 8, 16, 0.85)',
        backdropFilter: 'blur(4px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 9999,
        padding: '1rem',
      }}
    >
      <div
        style={{
          background: '#041120',
          border: '1px solid #ff2d55',
          boxShadow: '0 0 30px rgba(255, 45, 85, 0.25)',
          borderRadius: '4px',
          maxWidth: '540px',
          width: '100%',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,45,85,0.3)', paddingBottom: '0.75rem' }}>
          <div>
            <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 16, fontWeight: 700, color: '#ff2d55' }}>
              CONTAINMENT <span style={{ color: '#c8e6f5' }}>VERIFICATION</span>
            </div>
            <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#7ab3cc', letterSpacing: 1 }}>
              // POLICY-GOVERNED ACTIVE RESPONSE CONFIRMATION
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={loading}
            style={{
              background: 'none',
              border: 'none',
              color: '#3a6a88',
              fontSize: 18,
              cursor: 'pointer',
            }}
          >
            ✕
          </button>
        </div>

        {/* Backend Mode Pill */}
        <div
          style={{
            background: isMock ? 'rgba(0, 212, 255, 0.1)' : 'rgba(255, 45, 85, 0.1)',
            border: `1px solid ${isMock ? 'rgba(0, 212, 255, 0.3)' : 'rgba(255, 45, 85, 0.4)'}`,
            padding: '8px 12px',
            borderRadius: '2px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: isMock ? '#00d4ff' : '#ff2d55' }}>
            ● ENFORCEMENT ENGINE: {isMock ? 'SIMULATION / MOCK ADAPTER' : 'WINDOWS FIREWALL (HOST)'}
          </span>
          <span style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#7ab3cc' }}>
            {isMock ? 'Safe Dev Mode' : 'Live Host Rules'}
          </span>
        </div>

        {/* Target Details */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', background: 'rgba(8, 31, 53, 0.5)', padding: '12px', borderRadius: '2px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>TARGET ADDRESS:</span>
            <span style={{ fontSize: 14, color: '#00d4ff', fontFamily: 'Share Tech Mono,monospace', fontWeight: 'bold' }}>{target}</span>
          </div>
          {threatInfo?.attackType && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>DETECTED VECTOR:</span>
              <span style={{ fontSize: 12, color: '#c8e6f5' }}>{threatInfo.attackType} ({threatInfo.severity || 'UNKNOWN'})</span>
            </div>
          )}
          {threatInfo?.aiScore !== undefined && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>AI CONFIDENCE SCORE:</span>
              <span style={{ fontSize: 12, color: threatInfo.aiScore >= 0.9 ? '#ff2d55' : '#ffaa00', fontFamily: 'Share Tech Mono,monospace' }}>
                {Math.round(threatInfo.aiScore * 100)}%
              </span>
            </div>
          )}
        </div>

        {/* Options */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: 10, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>
              Containment Duration (TTL)
            </label>
            <select
              value={duration}
              onChange={(e) => setDuration(e.target.value)}
              disabled={loading}
              style={{
                background: '#081f35',
                border: '1px solid #0d3352',
                color: '#c8e6f5',
                fontFamily: 'Share Tech Mono,monospace',
                fontSize: 12,
                padding: '8px 10px',
                borderRadius: '2px',
                outline: 'none',
              }}
            >
              <option value="3600">1 Hour (Standard containment)</option>
              <option value="21600">6 Hours</option>
              <option value="86400">24 Hours (1 Day)</option>
              <option value="604800">7 Days</option>
              <option value="permanent">Permanent (Requires Admin Confirmation)</option>
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: 10, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>
              Operator Justification / Notes
            </label>
            <input
              type="text"
              placeholder="e.g. Confirmed scanner IP from threat telemetry"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={loading}
              style={{
                background: '#081f35',
                border: '1px solid #0d3352',
                color: '#c8e6f5',
                fontFamily: 'Rajdhani,sans-serif',
                fontSize: 13,
                padding: '8px 10px',
                borderRadius: '2px',
                outline: 'none',
              }}
            />
          </div>
        </div>

        {/* Policy Safety Warning */}
        <div style={{ fontSize: 11, color: '#7ab3cc', lineHeight: '1.4', background: 'rgba(13, 51, 82, 0.3)', padding: '8px 10px', borderRadius: '2px' }}>
          <strong style={{ color: '#00d4ff' }}>Safety Guarantee:</strong> Requests are checked against loopback, gateway, and service ports (5000, 8000, 27017, 3000) before any action is approved.
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '0.5rem' }}>
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            style={{
              background: 'transparent',
              border: '1px solid #0d3352',
              color: '#7ab3cc',
              fontFamily: 'Share Tech Mono,monospace',
              fontSize: 11,
              padding: '8px 16px',
              borderRadius: '2px',
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={loading}
            style={{
              background: '#ff2d55',
              border: '1px solid #ff2d55',
              color: '#fff',
              fontFamily: 'Rajdhani,sans-serif',
              fontWeight: 700,
              fontSize: 12,
              letterSpacing: '1px',
              textTransform: 'uppercase',
              padding: '8px 20px',
              borderRadius: '2px',
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: '0 0 10px rgba(255, 45, 85, 0.4)',
            }}
          >
            {loading ? 'Validating & Applying...' : 'Confirm Containment'}
          </button>
        </div>
      </div>
    </div>
  )
}
