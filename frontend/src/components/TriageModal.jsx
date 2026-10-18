import React, { useState, useEffect } from 'react'
import { threatAPI } from '../services/api.js'
import toast from 'react-hot-toast'

const ALLOWED_STATUSES = [
  'DETECTED',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE',
]

export default function TriageModal({
  isOpen,
  threat,
  isReadOnly = false,
  onClose,
  onSuccess,
}) {
  const [status, setStatus] = useState('DETECTED')
  const [triageNotes, setTriageNotes] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (threat) {
      setStatus(threat.status || 'DETECTED')
      setTriageNotes(threat.triageNotes || '')
    }
  }, [threat])

  if (!isOpen || !threat) return null

  const handleSave = async () => {
    if (isReadOnly) return
    setLoading(true)
    try {
      const res = await threatAPI.triage(threat._id, {
        status,
        triageNotes,
      })
      toast.success('Threat triage updated successfully')
      if (onSuccess) {
        onSuccess(res.data?.data?.threat || { ...threat, status, triageNotes })
      }
      onClose()
    } catch (err) {
      toast.error(err.response?.data?.error || 'Failed to update threat triage')
    } finally {
      setLoading(false)
    }
  }

  const inputStyle = {
    background: '#081f35',
    border: '1px solid #0d3352',
    borderRadius: 2,
    padding: '8px 12px',
    color: '#c8e6f5',
    fontFamily: 'Share Tech Mono,monospace',
    fontSize: 12,
    outline: 'none',
    width: '100%',
  }

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
          border: '1px solid #00d4ff',
          boxShadow: '0 0 30px rgba(0, 212, 255, 0.2)',
          borderRadius: '4px',
          maxWidth: '560px',
          width: '100%',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(0,212,255,0.25)', paddingBottom: '0.75rem' }}>
          <div>
            <div style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 16, fontWeight: 700, color: '#00d4ff' }}>
              INCIDENT <span style={{ color: '#c8e6f5' }}>TRIAGE & NOTES</span>
            </div>
            <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#7ab3cc', letterSpacing: 1 }}>
              {isReadOnly ? '// READ-ONLY INCIDENT DOSSIER' : '// ANALYST INVESTIGATION & WORKFLOW DISPOSITION'}
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

        {/* Threat Context Card */}
        <div style={{
          background: 'rgba(8,31,53,0.6)',
          border: '1px solid #0d3352',
          borderRadius: '2px',
          padding: '10px 14px',
          display: 'grid',
          gridTemplateColumns: 'repeat(2, 1fr)',
          gap: '8px',
          fontFamily: 'Share Tech Mono,monospace',
          fontSize: 11,
        }}>
          <div>
            <span style={{ color: '#3a6a88' }}>TARGET / TYPE:</span>{' '}
            <span style={{ color: '#c8e6f5' }}>{threat.attackType}</span>
          </div>
          <div>
            <span style={{ color: '#3a6a88' }}>SOURCE IP:</span>{' '}
            <span style={{ color: '#00d4ff' }}>{threat.sourceIP}</span>
          </div>
          <div>
            <span style={{ color: '#3a6a88' }}>SEVERITY:</span>{' '}
            <span style={{ color: threat.severity === 'CRITICAL' ? '#ff2d55' : threat.severity === 'HIGH' ? '#ffaa00' : '#00d4ff' }}>
              {threat.severity}
            </span>
          </div>
          <div>
            <span style={{ color: '#3a6a88' }}>AI RISK SCORE:</span>{' '}
            <span style={{ color: '#00ff88' }}>{((threat.aiScore || 0) * 100).toFixed(0)}%</span>
          </div>
        </div>

        {/* Status Selection */}
        <div>
          <label style={{ display: 'block', fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#7ab3cc', marginBottom: 6 }}>
            INVESTIGATION DISPOSITION / STATUS:
          </label>
          {isReadOnly ? (
            <div style={{ ...inputStyle, background: 'rgba(8,31,53,0.3)', border: '1px dashed #0d3352', color: '#ffaa00' }}>
              {threat.status}
            </div>
          ) : (
            <select
              style={{ ...inputStyle, cursor: 'pointer' }}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              disabled={loading}
            >
              {ALLOWED_STATUSES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}
        </div>

        {/* Notes */}
        <div>
          <label style={{ display: 'block', fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#7ab3cc', marginBottom: 6 }}>
            ANALYST TRIAGE NOTES:
          </label>
          {isReadOnly ? (
            <div style={{
              ...inputStyle,
              minHeight: '90px',
              background: 'rgba(8,31,53,0.3)',
              border: '1px dashed #0d3352',
              whiteSpace: 'pre-wrap',
              color: threat.triageNotes ? '#c8e6f5' : '#4a6984',
            }}>
              {threat.triageNotes || 'No analyst notes recorded for this security event.'}
            </div>
          ) : (
            <textarea
              style={{ ...inputStyle, minHeight: '90px', resize: 'vertical' }}
              placeholder="Record forensic findings, containment justification, or false-positive notes..."
              value={triageNotes}
              onChange={(e) => setTriageNotes(e.target.value)}
              disabled={loading}
              maxLength={1000}
            />
          )}
        </div>

        {/* Footer Actions */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 4 }}>
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            style={{
              background: 'transparent',
              border: '1px solid #1a4a6e',
              color: '#7ab3cc',
              fontFamily: 'Rajdhani,sans-serif',
              fontWeight: 600,
              fontSize: 12,
              letterSpacing: 1,
              textTransform: 'uppercase',
              padding: '7px 16px',
              borderRadius: 2,
              cursor: 'pointer',
            }}
          >
            {isReadOnly ? 'Close' : 'Cancel'}
          </button>
          {!isReadOnly && (
            <button
              type="button"
              onClick={handleSave}
              disabled={loading}
              style={{
                background: 'rgba(0, 212, 255, 0.15)',
                border: '1px solid #00d4ff',
                color: '#00d4ff',
                fontFamily: 'Rajdhani,sans-serif',
                fontWeight: 600,
                fontSize: 12,
                letterSpacing: 1,
                textTransform: 'uppercase',
                padding: '7px 16px',
                borderRadius: 2,
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1,
              }}
            >
              {loading ? 'Updating...' : 'Save Triage'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
