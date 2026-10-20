import React, { useState, useEffect } from 'react'
import { threatAPI } from '../services/api.js'
import toast from 'react-hot-toast'
import Modal from './Modal.jsx'

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
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      dismissible={!loading}
      title="INCIDENT TRIAGE & NOTES"
      subtitle={isReadOnly ? '// READ-ONLY INCIDENT DOSSIER' : '// ANALYST INVESTIGATION & WORKFLOW DISPOSITION'}
      maxWidth="560px"
      borderColor="#00d4ff"
      glowColor="rgba(0, 212, 255, 0.2)"
      titleColor="#00d4ff"
    >
      {/* Target Details */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, background: 'rgba(8, 31, 53, 0.5)', padding: 12, borderRadius: 2 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>THREAT ID:</span>
          <span style={{ fontSize: 11, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace' }}>{threat._id}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>SOURCE IP:</span>
          <span style={{ fontSize: 13, color: '#00d4ff', fontFamily: 'Share Tech Mono,monospace', fontWeight: 'bold' }}>{threat.sourceIP}</span>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>ATTACK TYPE:</span>
          <span style={{ fontSize: 12, color: '#c8e6f5' }}>{threat.attackType} ({threat.severity || 'UNKNOWN'})</span>
        </div>
        {threat.aiScore !== undefined && (
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>AI CONFIDENCE SCORE:</span>
            <span style={{ fontSize: 12, color: threat.aiScore >= 0.9 ? '#ff2d55' : threat.aiScore >= 0.7 ? '#ffaa00' : '#00d4ff', fontFamily: 'Share Tech Mono,monospace' }}>
              {Math.round(threat.aiScore * 100)}%
            </span>
          </div>
        )}
        {threat.targetService && (
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 11, color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace' }}>TARGET SERVICE:</span>
            <span style={{ fontSize: 12, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace' }}>{threat.targetService}</span>
          </div>
        )}
      </div>

      {/* Threat Intel Dossier Summary */}
      {threat.threatIntel && (
        <div style={{ background: 'rgba(8, 31, 53, 0.3)', border: '1px solid #0d3352', padding: 10, borderRadius: 2 }}>
          <div style={{ fontSize: 10, fontFamily: 'Share Tech Mono,monospace', color: '#c39bd3', marginBottom: 4, letterSpacing: 0.5 }}>
            EXTERNAL THREAT INTEL (ABUSEIPDB)
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, fontSize: 11, fontFamily: 'Share Tech Mono,monospace' }}>
            <div>
              <span style={{ color: '#3a6a88' }}>Confidence: </span>
              <span style={{ color: threat.threatIntel.abuseConfidenceScore > 50 ? '#ff2d55' : '#00d4ff' }}>
                {threat.threatIntel.abuseConfidenceScore ?? 'N/A'}%
              </span>
            </div>
            <div>
              <span style={{ color: '#3a6a88' }}>Reports: </span>
              <span style={{ color: '#c8e6f5' }}>{threat.threatIntel.totalReports ?? 0}</span>
            </div>
            <div style={{ gridColumn: 'span 2' }}>
              <span style={{ color: '#3a6a88' }}>ISP: </span>
              <span style={{ color: '#7ab3cc' }}>{threat.threatIntel.isp || 'N/A'}</span>
            </div>
          </div>
        </div>
      )}

      {/* Form Controls */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label htmlFor="triage-status" style={{ fontSize: 10, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>
            Workflow Incident Status
          </label>
          {isReadOnly ? (
            <div style={{ ...inputStyle, background: '#041120', color: '#00d4ff' }}>
              {status}
            </div>
          ) : (
            <select
              id="triage-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              disabled={loading}
              style={{ ...inputStyle, cursor: 'pointer' }}
            >
              {ALLOWED_STATUSES.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <label htmlFor="triage-notes" style={{ fontSize: 10, color: '#7ab3cc', fontFamily: 'Share Tech Mono,monospace', textTransform: 'uppercase' }}>
            Analyst Investigation Notes & Dossier Annotations
          </label>
          {isReadOnly ? (
            <div style={{
              ...inputStyle,
              background: '#041120',
              minHeight: 80,
              whiteSpace: 'pre-wrap',
              color: triageNotes ? '#c8e6f5' : '#3a6a88'
            }}>
              {triageNotes || 'No investigation notes recorded for this incident.'}
            </div>
          ) : (
            <textarea
              id="triage-notes"
              rows={4}
              placeholder="Record forensic observations, escalation justifications, or false-positive disposition..."
              value={triageNotes}
              onChange={(e) => setTriageNotes(e.target.value)}
              disabled={loading}
              maxLength={1000}
              style={{ ...inputStyle, resize: 'vertical' }}
            />
          )}
        </div>
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
    </Modal>
  )
}
