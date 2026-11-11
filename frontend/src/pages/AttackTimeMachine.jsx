import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import SessionSelector, { btn } from '../components/attackTimeline/SessionSelector.jsx'
import SessionReplay from '../components/attackTimeline/SessionReplay.jsx'
import { honeypotAPI } from '../services/api.js'
import { useSocket } from '../hooks/useSocket.js'

const OBJECT_ID = /^[a-f0-9]{24}$/i
const LIVE_RELOAD_MS = 1500

// Attack Time Machine: forensic replay of one recorded honeypot session. Read-only: the only requests are GETs.
export default function AttackTimeMachine() {
  const [params, setParams] = useSearchParams()
  const sessionParam = params.get('session') || ''
  const selected = OBJECT_ID.test(sessionParam) ? sessionParam : null
  const [evidence, setEvidence] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const { connected, on } = useSocket()
  const reloadTimer = useRef(null)

  // Only the latest request may update the page, so a slow response for a previous session is discarded.
  const requestRef = useRef(0)
  const load = useCallback((id, { quiet = false } = {}) => {
    const req = ++requestRef.current
    if (!quiet) { setLoading(true); setError(null) }
    return honeypotAPI.timeline(id)
      .then((r) => { if (req === requestRef.current) { setEvidence(r.data?.data || null); setError(null) } })
      .catch((err) => {
        if (quiet || req !== requestRef.current) return
        setEvidence(null)
        setError(err?.response?.status === 404 ? 'This session was not found.' : 'The session timeline could not be loaded.')
      })
      .finally(() => { if (!quiet && req === requestRef.current) setLoading(false) })
  }, [])

  useEffect(() => {
    setEvidence(null)
    setError(null)
    if (!selected) { requestRef.current++; setLoading(false); return }
    load(selected)
  }, [selected, load])

  // Live sessions: refetch (through the same RBAC-filtered API) when this session records a command or closes.
  const sessionId = evidence?.session?.sessionId
  const isLive = evidence?.session?.status === 'active'
  useEffect(() => {
    if (!connected || !selected || !isLive || !sessionId) return undefined
    const schedule = (payload) => {
      if (payload?.sessionId !== sessionId || reloadTimer.current) return
      reloadTimer.current = setTimeout(() => { reloadTimer.current = null; load(selected, { quiet: true }) }, LIVE_RELOAD_MS)
    }
    const offCmd = on('honeypot_command', schedule)
    const offClose = on('honeypot_session_closed', schedule)
    return () => { offCmd?.(); offClose?.(); clearTimeout(reloadTimer.current); reloadTimer.current = null }
  }, [connected, selected, isLive, sessionId, on, load])

  const open = (id) => {
    const next = new URLSearchParams(params)
    next.set('session', id)
    setParams(next)
  }
  const back = () => {
    const next = new URLSearchParams(params)
    next.delete('session')
    setParams(next)
  }

  return (
    <DashboardLayout>
      <div style={{ marginBottom: '1.25rem' }}>
        <h1 style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 18, fontWeight: 700, margin: 0 }}>
          Attack <span style={{ color: '#00d4ff' }}>Time Machine</span>
        </h1>
        <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88', marginTop: 6, lineHeight: 1.6 }}>
          Replay a recorded honeypot session as an ordered investigation timeline. Playback animates stored evidence only; it
          never executes commands, contacts the attacker, or triggers containment.
        </div>
      </div>

      {!selected ? (
        <SessionSelector params={params} setParams={setParams} onOpen={open} />
      ) : loading ? (
        <div role="status" style={{ color: '#3a6a88', fontFamily: 'Share Tech Mono,monospace', fontSize: 12 }}>Loading recorded evidence…</div>
      ) : error ? (
        <div role="alert" style={{ color: '#ff2d55', fontFamily: 'Share Tech Mono,monospace', fontSize: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          {error}
          <button type="button" style={btn} onClick={() => load(selected)}>Retry</button>
          <button type="button" style={btn} onClick={back}>← Session list</button>
        </div>
      ) : evidence ? (
        <SessionReplay key={selected} evidence={evidence} onBack={back} live={isLive} />
      ) : null}
    </DashboardLayout>
  )
}
