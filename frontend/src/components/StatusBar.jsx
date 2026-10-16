import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useEffect, useState } from 'react'

export default function StatusBar({ threatCount = 0, activeHoneypots = 0, aiEngineStatus = 'Unknown', operational = false }) {
  const [clock, setClock] = useState('')

  useEffect(() => {
    const tick = () => {
      const now = new Date()
      const date = now.toLocaleDateString('en-IN', { timeZone: REPORT_TIME_ZONE, weekday:'short', year:'numeric', month:'short', day:'2-digit' })
      const time = now.toLocaleTimeString('en-IN', { timeZone: REPORT_TIME_ZONE, hour12: false })
      setClock(`${date}  ${time}  IST`)
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [])

  const dot = { width: 8, height: 8, borderRadius: '50%', background: operational ? '#00ff88' : '#ffaa00',
    animation: 'pulseDot 1.5s ease-in-out infinite' }
  const sep = <span style={{ color: '#1a4a6e', margin: '0 .5rem' }}>|</span>
  const mono = { fontFamily: 'Share Tech Mono,monospace', fontSize: 12, color: '#7ab3cc' }

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '1rem',
      padding: '10px 1rem', background: '#081f35',
      border: '1px solid #0d3352', borderRadius: 2, marginBottom: '1.5rem',
      flexWrap: 'wrap',
    }}>
      <div style={dot} />
      <span style={mono}>SENTINEL — <span style={{ color: operational ? '#00ff88' : '#ffaa00' }}>{operational ? 'Detection services connected' : 'Detection services unavailable or connecting'}</span></span>
      {sep}
      <span style={mono}>Honeypot: <span style={{ color: activeHoneypots > 0 ? '#00d4ff' : '#7ab3cc' }}>{activeHoneypots} active</span></span>
      {sep}
      <span style={mono}>AI Engine: <span style={{ color: aiEngineStatus === 'Running' || aiEngineStatus === 'connected' ? '#00d4ff' : '#ffaa00' }}>{aiEngineStatus}</span></span>
      {sep}
      <span style={mono}>Threats today: <span style={{ color: '#ff2d55' }}>{threatCount}</span></span>
      <div style={{ marginLeft: 'auto', fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88' }}>
        {clock}
      </div>
    </div>
  )
}
