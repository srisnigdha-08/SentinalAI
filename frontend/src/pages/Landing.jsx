import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Navbar from '../components/Navbar.jsx'
import { threatAPI, honeypotAPI, aiAPI } from '../services/api.js'

function animateCounter(el, target, suffix = '') {
  if (!el) return
  if (target === 0) {
    el.textContent = '0' + suffix
    return
  }
  let v = 0; const step = Math.max(target / 60, 1)
  const t = setInterval(() => {
    v = Math.min(v + step, target)
    el.textContent = Math.round(v).toLocaleString() + suffix
    if (v >= target) clearInterval(t)
  }, 24)
}

export default function Landing() {
  const navigate = useNavigate()
  const cnt1 = useRef(); const cnt2 = useRef(); const cnt3 = useRef(); const cnt4 = useRef()

  useEffect(() => {
    let isMounted = true
    Promise.all([
      threatAPI.analytics().catch(() => null),
      honeypotAPI.analytics().catch(() => null),
      aiAPI.stats().catch(() => null),
      aiAPI.modelInfo().catch(() => null),
    ]).then(([tRes, hRes, aRes, mRes]) => {
      if (!isMounted) return
      const kpis = tRes?.data?.data?.kpis || {}
      const hpKpis = hRes?.data?.data?.kpis || {}
      const aiSummary = aRes?.data?.data?.summary || {}
      const modelInfo = mRes?.data?.data || mRes?.data || {}

      // REAL DATA SOURCE: actual counters from the SentinelAI pipeline
      // If 0, counters display 0.
      const realBlocked = kpis.blockedCount || 0
      const realAnalyzed = kpis.totalAllTime || 0
      const realHoneypot = hpKpis.totalToday || 0
      
      let realAccuracy = 0
      if (aiSummary.verifiedAccuracy) {
        realAccuracy = Math.round(aiSummary.verifiedAccuracy)
      } else if (modelInfo.rfMetrics?.accuracy) {
        realAccuracy = Math.round(modelInfo.rfMetrics.accuracy * 100)
      }

      // ======================================================================
      // PRESERVED SIMULATION VALUES (previously hardcoded for demo):
      // animateCounter(cnt1.current, 2341)
      // animateCounter(cnt2.current, 14823)
      // animateCounter(cnt3.current, 312)
      // animateCounter(cnt4.current, 94, '%')
      // ======================================================================

      animateCounter(cnt1.current, realBlocked)
      animateCounter(cnt2.current, realAnalyzed)
      animateCounter(cnt3.current, realHoneypot)
      animateCounter(cnt4.current, realAccuracy, '%')
    })
    return () => { isMounted = false }
  }, [])

  return (
    <>
      <Navbar />
      <div style={{ paddingTop: 56, minHeight: '100vh', background: '#020b18', position: 'relative', overflow: 'hidden' }}>

        {/* Grid background */}
        <div style={{
          position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
          backgroundImage: 'linear-gradient(#0d3352 1px,transparent 1px),linear-gradient(90deg,#0d3352 1px,transparent 1px)',
          backgroundSize: '60px 60px', opacity: .3, animation: 'gridPulse 4s ease-in-out infinite',
          pointerEvents: 'none',
        }} />

        {/* Pulse rings */}
        {[600,800,1000].map((size,i) => (
          <div key={size} style={{
            position: 'absolute', top: '50%', left: '50%',
            width: size, height: size, borderRadius: '50%',
            border: '1px solid #00d4ff', opacity: .05,
            transform: 'translate(-50%,-50%)',
            animation: `ringExpand 3s ${i*0.5}s ease-in-out infinite`,
            pointerEvents: 'none',
          }} />
        ))}

        {/* Hero */}
        <section style={{
          minHeight: 'calc(100vh - 56px)', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', position: 'relative',
          padding: '4rem 2rem', textAlign: 'center',
        }}>
          <div style={{
            fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#00d4ff',
            border: '1px solid #1a4a6e', padding: '6px 16px', letterSpacing: 3,
            marginBottom: '2rem', animation: 'fadeUp .6s ease both',
          }}>
            // AUTONOMOUS CYBER DEFENCE PLATFORM v2.4.1
          </div>

          <h1 style={{
            fontFamily: 'Orbitron,sans-serif', fontSize: 'clamp(36px,6vw,80px)',
            fontWeight: 900, lineHeight: 1.05, marginBottom: '1.5rem',
            animation: 'fadeUp .6s .15s ease both',
          }}>
            <span style={{ display: 'block', color: '#c8e6f5' }}>SELF-EVOLVING AI</span>
            <span style={{ display: 'block', color: '#00d4ff', textShadow: '0 0 40px rgba(0,212,255,.4)' }}>
              SENTINEL DEFENCE
            </span>
          </h1>

          <p style={{
            fontSize: 17, color: '#7ab3cc', maxWidth: 600, lineHeight: 1.7,
            marginBottom: '3rem', animation: 'fadeUp .6s .3s ease both',
          }}>
            Next-generation autonomous threat detection, adaptive honeypot intelligence,
            and real-time incident response — powered by continuous machine learning.
          </p>

          <div style={{ display: 'flex', gap: 16, justifyContent: 'center', animation: 'fadeUp .6s .45s ease both' }}>
            <button onClick={() => navigate('/dashboard')} style={{
              background: '#00d4ff', border: '1px solid #00d4ff', color: '#000',
              fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 14,
              letterSpacing: 2, textTransform: 'uppercase', padding: '14px 36px',
              borderRadius: 2, cursor: 'pointer',
            }}>Launch SOC Console →</button>
            <button onClick={() => navigate('/features')} style={{
              background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc',
              fontFamily: 'Rajdhani,sans-serif', fontWeight: 600, fontSize: 14,
              letterSpacing: 2, textTransform: 'uppercase', padding: '14px 36px',
              borderRadius: 2, cursor: 'pointer',
            }}>Explore Features</button>
          </div>

          {/* Counters */}
          <div style={{
            display: 'flex', gap: '3rem', marginTop: '5rem',
            animation: 'fadeUp .6s .6s ease both',
          }}>
            {[
              { ref: cnt1, label: 'Threats Blocked' },
              { ref: cnt2, label: 'Attacks Analyzed' },
              { ref: cnt3, label: 'Honeypot Sessions' },
              { ref: cnt4, label: 'AI Accuracy' },
            ].map(({ ref, label }) => (
              <div key={label} style={{ textAlign: 'center' }}>
                <div ref={ref} style={{
                  fontFamily: 'Orbitron,sans-serif', fontSize: 32, fontWeight: 700, color: '#00d4ff',
                }}>0</div>
                <div style={{
                  fontSize: 12, color: '#3a6a88', letterSpacing: 2,
                  textTransform: 'uppercase', marginTop: 4,
                }}>{label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Terminal preview */}
        <section style={{ padding: '0 3rem 5rem', maxWidth: 900, margin: '0 auto' }}>
          <div style={{
            background: '#000', border: '1px solid #0d3352', borderRadius: 2,
            padding: '1rem', fontFamily: 'Share Tech Mono,monospace', fontSize: 12,
          }}>
            {/*
              PRESERVED SIMULATED TERMINAL OUTPUT (for demo mode):
              ['warn',   '[00:00:07] ⚠ High-risk IP detected: 185.220.101.47 — SSH brute force pattern'],
              ['err',    '[00:00:08] ALERT: Honeypot session opened from 45.95.147.22'],
              ['out',    '[00:00:09] Autonomous response: IP 45.95.147.22 flagged for isolation'],
              ['info',   '[00:00:10] All systems nominal. Monitoring 847 endpoints.'],
            */}
            {[
              ['prompt', 'sentinel@soc:~$ ./start-defence.sh --real-mode'],
              ['out',    '[00:00:01] Initializing SentinelAI v2.4.1 [REAL MODE]...'],
              ['out',    '[00:00:02] Loading threat intelligence models... ✓'],
              ['out',    '[00:00:03] Connecting to honeypot network... ✓'],
              ['out',    '[00:00:04] Anomaly detection engine started [Isolation Forest + Random Forest]'],
              ['out',    '[00:00:05] WebSocket server listening on :5000 (real-time stream ready)'],
              ['out',    '[00:00:06] MongoDB connected: sentinel-db'],
              ['info',   '[00:00:07] Simulation mode disabled. Pipeline listening for live packet & honeypot events...'],
              ['info',   '[00:00:08] Defense shield online. All real telemetry monitoring active.'],
            ].map(([type, text], i) => (
              <div key={i} style={{
                color: type==='prompt'?'#c8e6f5':type==='warn'?'#ffaa00':type==='err'?'#ff2d55':type==='info'?'#00d4ff':'#7ab3cc',
                marginBottom: 2,
              }}>{text}</div>
            ))}
          </div>
        </section>
      </div>
    </>
  )
}
