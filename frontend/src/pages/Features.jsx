import Navbar from '../components/Navbar.jsx'

const FEATURES = [
  { icon:'🧠', title:'AI Anomaly Detection', accent:'#00d4ff', text:'Isolation Forest and Random Forest models trained on CICIDS2017 detect zero-day anomalies in real time with sub-second inference latency via FastAPI microservice.' },
  { icon:'🍯', title:'Adaptive Honeypot', accent:'#ff2d55', text:'Cowrie SSH honeypot with a reinforcement-learning lure engine that dynamically morphs its OS fingerprint and service banner to maximize attacker engagement.' },
  { icon:'⚡', title:'Autonomous Response', accent:'#00ff88', text:'Automatic IP blocking, session termination, and SOAR playbook execution — all gated by confidence thresholding to minimize false-positive-driven disruptions.' },
  { icon:'📡', title:'Real-Time Monitoring', accent:'#ffaa00', text:'Socket.IO-powered live threat feed, WebSocket dashboard updates, and instant alert notifications with sub-100ms latency from detection to analyst display.' },
  { icon:'🔐', title:'JWT Role-Based Auth', accent:'#8b5cf6', text:'Full RBAC system with Admin, Analyst, and Viewer roles. bcrypt-hashed credentials, refresh token rotation, and session management via MongoDB.' },
  { icon:'📊', title:'Threat Intelligence', accent:'#00d4ff', text:'IOC extraction, attack correlation, MITRE ATT&CK mapping, and historical trend analytics surfaced through a live SOC dashboard.' },
  { icon:'🛡️', title:'Dual-Engine Ensemble', accent:'#ff2d55', text:'Deterministic ensemble combining supervised Random Forest signature classification with unsupervised Isolation Forest anomaly scoring.' },
]

export default function Features() {
  return (
    <>
      <Navbar />
      <div style={{ paddingTop: 56, background: '#020b18', minHeight: '100vh' }}>
        <section style={{ padding: '5rem 3rem' }}>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#00d4ff', letterSpacing:3, marginBottom:'1rem' }}>
            // PLATFORM CAPABILITIES
          </div>
          <h2 style={{ fontFamily:'Orbitron,sans-serif', fontSize:'clamp(24px,4vw,40px)', fontWeight:700, marginBottom:'1rem' }}>
            Enterprise-Grade Defence Stack
          </h2>
          <p style={{ color:'#7ab3cc', maxWidth:560, lineHeight:1.7 }}>
            Every module is designed for real SOC deployments — from AI anomaly detection to adaptive honeypot deception.
          </p>

          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(280px,1fr))', gap:'1.5rem', marginTop:'3rem' }}>
            {FEATURES.map(f => (
              <div key={f.title} style={{
                background: '#081f35', border: '1px solid #0d3352', borderRadius: 2,
                padding: '2rem', position: 'relative', overflow: 'hidden',
                transition: 'border-color .2s, transform .2s', cursor: 'default',
              }}
                onMouseEnter={e => { e.currentTarget.style.transform='translateY(-2px)'; e.currentTarget.style.borderColor='#1a4a6e'; e.currentTarget.querySelector('.feat-bar').style.transform='scaleX(1)' }}
                onMouseLeave={e => { e.currentTarget.style.transform=''; e.currentTarget.style.borderColor='#0d3352'; e.currentTarget.querySelector('.feat-bar').style.transform='scaleX(0)' }}
              >
                <div className="feat-bar" style={{
                  position:'absolute', top:0, left:0, right:0, height:2,
                  background: f.accent, transform:'scaleX(0)', transformOrigin:'left', transition:'transform .3s',
                }} />
                <div style={{ fontSize:28, marginBottom:'1rem' }}>{f.icon}</div>
                <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:12, fontWeight:700, color:f.accent, letterSpacing:2, marginBottom:'.75rem' }}>
                  {f.title.toUpperCase()}
                </div>
                <p style={{ color:'#7ab3cc', fontSize:14, lineHeight:1.7 }}>{f.text}</p>
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  )
}
