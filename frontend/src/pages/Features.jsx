import Navbar from '../components/Navbar.jsx'

const FEATURES = [
  { icon:'🧠', title:'AI Anomaly Detection', accent:'#00d4ff', text:'XGBoost and Isolation Forest models trained on CICIDS2017 classify flow records served by a FastAPI microservice. Attacks of types never seen in training are largely missed (see the evaluation in the docs).' },
  { icon:'🍯', title:'Adaptive Honeypot', accent:'#ff2d55', text:'Cowrie SSH honeypot with a Q-learning agent that recommends the next decoy persona; a rotator script can switch the Cowrie persona between sessions.' },
  { icon:'⚡', title:'Policy-Governed Response', accent:'#00ff88', text:'Optional auto-blocking above a confidence threshold, plus analyst blocks, all checked against a containment policy. Enforcement runs through a pluggable adapter that is simulated (mock) by default.' },
  { icon:'📡', title:'Real-Time Monitoring', accent:'#ffaa00', text:'Socket.IO-powered live threat feed, dashboard updates and alert notifications pushed to analysts as events are processed.' },
  { icon:'🔐', title:'JWT Role-Based Auth', accent:'#8b5cf6', text:'Full RBAC system with Admin, Analyst, and Viewer roles. bcrypt-hashed credentials, refresh token rotation, and session management via MongoDB.' },
  { icon:'📊', title:'Threat Intelligence', accent:'#00d4ff', text:'IOC extraction from honeypot sessions, campaign correlation, MITRE ATT&CK mapping of attacker commands, and historical trend analytics.' },
  { icon:'🛡️', title:'Dual-Engine Ensemble', accent:'#ff2d55', text:'Fixed-weight combination of a supervised XGBoost classifier and an unsupervised Isolation Forest anomaly score.' },
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
