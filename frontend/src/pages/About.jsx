import Navbar from '../components/Navbar.jsx'

const TECH = ['React.js','Node.js','Express.js','MongoDB','Python','Scikit-learn','Socket.IO','JWT','Cowrie','FastAPI','Tailwind CSS']

export default function About() {
  return (
    <>
      <Navbar />
      <div style={{ paddingTop: 56, background: '#020b18', minHeight: '100vh' }}>
        <div style={{ maxWidth: 900, margin: '0 auto', padding: '5rem 3rem 3rem' }}>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#00d4ff', letterSpacing:3, marginBottom:'1rem' }}>
            // ABOUT THE PROJECT
          </div>
          <h1 style={{ fontFamily:'Orbitron,sans-serif', fontSize:'clamp(24px,4vw,42px)', fontWeight:700, marginBottom:'1rem' }}>
            Built for the Next Generation<br/>of SOC Operations
          </h1>
          <p style={{ color:'#7ab3cc', lineHeight:1.8, maxWidth:700 }}>
            SentinelAI is a final-year engineering major project exploring the intersection of autonomous AI systems,
            adaptive cyber deception, and real-time threat response. It demonstrates how machine learning can be
            applied to enterprise cybersecurity at scale.
          </p>
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:'3rem', maxWidth:900, margin:'0 auto', padding:'0 3rem 5rem' }}>
          {[
            { title:'Research Focus', text:'This project investigates whether a reinforcement-learning-based honeypot system can improve attacker engagement time and threat intelligence quality compared to static honeypot deployments — using MITRE ATT&CK framework TTPs as behavioral ground truth.' },
            { title:'Academic Context', text:'Designed to IEEE final-year project standards. Evaluation uses detection rate, false positive rate, mean time to detect (MTTD), and honeypot engagement duration as primary metrics against the CICIDS2017 benchmark dataset.' },
            { title:'Key Contributions', text:'1. Adaptive honeypot deception engine using RL\n\n2. Dual-engine ML threat classifier (CICIDS2017)\n\n3. Autonomous response pipeline with confidence thresholding\n\n4. Real-time SOC dashboard with live attack visualization' },
          ].map(({ title, text }) => (
            <div key={title}>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:12, fontWeight:700, color:'#00d4ff', letterSpacing:3, marginBottom:'1rem' }}>
                {title.toUpperCase()}
              </div>
              <p style={{ color:'#7ab3cc', lineHeight:1.8, whiteSpace:'pre-line' }}>{text}</p>
            </div>
          ))}

          <div>
            <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:12, fontWeight:700, color:'#00d4ff', letterSpacing:3, marginBottom:'1rem' }}>
              TECHNOLOGY STACK
            </div>
            <div style={{ display:'flex', flexWrap:'wrap', gap:8 }}>
              {TECH.map(t => (
                <span key={t} style={{
                  fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#00d4ff',
                  border:'1px solid #1a4a6e', padding:'4px 12px', letterSpacing:1,
                }}>{t}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
