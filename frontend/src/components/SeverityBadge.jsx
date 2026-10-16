const SEV_STYLES = {
  CRITICAL: { background:'rgba(255,45,85,.2)',  color:'#ff2d55', border:'1px solid rgba(255,45,85,.4)' },
  HIGH:     { background:'rgba(255,100,0,.15)', color:'#ff6400', border:'1px solid rgba(255,100,0,.3)' },
  MEDIUM:   { background:'rgba(255,170,0,.12)', color:'#ffaa00', border:'1px solid rgba(255,170,0,.3)' },
  LOW:      { background:'rgba(0,212,255,.1)',  color:'#00d4ff', border:'1px solid rgba(0,212,255,.25)'},
}

export default function SeverityBadge({ sev }) {
  const s = SEV_STYLES[sev] || SEV_STYLES.LOW
  return (
    <span style={{
      ...s,
      fontFamily: 'Share Tech Mono,monospace', fontSize: 10,
      padding: '3px 8px', borderRadius: 1, letterSpacing: 1, fontWeight: 700,
    }}>{sev}</span>
  )
}
