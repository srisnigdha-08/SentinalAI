export default function KpiCard({ label, value, delta, color = '#00d4ff' }) {
  return (
    <div style={{
      background: '#081f35', border: '1px solid #0d3352', borderRadius: 2,
      padding: '1.25rem', position: 'relative', overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0, height: 2,
        background: color,
      }} />
      <div style={{
        fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88',
        letterSpacing: 2, textTransform: 'uppercase', marginBottom: '.5rem',
      }}>{label}</div>
      <div style={{
        fontFamily: 'Orbitron,sans-serif', fontSize: 28, fontWeight: 700,
        color, lineHeight: 1,
      }}>{value}</div>
      {delta && (
        <div style={{ fontSize: 12, color: '#3a6a88', marginTop: '.25rem' }}>{delta}</div>
      )}
    </div>
  )
}
