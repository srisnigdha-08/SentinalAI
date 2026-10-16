export default function Panel({ title, badge, badgeType = 'live', children, style = {} }) {
  const badgeColors = {
    live:  { bg: 'rgba(255,45,85,.15)',   color: '#ff2d55', border: 'rgba(255,45,85,.3)'   },
    ok:    { bg: 'rgba(0,255,136,.1)',    color: '#00ff88', border: 'rgba(0,255,136,.3)'   },
    warn:  { bg: 'rgba(255,170,0,.1)',    color: '#ffaa00', border: 'rgba(255,170,0,.3)'   },
    info:  { bg: 'rgba(0,212,255,.1)',    color: '#00d4ff', border: 'rgba(0,212,255,.25)'  },
  }
  const bc = badgeColors[badgeType] || badgeColors.live

  return (
    <div data-sentinel-panel style={{
      background: '#081f35', border: '1px solid #0d3352', borderRadius: 2,
      padding: '1.25rem', minWidth: 0, overflowWrap: 'anywhere', ...style,
    }}>
      {(title || badge) && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, marginBottom: '1rem' }}>
          {title && (
            <div style={{
              fontFamily: 'Orbitron,sans-serif', fontSize: 12, fontWeight: 700,
              color: '#7ab3cc', letterSpacing: 2, textTransform: 'uppercase',
            }}>{title}</div>
          )}
          {badge && (
            <div style={{
              fontFamily: 'Share Tech Mono,monospace', fontSize: 10,
              padding: '3px 8px', borderRadius: 1, letterSpacing: 1,
              background: bc.bg, color: bc.color, border: `1px solid ${bc.border}`,
            }}>{badge}</div>
          )}
        </div>
      )}
      {children}
    </div>
  )
}
