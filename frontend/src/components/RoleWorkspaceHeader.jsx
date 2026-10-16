import { useAuth } from '../hooks/useAuth.js'

const ROLE_CONFIGS = {
  admin: {
    title: 'CONTROL WORKSPACE // ROOT OPERATOR',
    subtitle: 'Full Administrative Authority',
    badge: 'ADMIN PRIVILEGES',
    badgeColor: '#8b5cf6',
    borderColor: 'rgba(139, 92, 246, 0.35)',
    glowColor: 'rgba(139, 92, 246, 0.08)',
    indicator: '● ADMIN PERMISSIONS',
  },
  analyst: {
    title: 'DEFENSE WORKSPACE // TACTICAL TRIAGE',
    subtitle: 'Incident Containment & Investigation',
    badge: 'TACTICAL OPERATOR',
    badgeColor: '#00d4ff',
    borderColor: 'rgba(0, 212, 255, 0.35)',
    glowColor: 'rgba(0, 212, 255, 0.08)',
    indicator: '● ANALYST PERMISSIONS',
  },
  viewer: {
    title: 'OBSERVATION WORKSPACE // READ-ONLY TELEMETRY',
    subtitle: 'Security Monitoring Mode',
    badge: 'AUDIT / TELEMETRY',
    badgeColor: '#7ab3cc',
    borderColor: 'rgba(122, 179, 204, 0.25)',
    glowColor: 'rgba(122, 179, 204, 0.05)',
    indicator: '○ READ ONLY',
  },
}

export default function RoleWorkspaceHeader() {
  const { user } = useAuth()
  const role = user?.role || 'viewer'
  const config = ROLE_CONFIGS[role] || ROLE_CONFIGS.viewer

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '10px 16px',
        marginBottom: '1.25rem',
        background: `linear-gradient(90deg, #041120 0%, ${config.glowColor} 100%)`,
        border: `1px solid ${config.borderColor}`,
        borderRadius: 2,
        boxShadow: `0 2px 12px rgba(0,0,0,0.35)`,
        flexWrap: 'wrap',
        minWidth: 0,
        overflowWrap: 'anywhere',
        gap: '12px',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div
          style={{
            width: 8,
            height: 28,
            background: config.badgeColor,
            borderRadius: 1,
            boxShadow: `0 0 10px ${config.badgeColor}`,
          }}
        />
        <div>
          <div
            style={{
              fontFamily: 'Orbitron, sans-serif',
              fontSize: 13,
              fontWeight: 700,
              color: '#c8e6f5',
              letterSpacing: 2,
            }}
          >
            {config.title}
          </div>
          <div
            style={{
              fontFamily: 'Rajdhani, sans-serif',
              fontSize: 12,
              fontWeight: 600,
              color: '#7ab3cc',
              letterSpacing: 0.5,
              marginTop: 1,
            }}
          >
            {config.subtitle}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span
          style={{
            fontFamily: 'Share Tech Mono, monospace',
            fontSize: 11,
            color: config.badgeColor,
            border: `1px solid ${config.borderColor}`,
            background: 'rgba(4, 17, 32, 0.8)',
            padding: '4px 10px',
            borderRadius: 2,
            letterSpacing: 1,
          }}
        >
          {config.indicator}
        </span>
        <span
          style={{
            fontFamily: 'Share Tech Mono, monospace',
            fontSize: 10,
            color: '#3a6a88',
            letterSpacing: 1,
          }}
        >
          {user?.email || 'authenticated'}
        </span>
      </div>
    </div>
  )
}
