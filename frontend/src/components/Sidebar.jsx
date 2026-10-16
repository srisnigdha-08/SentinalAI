import { NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import { useRealTimeAlerts } from '../hooks/useRealTimeAlerts.js'
import toast from 'react-hot-toast'

export default function Sidebar() {
  const { user, logout, logoutAll } = useAuth()
  const { unreadCount } = useRealTimeAlerts()
  const navigate = useNavigate()

  // Real-time navigation items — badge reflects actual unread critical alerts
  // OLD CODE PRESERVED: { to: '/dashboard', icon: '⬛', label: 'Dashboard', badge: 3 }
  const NAV = [
    { section: 'Overview', items: [
      { to: '/dashboard',          icon: '⬛', label: 'Dashboard',    badge: unreadCount > 0 ? unreadCount : null },
      { to: '/dashboard/threats',  icon: '⚠',  label: 'Threat Logs'           },
      { to: '/dashboard/honeypot', icon: '🍯', label: 'Honeypot'              },
      { to: '/dashboard/campaigns',icon: '🕸', label: 'Campaigns'             },
      { to: '/dashboard/ai',       icon: '🧠', label: 'AI Analytics'          },
    ]},
    { section: 'Management', items: [
      { to: '/dashboard/users',    icon: '👤', label: 'Users',    roles: ['admin'] },
      { to: '/settings',           icon: '⚙',  label: 'Settings', roles: ['admin'] },
    ]},
  ]

  const userRole = user?.role || 'viewer'

  const getSectionTitle = (sectionKey) => {
    if (sectionKey === 'Overview') {
      if (userRole === 'analyst') return 'SOC OPERATIONS'
      if (userRole === 'viewer') return 'SECURITY MONITORING'
      return 'OVERVIEW'
    }
    return sectionKey.toUpperCase()
  }

  const roleIndicator = {
    analyst: 'TACTICAL DEFENSE',
    viewer: 'READ-ONLY OBSERVATION',
  }[userRole]

  const roleBadgeText = {
    admin: 'ADMIN // CONTROL',
    analyst: 'ANALYST // DEFEND',
    viewer: 'VIEWER // OBSERVE',
  }[userRole] || `${userRole.toUpperCase()} // UNVERIFIED`

  const filteredNav = NAV.map(group => ({
    ...group,
    items: group.items.filter(item => !item.roles || item.roles.includes(userRole)),
  })).filter(group => group.items.length > 0)

  const handleLogout = async (all = false) => {
    const result = await (all ? logoutAll() : logout())
    if (result.confirmed) toast.success(all ? 'All server sessions revoked' : 'Server session revoked')
    else toast.error(all ? 'Signed out locally; logout of all sessions could not be confirmed.' : 'Signed out locally; server logout could not be confirmed.')
    navigate('/')
  }

  return (
    <aside className="sentinel-sidebar" style={{
      background: '#041120', borderRight: '1px solid #0d3352',
      flexShrink: 0, display: 'flex', flexDirection: 'column',
      padding: '1.5rem 0',
    }}>
      {filteredNav.map(group => (
        <div key={group.section} style={{ marginBottom: '1.5rem' }}>
          <div style={{
            fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88',
            letterSpacing: 2, padding: '0 1.25rem', marginBottom: '.75rem',
          }}>
            <div>{getSectionTitle(group.section)}</div>
            {roleIndicator && group.section === 'Overview' && (
              <div style={{
                fontFamily: 'Share Tech Mono,monospace',
                fontSize: 9,
                color: userRole === 'analyst' ? '#00d4ff' : '#7ab3cc',
                letterSpacing: 1,
                marginTop: 3,
              }}>
                [{roleIndicator}]
              </div>
            )}
          </div>
          {group.items.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/dashboard'}
              style={({ isActive }) => ({
                display: 'flex', alignItems: 'center', gap: 12,
                padding: '10px 1.25rem',
                color: isActive ? '#00d4ff' : '#7ab3cc',
                fontFamily: 'Rajdhani,sans-serif', fontSize: 14, fontWeight: 500,
                textDecoration: 'none',
                background: isActive ? 'rgba(0,212,255,.08)' : 'transparent',
                borderLeft: isActive ? '2px solid #00d4ff' : '2px solid transparent',
                transition: 'all .15s',
              })}
            >
              <span style={{ width: 18, textAlign: 'center', fontSize: 15 }}>{item.icon}</span>
              {item.label}
              {item.badge && (
                <span style={{
                  marginLeft: 'auto', background: '#ff2d55', color: '#fff',
                  fontSize: 10, fontFamily: 'Share Tech Mono,monospace',
                  padding: '2px 6px', borderRadius: 2, minWidth: 20, textAlign: 'center',
                }}>{item.badge}</span>
              )}
            </NavLink>
          ))}
        </div>
      ))}

      {/* User footer */}
      <div style={{
        marginTop: 'auto', padding: '1.25rem',
        borderTop: '1px solid #0d3352',
      }}>
        <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88', marginBottom: 4 }}>
          LOGGED IN AS
        </div>
        <div style={{ fontSize: 13, color: '#00d4ff', fontWeight: 600 }}>{user?.email}</div>
        <div style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88', marginTop: 3 }}>
          ROLE: <span style={{
            color: userRole === 'admin' ? '#8b5cf6' : userRole === 'analyst' ? '#00d4ff' : '#7ab3cc',
            fontWeight: 700,
          }}>{roleBadgeText}</span>
        </div>
        <button onClick={() => handleLogout()} style={{
          marginTop: 12, width: '100%', background: 'transparent',
          border: '1px solid #1a4a6e', color: '#7ab3cc',
          fontFamily: 'Rajdhani,sans-serif', fontWeight: 600, fontSize: 10,
          letterSpacing: 1, textTransform: 'uppercase', padding: '6px 12px',
          borderRadius: 2, cursor: 'pointer',
        }}>LOGOUT</button>
        <button onClick={() => handleLogout(true)} style={{
          marginTop: 6, width: '100%', background: 'transparent',
          border: '1px solid #1a4a6e', color: '#7ab3cc',
          fontFamily: 'Rajdhani,sans-serif', fontWeight: 600, fontSize: 10,
          letterSpacing: 1, textTransform: 'uppercase', padding: '6px 12px',
          borderRadius: 2, cursor: 'pointer',
        }}>LOGOUT ALL SESSIONS</button>
      </div>
    </aside>
  )
}
