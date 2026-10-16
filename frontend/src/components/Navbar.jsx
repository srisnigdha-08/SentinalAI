import { Link, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import toast from 'react-hot-toast'

export default function Navbar() {
  const { pathname } = useLocation()
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    const result = await logout()
    if (result.confirmed) toast.success('Server session revoked')
    else toast.error('Signed out locally; server logout could not be confirmed.')
    navigate('/')
  }

  const navLinks = [
    { to: '/',        label: 'Home'      },
    { to: '/about',   label: 'About'     },
    { to: '/features',label: 'Features'  },
    { to: '/dashboard',label:'Dashboard' },
  ]

  return (
    <nav className="sentinel-navbar" style={{
      position: 'fixed', top: 0, left: 0, right: 0, height: 56,
      background: 'rgba(4,17,32,0.96)', backdropFilter: 'blur(12px)',
      borderBottom: '1px solid #0d3352', display: 'flex', alignItems: 'center',
      zIndex: 1000,
    }}>
      {/* Logo */}
      <Link to="/" style={{ fontFamily: 'Orbitron,sans-serif', fontSize: 16, fontWeight: 700,
        color: '#00d4ff', letterSpacing: 3, textDecoration: 'none', whiteSpace: 'nowrap' }}>
        SENTINEL<span style={{ color: '#ff2d55' }}>AI</span>
      </Link>

      {/* Links */}
      <div className="sentinel-nav-links" style={{ display: 'flex', gap: '1.5rem', flex: 1, minWidth: 0, overflowX: 'auto', whiteSpace: 'nowrap' }}>
        {navLinks.map(l => (
          <Link key={l.to} to={l.to} style={{
            color: pathname === l.to ? '#00d4ff' : '#7ab3cc',
            fontFamily: 'Rajdhani,sans-serif', fontSize: 14, fontWeight: 500,
            letterSpacing: 1, textDecoration: 'none', textTransform: 'uppercase',
            borderBottom: pathname === l.to ? '1px solid #00d4ff' : '1px solid transparent',
            paddingBottom: 2, transition: 'color .2s',
          }}>
            {l.label}
          </Link>
        ))}
      </div>

      {/* Right side */}
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginLeft: 'auto', flexShrink: 0 }}>
        {user ? (
          <>
            <span className="sentinel-account-email" style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#3a6a88' }}>
              {user.email}
            </span>
            <button onClick={handleLogout} style={{
              background: 'transparent', border: '1px solid #ff2d55', color: '#ff2d55',
              fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 12,
              letterSpacing: 1, textTransform: 'uppercase', padding: '7px 18px',
              borderRadius: 2, cursor: 'pointer',
            }}>Logout</button>
          </>
        ) : (
          <>
            <Link to="/login" style={{
              background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc',
              fontFamily: 'Rajdhani,sans-serif', fontWeight: 600, fontSize: 12,
              letterSpacing: 1, textTransform: 'uppercase', padding: '7px 18px',
              borderRadius: 2, textDecoration: 'none', transition: 'all .2s',
            }}>Sign In</Link>
          </>
        )}
      </div>
    </nav>
  )
}
