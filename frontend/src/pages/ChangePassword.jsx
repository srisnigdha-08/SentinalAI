import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import Navbar from '../components/Navbar.jsx'
import toast from 'react-hot-toast'

export default function ChangePassword() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState(null)
  const { user, updatePassword, logout } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    if (e) e.preventDefault()
    setFormError(null)

    if (!currentPassword) {
      const msg = 'Current password is required'
      setFormError(msg)
      toast.error(msg)
      return
    }
    if (!newPassword || newPassword.length < 8) {
      const msg = 'New password must be at least 8 characters long'
      setFormError(msg)
      toast.error(msg)
      return
    }
    if (newPassword.length > 128) {
      const msg = 'New password must not exceed 128 characters'
      setFormError(msg)
      toast.error(msg)
      return
    }
    if (newPassword !== confirmPassword) {
      const msg = 'New passwords do not match'
      setFormError(msg)
      toast.error(msg)
      return
    }
    if (currentPassword === newPassword) {
      const msg = 'New password must be different from current password'
      setFormError(msg)
      toast.error(msg)
      return
    }

    setLoading(true)
    try {
      await updatePassword({ currentPassword, newPassword })
      toast.success('Password updated successfully')
      navigate('/dashboard')
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to update password'
      setFormError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = async () => {
    try {
      await logout()
      navigate('/login')
    } catch {
      navigate('/login')
    }
  }

  const inputStyle = {
    width: '100%',
    background: '#041120',
    border: '1px solid #0d3352',
    borderRadius: 2,
    padding: '10px 14px',
    color: '#c8e6f5',
    fontFamily: 'Share Tech Mono, monospace',
    fontSize: 13,
    outline: 'none',
  }

  const labelStyle = {
    fontFamily: 'Share Tech Mono, monospace',
    fontSize: 11,
    color: '#7ab3cc',
    letterSpacing: 2,
    textTransform: 'uppercase',
    display: 'block',
    marginBottom: 8,
  }

  return (
    <>
      <Navbar />
      <div
        style={{
          minHeight: 'calc(100vh - 56px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '3rem 1rem',
          paddingTop: 'calc(56px + 3rem)',
          background: '#020b18',
        }}
      >
        <div
          style={{
            background: '#081f35',
            border: '1px solid #0d3352',
            borderRadius: 2,
            padding: '3rem',
            width: '100%',
            maxWidth: 440,
            position: 'relative',
          }}
        >
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 2,
              background: 'linear-gradient(90deg, transparent, #ffaa00, transparent)',
            }}
          />
          <div
            style={{
              fontFamily: 'Orbitron, sans-serif',
              fontSize: 18,
              fontWeight: 700,
              color: '#ffaa00',
              letterSpacing: 2,
              marginBottom: '.5rem',
            }}
          >
            PASSWORD CHANGE REQUIRED
          </div>
          <div
            style={{
              fontFamily: 'Share Tech Mono, monospace',
              fontSize: 12,
              color: '#7ab3cc',
              marginBottom: '1.5rem',
            }}
          >
            // Operator {user?.name || user?.email}: Your initial credential must be updated before accessing platform features.
          </div>

          {formError && (
            <div
              role="alert"
              style={{
                background: 'rgba(255, 45, 85, 0.1)',
                border: '1px solid #ff2d55',
                color: '#ff2d55',
                padding: '8px 12px',
                borderRadius: 2,
                fontFamily: 'Share Tech Mono, monospace',
                fontSize: 12,
                marginBottom: '1.5rem',
              }}
            >
              {formError}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1.25rem' }}>
              <label htmlFor="current-password" style={labelStyle}>
                Current Password
              </label>
              <input
                id="current-password"
                name="currentPassword"
                type="password"
                autoComplete="current-password"
                required
                placeholder="••••••••••••"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                style={inputStyle}
                onFocus={(e) => (e.target.style.borderColor = '#00d4ff')}
                onBlur={(e) => (e.target.style.borderColor = '#0d3352')}
              />
            </div>

            <div style={{ marginBottom: '1.25rem' }}>
              <label htmlFor="new-password" style={labelStyle}>
                New Password
              </label>
              <input
                id="new-password"
                name="newPassword"
                type="password"
                autoComplete="new-password"
                required
                minLength={8}
                maxLength={128}
                placeholder="Minimum 8 characters"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                style={inputStyle}
                onFocus={(e) => (e.target.style.borderColor = '#00d4ff')}
                onBlur={(e) => (e.target.style.borderColor = '#0d3352')}
              />
            </div>

            <div style={{ marginBottom: '1.75rem' }}>
              <label htmlFor="confirm-password" style={labelStyle}>
                Confirm New Password
              </label>
              <input
                id="confirm-password"
                name="confirmPassword"
                type="password"
                autoComplete="new-password"
                required
                minLength={8}
                maxLength={128}
                placeholder="Re-enter new password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                style={inputStyle}
                onFocus={(e) => (e.target.style.borderColor = '#00d4ff')}
                onBlur={(e) => (e.target.style.borderColor = '#0d3352')}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                padding: 12,
                background: loading ? '#cc8800' : '#ffaa00',
                border: '1px solid #ffaa00',
                color: '#000',
                fontFamily: 'Rajdhani, sans-serif',
                fontWeight: 700,
                fontSize: 14,
                letterSpacing: 2,
                textTransform: 'uppercase',
                borderRadius: 2,
                cursor: loading ? 'not-allowed' : 'pointer',
                marginBottom: '1rem',
              }}
            >
              {loading ? 'UPDATING CREDENTIALS...' : 'UPDATE PASSWORD →'}
            </button>
          </form>

          <div style={{ textAlign: 'center' }}>
            <button
              type="button"
              onClick={handleLogout}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#3a6a88',
                fontFamily: 'Share Tech Mono, monospace',
                fontSize: 12,
                cursor: 'pointer',
                textDecoration: 'underline',
              }}
            >
              Cancel & Sign Out
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
