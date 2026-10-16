import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import Navbar from '../components/Navbar.jsx'
import toast from 'react-hot-toast'

export default function Login() {
  const [email, setEmail]     = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const { login, error: sessionError } = useAuth()
  const navigate  = useNavigate()

  const handleSubmit = async () => {
    if (!email || !password) { toast.error('Enter credentials'); return }
    setLoading(true)
    try {
      const res  = await login({ email, password })
      const { user } = res.data
      toast.success(`Welcome back, ${user.name}`)
      if (user.mustChangePassword) {
        navigate('/change-password')
      } else {
        navigate('/dashboard')
      }
    } catch (err) {
      toast.error(err.response?.data?.error || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const input = {
    width:'100%', background:'#041120', border:'1px solid #0d3352',
    borderRadius:2, padding:'10px 14px', color:'#c8e6f5',
    fontFamily:'Share Tech Mono,monospace', fontSize:13, outline:'none',
  }
  const label = {
    fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#7ab3cc',
    letterSpacing:2, textTransform:'uppercase', display:'block', marginBottom:8,
  }

  return (
    <>
      <Navbar />
      <div style={{ minHeight:'calc(100vh - 56px)', display:'flex', alignItems:'center',
        justifyContent:'center', padding:'3rem 1rem', paddingTop:'calc(56px + 3rem)', background:'#020b18' }}>
        <div style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2,
          padding:'3rem', width:'100%', maxWidth:420, position:'relative' }}>
          <div style={{ position:'absolute', top:0, left:0, right:0, height:2,
            background:'linear-gradient(90deg,transparent,#00d4ff,transparent)' }} />
          <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700, color:'#00d4ff', letterSpacing:2, marginBottom:'.5rem' }}>
            SYSTEM ACCESS
          </div>
          <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#3a6a88', marginBottom:'2rem' }}>
            // Authorised personnel only — SentinelAI SOC Platform
          </div>
          {sessionError && <p role="alert" style={{ color: '#ffaa00', fontSize: 12 }}>{sessionError}</p>}
          <div style={{ marginBottom:'1.25rem' }}>
            <label style={label}>Operator ID</label>
            <input style={input} type="email" placeholder="operator@sentinel.io"
              value={email} onChange={e=>setEmail(e.target.value)}
              onKeyDown={e=>e.key==='Enter'&&handleSubmit()}
              onFocus={e=>e.target.style.borderColor='#00d4ff'}
              onBlur={e=>e.target.style.borderColor='#0d3352'} />
          </div>
          <div style={{ marginBottom:'1.5rem' }}>
            <label style={label}>Access Key</label>
            <input style={input} type="password" placeholder="••••••••••••"
              value={password} onChange={e=>setPassword(e.target.value)}
              onKeyDown={e=>e.key==='Enter'&&handleSubmit()}
              onFocus={e=>e.target.style.borderColor='#00d4ff'}
              onBlur={e=>e.target.style.borderColor='#0d3352'} />
          </div>
          <button onClick={handleSubmit} disabled={loading} style={{
            width:'100%', padding:12, background:loading?'#00aacc':'#00d4ff',
            border:'1px solid #00d4ff', color:'#000',
            fontFamily:'Rajdhani,sans-serif', fontWeight:700, fontSize:14,
            letterSpacing:2, textTransform:'uppercase', borderRadius:2, cursor:'pointer',
          }}>
            {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE →'}
          </button>
          <div style={{ textAlign:'center', marginTop:'1.5rem', fontSize:13, color:'#3a6a88' }}>
            Access is provisioned by your administrator. Public registration is disabled.
          </div>
        </div>
      </div>
    </>
  )
}
