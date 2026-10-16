import { REPORT_TIME_ZONE } from '../utils/reportingTime.js'
import { useState, useEffect } from 'react'
import DashboardLayout from '../layouts/DashboardLayout.jsx'
import Panel from '../components/Panel.jsx'
import { userAPI } from '../services/api.js'
import toast from 'react-hot-toast'

const ROLE_STYLES = {
  admin:   { background:'rgba(139,92,246,.2)', color:'#8b5cf6', border:'1px solid rgba(139,92,246,.4)' },
  analyst: { background:'rgba(0,212,255,.1)',  color:'#00d4ff', border:'1px solid rgba(0,212,255,.3)'  },
  viewer:  { background:'rgba(122,179,204,.1)',color:'#7ab3cc', border:'1px solid #0d3352'              },
}

export default function UserManagement() {
  const [users,   setUsers]   = useState([])
  const [stats,   setStats]   = useState(null)
  const [loading, setLoading] = useState(true)
  const [showProvision, setShowProvision] = useState(false)
  const [creating, setCreating] = useState(false)
  const emptyForm = { name: '', email: '', password: '', role: 'viewer', department: 'SOC' }
  const [form, setForm] = useState(emptyForm)
  const [createError, setCreateError] = useState(null)
  const provision = async event => {
    event.preventDefault()
    if (creating) return
    setCreating(true)
    setCreateError(null)
    try {
      const result = await userAPI.create(form)
      setUsers(previous => [result.data.data.user, ...previous])
      setForm(emptyForm)
      setShowProvision(false)
      toast.success('Account provisioned. Deliver credentials securely; the operator must sign in.')
      // A failed stats reload must not misreport a successful account creation.
      try { setStats((await userAPI.stats()).data.data) } catch { setStats(null) }
    } catch (error) {
      setCreateError(error.response?.data?.error || error.message || 'Account provisioning failed')
    } finally { setCreating(false) }
  }

  useEffect(() => {
    const load = async () => {
      try {
        const [uRes, sRes] = await Promise.all([userAPI.list(), userAPI.stats()])
        setUsers(uRes.data.data || [])
        setStats(sRes.data.data)
      } catch { toast.error('Failed to load users') }
      finally { setLoading(false) }
    }
    load()
  }, [])

  const deleteUser = async (user) => {
    if (!window.confirm(`Delete ${user.name}?`)) return
    try {
      await userAPI.delete(user._id)
      setUsers(prev => prev.filter(u => u._id !== user._id))
      toast.success(`${user.name} removed`)
    } catch (e) { toast.error(e.response?.data?.error || 'Delete failed') }
  }

  return (
    <DashboardLayout>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:'1.5rem' }}>
        <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:18, fontWeight:700 }}>
          User <span style={{ color:'#00d4ff' }}>Management</span>
        </div>
        <button onClick={()=>setShowProvision(value => !value)} style={{
          background:'#00d4ff', border:'1px solid #00d4ff', color:'#000',
          fontFamily:'Rajdhani,sans-serif', fontWeight:700, fontSize:11,
          letterSpacing:1, textTransform:'uppercase', padding:'8px 18px', borderRadius:2, cursor:'pointer',
        }}>{showProvision ? 'Cancel' : '+ Provision Operator'}</button>
      </div>

      {showProvision && <Panel title="Provision operator" style={{ marginBottom: '1.5rem' }}>
        <p>Administrator-only enrollment. Viewer is the default; assign elevated roles only after review.</p>
        <form onSubmit={provision} style={{ display: 'grid', gap: 12, marginTop: 16 }}>
          {[
            ['name', 'Full name', 'text'], ['email', 'Email', 'email'],
            ['password', 'Initial password', 'password'], ['department', 'Department', 'text'],
          ].map(([key, label, type]) => <label key={key}>
            {label}
            <input required type={type} value={form[key]} autoComplete={key === 'password' ? 'new-password' : 'off'}
              minLength={key === 'password' ? 8 : key === 'name' ? 2 : 1}
              maxLength={key === 'password' ? 128 : key === 'name' ? 50 : 100}
              onChange={event => setForm(previous => ({ ...previous, [key]: event.target.value }))}
              style={{ display: 'block', width: '100%', padding: 8, color: '#c8e6f5', background: '#041120', border: '1px solid #0d3352' }} />
          </label>)}
          <label>Role
            <select value={form.role} onChange={event => setForm(previous => ({ ...previous, role: event.target.value }))}
              style={{ display: 'block', padding: 8, color: '#c8e6f5', background: '#041120' }}>
              <option value="viewer">Viewer (least privilege)</option><option value="analyst">Analyst</option><option value="admin">Administrator</option>
            </select>
          </label>
          <p>No invitation email is sent. Deliver the initial password through an approved private channel; ask the operator to change it after first sign-in.</p>
          {createError && <p role="alert" style={{ color: '#ff2d55' }}>{createError}</p>}
          <button type="submit" disabled={creating}>{creating ? 'Provisioning...' : 'Provision account'}</button>
        </form>
      </Panel>}

      {/* Stats strip */}
      {stats && (
        <div style={{ display:'flex', gap:'1rem', marginBottom:'1.5rem' }}>
          {[
            { label:'Total Users', value: stats.total },
            ...(stats.byRole||[]).map(r=>({ label:r._id?.toUpperCase(), value:r.count })),
          ].map(s=>(
            <div key={s.label} style={{ background:'#081f35', border:'1px solid #0d3352', borderRadius:2,
              padding:'1rem 1.5rem', flex:1 }}>
              <div style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88', marginBottom:4 }}>{s.label}</div>
              <div style={{ fontFamily:'Orbitron,sans-serif', fontSize:24, fontWeight:700, color:'#00d4ff' }}>{s.value}</div>
            </div>
          ))}
        </div>
      )}

      <Panel>
        {loading ? (
          <div style={{ textAlign:'center', padding:'3rem', color:'#3a6a88', fontFamily:'Share Tech Mono,monospace', fontSize:12 }}>LOADING USERS...</div>
        ) : (
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:13 }}>
            <thead><tr>
              {['','Name','Email','Role','Status','Last Login','Actions'].map(h=>(
                <th key={h} style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, color:'#3a6a88',
                  letterSpacing:2, padding:'10px 12px', borderBottom:'1px solid #0d3352', textAlign:'left' }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {users.map(u=>(
                <tr key={u._id}
                  onMouseEnter={e=>e.currentTarget.style.background='rgba(0,212,255,.02)'}
                  onMouseLeave={e=>e.currentTarget.style.background=''}>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <div style={{ width:32, height:32, borderRadius:'50%', background:'#0a2540',
                      border:'1px solid #1a4a6e', display:'flex', alignItems:'center', justifyContent:'center',
                      fontFamily:'Orbitron,sans-serif', fontSize:10, color:'#00d4ff' }}>
                      {u.name?.split(' ').map(n=>n[0]).join('').slice(0,2).toUpperCase()}
                    </div>
                  </td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)', fontWeight:600 }}>{u.name}</td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:12, color:'#7ab3cc' }}>{u.email}</td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <span style={{ fontFamily:'Share Tech Mono,monospace', fontSize:10, padding:'3px 8px', borderRadius:1, ...(ROLE_STYLES[u.role]||ROLE_STYLES.viewer) }}>
                      {u.role}
                    </span>
                  </td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:8, height:8, borderRadius:'50%', background:u.status==='active'?'#00ff88':'#ffaa00' }} />
                      <span style={{ fontSize:12, color:u.status==='active'?'#00ff88':'#3a6a88' }}>{u.status}</span>
                    </div>
                  </td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)', fontFamily:'Share Tech Mono,monospace', fontSize:11, color:'#3a6a88' }}>
                    {u.lastLogin ? new Date(u.lastLogin).toLocaleDateString('en-IN', { timeZone: REPORT_TIME_ZONE }) : 'Never'}
                  </td>
                  <td style={{ padding:'12px', borderBottom:'1px solid rgba(13,51,82,.5)' }}>
                    <div style={{ display:'flex', gap:6 }}>
                      <button disabled title="Role/status changes currently use the authorized administrator API" style={{
                        background:'none', border:'1px solid #0d3352', color:'#3a6a88',
                        fontSize:10, fontFamily:'Share Tech Mono,monospace', padding:'4px 10px', cursor:'pointer', borderRadius:1,
                      }}>Edit via API</button>
                      {u.role !== 'admin' && (
                        <button onClick={()=>deleteUser(u)} style={{
                          background:'none', border:'1px solid rgba(255,45,85,.3)', color:'#ff2d55',
                          fontSize:10, fontFamily:'Share Tech Mono,monospace', padding:'4px 10px', cursor:'pointer', borderRadius:1,
                        }}>Remove</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </DashboardLayout>
  )
}
