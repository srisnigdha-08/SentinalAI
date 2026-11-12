import { useEffect, useState } from 'react'
import Modal from './Modal.jsx'
import { userAPI } from '../services/api.js'
import { validateUserEdit, changedUserFields, userEditErrorMessage } from '../utils/userEdit.js'

const inputStyle = {
  display: 'block', width: '100%', marginTop: 4, padding: '8px 10px', color: '#c8e6f5', background: '#020b18',
  border: '1px solid #0d3352', borderRadius: 2, fontFamily: 'Share Tech Mono,monospace', fontSize: 12, boxSizing: 'border-box',
}
const labelStyle = { fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#7ab3cc', letterSpacing: 1, textTransform: 'uppercase' }
const noteStyle = { fontFamily: 'Share Tech Mono,monospace', fontSize: 10, color: '#3a6a88', marginTop: 4, lineHeight: 1.5 }

/**
 * Edit User (admin only): name, department, role and status, via PUT /api/users/:id. The server enforces every
 * rule shown here (self-demotion, last active administrator, allowed fields, stale edits); the form only
 * explains them up front. Email is the sign-in identity and passwords have their own flows, so neither is here.
 */
export default function EditUserModal({ user, currentUserId, isLastActiveAdmin, onClose, onSaved, onStale }) {
  const [form, setForm] = useState(null)
  const [errors, setErrors] = useState({})
  const [serverError, setServerError] = useState(null)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (!user) return
    setForm({ name: user.name || '', department: user.department || '', role: user.role, status: user.status })
    setErrors({})
    setServerError(null)
  }, [user])

  if (!user || !form) return null
  const isSelf = String(user._id) === String(currentUserId)
  const lockPrivileges = isSelf || isLastActiveAdmin
  const changes = changedUserFields(user, form)
  const securityChange = 'role' in changes || 'status' in changes

  const set = (key) => (event) => setForm((prev) => ({ ...prev, [key]: event.target.value }))

  const submit = async (event) => {
    event.preventDefault()
    if (saving) return
    const found = validateUserEdit(form)
    setErrors(found)
    setServerError(null)
    if (Object.keys(found).length) return
    if (!Object.keys(changes).length) {
      setServerError('Nothing to save: no field was changed.')
      return
    }
    setSaving(true)
    try {
      const res = await userAPI.update(user._id, { ...changes, expectedUpdatedAt: user.updatedAt })
      onSaved(res.data?.data?.user || null, res.data?.data || {})
    } catch (err) {
      const status = err?.response?.status
      // A newer record or a deleted user: the parent reloads the list and closes the form
      if ((status === 409 || status === 404) && onStale) onStale(userEditErrorMessage(err))
      else setServerError(userEditErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal isOpen onClose={onClose} dismissible={!saving} title="Edit User" subtitle={`// ${user.email}`} maxWidth="520px">
      <form onSubmit={submit} noValidate style={{ display: 'grid', gap: 14 }} data-testid="edit-user-form">
        <label style={labelStyle}>
          Display name
          <input value={form.name} onChange={set('name')} maxLength={50} autoComplete="off" aria-invalid={Boolean(errors.name)}
            aria-describedby={errors.name ? 'edit-user-name-error' : undefined} style={inputStyle} />
          {errors.name && <span id="edit-user-name-error" role="alert" style={{ ...noteStyle, color: '#ff2d55' }}>{errors.name}</span>}
        </label>
        <div style={labelStyle}>
          Email (sign-in identity)
          <div style={{ ...inputStyle, color: '#7ab3cc', background: '#041120' }} aria-readonly="true">{user.email}</div>
          <div style={noteStyle}>Email cannot be changed here. Passwords are changed by the user or through a forced reset.</div>
        </div>
        <label style={labelStyle}>
          Department
          <input value={form.department} onChange={set('department')} maxLength={100} autoComplete="off" aria-invalid={Boolean(errors.department)}
            aria-describedby={errors.department ? 'edit-user-dept-error' : undefined} style={inputStyle} />
          {errors.department && <span id="edit-user-dept-error" role="alert" style={{ ...noteStyle, color: '#ff2d55' }}>{errors.department}</span>}
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
          <label style={labelStyle}>
            Role
            <select value={form.role} onChange={set('role')} disabled={lockPrivileges} style={inputStyle}>
              <option value="viewer">Viewer</option>
              <option value="analyst">Analyst</option>
              <option value="admin">Administrator</option>
            </select>
          </label>
          <label style={labelStyle}>
            Status
            <select value={form.status} onChange={set('status')} disabled={lockPrivileges} style={inputStyle}>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="suspended">Suspended</option>
            </select>
          </label>
        </div>
        {isSelf && <div style={noteStyle}>You cannot change your own role or status. Ask another administrator.</div>}
        {!isSelf && isLastActiveAdmin && (
          <div style={noteStyle}>This is the last active administrator: its role and status cannot change until another administrator is active.</div>
        )}
        {securityChange && (
          <div role="note" style={{ ...noteStyle, color: '#ffaa00' }}>
            Changing role or status signs this user out of every session; they must sign in again.
          </div>
        )}
        {serverError && <div role="alert" style={{ fontFamily: 'Share Tech Mono,monospace', fontSize: 11, color: '#ff2d55' }}>{serverError}</div>}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, flexWrap: 'wrap' }}>
          <button type="button" onClick={onClose} disabled={saving} style={{
            background: 'transparent', border: '1px solid #1a4a6e', color: '#7ab3cc', fontFamily: 'Rajdhani,sans-serif',
            fontWeight: 600, fontSize: 12, letterSpacing: 1, textTransform: 'uppercase', padding: '8px 16px', borderRadius: 2, cursor: 'pointer',
          }}>Cancel</button>
          <button type="submit" disabled={saving} aria-busy={saving} style={{
            background: saving ? '#0d3352' : '#00d4ff', border: '1px solid #00d4ff', color: saving ? '#7ab3cc' : '#000',
            fontFamily: 'Rajdhani,sans-serif', fontWeight: 700, fontSize: 12, letterSpacing: 1, textTransform: 'uppercase',
            padding: '8px 18px', borderRadius: 2, cursor: saving ? 'wait' : 'pointer',
          }}>{saving ? 'Saving...' : 'Save changes'}</button>
        </div>
      </form>
    </Modal>
  )
}
