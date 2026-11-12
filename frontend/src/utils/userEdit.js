// Edit User form rules. They mirror PUT /api/users/:id, which enforces them again on the server.

export const EDITABLE_USER_FIELDS = ['name', 'department', 'role', 'status']
const ROLES = ['admin', 'analyst', 'viewer']
const STATUSES = ['active', 'inactive', 'suspended']

/** Field errors for the form values ({} when valid). */
export function validateUserEdit(form) {
  const errors = {}
  const name = String(form?.name ?? '').trim()
  const department = String(form?.department ?? '').trim()
  if (name.length < 2 || name.length > 50) errors.name = 'Name must be 2-50 characters.'
  if (!department || department.length > 100) errors.department = 'Department must be 1-100 characters.'
  if (!ROLES.includes(form?.role)) errors.role = 'Choose a valid role.'
  if (!STATUSES.includes(form?.status)) errors.status = 'Choose a valid status.'
  return errors
}

/** Only the fields that differ from the stored user (trimmed), so unchanged values are never re-sent. */
export function changedUserFields(user, form) {
  const out = {}
  for (const key of EDITABLE_USER_FIELDS) {
    const next = typeof form?.[key] === 'string' ? form[key].trim() : form?.[key]
    const prev = key === 'department' ? (user?.[key] ?? '') : user?.[key]
    if (next !== undefined && next !== prev) out[key] = next
  }
  return out
}

/** True when `user` is the only active administrator in `users`. */
export function isLastActiveAdmin(user, users) {
  if (user?.role !== 'admin' || user?.status !== 'active') return false
  return (users || []).filter((u) => u.role === 'admin' && u.status === 'active').length <= 1
}

/** Readable message for a failed update. */
export function userEditErrorMessage(err) {
  if (!err?.response) return 'The server could not be reached. Your changes were not saved.'
  const { status, data } = err.response
  if (status === 401) return 'Your session has expired. Sign in again; your changes were not saved.'
  if (status === 403) return 'Only active administrators can edit users.'
  if (status === 404) return 'This user no longer exists. The list has been reloaded.'
  if (status === 409) return data?.error || 'This account was changed by someone else. The list has been reloaded; reopen it and try again.'
  return data?.error || `Save failed (HTTP ${status}).`
}
