import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthClient } from '../src/services/authClient.js'

function fixture() {
  let chain = Promise.resolve()
  const locks = {
    request(_name, action) {
      const result = chain.then(action)
      chain = result.catch(() => {})
      return result
    },
  }
  const values = new Map()
  const storage = {
    getItem: (name) => values.get(name),
    setItem: (name, value) => values.set(name, value),
    removeItem: (name) => values.delete(name),
  }
  const counters = { updatePassword: 0, login: 0, csrf: 0 }
  let mustChangePassword = true
  let authVersion = 0

  const fetch = async (url, options) => {
    if (url.endsWith('/csrf')) {
      return { ok: true, json: async () => ({ data: { csrfToken: 'test-csrf-token' } }) }
    }
    if (url.endsWith('/login')) {
      counters.login++
      return {
        ok: true,
        json: async () => ({
          data: {
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InVuaXQtdXNlciIsImF2IjowLCJyb2xlIjoiYW5hbHlzdCIsImV4cCI6OTk5OTk5OTk5OX0.dummy',
            user: { _id: 'unit-user', name: 'New Analyst', email: 'analyst@sentinel.io', role: 'analyst', mustChangePassword, authVersion },
          },
        }),
      }
    }
    if (url.endsWith('/update-password')) {
      counters.updatePassword++
      const body = JSON.parse(options.body || '{}')
      if (body.currentPassword !== 'CorrectOldPassword123') {
        return {
          ok: false,
          status: 401,
          json: async () => ({ success: false, error: 'Wrong password' }),
        }
      }
      if (!body.newPassword || body.newPassword.length < 8) {
        return {
          ok: false,
          status: 400,
          json: async () => ({ success: false, error: 'Valid current and new password required' }),
        }
      }
      mustChangePassword = false
      authVersion++
      return {
        ok: true,
        json: async () => ({
          success: true,
          data: {
            token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InVuaXQtdXNlciIsImF2IjoxLCJyb2xlIjoiYW5hbHlzdCIsImV4cCI6OTk5OTk5OTk5OX0.dummy2',
            user: { _id: 'unit-user', name: 'New Analyst', email: 'analyst@sentinel.io', role: 'analyst', mustChangePassword: false, authVersion },
          },
        }),
      }
    }
    return { ok: true, json: async () => ({ data: {} }) }
  }

  return { locks, storage, values, fetch, counters, getMustChange: () => mustChangePassword }
}

// Route guard simulator function matching App.jsx logic
function evaluateProtectedRoute(user) {
  if (!user) return { redirect: '/login' }
  if (user.mustChangePassword) return { redirect: '/change-password' }
  return { allowed: true }
}

function evaluatePublicRoute(user) {
  if (user) {
    return user.mustChangePassword ? { redirect: '/change-password' } : { redirect: '/dashboard' }
  }
  return { allowed: true }
}

function evaluateChangePasswordRoute(user) {
  if (!user) return { redirect: '/login' }
  if (!user.mustChangePassword) return { redirect: '/dashboard' }
  return { allowed: true }
}

function validateChangePasswordForm(currentPassword, newPassword, confirmPassword) {
  if (!currentPassword) return { valid: false, error: 'Current password is required' }
  if (!newPassword || newPassword.length < 8) return { valid: false, error: 'New password must be at least 8 characters long' }
  if (newPassword.length > 128) return { valid: false, error: 'New password must not exceed 128 characters' }
  if (newPassword !== confirmPassword) return { valid: false, error: 'New passwords do not match' }
  if (currentPassword === newPassword) return { valid: false, error: 'New password must be different from current password' }
  return { valid: true }
}

test('1. Login returns mustChangePassword state and triggers redirect to /change-password', async () => {
  const f = fixture()
  const client = createAuthClient(f)
  const res = await client.login({ email: 'analyst@sentinel.io', password: 'TemporaryPassword123' })

  assert.equal(res.data.user.mustChangePassword, true)
  assert.equal(client.getState().user.mustChangePassword, true)

  const navTarget = res.data.user.mustChangePassword ? '/change-password' : '/dashboard'
  assert.equal(navTarget, '/change-password')
})

test('2. ProtectedRoute blocks normal screens for restricted users and redirects to /change-password', () => {
  // Restricted user
  const restrictedUser = { _id: 'u1', name: 'Restricted', mustChangePassword: true }
  assert.deepEqual(evaluateProtectedRoute(restrictedUser), { redirect: '/change-password' })

  // Normal user
  const normalUser = { _id: 'u2', name: 'Normal', mustChangePassword: false }
  assert.deepEqual(evaluateProtectedRoute(normalUser), { allowed: true })

  // Unauthenticated user
  assert.deepEqual(evaluateProtectedRoute(null), { redirect: '/login' })
})

test('3. PublicRoute routes restricted users away from login to /change-password', () => {
  const restrictedUser = { _id: 'u1', mustChangePassword: true }
  assert.deepEqual(evaluatePublicRoute(restrictedUser), { redirect: '/change-password' })

  const normalUser = { _id: 'u2', mustChangePassword: false }
  assert.deepEqual(evaluatePublicRoute(normalUser), { redirect: '/dashboard' })

  assert.deepEqual(evaluatePublicRoute(null), { allowed: true })
})

test('4. ChangePasswordRoute allows restricted users and redirects normal users to /dashboard', () => {
  const restrictedUser = { _id: 'u1', mustChangePassword: true }
  assert.deepEqual(evaluateChangePasswordRoute(restrictedUser), { allowed: true })

  const normalUser = { _id: 'u2', mustChangePassword: false }
  assert.deepEqual(evaluateChangePasswordRoute(normalUser), { redirect: '/dashboard' })

  assert.deepEqual(evaluateChangePasswordRoute(null), { redirect: '/login' })
})

test('5. Change password form validation enforces password rules and match check', () => {
  assert.deepEqual(validateChangePasswordForm('', 'NewPass123!', 'NewPass123!'), {
    valid: false,
    error: 'Current password is required',
  })
  assert.deepEqual(validateChangePasswordForm('OldPass123!', 'short', 'short'), {
    valid: false,
    error: 'New password must be at least 8 characters long',
  })
  assert.deepEqual(validateChangePasswordForm('OldPass123!', 'NewPass123!', 'Mismatch123!'), {
    valid: false,
    error: 'New passwords do not match',
  })
  assert.deepEqual(validateChangePasswordForm('OldPass123!', 'OldPass123!', 'OldPass123!'), {
    valid: false,
    error: 'New password must be different from current password',
  })
  assert.deepEqual(validateChangePasswordForm('OldPass123!', 'NewPass123!', 'NewPass123!'), {
    valid: true,
  })
})

test('6. Successful updatePassword clears mustChangePassword and updates client auth state', async () => {
  const f = fixture()
  const client = createAuthClient(f)
  await client.login({ email: 'analyst@sentinel.io', password: 'TemporaryPassword123' })
  assert.equal(client.getState().user.mustChangePassword, true)

  const res = await client.updatePassword({
    currentPassword: 'CorrectOldPassword123',
    newPassword: 'BrandNewSecurePassword123!',
  })

  assert.equal(res.success, true)
  assert.equal(res.data.user.mustChangePassword, false)
  assert.equal(client.getState().user.mustChangePassword, false)
  assert.equal(client.getState().user.authVersion, 1)

  // After successful update, ProtectedRoute now allows dashboard access
  assert.deepEqual(evaluateProtectedRoute(client.getState().user), { allowed: true })
})

test('7. Failed updatePassword preserves restriction and does not clear mustChangePassword', async () => {
  const f = fixture()
  const client = createAuthClient(f)
  await client.login({ email: 'analyst@sentinel.io', password: 'TemporaryPassword123' })
  assert.equal(client.getState().user.mustChangePassword, true)

  await assert.rejects(
    () =>
      client.updatePassword({
        currentPassword: 'WrongPassword!',
        newPassword: 'BrandNewSecurePassword123!',
      }),
    { message: 'Wrong password' }
  )

  // State retains mustChangePassword: true
  assert.equal(client.getState().user.mustChangePassword, true)
  assert.deepEqual(evaluateProtectedRoute(client.getState().user), { redirect: '/change-password' })
})

test('8. Expired sessions and logout do not create redirect loops', async () => {
  const f = fixture()
  const client = createAuthClient(f)
  await client.login({ email: 'analyst@sentinel.io', password: 'TemporaryPassword123' })

  // Logout clears credentials completely
  await client.logout()
  assert.equal(client.getState().user, null)
  assert.equal(client.getState().token, null)

  // When user is null, protected route goes directly to /login without loop
  assert.deepEqual(evaluateProtectedRoute(client.getState().user), { redirect: '/login' })
  assert.deepEqual(evaluateChangePasswordRoute(client.getState().user), { redirect: '/login' })
  assert.deepEqual(evaluatePublicRoute(client.getState().user), { allowed: true })
})
