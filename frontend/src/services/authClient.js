// Tokens stay in memory. Cross-tab network mutations share one Web Lock.
export function createAuthClient({ fetch: request, locks, channel, storage, base = '/api' }) {
  let state = { user: null, token: null }
  let epoch = 0
  let refreshing = null
  let refreshTimer
  let localPending = null
  let lastConfirmed = null
  const listeners = new Set()
  const publish = value => {
    clearTimeout(refreshTimer)
    state = value
    if (value.token) {
      try {
        const claims = JSON.parse(atob(value.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
        if (Number.isFinite(claims.exp)) {
          refreshTimer = setTimeout(() => refresh().catch(() => {}), Math.max(1000, claims.exp * 1000 - Date.now() - 30000))
          refreshTimer.unref?.()
        }
      } catch {}
    }
    listeners.forEach(listener => listener(state))
  }
  const cleanLegacy = () => { for (const key of ['sentinel_token', 'sentinel_refresh', 'sentinel_user']) { try { storage?.removeItem(key) } catch {} } }
  const pending = value => {
    localPending = value || null
    try { value ? storage?.setItem('sentinel_logout_pending', JSON.stringify(value)) : storage?.removeItem('sentinel_logout_pending') } catch {}
  }
  const readPending = () => {
    try {
      if (!storage) return localPending
      const value = storage.getItem('sentinel_logout_pending')
      if (value === '1') return { id: 'legacy-local-intent', mode: 'session' }
      const intent = value && JSON.parse(value)
      return intent && typeof intent.id === 'string' && ['session', 'all'].includes(intent.mode) ? intent : null
    } catch { return localPending }
  }
  const intent = mode => ({ id: crypto.randomUUID(), mode })
  const confirmed = id => {
    try { return lastConfirmed === id || storage?.getItem('sentinel_logout_confirmed') === id } catch { return lastConfirmed === id }
  }
  const confirm = value => {
    lastConfirmed = value.id
    try { storage?.setItem('sentinel_logout_confirmed', value.id) } catch {}
    pending(false)
    channel?.postMessage({ type: 'logout-confirmed' })
  }
  cleanLegacy()
  const clear = () => { epoch++; publish({ user: null, token: null }); cleanLegacy() }
  channel?.addEventListener('message', event => {
    if (['logout', 'logout-all'].includes(event.data?.type)) {
      if (!readPending()) pending(intent(event.data.type === 'logout-all' ? 'all' : 'session'))
      clear()
    }
    if (event.data?.type === 'logout-confirmed') {
      try { lastConfirmed = storage?.getItem('sentinel_logout_confirmed') } catch {}
      localPending = null
    }
    if (event.data?.type === 'session-changed') { clear(); refresh().catch(() => {}) }
  })
  const exclusive = action => {
    if (!locks?.request) return Promise.reject(new Error('This browser requires Web Locks for secure session coordination.'))
    return locks.request('sentinel-auth-v2', action)
  }
  async function call(endpoint, body, token, method = 'POST') {
    const csrfResponse = await request(base + '/auth/csrf', { credentials: 'include', cache: 'no-store', signal: AbortSignal.timeout(10000) })
    if (!csrfResponse.ok) throw new Error('Session protection is unavailable')
    const csrf = (await csrfResponse.json()).data.csrfToken
    const response = await request(base + '/auth/' + endpoint, { method, credentials: 'include', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...(token ? { Authorization: 'Bearer ' + token } : {}) },
      body: JSON.stringify(body || {}), signal: AbortSignal.timeout(10000) })
    const result = await response.json()
    if (!response.ok) {
      const error = new Error(result.error || 'Authentication failed')
      error.status = response.status
      error.response = { data: result, status: response.status }
      throw error
    }
    return result
  }
  async function revokeIntent(value, token) {
    if (confirmed(value.id)) return
    const current = value.mode === 'all' ? (await call('refresh-token')).data.token : token
    await call(value.mode === 'all' ? 'logout-all' : 'logout', {}, current)
    confirm(value)
  }
  function refresh() {
    if (refreshing) return refreshing
    const started = epoch
    refreshing = exclusive(async () => {
      const isPending = readPending()
      if (isPending) {
        await revokeIntent(isPending)
        return null
      }
      if (started !== epoch) return null
      const result = await call('refresh-token')
      if (started === epoch) publish({ user: result.data.user, token: result.data.token })
      return started === epoch ? result.data.token : null
    }).catch(error => {
      if (error.status === 401 || error.status === 403) clear()
      else {
        // A timed-out/lost response may have consumed the refresh token. Do not restore it.
        if (!readPending()) pending(intent('session'))
        clear(); channel?.postMessage({ type: readPending()?.mode === 'all' ? 'logout-all' : 'logout' })
      }
      throw error
    }).finally(() => { refreshing = null })
    return refreshing
  }
  async function login(credentials) {
    epoch++
    const started = epoch
    return exclusive(async () => {
      const result = await call('login', credentials)
      pending(false)
      if (started === epoch) publish({ user: result.data.user, token: result.data.token })
      channel?.postMessage({ type: 'session-changed' })
      return result
    })
  }
  async function logout(all = false) {
    const token = state.token
    const requested = intent(all ? 'all' : 'session')
    pending(requested)
    clear()
    channel?.postMessage({ type: all ? 'logout-all' : 'logout' })
    try {
      await exclusive(() => revokeIntent(requested, token))
      return { confirmed: true }
    } catch { return { confirmed: false } }
  }
  const register = () => {
    const error = new Error('Public registration is disabled. Contact an administrator for access.')
    error.status = 403
    return Promise.reject(error)
  }
  const provision = data => exclusive(async () => {
    if (readPending() || !state.token || state.user?.role !== 'admin') {
      const error = new Error('Administrator sign-in required')
      error.status = 403
      throw error
    }
    // Keep the existing nonce-cookie Path and shared cookie-mutation lock.
    return call('provision', data, state.token)
  })
  const updatePassword = data => exclusive(async () => {
    const result = await call('update-password', data, state.token, 'PUT')
    epoch++
    publish({ user: result.data.user, token: result.data.token })
    channel?.postMessage({ type: 'session-changed' })
    return result
  })
  return { login, logout, register, provision, updatePassword, refresh, clear, getState: () => state,
    subscribe(listener) { listeners.add(listener); listener(state); return () => listeners.delete(listener) } }
}
