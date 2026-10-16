import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthClient } from '../src/services/authClient.js'
function fixture() {
  let chain = Promise.resolve()
  const locks = { request(_name, action) { const result = chain.then(action); chain = result.catch(() => {}); return result } }
  const values = new Map([['sentinel_token', 'legacy-access'], ['sentinel_refresh', 'legacy-refresh'], ['sentinel_user', 'legacy-user']])
  const storage = { getItem: name => values.get(name), setItem: (name, value) => values.set(name, value), removeItem: name => values.delete(name) }
  const counters = { refresh: 0, csrf: 0, logout: 0, logoutAll: 0, replay: 0 }
  let generation = 0
  let nonce = ''
  let failLogout = false
  const fetch = async (url, options) => {
    assert.equal(options.credentials, 'include')
    if (url.endsWith('/csrf')) { nonce = String(++counters.csrf); return { ok: true, json: async () => ({ data: { csrfToken: nonce } }) } }
    assert.equal(options.headers['X-CSRF-Token'], nonce)
    if (url.endsWith('/logout-all')) counters.logoutAll++
    if (url.endsWith('/logout')) { counters.logout++; if (failLogout) throw new Error('Network unavailable'); return { ok: true, json: async () => ({ data: {} }) } }
    if (url.endsWith('/refresh-token')) {
      counters.refresh++
      const presented = generation
      await new Promise(resolve => setTimeout(resolve, 2))
      if (presented !== generation) { counters.replay++; return { ok: false, status: 401, json: async () => ({ error: 'Replay' }) } }
      generation++
    }
    return { ok: true, json: async () => ({ data: { token: 'memory-only-' + generation, user: { _id: 'unit-user', role: 'analyst' } } }) }
  }
  return { locks, storage, values, fetch, counters, failLogout() { failLogout = true } }
}
test('legacy tokens are deleted and never restored; new tokens stay out of storage', async () => {
  const f = fixture(); const client = createAuthClient(f)
  assert.equal(f.values.size, 0)
  await client.login({ email: 'unit@example.invalid', password: 'test-only' })
  assert.ok(client.getState().token)
  assert.equal([...f.values.values()].some(value => value.includes('memory-only')), false)
})
test('same-tab parallel refresh is single-flight', async () => {
  const f = fixture(); const client = createAuthClient(f)
  await Promise.all([client.refresh(), client.refresh(), client.refresh()])
  assert.equal(f.counters.refresh, 1)
})
test('cross-tab refreshes serialize cookie mutations without replay', async () => {
  const f = fixture(); const a = createAuthClient(f); const b = createAuthClient(f)
  await Promise.all([a.refresh(), b.refresh()])
  assert.equal(f.counters.refresh, 2)
  assert.equal(f.counters.replay, 0)
  assert.ok(a.getState().token && b.getState().token)
})
test('logout racing with refresh cannot restore memory authentication', async () => {
  const f = fixture(); const client = createAuthClient(f)
  const refreshing = client.refresh()
  const logout = client.logout()
  await Promise.allSettled([refreshing, logout])
  assert.equal(client.getState().token, null)
  assert.ok(f.counters.logout >= 1 && f.counters.logout <= 2) // Pending bootstrap and logout may both safely revoke.
})
test('failed server logout is reported unconfirmed and bootstrap retries logout instead of restoring a session', async () => {
  const f = fixture(); const client = createAuthClient(f)
  await client.refresh(); f.failLogout()
  assert.equal((await client.logout()).confirmed, false)
  assert.equal(client.getState().token, null)
  const reloaded = createAuthClient(f)
  await assert.rejects(reloaded.refresh())
  assert.equal(reloaded.getState().token, null)
  assert.equal(f.counters.refresh, 1)
})
test('unavailable Web Locks fails safely instead of uncoordinated rotation', async () => {
  const f = fixture(); f.locks = null
  const client = createAuthClient(f)
  await assert.rejects(client.refresh(), /Web Locks/)
  assert.equal(f.counters.refresh, 0)
})
test('blocked localStorage does not expose tokens or break memory login', async () => {
  const f = fixture(); f.storage = { removeItem() { throw new Error('Blocked') }, getItem() { throw new Error('Blocked') } }
  const client = createAuthClient(f)
  await client.login({})
  assert.ok(client.getState().token)
})
test('lost refresh response requires sign-in; a new bootstrap revokes rather than restores the uncertain family', async () => {
  const f = fixture()
  const network = f.fetch
  let lose = true
  f.fetch = async (...args) => {
    const response = await network(...args)
    if (args[0].endsWith('/refresh-token') && lose) { lose = false; throw new Error('Response lost after server rotation') }
    return response
  }
  const client = createAuthClient(f)
  await assert.rejects(client.refresh())
  assert.equal(client.getState().token, null)
  const reloaded = createAuthClient(f)
  assert.equal(await reloaded.refresh(), null)
  assert.equal(f.counters.logout, 1)
})
test('logout broadcasts clear other tabs without transmitting credentials', async () => {
  const f = fixture()
  const endpoints = []
  const channel = () => {
    const handlers = []
    const endpoint = { addEventListener(_event, handler) { handlers.push(handler) },
      postMessage(data) { assert.deepEqual(Object.keys(data), ['type']); for (const other of endpoints) if (other !== endpoint) other.deliver(data) },
      deliver(data) { handlers.forEach(handler => handler({ data })) } }
    endpoints.push(endpoint)
    return endpoint
  }
  const a = createAuthClient({ ...f, channel: channel() })
  const b = createAuthClient({ ...f, channel: channel() })
  await a.refresh(); await b.refresh()
  await a.logout()
  assert.equal(a.getState().token, null)
  assert.equal(b.getState().token, null)
})

test('logout-all obtains fresh access under the cookie lock and clears memory', async () => {
  const f = fixture()
  const network = f.fetch
  const requests = []
  f.fetch = async (url, options) => {
    if (!url.endsWith('/csrf')) requests.push({ url, bearer: options.headers.Authorization })
    return network(url, options)
  }
  const client = createAuthClient(f)
  await client.login({})
  assert.equal((await client.logout(true)).confirmed, true)
  assert.ok(requests.at(-2).url.endsWith('/refresh-token'))
  assert.ok(requests.at(-1).url.endsWith('/logout-all'))
  assert.equal(requests.at(-1).bearer, 'Bearer memory-only-1')
  assert.equal(client.getState().token, null)
})

test('a queued refresh in another tab completes the same logout-all intent instead of downgrading it', async () => {
  const f = fixture()
  const a = createAuthClient(f)
  const b = createAuthClient(f)
  await a.login({})
  const earlierRefresh = b.refresh()
  const logout = a.logout(true)
  await earlierRefresh
  assert.equal((await logout).confirmed, true)
  assert.equal(f.counters.logout, 0)
  assert.equal(f.counters.logoutAll, 1)
  assert.equal(a.getState().token, null)
  assert.equal(b.getState().token, null)
})
