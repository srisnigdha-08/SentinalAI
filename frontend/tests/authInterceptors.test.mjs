import test from 'node:test'
import assert from 'node:assert/strict'
import axios from 'axios'
import { installAuthInterceptors } from '../src/services/authInterceptors.js'
function fixture({ denyRetry = false, refreshFailure = false } = {}) {
  const calls = []
  const counters = { refresh: 0, clear: 0 }
  let token = 'initial-memory-token'
  const session = {
    getState: () => ({ token }),
    clear() { counters.clear++; token = null },
    async refresh() {
      counters.refresh++
      if (refreshFailure) throw Object.assign(new Error('Revoked'), { status: 401 })
      token = 'rotated-memory-token'
      return token
    },
  }
  const api = axios.create({ adapter: async config => {
    calls.push({ token: config.headers.Authorization, url: config.url })
    if (denyRetry || calls.length === 1) throw { config, response: { status: 401 } }
    return { config, status: 200, data: { actualResponse: true }, headers: {} }
  } })
  installAuthInterceptors(api, session)
  return { api, calls, counters, session }
}
test('a protected request retries once with the rotated memory token', async () => {
  const f = fixture()
  assert.equal((await f.api.get('/threats')).status, 200)
  assert.deepEqual(f.calls.map(call => call.token), ['Bearer initial-memory-token', 'Bearer rotated-memory-token'])
  assert.equal(f.counters.refresh, 1)
})
test('a denied retry clears state without a second refresh or retry loop', async () => {
  const f = fixture({ denyRetry: true })
  await assert.rejects(f.api.get('/threats'))
  assert.equal(f.calls.length, 2)
  assert.equal(f.counters.refresh, 1)
  assert.equal(f.session.getState().token, null)
})
test('a failed refresh does not retry the protected request', async () => {
  const f = fixture({ refreshFailure: true })
  await assert.rejects(f.api.get('/threats'), /Revoked/)
  assert.equal(f.calls.length, 1)
  assert.equal(f.session.getState().token, null)
})
test('authentication requests and explicitly excluded requests do not refresh recursively', async () => {
  for (const options of [{ url: '/auth/me' }, { url: '/threats', skipAuthRedirect: true }]) {
    const f = fixture()
    await assert.rejects(f.api(options))
    assert.equal(f.counters.refresh, 0)
    assert.equal(f.calls.length, 1)
  }
})
