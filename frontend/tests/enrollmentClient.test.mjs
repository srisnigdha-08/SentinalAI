import test from 'node:test'
import assert from 'node:assert/strict'
import { createAuthClient } from '../src/services/authClient.js'

function fixture(role) {
  const calls = []
  let locked = false
  let blocked = false
  const locks = { async request(_key, action) { assert.equal(locked, false); locked = true; try { return await action() } finally { locked = false } } }
  const client = createAuthClient({ locks, fetch: async (url, options) => {
    assert.equal(locked, true)
    assert.equal(options.credentials, 'include')
    calls.push({ url, options })
    if (url.endsWith('/csrf')) return { ok: true, json: async () => ({ data: { csrfToken: 'unit-csrf' } }) }
    assert.equal(options.headers['X-CSRF-Token'], 'unit-csrf')
    if (url.endsWith('/provision')) {
      assert.equal(options.headers.Authorization, 'Bearer memory-access')
      if (blocked) return { ok: false, status: 403, json: async () => ({ error: 'Access denied' }) }
      return { ok: true, json: async () => ({ data: { user: { role: 'viewer', name: 'Unit Operator' } } }) }
    }
    return { ok: true, json: async () => ({ data: { token: 'memory-access', user: { role } } }) }
  } })
  return { client, calls, block: () => { blocked = true } }
}
test('public client registration is disabled without network calls or changing the existing session', async () => {
  const f = fixture('admin')
  await f.client.login({})
  const before = f.client.getState()
  const count = f.calls.length
  await assert.rejects(f.client.register({ role: 'admin' }), { status: 403 })
  assert.equal(f.calls.length, count)
  assert.equal(f.client.getState(), before)
})
for (const role of ['viewer', 'analyst']) test(`${role} client cannot provision`, async () => {
  const f = fixture(role)
  await f.client.login({})
  const count = f.calls.length
  await assert.rejects(f.client.provision({ role: 'admin' }), { status: 403 })
  assert.equal(f.calls.length, count)
})
test('administrator provisioning uses the shared cookie lock, bearer and CSRF without replacing session', async () => {
  const f = fixture('admin')
  await f.client.login({})
  const state = f.client.getState()
  const result = await f.client.provision({ name: 'Unit Operator' })
  assert.equal(result.data.user.role, 'viewer')
  assert.equal(f.calls.at(-1).url, '/api/auth/provision')
  assert.equal(f.client.getState(), state)
})
test('server authorization denial cannot be interpreted as successful provisioning', async () => {
  const f = fixture('admin')
  await f.client.login({})
  f.block()
  await assert.rejects(f.client.provision({}), { status: 403 })
  assert.equal(f.client.getState().user.role, 'admin')
})
test('signed-out client cannot provision', async () => {
  const f = fixture('admin')
  await assert.rejects(f.client.provision({}), { status: 403 })
  assert.equal(f.calls.length, 0)
})
