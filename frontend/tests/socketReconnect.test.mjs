import test from 'node:test'
import assert from 'node:assert/strict'
import { serverDisconnectRetryDelay } from '../src/utils/socketReconnect.js'

test('only server-side disconnects and an unavailable auth service are retried by the app', () => {
  for (const reason of ['transport close', 'transport error', 'ping timeout', 'io client disconnect', 'parse error']) {
    assert.equal(serverDisconnectRetryDelay(reason, 0), null, reason)
  }
  assert.notEqual(serverDisconnectRetryDelay('io server disconnect', 0), null)
  assert.notEqual(serverDisconnectRetryDelay('Authentication service unavailable', 0), null) // 503, e.g. MongoDB down
})

test('a refused token is never retried, so a revoked or expired session cannot reconnect by retrying', () => {
  for (const reason of ['Authentication rejected', 'Password change required', 'xhr poll error', 'timeout']) {
    assert.equal(serverDisconnectRetryDelay(reason, 0), null, reason)
  }
})

test('retry delay backs off exponentially with bounded jitter and never exceeds 30 s', () => {
  const mid = () => 0.5 // jitter factor 1.0
  assert.deepEqual([0, 1, 2, 3, 4, 5, 9].map(a => serverDisconnectRetryDelay('io server disconnect', a, mid)),
    [2000, 4000, 8000, 16000, 30000, 30000, 30000])
  // jitter stays within +-25 % of the base and never pushes past the 30 s cap
  for (const r of [0, 0.25, 0.5, 0.75, 0.999]) {
    const d0 = serverDisconnectRetryDelay('io server disconnect', 0, () => r)
    assert.ok(d0 >= 1500 && d0 <= 2500, `attempt 0, random ${r}: ${d0}`)
    assert.ok(serverDisconnectRetryDelay('io server disconnect', 9, () => r) <= 30000)
  }
  assert.equal(serverDisconnectRetryDelay('io server disconnect', -3, mid), 2000)
})
