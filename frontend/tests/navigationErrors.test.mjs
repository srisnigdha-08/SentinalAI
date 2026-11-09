import test from 'node:test'
import assert from 'node:assert/strict'
import { cannotLoadUrl, isNavigationCancellation } from '../e2e/fixtures/navigationErrors.js'

// Shape of the page error Playwright delivers for WebKit (captured in the TEST-009 investigation)
const webkit = (url) => ({
  name: 'XMLHttpRequest cannot load http',
  message: url.replace(/^https?:\//, '') + ' due to access control checks.',
  stack: `XMLHttpRequest cannot load ${url} due to access control checks.\n    at dispatchXhrRequest (axios.js:2267:17)`,
})
const ORIGIN = 'http://127.0.0.1:3000'

test('a WebKit cancellation report is recognised and its URL recovered', () => {
  assert.equal(cannotLoadUrl(webkit(ORIGIN + '/api/alerts/unread-count')), ORIGIN + '/api/alerts/unread-count')
  assert.equal(cannotLoadUrl({ name: 'TypeError', message: 'x is undefined', stack: 'TypeError: x is undefined\n at a' }), null)
})

test('same-origin refusals (API pollers, Socket.IO long-polls) are cancellations', () => {
  assert.equal(isNavigationCancellation(webkit(ORIGIN + '/api/alerts?limit=10&isRead=false'), ORIGIN), true)
  assert.equal(isNavigationCancellation(webkit(ORIGIN + '/socket.io/?EIO=4&transport=polling&t=1&sid=a'), ORIGIN), true)
})

test('a cross-origin refusal may be a real CORS failure and stays fatal', () => {
  assert.equal(isNavigationCancellation(webkit('http://127.0.0.1:5000/api/alerts'), ORIGIN), false)
  assert.equal(isNavigationCancellation(webkit('https://api.example.test/x'), ORIGIN), false)
  assert.equal(isNavigationCancellation(webkit(ORIGIN + '/api/x'), null), false) // page origin unknown
})

test('app errors are never treated as cancellations', () => {
  const appError = { name: 'TypeError', message: "Cannot read properties of undefined (reading 'map')", stack: 'TypeError: ...' }
  assert.equal(isNavigationCancellation(appError, ORIGIN), false)
  const unhandled = { name: 'Error', message: 'Request failed with status code 500', stack: 'Error: Request failed with status code 500\n at settle' }
  assert.equal(isNavigationCancellation(unhandled, ORIGIN), false)
})

test('request failures: navigation cancellations are ignored; real failures of API/Socket.IO requests are reported', async () => {
  const { isGenuineRequestFailure } = await import('../e2e/fixtures/navigationErrors.js')
  for (const t of ['Load request cancelled', 'NS_BINDING_ABORTED', 'net::ERR_ABORTED']) {
    assert.equal(isGenuineRequestFailure(ORIGIN + '/api/alerts', t, ORIGIN), false, t)
  }
  for (const t of ['net::ERR_CONNECTION_REFUSED', 'NS_ERROR_CONNECTION_REFUSED', 'Could not connect to the server.', 'Blocked by Web Inspector', '']) {
    assert.equal(isGenuineRequestFailure(ORIGIN + '/api/alerts', t, ORIGIN), true, t)
    assert.equal(isGenuineRequestFailure(ORIGIN + '/socket.io/?EIO=4&transport=polling', t, ORIGIN), true, t)
  }
  // fonts, page assets and other origins are out of scope for this check
  assert.equal(isGenuineRequestFailure('https://fonts.gstatic.com/x.woff2', 'net::ERR_FAILED', ORIGIN), false)
  assert.equal(isGenuineRequestFailure(ORIGIN + '/src/pages/Dashboard.jsx', 'net::ERR_FAILED', ORIGIN), false)
})
