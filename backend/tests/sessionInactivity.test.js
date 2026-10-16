process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-session-tests'
process.env.HONEYPOT_API_KEY = 'unit-honeypot-secret-for-session-tests'
process.env.SENTINEL_KEY = 'unit-sentinel-secret-for-session-tests'
process.env.CLIENT_URL = 'http://localhost:3000'

jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), stopHealthBroadcast: jest.fn() }))

const jwt = require('jsonwebtoken')
const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const { install } = require('./helpers/authMemoryStore')
const auth = require('../services/authSessionService')
const { app } = require('../server')

let memory

beforeEach(() => {
  jest.clearAllMocks()
  memory = install(User, Session)
  auth.attachSocketServer(null)
  auth.setAvailability(null)
})

afterEach(() => auth.setAvailability(null))

async function csrf(agent) {
  return (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
}

describe('Phase 6B — Session Inactivity Timeout Tests', () => {
  describe('Configuration & Parsing', () => {
    test('parseInactivityTimeout returns default 900 for undefined, null, or empty string', () => {
      expect(auth.parseInactivityTimeout(undefined)).toBe(900)
      expect(auth.parseInactivityTimeout(null)).toBe(900)
      expect(auth.parseInactivityTimeout('')).toBe(900)
    })

    test('parseInactivityTimeout accepts valid integers within 60 to 2592000', () => {
      expect(auth.parseInactivityTimeout(60)).toBe(60)
      expect(auth.parseInactivityTimeout(1800)).toBe(1800)
      expect(auth.parseInactivityTimeout('3600')).toBe(3600)
      expect(auth.parseInactivityTimeout(2592000)).toBe(2592000)
    })

    test('parseInactivityTimeout rejects invalid numbers, out of bounds, and non-integers', () => {
      expect(() => auth.parseInactivityTimeout(59)).toThrow(/Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS/)
      expect(() => auth.parseInactivityTimeout(2592001)).toThrow(/Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS/)
      expect(() => auth.parseInactivityTimeout(-100)).toThrow(/Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS/)
      expect(() => auth.parseInactivityTimeout('abc')).toThrow(/Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS/)
      expect(() => auth.parseInactivityTimeout(12.34)).toThrow(/Invalid SESSION_INACTIVITY_TIMEOUT_SECONDS/)
    })
  })

  describe('Idle Expiration Logic', () => {
    test('active session within inactivity window is valid', async () => {
      const issued = await auth.issue(memory.user)
      const now = Date.now() + 5 * 60 * 1000 // 5 minutes later (< 15 minutes)
      const authorized = await auth.authorize(issued.token, { now })
      expect(authorized.user.role).toBe('analyst')
      expect(authorized.session.revokedAt).toBeNull()
    })

    test('session becomes idle-expired after 15 minutes of inactivity', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const now = Date.now() + 15 * 60 * 1000 + 1000 // 15 minutes + 1s later

      await expect(auth.authorize(issued.token, { now })).rejects.toMatchObject({
        statusCode: 401,
        message: 'Session expired due to inactivity',
      })

      // In-memory store should record revocation due to inactivity-timeout
      const stored = memory.sessions.get(sid)
      expect(stored.revokedAt).not.toBeNull()
      expect(stored.revocationReason).toBe('inactivity-timeout')
    })

    test('absolute session expiry still applies even if lastUsedAt was recently updated', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      // Simulate session is 31 days old, but lastUsedAt was touched 2 minutes ago
      const absoluteExpiryTime = Date.now() + 31 * 86400 * 1000
      memory.sessions.get(sid).lastUsedAt = new Date(absoluteExpiryTime - 120 * 1000)

      await expect(auth.authorize(issued.token, { now: absoluteExpiryTime })).rejects.toMatchObject({
        statusCode: 401,
      })
    })

    test('refresh cannot revive an idle-expired session', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.refreshToken).sid
      const idleTime = Date.now() + 16 * 60 * 1000 // 16 minutes later

      await expect(auth.rotate(issued.refreshToken, { now: idleTime })).rejects.toMatchObject({
        statusCode: 401,
        message: 'Session expired due to inactivity',
      })

      // Subsequent attempt with refresh token is rejected because session is revoked
      await expect(auth.rotate(issued.refreshToken, { now: idleTime + 1000 })).rejects.toMatchObject({
        statusCode: 401,
      })
    })
  })

  describe('Throttled Activity Tracking', () => {
    test('recordActivity throttles updates within the throttle window', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const initialLastUsed = new Date(memory.sessions.get(sid).lastUsedAt).getTime()

      // Request 10 seconds later (within 60s throttle interval)
      await auth.recordActivity(sid, initialLastUsed + 10000)
      const unchanged = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      expect(unchanged).toBe(initialLastUsed)

      // Request 70 seconds later (beyond 60s throttle interval)
      const later = initialLastUsed + 70000
      await auth.recordActivity(sid, later)
      const updated = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      expect(updated).toBe(later)
    })

    test('recordActivity does not update a revoked session', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      await auth.revokeSession(sid, 'test-revocation')

      const timeBefore = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      await auth.recordActivity(sid, timeBefore + 120000)
      const timeAfter = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      expect(timeAfter).toBe(timeBefore)
    })
  })

  describe('REST Protection & Cookie Clearing', () => {
    test('protect middleware clears cookies when token is idle expired', async () => {
      const agent = request.agent(app)
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid

      // Manually set session lastUsedAt to 20 minutes ago
      const twentyMinAgo = new Date(Date.now() - 20 * 60 * 1000)
      memory.sessions.get(sid).lastUsedAt = twentyMinAgo

      const res = await agent
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + issued.token)
        .set('Origin', process.env.CLIENT_URL)

      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Session expired due to inactivity')
      expect(res.headers['set-cookie']).toBeDefined()
      // Verify cookie clear header includes Max-Age=0 or Expires in the past
      const setCookieStr = res.headers['set-cookie'].join('; ')
      expect(setCookieStr).toMatch(/Expires=Thu, 01 Jan 1970|Max-Age=0/i)
    })

    test('unauthenticated endpoints and health checks do not update session activity', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const initialLastUsed = new Date(memory.sessions.get(sid).lastUsedAt).getTime()

      // Hit public CSRF endpoint
      await request(app).get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)
      // Hit endpoint with no authorization header
      await request(app).get('/api/auth/me')

      const currentLastUsed = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      expect(currentLastUsed).toBe(initialLastUsed)
    })
  })
})
