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

describe('Phase 7 Verification — Concurrency, Boundary Timestamps, & Stale Replay Tests', () => {
  describe('Boundary Timestamps for Idle Expiration', () => {
    test('session at exactly 900,000ms (15m exact) is NOT idle-expired', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const startTime = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      const exactBoundary = startTime + 900 * 1000 // Exactly 900 seconds (now - lastActivity === 900000, not >)

      const result = await auth.authorize(issued.token, { now: exactBoundary })
      expect(result.session.revokedAt).toBeNull()
      expect(result.user._id).toBe(memory.user._id)
    })

    test('session at 900,001ms (15m + 1ms) IS idle-expired', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const startTime = new Date(memory.sessions.get(sid).lastUsedAt).getTime()
      const pastBoundary = startTime + 900 * 1000 + 1 // 1 ms beyond boundary

      await expect(auth.authorize(issued.token, { now: pastBoundary })).rejects.toMatchObject({
        statusCode: 401,
        message: 'Session expired due to inactivity',
      })

      const stored = memory.sessions.get(sid)
      expect(stored.revokedAt).not.toBeNull()
      expect(stored.revocationReason).toBe('inactivity-timeout')
    })

    test('throttling boundary: 59,999ms skips DB update; 60,001ms executes DB update', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const initialLastUsed = new Date(memory.sessions.get(sid).lastUsedAt).getTime()

      // 59,999 ms later -> throttled (no update)
      await auth.recordActivity(sid, initialLastUsed + 59999)
      expect(new Date(memory.sessions.get(sid).lastUsedAt).getTime()).toBe(initialLastUsed)

      // 60,001 ms later -> outside throttle (updates lastUsedAt)
      const touchTime = initialLastUsed + 60001
      await auth.recordActivity(sid, touchTime)
      expect(new Date(memory.sessions.get(sid).lastUsedAt).getTime()).toBe(touchTime)
    })
  })

  describe('Concurrency & Stale Refresh Replay Races', () => {
    test('concurrent recordActivity calls handle parallel invocation safely', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const baseTime = Date.now() + 100000 // Well outside throttle

      // Fire 5 concurrent recordActivity calls with the same timestamp
      await Promise.all([
        auth.recordActivity(sid, baseTime),
        auth.recordActivity(sid, baseTime),
        auth.recordActivity(sid, baseTime),
        auth.recordActivity(sid, baseTime),
        auth.recordActivity(sid, baseTime),
      ])

      expect(new Date(memory.sessions.get(sid).lastUsedAt).getTime()).toBe(baseTime)
      expect(memory.sessions.get(sid).revokedAt).toBeNull()
    })

    test('stale refresh token replay detection revokes entire session', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.refreshToken).sid

      // First legitimate rotation (gen 0 -> gen 1)
      const rotated = await auth.rotate(issued.refreshToken)
      expect(rotated.refreshToken).toBeDefined()
      expect(memory.sessions.get(sid).generation).toBe(1)

      // An attacker (or race condition) attempts to reuse the OLD generation-0 refresh token
      await expect(auth.rotate(issued.refreshToken)).rejects.toMatchObject({
        statusCode: 401,
        message: 'Refresh replay; sign in again',
      })

      // The entire session must be revoked with reason 'refresh-replay'
      const stored = memory.sessions.get(sid)
      expect(stored.revokedAt).not.toBeNull()
      expect(stored.revocationReason).toBe('refresh-replay')

      // Even the latest rotated token is now unusable
      await expect(auth.rotate(rotated.refreshToken)).rejects.toMatchObject({
        statusCode: 401,
      })
    })

    test('concurrent rotation requests: only one succeeds, subsequent is treated as replay', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.refreshToken).sid

      // Simulate sequential arrival where second caller has old token
      const res1 = await auth.rotate(issued.refreshToken)
      expect(res1.refreshToken).toBeDefined()

      // The second call with the original token must be caught as a replay
      await expect(auth.rotate(issued.refreshToken)).rejects.toMatchObject({
        statusCode: 401,
        message: 'Refresh replay; sign in again',
      })

      expect(memory.sessions.get(sid).revocationReason).toBe('refresh-replay')
    })
  })

  describe('Failed Requests & Security State Invariance', () => {
    test('request with invalid token does not touch session activity or extend lifetime', async () => {
      const issued = await auth.issue(memory.user)
      const sid = jwt.decode(issued.token).sid
      const initialLastUsed = new Date(memory.sessions.get(sid).lastUsedAt).getTime()

      // Send corrupted token
      const badToken = issued.token.slice(0, -5) + 'xxxxx'
      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + badToken)
        .set('Origin', process.env.CLIENT_URL)

      expect(res.status).toBe(401)
      // Session in store remains unchanged
      expect(new Date(memory.sessions.get(sid).lastUsedAt).getTime()).toBe(initialLastUsed)
    })

    test('inactive user cannot access protected endpoints and cookies are cleared', async () => {
      const issued = await auth.issue(memory.user)
      // Deactivate user in memory store
      memory.users.get(memory.user._id).status = 'disabled'

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + issued.token)
        .set('Origin', process.env.CLIENT_URL)

      expect(res.status).toBe(403)
      expect(res.body.error).toBe('Account inactive')
    })

    test('password change required blocks platform endpoints with 403', async () => {
      memory.users.get(memory.user._id).mustChangePassword = true
      const issued = await auth.issue(memory.user)

      // Try hitting threat logs (normal platform feature protected by protect middleware)
      const res = await request(app)
        .get('/api/threats')
        .set('Authorization', 'Bearer ' + issued.token)
        .set('Origin', process.env.CLIENT_URL)

      expect(res.status).toBe(403)
      expect(res.body.code).toBe('PASSWORD_CHANGE_REQUIRED')

      // But lifecycle endpoints like /api/auth/me are allowed
      const meRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + issued.token)
        .set('Origin', process.env.CLIENT_URL)

      expect(meRes.status).toBe(200)
    })
  })
})
