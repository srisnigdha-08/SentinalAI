'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-session-tests'
process.env.HONEYPOT_API_KEY = 'test-honeypot-api-key'
process.env.SENTINEL_KEY = 'test-sentinel-api-key'

jest.mock('../models/HoneypotSession')
jest.mock('../models/ThreatLog')
jest.mock('../models/Alert')
jest.mock('../models/BlockedIP')
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  stopHealthBroadcast: jest.fn(),
  emitHoneypotEvent: jest.fn(),
  emitNewAlert: jest.fn(),
}))

const request = require('supertest')
const { app } = require('../server')
const HoneypotSession = require('../models/HoneypotSession')

describe('Phase 6E — Cowrie Telemetry Ingest & Hardening Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Ingest Validation & Security Boundaries', () => {
    test('rejects unauthenticated requests without API key', async () => {
      const res = await request(app).post('/api/honeypot/ingest').send({
        eventType: 'SESSION_OPENED',
        sessionId: 'cowrie-sess-1',
        sourceIP: '192.0.2.1',
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Missing API key')
    })

    test('rejects invalid API key', async () => {
      const res = await request(app).post('/api/honeypot/ingest').set('x-api-key', 'wrong-key').send({
        eventType: 'SESSION_OPENED',
        sessionId: 'cowrie-sess-1',
        sourceIP: '192.0.2.1',
      })
      expect(res.status).toBe(401)
      expect(res.body.error).toBe('Invalid API key')
    })

    test('rejects unsupported eventType', async () => {
      const res = await request(app).post('/api/honeypot/ingest').set('x-api-key', 'test-honeypot-api-key').send({
        eventType: 'ARBITRARY_ATTACK',
        sessionId: 'cowrie-sess-1',
        sourceIP: '192.0.2.1',
      })
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('Unsupported honeypot eventType')
    })

    test.each([{ $ne: null }, 'not-hex!', 'abc', 12345])('rejects a malformed eventId (%p)', async (eventId) => {
      const res = await request(app)
        .post('/api/honeypot/ingest/command')
        .set('x-api-key', 'test-honeypot-api-key')
        .send({
          sessionId: 'cowrie-sess-1',
          sourceIP: '192.0.2.1',
          command: 'id',
          eventId,
        })
      expect(res.status).toBe(400)
      expect(res.body.error).toBe('eventId must be a hex string')
    })

    test('rejects oversized commands exceeding 2048 chars', async () => {
      const hugeCommand = 'cat ' + 'a'.repeat(2500)
      const res = await request(app).post('/api/honeypot/ingest').set('x-api-key', 'test-honeypot-api-key').send({
        eventType: 'COMMAND_INPUT',
        sessionId: 'cowrie-sess-1',
        sourceIP: '192.0.2.1',
        command: hugeCommand,
      })
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/exceeds maximum of 2048 characters/)
    })

    test('rejects oversized download URLs exceeding 2048 chars', async () => {
      const hugeUrl = 'http://malware.invalid/' + 'x'.repeat(2100)
      const res = await request(app).post('/api/honeypot/ingest').set('x-api-key', 'test-honeypot-api-key').send({
        eventType: 'FILE_DOWNLOAD',
        sessionId: 'cowrie-sess-1',
        sourceIP: '192.0.2.1',
        url: hugeUrl,
      })
      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/exceeds maximum of 2048 characters/)
    })
  })

  describe('Telemetry Health & Status Verification', () => {
    test('reports status idle and liveTelemetry false when no daemon is active', async () => {
      // Mock countDocuments and findOne
      HoneypotSession.countDocuments = jest.fn().mockResolvedValue(0)
      HoneypotSession.findOne = jest.fn().mockReturnValue({
        sort: jest.fn().mockResolvedValue(null),
      })

      // Authenticate via mock token for protected route
      const jwt = require('jsonwebtoken')
      const token = jwt.sign(
        {
          id: '123456789012345678901234',
          sid: '11111111-2222-3333-4444-555555555555',
          av: 0,
          role: 'analyst',
          purpose: 'access',
          jti: 'a'.repeat(64),
        },
        process.env.JWT_SECRET,
        { algorithm: 'HS256', issuer: 'sentinelai', audience: 'sentinelai-browser' }
      )

      // Mock session load
      const auth = require('../services/authSessionService')
      jest.spyOn(auth, 'authorize').mockResolvedValue({
        user: { _id: '123456789012345678901234', role: 'analyst', status: 'active' },
        session: { _id: '11111111-2222-3333-4444-555555555555', lastUsedAt: new Date() },
      })

      const res = await request(app)
        .get('/api/honeypot/status')
        .set('Authorization', 'Bearer ' + token)

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(res.body.data.liveTelemetry).toBe(false)
      expect(res.body.data.status).toBe('idle')
      expect(res.body.data.liveTelemetryBlocked).toBe(true)
      expect(res.body.data.reason).toMatch(/No active Cowrie daemon/)
    })
  })
})
