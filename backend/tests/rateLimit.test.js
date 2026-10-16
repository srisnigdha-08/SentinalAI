'use strict'
/**
 * tests/rateLimit.test.js
 *
 * Verifies that the global rate limiter cannot be bypassed using arbitrary or invalid
 * Authorization headers, while legitimate internal service API keys are correctly skipped.
 */

// Configure environment with low rate limit threshold before importing app
process.env.RATE_LIMIT_WINDOW_MS = '60000'
process.env.RATE_LIMIT_MAX = '5'
process.env.JWT_SECRET = 'test-jwt-secret'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret'
process.env.JWT_EXPIRES_IN = '1d'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-honeypot-key-xyz'
process.env.SENTINEL_KEY = 'test-sentinel-key-xyz'
process.env.PORT = '0'

// Mock Mongoose models and logger
jest.mock('../models/User')
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}))
jest.mock('../config/db', () => jest.fn())
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  startDemoFeed: jest.fn(),
  stopDemoFeed: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))

const request = require('supertest')
const { app } = require('../server')

describe('Global Rate Limiter (Phase 1.1)', () => {
  afterEach(() => jest.clearAllMocks())

  test('blocks requests when threshold is exceeded even if an invalid Authorization header is present', async () => {
    // RATE_LIMIT_MAX is set to 5.
    // Send 5 requests with an arbitrary/invalid Authorization header.
    for (let i = 0; i < 5; i++) {
      const res = await request(app).get('/api/ws/stats').set('Authorization', 'Bearer invalid-token-bypass-attempt')
      expect(res.status).not.toBe(429)
    }

    // The 6th request must be blocked by the rate limiter with 429 Too Many Requests
    const blockedRes = await request(app)
      .get('/api/ws/stats')
      .set('Authorization', 'Bearer invalid-token-bypass-attempt')

    expect(blockedRes.status).toBe(429)
    expect(blockedRes.body.success).toBe(false)
    expect(blockedRes.body.error).toMatch(/too many requests/i)
  })

  test('allows internal services with valid X-API-Key to skip rate limiting', async () => {
    // Send 7 requests with valid internal API key - none should be blocked by rate limit
    for (let i = 0; i < 7; i++) {
      const res = await request(app).get('/api/ws/stats').set('X-API-Key', 'test-honeypot-key-xyz')
      expect(res.status).not.toBe(429)
    }
  })
})
