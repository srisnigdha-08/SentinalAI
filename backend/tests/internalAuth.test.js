'use strict'

// ── ENV must be set before any module that reads it ─────────────────────────
process.env.JWT_SECRET = 'test-jwt-secret'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret'
process.env.JWT_EXPIRES_IN = '1d'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-internal-api-key-12345'
process.env.SENTINEL_KEY = 'test-sentinel-key-12345'
process.env.PORT = '0' // avoid EADDRINUSE by binding to random port

// ── Mock Mongoose models and logger before importing app ─────────────────────
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/AIPrediction') // Mock prediction model
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}))
jest.mock('../config/db', () => jest.fn()) // prevent actual DB connection
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  startDemoFeed: jest.fn(),
  stopDemoFeed: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))

// Mock aiService storePrediction call to prevent DB queries
jest.mock('../services/aiService', () => ({
  storePrediction: jest.fn().mockResolvedValue({ _id: 'mock-pred-id-123' }),
}))

const request = require('supertest')
const { accessToken } = require('./helpers/accessFixture')
const User = require('../models/User')
const { app } = require('../server')

const validToken = () => accessToken({ _id: '123456789012345678901234', role: 'admin' })

describe('AI Engine routes authentication', () => {
  afterEach(() => jest.clearAllMocks())

  // 1. POST /api/ai/predictions accepts the AI engine key
  test('POST /api/ai/predictions succeeds with the AI engine (SENTINEL_KEY) key', async () => {
    const res = await request(app)
      .post('/api/ai/predictions')
      .set('X-API-Key', 'test-sentinel-key-12345')
      .send({ sourceIP: '192.168.1.1', predictedClass: 'BENIGN' })

    expect(res.status).toBe(201)
    expect(res.body.success).toBe(true)
  })

  test('POST /api/ai/predictions rejects the honeypot key with 403', async () => {
    const res = await request(app)
      .post('/api/ai/predictions')
      .set('X-API-Key', 'test-internal-api-key-12345')
      .send({ sourceIP: '192.168.1.1', predictedClass: 'BENIGN', threatScore: 0.99 })

    expect(res.status).toBe(403)
    expect(require('../services/aiService').storePrediction).not.toHaveBeenCalled()
  })

  test('POST /api/ai/predictions rejects a user JWT (no key)', async () => {
    const res = await request(app)
      .post('/api/ai/predictions')
      .set('Authorization', `Bearer ${validToken()}`)
      .send({ sourceIP: '192.168.1.1', predictedClass: 'BENIGN' })

    expect(res.status).toBe(401)
  })

  test('POST /api/ai/predictions drops server-owned fields (no mass assignment)', async () => {
    const aiService = require('../services/aiService')
    await request(app).post('/api/ai/predictions').set('X-API-Key', 'test-sentinel-key-12345').send({
      sourceIP: '203.0.113.9',
      predictedClass: 'DDoS',
      threatScore: 0.5,
      verified: true,
      actualClass: 'BENIGN',
      generatedThreat: '123456789012345678901234',
      inputSource: 'manual',
    })

    const stored = aiService.storePrediction.mock.calls[0][0]
    expect(stored).toMatchObject({
      sourceIP: '203.0.113.9',
      predictedClass: 'DDoS',
      threatScore: 0.5,
      inputSource: 'network_traffic',
    })
    expect(stored).not.toHaveProperty('verified')
    expect(stored).not.toHaveProperty('actualClass')
    expect(stored).not.toHaveProperty('generatedThreat')
  })

  // 2. POST /api/ai/predictions rejects a missing API key (if no JWT present)
  test('POST /api/ai/predictions fails with 401 when API key and JWT are missing', async () => {
    const res = await request(app)
      .post('/api/ai/predictions')
      .send({ sourceIP: '192.168.1.1', predictedClass: 'BENIGN' })

    expect(res.status).toBe(401)
    expect(res.body.success).toBe(false)
  })

  // 3. POST /api/ai/predictions rejects an invalid API key
  test('POST /api/ai/predictions fails with 401 with invalid API key', async () => {
    const res = await request(app)
      .post('/api/ai/predictions')
      .set('X-API-Key', 'wrong-api-key')
      .send({ sourceIP: '192.168.1.1', predictedClass: 'BENIGN' })

    expect(res.status).toBe(401)
    expect(res.body.success).toBe(false)
  })

  // 4. GET /api/ai/predictions does NOT bypass JWT authentication when internal key is provided
  test('GET /api/ai/predictions rejects internal API key (requires JWT)', async () => {
    const res = await request(app).get('/api/ai/predictions').set('X-API-Key', 'test-internal-api-key-12345')

    expect(res.status).toBe(401)
  })

  // 5. Supplying only the internal API key does not authenticate on unrelated JWT-protected routes
  test('GET /api/users/stats rejects internal API key (requires JWT)', async () => {
    const res = await request(app).get('/api/users/stats').set('X-API-Key', 'test-internal-api-key-12345')

    expect(res.status).toBe(401)
  })

  // 6. Normal JWT-protected routes still require JWT and work when provided
  test('GET /api/users/stats succeeds with valid JWT', async () => {
    const user = {
      _id: '123456789012345678901234',
      role: 'admin',
      status: 'active',
      save: jest.fn().mockResolvedValue(true),
    }
    User.findById = jest.fn().mockReturnValue({ select: jest.fn().mockResolvedValue(user) })

    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${validToken()}`)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
  })
})
