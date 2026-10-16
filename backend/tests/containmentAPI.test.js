'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-containment-api'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-containment-api'
process.env.HONEYPOT_API_KEY = 'unit-honeypot-secret-for-containment-api'
process.env.SENTINEL_KEY = 'unit-sentinel-secret-for-containment-api'
process.env.CLIENT_URL = 'http://localhost:3000'

jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/ContainmentAction')
jest.mock('../models/BlockedIP')
jest.mock('../models/ThreatLog')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  stopHealthBroadcast: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitThreatUpdated: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))

const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const ContainmentAction = require('../models/ContainmentAction')
const { install } = require('./helpers/authMemoryStore')
const auth = require('../services/authSessionService')
const { app } = require('../server')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

let memory
let mockAdapter

function makeUser(data) {
  const doc = {
    _id: data._id || '507f1f77bcf86cd799439011',
    name: data.name || 'Test Analyst',
    email: data.email || 'analyst@sentinelai.local',
    password: data.password || 'CorrectPassword123',
    role: data.role || 'analyst',
    status: data.status || 'active',
    authVersion: data.authVersion ?? 0,
    ...(data.mustChangePassword !== undefined ? { mustChangePassword: data.mustChangePassword } : {}),
  }
  doc.toJSON = () => {
    const copy = { ...doc }
    delete copy.password
    return copy
  }
  doc.comparePassword = async (pwd) => pwd === (data.password || 'CorrectPassword123')
  doc.save = async () => {
    memory.users.set(doc._id, doc)
    return doc
  }
  memory.users.set(doc._id, doc)
  return doc
}

describe('Containment API & Authorization Boundary', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    memory = install(User, Session)
    mockAdapter = new MockContainmentAdapter()
    setContainmentAdapter(mockAdapter)
  })

  afterEach(() => {
    resetContainmentAdapter()
  })

  test('GET /api/containment/status returns 401 for unauthenticated requests', async () => {
    const res = await request(app).get('/api/containment/status')
    expect(res.status).toBe(401)
  })

  test('GET /api/containment/status returns 403 for viewer role', async () => {
    const viewer = makeUser({ _id: '507f1f77bcf86cd799439099', role: 'viewer', email: 'viewer@test.com' })
    const login = await auth.issue(viewer)

    const res = await request(app).get('/api/containment/status').set('Authorization', `Bearer ${login.token}`)

    expect(res.status).toBe(403)
  })

  test('GET /api/containment/status returns 403 for user with mustChangePassword === true', async () => {
    const restricted = makeUser({
      _id: '507f1f77bcf86cd799439088',
      role: 'analyst',
      email: 'restricted@test.com',
      mustChangePassword: true,
    })
    const login = await auth.issue(restricted)

    const res = await request(app).get('/api/containment/status').set('Authorization', `Bearer ${login.token}`)

    expect(res.status).toBe(403)
    expect(res.body.error).toMatch(/password change required/i)
  })

  test('GET /api/containment/status returns 200 with adapter details for authorized analyst', async () => {
    const analyst = makeUser({ _id: '507f1f77bcf86cd799439077', role: 'analyst', email: 'analyst@test.com' })
    const login = await auth.issue(analyst)

    ContainmentAction.countDocuments = jest.fn().mockResolvedValue(0)

    const res = await request(app).get('/api/containment/status').set('Authorization', `Bearer ${login.token}`)

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.backend).toBe('mock')
    expect(res.body.data.realEnforcementEnabled).toBe(false)
  })

  test('POST /api/containment/actions returns 403 when target violates self-lockout policy', async () => {
    const analyst = makeUser({ _id: '507f1f77bcf86cd799439077', role: 'analyst', email: 'analyst@test.com' })
    const login = await auth.issue(analyst)

    ContainmentAction.findOne = jest.fn().mockResolvedValue(null)

    // Attempt to block loopback 127.0.0.1
    const res = await request(app).post('/api/containment/actions').set('Authorization', `Bearer ${login.token}`).send({
      target: '127.0.0.1',
      reason: 'Attempted self-lockout',
    })

    expect(res.status).toBe(403)
    expect(res.body.error).toContain('policy rejected')
    expect(res.body.error).toContain('loopback')
  })

  test('POST /api/containment/actions returns 400 when target is missing or empty', async () => {
    const analyst = makeUser({ _id: '507f1f77bcf86cd799439077', role: 'analyst', email: 'analyst@test.com' })
    const login = await auth.issue(analyst)

    const res = await request(app).post('/api/containment/actions').set('Authorization', `Bearer ${login.token}`).send({
      target: '',
    })

    expect(res.status).toBe(400)
  })

  test('POST /api/containment/actions/:id/rollback returns 404 when action does not exist', async () => {
    const admin = makeUser({ _id: '507f1f77bcf86cd799439066', role: 'admin', email: 'admin@test.com' })
    const login = await auth.issue(admin)

    ContainmentAction.findOne = jest.fn().mockResolvedValue(null)

    const res = await request(app)
      .post('/api/containment/actions/non-existent-action/rollback')
      .set('Authorization', `Bearer ${login.token}`)
      .send({ reason: 'Rollback test' })

    expect(res.status).toBe(404)
    expect(res.body.error).toContain('not found')
  })
})
