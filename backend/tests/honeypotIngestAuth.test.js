'use strict'
/**
 * Honeypot ingest boundary (Phase 4): L8 only the honeypot key is accepted (not the AI engine's SENTINEL_KEY),
 * H3 the key can be bound to the honeypot host's address, L4 the blocker's deny-list poll is the node heartbeat.
 */
process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-session-tests'
process.env.HONEYPOT_API_KEY = 'test-honeypot-api-key'
process.env.SENTINEL_KEY = 'test-sentinel-api-key'

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/BlockedIP', () => ({
  find: jest.fn(() => ({ lean: async () => [{ ip: '203.0.113.9' }] })),
  findOne: jest.fn().mockResolvedValue(null),
}))
jest.mock('../models/HoneypotSession', () => ({ countDocuments: jest.fn().mockResolvedValue(0) }))

const request = require('supertest')
const { app } = require('../server')
const heartbeat = require('../services/honeypotHeartbeat')
const honeypotService = require('../services/honeypotService')

const checkBlock = (key) => {
  const req = request(app).get('/api/honeypot/ingest/check-block')
  return key ? req.set('x-api-key', key) : req
}

describe('honeypot ingest authentication', () => {
  beforeEach(() => {
    delete process.env.HONEYPOT_ALLOWED_SOURCES
    heartbeat.reset()
  })

  test('L8: the AI engine key is refused on honeypot routes', async () => {
    expect((await checkBlock('test-sentinel-api-key')).status).toBe(401)
    const res = await request(app)
      .post('/api/honeypot/ingest/command')
      .set('x-api-key', 'test-sentinel-api-key')
      .send({ sessionId: 's', sourceIP: '192.0.2.1', command: 'id' })
    expect(res.status).toBe(401)
    expect((await checkBlock('test-honeypot-api-key')).status).toBe(200)
  })

  test.each([
    ['exact address', '127.0.0.1', 200],
    ['IPv4-mapped form', '::ffff:127.0.0.1', 200],
    ['CIDR', '127.0.0.0/8', 200],
    ['list with a match', '10.0.0.1, 127.0.0.1', 200],
    ['other address', '10.9.9.9', 403],
    ['other CIDR', '10.0.0.0/8', 403],
  ])('H3: HONEYPOT_ALLOWED_SOURCES %s -> %i', async (_label, rule, status) => {
    process.env.HONEYPOT_ALLOWED_SOURCES = rule
    const res = await checkBlock('test-honeypot-api-key')
    expect(res.status).toBe(status)
    if (status === 403) expect(res.body.error).toBe('Honeypot key not accepted from this address')
  })

  test('H3: a refused source does not count as a heartbeat', async () => {
    process.env.HONEYPOT_ALLOWED_SOURCES = '10.9.9.9'
    await checkBlock('test-honeypot-api-key')
    expect(heartbeat.status().liveness).toBe('unknown')
  })

  test('L4: node liveness follows the blocker poll, not attacker sessions', async () => {
    let [node] = await honeypotService.getNodeStatus()
    expect(node).toMatchObject({ name: 'SSH-COWRIE-01', status: 'unknown', liveness: 'unknown', lastSeen: null })
    await checkBlock('test-honeypot-api-key')
    ;[node] = await honeypotService.getNodeStatus()
    expect(node).toMatchObject({ status: 'active', liveness: 'online', sessionsToday: 0 })
    ;[node] = await honeypotService.getNodeStatus(new Date(Date.now() + 120 * 1000))
    expect(node).toMatchObject({ status: 'offline', liveness: 'offline' })
  })
})
