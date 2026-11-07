process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'test-health-access-secret-0123456789'
process.env.JWT_REFRESH_SECRET = 'test-health-refresh-secret-0123456789'
process.env.HONEYPOT_API_KEY = 'test-health-honeypot-secret-0123456789'
process.env.SENTINEL_KEY = 'test-health-sentinel-secret-0123456789'
/**
 * F-03: GET /health is a strict "every dependency healthy" check, so it answered 503 whenever only the AI engine was
 * down although the backend keeps serving safely in degraded mode (threats held as MONITOR, never blocked). An
 * orchestrator using it as a liveness probe would restart a working backend. Added:
 *   GET /health/live   process up and answering (no dependency checks)
 *   GET /health/ready  can serve requests: MongoDB and revocation delivery required; the AI engine reported, optional
 * GET /health is unchanged for existing consumers (integration harness, native readiness scripts).
 */
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), getStats: jest.fn() }))
const mockAi = { getHealth: jest.fn() }
jest.mock('../services/aiEngineService', () => mockAi)

const request = require('supertest')
const mongoose = require('mongoose')
const { app, revocationDelivery } = require('../server')

const state = (db, ai, revocation) => {
  mongoose.connection.readyState = db ? 1 : 0 // same stub as roleMatrix.test.js (readyState has a setter)
  mockAi.getHealth.mockResolvedValue(ai ? { status: 'ok' } : { status: 'unreachable', error: 'down' })
  jest.spyOn(revocationDelivery, 'available').mockReturnValue(revocation)
}
afterEach(() => jest.restoreAllMocks())

test('all dependencies healthy: live 200, ready 200 "ready", /health 200', async () => {
  state(true, true, true)
  expect((await request(app).get('/health/live')).status).toBe(200)
  const ready = await request(app).get('/health/ready')
  expect(ready.status).toBe(200)
  expect(ready.body).toMatchObject({
    status: 'ready',
    dependencies: { database: 'connected', aiEngine: 'available', revocation: 'available' },
  })
  expect((await request(app).get('/health')).status).toBe(200)
})

test('AI engine down: still ready (degraded), still alive; strict /health keeps answering 503', async () => {
  state(true, false, true)
  const live = await request(app).get('/health/live')
  expect(live.status).toBe(200)
  expect(live.body.status).toBe('alive')
  const ready = await request(app).get('/health/ready')
  expect(ready.status).toBe(200)
  expect(ready.body).toMatchObject({ status: 'degraded', dependencies: { aiEngine: 'unavailable' } })
  expect((await request(app).get('/health')).status).toBe(503)
})

test('MongoDB down: not ready (503), but alive so the process is not restarted for a database outage', async () => {
  state(false, true, true)
  expect((await request(app).get('/health/live')).status).toBe(200)
  const ready = await request(app).get('/health/ready')
  expect(ready.status).toBe(503)
  expect(ready.body).toMatchObject({ status: 'unavailable', dependencies: { database: 'disconnected' } })
})

test('revocation delivery unavailable: not ready (sessions cannot be checked safely)', async () => {
  state(true, true, false)
  const ready = await request(app).get('/health/ready')
  expect(ready.status).toBe(503)
  expect(ready.body.dependencies.revocation).toBe('unavailable')
})

test('recovery: once MongoDB is back the backend is ready again', async () => {
  state(false, true, true)
  expect((await request(app).get('/health/ready')).status).toBe(503)
  jest.restoreAllMocks()
  state(true, true, true)
  expect((await request(app).get('/health/ready')).status).toBe(200)
})

test('liveness never calls a dependency, and no endpoint reports versions or error details', async () => {
  state(true, false, true)
  mockAi.getHealth.mockClear()
  const live = await request(app).get('/health/live')
  expect(mockAi.getHealth).not.toHaveBeenCalled()
  const ready = await request(app).get('/health/ready')
  for (const body of [live.body, ready.body]) {
    expect(JSON.stringify(body)).not.toMatch(/down|error|version|mongodb:\/\//i)
  }
})
