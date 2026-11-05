'use strict'
/**
 * THR-004: GET /api/ai/score-lines returned the same { alert, block } whether the values were confirmed by the AI
 * engine, last-confirmed values kept through an outage, or defaults because the engine was never reached. The
 * dashboard (and an operator) could not tell them apart. getScoreLines() now reports the source and when the engine
 * last confirmed them; the values themselves and their fallbacks are unchanged.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'score-lines-source-test-key-0123456789' // secret-scan: allow (test placeholder)

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const load = (get) => {
  let svc
  jest.isolateModules(() => {
    jest.doMock('axios', () => ({
      create: () => ({ get, post: jest.fn(), interceptors: { request: { use: jest.fn() } } }),
    }))
    svc = jest.requireActual('../services/aiEngineService')
  })
  return svc
}

test('engine never reached: defaults, reported as such', async () => {
  const svc = load(jest.fn().mockRejectedValue(new Error('ECONNREFUSED')))
  await expect(svc.getScoreLines()).resolves.toEqual({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null })
})

test('engine reachable: its own (overridden) lines, reported as confirmed', async () => {
  const svc = load(jest.fn().mockResolvedValue({ data: { thresholds: { monitor: 0.8, block: 0.85 } } }))
  const lines = await svc.getScoreLines()
  expect(lines).toMatchObject({ alert: 0.8, block: 0.85, source: 'engine' })
  expect(lines.confirmedAt).toBeInstanceOf(Date)
})

test('engine down after a confirmation: last confirmed lines, reported as cached, values unchanged', async () => {
  const get = jest
    .fn()
    .mockResolvedValueOnce({ data: { thresholds: { monitor: 0.8, block: 0.85 } } })
    .mockRejectedValue(new Error('ECONNREFUSED'))
  const svc = load(get)
  const first = await svc.getScoreLines()
  svc.invalidateThresholds() // the next call goes to the engine (as after a reload), which is now down
  const second = await svc.getScoreLines()
  expect(second).toMatchObject({ alert: 0.8, block: 0.85, source: 'engine-cached' })
  expect(second.confirmedAt).toEqual(first.confirmedAt)
})

test('the route returns the source with the lines', async () => {
  const express = require('express')
  const request = require('supertest')
  let app
  jest.isolateModules(() => {
    jest.doMock('../middleware/auth', () => ({
      protect: (req, res, next) => ((req.user = { role: 'viewer' }), next()),
      restrictTo: () => (req, res, next) => next(),
      requirePermission: () => (req, res, next) => next(),
    }))
    jest.doMock('../services/aiEngineService', () => ({
      getScoreLines: jest.fn().mockResolvedValue({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null }),
    }))
    app = express().use('/api/ai', require('../routes/aiEngine'))
  })
  const res = await request(app).get('/api/ai/score-lines')
  expect(res.body.data).toEqual({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null })
})

// THR-005: after a backend restart the lines were fetched only on the first scored flow, so a containment restore
// before that used the 0.90 default even when the engine runs with another ALERT_THRESHOLD. warmScoreLines() runs at
// startup (server.js) and records the engine's line for those paths.
test('warmScoreLines records the engine line for restore paths; an unreachable engine leaves the defaults', async () => {
  let svc
  let severity
  jest.isolateModules(() => {
    const get = jest.fn().mockResolvedValue({ data: { thresholds: { monitor: 0.8, block: 0.85 } } })
    jest.doMock('axios', () => ({
      create: () => ({ get, post: jest.fn(), interceptors: { request: { use: jest.fn() } } }),
    }))
    svc = jest.requireActual('../services/aiEngineService')
    severity = jest.requireActual('../utils/severity')
  })
  expect(severity.currentAlertLine()).toBe(0.9) // before warm-up: the default
  await expect(svc.warmScoreLines()).resolves.toMatchObject({ alert: 0.8, source: 'engine' })
  expect(severity.currentAlertLine()).toBe(0.8)

  const down = load(jest.fn().mockRejectedValue(new Error('ECONNREFUSED')))
  await expect(down.warmScoreLines()).resolves.toMatchObject({ source: 'default' }) // never throws at startup
})

test('server startup warms the score lines', () => {
  const source = require('fs').readFileSync(require.resolve('../server'), 'utf8')
  expect(source).toMatch(/warmScoreLines\(\)/)
})
