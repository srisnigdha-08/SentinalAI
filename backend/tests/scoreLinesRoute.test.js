'use strict'
/**
 * THR-003: the dashboard coloured and filtered scores at fixed 0.90/0.92 while the backend raises and blocks at the
 * engine's ALERT_THRESHOLD/BLOCK_THRESHOLD. GET /api/ai/score-lines tells every signed-in role which lines the
 * backend is using, falling back to the defaults while the engine is unreachable.
 */
const express = require('express')
const request = require('supertest')

jest.mock('../middleware/auth', () => ({
  protect: (req, res, next) =>
    req.headers.authorization ? ((req.user = { role: 'viewer' }), next()) : res.status(401).json({ success: false }),
  restrictTo: () => (req, res, next) => next(),
  requirePermission: () => (req, res, next) => next(),
}))
const mockEngine = { getScoreLines: jest.fn() }
jest.mock('../services/aiEngineService', () => mockEngine)

const app = express().use('/api/ai', require('../routes/aiEngine'))
const get = () => request(app).get('/api/ai/score-lines').set('Authorization', 'Bearer t')

test('returns the lines the backend scores with (an engine started with ALERT_THRESHOLD=0.80)', async () => {
  mockEngine.getScoreLines.mockResolvedValue({ alert: 0.8, block: 0.85, source: 'engine', confirmedAt: null })
  const res = await get()
  expect(res.status).toBe(200)
  expect(res.body.data).toMatchObject({ alert: 0.8, block: 0.85, source: 'engine' })
})

test('defaults are returned unchanged when the engine was never reached', async () => {
  mockEngine.getScoreLines.mockResolvedValue({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null })
  expect((await get()).body.data).toEqual({ alert: 0.9, block: 0.92, source: 'default', confirmedAt: null })
})

test('requires a signed-in user', async () => {
  expect((await request(app).get('/api/ai/score-lines')).status).toBe(401)
})
