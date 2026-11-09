'use strict'
/**
 * GET /api/threats search is an unanchored, case-insensitive match over three fields, so a search with few matches
 * scans the collection (443 ms at 100,000 documents, measured). These tests pin the existing search behaviour, then
 * prove the time limit using MongoDB's own timeout failpoint on a disposable server: a real server-side timeout.
 */
const mongoose = require('mongoose')
const request = require('supertest')
const express = require('express')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({ getBlockThreshold: jest.fn() }))
jest.mock('../services/containmentService', () => ({}))
jest.mock('../websocket/socketManager', () => ({}))

require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const { getThreats } = require('../controllers/threatController')
const { errorHandler } = require('../middleware/errorHandler')

const app = express()
app.get(
  '/threats',
  (req, _res, next) => {
    req.user = { role: 'analyst' }
    next()
  },
  getThreats
)
app.use(errorHandler)

let mongo
const admin = () => mongoose.connection.db.admin()
const timeoutFailpoint = (mode) => admin().command({ configureFailPoint: 'maxTimeAlwaysTimeOut', mode })

beforeAll(async () => {
  mongo = await MongoMemoryServer.create({ instance: { args: ['--setParameter', 'enableTestCommands=1'] } })
  await mongoose.connect(mongo.getUri('search_limits'))
  await ThreatLog.create([
    { sourceIP: '198.51.100.7', attackType: 'DDoS', severity: 'HIGH', status: 'DETECTED', targetService: 'web' },
    { sourceIP: '203.0.113.9', attackType: 'Port Scan', severity: 'LOW', status: 'DETECTED', targetService: 'ssh' },
    {
      sourceIP: '192.0.2.5',
      attackType: 'SQL Injection',
      severity: 'HIGH',
      status: 'RESOLVED',
      targetService: 'db.api',
    },
  ])
})
afterAll(async () => {
  await timeoutFailpoint('off').catch(() => {})
  await mongoose.disconnect()
  await mongo.stop()
})
afterEach(() => timeoutFailpoint('off'))

const search = (q) => request(app).get('/threats').query(q)

describe('existing search behaviour is unchanged', () => {
  test.each([
    ['sourceIP substring', '51.100', 1],
    ['attackType, case-insensitive', 'ddos', 1],
    ['targetService', 'ssh', 1],
    ['matches nothing', 'nothing-here', 0],
  ])('%s', async (_label, value, count) => {
    const r = await search({ search: value })
    expect(r.status).toBe(200)
    expect(r.body.data).toHaveLength(count)
    expect(r.body.pagination.total).toBe(count)
  })

  test('regex characters are literal', async () => {
    expect((await search({ search: '.*' })).body.data).toHaveLength(0)
    expect((await search({ search: 'db.api' })).body.data).toHaveLength(1)
  })

  test('combines with filters and keeps the response shape', async () => {
    const r = await search({ search: '19', severity: 'high', page: 1, limit: 1 })
    expect(r.status).toBe(200)
    expect(Object.keys(r.body).sort()).toEqual(['data', 'pagination', 'success', 'timestamp'])
    expect(r.body.pagination).toMatchObject({ total: 2, page: 1, limit: 1, pages: 2 })
  })

  test('a blank or non-string search is no search', async () => {
    expect((await search({ search: '   ' })).body.data).toHaveLength(3)
    expect((await search({ 'search[$ne]': 'x' })).body.data).toHaveLength(3)
  })
})

describe('slow searches are bounded', () => {
  test('a search that exceeds the limit answers 422 with guidance, not a hang or a 500', async () => {
    await timeoutFailpoint('alwaysOn')
    const r = await search({ search: 'ddos' })
    expect(r.status).toBe(422)
    expect(r.body).toMatchObject({ success: false, error: expect.stringMatching(/took too long/i), code: 422 })
    expect(JSON.stringify(r.body)).not.toMatch(/maxTime|MongoServerError|operation exceeded/i)
  })

  test('listing without a search carries no limit', async () => {
    await timeoutFailpoint('alwaysOn')
    const r = await search({})
    expect(r.status).toBe(200)
    expect(r.body.data).toHaveLength(3)
  })

  test('other database errors are still reported as server errors', async () => {
    const spy = jest.spyOn(ThreatLog, 'countDocuments').mockRejectedValueOnce(new Error('connection reset'))
    const r = await search({ search: 'ddos' })
    spy.mockRestore()
    expect(r.status).toBe(500)
    expect(r.body.error).toBe('Internal server error')
  })
})
