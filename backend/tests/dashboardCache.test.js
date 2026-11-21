'use strict'
// M2: dashboard analytics cache (services/threatService.js) on a disposable in-memory MongoDB.
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const ThreatLog = require('../models/ThreatLog')
const svc = require('../services/threatService')

let server
const threat = (over = {}) => ({
  severity: 'HIGH',
  sourceIP: '203.0.113.10',
  attackType: 'DDoS',
  status: 'MONITORING',
  aiScore: 0.95,
  ...over,
})

beforeAll(async () => {
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})
beforeEach(async () => {
  await ThreatLog.deleteMany({})
  svc.resetDashboardCache()
  process.env.DASHBOARD_CACHE_MS = '60000'
})
afterEach(() => {
  jest.restoreAllMocks()
  delete process.env.DASHBOARD_CACHE_MS
})

test('within the window the figures are computed once, also for concurrent requests', async () => {
  await ThreatLog.create(threat())
  const spy = jest.spyOn(ThreatLog, 'aggregate')
  const results = await Promise.all([svc.getDashboardAnalytics(), svc.getDashboardAnalytics()])
  const callsAfterFirst = spy.mock.calls.length
  await svc.getDashboardAnalytics()
  expect(spy.mock.calls.length).toBe(callsAfterFirst) // no new aggregation
  expect(results[0].kpis.totalAllTime).toBe(1)
})

test('each caller gets its own copy: redacting one response does not change the next', async () => {
  await ThreatLog.create(threat())
  const first = await svc.getDashboardAnalytics()
  first.intelligence.topSourceIPs[0]._id = '203.0.113.xxx' // what the controller does for viewers
  const second = await svc.getDashboardAnalytics()
  expect(second.intelligence.topSourceIPs[0]._id).toBe('203.0.113.10')
})

test('a new threat shows up once the window has passed; DASHBOARD_CACHE_MS=0 disables the cache', async () => {
  await ThreatLog.create(threat())
  expect((await svc.getDashboardAnalytics()).kpis.totalAllTime).toBe(1)
  await ThreatLog.create(threat({ sourceIP: '203.0.113.11' }))
  expect((await svc.getDashboardAnalytics()).kpis.totalAllTime).toBe(1) // cached
  process.env.DASHBOARD_CACHE_MS = '0'
  expect((await svc.getDashboardAnalytics()).kpis.totalAllTime).toBe(2)
})

test('an explicit time is never served from the cache', async () => {
  await svc.getDashboardAnalytics()
  const spy = jest.spyOn(ThreatLog, 'aggregate')
  await svc.getDashboardAnalytics(new Date())
  expect(spy).toHaveBeenCalled()
})

test('a failed computation is not cached', async () => {
  const spy = jest.spyOn(ThreatLog, 'countDocuments').mockRejectedValueOnce(new Error('db down'))
  await expect(svc.getDashboardAnalytics()).rejects.toThrow('db down')
  spy.mockRestore()
  await ThreatLog.create(threat())
  expect((await svc.getDashboardAnalytics()).kpis.totalAllTime).toBe(1)
})
