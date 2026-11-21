'use strict'
// M1: routine network-flow predictions expire (TTL on expireAt); everything an analyst or a threat relies on is kept.
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-prediction-retention'
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
require('../models/User') // verifyPrediction populates verifiedBy
const aiEngineService = require('../services/aiEngineService')
const aiService = require('../services/aiService')

let server
const DAY = 24 * 3600 * 1000
const flow = (over = {}) => ({
  inputSource: 'network_traffic',
  sourceIP: '198.51.100.7',
  predictedClass: 'BENIGN',
  threatScore: 0.02,
  modelVersion: 'xgb_cicids_v1',
  action: 'ALLOW',
  ...over,
})

beforeAll(async () => {
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri())
  await AIPrediction.syncIndexes()
})
afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})
beforeEach(() => {
  jest.spyOn(aiEngineService, 'getAlertThreshold').mockResolvedValue(0.9)
  jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.92)
  delete process.env.PREDICTION_RETENTION_DAYS
})
afterEach(async () => {
  jest.restoreAllMocks()
  await AIPrediction.deleteMany({})
  await ThreatLog.deleteMany({})
})

test('the TTL index exists and deletes at expireAt', async () => {
  const ttl = (await AIPrediction.collection.indexes()).find((i) => i.key.expireAt === 1)
  expect(ttl).toMatchObject({ expireAfterSeconds: 0 })
})

test('a routine benign flow expires after 30 days by default', async () => {
  const before = Date.now()
  const p = await aiService.storePrediction(flow())
  const stored = await AIPrediction.findById(p._id).lean()
  expect(stored.expireAt.getTime()).toBeGreaterThanOrEqual(before + 30 * DAY - 1000)
  expect(stored.expireAt.getTime()).toBeLessThanOrEqual(Date.now() + 30 * DAY + 1000)
})

test('PREDICTION_RETENTION_DAYS sets the period; 0 keeps every prediction', async () => {
  process.env.PREDICTION_RETENTION_DAYS = '7'
  const seven = await aiService.storePrediction(flow())
  expect((await AIPrediction.findById(seven._id).lean()).expireAt.getTime()).toBeLessThan(Date.now() + 8 * DAY)
  process.env.PREDICTION_RETENTION_DAYS = '0'
  const kept = await aiService.storePrediction(flow())
  expect((await AIPrediction.findById(kept._id).lean()).expireAt).toBeUndefined()
})

test('kept: a prediction that created a threat, one in the review queue, and honeypot predictions', async () => {
  const threat = await aiService.storePrediction(flow({ predictedClass: 'DDoS', threatScore: 0.95, action: 'MONITOR' }))
  const review = await aiService.storePrediction(
    flow({ predictedClass: 'Unknown', threatScore: 0.55, action: 'REVIEW' })
  )
  const honeypot = await aiService.storePrediction(flow({ inputSource: 'honeypot_log', action: 'ALLOW' }))
  for (const p of [threat, review, honeypot])
    expect((await AIPrediction.findById(p._id).lean()).expireAt).toBeUndefined()
  expect(await ThreatLog.countDocuments({})).toBe(1)
})

test('verifying a prediction removes its expiry', async () => {
  jest.spyOn(require('../services/trainingSampleService'), 'syncPredictionToQuarantine').mockResolvedValue()
  const p = await aiService.storePrediction(flow())
  expect((await AIPrediction.findById(p._id).lean()).expireAt).toBeInstanceOf(Date)
  await aiService.verifyPrediction(p._id, new mongoose.Types.ObjectId(), 'BENIGN')
  const stored = await AIPrediction.findById(p._id).lean()
  expect(stored.verified).toBe(true)
  expect(stored.expireAt).toBeUndefined()
})
