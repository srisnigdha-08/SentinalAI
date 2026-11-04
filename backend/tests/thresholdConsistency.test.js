'use strict'
/**
 * THR-002: status fallbacks still used the pre-C2 0.70 line while threats are raised at the shared alert line
 * (0.90 by default, /model/info). A BLOCKED threat without a saved preBlockStatus (seeded or legacy rows) scored
 * 0.70-0.89 was restored as MONITORING on unblock/rollback/TTL expiry, a state the live pipeline never produces
 * below the alert line. Fallbacks now use the backend's current alert line.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const containment = require('../services/containmentService')
const severity = require('../utils/severity')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')

describe('restore fallback follows the alert line', () => {
  test.each([
    [0.69, 'DETECTED'],
    [0.7, 'DETECTED'],
    [0.85, 'DETECTED'],
    [0.89, 'DETECTED'],
    [0.9, 'MONITORING'],
    [0.91, 'MONITORING'],
    [0.92, 'MONITORING'],
    [0.99, 'MONITORING'],
  ])('score %s without preBlockStatus restores to %s', (score, expected) => {
    expect(severity.restoreStatusFor({ aiScore: score }, 0.9)).toBe(expected)
  })

  test('a saved preBlockStatus always wins', () => {
    expect(severity.restoreStatusFor({ aiScore: 0.5, preBlockStatus: 'ESCALATED' }, 0.9)).toBe('ESCALATED')
  })

  test('the line is what aiEngineService last read from /model/info, defaulting to 0.90', () => {
    expect(severity.DEFAULT_ALERT_THRESHOLD).toBe(0.9)
    expect(severity.DEFAULT_BLOCK_THRESHOLD).toBe(0.92)
    expect(severity.currentAlertLine()).toBe(0.9)
    severity.recordAlertLine(0.8) // an engine started with ALERT_THRESHOLD=0.80
    expect(severity.restoreStatusFor({ aiScore: 0.85 })).toBe('MONITORING')
    for (const bad of [Number.NaN, 0, 1.5, undefined]) severity.recordAlertLine(bad)
    expect(severity.currentAlertLine()).toBe(0.8) // invalid values are ignored
    severity.recordAlertLine(0.9)
  })

  test('this suite runs without SENTINEL_KEY: containment code never loads the AI engine client', () => {
    expect(process.env.SENTINEL_KEY).toBeUndefined()
    expect(require.cache[require.resolve('../services/aiEngineService')]).toBeUndefined()
  })
})

describe('containment paths restore seeded/legacy BLOCKED threats by the alert line', () => {
  const IP = '198.51.100.95'
  let mongo
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create()
    await mongoose.connect(mongo.getUri())
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await mongo.stop()
  })
  beforeEach(() => setContainmentAdapter(new MockContainmentAdapter()))
  afterEach(async () => {
    resetContainmentAdapter()
    await Promise.all([ThreatLog.deleteMany({}), BlockedIP.deleteMany({}), ContainmentAction.deleteMany({})])
  })

  // As utils/seed.js and pre-preBlockStatus records store them: BLOCKED, no preBlockStatus
  const seededBlocked = (aiScore) =>
    ThreatLog.create({ severity: 'HIGH', sourceIP: IP, attackType: 'DDoS', aiScore, status: 'BLOCKED' })

  test('Settings -> Unblock IP: 0.85 -> DETECTED, 0.95 -> MONITORING', async () => {
    const block = await BlockedIP.create({ ip: IP, reason: 'legacy', blockedAt: new Date() })
    const low = await seededBlocked(0.85)
    const high = await seededBlocked(0.95)
    // A legacy manual block tagged its threats with the BlockedIP id but saved no preBlockStatus
    await ThreatLog.updateMany({ _id: { $in: [low._id, high._id] } }, { $set: { containmentId: block._id } })
    await containment.unblockIPManual({ ip: IP })
    expect((await ThreatLog.findById(low._id)).status).toBe('DETECTED')
    expect((await ThreatLog.findById(high._id)).status).toBe('MONITORING')
  })

  test('TTL expiry restore: 0.85 -> DETECTED', async () => {
    const trigger = await ThreatLog.create({
      severity: 'CRITICAL',
      sourceIP: IP,
      attackType: 'DDoS',
      aiScore: 0.99,
      status: 'DETECTED',
    })
    await containment.executeAutoBlock({ threat: trigger, threatScore: 0.99 })
    const legacy = await seededBlocked(0.85)
    await ContainmentAction.collection.updateOne(
      { normalizedTarget: IP, enforcementStatus: 'ACTIVE' },
      { $set: { expiresAt: new Date(Date.now() - 60000) } }
    )
    expect((await new ContainmentReconciliationService().reconcileExpiredActions()).successful).toBe(1)
    expect((await ThreatLog.findById(legacy._id)).status).toBe('DETECTED')
    expect((await ThreatLog.findById(trigger._id)).status).toBe('DETECTED') // its own preBlockStatus
  })
})

describe('AI Analytics daily "threats" count uses the alert line', () => {
  let mongo
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create()
    await mongoose.connect(mongo.getUri())
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await mongo.stop()
  })

  test('predictions scored 0.85 are not counted as threats; 0.90 and 0.95 are', async () => {
    const AIPrediction = require('../models/AIPrediction')
    const base = { inputSource: 'network_traffic', sourceIP: '198.51.100.96', predictedClass: 'DDoS' }
    await AIPrediction.create([0.85, 0.9, 0.95].map((threatScore) => ({ ...base, threatScore })))
    const stats = await require('../services/aiService').getModelStats()
    const days = stats.charts.dailyPredictions
    expect(days.reduce((n, d) => n + d.count, 0)).toBe(3)
    expect(days.reduce((n, d) => n + d.threats, 0)).toBe(2)
  })
})
