'use strict'
/**
 * AI outage behaviour: degraded flows are still recorded, but only one SYSTEM_HEALTH alert is raised
 * per cooldown window, and the block-threshold lookup backs off instead of re-timing-out per call.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-for-backoff'
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/AIPrediction', () => ({ create: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({ create: jest.fn() }))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn().mockResolvedValue(null) }))
jest.mock('../models/BlockedIP', () => ({}))
jest.mock('../websocket/socketManager', () => ({
  emitNewThreat: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
}))
jest.mock('../services/alertService', () => ({
  createAlert: jest.fn().mockResolvedValue({ _id: 'alert-1' }),
  createAlertFromThreat: jest.fn(),
}))
jest.mock('../services/aiEngineService', () => ({
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.7),
}))

const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
const alertService = require('../services/alertService')
const aiService = require('../services/aiService')

const degraded = (ip) => ({
  sourceIP: ip,
  threatScore: 0.5,
  predictedClass: 'UNINSPECTED_TRAFFIC',
  status: 'UNAVAILABLE',
})

describe('degraded-mode alert de-duplication', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    aiService.resetDegradedAlertCooldown()
    AIPrediction.create.mockImplementation(async (p) => ({ _id: 'pred', ...p, save: jest.fn() }))
    ThreatLog.create.mockImplementation(async (t) => ({ _id: 'threat', ...t }))
  })

  test('every degraded flow is recorded, but only the first raises a system alert', async () => {
    for (let i = 0; i < 5; i++) await aiService.storePrediction(degraded(`198.51.100.${i + 1}`))

    expect(ThreatLog.create).toHaveBeenCalledTimes(5)
    expect(ThreatLog.create.mock.calls.every(([t]) => t.status === 'DEGRADED')).toBe(true)
    expect(alertService.createAlert).toHaveBeenCalledTimes(1)
    expect(alertService.createAlert.mock.calls[0][0]).toMatchObject({ type: 'SYSTEM_HEALTH' })
  })

  test('a new alert is raised once the cooldown has been reset (next outage window)', async () => {
    await aiService.storePrediction(degraded('198.51.100.1'))
    aiService.resetDegradedAlertCooldown()
    await aiService.storePrediction(degraded('198.51.100.2'))
    expect(alertService.createAlert).toHaveBeenCalledTimes(2)
  })
})

describe('getBlockThreshold back-off', () => {
  test('a failed fetch is not retried on every call within the cache window', async () => {
    const get = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    let svc
    jest.isolateModules(() => {
      jest.doMock('axios', () => ({ create: () => ({ get, post: jest.fn() }) }))
      svc = jest.requireActual('../services/aiEngineService')
    })

    await expect(svc.getBlockThreshold()).resolves.toBe(0.92)
    await expect(svc.getBlockThreshold()).resolves.toBe(0.92)
    await expect(svc.getBlockThreshold()).resolves.toBe(0.92)
    expect(get).toHaveBeenCalledTimes(1)
    expect(get.mock.calls[0][1]).toMatchObject({ timeout: 1500 })
  })

  test('a successful fetch updates the cached threshold', async () => {
    const get = jest.fn().mockResolvedValue({ data: { thresholds: { block: 0.95 } } })
    let svc
    jest.isolateModules(() => {
      jest.doMock('axios', () => ({ create: () => ({ get, post: jest.fn() }) }))
      svc = jest.requireActual('../services/aiEngineService')
    })
    await expect(svc.getBlockThreshold()).resolves.toBe(0.95)
    await expect(svc.getBlockThreshold()).resolves.toBe(0.95)
    expect(get).toHaveBeenCalledTimes(1)
  })
})
