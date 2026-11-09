'use strict'
/**
 * M3: storePrediction writes the prediction already linked to its threat, and unlinks it if the threat
 * write fails. M4: request_stats bursts are answered from a cached snapshot. M6: dashboard aggregates are
 * bounded to their reporting window.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-medium'
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/AIPrediction', () => ({
  create: jest.fn(),
  updateOne: jest.fn(),
  aggregate: jest.fn().mockResolvedValue([]),
  countDocuments: jest.fn().mockResolvedValue(0),
  estimatedDocumentCount: jest.fn().mockResolvedValue(0),
}))
jest.mock('../models/ThreatLog', () => ({ create: jest.fn(), countDocuments: jest.fn().mockResolvedValue(0) }))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn().mockResolvedValue(null) }))
jest.mock('../models/BlockedIP', () => ({}))
jest.mock('../services/alertService', () => ({ createAlert: jest.fn(), createAlertFromThreat: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.7),
}))

const AIPrediction = require('../models/AIPrediction')
const ThreatLog = require('../models/ThreatLog')
const aiService = require('../services/aiService')

describe('M3: prediction ↔ threat linking', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    AIPrediction.create.mockImplementation(async (p) => ({ _id: 'pred-1', ...p, save: jest.fn() }))
    AIPrediction.updateOne.mockReturnValue({ catch: () => Promise.resolve() })
  })

  test('the prediction is created already pointing at the threat id the threat is then created with', async () => {
    ThreatLog.create.mockImplementation(async (t) => ({ ...t }))
    const pred = await aiService.storePrediction({
      sourceIP: '198.51.100.9',
      predictedClass: 'DDoS',
      threatScore: 0.95,
    })
    const [predPayload] = AIPrediction.create.mock.calls[0]
    const [threatPayload] = ThreatLog.create.mock.calls[0]
    expect(predPayload.generatedThreat).toBeDefined()
    expect(String(threatPayload._id)).toBe(String(predPayload.generatedThreat))
    expect(threatPayload.predictionId).toBe('pred-1')
    expect(pred.save).not.toHaveBeenCalled() // no follow-up write that could fail and leave a half link
  })

  test('a failed threat write unlinks the prediction and propagates the error', async () => {
    ThreatLog.create.mockRejectedValue(new Error('write conflict'))
    await expect(
      aiService.storePrediction({ sourceIP: '198.51.100.9', predictedClass: 'DDoS', threatScore: 0.95 })
    ).rejects.toThrow('write conflict')
    expect(AIPrediction.updateOne).toHaveBeenCalledWith({ _id: 'pred-1' }, { $unset: { generatedThreat: 1 } })
  })

  test('low-score or BENIGN predictions are stored without a threat link', async () => {
    await aiService.storePrediction({ sourceIP: '198.51.100.9', predictedClass: 'BENIGN', threatScore: 0.1 })
    expect(AIPrediction.create.mock.calls[0][0].generatedThreat).toBeUndefined()
    expect(ThreatLog.create).not.toHaveBeenCalled()
  })
})

describe('M6: AI analytics aggregates are windowed', () => {
  test('every score/class/anomaly/latency aggregate starts with a createdAt window; total is O(1)', async () => {
    jest.clearAllMocks()
    const stats = await aiService.getModelStats(new Date('2026-10-21T10:00:00Z'))
    const pipelines = AIPrediction.aggregate.mock.calls.map(([p]) => p)
    const verified = pipelines.filter((p) => p[0].$match && p[0].$match.verified === true)
    const windowed = pipelines.filter((p) => p[0].$match && p[0].$match.createdAt)
    expect(verified).toHaveLength(1) // verified accuracy stays all-time
    expect(windowed).toHaveLength(pipelines.length - 1)
    expect(AIPrediction.estimatedDocumentCount).toHaveBeenCalled()
    expect(stats.reporting.analyticsWindow.days).toBe(30)
  })
})

describe('M4: request_stats throttle', () => {
  test('a burst triggers one set of counts; later requests get the cached snapshot', async () => {
    jest.resetModules()
    jest.doMock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
    const Threat = require('../models/ThreatLog')
    Threat.countDocuments.mockResolvedValue(3)
    const manager = require('../websocket/socketManager')
    let connect
    manager.init({ on: (_e, l) => (connect = l), engine: { clientsCount: 0 } })
    const handlers = {}
    const socket = { id: 'burst', user: { role: 'viewer' }, on: (e, h) => (handlers[e] = h), emit: jest.fn() }
    connect(socket)

    for (let i = 0; i < 10; i++) await handlers.request_stats()
    expect(Threat.countDocuments).toHaveBeenCalledTimes(3) // one snapshot = 3 counts
    const snapshots = socket.emit.mock.calls.filter(([e]) => e === 'stats_snapshot')
    expect(snapshots).toHaveLength(10)
    expect(new Set(snapshots.map(([, s]) => s.timestamp)).size).toBe(1)
    manager.stopHealthBroadcast()
  })
})
