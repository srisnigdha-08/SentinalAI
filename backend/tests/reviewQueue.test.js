'use strict'
/**
 * H5: flows the classifier calls BENIGN but the anomaly tier flags strongly come back from the engine as
 * predictedClass "Unknown", action "REVIEW". They are stored for analyst review (needsReview), listed by
 * GET /api/ai/predictions?review=true, never become threats, and leave the queue once verified.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-review-queue'
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitNewThreat: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
}))
jest.mock('../services/alertService', () => ({ createAlertFromThreat: jest.fn() }))
jest.mock('../services/threatIntelService', () => ({ enrichThreat: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/containmentService', () => ({ executeAutoBlock: jest.fn() }))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn().mockResolvedValue({ value: false }) }))

let created = null
const mockCreate = jest.fn().mockImplementation(async (payload) => {
  created = { ...payload }
  return { _id: 'pred-review-1', ...payload, save: jest.fn() }
})
const mockFind = jest.fn()
jest.mock('../models/AIPrediction', () => {
  const actual = jest.requireActual('../models/AIPrediction')
  actual.create = mockCreate
  actual.countDocuments = jest.fn().mockResolvedValue(0)
  actual.find = mockFind
  return actual
})
const mockThreatCreate = jest.fn()
jest.mock('../models/ThreatLog', () => ({ create: mockThreatCreate }))

const AIPrediction = require('../models/AIPrediction')
const aiService = require('../services/aiService')
const aiEngineService = require('../services/aiEngineService')

const chain = () => {
  const q = { sort: () => q, skip: () => q, limit: () => q, populate: () => q, lean: () => Promise.resolve([]) }
  return q
}

describe('H5 analyst review queue', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    created = null
    jest.spyOn(aiEngineService, 'getAlertThreshold').mockResolvedValue(0.9)
    jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.92)
  })

  test('schema has needsReview defaulting to false', () => {
    const doc = new AIPrediction({ inputSource: 'network_traffic', predictedClass: 'BENIGN', threatScore: 0.1 })
    expect(doc.needsReview).toBe(false)
  })

  test('engine REVIEW is kept by the pipeline, stored as needsReview, and creates no threat', async () => {
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'Unknown', threatScore: 0.55, action: 'REVIEW', isAnomaly: true, anomalyScore: -0.7 },
    })
    const res = await aiEngineService.runFullPipeline({ sourceIP: '10.0.0.9' })
    expect(res.action).toBe('REVIEW')
    expect(created.needsReview).toBe(true)
    expect(mockThreatCreate).not.toHaveBeenCalled()
  })

  test('ordinary predictions are not queued for review', async () => {
    await aiService.storePrediction({ inputSource: 'network_traffic', predictedClass: 'BENIGN', threatScore: 0.1, action: 'ALLOW' })
    expect(created.needsReview).toBe(false)
  })

  test('?review=true lists unverified review items only', async () => {
    mockFind.mockReturnValue(chain())
    await aiService.findPredictions({ review: 'true' })
    expect(mockFind).toHaveBeenCalledWith({ needsReview: true, verified: false })
  })
})

describe('U4 honeypot corroboration', () => {
  const HoneypotSession = require('../models/HoneypotSession')
  let readyState
  beforeEach(() => {
    jest.clearAllMocks()
    readyState = jest.spyOn(aiService, 'dbConnected').mockReturnValue(true)
    jest.spyOn(aiEngineService, 'getAlertThreshold').mockResolvedValue(0.9)
    jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.92)
  })
  afterEach(() => jest.restoreAllMocks())
  const flow = (predictedClass) => ({ inputSource: 'network_traffic', sourceIP: '203.0.113.50', predictedClass, threatScore: 0.1 })

  test('a BENIGN flow from a recent honeypot attacker is queued for review', async () => {
    jest.spyOn(HoneypotSession, 'exists').mockResolvedValue({ _id: 's1' })
    await aiService.storePrediction(flow('BENIGN'))
    expect(created).toMatchObject({ honeypotCorroborated: true, needsReview: true })
    expect(mockThreatCreate).not.toHaveBeenCalled()
  })

  test('an attack verdict from such an IP is marked but not queued (it is already a detection)', async () => {
    jest.spyOn(HoneypotSession, 'exists').mockResolvedValue({ _id: 's1' })
    await aiService.storePrediction(flow('Port Scan'))
    expect(created.honeypotCorroborated).toBe(true)
    expect(created.needsReview).toBe(false)
  })

  test('no lookup while MongoDB is not connected', async () => {
    readyState.mockReturnValue(false)
    const exists = jest.spyOn(HoneypotSession, 'exists')
    await aiService.storePrediction(flow('BENIGN'))
    expect(exists).not.toHaveBeenCalled()
    expect(created.honeypotCorroborated).toBeUndefined()
  })
})
