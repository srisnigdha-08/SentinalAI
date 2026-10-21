'use strict'
/**
 * AI engine audit, medium-priority fixes on the backend side:
 *  M1 one severity scale anchored on the shared alert/block lines (utils/severity.js)
 *  M2 predictions on incomplete input (many defaulted features) never trigger an automatic block
 *  (M9, the reload admin key, is tested in aiDependencyContract.test.js with the mocked engine client)
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-ai-medium'
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitNewThreat: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
}))
jest.mock('../services/alertService', () => ({ createAlertFromThreat: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/threatIntelService', () => ({ enrichThreat: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/containmentService', () => ({ executeAutoBlock: jest.fn().mockResolvedValue({}) }))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn().mockResolvedValue({ value: true }) })) // auto-block ON
jest.mock('../models/AIPrediction', () => {
  const actual = jest.requireActual('../models/AIPrediction')
  actual.create = jest.fn().mockImplementation(async (p) => ({ _id: 'pred-m-1', ...p, save: jest.fn() }))
  return actual
})
const mockThreatCreate = jest.fn().mockImplementation(async (doc) => ({ ...doc, save: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({ create: mockThreatCreate }))

const { severityFor } = require('../utils/severity')
const aiService = require('../services/aiService')
const aiEngineService = require('../services/aiEngineService')

const LINES = { alertThreshold: 0.9, blockThreshold: 0.92 }

describe('M1 severity scale', () => {
  test.each([
    [0.99, 'CRITICAL'],
    [0.92, 'CRITICAL'],
    [0.91, 'HIGH'],
    [0.9, 'HIGH'],
    [0.6, 'MEDIUM'],
    [0.2, 'LOW'],
  ])('score %p -> %s', (score, expected) => {
    expect(severityFor(score, LINES)).toBe(expected)
  })
})

describe('M2 incomplete input', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    jest.spyOn(aiEngineService, 'getAlertThreshold').mockResolvedValue(0.9)
    jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.92)
  })
  const base = { inputSource: 'network_traffic', sourceIP: '203.0.113.9', predictedClass: 'DDoS', threatScore: 0.99 }

  test('complete input above the block line is blocked when auto-block is on', async () => {
    await aiService.storePrediction({ ...base })
    const doc = mockThreatCreate.mock.calls[0][0]
    expect(doc.status).toBe('BLOCKED')
    expect(doc.severity).toBe('CRITICAL')
  })

  test('incomplete input raises a threat but is never auto-blocked', async () => {
    await aiService.storePrediction({ ...base, incompleteInput: true })
    const doc = mockThreatCreate.mock.calls[0][0]
    expect(doc.status).toBe('MONITORING')
    expect(doc.autonomousAction.taken).toBe(false)
  })
})
