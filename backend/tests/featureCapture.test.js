'use strict'
/**
 * tests/featureCapture.test.js
 *
 * Phase 2.5C-2 Data Capture Implementation Test Suite:
 *
 * 1. Schema properties:
 *    - featureVector has type [Number] and select: false
 *    - featureSchemaVersion has type String and select: false
 *    - toJSON and toObject transforms remove featureVector & featureSchemaVersion
 *
 * 2. storePrediction with valid 53-element vector:
 *    - Persists featureVector and featureSchemaVersion in payload
 *    - Values are raw/unscaled and preserved accurately
 *
 * 3. storePrediction with invalid vectors (resilience & availability):
 *    - Vector missing: creates record normally without crashing
 *    - Vector with wrong length (!== 53): omits featureVector, logs warning, saves record
 *    - Vector with NaN / Infinity: omits featureVector, logs warning, saves record
 *    - Vector with non-numeric / non-array: omits featureVector, logs warning, saves record
 *
 * 4. Operational containment & socket invariants:
 *    - Prediction with high threat score still triggers threat creation & socket emission
 */

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}
jest.mock('../utils/logger', () => mockLogger)

const mockSocketManager = {
  emitNewThreat: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
}
jest.mock('../websocket/socketManager', () => mockSocketManager)

const mockAlertService = {
  createAlertFromThreat: jest.fn().mockResolvedValue({ _id: 'alert-1', severity: 'HIGH' }),
}
jest.mock('../services/alertService', () => mockAlertService)

const mockThreatIntelService = {
  enrichThreat: jest.fn().mockResolvedValue({}),
}
jest.mock('../services/threatIntelService', () => mockThreatIntelService)

const mockContainmentService = {
  executeAutoBlock: jest.fn().mockResolvedValue({}),
}
jest.mock('../services/containmentService', () => mockContainmentService)

const mockAiEngineService = {
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}
jest.mock('../services/aiEngineService', () => mockAiEngineService)

// Mock Mongoose models
let savedPredictionPayload = null
const mockAIPredictionCreate = jest.fn().mockImplementation(async (payload) => {
  savedPredictionPayload = { ...payload }
  return {
    _id: 'pred-mock-id-001',
    ...payload,
    save: jest.fn().mockResolvedValue(true),
  }
})

jest.mock('../models/AIPrediction', () => {
  const actualModel = jest.requireActual('../models/AIPrediction')
  actualModel.create = mockAIPredictionCreate
  return actualModel
})

const mockThreatLogCreate = jest.fn().mockImplementation(async (payload) => ({
  _id: 'threat-mock-id-001',
  ...payload,
  save: jest.fn().mockResolvedValue(true),
}))
jest.mock('../models/ThreatLog', () => ({
  create: mockThreatLogCreate,
}))

jest.mock('../models/SystemSetting', () => ({
  findOne: jest.fn().mockResolvedValue({ value: false }),
}))

const AIPrediction = require('../models/AIPrediction')
const aiService = require('../services/aiService')

describe('Phase 2.5C-2 Data Capture Foundation Tests', () => {
  const validVector = Array.from({ length: 53 }, (_, i) => i * 1.5 + 10.0)

  beforeEach(() => {
    jest.clearAllMocks()
    savedPredictionPayload = null
  })

  describe('1. AIPrediction Schema Configuration', () => {
    test('featureVector field exists with type [Number] and select: false', () => {
      const field = AIPrediction.schema.path('featureVector')
      expect(field).toBeDefined()
      expect(field.options.select).toBe(false)
      expect(field.instance).toBe('Array')
    })

    test('featureSchemaVersion field exists with type String and select: false', () => {
      const field = AIPrediction.schema.path('featureSchemaVersion')
      expect(field).toBeDefined()
      expect(field.options.select).toBe(false)
      expect(field.instance).toBe('String')
    })

    test('toJSON and toObject transforms remove featureVector and featureSchemaVersion', () => {
      const doc = new AIPrediction({
        inputSource: 'network_traffic',
        sourceIP: '10.0.0.1',
        predictedClass: 'Port Scan',
        threatScore: 0.85,
        featureVector: validVector,
        featureSchemaVersion: 'v2.1_53feat',
      })

      const jsonOutput = doc.toJSON()
      expect(jsonOutput.featureVector).toBeUndefined()
      expect(jsonOutput.featureSchemaVersion).toBeUndefined()
      expect(jsonOutput.predictedClass).toBe('Port Scan')

      const objOutput = doc.toObject()
      expect(objOutput.featureVector).toBeUndefined()
      expect(objOutput.featureSchemaVersion).toBeUndefined()
    })
  })

  describe('2. Persistence with Valid Feature Vector', () => {
    test('storePrediction persists 53-element raw vector and schema version', async () => {
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.100',
        predictedClass: 'Port Scan',
        threatScore: 0.85,
        featureVector: validVector,
        featureSchemaVersion: 'v2.1_53feat',
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(mockAIPredictionCreate).toHaveBeenCalledTimes(1)

      expect(savedPredictionPayload).toBeDefined()
      expect(savedPredictionPayload.featureVector).toEqual(validVector)
      expect(savedPredictionPayload.featureVector.length).toBe(53)
      expect(savedPredictionPayload.featureSchemaVersion).toBe('v2.1_53feat')
      expect(savedPredictionPayload.featureVector[0]).toBe(10.0)
    })
  })

  describe('3. Resilience with Invalid Feature Vectors', () => {
    test('missing featureVector succeeds without error', async () => {
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.101',
        predictedClass: 'BENIGN',
        threatScore: 0.15,
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(savedPredictionPayload.featureVector).toBeUndefined()
      expect(savedPredictionPayload.featureSchemaVersion).toBeUndefined()
      expect(mockLogger.warn).not.toHaveBeenCalled()
    })

    test('vector with incorrect length (52 elements) is safely omitted', async () => {
      const shortVector = validVector.slice(0, 52)
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.102',
        predictedClass: 'DDoS',
        threatScore: 0.95,
        featureVector: shortVector,
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(savedPredictionPayload.featureVector).toBeUndefined()
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('[AI Persistence] Invalid featureVector received')
      )
    })

    test('vector with NaN values is safely omitted', async () => {
      const nanVector = [...validVector]
      nanVector[5] = NaN
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.103',
        predictedClass: 'DDoS',
        threatScore: 0.95,
        featureVector: nanVector,
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(savedPredictionPayload.featureVector).toBeUndefined()
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('[AI Persistence] Invalid featureVector received')
      )
    })

    test('vector with Infinity is safely omitted', async () => {
      const infVector = [...validVector]
      infVector[10] = Infinity
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.104',
        predictedClass: 'DDoS',
        threatScore: 0.95,
        featureVector: infVector,
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(savedPredictionPayload.featureVector).toBeUndefined()
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('[AI Persistence] Invalid featureVector received')
      )
    })

    test('non-array featureVector is safely omitted', async () => {
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.105',
        predictedClass: 'DDoS',
        threatScore: 0.95,
        featureVector: 'not-an-array',
      }

      const result = await aiService.storePrediction(predData)
      expect(result).toBeDefined()
      expect(savedPredictionPayload.featureVector).toBeUndefined()
      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('[AI Persistence] Invalid featureVector received')
      )
    })
  })

  describe('4. Operational Security & Decision Pipeline Invariants', () => {
    test('high threat score with feature capture triggers ThreatLog and WebSocket emission', async () => {
      const predData = {
        inputSource: 'network_traffic',
        sourceIP: '192.168.1.106',
        predictedClass: 'SSH Brute Force',
        threatScore: 0.88,
        featureVector: validVector,
        featureSchemaVersion: 'v2.1_53feat',
      }

      await aiService.storePrediction(predData)

      expect(mockThreatLogCreate).toHaveBeenCalledTimes(1)
      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          sourceIP: '192.168.1.106',
          attackType: 'SSH Brute Force',
          aiScore: 0.88,
          status: 'MONITORING',
        })
      )
      expect(mockSocketManager.emitNewThreat).toHaveBeenCalledTimes(1)
      expect(mockSocketManager.emitAIPrediction).toHaveBeenCalledTimes(1)
    })
  })
})
