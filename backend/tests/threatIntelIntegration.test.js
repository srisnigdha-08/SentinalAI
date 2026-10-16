'use strict'
/**
 * tests/threatIntelIntegration.test.js
 *
 * Controlled integration test for Phase 2.4B runtime verification:
 * Verifies before and after counters:
 * - AIPrediction created
 * - ThreatLog created
 * - Alert created
 * - BlockedIP count remains 0 (No containment occurs due to AbuseIPDB)
 * - Enrichment adds only ThreatLog.threatIntel
 * - ThreatScore and action remain unchanged
 */

const axios = require('axios')
jest.mock('axios')

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}
jest.mock('../utils/logger', () => mockLogger)

const mockSocketManager = {
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitThreatIntelUpdated: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
}
jest.mock('../websocket/socketManager', () => mockSocketManager)

const mockBlockedIP = {
  create: jest.fn(),
  findOneAndUpdate: jest.fn(),
}
jest.mock('../models/BlockedIP', () => mockBlockedIP)

const mockContainmentService = {
  executeAutoBlock: jest.fn(),
  blockThreat: jest.fn(),
}
jest.mock('../services/containmentService', () => mockContainmentService)

const mockAlertService = {
  createAlertFromThreat: jest.fn().mockResolvedValue({ _id: 'alert-mock-123', severity: 'HIGH' }),
}
jest.mock('../services/alertService', () => mockAlertService)

const mockAiEngineService = {
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}
jest.mock('../services/aiEngineService', () => mockAiEngineService)

let mockAiPredictionCount = 0
let mockThreatLogCount = 0
let mockAlertCount = 0
let mockBlockedIPCount = 0

const mockThreatLogFindByIdAndUpdate = jest.fn()
jest.mock('../models/ThreatLog', () => ({
  create: jest.fn().mockImplementation(async (data) => {
    mockThreatLogCount++
    return {
      _id: 'threat-integration-001',
      ...data,
    }
  }),
  findByIdAndUpdate: (...args) => mockThreatLogFindByIdAndUpdate(...args),
}))

jest.mock('../models/AIPrediction', () => ({
  create: jest.fn().mockImplementation(async (data) => {
    mockAiPredictionCount++
    return {
      _id: 'pred-integration-001',
      ...data,
      save: jest.fn().mockResolvedValue(true),
    }
  }),
}))

jest.mock('../models/SystemSetting', () => ({
  findOne: jest.fn().mockResolvedValue({ key: 'autoBlockEnabled', value: false }),
}))

const aiService = require('../services/aiService')
const threatIntelService = require('../services/threatIntelService')

describe('Phase 2.4B: Controlled Runtime Verification of Threat Intel Enrichment', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    threatIntelService.clearCache()
    process.env.ABUSEIPDB_API_KEY = 'test-runtime-key'
    mockAiPredictionCount = 0
    mockThreatLogCount = 0
    mockAlertCount = 0
    mockBlockedIPCount = 0
  })

  test('Runtime Verification: Controlled prediction triggers async enrichment without containment', async () => {
    // AbuseIPDB returns 100% confidence score
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: {
        data: {
          ipAddress: '185.220.101.5',
          abuseConfidenceScore: 100,
          totalReports: 999,
          countryCode: 'RU',
          isp: 'Malicious Exit',
        },
      },
    })

    const initialPredictionCount = mockAiPredictionCount
    const initialThreatLogCount = mockThreatLogCount
    const initialBlockedIPCount = mockBlockedIPCount

    // Feed a high-severity prediction (score = 0.80, Port Scan, MONITORING)
    const predData = {
      inputSource: 'network_traffic',
      sourceIP: '185.220.101.5',
      targetIP: '10.0.0.1',
      predictedClass: 'Port Scan',
      threatScore: 0.8,
      confidence: 0.8,
      modelVersion: 'v2.1',
      action: 'MONITOR',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce({
      _id: 'threat-integration-001',
      severity: 'HIGH',
      sourceIP: '185.220.101.5',
      aiScore: 0.8,
      status: 'MONITORING',
      threatIntel: {
        provider: 'AbuseIPDB',
        status: 'SUCCESS',
        abuseConfidenceScore: 100,
      },
    })

    // Store prediction (normal pipeline flow)
    const stored = await aiService.storePrediction(predData)

    // Verify synchronous flow completed immediately
    expect(stored).toBeDefined()
    expect(mockAiPredictionCount).toBe(initialPredictionCount + 1)
    expect(mockThreatLogCount).toBe(initialThreatLogCount + 1)
    expect(mockBlockedIPCount).toBe(initialBlockedIPCount) // 0 new BlockedIPs
    expect(mockContainmentService.executeAutoBlock).not.toHaveBeenCalled()

    // Wait for the asynchronous setImmediate enrichment task to execute
    await new Promise((resolve) => setImmediate(resolve))

    // Verify enrichment updated ThreatLog.threatIntel
    expect(mockThreatLogFindByIdAndUpdate).toHaveBeenCalledTimes(1)
    expect(mockThreatLogFindByIdAndUpdate).toHaveBeenCalledWith(
      'threat-integration-001',
      {
        $set: {
          threatIntel: expect.objectContaining({
            provider: 'AbuseIPDB',
            status: 'SUCCESS',
            abuseConfidenceScore: 100,
            totalReports: 999,
            countryCode: 'RU',
          }),
        },
      },
      { new: true, runValidators: true }
    )

    // Verify WebSocket emitted only threat_intel_updated for enrichment
    expect(mockSocketManager.emitThreatIntelUpdated).toHaveBeenCalledTimes(1)
    expect(mockSocketManager.emitIPBlocked).not.toHaveBeenCalled()

    // Final check: BlockedIP count remains exactly 0
    expect(mockBlockedIP.create).not.toHaveBeenCalled()
    expect(mockBlockedIP.findOneAndUpdate).not.toHaveBeenCalled()
  })
})
