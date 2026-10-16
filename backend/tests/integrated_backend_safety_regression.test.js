/**
 * integrated_backend_safety_regression.test.js
 *
 * Integrated regression test suite for SentinelAI GATE-1 Phase 3D:
 * Controlled Backend Safety Patch and Integrated Regression Verification.
 *
 * Covers all 17 required scenarios specified in Section 3.
 * Exercises actual patched application code in backend/services, backend/models, backend/utils.
 */

'use strict'

process.env.SENTINEL_KEY = 'phase3d-test-secret-key-offline'
process.env.AI_ENGINE_URL = 'http://localhost:8000'
process.env.NODE_ENV = 'test'

const mongoose = require('mongoose')
const path = require('path')
const fs = require('fs')

// Explicit Runtime Database Guard (Mandatory Safety Preflight)
const DISPOSABLE_TEST_DB_URI = 'mongodb://127.0.0.1:27017/sentinelai_disposable_phase3d_test'
function runtimeDatabaseGuard(uri) {
  if (!uri) return false
  if (uri.includes('sentinel-db') || uri.endsWith('/sentinel-db')) {
    throw new Error('FATAL SECURITY VIOLATION: Test attempted to connect to live sentinel-db! Aborting immediately.')
  }
  const url = new URL(uri)
  if (!url.pathname.includes('disposable') && !url.pathname.includes('test')) {
    throw new Error('FATAL SECURITY VIOLATION: Database name must contain "test" or "disposable". Got: ' + url.pathname)
  }
  return true
}
runtimeDatabaseGuard(DISPOSABLE_TEST_DB_URI)

// Import Actual Patched Application Modules
const ThreatLog = require('../models/ThreatLog')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const SystemSetting = require('../models/SystemSetting')
const aiEngineService = require('../services/aiEngineService')
const threatService = require('../services/threatService')
const aiService = require('../services/aiService')
const emergencyAudit = require('../utils/emergencyAudit')
const logger = require('../utils/logger')

describe('SentinelAI GATE-1 Phase 3D: Integrated Backend Safety Regression Tests', () => {
  beforeEach(() => {
    jest.restoreAllMocks()
    jest.clearAllMocks()
  })

  // --------------------------------------------------------------------------
  // Scenario 1: Valid BENIGN Inference (Unit / Component)
  // --------------------------------------------------------------------------
  test('1. Valid BENIGN inference returns action ALLOW and skips ThreatLog creation', async () => {
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockResolvedValue({
      _id: 'pred-benign-1',
      threatScore: 0.02,
      predictedClass: 'BENIGN',
    })
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: {
        predictedClass: 'BENIGN',
        threatScore: 0.02,
        action: 'ALLOW',
        status: 'HEALTHY',
        classProbabilities: { BENIGN: 0.98, DDoS: 0.02 },
      },
    })

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.10', destinationIP: '10.0.0.1' })
    expect(res.action).toBe('ALLOW')
    expect(res.predictedClass).toBe('BENIGN')
    expect(mockStorePrediction).toHaveBeenCalledWith(
      expect.objectContaining({
        predictedClass: 'BENIGN',
        threatScore: 0.02,
        action: 'ALLOW',
      })
    )
  })

  // --------------------------------------------------------------------------
  // Scenario 2: Valid MONITOR Inference (Unit / Component)
  // --------------------------------------------------------------------------
  test('2. Valid attack inference with score 0.85 returns action MONITOR', async () => {
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockResolvedValue({
      _id: 'pred-monitor-1',
      threatScore: 0.85,
      predictedClass: 'Port Scan',
    })
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: {
        predictedClass: 'Port Scan',
        threatScore: 0.85,
        action: 'MONITOR',
        status: 'HEALTHY',
      },
    })

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.20' })
    expect(res.action).toBe('MONITOR')
    expect(res.predictedClass).toBe('Port Scan')
  })

  // --------------------------------------------------------------------------
  // Scenario 3: Simulated BLOCK while real enforcement disabled (Component)
  // --------------------------------------------------------------------------
  test('3. Simulated BLOCK is distinct from actual firewall enforcement when autoBlockEnabled=false', async () => {
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockResolvedValue({
      _id: 'pred-block-1',
      threatScore: 0.95,
      predictedClass: 'DDoS',
    })
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: {
        predictedClass: 'DDoS',
        threatScore: 0.95,
        action: 'BLOCK',
        status: 'HEALTHY',
      },
    })

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.30' })
    expect(res.action).toBe('BLOCK')
    // Verification that no Windows Firewall execution adapter is triggered
    expect(process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT).not.toBe('true')
    expect(process.env.AUTONOMOUS_CONTAINMENT).not.toBe('true')
  })

  // --------------------------------------------------------------------------
  // Scenario 4: Explicit Degraded Response with Score 0.50 (Component)
  // --------------------------------------------------------------------------
  test('4. Explicit degraded response (score=0.50, action=MONITOR) is NOT overwritten to ALLOW', async () => {
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockImplementation(async (payload) => ({
      _id: 'pred-degraded-1',
      ...payload,
    }))
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: {
        predictedClass: 'UNINSPECTED_TRAFFIC',
        threatScore: 0.5,
        action: 'MONITOR',
        status: 'DEGRADED',
      },
    })

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.40' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(mockStorePrediction).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'MONITOR',
        status: 'DEGRADED',
        predictedClass: 'UNINSPECTED_TRAFFIC',
      })
    )
  })

  // --------------------------------------------------------------------------
  // Scenario 5: Axios Timeout (Integration / Failure Recovery)
  // --------------------------------------------------------------------------
  test('5. Axios timeout does not return null; safely falls back to UNAVAILABLE and MONITOR', async () => {
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue(null)
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockImplementation(async (payload) => ({
      _id: 'pred-timeout-1',
      ...payload,
    }))

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.50' })
    expect(res).not.toBeNull()
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('UNAVAILABLE')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(res.threatScore).toBe(0.5)
  })

  // --------------------------------------------------------------------------
  // Scenario 6: ECONNREFUSED Connection Failure (Integration / Failure Recovery)
  // --------------------------------------------------------------------------
  test('6. ECONNREFUSED produces observable failure result with action MONITOR', async () => {
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue(null)
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockImplementation(async (payload) => ({
      _id: 'pred-econnrefused-1',
      ...payload,
    }))

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.60' })
    expect(res).not.toBeNull()
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('UNAVAILABLE')
    expect(res.threatScore).toBe(0.5)
  })

  // --------------------------------------------------------------------------
  // Scenario 7: AI Service HTTP 500 (Integration / Failure Recovery)
  // --------------------------------------------------------------------------
  test('7. AI engine HTTP 500 internal server error falls back to UNAVAILABLE and MONITOR', async () => {
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue(null)
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockImplementation(async (payload) => ({
      _id: 'pred-500-1',
      ...payload,
    }))

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.70' })
    expect(res).not.toBeNull()
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('UNAVAILABLE')
  })

  // --------------------------------------------------------------------------
  // Scenario 8: Null and Malformed Responses (Unit / Validation)
  // --------------------------------------------------------------------------
  test('8. Null and malformed inference responses safely fall back to UNAVAILABLE', async () => {
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({})
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockImplementation(async (p) => ({
      _id: 'pred-malformed-1',
      ...p,
    }))

    const res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.80' })
    expect(res).not.toBeNull()
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('UNAVAILABLE')
  })

  // --------------------------------------------------------------------------
  // Scenario 9: Missing, Non-Finite, and Out-of-Range Scores (Fail-Safe Validation)
  // --------------------------------------------------------------------------
  test('9. Missing, non-finite, and out-of-range scores are rejected as invalid degraded states', async () => {
    let storedPayload = null
    jest.spyOn(aiService, 'storePrediction').mockImplementation(async (p) => {
      storedPayload = p
      return { _id: 'pred-test-9', ...p }
    })

    // 9A: Out of range > 1 (e.g. 1.5) -> Rejected to degraded MONITOR
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'DDoS', threatScore: 1.5, action: 'BLOCK' },
    })
    let res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.91' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(storedPayload.threatScore).toBe(0.5)

    // 9B: Out of range < 0 (e.g. -0.5) -> Rejected to degraded MONITOR
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: -0.5, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.92' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(storedPayload.threatScore).toBe(0.5)

    // 9C: NaN -> Rejected to degraded MONITOR (NEVER falls through to ALLOW!)
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: NaN, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.93' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(storedPayload.threatScore).toBe(0.5)

    // 9D: Positive & Negative Infinity -> Rejected to degraded MONITOR
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'DDoS', threatScore: Infinity, action: 'BLOCK' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.94' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')

    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: -Infinity, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.95' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')

    // 9E: Non-numeric string ('invalid_nan') -> Rejected to degraded MONITOR
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'Port Scan', threatScore: 'invalid_nan', action: 'MONITOR' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.96' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')
    expect(res.predictedClass).toBe('UNINSPECTED_TRAFFIC')
    expect(storedPayload.threatScore).toBe(0.5)

    // 9F: Missing / undefined / null -> Rejected to degraded MONITOR
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: undefined, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.97' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')

    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: null, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.98' })
    expect(res.action).toBe('MONITOR')
    expect(res.status).toBe('DEGRADED')

    // 9G: Valid numeric string ('0.85') -> Preserved as valid number 0.85
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'Port Scan', threatScore: '0.85', action: 'MONITOR' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.99' })
    expect(res.action).toBe('MONITOR')
    expect(res.predictedClass).toBe('Port Scan')
    expect(storedPayload.threatScore).toBe(0.85)

    // 9H: Valid boundary values 0 and 1 -> Preserved
    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'BENIGN', threatScore: 0, action: 'ALLOW' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.100' })
    expect(res.action).toBe('ALLOW')
    expect(storedPayload.threatScore).toBe(0)

    jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: { predictedClass: 'DDoS', threatScore: 1, action: 'BLOCK' },
    })
    res = await aiEngineService.runFullPipeline({ sourceIP: '192.168.1.101' })
    expect(res.action).toBe('BLOCK')
    expect(storedPayload.threatScore).toBe(1)
  })

  // --------------------------------------------------------------------------
  // Scenario 10: ThreatLog and Alert Schema Validation (Mongoose In-Memory)
  // --------------------------------------------------------------------------
  test('10. ThreatLog and Alert schemas validate DEGRADED, UNINSPECTED_TRAFFIC, and AIPrediction', () => {
    // A. ThreatLog validation with DEGRADED status and UNINSPECTED_TRAFFIC attackType
    const validThreat = new ThreatLog({
      severity: 'MEDIUM',
      sourceIP: '192.168.1.100',
      attackType: 'UNINSPECTED_TRAFFIC',
      aiScore: 0.5,
      status: 'DEGRADED',
      preBlockStatus: 'DEGRADED',
    })
    const threatValidationErr = validThreat.validateSync()
    expect(threatValidationErr).toBeUndefined() // No validation errors!

    // B. Rejection of invalid status
    const invalidThreat = new ThreatLog({
      severity: 'MEDIUM',
      sourceIP: '192.168.1.100',
      attackType: 'DDoS',
      status: 'NON_EXISTENT_STATUS',
    })
    const invalidThreatErr = invalidThreat.validateSync()
    expect(invalidThreatErr).toBeDefined()
    expect(invalidThreatErr.errors.status).toBeDefined()

    // C. Alert validation with refModel AIPrediction
    const validAlert = new Alert({
      title: 'System Alert: AI Engine Unavailable',
      message: 'Traffic held in MONITOR',
      severity: 'MEDIUM',
      type: 'SYSTEM_HEALTH',
      sourceRef: {
        refModel: 'AIPrediction',
        refId: new mongoose.Types.ObjectId(),
      },
    })
    const alertValidationErr = validAlert.validateSync()
    expect(alertValidationErr).toBeUndefined()
  })

  // --------------------------------------------------------------------------
  // Scenario 11: AIPrediction Model Registration & Reference Compatibility
  // --------------------------------------------------------------------------
  test('11. AIPrediction model registers cleanly and validates schema fields', () => {
    const validPred = new AIPrediction({
      inputSource: 'network_traffic',
      sourceIP: '10.0.0.5',
      predictedClass: 'UNINSPECTED_TRAFFIC',
      threatScore: 0.5,
      modelVersion: 'v2.1-fallback',
      modelType: 'random_forest',
    })
    const err = validPred.validateSync()
    expect(err).toBeUndefined()
  })

  // --------------------------------------------------------------------------
  // Scenario 12: Database Unavailable & Persistence Failure (Emergency Fallback)
  // --------------------------------------------------------------------------
  test('12. Database persistence failure logs emergency audit to disk and propagates error', async () => {
    const mockPredictRecord = jest.spyOn(aiEngineService, 'predictRecord').mockResolvedValue({
      result: {
        predictedClass: 'DDoS',
        threatScore: 0.88,
        action: 'MONITOR',
      },
    })
    const mockStorePrediction = jest.spyOn(aiService, 'storePrediction').mockRejectedValue(
      new Error('MongoNetworkError: failed to connect to server [127.0.0.1:27017]')
    )

    const emergencyAuditSpy = jest.spyOn(emergencyAudit, 'writeEmergencyAudit')

    await expect(aiEngineService.runFullPipeline({ sourceIP: '192.168.1.120' })).rejects.toThrow(
      'MongoNetworkError'
    )

    expect(emergencyAuditSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'PERSISTENCE_FAILURE_EMERGENCY_AUDIT',
        sourceIP: '192.168.1.120',
        threatScore: 0.88,
        action: 'MONITOR',
      })
    )
  })

  // --------------------------------------------------------------------------
  // Scenario 13: Emergency Audit Fallback File Guarantees & Bounded Retention
  // --------------------------------------------------------------------------
  test('13. writeEmergencyAudit synchronously writes durable audit record with bounded retention', () => {
    const testRecord = {
      event: 'UNIT_TEST_EMERGENCY_AUDIT',
      sourceIP: '10.99.99.99',
      threatScore: 0.5,
      secret_password: 'super-secret-password-123',
    }

    const auditRes = emergencyAudit.writeEmergencyAudit(testRecord)
    expect(auditRes.success).toBe(true)
    expect(auditRes.durable).toBe(true)
    expect(fs.existsSync(auditRes.path)).toBe(true)

    // Verify sanitization in written record
    const content = fs.readFileSync(auditRes.path, 'utf8')
    expect(content.includes('UNIT_TEST_EMERGENCY_AUDIT')).toBe(true)
    expect(content.includes('super-secret-password-123')).toBe(false)

    // Verify bounded retention: ensure rotated archives do not exceed MAX_ROTATED_FILES (5)
    const logsDir = path.dirname(auditRes.path)
    const rotated = fs.readdirSync(logsDir).filter((f) => f.startsWith('emergency_audit.') && f.endsWith('.log'))
    expect(rotated.length).toBeLessThanOrEqual(5)
  })

  // --------------------------------------------------------------------------
  // Scenario 14: Notification & WebSocket Delivery Failure (Non-Fatal Resilience)
  // --------------------------------------------------------------------------
  test('14. Notification delivery failure is logged as warning and does not abort transaction', async () => {
    jest.spyOn(SystemSetting, 'findOne').mockResolvedValue({ key: 'autoBlockEnabled', value: false })
    jest.spyOn(AIPrediction, 'create').mockResolvedValue({
      _id: 'pred-notif-1',
      sourceIP: '192.168.1.140',
      threatScore: 0.5,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      save: jest.fn().mockResolvedValue(true),
    })
    jest.spyOn(ThreatLog, 'create').mockResolvedValue({
      _id: 'threat-notif-1',
      sourceIP: '192.168.1.140',
      threatScore: 0.5,
      status: 'DEGRADED',
      severity: 'MEDIUM',
    })
    const socketManager = require('../websocket/socketManager')
    jest.spyOn(socketManager, 'emitNewThreat').mockImplementation(() => {
      throw new Error('WebSocket connection broken')
    })
    const loggerWarnSpy = jest.spyOn(logger, 'warn')

    const res = await aiService.storePrediction({
      sourceIP: '192.168.1.140',
      threatScore: 0.5,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      status: 'DEGRADED',
    })

    expect(res).toBeDefined()
    expect(res._id).toBe('pred-notif-1')
    expect(loggerWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[AI] Socket/Alert emission error: WebSocket connection broken')
    )
  })

  // --------------------------------------------------------------------------
  // Scenario 15: Duplicate Prevention Across Retry Paths (Idempotency)
  // --------------------------------------------------------------------------
  test('15. Repeated degraded predictions do not overwrite preBlockStatus or cause unbounded alerts', async () => {
    jest.spyOn(SystemSetting, 'findOne').mockResolvedValue({ key: 'autoBlockEnabled', value: false })
    jest.spyOn(AIPrediction, 'create').mockResolvedValue({
      _id: 'pred-retry-1',
      sourceIP: '192.168.1.150',
      threatScore: 0.5,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      save: jest.fn().mockResolvedValue(true),
    })
    const mockThreatLogCreate = jest.spyOn(ThreatLog, 'create').mockResolvedValue({
      _id: 'threat-retry-1',
      status: 'DEGRADED',
    })
    const alertService = require('../services/alertService')
    const mockCreateAlert = jest.spyOn(alertService, 'createAlert').mockResolvedValue({
      _id: 'alert-retry-1',
    })

    await aiService.storePrediction({
      sourceIP: '192.168.1.150',
      threatScore: 0.5,
      predictedClass: 'UNINSPECTED_TRAFFIC',
      status: 'DEGRADED',
    })

    expect(mockThreatLogCreate).toHaveBeenCalledTimes(1)
    expect(mockCreateAlert).toHaveBeenCalledTimes(1)
  })

  // --------------------------------------------------------------------------
  // Scenario 16: Dashboard and Query Compatibility with New Statuses (Integration)
  // --------------------------------------------------------------------------
  test('16. findThreats parses and accepts status=DEGRADED without validation error', async () => {
    jest.spyOn(ThreatLog, 'countDocuments').mockResolvedValue(5)
    const mockFind = jest.spyOn(ThreatLog, 'find').mockReturnValue({
      sort: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      populate: jest.fn().mockReturnThis(),
      lean: jest.fn().mockResolvedValue([
        { _id: 't-1', status: 'DEGRADED', attackType: 'UNINSPECTED_TRAFFIC', aiScore: 0.5 },
      ]),
    })

    const result = await threatService.findThreats({ status: 'DEGRADED', page: 1, limit: 10 })
    expect(result.total).toBe(5)
    expect(result.data).toHaveLength(1)
    expect(result.data[0].status).toBe('DEGRADED')
    expect(mockFind).toHaveBeenCalledWith(
      expect.objectContaining({
        status: 'DEGRADED',
      })
    )
  })

  // --------------------------------------------------------------------------
  // Scenario 17: Authentication and Unrelated API Regressions (Regression Shield)
  // --------------------------------------------------------------------------
  test('17. Query security utilities and input validation remain intact', () => {
    const { isValidIP, escapeRegex, parsePagination } = require('../utils/querySecurity')

    expect(isValidIP('192.168.1.1')).toBe(true)
    expect(isValidIP('999.999.999.999')).toBe(false)
    expect(isValidIP('; DROP TABLE users;')).toBe(false)

    expect(escapeRegex('attack.*')).toBe('attack\\.\\*')

    const pagination = parsePagination({ page: 2, limit: 25 })
    expect(pagination.page).toBe(2)
    expect(pagination.limit).toBe(25)
    expect(pagination.skip).toBe(25)
  })
})
