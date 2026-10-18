'use strict'

/**
 * tests/threatSecurityRemediation.test.js
 *
 * Phase 3.1: Minimal Backend Security & Telemetry Remediation Test Suite
 *
 * Verifies:
 * - SEC-01: Untrusted client threat scores & autonomous containment actions stripped on createThreat
 * - SEC-02: attackType validated against canonical enum values (HTTP 400 on invalid)
 * - SEC-03: autonomousAction tampering prevented on updateThreat (stripped from allowed fields)
 * - REL-02: Event timestamp preservation, parsing, and boundary validation
 * - OBS-01: Bi-directional traceability linking AIPrediction <-> ThreatLog (predictionId)
 * - SEC-04: CastError message sanitization preventing raw user input reflection
 */

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-threat-security'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-threat-security'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key'

jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))
jest.mock('../websocket/socketManager', () => ({
  init: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
}))
jest.mock('../services/alertService', () => ({
  createAlert: jest.fn().mockResolvedValue({ _id: 'alert-1' }),
  createAlertFromThreat: jest.fn().mockResolvedValue({ _id: 'alert-2' }),
}))
jest.mock('../services/threatIntelService', () => ({
  enrichThreat: jest.fn().mockResolvedValue({}),
}))

const mongoose = require('mongoose')
const ThreatLog = require('../models/ThreatLog')
const AIPrediction = require('../models/AIPrediction')
const SystemSetting = require('../models/SystemSetting')
const containmentService = require('../services/containmentService')
const aiEngineService = require('../services/aiEngineService')
const threatService = require('../services/threatService')
const aiService = require('../services/aiService')
const { createThreat, updateThreat } = require('../controllers/threatController')
const { errorHandler } = require('../middleware/errorHandler')

describe('Phase 3.1: ThreatLog Schema Telemetry & Traceability (OBS-01, REL-02)', () => {
  test('ThreatLog schema defines predictionId and eventTime fields', () => {
    const paths = ThreatLog.schema.paths
    expect(paths.predictionId).toBeDefined()
    expect(paths.predictionId.instance).toBe('ObjectId')
    expect(paths.predictionId.options.ref).toBe('AIPrediction')

    expect(paths.eventTime).toBeDefined()
    expect(paths.eventTime.instance).toBe('Date')
  })

  test('ThreatLog exports ALLOWED_ATTACK_TYPES matching enumValues', () => {
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toBeDefined()
    expect(Array.isArray(ThreatLog.ALLOWED_ATTACK_TYPES)).toBe(true)
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toContain('SSH Brute Force')
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toContain('DDoS')
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toContain('Port Scan')
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toContain('SQL Injection')
    expect(ThreatLog.ALLOWED_ATTACK_TYPES).toContain('UNINSPECTED_TRAFFIC')
  })
})

describe('Phase 3.1: SEC-01 & SEC-02 & REL-02 threatController.createThreat', () => {
  let req, res, next

  beforeEach(() => {
    req = {
      body: {},
      user: { _id: new mongoose.Types.ObjectId(), name: 'Analyst Jane', email: 'jane@sentinel.io', role: 'analyst' },
    }
    res = {
      statusCode: null,
      jsonData: null,
      status(code) {
        this.statusCode = code
        return this
      },
      json(data) {
        this.jsonData = data
        return this
      },
    }
    next = jest.fn()
    jest.clearAllMocks()
  })

  test('SEC-02: rejects invalid attackType with HTTP 400', async () => {
    req.body = {
      sourceIP: '192.168.1.50',
      attackType: 'ForgedMaliciousType',
      severity: 'HIGH',
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
    expect(res.jsonData.error).toMatch(/Valid attackType is required/)
  })

  test('SEC-02: rejects non-string attackType with HTTP 400', async () => {
    req.body = {
      sourceIP: '192.168.1.50',
      attackType: 12345,
      severity: 'HIGH',
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
  })

  test('SEC-01: strips client-supplied aiScore, confidence, and autonomousAction', async () => {
    const mockThreat = {
      _id: new mongoose.Types.ObjectId(),
      sourceIP: '192.168.1.50',
      attackType: 'Port Scan',
      severity: 'MEDIUM',
      aiScore: 0,
      confidence: 0,
      status: 'DETECTED',
      preBlockStatus: null,
      autonomousAction: { taken: false, actionType: null, actionTime: null },
      eventTime: null,
    }

    const spyCreateThreat = jest.spyOn(threatService, 'createThreat').mockResolvedValue(mockThreat)

    req.body = {
      sourceIP: '192.168.1.50',
      attackType: 'Port Scan',
      severity: 'MEDIUM',
      aiScore: 0.99,
      confidence: 0.98,
      status: 'BLOCKED',
      preBlockStatus: 'MONITORING',
      containmentId: new mongoose.Types.ObjectId(),
      isAiGenerated: true,
      autonomousAction: {
        taken: true,
        actionType: 'IP_BLOCKED',
        actionTime: new Date(),
      },
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(201)
    expect(spyCreateThreat).toHaveBeenCalledTimes(1)
    const passedData = spyCreateThreat.mock.calls[0][0]

    // Verify client overrides were stripped/neutralized:
    expect(passedData.aiScore).toBe(0)
    expect(passedData.confidence).toBe(0)
    expect(passedData.status).toBe('DETECTED')
    expect(passedData.preBlockStatus).toBeNull()
    expect(passedData.containmentId).toBeNull()
    expect(passedData.isAiGenerated).toBe(false)
    expect(passedData.autonomousAction).toEqual({
      taken: false,
      actionType: null,
      actionTime: null,
    })

    spyCreateThreat.mockRestore()
  })

  test('REL-02: parses valid ISO timestamp into eventTime Date', async () => {
    // Pick timestamp 10 minutes in the past
    const pastDate = new Date(Date.now() - 10 * 60 * 1000)
    const isoString = pastDate.toISOString()
    const spyCreateThreat = jest.spyOn(threatService, 'createThreat').mockImplementation(async (d) => ({
      _id: new mongoose.Types.ObjectId(),
      ...d,
    }))

    req.body = {
      sourceIP: '10.0.0.1',
      attackType: 'SSH Brute Force',
      timestamp: isoString,
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(201)
    const passedData = spyCreateThreat.mock.calls[0][0]
    expect(passedData.eventTime).toBeInstanceOf(Date)
    expect(passedData.eventTime.toISOString()).toBe(isoString)

    spyCreateThreat.mockRestore()
  })

  test('REL-02: parses valid numeric unix seconds timestamp into eventTime Date', async () => {
    const unixSeconds = Math.floor((Date.now() - 3600 * 1000) / 1000) // 1 hour ago
    const spyCreateThreat = jest.spyOn(threatService, 'createThreat').mockImplementation(async (d) => ({
      _id: new mongoose.Types.ObjectId(),
      ...d,
    }))

    req.body = {
      sourceIP: '10.0.0.1',
      attackType: 'SQL Injection',
      timestamp: unixSeconds,
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(201)
    const passedData = spyCreateThreat.mock.calls[0][0]
    expect(passedData.eventTime).toBeInstanceOf(Date)
    expect(passedData.eventTime.getTime()).toBe(unixSeconds * 1000)

    spyCreateThreat.mockRestore()
  })

  test('REL-02: rejects invalid timestamp format with HTTP 400', async () => {
    req.body = {
      sourceIP: '10.0.0.1',
      attackType: 'DDoS',
      timestamp: 'not-a-timestamp',
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
    expect(res.jsonData.error).toMatch(/Invalid event timestamp/i)
  })

  test('REL-02: rejects future timestamp (>1 min ahead) with HTTP 400', async () => {
    const futureDate = new Date(Date.now() + 10 * 60 * 1000).toISOString()
    req.body = {
      sourceIP: '10.0.0.1',
      attackType: 'DDoS',
      timestamp: futureDate,
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
    expect(res.jsonData.error).toMatch(/cannot be in the future/i)
  })

  test('REL-02: leaves eventTime null when missing without inventing current time', async () => {
    const spyCreateThreat = jest.spyOn(threatService, 'createThreat').mockImplementation(async (d) => ({
      _id: new mongoose.Types.ObjectId(),
      ...d,
    }))

    req.body = {
      sourceIP: '10.0.0.1',
      attackType: 'Port Scan',
    }

    await createThreat(req, res, next)

    expect(res.statusCode).toBe(201)
    const passedData = spyCreateThreat.mock.calls[0][0]
    expect(passedData.eventTime).toBeNull()

    spyCreateThreat.mockRestore()
  })
})

describe('Phase 3.1: SEC-03 threatController.updateThreat Tamper Prevention', () => {
  let req, res, next

  beforeEach(() => {
    req = {
      params: { id: new mongoose.Types.ObjectId().toString() },
      body: {},
      user: { _id: new mongoose.Types.ObjectId(), role: 'analyst' },
    }
    res = {
      statusCode: null,
      jsonData: null,
      status(code) {
        this.statusCode = code
        return this
      },
      json(data) {
        this.jsonData = data
        return this
      },
    }
    next = jest.fn()
    jest.clearAllMocks()
  })

  test('SEC-03: autonomousAction cannot be updated via PUT /api/threats/:id', async () => {
    const spyUpdateThreat = jest.spyOn(threatService, 'updateThreat').mockResolvedValue({
      _id: req.params.id,
      notes: 'Analyst note',
      status: 'MONITORING',
    })

    req.body = {
      notes: 'Analyst note',
      status: 'MONITORING',
      autonomousAction: {
        taken: true,
        actionType: 'IP_BLOCKED',
        actionTime: new Date(),
      },
      aiScore: 0.99,
    }

    await updateThreat(req, res, next)

    expect(res.statusCode).toBe(200)
    expect(spyUpdateThreat).toHaveBeenCalledTimes(1)
    const passedUpdates = spyUpdateThreat.mock.calls[0][1]

    expect(passedUpdates.notes).toBe('Analyst note')
    expect(passedUpdates.status).toBe('MONITORING')
    expect(passedUpdates.autonomousAction).toBeUndefined()
    expect(passedUpdates.aiScore).toBeUndefined()

    spyUpdateThreat.mockRestore()
  })

  test('SEC-03: rejects invalid handledBy ID with HTTP 400', async () => {
    req.body = {
      handledBy: 'invalid-not-an-objectid',
    }

    await updateThreat(req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
    expect(res.jsonData.error).toMatch(/Invalid handledBy user ID/)
  })
})

describe('Phase 3.1: SEC-01 threatService.createThreat Defense-in-Depth', () => {
  test('non-AI threat never executes auto-block even if autoBlockEnabled is true and aiScore >= blockThreshold', async () => {
    jest.spyOn(SystemSetting, 'findOne').mockResolvedValue({ key: 'autoBlockEnabled', value: true })
    jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.85)
    const spyAutoBlock = jest.spyOn(containmentService, 'executeAutoBlock').mockResolvedValue({ success: true })
    const spyThreatCreate = jest.spyOn(ThreatLog, 'create').mockImplementation(async (payload) => ({
      _id: new mongoose.Types.ObjectId(),
      ...payload,
    }))

    const result = await threatService.createThreat({
      sourceIP: '192.168.1.100',
      attackType: 'SSH Brute Force',
      severity: 'CRITICAL',
      aiScore: 0.99, // Attempted spoof without isAiGenerated
      isAiGenerated: false,
    })

    expect(spyAutoBlock).not.toHaveBeenCalled()
    expect(result.aiScore).toBe(0)
    expect(result.status).toBe('DETECTED')
    expect(result.autonomousAction.taken).toBe(false)

    SystemSetting.findOne.mockRestore()
    aiEngineService.getBlockThreshold.mockRestore()
    spyAutoBlock.mockRestore()
    spyThreatCreate.mockRestore()
  })
})

describe('Phase 3.1: OBS-01 aiService.storePrediction Bi-directional Linking', () => {
  test('high-threat prediction generates ThreatLog with predictionId, and AIPrediction has generatedThreat', async () => {
    const dummyPredId = new mongoose.Types.ObjectId()
    const dummyThreatId = new mongoose.Types.ObjectId()

    const mockPredDoc = {
      _id: dummyPredId,
      sourceIP: '185.220.101.5',
      predictedClass: 'DDoS',
      threatScore: 0.92,
      inputSource: 'network_traffic',
      generatedThreat: null,
      save: jest.fn().mockResolvedValue(true),
    }

    jest.spyOn(AIPrediction, 'create').mockResolvedValue(mockPredDoc)
    jest.spyOn(SystemSetting, 'findOne').mockResolvedValue({ key: 'autoBlockEnabled', value: false })
    jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.85)

    let createdThreatPayload = null
    jest.spyOn(ThreatLog, 'create').mockImplementation(async (payload) => {
      createdThreatPayload = {
        _id: dummyThreatId,
        ...payload,
      }
      return createdThreatPayload
    })

    const result = await aiService.storePrediction({
      sourceIP: '185.220.101.5',
      predictedClass: 'DDoS',
      threatScore: 0.92,
      inputSource: 'network_traffic',
      timestamp: '2026-10-18T07:15:00.000Z',
    })

    expect(createdThreatPayload).toBeDefined()
    expect(createdThreatPayload.predictionId).toEqual(dummyPredId)
    expect(createdThreatPayload.attackType).toBe('DDoS')
    expect(createdThreatPayload.eventTime).toEqual(new Date('2026-10-18T07:15:00.000Z'))
    expect(mockPredDoc.generatedThreat).toEqual(dummyThreatId)
    expect(mockPredDoc.save).toHaveBeenCalled()

    AIPrediction.create.mockRestore()
    SystemSetting.findOne.mockRestore()
    aiEngineService.getBlockThreshold.mockRestore()
    ThreatLog.create.mockRestore()
  })
})

describe('Phase 3.1: SEC-04 errorHandler CastError Message Sanitization', () => {
  test('CastError does not reflect raw untrusted user input', () => {
    const maliciousInput = '<script>alert("xss")</script>'
    const castError = {
      name: 'CastError',
      path: '_id',
      value: maliciousInput,
    }

    const req = { method: 'GET', path: '/api/threats/' + maliciousInput }
    const res = {
      statusCode: null,
      jsonData: null,
      status(code) {
        this.statusCode = code
        return this
      },
      json(data) {
        this.jsonData = data
        return this
      },
    }
    const next = jest.fn()

    errorHandler(castError, req, res, next)

    expect(res.statusCode).toBe(400)
    expect(res.jsonData.success).toBe(false)
    expect(res.jsonData.error).toBe('Invalid identifier for _id')
    expect(res.jsonData.error).not.toContain(maliciousInput)
  })
})
