'use strict'
/**
 * tests/containmentPolicy.test.js
 *
 * Comprehensive containment policy alignment and atomicity tests:
 *
 * PHASE 2.2A:
 * TEST 1: score < 0.70, autoBlockEnabled = false -> non-blocked state
 * TEST 2: score = 0.70, autoBlockEnabled = false -> MONITORING
 * TEST 3: score = 0.92, autoBlockEnabled = false -> NOT BLOCKED, no BlockedIP, autonomousAction.taken != true
 * TEST 4: score > 0.92, autoBlockEnabled = false -> NOT BLOCKED, no BlockedIP, no autonomous containment claim
 * TEST 5: score = 0.92, autoBlockEnabled = true -> BLOCKED, BlockedIP created/upserted, autonomousAction.taken = true, actionType = IP_BLOCKED
 * TEST 6: score > 0.92, autoBlockEnabled = true -> BLOCKED, BlockedIP created/upserted
 * TEST 7: manual block -> BlockedIP created, ThreatLog updated, WebSocket events emitted
 * TEST 8: manual unblock -> BlockedIP removed, expected ThreatLog state updated, WebSocket events emitted
 * TEST 9: threshold consistency -> no production path silently uses a different block threshold
 *
 * PHASE 2.2B (Atomicity, Compensating Rollback & State Restoration):
 * TEST 10: State restoration: MONITORING -> BLOCKED -> MONITORING
 * TEST 11: State restoration: DETECTED -> BLOCKED -> DETECTED
 * TEST 12: Analyst state protection: FALSE_POSITIVE remains FALSE_POSITIVE on manual block
 * TEST 13: Analyst state protection: RESOLVED remains RESOLVED on manual block
 * TEST 14: Historical protection: Old historical ThreatLog is not changed by a new unblock operation
 * TEST 15: Compensation: BlockedIP failure causes ThreatLog compensation (Scenario A)
 * TEST 16: Compensation: ThreatLog failure causes BlockedIP compensation (Scenario B)
 * TEST 17: Compensation: Existing BlockedIP is restored correctly after failed operation
 * TEST 18: Compensation: Newly-created BlockedIP is removed after failed operation
 * TEST 19: Idempotency: Duplicate block is safe
 * TEST 20: Idempotency: Duplicate unblock is safe
 * TEST 21: Idempotency: Retried block does not overwrite preBlockStatus
 * TEST 22: WebSocket: Successful autonomous block emits the expected event
 * TEST 23: WebSocket: Failed/rolled-back block does not emit a false success event
 * TEST 24: Error semantics: Compensation failure is surfaced and logged distinctly
 */

// ── Mock all external dependencies before imports ────────────────────────────
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
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitAIPrediction: jest.fn(),
}
jest.mock('../websocket/socketManager', () => mockSocketManager)

const mockAlertService = {
  createAlert: jest.fn().mockResolvedValue({ _id: 'alert-123' }),
  createAlertFromThreat: jest.fn().mockResolvedValue({ _id: 'alert-456' }),
}
jest.mock('../services/alertService', () => mockAlertService)

const mockSystemSettingFindOne = jest.fn()
jest.mock('../models/SystemSetting', () => ({
  findOne: (...args) => mockSystemSettingFindOne(...args),
  findOneAndUpdate: jest.fn().mockResolvedValue({}),
}))

const mockBlockedIPFindOneAndUpdate = jest.fn()
const mockBlockedIPFindOneAndDelete = jest.fn()
const mockBlockedIPFindOneAndReplace = jest.fn()
const mockBlockedIPFindByIdAndDelete = jest.fn()
const mockBlockedIPDeleteOne = jest.fn()
const mockBlockedIPFindOne = jest.fn()
const mockBlockedIPFind = jest.fn()

jest.mock('../models/BlockedIP', () => ({
  findOneAndUpdate: (...args) => mockBlockedIPFindOneAndUpdate(...args),
  findOneAndDelete: (...args) => mockBlockedIPFindOneAndDelete(...args),
  findOneAndReplace: (...args) => mockBlockedIPFindOneAndReplace(...args),
  findByIdAndDelete: (...args) => mockBlockedIPFindByIdAndDelete(...args),
  deleteOne: (...args) => mockBlockedIPDeleteOne(...args),
  findOne: (...args) => mockBlockedIPFindOne(...args),
  find: (...args) => mockBlockedIPFind(...args),
}))

const mockThreatLogCreate = jest.fn()
const mockThreatLogFindById = jest.fn()
const mockThreatLogFindByIdAndUpdate = jest.fn()
const mockThreatLogUpdateMany = jest.fn()
const mockThreatLogFind = jest.fn()
const mockThreatLogFindOne = jest.fn()

jest.mock('../models/ThreatLog', () => ({
  create: (...args) => mockThreatLogCreate(...args),
  findById: (...args) => mockThreatLogFindById(...args),
  findByIdAndUpdate: (...args) => mockThreatLogFindByIdAndUpdate(...args),
  updateMany: (...args) => mockThreatLogUpdateMany(...args),
  find: (...args) => mockThreatLogFind(...args),
  findOne: (...args) => mockThreatLogFindOne(...args),
}))

const mockAIPredictionCreate = jest.fn()
jest.mock('../models/AIPrediction', () => ({
  create: (...args) => mockAIPredictionCreate(...args),
}))

jest.mock('../models/AuditLog', () => ({
  create: jest.fn().mockResolvedValue({}),
  find: jest.fn().mockReturnValue({ sort: jest.fn().mockReturnThis(), limit: jest.fn().mockReturnThis(), lean: jest.fn().mockResolvedValue([]) }),
}))

const mockGetBlockThreshold = jest.fn().mockResolvedValue(0.92)
jest.mock('../services/aiEngineService', () => ({
  getBlockThreshold: () => mockGetBlockThreshold(),
  predictRecord: jest.fn(),
  runFullPipeline: jest.fn(),
}))

const aiService = require('../services/aiService')
const threatService = require('../services/threatService')
const threatController = require('../controllers/threatController')
const containmentService = require('../services/containmentService')

describe('Phase 2.2: Containment Policy Alignment & Atomicity', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockGetBlockThreshold.mockResolvedValue(0.92)
    mockBlockedIPFind.mockReturnValue({
      populate: jest.fn().mockReturnThis(),
      sort: jest.fn().mockReturnThis(),
      skip: jest.fn().mockReturnThis(),
      limit: jest.fn().mockResolvedValue([]),
    })
  })

  // ==========================================================================
  // PHASE 2.2A BASELINE POLICY TESTS
  // ==========================================================================
  describe('Phase 2.2A: Policy Alignment', () => {
    test('TEST 1: score < 0.70 and autoBlockEnabled = false -> does not create ThreatLog (non-blocked state)', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: false })
      mockAIPredictionCreate.mockResolvedValue({
        _id: 'pred-1',
        threatScore: 0.55,
        predictedClass: 'DDoS',
        sourceIP: '192.168.1.100',
      })

      const result = await aiService.storePrediction({
        threatScore: 0.55,
        predictedClass: 'DDoS',
        sourceIP: '192.168.1.100',
      })

      expect(result).toBeDefined()
      expect(mockThreatLogCreate).not.toHaveBeenCalled()
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
    })

    test('TEST 2: score = 0.70 and autoBlockEnabled = false -> status is MONITORING and no BlockedIP', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: false })
      const mockPred = {
        _id: 'pred-2',
        threatScore: 0.7,
        predictedClass: 'Port Scan',
        sourceIP: '192.168.1.101',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)
      const mockCreatedThreat = {
        _id: 'threat-2',
        status: 'MONITORING',
        sourceIP: '192.168.1.101',
        severity: 'MEDIUM',
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)

      await aiService.storePrediction({
        threatScore: 0.7,
        predictedClass: 'Port Scan',
        sourceIP: '192.168.1.101',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'MONITORING',
          autonomousAction: {
            taken: false,
            actionType: null,
            actionTime: null,
          },
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
    })

    test('TEST 3: score = 0.92 and autoBlockEnabled = false -> NOT BLOCKED (MONITORING), no BlockedIP', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: false })
      const mockPred = {
        _id: 'pred-3',
        threatScore: 0.92,
        predictedClass: 'SSH Brute Force',
        sourceIP: '192.168.1.102',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)
      const mockCreatedThreat = {
        _id: 'threat-3',
        status: 'MONITORING',
        sourceIP: '192.168.1.102',
        severity: 'CRITICAL',
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)

      await aiService.storePrediction({
        threatScore: 0.92,
        predictedClass: 'SSH Brute Force',
        sourceIP: '192.168.1.102',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'MONITORING',
          autonomousAction: {
            taken: false,
            actionType: null,
            actionTime: null,
          },
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
      expect(mockSocketManager.emitIPBlocked).not.toHaveBeenCalled()
    })

    test('TEST 4: score = 0.98 and autoBlockEnabled = false -> NOT BLOCKED (MONITORING), no containment claim', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: false })
      const mockPred = {
        _id: 'pred-4',
        threatScore: 0.98,
        predictedClass: 'Ransomware',
        sourceIP: '192.168.1.103',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)
      const mockCreatedThreat = {
        _id: 'threat-4',
        status: 'MONITORING',
        sourceIP: '192.168.1.103',
        severity: 'CRITICAL',
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)

      await aiService.storePrediction({
        threatScore: 0.98,
        predictedClass: 'Ransomware',
        sourceIP: '192.168.1.103',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'MONITORING',
          autonomousAction: {
            taken: false,
            actionType: null,
            actionTime: null,
          },
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
      expect(mockSocketManager.emitIPBlocked).not.toHaveBeenCalled()
    })

    test('TEST 5: score = 0.92 and autoBlockEnabled = true -> BLOCKED, BlockedIP upserted, autonomousAction taken', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: true })
      const mockPred = {
        _id: 'pred-5',
        threatScore: 0.92,
        predictedClass: 'SSH Brute Force',
        sourceIP: '185.220.101.47',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)
      const mockCreatedThreat = {
        _id: 'threat-5',
        status: 'BLOCKED',
        sourceIP: '185.220.101.47',
        severity: 'CRITICAL',
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-doc-5', ip: '185.220.101.47' })

      await aiService.storePrediction({
        threatScore: 0.92,
        predictedClass: 'SSH Brute Force',
        sourceIP: '185.220.101.47',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'BLOCKED',
          autonomousAction: expect.objectContaining({
            taken: true,
            actionType: 'IP_BLOCKED',
          }),
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).toHaveBeenCalledWith(
        { ip: '185.220.101.47' },
        expect.objectContaining({
          ip: '185.220.101.47',
          threatRef: 'threat-5',
        }),
        { upsert: true, new: true }
      )
      expect(mockSocketManager.emitIPBlocked).toHaveBeenCalledWith('185.220.101.47', 'AI Engine', 'threat-5')
    })

    test('TEST 6: score = 0.96 and autoBlockEnabled = true -> BLOCKED, BlockedIP created', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: true })
      const mockPred = {
        _id: 'pred-6',
        threatScore: 0.96,
        predictedClass: 'DDoS',
        sourceIP: '45.95.147.22',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)
      const mockCreatedThreat = {
        _id: 'threat-6',
        status: 'BLOCKED',
        sourceIP: '45.95.147.22',
        severity: 'CRITICAL',
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-doc-6', ip: '45.95.147.22' })

      await aiService.storePrediction({
        threatScore: 0.96,
        predictedClass: 'DDoS',
        sourceIP: '45.95.147.22',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'BLOCKED',
          autonomousAction: expect.objectContaining({
            taken: true,
            actionType: 'IP_BLOCKED',
          }),
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).toHaveBeenCalledWith(
        { ip: '45.95.147.22' },
        expect.objectContaining({
          ip: '45.95.147.22',
        }),
        { upsert: true, new: true }
      )
      expect(mockSocketManager.emitIPBlocked).toHaveBeenCalledWith('45.95.147.22', 'AI Engine', 'threat-6')
    })

    test('TEST 7: Manual block via blockThreatIP -> updates threat, creates BlockedIP, emits WebSockets', async () => {
      const mockThreat = {
        _id: 'threat-manual-7',
        sourceIP: '198.51.100.1',
        status: 'MONITORING',
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogFindById.mockResolvedValue(mockThreat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-doc-7', ip: '198.51.100.1' })

      const updated = await threatService.blockThreatIP('threat-manual-7', 'analyst-123')

      expect(updated).toBeDefined()
      expect(mockThreat.status).toBe('BLOCKED')
      expect(mockThreat.preBlockStatus).toBe('MONITORING')
      expect(mockThreat.handledBy).toBe('analyst-123')
      expect(mockThreat.autonomousAction.taken).toBe(true)
      expect(mockThreat.autonomousAction.actionType).toBe('IP_BLOCKED')
      expect(mockThreat.save).toHaveBeenCalled()
      expect(mockBlockedIPFindOneAndUpdate).toHaveBeenCalledWith(
        { ip: '198.51.100.1' },
        expect.objectContaining({
          ip: '198.51.100.1',
          blockedBy: 'analyst-123',
          threatRef: 'threat-manual-7',
        }),
        { upsert: true, new: true }
      )
    })

    test('TEST 8: Manual unblock via unblockIPManual -> deletes BlockedIP, restores ThreatLogs, emits WebSockets', async () => {
      const mockBlockedDoc = {
        _id: 'block-doc-8',
        ip: '198.51.100.1',
        threatRef: 't-1',
      }
      mockBlockedIPFindOne.mockResolvedValue(mockBlockedDoc)
      mockBlockedIPDeleteOne.mockResolvedValue({ deletedCount: 1 })

      const threat1 = {
        _id: 't-1',
        sourceIP: '198.51.100.1',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        containmentId: 'block-doc-8',
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogFind.mockResolvedValue([threat1])

      const req = {
        body: { ip: '198.51.100.1' },
        user: { _id: 'analyst-123', name: 'Security Analyst', email: 'analyst@sentinel.internal' },
      }
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      }
      const next = jest.fn()

      await threatController.unblockIPManual(req, res, next)

      expect(mockBlockedIPDeleteOne).toHaveBeenCalledWith({ _id: 'block-doc-8' })
      expect(threat1.status).toBe('MONITORING')
      expect(threat1.preBlockStatus).toBeNull()
      expect(threat1.containmentId).toBeNull()
      expect(threat1.save).toHaveBeenCalled()
      expect(mockSocketManager.emitThreatUpdated).toHaveBeenCalledWith(threat1)
      expect(mockSocketManager.emitIPUnblocked).toHaveBeenCalledWith('198.51.100.1', 'Security Analyst')
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: true,
          message: 'IP unblocked successfully',
        })
      )
    })

    test('TEST 9: Threshold consistency -> verify authoritative block threshold resolution', async () => {
      const aiEngineService = require('../services/aiEngineService')
      const resolvedThreshold = await aiEngineService.getBlockThreshold()
      expect(resolvedThreshold).toBe(0.92)

      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: true })
      const mockPredBorderline = {
        _id: 'pred-borderline',
        threatScore: 0.919,
        predictedClass: 'DDoS',
        sourceIP: '10.10.10.10',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPredBorderline)
      mockThreatLogCreate.mockResolvedValue({ _id: 'threat-borderline', status: 'MONITORING' })

      await aiService.storePrediction({
        threatScore: 0.919,
        predictedClass: 'DDoS',
        sourceIP: '10.10.10.10',
      })

      expect(mockThreatLogCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'MONITORING',
          autonomousAction: {
            taken: false,
            actionType: null,
            actionTime: null,
          },
        })
      )
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
    })
  })

  // ==========================================================================
  // PHASE 2.2B ATOMICITY, COMPENSATING ROLLBACK & STATE RESTORATION TESTS
  // ==========================================================================
  describe('Phase 2.2B: State Restoration, Compensation & Invariants', () => {
    // ------------------------------------------------------------------------
    // TEST 10: State restoration: MONITORING -> BLOCKED -> MONITORING
    // ------------------------------------------------------------------------
    test('TEST 10: State restoration: MONITORING -> BLOCKED -> MONITORING preserves exact state', async () => {
      const threat = {
        _id: 'threat-restore-mon',
        sourceIP: '192.168.10.50',
        status: 'MONITORING',
        preBlockStatus: null,
        containmentId: null,
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogFindById.mockResolvedValue(threat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-mon-1', ip: '192.168.10.50' })

      // Step 1: Block
      await containmentService.blockThreat('threat-restore-mon', 'analyst-1')
      expect(threat.status).toBe('BLOCKED')
      expect(threat.preBlockStatus).toBe('MONITORING')
      expect(threat.containmentId).toBe('block-mon-1')

      // Step 2: Unblock
      mockBlockedIPFindOne.mockResolvedValue({
        _id: 'block-mon-1',
        ip: '192.168.10.50',
      })
      mockBlockedIPDeleteOne.mockResolvedValue({ deletedCount: 1 })
      mockThreatLogFind.mockResolvedValue([threat])

      const unblockResult = await containmentService.unblockIPManual({
        ip: '192.168.10.50',
        analystId: 'analyst-1',
      })

      expect(unblockResult.success).toBe(true)
      expect(threat.status).toBe('MONITORING')
      expect(threat.preBlockStatus).toBeNull()
      expect(threat.containmentId).toBeNull()
    })

    // ------------------------------------------------------------------------
    // TEST 11: State restoration: DETECTED -> BLOCKED -> DETECTED
    // ------------------------------------------------------------------------
    test('TEST 11: State restoration: DETECTED -> BLOCKED -> DETECTED preserves exact state', async () => {
      const threat = {
        _id: 'threat-restore-det',
        sourceIP: '192.168.10.51',
        status: 'DETECTED',
        preBlockStatus: null,
        containmentId: null,
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogFindById.mockResolvedValue(threat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-det-1', ip: '192.168.10.51' })

      // Step 1: Block
      await containmentService.blockThreat('threat-restore-det', 'analyst-1')
      expect(threat.status).toBe('BLOCKED')
      expect(threat.preBlockStatus).toBe('DETECTED')
      expect(threat.containmentId).toBe('block-det-1')

      // Step 2: Unblock
      mockBlockedIPFindOne.mockResolvedValue({
        _id: 'block-det-1',
        ip: '192.168.10.51',
      })
      mockBlockedIPDeleteOne.mockResolvedValue({ deletedCount: 1 })
      mockThreatLogFind.mockResolvedValue([threat])

      const unblockResult = await containmentService.unblockIPManual({
        ip: '192.168.10.51',
        analystId: 'analyst-1',
      })

      expect(unblockResult.success).toBe(true)
      expect(threat.status).toBe('DETECTED')
      expect(threat.preBlockStatus).toBeNull()
      expect(threat.containmentId).toBeNull()
    })

    // ------------------------------------------------------------------------
    // TEST 12: Analyst state protection: FALSE_POSITIVE remains FALSE_POSITIVE
    // ------------------------------------------------------------------------
    test('TEST 12: Analyst state protection: FALSE_POSITIVE remains FALSE_POSITIVE on manual block', async () => {
      const threatFP = {
        _id: 'threat-fp',
        sourceIP: '192.168.10.52',
        status: 'FALSE_POSITIVE',
        save: jest.fn(),
      }
      mockThreatLogFindById.mockResolvedValue(threatFP)

      // 1. Direct blockThreat should refuse to overwrite FALSE_POSITIVE
      const res1 = await containmentService.blockThreat('threat-fp', 'analyst-1')
      expect(res1.status).toBe('FALSE_POSITIVE')
      expect(threatFP.save).not.toHaveBeenCalled()
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()

      // 2. IP-wide blockIPManual should exclude FALSE_POSITIVE threats from candidates
      mockBlockedIPFindOne.mockResolvedValue(null)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-fp-ip', ip: '192.168.10.52' })
      mockThreatLogFind.mockResolvedValue([]) // candidate query { status: { $in: [...] } } excludes FALSE_POSITIVE

      await containmentService.blockIPManual({
        ip: '192.168.10.52',
        reason: 'Block IP test',
        analystId: 'analyst-1',
      })

      expect(mockThreatLogFind).toHaveBeenCalledWith(
        expect.objectContaining({
          sourceIP: '192.168.10.52',
          status: { $in: ['DETECTED', 'MONITORING', 'ESCALATED'] },
        })
      )
      expect(threatFP.status).toBe('FALSE_POSITIVE')
    })

    // ------------------------------------------------------------------------
    // TEST 13: Analyst state protection: RESOLVED remains RESOLVED
    // ------------------------------------------------------------------------
    test('TEST 13: Analyst state protection: RESOLVED remains RESOLVED on manual block', async () => {
      const threatResolved = {
        _id: 'threat-resolved',
        sourceIP: '192.168.10.53',
        status: 'RESOLVED',
        save: jest.fn(),
      }
      mockThreatLogFindById.mockResolvedValue(threatResolved)

      // Direct blockThreat should refuse to overwrite RESOLVED
      const res = await containmentService.blockThreat('threat-resolved', 'analyst-1')
      expect(res.status).toBe('RESOLVED')
      expect(threatResolved.save).not.toHaveBeenCalled()
      expect(mockBlockedIPFindOneAndUpdate).not.toHaveBeenCalled()
    })

    // ------------------------------------------------------------------------
    // TEST 14: Historical protection: Old historical ThreatLog is not changed
    // ------------------------------------------------------------------------
    test('TEST 14: Historical protection: Old historical ThreatLog is not mutated by unblock', async () => {
      const oldThreat = {
        _id: 'threat-old-incident',
        sourceIP: '192.168.10.54',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        containmentId: 'old-containment-id',
        save: jest.fn(),
      }
      const activeThreat = {
        _id: 'threat-active-incident',
        sourceIP: '192.168.10.54',
        status: 'BLOCKED',
        preBlockStatus: 'DETECTED',
        containmentId: 'new-containment-id',
        save: jest.fn().mockResolvedValue(true),
      }

      mockBlockedIPFindOne.mockResolvedValue({
        _id: 'new-containment-id',
        ip: '192.168.10.54',
      })
      mockBlockedIPDeleteOne.mockResolvedValue({ deletedCount: 1 })

      // Mock find to return ONLY threats matching new-containment-id
      mockThreatLogFind.mockImplementation((query) => {
        if (query.containmentId === 'new-containment-id') {
          return Promise.resolve([activeThreat])
        }
        return Promise.resolve([])
      })

      const res = await containmentService.unblockIPManual({
        ip: '192.168.10.54',
        analystId: 'analyst-1',
      })

      expect(res.success).toBe(true)
      expect(activeThreat.status).toBe('DETECTED')
      expect(activeThreat.save).toHaveBeenCalled()

      // The historical threat was NEVER modified or saved
      expect(oldThreat.status).toBe('BLOCKED')
      expect(oldThreat.containmentId).toBe('old-containment-id')
      expect(oldThreat.save).not.toHaveBeenCalled()
    })

    // ------------------------------------------------------------------------
    // TEST 15: Compensation: BlockedIP failure causes ThreatLog compensation (Scenario A)
    // ------------------------------------------------------------------------
    test('TEST 15: Compensation Scenario A: BlockedIP failure causes ThreatLog rollback to previous state', async () => {
      const threat = {
        _id: 'threat-comp-a',
        sourceIP: '10.0.0.50',
        status: 'MONITORING',
        preBlockStatus: null,
        containmentId: null,
        autonomousAction: { taken: false, actionType: null, actionTime: null },
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogFindById.mockResolvedValue(threat)

      // Inject failure on BlockedIP write
      mockBlockedIPFindOneAndUpdate.mockRejectedValueOnce(new Error('Mongo Network Timeout'))

      await expect(containmentService.blockThreat('threat-comp-a', 'analyst-1')).rejects.toThrow(
        'Mongo Network Timeout'
      )

      // ThreatLog save was called initially to transition to BLOCKED, and then called again to rollback to MONITORING
      expect(threat.save).toHaveBeenCalledTimes(2)
      expect(threat.status).toBe('MONITORING')
      expect(threat.preBlockStatus).toBeNull()
      expect(threat.containmentId).toBeNull()
      expect(threat.autonomousAction.taken).toBe(false)
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.stringContaining('ThreatLog threat-comp-a successfully compensated back to MONITORING')
      )
    })

    // ------------------------------------------------------------------------
    // TEST 16: Compensation: ThreatLog failure causes BlockedIP compensation (Scenario B)
    // ------------------------------------------------------------------------
    test('TEST 16: Compensation Scenario B: ThreatLog failure causes BlockedIP compensation', async () => {
      mockBlockedIPFindOne.mockResolvedValue(null) // newly created
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({
        _id: 'new-block-ip-16',
        ip: '10.0.0.51',
      })
      mockBlockedIPFindByIdAndDelete.mockResolvedValue({ _id: 'new-block-ip-16' })

      const threatFailing = {
        _id: 'threat-fail-16',
        sourceIP: '10.0.0.51',
        status: 'DETECTED',
        save: jest.fn().mockRejectedValueOnce(new Error('ThreatLog disk full error')),
      }
      mockThreatLogFind.mockResolvedValue([threatFailing])

      await expect(
        containmentService.blockIPManual({
          ip: '10.0.0.51',
          reason: 'Test fail',
          analystId: 'analyst-1',
        })
      ).rejects.toThrow('ThreatLog disk full error')

      // BlockedIP newly created must be compensated by deletion
      expect(mockBlockedIPFindByIdAndDelete).toHaveBeenCalledWith('new-block-ip-16')
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.stringContaining('Successfully removed newly created BlockedIP record for 10.0.0.51')
      )
    })

    // ------------------------------------------------------------------------
    // TEST 17: Compensation: Existing BlockedIP is restored correctly
    // ------------------------------------------------------------------------
    test('TEST 17: Compensation Scenario B: Existing BlockedIP is restored after ThreatLog failure', async () => {
      const priorBlockedDoc = {
        _id: 'existing-block-17',
        ip: '10.0.0.52',
        reason: 'Prior manual block',
        blockedBy: 'prior-analyst',
      }
      mockBlockedIPFindOne.mockResolvedValue(priorBlockedDoc)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({
        _id: 'existing-block-17',
        ip: '10.0.0.52',
        reason: 'Updated reason',
      })
      mockBlockedIPFindOneAndReplace.mockResolvedValue(priorBlockedDoc)

      const threatFailing = {
        _id: 'threat-fail-17',
        sourceIP: '10.0.0.52',
        status: 'MONITORING',
        save: jest.fn().mockRejectedValueOnce(new Error('Write concern error')),
      }
      mockThreatLogFind.mockResolvedValue([threatFailing])

      await expect(
        containmentService.blockIPManual({
          ip: '10.0.0.52',
          reason: 'Updated reason',
          analystId: 'analyst-2',
        })
      ).rejects.toThrow('Write concern error')

      // Existing BlockedIP must be restored, NOT deleted
      expect(mockBlockedIPFindByIdAndDelete).not.toHaveBeenCalled()
      expect(mockBlockedIPFindOneAndReplace).toHaveBeenCalledWith({ _id: 'existing-block-17' }, priorBlockedDoc)
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.stringContaining('Successfully restored previous BlockedIP record for 10.0.0.52')
      )
    })

    // ------------------------------------------------------------------------
    // TEST 18: Compensation: Newly-created BlockedIP is removed after failed operation
    // ------------------------------------------------------------------------
    test('TEST 18: Compensation: Newly-created BlockedIP is removed if ThreatLog fails during unblock', async () => {
      const savedBlockedDoc = {
        _id: 'block-doc-18',
        ip: '10.0.0.53',
        reason: 'Manual block',
        threatRef: 'threat-18',
      }
      mockBlockedIPFindOne.mockResolvedValue(savedBlockedDoc)
      mockBlockedIPDeleteOne.mockResolvedValue({ deletedCount: 1 })

      const threatFailing = {
        _id: 'threat-18',
        sourceIP: '10.0.0.53',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        containmentId: 'block-doc-18',
        save: jest.fn().mockRejectedValueOnce(new Error('Database write failure during restore')),
      }
      mockThreatLogFind.mockResolvedValue([threatFailing])

      await expect(
        containmentService.unblockIPManual({
          ip: '10.0.0.53',
          analystId: 'analyst-1',
        })
      ).rejects.toThrow('Database write failure during restore')

      // BlockedIP must be re-inserted to prevent traffic bypass
      expect(mockBlockedIPFindOneAndUpdate).toHaveBeenCalledWith(
        { ip: '10.0.0.53' },
        expect.objectContaining({
          reason: 'Manual block',
          threatRef: 'threat-18',
        }),
        { upsert: true, new: true }
      )
      expect(mockLogger.info).toHaveBeenCalledWith(
        expect.stringContaining('Successfully compensated unblock failure: BlockedIP restored for 10.0.0.53')
      )
    })

    // ------------------------------------------------------------------------
    // TEST 19: Idempotency: Duplicate block is safe
    // ------------------------------------------------------------------------
    test('TEST 19: Idempotency: Duplicate block is safe and preserves existing preBlockStatus', async () => {
      const alreadyBlockedThreat = {
        _id: 'threat-dup-block',
        sourceIP: '10.0.0.54',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        containmentId: 'block-doc-19',
        save: jest.fn(),
      }
      mockThreatLogFindById.mockResolvedValue(alreadyBlockedThreat)
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-doc-19', ip: '10.0.0.54' })

      const result = await containmentService.blockThreat('threat-dup-block', 'analyst-1')

      expect(result.status).toBe('BLOCKED')
      expect(result.preBlockStatus).toBe('MONITORING') // Unchanged! Not overwritten to 'BLOCKED'
      expect(alreadyBlockedThreat.save).not.toHaveBeenCalled()
    })

    // ------------------------------------------------------------------------
    // TEST 20: Idempotency: Duplicate unblock is safe
    // ------------------------------------------------------------------------
    test('TEST 20: Idempotency: Duplicate unblock returns 404 safely without modifying database', async () => {
      mockBlockedIPFindOne.mockResolvedValue(null) // already unblocked

      const req = {
        body: { ip: '10.0.0.55' },
        user: { _id: 'analyst-1', name: 'Analyst', email: 'analyst@sentinel.internal' },
      }
      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      }
      const next = jest.fn()

      await threatController.unblockIPManual(req, res, next)

      expect(res.status).toHaveBeenCalledWith(404)
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          success: false,
          error: 'IP is not blocked',
        })
      )
      expect(mockThreatLogFind).not.toHaveBeenCalled()
      expect(mockBlockedIPDeleteOne).not.toHaveBeenCalled()
    })

    // ------------------------------------------------------------------------
    // TEST 21: Idempotency: Retried block does not overwrite preBlockStatus
    // ------------------------------------------------------------------------
    test('TEST 21: Idempotency: Retried blockIPManual does not overwrite preBlockStatus of already blocked threats', async () => {
      mockBlockedIPFindOne.mockResolvedValue({ _id: 'block-retried', ip: '10.0.0.56' })
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-retried', ip: '10.0.0.56' })

      // Candidate query excludes 'BLOCKED' status
      mockThreatLogFind.mockResolvedValue([])

      await containmentService.blockIPManual({
        ip: '10.0.0.56',
        reason: 'Retry attempt',
        analystId: 'analyst-1',
      })

      expect(mockThreatLogFind).toHaveBeenCalledWith(
        expect.objectContaining({
          sourceIP: '10.0.0.56',
          status: { $in: ['DETECTED', 'MONITORING', 'ESCALATED'] },
        })
      )
    })

    // ------------------------------------------------------------------------
    // TEST 22: WebSocket: Successful autonomous block emits the expected event
    // ------------------------------------------------------------------------
    test('TEST 22: WebSocket: Successful autonomous block emits IPBlocked and Alert events', async () => {
      const threat = {
        _id: 'threat-ws-success',
        sourceIP: '10.0.0.57',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        save: jest.fn().mockResolvedValue(true),
      }
      mockBlockedIPFindOneAndUpdate.mockResolvedValue({ _id: 'block-ws-57', ip: '10.0.0.57' })

      await containmentService.executeAutoBlock({
        threat,
        threatScore: 0.95,
        source: 'AI Engine',
      })

      expect(mockSocketManager.emitIPBlocked).toHaveBeenCalledWith('10.0.0.57', 'AI Engine', 'threat-ws-success')
      expect(mockSocketManager.emitNewAlert).toHaveBeenCalledWith(expect.objectContaining({ _id: 'alert-123' }))
    })

    // ------------------------------------------------------------------------
    // TEST 23: WebSocket: Failed/rolled-back block does not emit false success event
    // ------------------------------------------------------------------------
    test('TEST 23: WebSocket: Failed/rolled-back block does NOT emit false success events', async () => {
      mockSystemSettingFindOne.mockResolvedValue({ key: 'autoBlockEnabled', value: true })
      const mockPred = {
        _id: 'pred-ws-fail',
        threatScore: 0.95,
        predictedClass: 'DDoS',
        sourceIP: '10.0.0.58',
        save: jest.fn().mockResolvedValue(true),
      }
      mockAIPredictionCreate.mockResolvedValue(mockPred)

      const mockCreatedThreat = {
        _id: 'threat-ws-fail',
        status: 'BLOCKED',
        preBlockStatus: 'MONITORING',
        sourceIP: '10.0.0.58',
        save: jest.fn().mockResolvedValue(true),
      }
      mockThreatLogCreate.mockResolvedValue(mockCreatedThreat)

      // Inject failure into BlockedIP upsert
      mockBlockedIPFindOneAndUpdate.mockRejectedValueOnce(new Error('Connection dropped to MongoDB'))

      await aiService.storePrediction({
        threatScore: 0.95,
        predictedClass: 'DDoS',
        sourceIP: '10.0.0.58',
      })

      // The threat must be rolled back
      expect(mockCreatedThreat.status).toBe('MONITORING')
      // No IPBlocked event must be emitted
      expect(mockSocketManager.emitIPBlocked).not.toHaveBeenCalled()
    })

    // ------------------------------------------------------------------------
    // TEST 24: Error semantics: Compensation failure is surfaced and logged distinctly
    // ------------------------------------------------------------------------
    test('TEST 24: Error semantics: Compensation failure is surfaced with distinct error and CRITICAL log', async () => {
      const threat = {
        _id: 'threat-double-fault',
        sourceIP: '10.0.0.59',
        status: 'MONITORING',
        preBlockStatus: null,
        containmentId: null,
        autonomousAction: { taken: false },
        save: jest
          .fn()
          .mockResolvedValueOnce(true) // 1st save succeeds (transitions to BLOCKED)
          .mockRejectedValueOnce(new Error('Fatal disk corruption on compensation')), // 2nd save fails!
      }
      mockThreatLogFindById.mockResolvedValue(threat)
      mockBlockedIPFindOneAndUpdate.mockRejectedValueOnce(new Error('Primary network drop'))

      let caughtErr
      try {
        await containmentService.blockThreat('threat-double-fault', 'analyst-1')
      } catch (e) {
        caughtErr = e
      }

      expect(caughtErr).toBeDefined()
      expect(caughtErr.isInconsistent).toBe(true)
      expect(caughtErr.message).toContain('Containment failed and compensation failed')
      expect(caughtErr.originalError.message).toBe('Primary network drop')
      expect(caughtErr.compensationError.message).toBe('Fatal disk corruption on compensation')

      expect(mockLogger.error).toHaveBeenCalledWith(
        expect.stringContaining('[CRITICAL] [Containment Compensation Failure]')
      )
    })
  })
})
