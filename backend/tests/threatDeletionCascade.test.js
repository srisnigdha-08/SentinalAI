'use strict'

/**
 * tests/threatDeletionCascade.test.js
 *
 * TASK 6 Verification: Stop Orphaned Alerts at the Source
 *
 * Verifies:
 * 1. threatService.deleteThreat(id) removes the ThreatLog AND associated Alert documents
 *    matching { 'sourceRef.refModel': 'ThreatLog', 'sourceRef.refId': threatId }.
 * 2. threatService.deleteThreat(id) does not invoke Alert.deleteMany if ThreatLog does not exist.
 * 3. threatController.deleteThreat enforces the AUDIT-FIRST policy: if logAudit rejects,
 *    the deletion aborts, returning HTTP 500, and threatService.deleteThreat is never called.
 * 4. threatController.deleteThreat invokes threatService.deleteThreat only when audit succeeds,
 *    returning HTTP 200 with { success: true, message: 'Deleted' }.
 * 5. threatController.deleteThreat returns HTTP 404 when threat does not exist, without invoking audit or service deletion.
 */

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-threat-cascade'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-threat-cascade'

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
jest.mock('../utils/auditLogger', () => ({
  logAudit: jest.fn().mockResolvedValue({}),
}))

const mongoose = require('mongoose')
const ThreatLog = require('../models/ThreatLog')
const Alert = require('../models/Alert')
const threatService = require('../services/threatService')
const { deleteThreat: deleteThreatController } = require('../controllers/threatController')
const { logAudit } = require('../utils/auditLogger')

describe('Task 6: Orphaned Alert Prevention on Threat Deletion', () => {
  const dummyThreatId = new mongoose.Types.ObjectId()
  let req
  let res
  let next

  beforeEach(() => {
    req = {
      params: { id: dummyThreatId.toString() },
      user: {
        _id: new mongoose.Types.ObjectId(),
        name: 'Sec Admin',
        email: 'admin@sentinel.io',
        role: 'admin',
      },
      ip: '127.0.0.1',
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

  describe('threatService.deleteThreat', () => {
    test('1. Deletes the ThreatLog and associated Alert documents pointing to it', async () => {
      const mockThreat = {
        _id: dummyThreatId,
        sourceIP: '198.51.100.99',
        attackType: 'SQL Injection',
      }

      const findByIdAndDeleteSpy = jest.spyOn(ThreatLog, 'findByIdAndDelete').mockResolvedValue(mockThreat)
      const deleteManySpy = jest.spyOn(Alert, 'deleteMany').mockResolvedValue({ deletedCount: 2 })

      const result = await threatService.deleteThreat(dummyThreatId)

      expect(findByIdAndDeleteSpy).toHaveBeenCalledWith(dummyThreatId)
      expect(deleteManySpy).toHaveBeenCalledWith({
        'sourceRef.refModel': 'ThreatLog',
        'sourceRef.refId': dummyThreatId,
      })
      expect(result).toBe(mockThreat)

      findByIdAndDeleteSpy.mockRestore()
      deleteManySpy.mockRestore()
    })

    test('2. Does not delete alerts if ThreatLog is not found', async () => {
      const findByIdAndDeleteSpy = jest.spyOn(ThreatLog, 'findByIdAndDelete').mockResolvedValue(null)
      const deleteManySpy = jest.spyOn(Alert, 'deleteMany').mockResolvedValue({ deletedCount: 0 })

      const result = await threatService.deleteThreat(dummyThreatId)

      expect(findByIdAndDeleteSpy).toHaveBeenCalledWith(dummyThreatId)
      expect(deleteManySpy).not.toHaveBeenCalled()
      expect(result).toBeNull()

      findByIdAndDeleteSpy.mockRestore()
      deleteManySpy.mockRestore()
    })
  })

  describe('threatController.deleteThreat with Audit-First Policy', () => {
    test('3. Enforces Audit-First Policy: aborts deletion and returns 500 when logAudit rejects', async () => {
      const mockThreat = {
        _id: dummyThreatId,
        sourceIP: '198.51.100.99',
      }

      const findByIdSpy = jest.spyOn(ThreatLog, 'findById').mockResolvedValue(mockThreat)
      logAudit.mockRejectedValueOnce(new Error('Audit database write timeout'))
      const serviceDeleteSpy = jest.spyOn(threatService, 'deleteThreat')

      await deleteThreatController(req, res, next)

      expect(findByIdSpy).toHaveBeenCalledWith(dummyThreatId.toString())
      expect(logAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'THREAT_DELETED',
          target: { id: dummyThreatId.toString(), type: 'ThreatLog' },
          status: 'SUCCESS',
        })
      )
      expect(res.statusCode).toBe(500)
      expect(res.jsonData.success).toBe(false)
      expect(res.jsonData.error).toMatch(/audit logging failed|change not applied/i)

      // Service deletion must NEVER be called if audit fails
      expect(serviceDeleteSpy).not.toHaveBeenCalled()

      findByIdSpy.mockRestore()
      serviceDeleteSpy.mockRestore()
    })

    test('4. Calls service deletion and returns 200 when threat exists and audit succeeds', async () => {
      const mockThreat = {
        _id: dummyThreatId,
        sourceIP: '198.51.100.99',
      }

      const findByIdSpy = jest.spyOn(ThreatLog, 'findById').mockResolvedValue(mockThreat)
      logAudit.mockResolvedValueOnce({ _id: 'audit-log-1' })
      const serviceDeleteSpy = jest.spyOn(threatService, 'deleteThreat').mockResolvedValue(mockThreat)

      await deleteThreatController(req, res, next)

      expect(findByIdSpy).toHaveBeenCalledWith(dummyThreatId.toString())
      expect(logAudit).toHaveBeenCalled()
      expect(serviceDeleteSpy).toHaveBeenCalledWith(dummyThreatId.toString())
      expect(res.statusCode).toBe(200)
      expect(res.jsonData.success).toBe(true)
      expect(res.jsonData.message).toBe('Deleted')

      findByIdSpy.mockRestore()
      serviceDeleteSpy.mockRestore()
    })

    test('5. Returns 404 when threat does not exist, without logging audit or calling service', async () => {
      const findByIdSpy = jest.spyOn(ThreatLog, 'findById').mockResolvedValue(null)
      const serviceDeleteSpy = jest.spyOn(threatService, 'deleteThreat')

      await deleteThreatController(req, res, next)

      expect(findByIdSpy).toHaveBeenCalledWith(dummyThreatId.toString())
      expect(logAudit).not.toHaveBeenCalled()
      expect(serviceDeleteSpy).not.toHaveBeenCalled()
      expect(res.statusCode).toBe(404)
      expect(res.jsonData.success).toBe(false)
      expect(res.jsonData.error).toBe('Not found')

      findByIdSpy.mockRestore()
      serviceDeleteSpy.mockRestore()
    })
  })
})
