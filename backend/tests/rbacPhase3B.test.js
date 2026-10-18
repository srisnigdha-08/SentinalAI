'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-rbac-3b'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-rbac-3b'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-rbac-3b'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-rbac-3b'

jest.mock('../config/db', () => jest.fn())
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/ThreatLog')
jest.mock('../models/AuditLog')
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
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  getStats: jest.fn().mockReturnValue({}),
  disconnectUser: jest.fn(),
}))

const mongoose = require('mongoose')
const request = require('supertest')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const AuditLog = require('../models/AuditLog')
const AuthSession = require('../models/AuthSession')
const { accessToken } = require('./helpers/accessFixture')
const { logAudit } = require('../utils/auditLogger')
const { app } = require('../server')

describe('Phase 3B: Real Role Separation & Governance', () => {
  const adminId = new mongoose.Types.ObjectId().toString()
  const analystId = new mongoose.Types.ObjectId().toString()
  const viewerId = new mongoose.Types.ObjectId().toString()
  const targetUserId = new mongoose.Types.ObjectId().toString()
  const threatId = new mongoose.Types.ObjectId().toString()

  let adminToken
  let analystToken
  let viewerToken

  beforeEach(() => {
    jest.clearAllMocks()

    adminToken = accessToken({ _id: adminId, role: 'admin', authVersion: 0 })
    analystToken = accessToken({ _id: analystId, role: 'analyst', authVersion: 0 })
    viewerToken = accessToken({ _id: viewerId, role: 'viewer', authVersion: 0 })

    User.findById = jest.fn((id) => {
      const idStr = String(id)
      let role = 'viewer'
      let name = 'Viewer User'
      if (idStr === adminId) {
        role = 'admin'
        name = 'Admin User'
      } else if (idStr === analystId) {
        role = 'analyst'
        name = 'Analyst User'
      } else if (idStr === targetUserId) {
        role = 'analyst'
        name = 'Target User'
      }
      return {
        select: jest.fn().mockResolvedValue({
          _id: idStr,
          name,
          email: `${role}@sentinel.io`,
          role,
          status: 'active',
          authVersion: 0,
          tokenVersion: 0,
          permissions: [],
        }),
      }
    })
  })

  describe('1. Audit Logging & Governance (/api/audit)', () => {
    test('Unauthenticated access to GET /api/audit is rejected with 401', async () => {
      const res = await request(app).get('/api/audit')
      expect(res.status).toBe(401)
    })

    test('Viewer access to GET /api/audit is denied with 403', async () => {
      const res = await request(app)
        .get('/api/audit')
        .set('Authorization', `Bearer ${viewerToken}`)
      expect(res.status).toBe(403)
      expect(res.body.error).toMatch(/insufficient permissions|Access denied/i)
    })

    test('Analyst access to GET /api/audit is denied with 403', async () => {
      const res = await request(app)
        .get('/api/audit')
        .set('Authorization', `Bearer ${analystToken}`)
      expect(res.status).toBe(403)
      expect(res.body.error).toMatch(/insufficient permissions|Access denied/i)
    })

    test('Admin access to GET /api/audit succeeds with 200 and audit logs list', async () => {
      const mockLogs = [
        {
          _id: new mongoose.Types.ObjectId(),
          action: 'USER_ROLE_CHANGED',
          actor: { id: adminId, email: 'admin@sentinel.io', role: 'admin' },
          target: { id: targetUserId, identifier: 'target@sentinel.io', type: 'User' },
          status: 'SUCCESS',
          createdAt: new Date(),
        },
      ]

      AuditLog.find = jest.fn().mockReturnValue({
        sort: jest.fn().mockReturnValue({
          skip: jest.fn().mockReturnValue({
            limit: jest.fn().mockReturnValue({
              lean: jest.fn().mockResolvedValue(mockLogs),
            }),
          }),
        }),
      })
      AuditLog.countDocuments = jest.fn().mockResolvedValue(1)

      const res = await request(app)
        .get('/api/audit')
        .set('Authorization', `Bearer ${adminToken}`)

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(res.body.data).toHaveLength(1)
      expect(res.body.data[0].action).toBe('USER_ROLE_CHANGED')
    })

    test('logAudit helper persists valid AuditLog entries', async () => {
      AuditLog.create = jest.fn().mockResolvedValue({ _id: 'audit-created' })

      const entry = await logAudit({
        action: 'TEST_ACTION',
        actor: { _id: adminId, email: 'admin@sentinel.io', role: 'admin', name: 'Admin' },
        target: { id: 'target-123', identifier: 'test-ip', type: 'ThreatLog' },
        status: 'SUCCESS',
        details: { foo: 'bar' },
        ip: '127.0.0.1',
      })

      expect(AuditLog.create).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'TEST_ACTION',
          status: 'SUCCESS',
          actor: expect.objectContaining({ email: 'admin@sentinel.io', role: 'admin' }),
          target: expect.objectContaining({ id: 'target-123' }),
        })
      )
      expect(entry).toBeDefined()
    })
  })

  describe('2. Analyst Incident Triage Flow (PATCH /api/threats/:id/triage)', () => {
    test('Unauthenticated triage is rejected with 401', async () => {
      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .send({ status: 'INVESTIGATING', triageNotes: 'Starting analysis' })
      expect(res.status).toBe(401)
    })

    test('Viewer triage is denied with 403', async () => {
      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .set('Authorization', `Bearer ${viewerToken}`)
        .send({ status: 'INVESTIGATING', triageNotes: 'Unauthorized note' })
      expect(res.status).toBe(403)
      expect(res.body.error).toMatch(/insufficient permissions|Access denied/i)
    })

    test('Analyst can successfully triage threat with valid status and notes', async () => {
      AuditLog.create = jest.fn().mockResolvedValue({})
      ThreatLog.findById = jest.fn().mockResolvedValue({
        _id: threatId,
        sourceIP: '203.0.113.55',
        attackType: 'SQL Injection',
        status: 'DETECTED',
        triageNotes: '',
      })
      ThreatLog.findByIdAndUpdate = jest.fn().mockResolvedValue({
        _id: threatId,
        sourceIP: '203.0.113.55',
        attackType: 'SQL Injection',
        status: 'INVESTIGATING',
        triageNotes: 'Confirmed SQLi probe from staging subnet.',
      })

      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({
          status: 'INVESTIGATING',
          triageNotes: 'Confirmed SQLi probe from staging subnet.',
        })

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(res.body.data.threat.status).toBe('INVESTIGATING')
      expect(res.body.data.threat.triageNotes).toBe('Confirmed SQLi probe from staging subnet.')
    })

    test('Analyst triage returns real 404 error when threat does not exist', async () => {
      ThreatLog.findById = jest.fn().mockResolvedValue(null)
      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({ status: 'INVESTIGATING', triageNotes: 'Note' })

      expect(res.status).toBe(404)
      expect(res.body.success).toBe(false)
      expect(res.body.error).toMatch(/Not found/i)
    })

    test('Analyst triage rejects invalid status with 400', async () => {
      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({ status: 'SUPER_CRITICAL_HACK' })

      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/Invalid threat status/i)
    })

    test('Analyst triage rejects excessively long triageNotes with 400', async () => {
      const longNote = 'A'.repeat(1005)
      const res = await request(app)
        .patch(`/api/threats/${threatId}/triage`)
        .set('Authorization', `Bearer ${analystToken}`)
        .send({ triageNotes: longNote })

      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/Triage notes must be a string up to 1000 characters/i)
    })
  })

  describe('3. Admin User Guardrails (Self-Demotion, Self-Deactivation, Last Admin)', () => {
    test('Admin cannot self-demote role (returns 400)', async () => {
      const res = await request(app)
        .put(`/api/users/${adminId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'analyst' })

      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/cannot demote their own account/i)
    })

    test('Admin cannot self-deactivate account (returns 400)', async () => {
      const res = await request(app)
        .put(`/api/users/${adminId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ status: 'inactive' })

      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/cannot deactivate their own account/i)
    })

    test('Admin cannot demote or deactivate the last remaining active admin (returns 400)', async () => {
      const otherAdminId = new mongoose.Types.ObjectId().toString()

      // Target is another admin
      User.findById = jest.fn((id) => {
        const idStr = String(id)
        if (idStr === otherAdminId) {
          return Promise.resolve({
            _id: otherAdminId,
            name: 'Other Admin',
            email: 'otheradmin@sentinel.io',
            role: 'admin',
            status: 'active',
            authVersion: 0,
            tokenVersion: 0,
          })
        }
        return {
          select: jest.fn().mockResolvedValue({
            _id: adminId,
            name: 'Admin User',
            email: 'admin@sentinel.io',
            role: 'admin',
            status: 'active',
            authVersion: 0,
            tokenVersion: 0,
          }),
        }
      })

      // Count of active admins returns 1 (meaning otherAdminId is the last admin)
      User.countDocuments = jest.fn().mockResolvedValue(1)

      const res = await request(app)
        .put(`/api/users/${otherAdminId}`)
        .set('Authorization', `Bearer ${adminToken}`)
        .send({ role: 'analyst' })

      expect(res.status).toBe(400)
      expect(res.body.error).toMatch(/Cannot demote or deactivate the last remaining administrator/i)
    })
  })

  describe('4. Force Logout & Immediate Revocation (/api/users/:id/force-logout)', () => {
    test('Non-admin cannot force logout a user (returns 403)', async () => {
      const res = await request(app)
        .post(`/api/users/${targetUserId}/force-logout`)
        .set('Authorization', `Bearer ${analystToken}`)

      expect(res.status).toBe(403)
    })

    test('Admin can force logout a user, incrementing tokenVersion and revoking sessions', async () => {
      AuditLog.create = jest.fn().mockResolvedValue({})
      AuthSession.updateMany = jest.fn().mockResolvedValue({ modifiedCount: 2 })
      const targetUserDoc = {
        _id: targetUserId,
        name: 'Target User',
        email: 'target@sentinel.io',
        role: 'analyst',
        status: 'active',
        authVersion: 0,
        tokenVersion: 0,
      }

      User.findById = jest.fn((id) => {
        const idStr = String(id)
        if (idStr === targetUserId) {
          return Promise.resolve(targetUserDoc)
        }
        return {
          select: jest.fn().mockResolvedValue({
            _id: adminId,
            name: 'Admin User',
            email: 'admin@sentinel.io',
            role: 'admin',
            status: 'active',
            authVersion: 0,
            tokenVersion: 0,
          }),
        }
      })

      User.findByIdAndUpdate = jest.fn().mockResolvedValue({
        ...targetUserDoc,
        authVersion: 1,
        tokenVersion: 1,
      })

      const res = await request(app)
        .post(`/api/users/${targetUserId}/force-logout`)
        .set('Authorization', `Bearer ${adminToken}`)

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(User.findByIdAndUpdate).toHaveBeenCalledWith(
        targetUserId,
        expect.objectContaining({ $inc: { authVersion: 1, tokenVersion: 1 } }),
        { new: true }
      )
    })
  })
})
