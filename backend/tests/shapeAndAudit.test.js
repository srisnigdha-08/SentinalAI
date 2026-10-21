'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-shape-audit'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-shape-audit'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-shape-audit'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-shape-audit'

jest.mock('../config/db', () => jest.fn())
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/ThreatLog')
jest.mock('../models/AuditLog')
jest.mock('../models/SystemSetting')
jest.mock('../models/TrainingSample')
jest.mock('../models/HoneypotSession')
jest.mock('../models/Alert')
jest.mock('../models/Campaign')
jest.mock('../models/BlockedIP')
jest.mock('../models/ContainmentAction')

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
  emitHoneypotEvent: jest.fn(),
  getStats: jest.fn().mockReturnValue({ connections: 5, rooms: 3 }),
  disconnectUser: jest.fn(),
  stopHealthBroadcast: jest.fn(),
}))

const mongoose = require('mongoose')
const request = require('supertest')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const AuditLog = require('../models/AuditLog')
const SystemSetting = require('../models/SystemSetting')
const HoneypotSession = require('../models/HoneypotSession')
const Alert = require('../models/Alert')
const Campaign = require('../models/Campaign')
const AuthSession = require('../models/AuthSession')

const { accessToken } = require('./helpers/accessFixture')
const { logAudit } = require('../utils/auditLogger')
const { app } = require('../server')

function createChainableQuery(result) {
  const query = {}
  query.sort = jest.fn(() => query)
  query.skip = jest.fn(() => query)
  query.limit = jest.fn(() => query)
  query.populate = jest.fn(() => query)
  query.select = jest.fn(() => query)
  query.lean = jest.fn().mockResolvedValue(result)
  query.then = (resolve, reject) => Promise.resolve(result).then(resolve, reject)
  return query
}

describe('Phase 3.5: Shape Guarantee & Audit Completeness Verification', () => {
  const adminId = new mongoose.Types.ObjectId().toString()
  const analystId = new mongoose.Types.ObjectId().toString()
  const viewerId = new mongoose.Types.ObjectId().toString()
  const dummyId = new mongoose.Types.ObjectId().toString()

  let tokens = {}

  beforeAll(() => {
    tokens.admin = accessToken({ _id: adminId, role: 'admin', authVersion: 0 })
    tokens.analyst = accessToken({ _id: analystId, role: 'analyst', authVersion: 0 })
    tokens.viewer = accessToken({ _id: viewerId, role: 'viewer', authVersion: 0 })
  })

  beforeEach(() => {
    jest.clearAllMocks()
    mongoose.connection.readyState = 1

    AuthSession.updateMany = jest.fn().mockResolvedValue({})
    AuthSession.updateOne = jest.fn().mockResolvedValue({})

    User.findById = jest.fn((id) => {
      const idStr = String(id)
      let role = 'viewer'
      if (idStr === adminId) role = 'admin'
      else if (idStr === analystId) role = 'analyst'
      return {
        select: jest.fn().mockResolvedValue({
          _id: idStr,
          name: `${role} User`,
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

  describe('Item 5: Admin & Analyst Shape Guarantee (Unchanged from baseline)', () => {
    const rawThreat = {
      _id: dummyId,
      sourceIP: '198.51.100.24',
      destinationIP: '10.0.0.1',
      attackType: 'SQL Injection',
      severity: 'HIGH',
      status: 'DETECTED',
      payload: "SELECT * FROM users WHERE '1'='1'",
      payloadHash: 'a1b2c3d4e5f6',
      targetService: 'HTTP',
      aiScore: 0.92,
      confidence: 0.88,
      createdAt: '2026-10-18T10:00:00.000Z',
    }

    const rawSession = {
      _id: dummyId,
      sessionId: 'sess-secure-123',
      sourceIP: '198.51.100.77',
      sourcePort: 2222,
      honeypotNode: 'SSH-COWRIE-01',
      protocol: 'SSH',
      status: 'active',
      commands: [{ command: 'cat /etc/shadow', output: 'root:$6$xyz:18000:0:99999:7:::', timestamp: new Date() }],
      credentials: [{ username: 'root', password: 'SuperSecretPassword!', success: false }],
      iocExtracted: {
        ips: ['198.51.100.77'],
        hashes: ['abc123hash'],
        domains: ['malware.attacker.org'],
      },
      durationSeconds: 120,
      deceptionScore: 0.95,
      createdAt: '2026-10-18T10:00:00.000Z',
    }

    const rawCampaign = {
      _id: dummyId,
      name: 'Operation Redline',
      targetSubnet: '10.0.0.0/24',
      status: 'active',
      sourceIPs: ['198.51.100.55', '198.51.100.56'],
      sessionCount: 2,
      sessions: [dummyId],
      detectedPatterns: ['SSH Brute Force', 'Lateral Movement'],
      createdAt: '2026-10-18T10:00:00.000Z',
      lastSeen: '2026-10-18T10:30:00.000Z',
    }

    const rawAlert = {
      _id: dummyId,
      title: 'SQL Injection Detected',
      message: 'Malicious payload from 198.51.100.24 detected on API gateway.',
      severity: 'HIGH',
      type: 'SQL_INJECTION',
      read: false,
      createdAt: '2026-10-18T10:00:00.000Z',
    }

    const rawPrediction = {
      _id: dummyId,
      sourceIP: '198.51.100.99',
      targetIP: '10.0.0.5',
      predictedClass: 'SSH Brute Force',
      threatScore: 0.89,
      confidence: 0.91,
      rawFeatures: { byte_count: 512, packet_rate: 45 },
      verified: false,
      createdAt: '2026-10-18T10:00:00.000Z',
    }

    beforeEach(() => {
      ThreatLog.find = jest.fn(() => createChainableQuery([rawThreat]))
      ThreatLog.countDocuments = jest.fn().mockResolvedValue(1)
      ThreatLog.findById = jest.fn(() => createChainableQuery(rawThreat))

      HoneypotSession.findById = jest.fn(() => createChainableQuery(rawSession))

      Campaign.findById = jest.fn(() => createChainableQuery(rawCampaign))

      Alert.find = jest.fn(() => createChainableQuery([rawAlert]))
      Alert.countDocuments = jest.fn().mockResolvedValue(1)

      const AIPrediction = require('../models/AIPrediction')
      AIPrediction.find = jest.fn(() => createChainableQuery([rawPrediction]))
      AIPrediction.countDocuments = jest.fn().mockResolvedValue(1)
    })

    test('1. GET /api/threats: Admin and Analyst receive identical unredacted data, Viewer receives masked data', async () => {
      const adminRes = await request(app).get('/api/threats').set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app).get('/api/threats').set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app).get('/api/threats').set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      // Shape and data equality between admin and analyst
      expect(adminRes.body.data).toEqual(analystRes.body.data)
      expect(adminRes.body.data[0].sourceIP).toBe('198.51.100.24')
      expect(adminRes.body.data[0].payload).toBe("SELECT * FROM users WHERE '1'='1'")

      // Viewer data is redacted
      expect(viewerRes.body.data[0].sourceIP).toBe('198.51.100.xxx')
      expect(viewerRes.body.data[0].payload).toBe('[REDACTED_PAYLOAD]')
    })

    test('2. GET /api/threats/:id: Admin and Analyst receive identical unredacted single threat', async () => {
      const adminRes = await request(app).get(`/api/threats/${dummyId}`).set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app)
        .get(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app)
        .get(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      expect(adminRes.body.data.threat).toEqual(analystRes.body.data.threat)
      expect(adminRes.body.data.threat.sourceIP).toBe('198.51.100.24')
      expect(adminRes.body.data.threat.payload).toBe("SELECT * FROM users WHERE '1'='1'")

      expect(viewerRes.body.data.threat.sourceIP).toBe('198.51.100.xxx')
      expect(viewerRes.body.data.threat.payload).toBe('[REDACTED_PAYLOAD]')
    })

    test('3. GET /api/honeypot/sessions/:id: Admin and Analyst receive raw commands & credentials, Viewer receives redacted', async () => {
      const adminRes = await request(app)
        .get(`/api/honeypot/sessions/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app)
        .get(`/api/honeypot/sessions/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app)
        .get(`/api/honeypot/sessions/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      expect(adminRes.body.data.session).toEqual(analystRes.body.data.session)
      expect(adminRes.body.data.session.sourceIP).toBe('198.51.100.77')
      expect(adminRes.body.data.session.commands[0].output).toBe('root:$6$xyz:18000:0:99999:7:::')
      expect(adminRes.body.data.session.credentials[0].password).toBe('SuperSecretPassword!')

      // Viewer is redacted
      expect(viewerRes.body.data.session.sourceIP).toBe('198.51.100.xxx')
      expect(viewerRes.body.data.session.commands[0].output).toBe('[REDACTED_OUTPUT]')
      expect(viewerRes.body.data.session.credentials[0].password).toBeUndefined()
      expect(viewerRes.body.data.session.credentials[0].success).toBe(false)
    })

    test('4. GET /api/campaigns/:id: Admin and Analyst receive raw sourceIPs, Viewer receives masked sourceIPs', async () => {
      const adminRes = await request(app)
        .get(`/api/campaigns/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app)
        .get(`/api/campaigns/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app)
        .get(`/api/campaigns/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      expect(adminRes.body.data).toEqual(analystRes.body.data)
      expect(adminRes.body.data.sourceIPs).toEqual(['198.51.100.55', '198.51.100.56'])

      expect(viewerRes.body.data.sourceIPs).toEqual(['198.51.100.xxx', '198.51.100.xxx'])
    })

    test('5. GET /api/alerts: Admin and Analyst receive identical unredacted alerts, Viewer receives masked message', async () => {
      const adminRes = await request(app).get('/api/alerts').set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app).get('/api/alerts').set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app).get('/api/alerts').set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      expect(adminRes.body.data).toEqual(analystRes.body.data)
      expect(adminRes.body.data[0].message).toContain('198.51.100.24')

      expect(viewerRes.body.data[0].message).toContain('198.51.100.xxx')
    })

    test('6. GET /api/ai/predictions: Admin and Analyst receive raw targetIP & rawFeatures, Viewer receives redacted', async () => {
      const adminRes = await request(app).get('/api/ai/predictions').set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app).get('/api/ai/predictions').set('Authorization', `Bearer ${tokens.analyst}`)
      const viewerRes = await request(app).get('/api/ai/predictions').set('Authorization', `Bearer ${tokens.viewer}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)
      expect(viewerRes.status).toBe(200)

      expect(adminRes.body.data).toEqual(analystRes.body.data)
      expect(adminRes.body.data[0].sourceIP).toBe('198.51.100.99')
      expect(adminRes.body.data[0].targetIP).toBe('10.0.0.5')
      expect(adminRes.body.data[0].rawFeatures).toBeDefined()

      expect(viewerRes.body.data[0].sourceIP).toBe('198.51.100.xxx')
      expect(viewerRes.body.data[0].targetIP).toBe('10.0.0.xxx')
      expect(viewerRes.body.data[0].rawFeatures).toBe('[REDACTED_FEATURES]')
    })
  })

  describe('Item 7: Audit Log Completeness & Governance Integrity', () => {
    test('1. AuditLog model has NO update or delete routes in the router stack', () => {
      const routerMap = new Map([[require('../routes/audit'), '/api/audit']])
      const auditRoutes = []
      for (const layer of app.router.stack) {
        if (layer.handle && routerMap.has(layer.handle)) {
          const prefix = routerMap.get(layer.handle)
          for (const sub of layer.handle.stack) {
            if (sub.route) {
              const methods = Object.keys(sub.route.methods)
              for (const m of methods) {
                auditRoutes.push({
                  method: m.toUpperCase(),
                  path: `${prefix}${sub.route.path === '/' ? '' : sub.route.path}`,
                })
              }
            }
          }
        }
      }

      // Exactly 1 route exists for audit: GET /api/audit
      expect(auditRoutes).toEqual([{ method: 'GET', path: '/api/audit' }])
      // Absolutely no PUT, PATCH, or DELETE routes exist on audit
      const forbiddenAuditMethods = auditRoutes.filter((r) => ['PUT', 'PATCH', 'DELETE'].includes(r.method))
      expect(forbiddenAuditMethods).toEqual([])
    })

    test('2. GET /api/audit paginates with page, limit, total, and data array', async () => {
      const sampleLogs = [
        {
          _id: new mongoose.Types.ObjectId(),
          action: 'THREAT_BLOCKED',
          actor: { id: adminId, email: 'admin@sentinel.io', role: 'admin' },
          target: { id: dummyId, identifier: '198.51.100.24', type: 'ThreatLog' },
          status: 'SUCCESS',
          createdAt: new Date(),
        },
      ]

      AuditLog.find = jest.fn(() => createChainableQuery(sampleLogs))
      AuditLog.countDocuments = jest.fn().mockResolvedValue(45)

      const res = await request(app).get('/api/audit?page=2&limit=10').set('Authorization', `Bearer ${tokens.admin}`)

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(res.body.data).toHaveLength(1)
      expect(res.body.pagination).toBeDefined()
      expect(res.body.pagination.page).toBe(2)
      expect(res.body.pagination.limit).toBe(10)
      expect(res.body.pagination.total).toBe(45)
      expect(res.body.pagination.pages).toBe(5)
    })

    test('3. logAudit records structured events for all required security actions', async () => {
      AuditLog.create = jest.fn().mockImplementation((doc) => Promise.resolve({ _id: 'audit-mock', ...doc }))

      const requiredActions = [
        'THREAT_BLOCKED',
        'IP_BLOCKED_MANUAL',
        'IP_UNBLOCKED_MANUAL',
        'THREAT_DELETED',
        'SETTINGS_CHANGED',
        'USER_CREATED',
        'USER_ROLE_CHANGED',
        'USER_STATUS_CHANGED',
        'USER_DELETED',
        'USER_FORCE_LOGOUT',
        'THREAT_TRIAGED',
        'LOGIN_SUCCESS',
        'LOGIN_FAILED',
        'PERMISSION_DENIED',
      ]

      for (const action of requiredActions) {
        const logged = await logAudit({
          action,
          actor: { _id: adminId, email: 'admin@sentinel.io', role: 'admin' },
          target: { id: 'target-id', identifier: 'target-ident', type: 'System' },
          status: action === 'LOGIN_FAILED' || action === 'PERMISSION_DENIED' ? 'FAILURE' : 'SUCCESS',
          details: { sample: true },
          ip: '127.0.0.1',
        })

        expect(logged).toBeDefined()
        expect(AuditLog.create).toHaveBeenCalledWith(
          expect.objectContaining({
            action,
            status: action === 'LOGIN_FAILED' || action === 'PERMISSION_DENIED' ? 'FAILURE' : 'SUCCESS',
            actor: expect.objectContaining({ email: 'admin@sentinel.io', role: 'admin' }),
          })
        )
      }
    })

    test('4. AuditLog deduplication: drops rapid identical 403 / DENIED audit attempts within window', async () => {
      AuditLog.create = jest.fn().mockImplementation((doc) => Promise.resolve({ _id: 'audit-mock-1', ...doc }))
      const payload = {
        action: 'PERMISSION_DENIED',
        actor: { _id: viewerId, email: 'viewer@sentinel.io', role: 'viewer' },
        target: { id: 'threat-123', type: 'ThreatLog' },
        status: 'DENIED',
        details: { reason: 'Unauthorized route' },
        ip: '198.51.100.99',
      }

      const first = await logAudit(payload)
      expect(first).toBeDefined()
      expect(AuditLog.create).toHaveBeenCalledTimes(1)

      // Immediate second attempt with identical parameters should be deduplicated
      const second = await logAudit(payload)
      expect(second).toBeNull()
      expect(AuditLog.create).toHaveBeenCalledTimes(1)
    })

    test('5. AuditLog immutability: Mongoose pre-hooks block update, replace, and delete operations', async () => {
      const savedReadyState = mongoose.connection.readyState
      mongoose.connection.readyState = 0
      const ActualAuditLog = jest.requireActual('../models/AuditLog')
      mongoose.connection.readyState = savedReadyState

      const schema = ActualAuditLog.schema
      expect(schema).toBeDefined()

      // 1. Test save pre-hook on non-new document
      const saveHooks = (schema.s.hooks._pres.get('save') || []).map((h) => h.fn)
      let customSaveHook = null
      for (const fn of saveHooks) {
        let err = null
        try {
          fn.call({ isNew: false }, (e) => {
            err = e
          })
        } catch {}
        if (err && err.message && err.message.includes('strictly immutable')) {
          customSaveHook = fn
          break
        }
      }
      expect(customSaveHook).toBeDefined()

      // Test save pre-hook allows new document
      let newSaveErr = null
      customSaveHook.call({ isNew: true }, (err) => {
        newSaveErr = err
      })
      expect(newSaveErr).toBeUndefined()

      // 2. Test update pre-hooks
      const updateHooks = (schema.s.hooks._pres.get('updateOne') || []).map((h) => h.fn)
      let customUpdateHook = null
      for (const fn of updateHooks) {
        let err = null
        try {
          fn.call({}, (e) => {
            err = e
          })
        } catch {}
        if (err && err.message && err.message.includes('strictly immutable')) {
          customUpdateHook = fn
          break
        }
      }
      expect(customUpdateHook).toBeDefined()

      // 3. Test delete pre-hooks
      const deleteHooks = (schema.s.hooks._pres.get('deleteOne') || []).map((h) => h.fn)
      let customDeleteHook = null
      for (const fn of deleteHooks) {
        let err = null
        try {
          fn.call({}, (e) => {
            err = e
          })
        } catch {}
        if (err && err.message && err.message.includes('strictly immutable')) {
          customDeleteHook = fn
          break
        }
      }
      expect(customDeleteHook).toBeDefined()

      // 4. Test findOneAndReplace pre-hook
      const replaceHooks = (schema.s.hooks._pres.get('findOneAndReplace') || []).map((h) => h.fn)
      let customReplaceHook = null
      for (const fn of replaceHooks) {
        let err = null
        try {
          fn.call({}, (e) => {
            err = e
          })
        } catch {}
        if (err && err.message && err.message.includes('strictly immutable')) {
          customReplaceHook = fn
          break
        }
      }
      expect(customReplaceHook).toBeDefined()

      // 5. Test bulkWrite pre-hook
      const bulkWriteHooks = (schema.s.hooks._pres.get('bulkWrite') || []).map((h) => h.fn)
      let customBulkWriteHook = null
      for (const fn of bulkWriteHooks) {
        let err = null
        try {
          fn.call({}, (e) => {
            err = e
          })
        } catch {}
        if (err && err.message && err.message.includes('strictly immutable')) {
          customBulkWriteHook = fn
          break
        }
      }
      expect(customBulkWriteHook).toBeDefined()
    })

    test('6. DB Re-read & Session Layer Proof: Role changes trigger session revocation (401) and role re-read (403)', async () => {
      const tokenWithAnalystRole = tokens.analyst

      // Sub-case A: Real Session Layer Revocation
      // When an admin changes role, updateUser increments authVersion and revokes active sessions.
      // The session layer rejects the old token with HTTP 401 Unauthorized.
      User.findById = jest.fn(() => ({
        select: jest.fn().mockResolvedValue({
          _id: analystId,
          name: 'Demoted Analyst',
          email: 'analyst@sentinel.io',
          role: 'viewer',
          status: 'active',
          authVersion: 1, // Incremented by admin role change
          tokenVersion: 1,
          permissions: [],
        }),
      }))

      const revokedSessionRes = await request(app)
        .put(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokenWithAnalystRole}`)
        .send({ status: 'INVESTIGATING' })

      expect(revokedSessionRes.status).toBe(401)
      expect(revokedSessionRes.body.success).toBe(false)
      expect(revokedSessionRes.body.error).toMatch(/sign in again|session changed|invalid|unauthorized/i)

      // Sub-case B: DB Role Re-read Authorization Gate
      // If a token's session version remains valid but the database role is 'viewer',
      // req.user.role is populated from MongoDB as 'viewer', and the RBAC guard returns 403 Forbidden.
      User.findById = jest.fn(() => ({
        select: jest.fn().mockResolvedValue({
          _id: analystId,
          name: 'Demoted Analyst',
          email: 'analyst@sentinel.io',
          role: 'viewer',
          status: 'active',
          authVersion: 0, // Matching session version
          tokenVersion: 0,
          permissions: [],
        }),
      }))

      const rbacDeniedRes = await request(app)
        .put(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokenWithAnalystRole}`)
        .send({ status: 'INVESTIGATING' })

      expect(rbacDeniedRes.status).toBe(403)
      expect(rbacDeniedRes.body.success).toBe(false)
      expect(rbacDeniedRes.body.error).toMatch(/permission|forbidden|not allowed|access denied/i)
    })

    test('7. Response Shape Guarantee: recursive field names and types match baseline fixture schema', async () => {
      const threatExpectedShape = {
        _id: 'string',
        sourceIP: 'string',
        destinationIP: 'string',
        attackType: 'string',
        severity: 'string',
        status: 'string',
        payload: 'string',
        payloadHash: 'string',
        targetService: 'string',
        aiScore: 'number',
        confidence: 'number',
        createdAt: 'string',
      }

      function verifyShape(actual, expected) {
        for (const [key, expectedType] of Object.entries(expected)) {
          expect(actual).toHaveProperty(key)
          expect(typeof actual[key]).toBe(expectedType)
        }
      }

      const adminRes = await request(app).get(`/api/threats/${dummyId}`).set('Authorization', `Bearer ${tokens.admin}`)
      const analystRes = await request(app)
        .get(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.analyst}`)

      expect(adminRes.status).toBe(200)
      expect(analystRes.status).toBe(200)

      verifyShape(adminRes.body.data.threat, threatExpectedShape)
      verifyShape(analystRes.body.data.threat, threatExpectedShape)

      const adminKeys = Object.keys(adminRes.body.data.threat).sort()
      const analystKeys = Object.keys(analystRes.body.data.threat).sort()
      expect(adminKeys).toEqual(analystKeys)
    })

    test('8. Integration Test: POST /api/auth/login records LOGIN_SUCCESS with target.id === actor.id === user._id', async () => {
      AuditLog.create = jest.fn().mockImplementation((doc) => Promise.resolve({ _id: 'audit-mock-login', ...doc }))

      const testUserId = new mongoose.Types.ObjectId().toString()
      const mockLoginUser = {
        _id: testUserId,
        email: 'analyst.login@sentinel.io',
        name: 'Analyst Login User',
        role: 'analyst',
        status: 'active',
        authVersion: 0,
        tokenVersion: 0,
        comparePassword: jest.fn().mockResolvedValue(true),
        save: jest.fn().mockResolvedValue(true),
        toJSON: () => ({
          _id: testUserId,
          email: 'analyst.login@sentinel.io',
          name: 'Analyst Login User',
          role: 'analyst',
        }),
      }

      const originalUserFindById = User.findById
      const originalUserFindOne = User.findOne
      const originalSessionFindById = AuthSession.findById
      const originalSessionCreate = AuthSession.create

      const createdSessions = new Map()

      AuthSession.create = jest.fn().mockImplementation(async (session) => {
        createdSessions.set(session._id, session)
        return session
      })
      AuthSession.findById = jest.fn((id) => ({
        select: () => ({
          then: (resolve, reject) => Promise.resolve(createdSessions.get(id)).then(resolve, reject),
        }),
        then: (resolve, reject) => Promise.resolve(createdSessions.get(id)).then(resolve, reject),
      }))

      User.findOne = jest.fn().mockReturnValue({
        select: jest.fn().mockResolvedValue(mockLoginUser),
      })
      User.findById = jest.fn((id) => ({
        select: jest.fn().mockResolvedValue(String(id) === testUserId ? mockLoginUser : null),
        then: (resolve, reject) =>
          Promise.resolve(String(id) === testUserId ? mockLoginUser : null).then(resolve, reject),
      }))

      try {
        const clientUrl = process.env.CLIENT_URL || 'http://localhost:3000'
        const agent = request.agent(app)
        const csrfRes = await agent.get('/api/auth/csrf').set('Origin', clientUrl)
        expect(csrfRes.status).toBe(200)
        const csrfToken = csrfRes.body.data.csrfToken

        const loginRes = await agent
          .post('/api/auth/login')
          .set('Origin', clientUrl)
          .set('X-CSRF-Token', csrfToken)
          .send({
            email: 'analyst.login@sentinel.io',
            password: 'CorrectPassword123',
          })

        expect(loginRes.status).toBe(200)
        expect(loginRes.body.success).toBe(true)
        expect(loginRes.body.data.token).toBeDefined()

        const loginAuditCall = AuditLog.create.mock.calls.find((call) => call[0]?.action === 'LOGIN_SUCCESS')
        expect(loginAuditCall).toBeDefined()
        const entry = loginAuditCall[0]
        expect(entry.actor.id).toBe(testUserId)
        expect(entry.target.id).toBe(testUserId)
        expect(entry.target.id).toBe(entry.actor.id)
      } finally {
        User.findById = originalUserFindById
        User.findOne = originalUserFindOne
        AuthSession.findById = originalSessionFindById
        AuthSession.create = originalSessionCreate
      }
    })

    test('9. Audit Failure Policy: admin mutation fails with 500 and change is rolled back when AuditLog.create rejects', async () => {
      // 1. Test updateSettings rollback when AuditLog.create rejects
      AuditLog.create = jest.fn().mockRejectedValue(new Error('Persistent disk full / connection terminated'))

      let storedSetting = { key: 'autoBlockEnabled', value: false }
      SystemSetting.findOne = jest.fn().mockResolvedValue({ key: 'autoBlockEnabled', value: false })
      SystemSetting.findOneAndUpdate = jest.fn().mockImplementation((filter, update) => {
        storedSetting.value = update.value
        return Promise.resolve(storedSetting)
      })

      const settingsRes = await request(app)
        .post('/api/threats/settings')
        .set('Authorization', `Bearer ${tokens.admin}`)
        .send({ autoBlockEnabled: true })

      expect(settingsRes.status).toBe(500)
      expect(settingsRes.body.success).toBe(false)
      expect(settingsRes.body.error).toMatch(/audit logging failed|change not applied/i)
      // Assert setting was reverted to false
      expect(storedSetting.value).toBe(false)

      // 2. Test user role change rollback when AuditLog.create rejects
      let userInDb = {
        _id: viewerId,
        name: 'Viewer User',
        email: 'viewer@sentinel.io',
        role: 'viewer',
        status: 'active',
        authVersion: 0,
      }
      User.findById = jest.fn((id) => {
        const idStr = String(id)
        if (idStr === adminId) {
          const adminObj = {
            _id: adminId,
            name: 'Admin User',
            email: 'admin@sentinel.io',
            role: 'admin',
            status: 'active',
            authVersion: 0,
            tokenVersion: 0,
            permissions: [],
          }
          return {
            select: jest.fn().mockResolvedValue(adminObj),
            ...adminObj,
          }
        }
        return {
          select: jest.fn().mockResolvedValue({ ...userInDb }),
          ...userInDb,
        }
      })
      User.findByIdAndUpdate = jest.fn().mockImplementation((id, update) => {
        if (update.$set) Object.assign(userInDb, update.$set)
        return {
          select: jest.fn().mockResolvedValue({ ...userInDb }),
          ...userInDb,
        }
      })

      const userUpdateRes = await request(app)
        .put(`/api/users/${viewerId}`)
        .set('Authorization', `Bearer ${tokens.admin}`)
        .send({ role: 'analyst' })

      expect(userUpdateRes.status).toBe(500)
      expect(userUpdateRes.body.success).toBe(false)
      expect(userUpdateRes.body.error).toMatch(/audit logging failed|change not applied/i)
      // Assert role was reverted to viewer
      expect(userInDb.role).toBe('viewer')

      // 3. Test deleteThreat rollback (deletion aborted when AuditLog.create rejects)
      ThreatLog.findById = jest.fn().mockResolvedValue({ _id: dummyId, sourceIP: '198.51.100.99' })
      const threatService = require('../services/threatService')
      const deleteSpy = jest.spyOn(threatService, 'deleteThreat')

      const deleteThreatRes = await request(app)
        .delete(`/api/threats/${dummyId}`)
        .set('Authorization', `Bearer ${tokens.admin}`)

      expect(deleteThreatRes.status).toBe(500)
      expect(deleteThreatRes.body.success).toBe(false)
      expect(deleteThreatRes.body.error).toMatch(/audit logging failed|change not applied/i)
      // Assert threatService.deleteThreat was NOT called
      expect(deleteSpy).not.toHaveBeenCalled()
      deleteSpy.mockRestore()
    })

    test('10. Session & Socket Invariance: sessions and sockets remain intact when audit write rejects', async () => {
      AuditLog.create = jest.fn().mockRejectedValue(new Error('Audit persistence network timeout'))

      const authSessions = require('../services/authSessionService')
      const socketManager = require('../websocket/socketManager')
      const revokeSpy = jest.spyOn(authSessions, 'revokeUserSessions')
      const authDisconnectSpy = jest.spyOn(authSessions, 'disconnectUser')
      const socketDisconnectSpy = socketManager.disconnectUser

      let targetUserDoc = {
        _id: viewerId,
        name: 'Viewer Target',
        email: 'viewer.target@sentinel.io',
        role: 'viewer',
        status: 'active',
        authVersion: 0,
        tokenVersion: 0,
      }

      User.findById = jest.fn((id) => {
        const idStr = String(id)
        if (idStr === adminId) {
          const adminObj = {
            _id: adminId,
            name: 'Admin User',
            email: 'admin@sentinel.io',
            role: 'admin',
            status: 'active',
            authVersion: 0,
          }
          return {
            select: jest.fn().mockResolvedValue(adminObj),
            ...adminObj,
          }
        }
        return {
          select: jest.fn().mockResolvedValue({ ...targetUserDoc }),
          ...targetUserDoc,
        }
      })

      User.findByIdAndUpdate = jest.fn().mockImplementation((id, update) => {
        if (update.$set) Object.assign(targetUserDoc, update.$set)
        return {
          select: jest.fn().mockResolvedValue({ ...targetUserDoc }),
          ...targetUserDoc,
        }
      })

      // Attempt 1: Role change (PUT /api/users/:id)
      const roleRes = await request(app)
        .put(`/api/users/${viewerId}`)
        .set('Authorization', `Bearer ${tokens.admin}`)
        .send({ role: 'analyst' })

      expect(roleRes.status).toBe(500)
      expect(revokeSpy).not.toHaveBeenCalled()
      expect(authDisconnectSpy).not.toHaveBeenCalled()
      expect(socketDisconnectSpy).not.toHaveBeenCalled()
      expect(targetUserDoc.role).toBe('viewer')

      // Attempt 2: Force logout (POST /api/users/:id/force-logout)
      const forceLogoutRes = await request(app)
        .post(`/api/users/${viewerId}/force-logout`)
        .set('Authorization', `Bearer ${tokens.admin}`)

      expect(forceLogoutRes.status).toBe(500)
      expect(revokeSpy).not.toHaveBeenCalled()
      expect(authDisconnectSpy).not.toHaveBeenCalled()
      expect(socketDisconnectSpy).not.toHaveBeenCalled()
      expect(targetUserDoc.authVersion).toBe(0) // authVersion NOT incremented

      revokeSpy.mockRestore()
      authDisconnectSpy.mockRestore()
    })
  })
})
