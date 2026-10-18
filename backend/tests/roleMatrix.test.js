'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-test-jwt-secret-role-matrix'
process.env.JWT_REFRESH_SECRET = 'unit-test-refresh-secret-role-matrix'
process.env.HONEYPOT_API_KEY = 'unit-test-honeypot-key-role-matrix'
process.env.SENTINEL_KEY = 'unit-test-sentinel-key-role-matrix'

jest.mock('../config/db', () => jest.fn())
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/ThreatLog', () => {
  const mockModel = jest.fn()
  mockModel.ALLOWED_ATTACK_TYPES = [
    'SSH Brute Force',
    'SSH Intrusion Attempt',
    'SQL Injection',
    'Port Scan',
    'DDoS',
    'Unknown',
  ]
  return mockModel
})
jest.mock('../models/AuditLog')
jest.mock('../models/SystemSetting')
jest.mock('../models/TrainingSample')
jest.mock('../models/HoneypotSession')
jest.mock('../models/Alert')
jest.mock('../models/Campaign')
jest.mock('../models/BlockedIP')
jest.mock('../models/ContainmentAction')
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

jest.mock('../services/threatService', () => ({
  findThreats: jest.fn().mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 }),
  getDashboardAnalytics: jest.fn().mockResolvedValue({ totalThreats: 10, attacksToday: 2 }),
  getAttackVectorTrend: jest.fn().mockResolvedValue([]),
  getRecentThreats: jest.fn().mockResolvedValue([]),
  findThreatById: jest.fn().mockResolvedValue({ _id: 'dummy', sourceIP: '198.51.100.24', status: 'DETECTED' }),
  getBlockedIPs: jest.fn().mockResolvedValue([]),
  blockIP: jest.fn().mockResolvedValue({ ip: '198.51.100.99', reason: 'Blocked' }),
  unblockIP: jest.fn().mockResolvedValue({ ip: '198.51.100.99', unblocked: true }),
  createThreat: jest.fn().mockResolvedValue({ _id: 'dummy', sourceIP: '198.51.100.99' }),
  updateThreat: jest.fn().mockResolvedValue({ _id: 'dummy', sourceIP: '198.51.100.24', status: 'INVESTIGATING' }),
  blockThreatIP: jest.fn().mockResolvedValue({ _id: 'dummy', sourceIP: '198.51.100.24', status: 'BLOCKED' }),
  deleteThreat: jest.fn().mockResolvedValue({ _id: 'dummy' }),
}))

jest.mock('../services/trainingSampleService', () => ({
  listSamples: jest.fn().mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 }),
  getSampleById: jest.fn().mockResolvedValue({ _id: 'dummy-sample-id', status: 'PENDING' }),
  ingestPredictionCandidate: jest.fn().mockResolvedValue({ _id: 'dummy-sample-id', status: 'QUARANTINED' }),
  transitionSampleStatus: jest.fn().mockResolvedValue({ _id: 'dummy-sample-id', status: 'VALIDATED' }),
}))

jest.mock('../services/aiEngineService', () => ({
  getHealth: jest.fn().mockResolvedValue({ status: 'ok' }),
  getModelInfo: jest.fn().mockResolvedValue({ model: 'RandomForest', version: '1.0' }),
  getModelStats: jest.fn().mockResolvedValue({ accuracy: 0.95, totalInferences: 120 }),
  runFullPipeline: jest.fn().mockResolvedValue({ threatScore: 0.88, classification: 'BRUTE_FORCE' }),
}))

jest.mock('../services/aiService', () => ({
  findPredictions: jest.fn().mockResolvedValue({ data: [], total: 0, page: 1, limit: 20 }),
  storePrediction: jest.fn().mockResolvedValue({ _id: 'pred-1' }),
  getModelStats: jest.fn().mockResolvedValue({ total: 10 }),
  verifyPrediction: jest.fn().mockResolvedValue({ _id: 'pred-1', verified: true }),
}))

jest.mock('../services/alertService', () => ({
  createAlertFromSession: jest.fn().mockResolvedValue({ _id: 'alert-hp' }),
  createAlert: jest.fn().mockResolvedValue({ _id: 'alert-1' }),
  findAlerts: jest.fn().mockResolvedValue({
    data: [{ _id: 'alert-1', title: 'Alert 1', message: 'Threat detected from 198.51.100.5', severity: 'HIGH' }],
    total: 1,
    page: 1,
    limit: 20,
  }),
  deleteAlert: jest.fn().mockResolvedValue({ _id: 'alert-1' }),
  getUnreadCount: jest.fn().mockResolvedValue(0),
  markAsRead: jest.fn().mockResolvedValue({ _id: 'alert-1', read: true }),
  markAllAsRead: jest.fn().mockResolvedValue(5),
}))

jest.mock('../services/honeypotService', () => ({
  getNodeStatus: jest.fn().mockResolvedValue([{ nodeId: 'SSH-01', status: 'active' }]),
  getActiveNodes: jest.fn().mockResolvedValue([]),
  getDeceptionMetrics: jest.fn().mockResolvedValue({ deceptionRatio: 0.9 }),
  getFullAnalytics: jest.fn().mockResolvedValue({ totalSessions: 10 }),
  findSessions: jest.fn().mockResolvedValue({
    data: [{ _id: 'hp-1', sessionId: 's1', sourceIP: '198.51.100.99', honeypotNode: 'SSH-01' }],
    total: 1,
    page: 1,
    limit: 20,
  }),
  findSessionById: jest.fn().mockResolvedValue({
    _id: 'hp-1',
    sessionId: 's1',
    sourceIP: '198.51.100.99',
    honeypotNode: 'SSH-01',
  }),
  createSession: jest.fn().mockResolvedValue({
    _id: 'hp-1',
    sessionId: 's1',
    sourceIP: '198.51.100.99',
    honeypotNode: 'SSH-01',
  }),
  appendCommands: jest.fn().mockResolvedValue({
    _id: 'hp-1',
    sessionId: 's1',
    sourceIP: '198.51.100.99',
    deceptionScore: 0.8,
  }),
  closeSession: jest.fn().mockResolvedValue({
    _id: 'hp-1',
    sessionId: 's1',
    sourceIP: '198.51.100.99',
    durationSeconds: 60,
    deceptionScore: 0.8,
  }),
}))


jest.mock('../services/containmentService', () => ({
  blockIPManual: jest.fn().mockResolvedValue({
    blockedIP: { ip: '198.51.100.99', reason: 'Manual analyst block' },
    updatedThreats: [],
  }),
  unblockIPManual: jest.fn().mockResolvedValue({
    unblockedIP: '198.51.100.99',
    restoredThreats: [],
  }),
}))

jest.mock('../controllers/containmentController', () => ({
  getStatus: jest.fn((req, res) => res.json({ success: true, data: { status: 'active' } })),
  getActions: jest.fn((req, res) => res.json({ success: true, data: [] })),
  getAction: jest.fn((req, res) => res.json({ success: true, data: { _id: req.params.id } })),
  requestContainment: jest.fn((req, res) => res.status(201).json({ success: true, data: { actionId: 'act-1' } })),
  rollbackContainment: jest.fn((req, res) => res.json({ success: true, data: { rolledBack: true } })),
}))

jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))

jest.mock('../utils/auditLogger', () => ({
  logAudit: jest.fn().mockResolvedValue({}),
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
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const TrainingSample = require('../models/TrainingSample')
const { defaultSecurityEventBus } = require('../utils/securityEventBus')
defaultSecurityEventBus.getOutboxStatus = jest.fn().mockResolvedValue({ pending: 0, failed: 0 })
defaultSecurityEventBus.redriveFailedOutbox = jest.fn().mockResolvedValue({ redriven: 0 })

const { accessToken } = require('./helpers/accessFixture')
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

describe('Phase 3C & 3.5: Comprehensive Role x Express Router Stack Matrix', () => {
  const adminId = new mongoose.Types.ObjectId().toString()
  const analystId = new mongoose.Types.ObjectId().toString()
  const viewerId = new mongoose.Types.ObjectId().toString()
  const dummyId = new mongoose.Types.ObjectId().toString()

  let tokens = {}

  beforeAll(() => {
    tokens.admin = accessToken({ _id: adminId, role: 'admin', authVersion: 0 })
    tokens.analyst = accessToken({ _id: analystId, role: 'analyst', authVersion: 0 })
    tokens.viewer = accessToken({ _id: viewerId, role: 'viewer', authVersion: 0 })
    tokens['no-token'] = null
  })

  beforeEach(() => {
    jest.clearAllMocks()
    mongoose.connection.readyState = 1
    const AuthSession = require('../models/AuthSession')
    AuthSession.updateMany = jest.fn().mockResolvedValue({})
    AuthSession.updateOne = jest.fn().mockResolvedValue({})

    User.findById = jest.fn((id) => {
      const idStr = String(id)
      let role = 'viewer'
      if (idStr === adminId) role = 'admin'
      else if (idStr === analystId) role = 'analyst'
      const userDoc = {
        _id: idStr,
        name: `${role} User`,
        email: `${role}@sentinel.io`,
        role,
        status: 'active',
        authVersion: 0,
        tokenVersion: 0,
        permissions: [],
      }
      return {
        select: jest.fn().mockResolvedValue(userDoc),
        then: (resolve) => Promise.resolve(userDoc).then(resolve),
        ...userDoc,
      }
    })

    const threatList = [
      {
        _id: dummyId,
        sourceIP: '198.51.100.24',
        attackType: 'SSH Brute Force',
        severity: 'HIGH',
        status: 'DETECTED',
        createdAt: new Date(),
        targetService: 'SSH',
        aiScore: 0.85,
      },
    ]

    ThreatLog.ALLOWED_ATTACK_TYPES = [
      'SSH Brute Force',
      'SSH Intrusion Attempt',
      'SQL Injection',
      'Port Scan',
      'DDoS',
      'Unknown',
    ]
    ThreatLog.find = jest.fn(() => createChainableQuery(threatList))
    ThreatLog.countDocuments = jest.fn().mockResolvedValue(1)
    ThreatLog.findById = jest.fn(() => createChainableQuery(threatList[0]))
    ThreatLog.findByIdAndUpdate = jest.fn().mockResolvedValue({
      _id: dummyId,
      status: 'INVESTIGATING',
      triageNotes: 'Triage note',
    })
    ThreatLog.findByIdAndDelete = jest.fn().mockResolvedValue({ _id: dummyId })
    ThreatLog.create = jest.fn().mockResolvedValue(threatList[0])

    SystemSetting.findOne = jest.fn().mockResolvedValue({ key: 'autoBlockEnabled', value: false })
    SystemSetting.findOneAndUpdate = jest.fn().mockResolvedValue({ key: 'autoBlockEnabled', value: true })

    AuditLog.find = jest.fn(() => createChainableQuery([]))
    AuditLog.countDocuments = jest.fn().mockResolvedValue(0)
    AuditLog.create = jest.fn().mockResolvedValue({})

    const sessionList = [
      {
        _id: dummyId,
        sessionId: 'sess-abc',
        sourceIP: '198.51.100.77',
        honeypotNode: 'SSH-COWRIE-01',
        protocol: 'SSH',
        status: 'active',
        commands: ['uname -a'],
        credentials: [{ success: false }],
        createdAt: new Date(),
      },
    ]

    HoneypotSession.find = jest.fn(() => createChainableQuery(sessionList))
    HoneypotSession.findOne = jest.fn(() => createChainableQuery(sessionList[0]))
    HoneypotSession.countDocuments = jest.fn().mockResolvedValue(1)
    HoneypotSession.create = jest.fn().mockResolvedValue(sessionList[0])
    HoneypotSession.findById = jest.fn(() => createChainableQuery(sessionList[0]))
    HoneypotSession.findByIdAndUpdate = jest.fn().mockResolvedValue(sessionList[0])

    const alertList = [
      {
        _id: dummyId,
        title: 'Alert 1',
        message: 'Threat detected from 198.51.100.5',
        severity: 'HIGH',
        createdAt: new Date(),
      },
    ]

    Alert.find = jest.fn(() => createChainableQuery(alertList))
    Alert.countDocuments = jest.fn().mockResolvedValue(1)
    Alert.findById = jest.fn(() => createChainableQuery(alertList[0]))
    Alert.findByIdAndDelete = jest.fn().mockResolvedValue({ _id: dummyId })
    Alert.create = jest.fn().mockResolvedValue(alertList[0])
    Alert.updateMany = jest.fn().mockResolvedValue({ modifiedCount: 1 })

    const campaignList = [
      {
        _id: dummyId,
        name: 'Campaign 1',
        targetSubnet: '10.0.0.0/24',
        sessions: [],
        createdAt: new Date(),
        lastSeen: new Date(),
      },
    ]

    Campaign.find = jest.fn(() => createChainableQuery(campaignList))
    Campaign.countDocuments = jest.fn().mockResolvedValue(1)
    Campaign.findById = jest.fn(() => createChainableQuery(campaignList[0]))

    BlockedIP.find = jest.fn(() => createChainableQuery([]))
    BlockedIP.findOne = jest.fn().mockResolvedValue(null)
    BlockedIP.create = jest.fn().mockResolvedValue({ ip: '198.51.100.99' })
    BlockedIP.deleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 })

    ContainmentAction.find = jest.fn(() => createChainableQuery([]))
    ContainmentAction.countDocuments = jest.fn().mockResolvedValue(0)
    ContainmentAction.findById = jest.fn(() => createChainableQuery({ _id: dummyId, status: 'ACTIVE' }))

    TrainingSample.find = jest.fn(() => createChainableQuery([]))
    TrainingSample.countDocuments = jest.fn().mockResolvedValue(0)
    TrainingSample.findById = jest.fn(() => createChainableQuery({ _id: dummyId, status: 'PENDING' }))

    User.find = jest.fn(() => createChainableQuery([]))
    User.countDocuments = jest.fn().mockResolvedValue(2)
    User.findByIdAndUpdate = jest.fn(() => {
      const doc = { _id: dummyId, email: 'user@sentinel.io', role: 'analyst', status: 'active' }
      return {
        select: jest.fn().mockResolvedValue(doc),
        then: (resolve, reject) => Promise.resolve(doc).then(resolve, reject),
      }
    })
    User.findByIdAndDelete = jest.fn().mockResolvedValue({ _id: dummyId })
  })

  // Dynamic Router Stack Extraction
  const routerMap = new Map([
    [require('../routes/auth'), '/api/auth'],
    [require('../routes/threats'), '/api/threats'],
    [require('../routes/containment'), '/api/containment'],
    [require('../routes/honeypotIngest'), '/api/honeypot/ingest'],
    [require('../routes/honeypot'), '/api/honeypot'],
    [require('../routes/campaigns'), '/api/campaigns'],
    [require('../routes/alerts'), '/api/alerts'],
    [require('../routes/users'), '/api/users'],
    [require('../routes/aiEngine'), '/api/ai'],
    [require('../routes/trainingSamples'), '/api/training-samples'],
    [require('../routes/systemOutbox'), '/api/system/outbox'],
    [require('../routes/audit'), '/api/audit'],
  ])

  const extractedEndpoints = []
  for (const layer of app.router.stack) {
    if (layer.route) {
      const methods = Object.keys(layer.route.methods)
      for (const m of methods) {
        extractedEndpoints.push({
          method: m.toLowerCase(),
          path: layer.route.path,
        })
      }
    } else if (layer.handle && routerMap.has(layer.handle)) {
      const prefix = routerMap.get(layer.handle)
      for (const sub of layer.handle.stack) {
        if (sub.route) {
          const methods = Object.keys(sub.route.methods)
          for (const m of methods) {
            const subPath = sub.route.path === '/' ? '' : sub.route.path
            extractedEndpoints.push({
              method: m.toLowerCase(),
              path: `${prefix}${subPath}`,
            })
          }
        }
      }
    }
  }

  // Full 81-Endpoint Role Matrix
  const MATRIX = [
    // 1. Root & Health
    { method: 'get', path: '/', expected: { 'no-token': 200, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/health', expected: { 'no-token': 200, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/system/health', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/ws/stats', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/docs.json', expected: { 'no-token': 200, viewer: 200, analyst: 200, admin: 200 } },

    // 2. Auth Routes
    { method: 'get', path: '/api/auth/csrf', expected: { 'no-token': 200, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/auth/register', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } },
    { method: 'post', path: '/api/auth/provision', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } }, // protectMutation rejects if no CSRF
    { method: 'post', path: '/api/auth/login', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } }, // CSRF protectMutation
    { method: 'post', path: '/api/auth/refresh-token', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } }, // CSRF protectMutation
    { method: 'post', path: '/api/auth/logout', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } }, // CSRF protectMutation
    { method: 'post', path: '/api/auth/logout-all', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } }, // protectMutation checked
    { method: 'get', path: '/api/auth/me', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'put', path: '/api/auth/update-password', expected: { 'no-token': 403, viewer: 403, analyst: 403, admin: 403 } },

    // 3. Threat Routes
    { method: 'get', path: '/api/threats/analytics/summary', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/threats/vector-trend', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/threats/recent', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/threats/settings', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/threats/settings', body: { autoBlockEnabled: true }, expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'get', path: '/api/threats/blocked-ips', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/threats/block-ip', body: { ip: '198.51.100.99' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/threats/unblock-ip', body: { ip: '198.51.100.99' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/threats', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/threats', body: { sourceIP: '198.51.100.99', attackType: 'SSH Brute Force' }, expected: { 'no-token': 401, viewer: 403, analyst: 201, admin: 201 } },
    { method: 'get', path: '/api/threats/:id', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'put', path: '/api/threats/:id', body: { triageNotes: 'Note' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'delete', path: '/api/threats/:id', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'post', path: '/api/threats/:id/block', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'patch', path: '/api/threats/:id/triage', body: { status: 'INVESTIGATING', triageNotes: 'Note' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },

    // 4. Containment Routes
    { method: 'get', path: '/api/containment/status', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/containment/actions', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/containment/actions', body: { target: '198.51.100.99' }, expected: { 'no-token': 401, viewer: 403, analyst: 201, admin: 201 } },
    { method: 'get', path: '/api/containment/actions/:id', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/containment/actions/:id/rollback', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },

    // 5. Honeypot Ingest (internalAuth) - 401 without X-API-KEY
    { method: 'get', path: '/api/honeypot/ingest/check-block', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },
    { method: 'post', path: '/api/honeypot/ingest', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },
    { method: 'post', path: '/api/honeypot/ingest/match-session', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },
    { method: 'post', path: '/api/honeypot/ingest/command', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },
    { method: 'post', path: '/api/honeypot/ingest/download', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },
    { method: 'post', path: '/api/honeypot/ingest/close', expected: { 'no-token': 401, viewer: 401, analyst: 401, admin: 401 } },

    // 6. Honeypot Sessions & Analytics
    { method: 'get', path: '/api/honeypot/status', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/honeypot/analytics', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/honeypot/nodes', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/honeypot/sessions', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/honeypot/sessions', body: { sourceIP: '198.51.100.99', sourcePort: 2222, honeypotNode: 'SSH-01' }, expected: { 'no-token': 401, viewer: 403, analyst: 201, admin: 201 } },
    { method: 'get', path: '/api/honeypot/sessions/:id', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/honeypot/sessions/:id/commands', body: { commands: [{ command: 'id' }] }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'put', path: '/api/honeypot/sessions/:id/close', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },

    // 7. Campaigns
    { method: 'get', path: '/api/campaigns', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/campaigns/:id', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },

    // 8. Alerts
    { method: 'get', path: '/api/alerts/unread-count', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'put', path: '/api/alerts/mark-all-read', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/alerts', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/alerts', body: { title: 'New Alert', message: 'Alert msg', severity: 'HIGH' }, expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 201 } },
    { method: 'put', path: '/api/alerts/:id/read', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'delete', path: '/api/alerts/:id', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },

    // 9. Users (Admin Only)
    { method: 'get', path: '/api/users/stats', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'get', path: '/api/users', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'get', path: '/api/users/:id', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'put', path: '/api/users/:id', body: { role: 'analyst' }, expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'delete', path: '/api/users/:id', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'post', path: '/api/users/:id/force-logout', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },

    // 10. AI Engine
    { method: 'get', path: '/api/ai/engine/health', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/ai/engine/model-info', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/ai/engine/stats', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/ai/analyze', body: { features: [1, 2, 3] }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/ai/predictions', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/ai/predictions', body: { sourceIP: '198.51.100.99', predictedClass: 'BRUTE_FORCE' }, expected: { 'no-token': 401, viewer: 403, analyst: 201, admin: 201 } },
    { method: 'get', path: '/api/ai/stats', expected: { 'no-token': 401, viewer: 200, analyst: 200, admin: 200 } },
    { method: 'put', path: '/api/ai/predictions/:id/verify', body: { actualClass: 'SSH Brute Force' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },

    // 11. Training Samples
    { method: 'get', path: '/api/training-samples', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/training-samples/:id', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/training-samples/ingest/:id', expected: { 'no-token': 401, viewer: 403, analyst: 201, admin: 201 } },
    { method: 'post', path: '/api/training-samples/:id/validate', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'post', path: '/api/training-samples/:id/reject', body: { reason: 'False positive' }, expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'post', path: '/api/training-samples/:id/promote', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'post', path: '/api/training-samples/:id/supersede', body: { reason: 'Superseded' }, expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },

    // 12. System Outbox
    { method: 'get', path: '/api/system/outbox/status', expected: { 'no-token': 401, viewer: 403, analyst: 200, admin: 200 } },
    { method: 'get', path: '/api/system/outbox/failed', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
    { method: 'post', path: '/api/system/outbox/redrive', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },

    // 13. Audit
    { method: 'get', path: '/api/audit', expected: { 'no-token': 401, viewer: 403, analyst: 403, admin: 200 } },
  ]

  test('Router stack coverage: must cover exactly all routes and none missing', () => {
    const extractedKeys = new Set(extractedEndpoints.map((ep) => `${ep.method.toUpperCase()} ${ep.path}`))
    const matrixKeys = new Set(MATRIX.map((m) => `${m.method.toUpperCase()} ${m.path}`))

    const unmappedInMatrix = extractedEndpoints
      .filter((ep) => !matrixKeys.has(`${ep.method.toUpperCase()} ${ep.path}`))
      .map((ep) => `${ep.method.toUpperCase()} ${ep.path}`)

    const extraInMatrix = MATRIX
      .filter((m) => !extractedKeys.has(`${m.method.toUpperCase()} ${m.path}`))
      .map((m) => `${m.method.toUpperCase()} ${m.path}`)

    if (unmappedInMatrix.length > 0) {
      throw new Error(`Unmapped routes in Express router stack missing from MATRIX: ${unmappedInMatrix.join(', ')}`)
    }
    if (extraInMatrix.length > 0) {
      throw new Error(`Extra routes in MATRIX not found in Express router stack: ${extraInMatrix.join(', ')}`)
    }

    expect(unmappedInMatrix).toEqual([])
    expect(extraInMatrix).toEqual([])
    expect(matrixKeys.size).toBe(extractedKeys.size)
  })

  // 81 endpoints x 4 roles = 324 dynamic matrix assertions
  describe.each(MATRIX)('$method $path', ({ method, path, body, expected }) => {
    const testUrl = path.replace(':id', dummyId)

    test.each(['no-token', 'viewer', 'analyst', 'admin'])('Role: %s', async (role) => {
      let req = request(app)[method](testUrl)
      if (tokens[role]) {
        req = req.set('Authorization', `Bearer ${tokens[role]}`)
      }
      if (body) {
        req = req.send(body)
      }
      const res = await req
      expect(res.status).toBe(expected[role])
    })
  })
})
