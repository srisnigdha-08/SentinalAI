'use strict'
/**
 * M1: concurrent containment requests for one target cannot both create an enforcement (targetLock
 * unique index). M7: AI auto-block also files a ContainmentAction through the configured adapter
 * (mock under NODE_ENV=test), sharing the audit/expiry/rollback lifecycle with manual containment.
 * Runs against a real in-memory MongoDB so the unique index is actually enforced.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../websocket/socketManager', () => ({
  emitIPBlocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitThreatUpdated: jest.fn(),
}))
jest.mock('../services/alertService', () => ({ createAlert: jest.fn().mockResolvedValue({ _id: 'alert' }) }))

const ContainmentAction = require('../models/ContainmentAction')
const BlockedIP = require('../models/BlockedIP')
const ThreatLog = require('../models/ThreatLog')
const containmentService = require('../services/containmentService')
const alertService = require('../services/alertService')

const analyst = { _id: new mongoose.Types.ObjectId(), name: 'Ana', role: 'analyst', status: 'active' }

describe('containment concurrency and auto-block unification', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
    await ContainmentAction.syncIndexes()
    await BlockedIP.syncIndexes()
  }, 60000)

  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })

  beforeEach(async () => {
    jest.clearAllMocks()
    await Promise.all([ContainmentAction.deleteMany({}), BlockedIP.deleteMany({}), ThreatLog.deleteMany({})])
  })

  test('M1: two simultaneous requests for one target yield exactly one enforced action', async () => {
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        containmentService.requestContainment({ target: '203.0.113.50', reason: 'race', requester: analyst })
      )
    )
    const active = await ContainmentAction.find({ normalizedTarget: '203.0.113.50', enforcementStatus: 'ACTIVE' })
    expect(active).toHaveLength(1)
    expect(await ContainmentAction.countDocuments({ normalizedTarget: '203.0.113.50' })).toBe(1)
    expect(results.every((r) => r.success)).toBe(true)
    expect(results.filter((r) => r.alreadyActive).length).toBe(4)
    expect(new Set(results.map((r) => String(r.action._id))).size).toBe(1)
  })

  test('M1: the lock is released after rollback, so the target can be contained again', async () => {
    const first = await containmentService.requestContainment({ target: '203.0.113.51', requester: analyst })
    expect(first.action.targetLock).toBe('203.0.113.51')
    await containmentService.rollbackContainment({
      containmentId: first.action.containmentId,
      operator: analyst,
      reason: 'done',
    })
    const rolledBack = await ContainmentAction.findOne({ containmentId: first.action.containmentId })
    expect(rolledBack.enforcementStatus).toBe('ROLLED_BACK')
    expect(rolledBack.targetLock).toBeUndefined()

    const second = await containmentService.requestContainment({ target: '203.0.113.51', requester: analyst })
    expect(second.alreadyActive).toBeUndefined()
    expect(second.action.enforcementStatus).toBe('ACTIVE')
  })

  test('M1: a policy-rejected request does not hold the lock', async () => {
    await expect(
      containmentService.requestContainment({ target: '127.0.0.1', requester: analyst })
    ).rejects.toMatchObject({ statusCode: 403 })
    const rejected = await ContainmentAction.findOne({ normalizedTarget: '127.0.0.1' })
    expect(rejected.enforcementStatus).toBe('REJECTED')
    expect(rejected.targetLock).toBeUndefined()
  })

  test('M7: auto-block writes the deny-list and an ACTIVE ContainmentAction via the adapter', async () => {
    const threat = await ThreatLog.create({
      severity: 'CRITICAL',
      sourceIP: '198.51.100.77',
      attackType: 'DDoS',
      aiScore: 0.97,
      status: 'BLOCKED',
      preBlockStatus: 'MONITORING',
    })
    const res = await containmentService.executeAutoBlock({ threat, threatScore: 0.97, source: 'AI Engine' })

    expect(res.success).toBe(true)
    expect(await BlockedIP.countDocuments({ ip: '198.51.100.77' })).toBe(1)
    const action = await ContainmentAction.findOne({ normalizedTarget: '198.51.100.77' })
    expect(action).toMatchObject({
      enforcementStatus: 'ACTIVE',
      enforcementBackend: 'mock',
      requestedByName: 'AI Auto-Block',
      requestedByRole: 'analyst',
      idempotencyKey: `auto-block:${threat._id}`,
    })
    expect(action.requestedBy).toBeNull()
    expect(action.expiresAt).toBeInstanceOf(Date) // default 1 h expiry, reconciled like manual blocks
    expect(res.enforcement).toMatchObject({ status: 'ACTIVE', backend: 'mock' })
    expect(alertService.createAlert.mock.calls[0][0].message).toMatch(/containment adapter "mock"/)

    // Re-running auto-block for the same threat is idempotent
    await containmentService.executeAutoBlock({ threat, threatScore: 0.97, source: 'AI Engine' })
    expect(await ContainmentAction.countDocuments({ normalizedTarget: '198.51.100.77' })).toBe(1)
  })
})
