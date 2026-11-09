'use strict'
/**
 * CONT-002: TTL reconciliation scanned only ACTIVE and ROLLBACK_FAILED actions. An action left in EXPIRING or
 * ROLLING_BACK (adapter removeRule threw, MongoDB failed between two saves, or the process stopped mid-rollback)
 * was never picked up again: it kept its targetLock, the address stayed deny-listed past its TTL and every new
 * containment request for it returned the stuck action as "already active".
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const containment = require('../services/containmentService')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')

const IP = '198.51.100.81'
let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
afterEach(async () => {
  resetContainmentAdapter()
  await Promise.all([ThreatLog.deleteMany({}), BlockedIP.deleteMany({}), ContainmentAction.deleteMany({})])
})

/** An auto-blocked address whose TTL has passed; optionally forced into `status`, last updated `ageMs` ago. */
async function expiredContainment({ status = null, ageMs = 0 } = {}) {
  setContainmentAdapter(new MockContainmentAdapter())
  const t = await ThreatLog.create({
    severity: 'CRITICAL',
    sourceIP: IP,
    attackType: 'DDoS',
    aiScore: 0.99,
    status: 'DETECTED',
  })
  const res = await containment.executeAutoBlock({ threat: t, threatScore: 0.99 })
  expect(res.success).toBe(true)
  const set = { expiresAt: new Date(Date.now() - 60000) }
  if (status) set.enforcementStatus = status
  if (ageMs) set.updatedAt = new Date(Date.now() - ageMs)
  // Raw collection write: bypasses the state machine and Mongoose's updatedAt, like a process that stopped mid-way
  await ContainmentAction.collection.updateOne({ normalizedTarget: IP, enforcementStatus: 'ACTIVE' }, { $set: set })
  return t
}

const actionFor = () => ContainmentAction.findOne({ normalizedTarget: IP }).lean()

test('a removeRule that throws leaves the action retryable (ROLLBACK_FAILED), and the next pass completes it', async () => {
  const t = await expiredContainment()
  setContainmentAdapter({
    getBackendType: () => 'mock',
    removeRule: async () => {
      throw new Error('adapter crashed')
    },
  })
  const reconciler = new ContainmentReconciliationService()
  const first = await reconciler.reconcileExpiredActions()
  expect(first.failed).toBe(1)
  expect((await actionFor()).enforcementStatus).toBe('ROLLBACK_FAILED')

  setContainmentAdapter(new MockContainmentAdapter())
  const second = await reconciler.reconcileExpiredActions()
  expect(second.successful).toBe(1)
  const action = await actionFor()
  expect(action.enforcementStatus).toBe('ROLLED_BACK')
  expect(action.targetLock).toBeUndefined()
  expect(await BlockedIP.exists({ ip: IP })).toBeNull()
  expect((await ThreatLog.findById(t._id)).status).toBe('DETECTED')
})

test.each(['ROLLING_BACK', 'EXPIRING'])(
  'an expired action left in %s by a stopped process is rolled back and its target released',
  async (status) => {
    await expiredContainment({ status, ageMs: 10 * 60000 })
    const res = await new ContainmentReconciliationService().reconcileExpiredActions()
    expect(res.successful).toBe(1)
    const action = await actionFor()
    expect(action.enforcementStatus).toBe('ROLLED_BACK')
    expect(action.targetLock).toBeUndefined()
    expect(await BlockedIP.exists({ ip: IP })).toBeNull()

    // The address can be contained again (before the fix: the stuck action came back as "already active")
    const t2 = await ThreatLog.create({
      severity: 'CRITICAL',
      sourceIP: IP,
      attackType: 'DDoS',
      aiScore: 0.99,
      status: 'DETECTED',
    })
    const again = await containment.executeAutoBlock({ threat: t2, threatScore: 0.99 })
    expect(again.success).toBe(true)
    expect(await ContainmentAction.countDocuments({ normalizedTarget: IP, enforcementStatus: 'ACTIVE' })).toBe(1)
  }
)

test('a rollback still in progress (updated within the grace period) is left to its owner', async () => {
  await expiredContainment({ status: 'ROLLING_BACK' })
  const res = await new ContainmentReconciliationService().reconcileExpiredActions()
  expect(res.processed).toBe(0)
  expect((await actionFor()).enforcementStatus).toBe('ROLLING_BACK')
})
