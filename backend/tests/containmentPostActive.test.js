'use strict'
/**
 * Batch 20 containment reliability (real MongoDB in memory, mock adapter only):
 *
 * CONT-005  After an action was saved ACTIVE, syncLegacyBlockState wrote the deny-list entry and marked the address's
 *           threats BLOCKED but swallowed both failures. A MongoDB error or a crash there left an ACTIVE action with
 *           a rule and no BlockedIP (the honeypot blocker does not block it and Settings -> Unblock IP says "not
 *           blocked") and unblocked threats, with nothing retrying. Now the ACTIVE save records legacySync.pending,
 *           cleared only once the sync succeeded, and the reconciliation pass re-runs the (idempotent) sync.
 * CONT-006  A manual rollback and TTL expiry releasing the same action: whichever saved second hit VersionError and
 *           reported it as a 500 (API), ROLLBACK_FAILED (Settings unblock) or a failed reconciliation, although the
 *           other path released the rule. Now it is a 409 CONTAINMENT_CONCURRENT_RELEASE / a skipped action.
 * CONT-007  removeLateRules retried an unconfirmed late rule on every pass. Now bounded exponential back-off.
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

const IP = '198.51.100.98'
const ADMIN = { id: new mongoose.Types.ObjectId().toString(), name: 'Admin', role: 'admin', status: 'active' }
let mongo
let adapter
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await ContainmentAction.init()
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
beforeEach(() => {
  adapter = new MockContainmentAdapter()
  setContainmentAdapter(adapter)
})
afterEach(async () => {
  jest.restoreAllMocks()
  resetContainmentAdapter()
  await Promise.all([ThreatLog.deleteMany({}), BlockedIP.deleteMany({}), ContainmentAction.deleteMany({})])
})

const threat = () =>
  ThreatLog.create({ severity: 'HIGH', sourceIP: IP, attackType: 'DDoS', aiScore: 0.95, status: 'DETECTED' })
const request = () =>
  containment.requestContainment({ target: IP, requester: ADMIN, reason: 'policy block', emitEvents: false })
const action = () => ContainmentAction.findOne({ normalizedTarget: IP }).lean()
const svc = () => new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 })
/** Ages the action past the post-ACTIVE sync grace, as a stopped process leaves it (raw write, no version bump). */
const age = () =>
  ContainmentAction.collection.updateMany({}, { $set: { updatedAt: new Date(Date.now() - 10 * 60000) } })

describe('CONT-005: state written after ACTIVE is recovered', () => {
  test('deny-list write fails after ACTIVE: flagged, then re-synced by the reconciliation pass', async () => {
    const t = await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValueOnce(new Error('MongoDB unavailable'))
    const res = await request()
    expect(res.action.enforcementStatus).toBe('ACTIVE')
    expect(adapter.activeRules.size).toBe(1)
    expect(await BlockedIP.exists({ ip: IP })).toBeNull() // the rule exists but the deny-list does not know
    expect((await action()).legacySync.pending).toBe(true)

    await age()
    const sweep = await svc().resyncLegacyState()
    expect(sweep).toMatchObject({ processed: 1, synced: 1 })
    expect(await BlockedIP.exists({ ip: IP })).not.toBeNull()
    expect((await ThreatLog.findById(t._id)).status).toBe('BLOCKED')
    expect((await action()).legacySync.pending).toBe(false)
  })

  test('threat update fails after ACTIVE (as if the process stopped there): threats are blocked on re-sync', async () => {
    const t = await threat()
    jest.spyOn(ThreatLog, 'find').mockRejectedValueOnce(new Error('connection reset'))
    await request()
    expect((await ThreatLog.findById(t._id)).status).toBe('DETECTED')
    expect((await action()).legacySync.pending).toBe(true)
    await age()
    await svc().resyncLegacyState()
    const updated = await ThreatLog.findById(t._id)
    expect(updated.status).toBe('BLOCKED')
    expect(updated.preBlockStatus).toBe('DETECTED')
  })

  test('re-sync is idempotent: a second pass changes nothing and keeps preBlockStatus', async () => {
    const t = await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValueOnce(new Error('MongoDB unavailable'))
    await request()
    await age()
    await svc().resyncLegacyState()
    expect((await svc().resyncLegacyState()).processed).toBe(0)
    expect(await BlockedIP.countDocuments({ ip: IP })).toBe(1)
    expect((await ThreatLog.findById(t._id)).preBlockStatus).toBe('DETECTED')
  })

  test('a successful request leaves nothing pending', async () => {
    await threat()
    await request()
    expect((await action()).legacySync.pending).toBe(false)
    await age()
    expect((await svc().resyncLegacyState()).processed).toBe(0)
  })

  test('an action released before the re-sync is not re-blocked', async () => {
    await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValueOnce(new Error('MongoDB unavailable'))
    const res = await request()
    await containment.rollbackContainment({ containmentId: res.action.containmentId, operator: ADMIN })
    await age()
    expect((await svc().resyncLegacyState()).processed).toBe(0)
    expect(await BlockedIP.exists({ ip: IP })).toBeNull()
  })

  test('a rollback that lands while the re-sync runs: the re-sync undoes what it wrote', async () => {
    const t = await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValueOnce(new Error('MongoDB unavailable'))
    const res = await request()
    await age()
    const realSync = containment.syncLegacyBlockState
    jest.spyOn(containment, 'syncLegacyBlockState').mockImplementationOnce(async (args) => {
      // the operator releases the address first, then the (late) sync writes the deny-list and blocks the threat
      await containment.rollbackContainment({ containmentId: res.action.containmentId, operator: ADMIN })
      return realSync(args)
    })
    const sweep = await svc().resyncLegacyState()
    expect(sweep).toMatchObject({ processed: 1, compensated: 1, synced: 0 })
    expect(await BlockedIP.exists({ ip: IP })).toBeNull() // not re-blocked after the release
    expect((await ThreatLog.findById(t._id)).status).toBe('DETECTED')
    expect((await action()).enforcementStatus).toBe('ROLLED_BACK')
  })

  test('the re-sync is a fresh request within the grace period: left to the original request', async () => {
    await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValueOnce(new Error('MongoDB unavailable'))
    await request()
    expect((await svc().resyncLegacyState()).processed).toBe(0)
  })

  test('the operator view counts actions whose post-ACTIVE state is still pending', async () => {
    await threat()
    jest.spyOn(BlockedIP, 'findOneAndUpdate').mockRejectedValue(new Error('MongoDB unavailable'))
    await request()
    await age()
    await svc().resyncLegacyState() // still failing
    const report = await svc().getRecoveryReport()
    expect(report.counts.legacySyncPending).toBe(1)
    expect(report.items.find((i) => i.legacySyncPending)).toMatchObject({
      enforcementStatus: 'ACTIVE',
      needsInvestigation: true,
    })
  })
})

describe('CONT-006: manual rollback and TTL expiry releasing the same action', () => {
  const expired = async () => {
    const res = await request()
    await ContainmentAction.collection.updateOne({}, { $set: { expiresAt: new Date(Date.now() - 60000) } })
    return res.action.containmentId
  }

  test('expiry wins while the operator rollback holds a stale copy: 409 with the current status, not a 500', async () => {
    const containmentId = await expired()
    const realFindOne = ContainmentAction.findOne.bind(ContainmentAction)
    jest.spyOn(ContainmentAction, 'findOne').mockImplementationOnce(async (q) => {
      const stale = await realFindOne(q) // the operator's request loads the action ...
      await svc().reconcileExpiredActions() // ... and expiry releases it meanwhile
      return stale
    })
    await expect(containment.rollbackContainment({ containmentId, operator: ADMIN })).rejects.toMatchObject({
      statusCode: 409,
      code: 'CONTAINMENT_CONCURRENT_RELEASE',
    })
    expect((await action()).enforcementStatus).toBe('ROLLED_BACK')
    expect(adapter.activeRules.size).toBe(0)
  })

  test('Settings unblock racing expiry reports the action as released concurrently, not ROLLBACK_FAILED', async () => {
    await expired()
    const realFindOne = ContainmentAction.findOne.bind(ContainmentAction)
    jest.spyOn(ContainmentAction, 'findOne').mockImplementationOnce(async (q) => {
      const stale = await realFindOne(q)
      await svc().reconcileExpiredActions()
      return stale
    })
    const results = await containment.releaseManualBlock({ ip: IP, operator: ADMIN })
    expect(results).toEqual([expect.objectContaining({ status: 'RELEASED_CONCURRENTLY' })])
    expect(adapter.activeRules.size).toBe(0)
  })

  test('operator rollback wins while expiry holds a stale copy: expiry skips it instead of counting a failure', async () => {
    const containmentId = await expired()
    const realFind = ContainmentAction.find.bind(ContainmentAction)
    jest.spyOn(ContainmentAction, 'find').mockImplementationOnce(async (q) => {
      const stale = await realFind(q) // expiry loads the due actions ...
      await containment.rollbackContainment({ containmentId, operator: ADMIN }) // ... the operator releases one
      return stale
    })
    const res = await svc().reconcileExpiredActions()
    expect(res).toMatchObject({ processed: 1, successful: 0, failed: 0, skipped: 1 })
    expect((await action()).enforcementStatus).toBe('ROLLED_BACK')
  })
})

describe('CONT-007: late-rule retries back off', () => {
  const flagLateRule = async () => {
    await ContainmentAction.collection.insertOne({
      containmentId: 'late-1',
      target: IP,
      normalizedTarget: IP,
      enforcementStatus: 'FAILED',
      enforcementBackend: 'mock',
      recovery: { lateRule: 'PRESENT_UNREMOVED', lateRuleAt: new Date() },
      createdAt: new Date(),
      updatedAt: new Date(),
      __v: 0,
    })
    adapter.activeRules.set('mock-rule-late-1', { ruleId: 'mock-rule-late-1' })
  }

  test('an unavailable adapter is retried after 1, 2, 4 ... minutes, capped, and the flag is never dropped', async () => {
    await flagLateRule()
    jest.spyOn(adapter, 'inspectRule').mockRejectedValue(new Error('adapter offline'))
    const t0 = new Date('2026-11-04T12:00:00Z')
    const s = svc()
    expect(await s.removeLateRules(t0)).toMatchObject({ processed: 1, unresolved: 1 })
    let a = await ContainmentAction.findOne({ containmentId: 'late-1' }).lean()
    expect(a.recovery).toMatchObject({ lateRule: 'PRESENT_UNREMOVED', lateRuleAttempts: 1 })
    expect(a.recovery.lateRuleLastError).toMatch(/adapter offline/)
    expect(new Date(a.recovery.lateRuleNextAttemptAt) - t0).toBe(60000)

    expect((await s.removeLateRules(new Date(t0.getTime() + 30000))).processed).toBe(0) // not due yet
    await s.removeLateRules(new Date(t0.getTime() + 60000))
    a = await ContainmentAction.findOne({ containmentId: 'late-1' }).lean()
    expect(a.recovery.lateRuleAttempts).toBe(2)
    expect(new Date(a.recovery.lateRuleNextAttemptAt) - new Date(t0.getTime() + 60000)).toBe(120000)

    for (let i = 0; i < 10; i++) await s.removeLateRules(new Date(t0.getTime() + 24 * 3600000 * (i + 1)))
    a = await ContainmentAction.findOne({ containmentId: 'late-1' }).lean()
    const lastGap = new Date(a.recovery.lateRuleNextAttemptAt) - new Date(t0.getTime() + 24 * 3600000 * 10)
    expect(lastGap).toBe(60 * 60000) // capped at one hour
    expect(a.recovery.lateRule).toBe('PRESENT_UNREMOVED') // exhausted retries never release anything
  })

  test('once the adapter answers, the rule is removed and the back-off cleared', async () => {
    await flagLateRule()
    const t0 = new Date('2026-11-04T12:00:00Z')
    const spy = jest.spyOn(adapter, 'inspectRule').mockRejectedValueOnce(new Error('adapter offline'))
    await svc().removeLateRules(t0)
    spy.mockRestore()
    expect(await svc().removeLateRules(new Date(t0.getTime() + 60000))).toMatchObject({ removed: 1 })
    const a = await ContainmentAction.findOne({ containmentId: 'late-1' }).lean()
    expect(a.recovery).toMatchObject({ lateRule: 'REMOVED', lateRuleNextAttemptAt: null })
    expect(adapter.activeRules.size).toBe(0)
  })
})
