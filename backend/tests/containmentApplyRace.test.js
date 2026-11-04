'use strict'
/**
 * CONT-003 race (batch 18 review): recovery may decide a request is abandoned while that request is still running.
 * Before fencing, the request's later saves were by _id only, so it could
 *   - save ACTIVE over recovery's FAILED although recovery had removed the rule (database says blocked, nothing is);
 *   - create its rule after recovery confirmed "no rule" and released the lock (an untracked rule);
 *   - carry on from APPROVED/APPLYING after recovery failed a VALIDATING/APPROVED action and apply a rule anyway.
 * Now every ContainmentAction save is version-checked (optimisticConcurrency) and recovery's claim bumps the version,
 * so a superseded request is fenced out; if it already created its rule it removes it, and a removal it cannot
 * confirm is flagged for the reconciliation pass (recovery.lateRule) instead of being forgotten.
 *
 * Interleavings are forced with promises the test releases; rules live in MockContainmentAdapter memory only.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ContainmentAction = require('../models/ContainmentAction')
const containment = require('../services/containmentService')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')

const IP = '198.51.100.97'
const ADMIN = { id: new mongoose.Types.ObjectId().toString(), name: 'Admin', role: 'admin', status: 'active' }

const deferred = () => {
  let resolve
  const promise = new Promise((r) => (resolve = r))
  return { promise, resolve }
}

/** Mock adapter whose applyRule can be held before and/or after it creates the rule. */
class ControlledAdapter extends MockContainmentAdapter {
  constructor() {
    super()
    this.beforeApply = null // deferred: applyRule waits here before creating the rule
    this.afterApply = null // deferred: applyRule waits here after creating the rule
    this.applyStarted = deferred()
    this.ruleCreated = deferred()
  }

  async applyRule(params) {
    this.applyStarted.resolve()
    if (this.beforeApply) await this.beforeApply.promise
    const result = await super.applyRule(params)
    this.ruleCreated.resolve()
    if (this.afterApply) await this.afterApply.promise
    return result
  }
}

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
  adapter = new ControlledAdapter()
  setContainmentAdapter(adapter)
})
afterEach(async () => {
  jest.restoreAllMocks()
  resetContainmentAdapter()
  await ContainmentAction.deleteMany({})
})

const request = () =>
  containment.requestContainment({ target: IP, requester: ADMIN, reason: 'race', emitEvents: false })
const action = () => ContainmentAction.findOne({ normalizedTarget: IP }).lean()
/** Makes the in-flight action look abandoned (raw write: no version bump, as a stalled process leaves it). */
const age = () =>
  ContainmentAction.collection.updateMany({}, { $set: { updatedAt: new Date(Date.now() - 10 * 60000) } })
const recover = () => new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 }).recoverAbandonedApplications()

test('1. normal application: ACTIVE, rule present, recovery leaves it alone', async () => {
  const res = await request()
  expect(res.action.enforcementStatus).toBe('ACTIVE')
  expect(adapter.activeRules.size).toBe(1)
  await age()
  expect((await recover()).processed).toBe(0)
  expect((await action()).enforcementStatus).toBe('ACTIVE')
})

test('4. adapter call delayed past recovery: the late rule is removed and the action stays FAILED', async () => {
  adapter.beforeApply = deferred()
  const pending = request()
  await adapter.applyStarted.promise
  await age()
  expect((await recover()).released).toBe(1) // no rule yet: RULE_ABSENT, lock released
  expect((await action()).enforcementStatus).toBe('FAILED')

  adapter.beforeApply.resolve() // the delayed adapter call now creates its rule
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  const a = await action()
  expect(a.enforcementStatus).toBe('FAILED') // not overwritten with ACTIVE
  expect(a.targetLock).toBeUndefined()
  expect(adapter.activeRules.size).toBe(0) // the superseded request removed its own rule
  expect(a.recovery.lateRule).toBe('REMOVED')
})

test('5. request completes after recovery removed its rule: it cannot save ACTIVE over FAILED', async () => {
  adapter.afterApply = deferred()
  const pending = request()
  await adapter.ruleCreated.promise
  await age()
  expect((await recover()).released).toBe(1) // PRESENT -> removed -> FAILED
  expect(adapter.activeRules.size).toBe(0)

  adapter.afterApply.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  const a = await action()
  expect(a.enforcementStatus).toBe('FAILED')
  expect(a.recovery.lastOutcome).toBe('RULE_REMOVED')
  expect(adapter.activeRules.size).toBe(0)
})

test('a request superseded before its adapter call never applies a rule', async () => {
  const realSave = ContainmentAction.prototype.save
  const hold = deferred()
  const reached = deferred()
  jest.spyOn(ContainmentAction.prototype, 'save').mockImplementation(async function (...args) {
    if (this.enforcementStatus === 'APPROVED') {
      reached.resolve()
      await hold.promise // the request stalls between VALIDATING and APPROVED
    }
    return realSave.apply(this, args)
  })
  const pending = request()
  await reached.promise
  await age()
  expect((await recover()).released).toBe(1) // VALIDATING -> FAILED (NOT_APPLIED)

  hold.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  expect((await action()).enforcementStatus).toBe('FAILED')
  expect(adapter.activeRules.size).toBe(0) // never applied
})

test('8/10. late rule whose removal fails is flagged, retried by the next pass and then cleared', async () => {
  adapter.beforeApply = deferred()
  const pending = request()
  await adapter.applyStarted.promise
  await age()
  await recover()
  adapter.setFailNextRemove('kernel busy') // the superseded request cannot remove its late rule
  adapter.beforeApply.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  let a = await action()
  expect(a.recovery.lateRule).toBe('PRESENT_UNREMOVED')
  expect(adapter.activeRules.size).toBe(1) // known and flagged, not silently forgotten

  const svc = new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 })
  const sweep = await svc.removeLateRules()
  expect(sweep).toMatchObject({ processed: 1, removed: 1 })
  a = await action()
  expect(a.recovery.lateRule).toBe('REMOVED')
  expect(adapter.activeRules.size).toBe(0)
  expect((await svc.removeLateRules()).processed).toBe(0) // nothing left to do
})

test('a late rule in UNKNOWN state stays flagged', async () => {
  adapter.beforeApply = deferred()
  const pending = request()
  await adapter.applyStarted.promise
  await age()
  await recover()
  adapter.setFailNextRemove('kernel busy')
  adapter.beforeApply.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' })
  const sweep = await new ContainmentReconciliationService().removeLateRules()
  expect(sweep).toMatchObject({ processed: 1, removed: 0, unresolved: 1 })
  expect((await action()).recovery.lateRule).toBe('PRESENT_UNREMOVED')
})

test('6. concurrent recovery workers against a stalled request: one claims it, the request is fenced', async () => {
  adapter.beforeApply = deferred()
  const pending = request()
  await adapter.applyStarted.promise
  await age()
  const [a, b] = await Promise.all([recover(), recover()])
  expect(a.released + b.released).toBe(1)
  adapter.beforeApply.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  expect((await action()).enforcementStatus).toBe('FAILED')
  expect(adapter.activeRules.size).toBe(0)
})

test('the address can be contained again after a fenced request cleaned up', async () => {
  adapter.beforeApply = deferred()
  const pending = request()
  await adapter.applyStarted.promise
  await age()
  await recover()
  adapter.beforeApply.resolve()
  await expect(pending).rejects.toMatchObject({ statusCode: 409 })
  adapter.beforeApply = null
  const again = await request()
  expect(again.action.enforcementStatus).toBe('ACTIVE')
  expect(adapter.activeRules.size).toBe(1)
})

describe('operator view of recovery problems (GET /api/containment/recovery)', () => {
  test('an action stuck with an unknown rule state is listed with attempts, age and needsInvestigation', async () => {
    adapter.beforeApply = deferred()
    const pending = request()
    await adapter.applyStarted.promise
    await age()
    const svc = new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 })
    jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' })
    await svc.recoverAbandonedApplications()
    await age() // still stuck at the next look
    const report = await svc.getRecoveryReport()
    expect(report.counts).toMatchObject({ stuck: 1, needsInvestigation: 1 })
    expect(report.items[0]).toMatchObject({
      target: IP,
      enforcementStatus: 'APPLYING',
      recoveryAttempts: 1,
      lastOutcome: 'RULE_STATE_UNKNOWN',
      ruleVerified: false,
      needsInvestigation: true,
    })
    expect(report.items[0].stuckForSeconds).toBeGreaterThanOrEqual(600)
    jest.restoreAllMocks()
    adapter.beforeApply.resolve()
    await pending.catch(() => {})
  })

  test('a late rule not confirmed removed is listed; the periodic pass exposes the count for the gauge', async () => {
    adapter.beforeApply = deferred()
    const pending = request()
    await adapter.applyStarted.promise
    await age()
    await recover()
    adapter.setFailNextRemove('kernel busy')
    adapter.beforeApply.resolve()
    await expect(pending).rejects.toMatchObject({ statusCode: 409 })
    const svc = new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 })
    const report = await svc.getRecoveryReport()
    expect(report.counts.lateRulesUnremoved).toBe(1)
    expect(report.items.find((i) => i.lateRule === 'PRESENT_UNREMOVED')).toMatchObject({
      enforcementStatus: 'FAILED',
      needsInvestigation: true,
      ruleVerified: false,
    })
    jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' }) // the sweep cannot resolve it yet
    await svc.runOnce()
    expect(svc.lastCounts.needsInvestigation).toBe(1)
  })

  test('nothing to investigate: empty report', async () => {
    await request()
    const report = await new ContainmentReconciliationService().getRecoveryReport()
    expect(report.counts).toEqual({ stuck: 0, lateRulesUnremoved: 0, needsInvestigation: 0 })
    expect(report.items).toEqual([])
  })
})
