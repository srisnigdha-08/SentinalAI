'use strict'
/**
 * CONT-003: a containment request interrupted before it reached ACTIVE or FAILED (process stopped, MongoDB error on a
 * save) left the action in VALIDATING, APPROVED or APPLYING. Nothing ever revisited those states, so the action held
 * its targetLock forever and every later request for the address came back "already active". From APPLYING it is
 * not known whether the adapter created the rule, so recovery asks the adapter (inspectRule: PRESENT / ABSENT /
 * UNKNOWN, or a throw = unavailable) and releases the lock only once the rule is confirmed absent.
 *
 * All rules here live in MockContainmentAdapter memory; no firewall command runs.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ContainmentAction = require('../models/ContainmentAction')
const containment = require('../services/containmentService')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')

const IP = '198.51.100.91'
const ADMIN = { id: new mongoose.Types.ObjectId().toString(), name: 'Admin', role: 'admin', status: 'active' }
let mongo
let adapter
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await ContainmentAction.init() // unique targetLock index must exist before the concurrency assertions
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
  await ContainmentAction.deleteMany({})
})

const request = () =>
  containment.requestContainment({ target: IP, requester: ADMIN, reason: 'test', emitEvents: false })

/** Runs a request whose save into `failAt` throws, as if the process stopped at that point. */
async function interruptedAt(failAt) {
  const realSave = ContainmentAction.prototype.save
  jest.spyOn(ContainmentAction.prototype, 'save').mockImplementation(function (...args) {
    if (this.enforcementStatus === failAt) return Promise.reject(new Error('simulated crash'))
    return realSave.apply(this, args)
  })
  await expect(request()).rejects.toThrow('simulated crash')
  jest.restoreAllMocks()
}

const age = (minutes = 10) =>
  ContainmentAction.collection.updateMany({}, { $set: { updatedAt: new Date(Date.now() - minutes * 60000) } })
const current = () => ContainmentAction.findOne({ normalizedTarget: IP }).lean()
const reconciler = () => new ContainmentReconciliationService({ stuckGraceMs: 5 * 60000 })

describe('interrupted application holds the lock until recovery proves the rule absent', () => {
  test('crash after the rule was applied but before ACTIVE was saved: rule removed, then lock released', async () => {
    await interruptedAt('ACTIVE')
    expect((await current()).enforcementStatus).toBe('APPLYING')
    expect(adapter.activeRules.size).toBe(1) // the rule exists although the database says APPLYING
    expect((await request()).alreadyActive).toBe(true) // the stuck action blocks every new request

    await age()
    const res = await reconciler().recoverAbandonedApplications()
    expect(res).toMatchObject({ processed: 1, released: 1, unresolved: 0 })
    const action = await current()
    expect(action.enforcementStatus).toBe('FAILED')
    expect(action.targetLock).toBeUndefined()
    expect(action.recovery.lastOutcome).toBe('RULE_REMOVED')
    expect(adapter.activeRules.size).toBe(0)

    const again = await request()
    expect(again.alreadyActive).toBeUndefined()
    expect(again.action.enforcementStatus).toBe('ACTIVE')
  })

  test.each(['APPROVED', 'APPLYING'])(
    'crash before the rule was applied (last saved state %s): no rule, lock released',
    async (savedState) => {
      // Failing the save into the next state leaves the previous one in the database
      await interruptedAt(savedState === 'APPROVED' ? 'APPLYING' : 'ACTIVE')
      if (savedState === 'APPLYING') adapter.clear() // the rule was never created
      expect((await current()).enforcementStatus).toBe(savedState)
      await age()
      const res = await reconciler().recoverAbandonedApplications()
      expect(res).toMatchObject({ processed: 1, released: 1 })
      const action = await current()
      expect(action.enforcementStatus).toBe('FAILED')
      expect(action.targetLock).toBeUndefined()
      expect(action.recovery.lastOutcome).toBe(savedState === 'APPROVED' ? 'NOT_APPLIED' : 'RULE_ABSENT')
    }
  )

  test('backend restart: a fresh mock adapter has no rules, so the action is released as RULE_ABSENT', async () => {
    await interruptedAt('ACTIVE')
    await age()
    setContainmentAdapter(new MockContainmentAdapter()) // in-memory rules did not survive the restart
    const res = await new ContainmentReconciliationService().recoverAbandonedApplications()
    expect(res.released).toBe(1)
    expect((await current()).recovery.lastOutcome).toBe('RULE_ABSENT')
  })

  test('rule state UNKNOWN: the lock is kept and the action is retried later', async () => {
    await interruptedAt('ACTIVE')
    await age()
    jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN', details: { reason: 'unparsed output' } })
    const res = await reconciler().recoverAbandonedApplications()
    expect(res).toMatchObject({ processed: 1, released: 0, unresolved: 1 })
    const action = await current()
    expect(action.enforcementStatus).toBe('APPLYING')
    expect(action.targetLock).toBe(IP)
    expect(action.recovery).toMatchObject({ lastOutcome: 'RULE_STATE_UNKNOWN', attempts: 1 })
  })

  test('adapter unavailable (inspectRule throws): the lock is kept, then released once the adapter answers', async () => {
    await interruptedAt('ACTIVE')
    await age()
    const spy = jest.spyOn(adapter, 'inspectRule').mockRejectedValue(new Error('adapter offline'))
    expect((await reconciler().recoverAbandonedApplications()).unresolved).toBe(1)
    expect((await current()).recovery.lastOutcome).toBe('ADAPTER_UNAVAILABLE')
    expect((await current()).targetLock).toBe(IP)

    spy.mockRestore()
    await age() // the next attempt waits for the grace period again
    expect((await reconciler().recoverAbandonedApplications()).released).toBe(1)
    expect((await current()).recovery).toMatchObject({ lastOutcome: 'RULE_REMOVED', attempts: 2 })
  })

  test('removal of a PRESENT rule fails: the lock is kept (rule may still be enforced)', async () => {
    await interruptedAt('ACTIVE')
    await age()
    adapter.setFailNextRemove('kernel busy')
    const res = await reconciler().recoverAbandonedApplications()
    expect(res.unresolved).toBe(1)
    const action = await current()
    expect(action.enforcementStatus).toBe('APPLYING')
    expect(action.recovery.lastOutcome).toBe('RULE_REMOVAL_FAILED')
    expect(adapter.activeRules.size).toBe(1)
  })

  test('an action recorded for another enforcement backend is never judged by the current adapter', async () => {
    await interruptedAt('ACTIVE')
    await ContainmentAction.collection.updateOne({}, { $set: { enforcementBackend: 'windows-firewall' } })
    await age()
    adapter.clear() // the mock would wrongly report ABSENT for a rule that lives in another backend
    const res = await reconciler().recoverAbandonedApplications()
    expect(res.unresolved).toBe(1)
    expect((await current()).recovery.lastOutcome).toBe('BACKEND_MISMATCH')
    expect((await current()).targetLock).toBe(IP)
  })

  test('repeated and concurrent recovery passes process each action once', async () => {
    await interruptedAt('ACTIVE')
    await age()
    const removeSpy = jest.spyOn(adapter, 'removeRule')
    const [a, b] = await Promise.all([
      reconciler().recoverAbandonedApplications(),
      reconciler().recoverAbandonedApplications(),
    ])
    expect(a.released + b.released).toBe(1)
    expect(removeSpy).toHaveBeenCalledTimes(1)
    const third = await reconciler().recoverAbandonedApplications()
    expect(third.processed).toBe(0)
    expect((await current()).enforcementStatus).toBe('FAILED')
  })

  test('a request still within the grace period is left alone', async () => {
    await interruptedAt('ACTIVE')
    const res = await reconciler().recoverAbandonedApplications()
    expect(res.processed).toBe(0)
    expect((await current()).enforcementStatus).toBe('APPLYING')
  })

  test('an expired interrupted action is recovered the same way; TTL reconciliation does not touch it', async () => {
    await interruptedAt('ACTIVE')
    await ContainmentAction.collection.updateOne({}, { $set: { expiresAt: new Date(Date.now() - 60000) } })
    await age()
    const svc = reconciler()
    expect((await svc.reconcileExpiredActions()).processed).toBe(0) // only ACTIVE/ROLLBACK_FAILED/abandoned removals
    expect((await svc.recoverAbandonedApplications()).released).toBe(1)
  })

  test('the periodic pass runs both TTL reconciliation and application recovery', async () => {
    const svc = reconciler()
    const ttl = jest.spyOn(svc, 'reconcileExpiredActions').mockResolvedValue({ processed: 0 })
    const rec = jest.spyOn(svc, 'recoverAbandonedApplications').mockResolvedValue({ processed: 0 })
    await svc.runOnce()
    expect(ttl).toHaveBeenCalledTimes(1)
    expect(rec).toHaveBeenCalledTimes(1)
  })
})
