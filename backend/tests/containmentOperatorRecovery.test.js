'use strict'
/**
 * CONT-R2: admin-only operator recovery of a containment request interrupted before ACTIVE/FAILED.
 * Real MongoDB in memory and the mock adapter only; no firewall is touched.
 */
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-operator-recovery-refresh-secret-0123'
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ContainmentAction = require('../models/ContainmentAction')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
const AuditLog = require('../models/AuditLog')
const containment = require('../services/containmentService')
const recovery = require('../services/containmentOperatorRecovery')
const audit = require('../utils/containmentAudit')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

const IP = '198.51.100.77'
const ADMIN = { _id: new mongoose.Types.ObjectId(), email: 'admin@rec.test', role: 'admin', status: 'active' }
const OTHER_ADMIN = { _id: new mongoose.Types.ObjectId(), email: 'other@rec.test', role: 'admin', status: 'active' }
let mongo
let adapter

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await ContainmentAction.init()
})
afterAll(async () => {
  await audit.settleContainmentAudit()
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
  await audit.settleContainmentAudit()
  await ContainmentAction.deleteMany({})
  await ContainmentAuditEvent.collection.deleteMany({})
  await AuditLog.collection.deleteMany({})
})

/** A request whose save into `failAt` throws, as if the process stopped there; then aged past the minimum age. */
async function stuckAt(failAt, { minutes = 10 } = {}) {
  const realSave = ContainmentAction.prototype.save
  jest.spyOn(ContainmentAction.prototype, 'save').mockImplementation(function (...args) {
    if (this.enforcementStatus === failAt) return Promise.reject(new Error('simulated crash'))
    return realSave.apply(this, args)
  })
  await expect(
    containment.requestContainment({ target: IP, requester: ADMIN, reason: 'test', emitEvents: false })
  ).rejects.toThrow('simulated crash')
  jest.restoreAllMocks()
  await ContainmentAction.collection.updateMany({}, { $set: { updatedAt: new Date(Date.now() - minutes * 60000) } })
  return ContainmentAction.findOne({ normalizedTarget: IP }).lean()
}
const current = () => ContainmentAction.findOne({ normalizedTarget: IP }).lean()
const REASON = 'verified on the host that the request process died'

test('diagnosis is read-only: nothing about the action or the rules changes', async () => {
  const before = await stuckAt('ACTIVE') // rule applied, ACTIVE never saved -> APPLYING
  expect(before.enforcementStatus).toBe('APPLYING')
  const rulesBefore = adapter.activeRules.size
  const d = await recovery.diagnose(before.containmentId, ADMIN)
  expect(d).toMatchObject({ ruleState: 'PRESENT', recoverable: true, plannedOutcome: 'REMOVE_RULE_THEN_RELEASE' })
  const after = await current()
  expect(after.__v).toBe(before.__v)
  expect(after.enforcementStatus).toBe('APPLYING')
  expect(adapter.activeRules.size).toBe(rulesBefore)
})

test('PRESENT rule: recovery removes it, confirms ABSENT, then releases the lock, with a full audit trail', async () => {
  const stuck = await stuckAt('ACTIVE')
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  const r = await recovery.recover(
    stuck.containmentId,
    { confirmationToken: d.confirmationToken, reason: REASON },
    ADMIN
  )
  expect(r).toMatchObject({ outcome: 'RULE_REMOVED', released: true, enforcementStatus: 'FAILED' })
  expect(adapter.activeRules.size).toBe(0)
  const after = await current()
  expect(after.targetLock ?? null).toBeNull()
  expect(after.recovery.lastOperator).toMatchObject({ id: String(ADMIN._id), email: ADMIN.email, reason: REASON })
  await audit.settleContainmentAudit()
  const trail = (await ContainmentAuditEvent.find({ containmentId: stuck.containmentId }).sort({ seq: 1 }).lean()).map(
    (e) => e.action
  )
  expect(trail).toEqual(expect.arrayContaining(['OPERATOR_RECOVERY_DIAGNOSED', 'OPERATOR_RECOVERY_RELEASED']))
  expect(
    await AuditLog.countDocuments({ action: 'CONTAINMENT_OPERATOR_RECOVERY', 'actor.id': String(ADMIN._id) })
  ).toBe(1)
})

test('UNKNOWN rule state: no token is issued and nothing can be released', async () => {
  const stuck = await stuckAt('ACTIVE')
  jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' })
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  expect(d.recoverable).toBe(false)
  expect(d.confirmationToken).toBeNull()
  expect(d.notRecoverableReason).toMatch(/UNKNOWN/)
  expect((await current()).enforcementStatus).toBe('APPLYING')
})

test('state turns UNKNOWN between diagnosis and recovery: the lock is kept', async () => {
  const stuck = await stuckAt('ACTIVE')
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' })
  const r = await recovery.recover(
    stuck.containmentId,
    { confirmationToken: d.confirmationToken, reason: REASON },
    ADMIN
  )
  expect(r).toMatchObject({ released: false, lockHeld: true, outcome: 'RULE_STATE_UNKNOWN' })
  const after = await current()
  expect(after.enforcementStatus).toBe('APPLYING')
  expect(after.targetLock).toBeTruthy()
  expect(adapter.activeRules.size).toBe(1)
})

test('adapter throws during recovery: treated as unavailable, lock kept', async () => {
  const stuck = await stuckAt('ACTIVE')
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  jest.spyOn(adapter, 'inspectRule').mockRejectedValue(new Error('adapter offline'))
  const r = await recovery.recover(
    stuck.containmentId,
    { confirmationToken: d.confirmationToken, reason: REASON },
    ADMIN
  )
  expect(r).toMatchObject({ released: false, outcome: 'ADAPTER_UNAVAILABLE' })
  expect((await current()).enforcementStatus).toBe('APPLYING')
})

test('APPROVED (adapter never called): released without touching the adapter', async () => {
  const stuck = await stuckAt('APPLYING') // the APPLYING save failed -> stays APPROVED
  expect(stuck.enforcementStatus).toBe('APPROVED')
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  expect(d.ruleState).toBe('NOT_APPLIED')
  const inspect = jest.spyOn(adapter, 'inspectRule')
  const r = await recovery.recover(
    stuck.containmentId,
    { confirmationToken: d.confirmationToken, reason: REASON },
    ADMIN
  )
  expect(r).toMatchObject({ released: true, outcome: 'NOT_APPLIED' })
  expect(inspect).not.toHaveBeenCalled()
})

test('a request updated moments ago is refused (it may still be running)', async () => {
  const stuck = await stuckAt('ACTIVE', { minutes: 0 })
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  expect(d.recoverable).toBe(false)
  expect(d.notRecoverableReason).toMatch(/still be running/)
})

test('ACTIVE and terminal actions are not offered for recovery', async () => {
  const { action } = await containment.requestContainment({
    target: IP,
    requester: ADMIN,
    reason: 'r',
    emitEvents: false,
  })
  await ContainmentAction.collection.updateMany({}, { $set: { updatedAt: new Date(Date.now() - 600000) } })
  const d = await recovery.diagnose(action.containmentId, ADMIN)
  expect(d.recoverable).toBe(false)
  expect(d.confirmationToken).toBeNull()
})

test('AuditLog unavailable: recovery is refused (503) before anything changes; the token stays usable', async () => {
  const stuck = await stuckAt('ACTIVE')
  const d = await recovery.diagnose(stuck.containmentId, ADMIN)
  const before = await current()
  jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('audit store down'))
  const body = { confirmationToken: d.confirmationToken, reason: REASON }
  await expect(recovery.recover(stuck.containmentId, body, ADMIN)).rejects.toMatchObject({ statusCode: 503 })
  const after = await current()
  expect(after.__v).toBe(before.__v) // not claimed
  expect(after.enforcementStatus).toBe('APPLYING')
  expect(adapter.activeRules.size).toBe(1) // rule untouched
  const r = await recovery.recover(stuck.containmentId, body, ADMIN) // audit back: the same token works once
  expect(r.released).toBe(true)
  const entries = await AuditLog.find({ 'target.id': stuck.containmentId }).sort({ createdAt: 1 }).lean()
  expect(entries.map((e) => e.action)).toEqual([
    'CONTAINMENT_OPERATOR_RECOVERY_REQUESTED',
    'CONTAINMENT_OPERATOR_RECOVERY',
  ])
})

describe('concurrency and replay', () => {
  test('two administrators recovering the same action at once: exactly one claims it, the other gets 409', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d1 = await recovery.diagnose(stuck.containmentId, ADMIN)
    const d2 = await recovery.diagnose(stuck.containmentId, OTHER_ADMIN)
    const results = await Promise.allSettled([
      recovery.recover(stuck.containmentId, { confirmationToken: d1.confirmationToken, reason: REASON }, ADMIN),
      recovery.recover(stuck.containmentId, { confirmationToken: d2.confirmationToken, reason: REASON }, OTHER_ADMIN),
    ])
    const ok = results.filter((r) => r.status === 'fulfilled')
    const refused = results.filter((r) => r.status === 'rejected')
    expect(ok).toHaveLength(1)
    expect(refused).toHaveLength(1)
    expect(refused[0].reason).toMatchObject({ statusCode: 409, code: 'STATE_CHANGED' })
    expect((await current()).recovery.attempts).toBe(1)
  })

  test('the same token sent twice at once: one runs, the other is refused', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    const body = { confirmationToken: d.confirmationToken, reason: REASON }
    const results = await Promise.allSettled([
      recovery.recover(stuck.containmentId, body, ADMIN),
      recovery.recover(stuck.containmentId, body, ADMIN),
    ])
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
    expect(results.find((r) => r.status === 'rejected').reason.statusCode).toBe(409)
  })

  test('replay after a process restart (used-token memory empty) is still refused: the token is bound to the version', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' }) // keeps the action recoverable
    const body = { confirmationToken: d.confirmationToken, reason: REASON }
    await recovery.recover(stuck.containmentId, body, ADMIN)
    recovery._usedTokens.clear() // what a restart does to the in-memory list
    await expect(recovery.recover(stuck.containmentId, body, ADMIN)).rejects.toMatchObject({
      statusCode: 409,
      code: 'STATE_CHANGED',
    })
  })

  test('a token for one action cannot be used on another', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    const other = await ContainmentAction.create({
      containmentId: 'CTN-other-' + Date.now(),
      target: '198.51.100.78',
      normalizedTarget: '198.51.100.78',
      targetType: 'ipv4',
      actionType: 'block_ip',
      enforcementStatus: 'FAILED',
      reason: 'x',
    })
    expect(await ContainmentAction.exists({ containmentId: other.containmentId })).toBeTruthy()
    const otherId = other.containmentId
    await expect(
      recovery.recover(otherId, { confirmationToken: d.confirmationToken, reason: REASON }, ADMIN)
    ).rejects.toMatchObject({ statusCode: 403, code: 'TOKEN_INVALID' })
  })
})

describe('confirmation token', () => {
  test('is single-use', async () => {
    const stuck = await stuckAt('ACTIVE')
    // diagnosed PRESENT; recovery then sees UNKNOWN, so the first use keeps the lock and the action stays recoverable
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    jest.spyOn(adapter, 'inspectRule').mockResolvedValue({ state: 'UNKNOWN' })
    const body = { confirmationToken: d.confirmationToken, reason: REASON }
    await recovery.recover(stuck.containmentId, body, ADMIN)
    await expect(recovery.recover(stuck.containmentId, body, ADMIN)).rejects.toMatchObject({ statusCode: 409 })
  })

  test('is bound to the administrator it was issued to', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    await expect(
      recovery.recover(stuck.containmentId, { confirmationToken: d.confirmationToken, reason: REASON }, OTHER_ADMIN)
    ).rejects.toMatchObject({ statusCode: 403 })
    expect((await current()).enforcementStatus).toBe('APPLYING')
  })

  test('expires', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    const later = Date.now() + 6 * 60000
    await expect(
      recovery.recover(stuck.containmentId, { confirmationToken: d.confirmationToken, reason: REASON }, ADMIN, later)
    ).rejects.toMatchObject({ statusCode: 403, code: 'TOKEN_EXPIRED' })
  })

  test('a tampered token is rejected', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    const [body, sig] = d.confirmationToken.split('.')
    const claims = JSON.parse(Buffer.from(body, 'base64url').toString())
    claims.exp += 3600000
    const forged = Buffer.from(JSON.stringify(claims)).toString('base64url') + '.' + sig
    await expect(
      recovery.recover(stuck.containmentId, { confirmationToken: forged, reason: REASON }, ADMIN)
    ).rejects.toMatchObject({ statusCode: 403, code: 'TOKEN_INVALID' })
  })

  test('the action changing after the diagnosis invalidates it (409, diagnose again)', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    await ContainmentAction.updateOne({ _id: stuck._id }, { $inc: { __v: 1 } }) // e.g. the reconciliation pass
    await expect(
      recovery.recover(stuck.containmentId, { confirmationToken: d.confirmationToken, reason: REASON }, ADMIN)
    ).rejects.toMatchObject({ statusCode: 409, code: 'STATE_CHANGED' })
  })

  test('a reason is required', async () => {
    const stuck = await stuckAt('ACTIVE')
    const d = await recovery.diagnose(stuck.containmentId, ADMIN)
    await expect(
      recovery.recover(stuck.containmentId, { confirmationToken: d.confirmationToken }, ADMIN)
    ).rejects.toMatchObject({ statusCode: 422 })
  })
})
