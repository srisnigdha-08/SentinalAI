'use strict'
/**
 * F-07: containment audit events were log lines only (utils/containmentAudit.js), lost with log rotation and
 * not queryable per action. They are now also stored in containment_audit_events. Real MongoDB in memory and
 * the mock adapter only; no firewall is touched.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const ContainmentAction = require('../models/ContainmentAction')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
const containment = require('../services/containmentService')
const audit = require('../utils/containmentAudit')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

const ADMIN = { id: new mongoose.Types.ObjectId().toString(), email: 'a@x.test', role: 'admin', status: 'active' }
let mongo
let ipCounter = 10
const nextIP = () => `198.51.100.${ipCounter++}`

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await Promise.all([ContainmentAction.init(), ContainmentAuditEvent.init()])
})
afterAll(async () => {
  await audit.settleContainmentAudit()
  await mongoose.disconnect()
  await mongo.stop()
})
beforeEach(() => setContainmentAdapter(new MockContainmentAdapter()))
afterEach(async () => {
  jest.restoreAllMocks()
  resetContainmentAdapter()
  await audit.settleContainmentAudit()
  await ContainmentAction.deleteMany({})
  await ContainmentAuditEvent.collection.deleteMany({})
})

const events = (containmentId) => ContainmentAuditEvent.find({ containmentId }).sort({ seq: 1 }).lean()

test('a containment lifecycle is stored durably, in order, with operator and policy traceability', async () => {
  const ip = nextIP()
  const { action } = await containment.requestContainment({
    target: ip,
    requester: ADMIN,
    reason: 'r',
    emitEvents: false,
  })
  await containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN, reason: 'done' })
  await audit.settleContainmentAudit()

  const trail = await events(action.containmentId)
  const names = trail.map((e) => e.action)
  expect(names[0]).toBe('CONTAINMENT_REQUESTED')
  expect(names).toContain('CONTAINMENT_ACTIVE')
  expect(names.indexOf('CONTAINMENT_ACTIVE')).toBeLessThan(names.indexOf('ROLLBACK_INITIATED'))
  expect(names[names.length - 1]).toBe('CONTAINMENT_ROLLED_BACK')
  for (let i = 1; i < trail.length; i++) {
    expect(trail[i].seq).toBeGreaterThan(trail[i - 1].seq)
    expect(trail[i].recordedAt.getTime()).toBeGreaterThanOrEqual(trail[i - 1].recordedAt.getTime())
  }
  const requested = trail[0]
  expect(requested).toMatchObject({ target: ip, policyDecision: expect.any(String), enforcementStatus: 'REQUESTED' })
  expect(requested.operator).toEqual({ id: ADMIN.id, email: ADMIN.email, role: 'admin' })
  expect(requested.correlationId).toBeTruthy()
})

test('the same once-per-action event recorded twice is stored once', async () => {
  const id = 'CTN-dup-' + Date.now()
  const e1 = audit.logContainmentAudit({ action: 'CONTAINMENT_ACTIVE', containmentId: id, target: nextIP() })
  const e2 = audit.logContainmentAudit({ action: 'CONTAINMENT_ACTIVE', containmentId: id, target: e1.target })
  expect(e1.eventId).toBe(e2.eventId)
  expect(await e1.persisted).toBe('stored')
  expect(await e2.persisted).toBe('duplicate')
  expect(await ContainmentAuditEvent.countDocuments({ containmentId: id })).toBe(1)
})

test('repeating events (rollback attempts) are each stored; a retried write of one attempt is not duplicated', async () => {
  const id = 'CTN-rep-' + Date.now()
  audit.logContainmentAudit({ action: 'ROLLBACK_FAILED', containmentId: id })
  audit.logContainmentAudit({ action: 'ROLLBACK_FAILED', containmentId: id })
  const a = audit.logContainmentAudit({
    action: 'CONTAINMENT_RECOVERY_DEFERRED',
    containmentId: id,
    eventKey: 'RECOVERY_DEFERRED:1',
  })
  const b = audit.logContainmentAudit({
    action: 'CONTAINMENT_RECOVERY_DEFERRED',
    containmentId: id,
    eventKey: 'RECOVERY_DEFERRED:1',
  })
  await Promise.all([a.persisted, b.persisted])
  expect(await ContainmentAuditEvent.countDocuments({ containmentId: id, action: 'ROLLBACK_FAILED' })).toBe(2)
  expect(
    await ContainmentAuditEvent.countDocuments({ containmentId: id, action: 'CONTAINMENT_RECOVERY_DEFERRED' })
  ).toBe(1)
})

test('a failed write is retried and stored exactly once', async () => {
  const id = 'CTN-retry-' + Date.now()
  jest.spyOn(ContainmentAuditEvent, 'create').mockRejectedValueOnce(new Error('simulated write timeout'))
  const e = audit.logContainmentAudit({ action: 'CONTAINMENT_REQUESTED', containmentId: id })
  expect(await e.persisted).toBe('stored')
  expect(await ContainmentAuditEvent.countDocuments({ containmentId: id })).toBe(1)
})

test('while MongoDB is unavailable events are queued, then stored in their original order', async () => {
  const id = 'CTN-queue-' + Date.now()
  // readyState has a setter that emits the matching connection event; the client itself stays connected.
  mongoose.connection.readyState = 0
  const queued = ['CONTAINMENT_REQUESTED', 'CONTAINMENT_ACTIVE', 'ROLLBACK_INITIATED', 'CONTAINMENT_ROLLED_BACK'].map(
    (action) => audit.logContainmentAudit({ action, containmentId: id })
  )
  expect(await Promise.all(queued.map((e) => e.persisted))).toEqual(['queued', 'queued', 'queued', 'queued'])
  expect(audit.containmentAuditBacklog().queued).toBeGreaterThanOrEqual(4)
  expect(await ContainmentAuditEvent.countDocuments({ containmentId: id })).toBe(0)

  mongoose.connection.readyState = 1 // emits 'connected': the backlog flush starts on its own
  await audit.settleContainmentAudit()
  expect((await events(id)).map((e) => e.action)).toEqual([
    'CONTAINMENT_REQUESTED',
    'CONTAINMENT_ACTIVE',
    'ROLLBACK_INITIATED',
    'CONTAINMENT_ROLLED_BACK',
  ])
  expect(audit.containmentAuditBacklog().queued).toBe(0)
})

test('an event logged while older ones are still being flushed is stored after them (no overtaking)', async () => {
  const id = 'CTN-order-' + Date.now()
  mongoose.connection.readyState = 0
  const a1 = audit.logContainmentAudit({ action: 'CONTAINMENT_REQUESTED', containmentId: id })
  const a2 = audit.logContainmentAudit({ action: 'CONTAINMENT_ACTIVE', containmentId: id })
  await Promise.all([a1.persisted, a2.persisted])
  // Slow down the flush of the first queued event so a newer event has the chance to overtake it.
  const realExists = ContainmentAuditEvent.exists.bind(ContainmentAuditEvent)
  jest.spyOn(ContainmentAuditEvent, 'exists').mockImplementation(async (filter) => {
    if (filter?.eventId === a1.eventId) await new Promise((r) => setTimeout(r, 150))
    return realExists(filter)
  })
  mongoose.connection.readyState = 1 // 'connected': flush starts
  audit.logContainmentAudit({ action: 'ROLLBACK_INITIATED', containmentId: id })
  await audit.settleContainmentAudit()
  expect((await events(id)).map((e) => e.action)).toEqual([
    'CONTAINMENT_REQUESTED',
    'CONTAINMENT_ACTIVE',
    'ROLLBACK_INITIATED',
  ])
})

test('events queued after write failures while connected are flushed without waiting for a reconnect', async () => {
  const id = 'CTN-stuck-' + Date.now()
  jest
    .spyOn(ContainmentAuditEvent, 'create')
    .mockRejectedValueOnce(new Error('timeout 1'))
    .mockRejectedValueOnce(new Error('timeout 2'))
    .mockRejectedValueOnce(new Error('timeout 3'))
  expect(await audit.logContainmentAudit({ action: 'CONTAINMENT_REQUESTED', containmentId: id }).persisted).toBe(
    'queued'
  )
  jest.restoreAllMocks()
  audit.logContainmentAudit({ action: 'CONTAINMENT_ACTIVE', containmentId: id })
  await audit.settleContainmentAudit()
  expect((await events(id)).map((e) => e.action)).toEqual(['CONTAINMENT_REQUESTED', 'CONTAINMENT_ACTIVE'])
  expect(audit.containmentAuditBacklog().queued).toBe(0)
})

test('recordedAt comes from the database clock, not the backend clock', async () => {
  const id = 'CTN-clock-' + Date.now()
  const realNow = Date.now()
  const SKEW = 3 * 3600 * 1000 // backend host clock 3 h fast
  // Fake only Date (new Date() and Date.now()); timers stay real so the MongoDB driver keeps working.
  jest.useFakeTimers({
    now: realNow + SKEW,
    doNotFake: [
      'hrtime',
      'nextTick',
      'performance',
      'queueMicrotask',
      'setImmediate',
      'clearImmediate',
      'setInterval',
      'clearInterval',
      'setTimeout',
      'clearTimeout',
    ],
  })
  try {
    await audit.logContainmentAudit({ action: 'CONTAINMENT_REQUESTED', containmentId: id }).persisted
  } finally {
    jest.useRealTimers()
  }
  const [stored] = await events(id)
  expect(stored.occurredAt.getTime()).toBeGreaterThanOrEqual(realNow + SKEW) // backend clock, as recorded
  expect(Math.abs(stored.recordedAt.getTime() - Date.now())).toBeLessThan(60 * 1000) // database clock
})

test('stored events are immutable through the model', async () => {
  const id = 'CTN-imm-' + Date.now()
  await audit.logContainmentAudit({ action: 'CONTAINMENT_REQUESTED', containmentId: id }).persisted
  await expect(ContainmentAuditEvent.updateOne({ containmentId: id }, { action: 'X' })).rejects.toThrow(/immutable/)
  await expect(ContainmentAuditEvent.deleteMany({ containmentId: id })).rejects.toThrow(/immutable/)
  const doc = await ContainmentAuditEvent.findOne({ containmentId: id })
  doc.action = 'X'
  await expect(doc.save()).rejects.toThrow(/immutable/)
})

test('secrets in details are redacted before storage', async () => {
  const id = 'CTN-red-' + Date.now()
  await audit.logContainmentAudit({
    action: 'CONTAINMENT_REQUESTED',
    containmentId: id,
    details: { reason: 'x', apiToken: 'tok-value', nested: { password: 'pw-value' } },
  }).persisted
  const [stored] = await events(id)
  expect(JSON.stringify(stored)).not.toMatch(/tok-value|pw-value/)
})

describe('GET /api/containment/actions/:id/audit', () => {
  const { getAuditTrail } = require('../controllers/containmentController')
  const call = (id) =>
    new Promise((resolve, reject) => {
      const res = {
        status(c) {
          this.code = c
          return this
        },
        json(body) {
          resolve({ status: this.code || 200, body })
        },
      }
      getAuditTrail({ params: { id } }, res, reject)
    })

  test('returns the trail of an existing action in order', async () => {
    const { action } = await containment.requestContainment({
      target: nextIP(),
      requester: ADMIN,
      reason: 'r',
      emitEvents: false,
    })
    await audit.settleContainmentAudit()
    const r = await call(action.containmentId)
    expect(r.status).toBe(200)
    expect(r.body.data.events[0].action).toBe('CONTAINMENT_REQUESTED')
    expect(r.body.data.events.every((e) => e._id === undefined)).toBe(true)
  })

  test('unknown action: 404', async () => {
    expect((await call('CTN-does-not-exist')).status).toBe(404)
  })
})
