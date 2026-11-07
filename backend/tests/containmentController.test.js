'use strict'
/**
 * F-08: containmentController had 45 % line coverage (its routes were tested only through mocks in roleMatrix).
 * These call the real handlers against in-memory MongoDB and the mock adapter: validation, policy rejection,
 * idempotent repeats, rollback, list filters (including operator-object query values), lookups by containmentId
 * and _id, error propagation, and the CONT-R2 / F-07 handlers' error mapping. No firewall is touched.
 */
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-containment-controller-refresh-0123456'
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  emit: jest.fn(),
}))

require('../models/User') // populate('requestedBy') needs the model registered, as server.js does
const ContainmentAction = require('../models/ContainmentAction')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
const ctl = require('../controllers/containmentController')
const audit = require('../utils/containmentAudit')
const { setContainmentAdapter, resetContainmentAdapter } = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

const ADMIN = {
  _id: new mongoose.Types.ObjectId(),
  email: 'admin@ctl.test',
  name: 'Admin',
  role: 'admin',
  status: 'active',
}
let mongo

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
beforeEach(() => setContainmentAdapter(new MockContainmentAdapter()))
afterEach(async () => {
  jest.restoreAllMocks()
  resetContainmentAdapter()
  await audit.settleContainmentAudit()
  await ContainmentAction.deleteMany({})
  await ContainmentAuditEvent.collection.deleteMany({})
})

function call(handler, { params = {}, body, query = {}, user = ADMIN } = {}) {
  return new Promise((resolve) => {
    const res = {
      statusCode: 200,
      set() {
        return this
      },
      status(c) {
        this.statusCode = c
        return this
      },
      json(b) {
        resolve({ status: this.statusCode, body: b })
        return this
      },
    }
    handler({ params, body, query, user }, res, (err) => {
      resolve({ status: 'next', error: err })
    })
  })
}

const block = (target, extra = {}) =>
  call(ctl.requestContainment, { body: { target, reason: 'ctl test', durationSeconds: 600, ...extra } })

describe('requestContainment', () => {
  test.each([[undefined], [''], ['   '], [42], [{ $ne: '' }]])('target %p: 400', async (target) => {
    const r = await call(ctl.requestContainment, { body: { target } })
    expect(r.status).toBe(400)
  })

  test('no body at all: 400, not a crash', async () => {
    expect((await call(ctl.requestContainment, { body: undefined })).status).toBe(400)
  })

  test('new action: 201 ACTIVE; the same target again: 200 already active (one action)', async () => {
    const first = await block('198.51.100.40')
    expect(first.status).toBe(201)
    expect(first.body.data.action.enforcementStatus).toBe('ACTIVE')
    const again = await block(' 198.51.100.40 ')
    expect(again.status).toBe(200)
    expect(await ContainmentAction.countDocuments({ normalizedTarget: '198.51.100.40' })).toBe(1)
  })

  test('policy rejection (loopback) is answered with its status code, not passed to the error handler', async () => {
    const r = await block('127.0.0.1')
    expect(r.status).toBeGreaterThanOrEqual(400)
    expect(r.status).toBeLessThan(500)
    expect(r.body.success).toBe(false)
  })

  test('isPermanent must be literally true', async () => {
    const r = await block('198.51.100.41', { isPermanent: 'true' })
    expect(r.status).toBe(201)
    expect(r.body.data.action.isPermanent).not.toBe(true)
  })

  test('an unexpected service error goes to next()', async () => {
    const svc = require('../services/containmentService')
    jest.spyOn(svc, 'requestContainment').mockRejectedValue(new Error('boom'))
    const r = await block('198.51.100.42')
    expect(r.status).toBe('next')
    expect(r.error.message).toBe('boom')
  })
})

describe('rollbackContainment', () => {
  test('rolls back an active action', async () => {
    const { body } = await block('198.51.100.43')
    const r = await call(ctl.rollbackContainment, { params: { id: body.data.action.containmentId }, body: {} })
    expect(r.status).toBe(200)
    expect(r.body.data.action.enforcementStatus).toBe('ROLLED_BACK')
  })

  test('unknown action: an error status, no crash', async () => {
    const r = await call(ctl.rollbackContainment, { params: { id: 'CTN-missing' }, body: undefined })
    if (r.status === 'next') expect(r.error).toBeInstanceOf(Error)
    else expect(r.status).toBeGreaterThanOrEqual(400)
  })

  test('rolling back twice: the second answer is an error status', async () => {
    const { body } = await block('198.51.100.44')
    const id = body.data.action.containmentId
    await call(ctl.rollbackContainment, { params: { id }, body: {} })
    const r = await call(ctl.rollbackContainment, { params: { id }, body: {} })
    expect(r.status === 'next' || r.status >= 400).toBe(true)
  })
})

describe('getActions', () => {
  beforeEach(async () => {
    await block('198.51.100.50')
    await block('198.51.100.51')
    await block('203.0.113.52')
  })

  test('paginates and reports the total', async () => {
    const r = await call(ctl.getActions, { query: { page: '1', limit: '2' } })
    expect(r.status).toBe(200)
    expect(r.body.data).toHaveLength(2)
    expect(r.body.pagination.total).toBe(3)
  })

  test('filters by target substring (regex-escaped), status and backend', async () => {
    expect((await call(ctl.getActions, { query: { target: '198.51.100.5' } })).body.data).toHaveLength(2)
    expect((await call(ctl.getActions, { query: { target: '198.51.100.5.' } })).body.data).toHaveLength(0) // '.' literal
    expect((await call(ctl.getActions, { query: { status: ' active ' } })).body.data).toHaveLength(3)
    expect((await call(ctl.getActions, { query: { status: 'ROLLED_BACK' } })).body.data).toHaveLength(0)
    expect((await call(ctl.getActions, { query: { backend: 'MOCK' } })).body.pagination.total).toBe(3)
  })

  test('operator objects in query values are ignored, not used as a filter', async () => {
    const r = await call(ctl.getActions, { query: { status: { $ne: 'X' }, target: { $regex: '.*' } } })
    expect(r.status).toBe(200)
    expect(r.body.pagination.total).toBe(3)
  })

  test('limit is capped at 100', async () => {
    const r = await call(ctl.getActions, { query: { limit: '100000' } })
    expect(r.body.pagination.limit).toBeLessThanOrEqual(100)
  })

  test('a database error goes to next()', async () => {
    jest.spyOn(ContainmentAction, 'countDocuments').mockRejectedValue(new Error('db down'))
    expect((await call(ctl.getActions, {})).status).toBe('next')
  })
})

describe('getAction / getStatus / getRecovery / getAuditTrail', () => {
  test('by containmentId and by _id; unknown: 404', async () => {
    const { body } = await block('198.51.100.60')
    const action = body.data.action
    expect(
      (await call(ctl.getAction, { params: { id: action.containmentId } })).body.data.action.normalizedTarget
    ).toBe('198.51.100.60')
    const doc = await ContainmentAction.findOne({ containmentId: action.containmentId }).lean()
    expect((await call(ctl.getAction, { params: { id: String(doc._id) } })).status).toBe(200)
    expect((await call(ctl.getAction, { params: { id: 'CTN-none' } })).status).toBe(404)
    expect((await call(ctl.getAction, { params: { id: String(new mongoose.Types.ObjectId()) } })).status).toBe(404)
  })

  test('getAction database error goes to next()', async () => {
    jest.spyOn(ContainmentAction, 'findOne').mockImplementation(() => {
      throw new Error('db down')
    })
    expect((await call(ctl.getAction, { params: { id: 'x' } })).status).toBe('next')
  })

  test('getStatus reports the backend and counts; real enforcement is off', async () => {
    await block('198.51.100.61')
    const r = await call(ctl.getStatus)
    expect(r.status).toBe(200)
    expect(r.body.data).toMatchObject({ activeContainmentCount: 1, realEnforcementEnabled: false })
  })

  test('getStatus / getRecovery errors go to next()', async () => {
    jest.spyOn(ContainmentAction, 'countDocuments').mockRejectedValue(new Error('db down'))
    expect((await call(ctl.getStatus)).status).toBe('next')
    const { defaultReconciliationService } = require('../services/containmentReconciliationService')
    jest.spyOn(defaultReconciliationService, 'getRecoveryReport').mockRejectedValue(new Error('db down'))
    expect((await call(ctl.getRecovery)).status).toBe('next')
  })

  test('getRecovery returns the report', async () => {
    const r = await call(ctl.getRecovery)
    expect(r.status).toBe(200)
    expect(r.body.success).toBe(true)
  })

  test('getAuditTrail: by _id, oversized id 404, error to next()', async () => {
    const { body } = await block('198.51.100.62')
    await audit.settleContainmentAudit()
    const doc = await ContainmentAction.findOne({ containmentId: body.data.action.containmentId }).lean()
    const r = await call(ctl.getAuditTrail, { params: { id: String(doc._id) } })
    expect(r.status).toBe(200)
    expect(r.body.data.events.length).toBeGreaterThan(0)
    expect((await call(ctl.getAuditTrail, { params: { id: 'x'.repeat(200) } })).status).toBe(404)
    jest.spyOn(ContainmentAction, 'findOne').mockImplementation(() => {
      throw new Error('db down')
    })
    expect((await call(ctl.getAuditTrail, { params: { id: 'y' } })).status).toBe('next')
  })
})

describe('operator recovery handlers', () => {
  test('diagnosis of an unknown action: 404; of an ACTIVE one: 200 not recoverable', async () => {
    expect((await call(ctl.diagnoseRecovery, { params: { id: 'CTN-none' } })).status).toBe(404)
    const { body } = await block('198.51.100.70')
    const r = await call(ctl.diagnoseRecovery, { params: { id: body.data.action.containmentId } })
    expect(r.status).toBe(200)
    expect(r.body.data.recoverable).toBe(false)
  })

  test('recover with a bad token: 403; without a reason: 422; no body: 422', async () => {
    const { body } = await block('198.51.100.71')
    const id = body.data.action.containmentId
    expect(
      (await call(ctl.operatorRecover, { params: { id }, body: { reason: 'long enough', confirmationToken: 'a.b' } }))
        .status
    ).toBe(403)
    expect((await call(ctl.operatorRecover, { params: { id }, body: { confirmationToken: 'a.b' } })).status).toBe(422)
    expect((await call(ctl.operatorRecover, { params: { id }, body: undefined })).status).toBe(422)
  })

  test('unexpected errors go to next()', async () => {
    const rec = require('../services/containmentOperatorRecovery')
    jest.spyOn(rec, 'diagnose').mockRejectedValue(new Error('boom'))
    jest.spyOn(rec, 'recover').mockRejectedValue(new Error('boom'))
    expect((await call(ctl.diagnoseRecovery, { params: { id: 'x' } })).status).toBe('next')
    expect((await call(ctl.operatorRecover, { params: { id: 'x' }, body: {} })).status).toBe('next')
  })
})
