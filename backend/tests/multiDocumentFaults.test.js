'use strict'
/**
 * F-06: fault injection on multi-document operations, through the real controllers, on disposable MongoDB.
 *
 * Each operation writes the business document(s) and an AuditLog entry. The audit write is made to fail
 * (AuditLog.create rejects, as on a write timeout or a dropped connection) and the test checks what is left:
 *   - replica set + MONGO_USE_TRANSACTIONS=true: the transaction aborts, so nothing changes;
 *   - standalone (the default deployment): the compensating fallback must restore exactly the prior state.
 *
 * Defects found and fixed with this suite (standalone fallback):
 *   - blockIP on an already-blocked threat, or on an IP another threat had already deny-listed, deleted the
 *     existing BlockedIP entry and set the threat to its pre-block status: an audit failure unblocked an IP
 *     that had been blocked legitimately;
 *   - blockIP compensation left handledBy / containmentId / autonomousAction set by the failed block;
 *   - updateUser compensation reverted role / status / authVersion only: a name or department change stayed
 *     applied although the API answered "change not applied", and tokenVersion stayed incremented.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitIPBlocked: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
  disconnectUser: jest.fn(),
}))

const mongoose = require('mongoose')
const { MongoMemoryServer, MongoMemoryReplSet } = require('mongodb-memory-server')
const User = require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const AuditLog = require('../models/AuditLog')
const { shouldUseTransactions } = require('../utils/transactionHelper')
const userController = require('../controllers/userController')
const threatController = require('../controllers/threatController')
const { denialCache } = require('../utils/auditLogger')

const ORIGINAL_TX = process.env.MONGO_USE_TRANSACTIONS
const admin = {
  _id: new mongoose.Types.ObjectId(),
  name: 'Admin',
  email: 'admin@fault.test',
  role: 'admin',
  status: 'active',
}

function call(handler, { params = {}, body = {} } = {}) {
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
    handler({ params, body, user: admin, ip: '127.0.0.1', headers: {} }, res, (err) =>
      resolve({ status: err?.statusCode || 500, error: err })
    )
  })
}

const failAuditOnce = () =>
  jest.spyOn(AuditLog, 'create').mockRejectedValueOnce(new Error('simulated audit write timeout'))

const strip = (doc) => {
  const o = doc ? (doc.toObject ? doc.toObject() : { ...doc }) : null
  if (o) delete o.updatedAt
  return o
}

async function seedUser(extra = {}) {
  return User.create({
    name: 'Original Name',
    email: `u${Date.now()}${Math.random().toString(16).slice(2)}@fault.test`,
    password: 'Original-Passw0rd!',
    role: 'analyst',
    department: 'SOC',
    status: 'active',
    authVersion: 3,
    tokenVersion: 5,
    ...extra,
  })
}

async function seedThreat(extra = {}) {
  return ThreatLog.create({
    sourceIP: '198.51.100.' + Math.floor(Math.random() * 200 + 20),
    attackType: 'SQL Injection',
    severity: 'HIGH',
    status: 'DETECTED',
    aiScore: 0.91,
    ...extra,
  })
}

function sharedCases(mode) {
  afterEach(async () => {
    jest.restoreAllMocks()
    denialCache?.clear?.()
    // AuditLog rejects deletes through the model (append-only); clear the disposable collection directly.
    await Promise.all([User, ThreatLog, BlockedIP, AuditLog].map((m) => m.collection.deleteMany({})))
  })

  test(`[${mode}] createUser: audit failure leaves no user and no audit entry`, async () => {
    failAuditOnce()
    const email = 'new-user@fault.test'
    const r = await call(userController.provisionUser, {
      body: { name: 'New', email, password: 'New-Passw0rd!long', role: 'viewer', department: 'SOC' },
    })
    expect(r.status).toBe(503) // provisionUser answers every failure with 503 'Account service unavailable'
    expect(await User.findOne({ email })).toBeNull()
    expect(await AuditLog.countDocuments({})).toBe(0)
  })

  test(`[${mode}] createUser: success writes the user and its audit entry`, async () => {
    const email = 'ok-user@fault.test'
    const r = await call(userController.provisionUser, {
      body: { name: 'Ok', email, password: 'Ok-Passw0rd!long1', role: 'viewer', department: 'SOC' },
    })
    expect(r.status).toBe(201)
    const user = await User.findOne({ email })
    expect(user).not.toBeNull()
    expect(await AuditLog.countDocuments({ action: 'USER_CREATED', 'target.id': user._id.toString() })).toBe(1)
  })

  test(`[${mode}] updateUser (name + department): audit failure restores every field`, async () => {
    const user = await seedUser()
    const before = strip(await User.findById(user._id).lean())
    failAuditOnce()
    const r = await call(userController.updateUser, {
      params: { id: user._id.toString() },
      body: { name: 'Changed Name', department: 'Changed Dept' },
    })
    expect(r.status).toBe(500)
    expect(strip(await User.findById(user._id).lean())).toEqual(before)
  })

  test(`[${mode}] updateUser (role change): audit failure restores role, authVersion and tokenVersion`, async () => {
    const user = await seedUser()
    const before = strip(await User.findById(user._id).lean())
    failAuditOnce()
    const r = await call(userController.updateUser, { params: { id: user._id.toString() }, body: { role: 'viewer' } })
    expect(r.status).toBe(500)
    expect(strip(await User.findById(user._id).lean())).toEqual(before)
  })

  test(`[${mode}] forceLogout: audit failure leaves sessions valid (authVersion unchanged)`, async () => {
    const user = await seedUser()
    failAuditOnce()
    const r = await call(userController.forceLogoutUser, { params: { id: user._id.toString() } })
    expect(r.status).toBe(500)
    const after = await User.findById(user._id).lean()
    expect(after.authVersion).toBe(3)
    expect(after.tokenVersion).toBe(5)
  })

  test(`[${mode}] blockIP on a DETECTED threat: audit failure restores the threat and leaves no deny-list entry`, async () => {
    const threat = await seedThreat()
    const before = strip(await ThreatLog.findById(threat._id).lean())
    failAuditOnce()
    const r = await call(threatController.blockIP, { params: { id: threat._id.toString() } })
    expect(r.status).toBe(500)
    expect(strip(await ThreatLog.findById(threat._id).lean())).toEqual(before)
    expect(await BlockedIP.findOne({ ip: threat.sourceIP })).toBeNull()
  })

  test(`[${mode}] blockIP on an already-blocked threat: audit failure must not unblock the IP`, async () => {
    const earlier = new mongoose.Types.ObjectId()
    const threat = await seedThreat({ status: 'BLOCKED', preBlockStatus: 'DETECTED', handledBy: earlier })
    await BlockedIP.create({ ip: threat.sourceIP, reason: 'Earlier block', blockedBy: earlier, threatRef: threat._id })
    const blockedBefore = strip(await BlockedIP.findOne({ ip: threat.sourceIP }).lean())
    const threatBefore = strip(await ThreatLog.findById(threat._id).lean())
    failAuditOnce()
    const r = await call(threatController.blockIP, { params: { id: threat._id.toString() } })
    expect(r.status).toBe(500)
    expect(strip(await BlockedIP.findOne({ ip: threat.sourceIP }).lean())).toEqual(blockedBefore)
    expect(strip(await ThreatLog.findById(threat._id).lean())).toEqual(threatBefore)
  })

  test(`[${mode}] blockIP when another threat already deny-listed the IP: audit failure keeps that entry`, async () => {
    const other = await seedThreat({ status: 'BLOCKED', preBlockStatus: 'DETECTED' })
    await BlockedIP.create({ ip: other.sourceIP, reason: 'Blocked via other threat', threatRef: other._id })
    const blockedBefore = strip(await BlockedIP.findOne({ ip: other.sourceIP }).lean())
    const threat = await seedThreat({ sourceIP: other.sourceIP })
    const threatBefore = strip(await ThreatLog.findById(threat._id).lean())
    failAuditOnce()
    const r = await call(threatController.blockIP, { params: { id: threat._id.toString() } })
    expect(r.status).toBe(500)
    expect(strip(await BlockedIP.findOne({ ip: other.sourceIP }).lean())).toEqual(blockedBefore)
    expect(strip(await ThreatLog.findById(threat._id).lean())).toEqual(threatBefore)
  })
}

describe('standalone MongoDB (compensating fallback)', () => {
  let server
  beforeAll(async () => {
    delete process.env.MONGO_USE_TRANSACTIONS
    server = await MongoMemoryServer.create()
    await mongoose.connect(server.getUri())
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await server.stop()
  })
  test('runs on the fallback path', () => {
    expect(shouldUseTransactions()).toBe(false)
  })
  sharedCases('standalone')

  test('retention: delete fails after archiving -> nothing lost, and the retry neither fails nor duplicates', async () => {
    const { applyRetention } = require('../services/retentionService')
    const db = mongoose.connection.db
    await db.collection('archived_threatlogs').deleteMany({})
    const old = await ThreatLog.create({
      sourceIP: '203.0.113.10',
      attackType: 'SSH Brute Force',
      severity: 'HIGH',
      status: 'DETECTED',
      createdAt: new Date(Date.now() - 120 * 86400000),
    })
    const opts = { force: true, dryRun: false, daysThreats: 90, daysSessions: 90 }

    jest.spyOn(ThreatLog, 'deleteMany').mockRejectedValueOnce(new Error('simulated connection reset during delete'))
    await expect(applyRetention(opts)).rejects.toThrow('simulated connection reset')
    expect(await ThreatLog.findById(old._id)).not.toBeNull() // still live
    expect(await db.collection('archived_threatlogs').countDocuments({ _originalId: old._id })).toBe(1) // and archived

    jest.restoreAllMocks()
    const result = await applyRetention(opts) // the next scheduled run
    expect(result.applied).toBe(true)
    expect(await ThreatLog.findById(old._id)).toBeNull()
    expect(await db.collection('archived_threatlogs').countDocuments({ _originalId: old._id })).toBe(1)
    await db.collection('archived_threatlogs').deleteMany({})
  })
})

describe('replica set with MONGO_USE_TRANSACTIONS=true (transactions)', () => {
  let rs
  beforeAll(async () => {
    process.env.MONGO_USE_TRANSACTIONS = 'true'
    rs = await MongoMemoryReplSet.create({ replSet: { count: 1, storageEngine: 'wiredTiger' } })
    await mongoose.connect(rs.getUri())
    // Collections must exist before a transaction writes to them on older servers; harmless on newer ones.
    await Promise.all([User, ThreatLog, BlockedIP, AuditLog].map((m) => m.createCollection().catch(() => {})))
  }, 120000)
  afterAll(async () => {
    process.env.MONGO_USE_TRANSACTIONS = ORIGINAL_TX
    if (ORIGINAL_TX === undefined) delete process.env.MONGO_USE_TRANSACTIONS
    await mongoose.disconnect()
    await rs.stop()
  })
  test('runs on the transaction path (not silently on the fallback)', () => {
    expect(shouldUseTransactions()).toBe(true)
  })
  sharedCases('replica set')
})
