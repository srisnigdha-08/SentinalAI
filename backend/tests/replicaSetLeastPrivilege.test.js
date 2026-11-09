'use strict'
/**
 * The replica-set deployment connects as the least-privilege sentinel_app user. This runs the real init script against
 * a disposable, authenticated single-node replica set and drives the real revocation and transaction code as that
 * user, so a missing or excessive privilege fails here. Nothing touches a real database.
 */
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const vm = require('vm')
const mongoose = require('mongoose')
const { MongoMemoryReplSet } = require('mongodb-memory-server')
const { MongoClient, ObjectId } = require('mongodb')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.setTimeout(120000)

const { createRevocationDelivery } = require('../services/revocationDelivery')
const { runWithTransactionOrFallback, shouldUseTransactions } = require('../utils/transactionHelper')
const { logAudit } = require('../utils/auditLogger')
const User = require('../models/User')

const DB = 'replica_role_test'
const rnd = () => crypto.randomBytes(18).toString('hex')
const secrets = { root: rnd(), app: rnd(), audit: rnd(), limited: rnd() }
let rs
let root
let app
let host

function commandsFromInitScript() {
  const commands = []
  const siblingDb = {
    createRole: ({ role, privileges, roles }) => commands.push({ createRole: role, privileges, roles }),
    createUser: ({ user, pwd, roles }) => commands.push({ createUser: user, pwd, roles }),
  }
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', '..', 'deployment', 'mongo-init.js'), 'utf8'), {
    db: { getSiblingDB: () => siblingDb },
    print: () => {},
    process: {
      env: { SENTINEL_DB_NAME: DB, SENTINEL_APP_PASSWORD: secrets.app, SENTINEL_AUDIT_PASSWORD: secrets.audit },
    },
  })
  return commands
}

const uriFor = (user, pwd, authDb = DB, db = DB) =>
  `mongodb://${user}:${pwd}@${host}/${db}?authSource=${authDb}&replicaSet=rs0`
const denied = (promise) => expect(promise).rejects.toMatchObject({ code: 13 })
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
async function waitFor(check, ms = 8000) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (check()) return true
    await sleep(50)
  }
  return false
}
const person = (tag) => ({
  name: 'Replica Test',
  email: `${tag}-${rnd()}@sentinel.test`,
  password: 'Replica-Test-Password-1',
  role: 'viewer',
  department: 'SOC',
  status: 'active',
})
const mustNotFallBack = () => {
  throw new Error('fell back to the non-transactional path')
}

beforeAll(async () => {
  process.env.MONGO_USE_TRANSACTIONS = 'true'
  rs = await MongoMemoryReplSet.create({
    replSet: {
      name: 'rs0',
      count: 1,
      storageEngine: 'wiredTiger',
      auth: { enable: true, customRootName: 'root_probe', customRootPwd: secrets.root },
    },
  })
  host = new URL(rs.getUri()).host
  root = await MongoClient.connect(uriFor('root_probe', secrets.root, 'admin', 'admin'))
  for (const command of commandsFromInitScript()) await root.db(DB).command(command)
  await mongoose.connect(uriFor('sentinel_app', secrets.app))
  await User.init()
  await mongoose.connection.db.createCollection('auditlogs').catch(() => {})
  app = await MongoClient.connect(uriFor('sentinel_app', secrets.app))
})

afterAll(async () => {
  delete process.env.MONGO_USE_TRANSACTIONS
  await app?.close()
  await mongoose.disconnect()
  await root?.close()
  await rs?.stop()
})

describe('privileges', () => {
  test('the only addition to the database-wide privilege is changeStream', () => {
    const role = commandsFromInitScript().find((c) => c.createRole === 'sentinel_app_role')
    const wide = role.privileges.filter((p) => p.resource.collection === '')
    expect(wide).toHaveLength(1)
    expect([...wide[0].actions].sort()).toEqual(
      ['changeStream', 'createCollection', 'createIndex', 'find', 'listCollections', 'listIndexes'].sort()
    )
    expect(role.roles).toEqual([])
  })

  test('the application cannot watch the cluster or another database', async () => {
    await denied(app.watch().tryNext())
    await denied(app.db('admin').watch().tryNext())
    await denied(app.db('another_database').watch().tryNext())
  })

  test('the application cannot administer the replica set', async () => {
    const admin = app.db('admin')
    await denied(admin.command({ replSetGetStatus: 1 }))
    await denied(admin.command({ replSetGetConfig: 1 }))
    await denied(admin.command({ replSetStepDown: 1 }))
    await denied(admin.command({ replSetReconfig: { _id: 'rs0', version: 2, members: [] } }))
    await denied(app.db('local').collection('oplog.rs').findOne())
  })

  test('existing engine-level restrictions still hold on a replica set', async () => {
    const database = app.db(DB)
    await database.collection('auditlogs').insertOne({ action: 'probe' })
    await denied(database.collection('auditlogs').updateOne({}, { $set: { x: 1 } }))
    await denied(database.collection('auditlogs').deleteOne({}))
    await denied(database.collection('containment_audit_events').updateOne({}, { $set: { x: 1 } }))
    await denied(database.collection('containment_audit_events').deleteOne({}))
    await denied(database.collection('containment_audit_events').drop())
    await denied(database.collection('counters').deleteOne({}))
    await denied(database.collection('not_a_listed_collection').insertOne({ a: 1 }))
    await denied(database.command({ createUser: 'intruder', pwd: rnd(), roles: [] }))
    await denied(app.db('admin').collection('system.users').findOne())
  })
})

describe('session revocation through the real change stream', () => {
  const start = (connection, calls) =>
    createRevocationDelivery({ mode: 'mongo-stream', connection, ...calls, logger: { warn: jest.fn() } })
  const callbacks = () => ({ disconnectSession: jest.fn(), disconnectUser: jest.fn(), disconnectAll: jest.fn() })

  test('a change made outside this process disconnects the session and the user', async () => {
    const sessionId = new ObjectId()
    const userId = new ObjectId()
    await root.db(DB).collection('authsessions').insertOne({ _id: sessionId, revokedAt: null })
    await root
      .db(DB)
      .collection('users')
      .insertOne({ _id: userId, authVersion: 0, email: `${rnd()}@sentinel.test` })
    const calls = callbacks()
    const delivery = start(mongoose.connection, calls)
    await delivery.start()
    expect(delivery.available()).toBe(true)

    await root
      .db(DB)
      .collection('authsessions')
      .updateOne({ _id: sessionId }, { $set: { revokedAt: new Date() } })
    expect(await waitFor(() => calls.disconnectSession.mock.calls.length > 0)).toBe(true)
    expect(String(calls.disconnectSession.mock.calls[0][0])).toBe(String(sessionId))

    await root
      .db(DB)
      .collection('users')
      .updateOne({ _id: userId }, { $inc: { authVersion: 1 } })
    expect(await waitFor(() => calls.disconnectUser.mock.calls.length > 0)).toBe(true)
    expect(String(calls.disconnectUser.mock.calls[0][0])).toBe(String(userId))
    await delivery.stop()
  })

  test('without the changeStream privilege startup fails closed instead of falling back', async () => {
    await root.db(DB).command({
      createRole: 'limited_role',
      privileges: [{ resource: { db: DB, collection: '' }, actions: ['find'] }],
      roles: [],
    })
    await root.db(DB).command({ createUser: 'limited', pwd: secrets.limited, roles: ['limited_role'] })
    const connection = await mongoose.createConnection(uriFor('limited', secrets.limited)).asPromise()
    const delivery = start(connection, callbacks())
    await expect(delivery.start()).rejects.toMatchObject({ code: 13 })
    expect(delivery.available()).toBe(false)
    await connection.close()
  })
})

describe('multi-document transactions as the application user', () => {
  const audits = (email) => root.db(DB).collection('auditlogs').countDocuments({ 'target.identifier': email })
  const stored = (email) => root.db(DB).collection('users').countDocuments({ email })
  const auditFor = (email, session) =>
    logAudit({ action: 'USER_CREATED', target: { identifier: email, type: 'User' }, status: 'SUCCESS', session })

  test('the transactional path is the one in use', () => {
    expect(shouldUseTransactions()).toBe(true)
  })

  test('commit stores both documents', async () => {
    const data = person('commit')
    await runWithTransactionOrFallback({
      transactionFn: async (session) => {
        await User.create([data], { session })
        await auditFor(data.email, session)
      },
      fallbackFn: mustNotFallBack,
    })
    expect(await stored(data.email)).toBe(1)
    expect(await audits(data.email)).toBe(1)
  })

  test('a thrown error aborts both documents, and neither is visible before commit', async () => {
    const data = person('abort')
    await expect(
      runWithTransactionOrFallback({
        transactionFn: async (session) => {
          await User.create([data], { session })
          await auditFor(data.email, session)
          expect(await stored(data.email)).toBe(0)
          throw new Error('abort requested')
        },
        fallbackFn: mustNotFallBack,
      })
    ).rejects.toThrow('abort requested')
    expect(await stored(data.email)).toBe(0)
    expect(await audits(data.email)).toBe(0)
  })

  test('an engine-level audit refusal rolls back the earlier write', async () => {
    const data = person('rollback')
    const privilege = [{ resource: { db: DB, collection: 'auditlogs' }, actions: ['insert'] }]
    await root.db(DB).command({ revokePrivilegesFromRole: 'sentinel_app_role', privileges: privilege })
    try {
      await expect(
        runWithTransactionOrFallback({
          transactionFn: async (session) => {
            await User.create([data], { session })
            await auditFor(data.email, session)
          },
          fallbackFn: mustNotFallBack,
        })
      ).rejects.toMatchObject({ code: 13 })
      expect(await stored(data.email)).toBe(0)
    } finally {
      await root.db(DB).command({ grantPrivilegesToRole: 'sentinel_app_role', privileges: privilege })
    }
  })

  test('audit logs stay append-only inside a transaction', async () => {
    const session = app.startSession()
    try {
      await expect(
        session.withTransaction(() =>
          app
            .db(DB)
            .collection('auditlogs')
            .updateOne({}, { $set: { x: 1 } }, { session })
        )
      ).rejects.toMatchObject({ code: 13 })
    } finally {
      await session.endSession()
    }
  })
})
