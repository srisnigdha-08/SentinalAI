'use strict'
/**
 * The Compose stack connects as the least-privilege sentinel_app user from deployment/mongo-init.js. That role had no
 * rights on containment_audit_events or counters, so durable containment audit writes were refused. This runs the real
 * init script against a disposable MongoDB with authentication on, then drives the real audit code as that user.
 */
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const vm = require('vm')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const { MongoClient } = require('mongodb')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.setTimeout(60000)

const audit = require('../utils/containmentAudit')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')

const DB = 'compose_role_test'
const rnd = () => crypto.randomBytes(18).toString('hex')
const secrets = { root: rnd(), app: rnd(), audit: rnd() }
let mongo
let root
let host

/** Runs the script as mongosh would, recording the role and user commands it issues. */
function commandsFromInitScript() {
  const commands = []
  const siblingDb = {
    createRole: ({ role, privileges, roles }) => commands.push({ createRole: role, privileges, roles }),
    createUser: ({ user, pwd, roles }) => commands.push({ createUser: user, pwd, roles }),
  }
  const source = fs.readFileSync(path.join(__dirname, '..', '..', 'deployment', 'mongo-init.js'), 'utf8')
  vm.runInNewContext(source, {
    db: { getSiblingDB: () => siblingDb },
    print: () => {},
    process: {
      env: { SENTINEL_DB_NAME: DB, SENTINEL_APP_PASSWORD: secrets.app, SENTINEL_AUDIT_PASSWORD: secrets.audit },
    },
  })
  return commands
}

const connectAs = (user, pwd) =>
  MongoClient.connect(`mongodb://${user}:${pwd}@${host}/${DB}?authSource=${DB}`, { serverSelectionTimeoutMS: 5000 })
const denied = async (promise) => expect(promise).rejects.toMatchObject({ code: 13 })

beforeAll(async () => {
  mongo = await MongoMemoryServer.create({
    auth: { enable: true, customRootName: 'root_probe', customRootPwd: secrets.root },
  })
  host = new URL(mongo.getUri()).host
  root = await MongoClient.connect(`mongodb://root_probe:${secrets.root}@${host}/admin`)
  for (const command of commandsFromInitScript()) await root.db(DB).command(command)
  await mongoose.connect(`mongodb://sentinel_app:${secrets.app}@${host}/${DB}?authSource=${DB}`)
  await ContainmentAuditEvent.init()
})
afterAll(async () => {
  await audit.settleContainmentAudit()
  await mongoose.disconnect()
  await root?.close()
  await mongo?.stop()
})

const log = (action, containmentId) => audit.logContainmentAudit({ action, containmentId, target: '198.51.100.7' })

test('the application role stores containment audit events and advances the sequence counter', async () => {
  const id = 'CTN-role-' + Date.now()
  expect(await log('CONTAINMENT_REQUESTED', id).persisted).toBe('stored')
  expect(await log('CONTAINMENT_ACTIVE', id).persisted).toBe('stored')

  const stored = await root
    .db(DB)
    .collection('containment_audit_events')
    .find({ containmentId: id })
    .sort({ seq: 1 })
    .toArray()
  expect(stored.map((e) => e.action)).toEqual(['CONTAINMENT_REQUESTED', 'CONTAINMENT_ACTIVE'])
  expect(stored[1].seq).toBeGreaterThan(stored[0].seq)
  const counter = await root.db(DB).collection('counters').findOne({ _id: 'containment_audit_events' })
  expect(counter.seq).toBeGreaterThanOrEqual(stored[1].seq)
  expect(audit.containmentAuditBacklog().queued).toBe(0)
})

describe('least privilege is preserved', () => {
  let app
  beforeAll(async () => {
    app = await connectAs('sentinel_app', secrets.app)
    await log('CONTAINMENT_REQUESTED', 'CTN-seed').persisted
  })
  afterAll(() => app.close())
  const c = (name) => app.db(DB).collection(name)

  test('containment audit events are insert-only', async () => {
    await denied(c('containment_audit_events').updateOne({ containmentId: 'CTN-seed' }, { $set: { action: 'X' } }))
    await denied(c('containment_audit_events').replaceOne({ containmentId: 'CTN-seed' }, { action: 'X' }))
    await denied(c('containment_audit_events').deleteOne({ containmentId: 'CTN-seed' }))
    await denied(c('containment_audit_events').deleteMany({}))
    await denied(c('containment_audit_events').drop())
  })

  test('the sequence counter can advance but not be removed', async () => {
    await denied(c('counters').deleteOne({ _id: 'containment_audit_events' }))
    await denied(c('counters').deleteMany({}))
    await denied(c('counters').drop())
  })

  test('auditlogs stay insert-only and unlisted collections stay read-only', async () => {
    await c('auditlogs').insertOne({ action: 'PROBE' })
    await denied(c('auditlogs').updateOne({ action: 'PROBE' }, { $set: { action: 'X' } }))
    await denied(c('auditlogs').deleteOne({ action: 'PROBE' }))
    await denied(c('not_a_listed_collection').insertOne({ a: 1 }))
  })

  test('the application user cannot reach other databases or manage users', async () => {
    await denied(app.db('admin').collection('system.users').findOne({}))
    await denied(app.db('another_db').collection('x').insertOne({ a: 1 }))
    await denied(app.db(DB).command({ createUser: 'intruder', pwd: rnd(), roles: [] }))
  })

  test('the audit worker role has no access to containment audit events', async () => {
    const worker = await connectAs('sentinel_audit', secrets.audit)
    try {
      await denied(worker.db(DB).collection('containment_audit_events').findOne({}))
      await denied(worker.db(DB).collection('containment_audit_events').insertOne({ a: 1 }))
    } finally {
      await worker.close()
    }
  })
})
