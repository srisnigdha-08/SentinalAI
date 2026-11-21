'use strict'
// utils/syncIndexes.js against a disposable in-memory MongoDB: a dry run changes nothing; --apply drops indexes no
// schema declares and creates missing ones, never `_id_`, and never touches documents.
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const { CONNECT_OPTIONS, loadModels, diffAll, applyAll, main } = require('../utils/syncIndexes')

let server
let models
const indexNames = async (name) => (await mongoose.connection.db.collection(name).indexes()).map((i) => i.name).sort()
const collectionNames = async () =>
  (await mongoose.connection.db.listCollections({}, { nameOnly: true }).toArray()).map((c) => c.name).sort()

beforeAll(async () => {
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri('sync_indexes_test'), CONNECT_OPTIONS)
  models = loadModels()
  const db = mongoose.connection.db
  // A leftover index (the audit found threatlogs.severity_1 in a real database) and one document.
  await db.collection('threatlogs').insertOne({ severity: 'HIGH', status: 'DETECTED' })
  await db.collection('threatlogs').createIndex({ severity: 1 })
})

afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})

test('every model is loaded', () => {
  expect(models.map((m) => m.modelName)).toEqual(
    expect.arrayContaining(['ThreatLog', 'AIPrediction', 'DeceptionExperiment'])
  )
})

test('the dry run reports the leftover index and the missing ones, and changes nothing', async () => {
  await new Promise((resolve) => setTimeout(resolve, 200)) // let any (unwanted) model init run before comparing
  const before = await indexNames('threatlogs')
  const collectionsBefore = await collectionNames()
  const diff = await diffAll(models)
  const threat = diff.find((d) => d.model === 'ThreatLog')
  expect(threat.toDrop).toEqual(['severity_1'])
  expect(threat.toCreate).toEqual(
    expect.arrayContaining(['createdAt:-1+_id:-1', 'status:1+createdAt:-1+_id:-1', 'sourceIP:1+createdAt:-1'])
  )
  expect(await indexNames('threatlogs')).toEqual(before)
  // Loading the models and diffing must not create the collections of models that have none yet.
  expect(collectionsBefore).toEqual(['threatlogs'])
  expect(await collectionNames()).toEqual(['threatlogs'])
  expect(diff.find((d) => d.model === 'OutboxEvent')).toMatchObject({ missingCollection: true })
})

test('index options are shown in the plan', async () => {
  const pred = (await diffAll(models)).find((d) => d.model === 'AIPrediction')
  expect(pred).toMatchObject({ missingCollection: true }) // no collection yet: nothing to plan
  const user = loadModels().find((m) => m.modelName === 'User')
  await mongoose.connection.db.createCollection(user.collection.collectionName)
  const diff = (await diffAll([user]))[0]
  expect(diff.toCreate).toEqual(['email:1 (unique)'])
})

test('apply drops the leftover, creates the declared indexes, keeps _id_ and the document', async () => {
  const results = await applyAll(models.filter((m) => m.modelName === 'ThreatLog'))
  expect(results).toEqual([{ model: 'ThreatLog', dropped: ['severity_1'] }])
  const names = await indexNames('threatlogs')
  expect(names).toContain('_id_')
  expect(names).toContain('createdAt_-1__id_-1')
  expect(names).toContain('attackType_1_createdAt_-1__id_-1')
  expect(names).not.toContain('severity_1')
  expect(await mongoose.connection.db.collection('threatlogs').countDocuments()).toBe(1)
  const again = (await diffAll(models)).find((d) => d.model === 'ThreatLog')
  expect(again).toMatchObject({ toDrop: [], toCreate: [] })
})

test('the partial unique flowId index is created and enforced only for documents that have a flowId', async () => {
  const [result] = await applyAll(models.filter((m) => m.modelName === 'AIPrediction'))
  expect(result.error).toBeUndefined()
  const col = mongoose.connection.db.collection('aipredictions')
  await col.insertMany([{ x: 1 }, { x: 2 }]) // no flowId: not indexed, so no conflict
  await col.insertOne({ flowId: 'abcdefgh' })
  await expect(col.insertOne({ flowId: 'abcdefgh' })).rejects.toMatchObject({ code: 11000 })
})

test('--apply without the matching --confirm is refused before connecting', async () => {
  const saved = process.env.MONGO_URI
  process.env.MONGO_URI = 'mongodb://127.0.0.1:1/some-db'
  const spy = jest.spyOn(console, 'error').mockImplementation(() => {})
  try {
    expect(await main(['--apply', '--confirm=other-db'])).toBe(1)
    expect(spy.mock.calls.join(' ')).toMatch(/BLOCKED/)
  } finally {
    spy.mockRestore()
    process.env.MONGO_URI = saved
  }
})
