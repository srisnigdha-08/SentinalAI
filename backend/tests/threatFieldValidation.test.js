'use strict'
// L3 / L4: threat tags are stored (and bounded); notes and rawPayload are bounded in the schema. In-memory MongoDB.
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ emitThreatUpdated: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const ThreatLog = require('../models/ThreatLog')
require('../models/User')
const { updateThreat } = require('../controllers/threatController')

let server
let threat
const call = async (body) => {
  const res = {
    statusCode: 200,
    status(c) {
      this.statusCode = c
      return this
    },
    json(d) {
      this.body = d
      return this
    },
  }
  let error
  await updateThreat({ params: { id: String(threat._id) }, body, user: { role: 'analyst' } }, res, (e) => (error = e))
  return { res, error }
}

beforeAll(async () => {
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})
beforeEach(async () => {
  await ThreatLog.deleteMany({})
  threat = await ThreatLog.create({ severity: 'HIGH', sourceIP: '203.0.113.9', attackType: 'DDoS' })
})

test('tags sent with PUT are now stored (they were silently dropped before)', async () => {
  const { res } = await call({ tags: ['apt29', ' botnet '] })
  expect(res.statusCode).toBe(200)
  expect((await ThreatLog.findById(threat._id).lean()).tags).toEqual(['apt29', 'botnet'])
})

test('invalid tags are refused with 400 and nothing is stored', async () => {
  for (const tags of ['apt29', [1, 2], [''], ['x'.repeat(41)], Array.from({ length: 21 }, (_, i) => `t${i}`)]) {
    const { res } = await call({ tags })
    expect(res.statusCode).toBe(400)
  }
  expect((await ThreatLog.findById(threat._id).lean()).tags).toBeUndefined()
})

test('the schema bounds notes, rawPayload and tags for every writer, not only the API', async () => {
  const base = { severity: 'LOW', sourceIP: '203.0.113.9', attackType: 'DDoS' }
  await expect(ThreatLog.create({ ...base, notes: 'n'.repeat(1001) })).rejects.toThrow(/notes/)
  await expect(ThreatLog.create({ ...base, rawPayload: 'p'.repeat(65537) })).rejects.toThrow(/rawPayload/)
  await expect(ThreatLog.create({ ...base, tags: Array.from({ length: 21 }, () => 'x') })).rejects.toThrow(/20 tags/)
  await expect(
    ThreatLog.create({ ...base, notes: 'n'.repeat(1000), rawPayload: 'p'.repeat(65536) })
  ).resolves.toBeTruthy()
})
