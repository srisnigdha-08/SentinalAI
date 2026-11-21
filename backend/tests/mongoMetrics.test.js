'use strict'
// M9: MongoDB command and pool metrics (utils/mongoMetrics.js) on a disposable in-memory MongoDB.
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const logger = require('../utils/logger')
const metrics = require('../utils/metrics')
const mongoMetrics = require('../utils/mongoMetrics')

let server
let client
const value = (name, labels = '') => {
  const line = metrics
    .render()
    .split('\n')
    .find((l) => l.startsWith(`${name}${labels ? `{${labels}}` : ''} `))
  return line ? Number(line.split(' ').pop()) : undefined
}

beforeAll(async () => {
  metrics.reset()
  mongoMetrics._reset()
  server = await MongoMemoryServer.create()
  await mongoose.connect(server.getUri('metrics_test'), { monitorCommands: true })
  client = mongoose.connection.getClient()
  expect(mongoMetrics.instrument(client)).toBe(true)
  expect(mongoMetrics.instrument(client)).toBe(false) // once per client
})
afterAll(async () => {
  await mongoose.disconnect()
  await server.stop()
})
afterEach(() => {
  delete process.env.MONGO_SLOW_MS
  jest.clearAllMocks()
})

test('operations are counted and timed by command type; heartbeats are not', async () => {
  const col = mongoose.connection.db.collection('things')
  await col.insertOne({ ip: '203.0.113.5', secret: 'do-not-log' })
  await col.find({ ip: '203.0.113.5' }).toArray()
  await col.aggregate([{ $match: {} }]).toArray()
  await mongoose.connection.db.admin().ping()
  expect(value('sentinel_mongo_commands_total', 'command="insert"')).toBeGreaterThanOrEqual(1)
  expect(value('sentinel_mongo_commands_total', 'command="find"')).toBeGreaterThanOrEqual(1)
  expect(value('sentinel_mongo_commands_total', 'command="aggregate"')).toBeGreaterThanOrEqual(1)
  expect(value('sentinel_mongo_command_duration_seconds_sum', 'command="find"')).toBeGreaterThanOrEqual(0)
  expect(metrics.render()).not.toMatch(/command="(ping|hello|isMaster)"/)
})

test('failures are counted', async () => {
  await expect(mongoose.connection.db.command({ find: 'things', filter: { $bogus: 1 } })).rejects.toThrow()
  expect(value('sentinel_mongo_command_failures_total', 'command="find"')).toBeGreaterThanOrEqual(1)
})

test('slow operations are counted and logged with type and collection only, never values', async () => {
  process.env.MONGO_SLOW_MS = '1'
  const col = mongoose.connection.db.collection('things')
  await col.find({ $where: 'sleep(20) || true', ip: '203.0.113.5' }).toArray()
  expect(value('sentinel_mongo_slow_commands_total', 'command="find"')).toBeGreaterThanOrEqual(1)
  const logged = logger.warn.mock.calls.map((c) => c[0]).join('\n')
  expect(logged).toMatch(/slow find on things: \d+ ms/)
  expect(logged).not.toMatch(/203\.0\.113|do-not-log|sleep/)
})

test('pool gauges track connections in use and return to zero when idle', async () => {
  const col = mongoose.connection.db.collection('things')
  await Promise.all(Array.from({ length: 5 }, () => col.findOne({})))
  expect(value('sentinel_mongo_pool_connections_open')).toBeGreaterThanOrEqual(1)
  expect(value('sentinel_mongo_pool_connections_in_use')).toBe(0)
  expect(value('sentinel_mongo_pool_connections_waiting')).toBe(0)
})
