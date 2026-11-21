'use strict'
/**
 * Start-up retry (config/db.js) and the readiness probe (utils/dbHealth.js). The retry tests mock mongoose.connect;
 * the probe tests use a disposable in-memory MongoDB. Nothing touches a real database.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const logger = require('../utils/logger')
const connectDB = require('../config/db')
const dbHealth = require('../utils/dbHealth')

describe('connectDB start-up retry', () => {
  const saved = { ...process.env }
  let connect
  let sleep
  beforeEach(() => {
    delete process.env.ADMIN_INITIAL_PASSWORD // no admin provisioning in these tests
    process.env.MONGO_URI = 'mongodb://user:secret-password@db.invalid:27017/x'
    connect = jest.spyOn(mongoose, 'connect')
    sleep = jest.spyOn(connectDB, 'sleep').mockResolvedValue()
    jest.clearAllMocks()
  })
  afterEach(() => {
    jest.restoreAllMocks()
    process.env = { ...saved }
  })
  const fail = () =>
    Object.assign(new Error('getaddrinfo ENOTFOUND db.invalid mongodb://user:secret-password@'), {
      name: 'MongoServerSelectionError',
    })
  const ok = { connection: { host: 'h', name: 'n' } }

  test('retries with exponential backoff and succeeds when MongoDB comes up', async () => {
    connect.mockRejectedValueOnce(fail()).mockRejectedValueOnce(fail()).mockResolvedValueOnce(ok)
    await connectDB()
    expect(connect).toHaveBeenCalledTimes(3)
    expect(sleep.mock.calls.map((c) => c[0])).toEqual([1000, 2000])
    expect(logger.warn).toHaveBeenCalledTimes(2)
  })

  test('gives up after MONGO_CONNECT_RETRIES and rethrows, without logging the connection string', async () => {
    process.env.MONGO_CONNECT_RETRIES = '2'
    connect.mockRejectedValue(fail())
    await expect(connectDB()).rejects.toMatchObject({ name: 'MongoServerSelectionError' })
    expect(connect).toHaveBeenCalledTimes(3)
    const logged = JSON.stringify([...logger.warn.mock.calls, ...logger.error.mock.calls])
    expect(logged).not.toMatch(/secret-password|mongodb:\/\//)
  })

  test('MONGO_CONNECT_RETRIES=0 fails on the first error', async () => {
    process.env.MONGO_CONNECT_RETRIES = '0'
    connect.mockRejectedValue(fail())
    await expect(connectDB()).rejects.toThrow()
    expect(connect).toHaveBeenCalledTimes(1)
    expect(sleep).not.toHaveBeenCalled()
  })

  test('backoff is capped at 15 s', () => {
    expect([0, 1, 2, 3, 4, 5, 9].map(connectDB.backoffMs)).toEqual([1000, 2000, 4000, 8000, 15000, 15000, 15000])
  })
})

describe('databaseHealth probe', () => {
  let server
  beforeAll(async () => {
    server = await MongoMemoryServer.create()
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await server.stop()
  })
  beforeEach(() => {
    process.env.HEALTH_DB_PING_CACHE_MS = '0'
    dbHealth.resetCache()
  })
  afterEach(() => jest.restoreAllMocks())

  test('disconnected before connecting', async () => {
    expect(await dbHealth.databaseHealth()).toEqual({ ok: false, state: 'disconnected' })
  })

  test('connected and answering a ping', async () => {
    await mongoose.connect(server.getUri())
    expect(await dbHealth.databaseHealth()).toEqual({ ok: true, state: 'connected' })
  })

  test('connected but the ping hangs: unresponsive after the timeout', async () => {
    process.env.HEALTH_DB_PING_TIMEOUT_MS = '50'
    const admin = mongoose.connection.db.admin()
    jest.spyOn(mongoose.connection.db, 'admin').mockReturnValue({ ...admin, ping: () => new Promise(() => {}) })
    expect(await dbHealth.databaseHealth()).toEqual({ ok: false, state: 'unresponsive' })
    delete process.env.HEALTH_DB_PING_TIMEOUT_MS
  })

  test('concurrent callers share one probe within the cache window', async () => {
    process.env.HEALTH_DB_PING_CACHE_MS = '5000'
    const spy = jest.spyOn(mongoose.connection.db, 'admin')
    await Promise.all(Array.from({ length: 10 }, () => dbHealth.databaseHealth()))
    expect(spy).toHaveBeenCalledTimes(1)
  })
})
