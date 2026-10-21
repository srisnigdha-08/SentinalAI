'use strict'
/**
 * MongoOutboxStore (OUTBOX_STORE=mongo) and SecurityEventBus.recordDelivered: live events pushed over
 * Socket.IO are recorded durably as DELIVERED; failures and redrive work against a real database.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const { SecurityEventBus, MongoOutboxStore, storeFromEnv } = require('../utils/securityEventBus')
const OutboxEvent = require('../models/OutboxEvent')

describe('MongoDB outbox', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
    await OutboxEvent.syncIndexes()
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })
  beforeEach(() => OutboxEvent.deleteMany({}))

  const flush = () => new Promise((resolve) => setTimeout(resolve, 200))

  test('recordDelivered stores a DELIVERED event with an expiry, once per event id', async () => {
    const bus = new SecurityEventBus({ outboxStore: new MongoOutboxStore() })
    const res = bus.recordDelivered({ eventType: 'IP_BLOCKED', payload: { ip: '198.51.100.7', blockedBy: 'AI' } })
    expect(res.status).toBe('published')
    await flush()
    const rec = await OutboxEvent.findOne({ eventId: res.eventId }).lean()
    expect(rec).toMatchObject({ eventType: 'IP_BLOCKED', status: 'DELIVERED' })
    expect(rec.expiresAt.getTime()).toBeGreaterThan(Date.now())
    expect(bus.getHistory({ eventType: 'IP_BLOCKED' })).toHaveLength(1)
  })

  test('invalid event types are not recorded and never throw', () => {
    const bus = new SecurityEventBus({ outboxStore: new MongoOutboxStore() })
    expect(bus.recordDelivered({ eventType: 'NOT_A_TYPE', payload: {} }).status).toBe('not_recorded')
  })

  test('failures move to FAILED after 3 attempts and can be redriven', async () => {
    const store = new MongoOutboxStore()
    const envelope = new SecurityEventBus().createEnvelope({ eventType: 'ALERT_CREATED', payload: { id: 'a1' } })
    await store.persistEnvelope(envelope)
    for (let i = 0; i < 3; i++) await store.markFailed(envelope.eventId, new Error('socket down'))
    expect((await store.getFailedEvents()).map((f) => f.envelope.eventId)).toEqual([envelope.eventId])
    expect(await store.redriveFailedEvents()).toBe(1)
    expect((await store.getPendingEvents()).map((e) => e.eventId)).toEqual([envelope.eventId])
    expect(await store.getOutboxStats()).toMatchObject({ pending: 1, failed: 0 })
  })

  test('OUTBOX_STORE selects the store', () => {
    expect(storeFromEnv({ OUTBOX_STORE: 'mongo' })).toBeInstanceOf(MongoOutboxStore)
    expect(storeFromEnv({})).toBeNull()
  })
})
