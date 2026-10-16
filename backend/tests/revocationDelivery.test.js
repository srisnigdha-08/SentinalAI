const { EventEmitter } = require('node:events')
const { createRevocationDelivery } = require('../services/revocationDelivery')
function fixture(mode = 'mongo-stream') {
  const connection = new EventEmitter()
  const pending = []
  const queued = [null]
  const stream = {
    closed: false,
    tryNext: jest.fn(() =>
      queued.length
        ? Promise.resolve(queued.shift())
        : new Promise((resolve, reject) => pending.push({ resolve, reject }))
    ),
    close: jest.fn(async () => {
      stream.closed = true
      pending.splice(0).forEach((waiter) => waiter.resolve(null))
    }),
  }
  let clock = 0
  connection.db = {
    admin: () => ({ command: jest.fn().mockResolvedValue({ setName: 'test-replica' }) }),
    watch: jest.fn(() => stream),
  }
  const callbacks = { disconnectSession: jest.fn(), disconnectUser: jest.fn(), disconnectAll: jest.fn() }
  const delivery = createRevocationDelivery({
    mode,
    connection,
    ...callbacks,
    logger: { warn: jest.fn() },
    now: () => clock,
    staleMs: 1000,
  })
  return {
    delivery,
    connection,
    stream,
    callbacks,
    setClock: (value) => {
      clock = value
    },
    push(change) {
      if (pending.length) pending.shift().resolve(change)
      else queued.push(change)
    },
  }
}
test('a lazy stream is not available before a successful server round trip; single mode is explicit', async () => {
  const f = fixture()
  expect(f.delivery.available()).toBe(false)
  await f.delivery.start()
  expect(f.connection.db.watch).toHaveBeenCalled()
  expect(f.stream.tryNext).toHaveBeenCalled()
  expect(f.delivery.available()).toBe(true)
  await f.delivery.stop()
  expect(f.delivery.available()).toBe(false)
  const single = fixture('single')
  await single.delivery.start()
  expect(single.connection.db.watch).not.toHaveBeenCalled()
  expect(single.delivery.status()).toEqual({ mode: 'single', ready: true })
  await single.delivery.stop()
})
test('standalone MongoDB startup fails rather than falling back to local disconnections', async () => {
  const f = fixture()
  f.connection.db.admin = () => ({ command: async () => ({}) })
  await expect(f.delivery.start()).rejects.toThrow(/replica set/)
  expect(f.delivery.available()).toBe(false)
  expect(f.connection.db.watch).not.toHaveBeenCalled()
  await f.delivery.stop()
})
test.each(['revokedAt', 'authVersion', 'expiresAt', 'user'])(
  'shared session security change %s disconnects its family',
  (field) => {
    const f = fixture()
    f.delivery.handle({
      ns: { coll: 'authsessions' },
      operationType: 'update',
      documentKey: { _id: 'family' },
      updateDescription: { updatedFields: { [field]: 'test' } },
    })
    expect(f.callbacks.disconnectSession).toHaveBeenCalledWith('family')
  }
)
test.each(['authVersion', 'password', 'passwordChangedAt', 'role', 'status'])(
  'shared user security change %s disconnects all user sockets',
  (field) => {
    const f = fixture()
    f.delivery.handle({
      ns: { coll: 'users' },
      operationType: 'update',
      documentKey: { _id: 'user' },
      updateDescription: { updatedFields: { [field]: 'test' } },
    })
    expect(f.callbacks.disconnectUser).toHaveBeenCalledWith('user')
  }
)
test('rotation alone and non-security user metadata do not revoke active sockets', () => {
  const f = fixture()
  f.delivery.handle({
    ns: { coll: 'authsessions' },
    operationType: 'update',
    documentKey: { _id: 'family' },
    updateDescription: { updatedFields: { generation: 2, refreshHash: 'opaque-test-hash' } },
  })
  f.delivery.handle({
    ns: { coll: 'users' },
    operationType: 'update',
    documentKey: { _id: 'user' },
    updateDescription: { updatedFields: { lastLogin: new Date() } },
  })
  expect(f.callbacks.disconnectSession).not.toHaveBeenCalled()
  expect(f.callbacks.disconnectUser).not.toHaveBeenCalled()
})
test.each(['delete', 'replace'])('shared security record %s revokes sockets', (operationType) => {
  const f = fixture()
  f.delivery.handle({ ns: { coll: 'users' }, operationType, documentKey: { _id: 'user' } })
  f.delivery.handle({ ns: { coll: 'authsessions' }, operationType, documentKey: { _id: 'family' } })
  expect(f.callbacks.disconnectUser).toHaveBeenCalledWith('user')
  expect(f.callbacks.disconnectSession).toHaveBeenCalledWith('family')
})
test('connection loss fails closed immediately and disconnects local sockets', async () => {
  const f = fixture()
  await f.delivery.start()
  f.connection.emit('disconnected')
  expect(f.delivery.available()).toBe(false)
  expect(f.callbacks.disconnectAll).toHaveBeenCalledTimes(1)
  await f.delivery.stop()
})

test('a disconnected store cannot become healthy from a buffered cursor event', async () => {
  const f = fixture()
  f.connection.readyState = 1
  await f.delivery.start()
  f.connection.readyState = 0
  f.connection.emit('disconnected')
  f.push(null)
  await Promise.resolve()
  expect(f.delivery.available()).toBe(false)
  await f.delivery.stop()
})
test('a stalled cursor fails availability checks and watchdog disconnects before periodic auth polling', async () => {
  jest.useFakeTimers()
  const f = fixture()
  try {
    await f.delivery.start()
    f.setClock(1001)
    expect(f.delivery.available()).toBe(false)
    await jest.advanceTimersByTimeAsync(250)
    expect(f.callbacks.disconnectAll).toHaveBeenCalledTimes(1)
  } finally {
    await f.delivery.stop()
    jest.useRealTimers()
  }
})
test('security collection invalidation disconnects all and cannot report a healthy stream', async () => {
  const f = fixture()
  await f.delivery.start()
  expect(() => f.delivery.handle({ ns: { coll: 'users' }, operationType: 'drop' })).toThrow()
  expect(f.delivery.available()).toBe(false)
  await f.delivery.stop()
})
