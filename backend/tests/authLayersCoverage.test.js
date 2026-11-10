'use strict'
/**
 * F-08: branch coverage of websocket/auth.js (60 %) and middleware/auth.js (67 %). Unit tests with the session
 * service mocked; a fake Socket.IO server captures the handshake middleware and connection handler so every
 * rejection and re-check path can be driven deterministically (fake timers for the 15 s recheck and expiry).
 */
class MockAuthError extends Error {
  constructor(message = 'Authentication rejected', statusCode = 401) {
    super(message)
    this.name = 'AuthError'
    this.statusCode = statusCode
  }
}
const mockSessions = {
  AuthError: MockAuthError,
  authorize: jest.fn(),
  recordActivity: jest.fn(),
  attachSocketServer: jest.fn(),
  sessionRoom: (id) => 'auth-session:' + id,
  userRoom: (id) => 'auth-user:' + id,
}
jest.mock('../services/authSessionService', () => mockSessions)
jest.mock('../middleware/authCookies', () => ({ clearCookies: jest.fn() }))
const mockLogAudit = jest.fn().mockResolvedValue(null)
jest.mock('../utils/auditLogger', () => ({ logAudit: (...a) => mockLogAudit(...a) }))

const wsAuth = require('../websocket/auth')
const { protect, restrictTo, requirePermission, optionalAuth } = require('../middleware/auth')

const okState = (over = {}) => ({
  user: { _id: 'u1', role: 'analyst', mustChangePassword: false, ...over },
  session: { _id: 's1' },
  claims: { sid: 's1', id: 'u1', exp: Math.floor(Date.now() / 1000) + 900 },
})

beforeEach(() => {
  jest.clearAllMocks()
  mockSessions.authorize.mockResolvedValue(okState())
})

// ---------------------------------------------------------------------------------------------------------------
describe('websocket/auth handshake', () => {
  let handshake
  beforeEach(() => {
    const io = { use: (fn) => (handshake = fn), on: jest.fn() }
    wsAuth.install(io)
    expect(mockSessions.attachSocketServer).toHaveBeenCalledWith(io)
  })
  const run = (socket) => new Promise((resolve) => handshake(socket, (err) => resolve({ err, socket })))

  test('token from handshake.auth', async () => {
    const { err, socket } = await run({ handshake: { headers: {}, auth: { token: 'tok-a' } } })
    expect(err).toBeUndefined()
    expect(mockSessions.authorize).toHaveBeenCalledWith('tok-a')
    expect(socket).toMatchObject({ authToken: 'tok-a', role: 'analyst' })
  })

  test('token from a Bearer Authorization header', async () => {
    await run({ handshake: { headers: { authorization: 'Bearer tok-b' } } })
    expect(mockSessions.authorize).toHaveBeenCalledWith('tok-b')
  })

  test('a non-Bearer header gives no token, and the session service rejects it', async () => {
    mockSessions.authorize.mockRejectedValue(new MockAuthError())
    const { err } = await run({ handshake: { headers: { authorization: 'Basic abc' } } })
    expect(mockSessions.authorize).toHaveBeenCalledWith(null)
    expect(err.message).toBe('Authentication rejected')
  })

  test('session service unavailable (503): reported as such, without the internal message', async () => {
    mockSessions.authorize.mockRejectedValue(new MockAuthError('mongo pool timeout at 10.0.0.5', 503))
    const { err } = await run({ handshake: { headers: {}, auth: { token: 't' } } })
    expect(err.message).toBe('Authentication service unavailable')
  })

  test('password change pending: rejected with that reason', async () => {
    mockSessions.authorize.mockResolvedValue(okState({ mustChangePassword: true }))
    const { err } = await run({ handshake: { headers: {}, auth: { token: 't' } } })
    expect(err.message).toBe('Password change required')
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('websocket/auth connected socket', () => {
  let onConnection
  beforeEach(() => {
    jest.useFakeTimers()
    wsAuth.install({ use: jest.fn(), on: (event, fn) => event === 'connection' && (onConnection = fn) })
  })
  afterEach(() => jest.useRealTimers())

  function fakeSocket({ role = 'analyst', exp } = {}) {
    const handlers = {}
    const socket = {
      connected: true,
      role,
      authToken: 'tok',
      authClaims: { sid: 's1', id: 'u1', exp: exp ?? Math.floor(Date.now() / 1000) + 900 },
      join: jest.fn().mockResolvedValue(undefined),
      disconnect: jest.fn(function () {
        this.connected = false
      }),
      on: (e, fn) => (handlers[e] = fn),
      use: (fn) => (handlers.packet = fn),
      handlers,
    }
    return socket
  }
  const flush = async () => {
    for (let i = 0; i < 5; i++) await Promise.resolve()
  }
  const packet = (socket) =>
    new Promise((resolve) => socket.handlers.packet(['evt'], () => resolve('next')).then(() => resolve('done')))

  test('joins the session and user rooms, then stays connected while the session is valid', async () => {
    const s = fakeSocket()
    onConnection(s)
    await flush()
    expect(s.join).toHaveBeenCalledWith('auth-session:s1')
    expect(s.join).toHaveBeenCalledWith('auth-user:u1')
    expect(s.disconnect).not.toHaveBeenCalled()
  })

  test.each([
    ['role changed', okState({ role: 'viewer' })],
    ['password change now required', okState({ mustChangePassword: true })],
  ])('re-read on connect: %s -> disconnected', async (_label, state) => {
    mockSessions.authorize.mockResolvedValue(state)
    const s = fakeSocket()
    onConnection(s)
    await flush()
    expect(s.disconnect).toHaveBeenCalledWith(true)
  })

  test('re-read on connect fails (revoked): disconnected', async () => {
    mockSessions.authorize.mockRejectedValue(new MockAuthError())
    const s = fakeSocket()
    onConnection(s)
    await flush()
    expect(s.disconnect).toHaveBeenCalledWith(true)
  })

  test('socket closed before the re-read finished: disconnect is enforced', async () => {
    const s = fakeSocket()
    s.join.mockImplementation(async () => {
      s.connected = false
    })
    onConnection(s)
    await flush()
    expect(s.disconnect).toHaveBeenCalled()
  })

  test('access token expiry disconnects the socket', async () => {
    const s = fakeSocket({ exp: Math.floor(Date.now() / 1000) + 2 })
    onConnection(s)
    await flush()
    expect(s.disconnect).not.toHaveBeenCalled()
    jest.advanceTimersByTime(2500)
    expect(s.disconnect).toHaveBeenCalledWith(true)
  })

  test('15 s recheck: a role change or a revoked session disconnects', async () => {
    const s = fakeSocket()
    onConnection(s)
    await flush()
    mockSessions.authorize.mockResolvedValue(okState({ role: 'viewer' }))
    jest.advanceTimersByTime(15000)
    await flush()
    expect(s.disconnect).toHaveBeenCalledWith(true)

    const s2 = fakeSocket()
    mockSessions.authorize.mockResolvedValue(okState())
    onConnection(s2)
    await flush()
    mockSessions.authorize.mockRejectedValue(new MockAuthError())
    jest.advanceTimersByTime(15000)
    await flush()
    expect(s2.disconnect).toHaveBeenCalledWith(true)
  })

  test('disconnect clears the expiry and recheck timers', async () => {
    const s = fakeSocket()
    onConnection(s)
    await flush()
    s.handlers.disconnect()
    mockSessions.authorize.mockRejectedValue(new MockAuthError())
    jest.advanceTimersByTime(60 * 60000)
    await flush()
    expect(s.disconnect).not.toHaveBeenCalled()
  })

  test('packets: authorised at most once per 5 s; a failed check disconnects', async () => {
    const s = fakeSocket()
    onConnection(s)
    await flush()
    const callsAfterConnect = mockSessions.authorize.mock.calls.length
    expect(await packet(s)).toBe('next')
    expect(mockSessions.authorize.mock.calls.length).toBe(callsAfterConnect + 1)
    expect(await packet(s)).toBe('next') // cached
    expect(mockSessions.authorize.mock.calls.length).toBe(callsAfterConnect + 1)

    jest.advanceTimersByTime(5000)
    mockSessions.authorize.mockResolvedValue(okState({ role: 'admin' })) // role changed
    await packet(s)
    expect(s.disconnect).toHaveBeenCalledWith(true)
  })

  test('connection set-up throwing (room join failed): disconnected', async () => {
    const s = fakeSocket()
    s.join.mockRejectedValue(new Error('adapter down'))
    onConnection(s)
    await flush()
    expect(s.disconnect).toHaveBeenCalledWith(true)
  })
})

// ---------------------------------------------------------------------------------------------------------------
describe('middleware/auth', () => {
  const res = () => {
    const r = { statusCode: 200, status: jest.fn((c) => ((r.statusCode = c), r)), json: jest.fn(() => r) }
    return r
  }

  test('protect: no or non-Bearer header -> 401 without calling the session service', async () => {
    for (const authorization of [undefined, 'Basic x', 'bearer lower']) {
      const r = res()
      await protect({ headers: { authorization } }, r, jest.fn())
      expect(r.statusCode).toBe(401)
    }
    expect(mockSessions.authorize).not.toHaveBeenCalled()
  })

  test('protect: valid session sets req.user and records activity', async () => {
    const req = { headers: { authorization: 'Bearer t' }, originalUrl: '/api/threats' }
    const next = jest.fn()
    await protect(req, res(), next)
    expect(next).toHaveBeenCalled()
    expect(req.user.role).toBe('analyst')
    expect(mockSessions.recordActivity).toHaveBeenCalledWith('s1')
  })

  test('protect: password change pending blocks platform routes but allows the lifecycle routes', async () => {
    mockSessions.authorize.mockResolvedValue(okState({ mustChangePassword: true }))
    const blocked = res()
    await protect({ headers: { authorization: 'Bearer t' }, originalUrl: '/api/threats' }, blocked, jest.fn())
    expect(blocked.statusCode).toBe(403)
    expect(blocked.json.mock.calls[0][0].code).toBe('PASSWORD_CHANGE_REQUIRED')

    for (const req of [
      { originalUrl: '/api/auth/me' },
      { originalUrl: '/api/auth/update-password?x=1' },
      { originalUrl: '/mounted/elsewhere', baseUrl: '/api/auth', path: '/logout' },
      { originalUrl: '', baseUrl: '', path: '/logout-all' },
    ]) {
      const next = jest.fn()
      await protect({ headers: { authorization: 'Bearer t' }, ...req }, res(), next)
      expect(next).toHaveBeenCalled()
    }
    const other = res()
    await protect(
      { headers: { authorization: 'Bearer t' }, originalUrl: '/x', baseUrl: '/api/users', path: '/me' },
      other,
      jest.fn()
    )
    expect(other.statusCode).toBe(403)
  })

  test('protect: revoked session -> 401 and cookies cleared; service failure -> 503', async () => {
    const { clearCookies } = require('../middleware/authCookies')
    mockSessions.authorize.mockRejectedValue(new MockAuthError('Session revoked', 401))
    const r1 = res()
    await protect({ headers: { authorization: 'Bearer t' } }, r1, jest.fn())
    expect(r1.statusCode).toBe(401)
    expect(clearCookies).toHaveBeenCalled()

    mockSessions.authorize.mockRejectedValue(new Error('pool exhausted'))
    const r2 = res()
    await protect({ headers: { authorization: 'Bearer t' } }, r2, jest.fn())
    expect(r2.statusCode).toBe(503)
  })

  test('restrictTo: denied role -> 403 and a PERMISSION_DENIED audit; allowed role -> next', () => {
    const r = res()
    restrictTo('admin')({ user: { role: 'viewer' }, originalUrl: '/x', method: 'GET' }, r, jest.fn())
    expect(r.statusCode).toBe(403)
    expect(mockLogAudit).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'PERMISSION_DENIED', status: 'DENIED' })
    )
    const next = jest.fn()
    restrictTo('admin', 'analyst')({ user: { role: 'analyst' } }, res(), next)
    expect(next).toHaveBeenCalled()
  })

  test('restrictTo / requirePermission: an audit write failure never changes the 403', () => {
    mockLogAudit.mockRejectedValueOnce(new Error('audit down')).mockRejectedValueOnce(new Error('audit down'))
    const r1 = res()
    restrictTo('admin')({ user: { role: 'viewer' } }, r1, jest.fn())
    expect(r1.statusCode).toBe(403)
    const r2 = res()
    requirePermission('containment:manage')({ user: { role: 'viewer' } }, r2, jest.fn())
    expect(r2.statusCode).toBe(403)
  })

  test('requirePermission: no user -> 401; missing permission -> 403; granted -> next', () => {
    const r1 = res()
    requirePermission('system:telemetry_full')({}, r1, jest.fn())
    expect(r1.statusCode).toBe(401)
    const r2 = res()
    requirePermission('system:telemetry_full')({ user: { role: 'viewer' } }, r2, jest.fn())
    expect(r2.statusCode).toBe(403)
    const next = jest.fn()
    requirePermission('system:telemetry_full')({ user: { role: 'admin' } }, res(), next)
    expect(next).toHaveBeenCalled()
  })

  test('optionalAuth: no header -> anonymous; valid -> user; rejected -> anonymous; 503 -> 503', async () => {
    const n1 = jest.fn()
    await optionalAuth({ headers: {} }, res(), n1)
    expect(n1).toHaveBeenCalled()

    const req = { headers: { authorization: 'Bearer t' } }
    await optionalAuth(req, res(), jest.fn())
    expect(req.user.role).toBe('analyst')

    mockSessions.authorize.mockRejectedValue(new MockAuthError())
    const req2 = { headers: { authorization: 'Bearer bad' } }
    const n2 = jest.fn()
    await optionalAuth(req2, res(), n2)
    expect(n2).toHaveBeenCalled()
    expect(req2.user).toBeUndefined()

    mockSessions.authorize.mockRejectedValue(new MockAuthError('down', 503))
    const r = res()
    const n3 = jest.fn()
    await optionalAuth({ headers: { authorization: 'Bearer t' } }, r, n3)
    expect(r.statusCode).toBe(503)
    expect(n3).not.toHaveBeenCalled()
  })
})
