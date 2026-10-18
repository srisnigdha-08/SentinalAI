process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-session-tests'
process.env.HONEYPOT_API_KEY = 'unit-honeypot-secret-for-session-tests'
process.env.SENTINEL_KEY = 'unit-sentinel-secret-for-session-tests'
process.env.CLIENT_URL = 'http://localhost:3000'
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/AuditLog')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), stopHealthBroadcast: jest.fn() }))
const jwt = require('jsonwebtoken')
const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const { install } = require('./helpers/authMemoryStore')
const auth = require('../services/authSessionService')
const cookies = require('../middleware/authCookies')
const { app } = require('../server')
jest.setTimeout(30000)
let memory
beforeEach(() => {
  jest.clearAllMocks()
  memory = install(User, Session)
  auth.attachSocketServer(null)
  auth.setAvailability(null)
})
afterEach(() => auth.setAvailability(null))
async function csrf(agent) {
  return (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
}
async function mutate(agent, endpoint, body = {}, token) {
  const nonce = await csrf(agent)
  let call = agent
    .post('/api/auth/' + endpoint)
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', nonce)
  if (token) call = call.set('Authorization', 'Bearer ' + token)
  return call.send(body)
}
test('each session/token is unique; lifetimes are 15 minutes and 30 absolute days', async () => {
  const a = await auth.issue(memory.user)
  const b = await auth.issue(memory.user)
  expect(a.refreshToken === b.refreshToken).toBe(false)
  const access = jwt.decode(a.token)
  const refresh = jwt.decode(a.refreshToken)
  expect(access.exp - access.iat).toBe(900)
  expect(refresh.exp - refresh.iat).toBe(2592000)
  expect(access.sid === jwt.decode(b.token).sid).toBe(false)
  expect(access.jti).toHaveLength(64)
  expect(memory.sessions.get(access.sid).refreshHash === a.refreshToken).toBe(false)
})
test('rotation persists a successor, preserves absolute expiry, and replay revokes only its family', async () => {
  const a = await auth.issue(memory.user)
  const independent = await auth.issue(memory.user)
  const rotated = await auth.rotate(a.refreshToken)
  expect(rotated.refreshToken === a.refreshToken).toBe(false)
  expect(jwt.decode(rotated.refreshToken).exp).toBe(jwt.decode(a.refreshToken).exp)
  await expect(auth.rotate(a.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
  await expect(auth.authorize(rotated.token)).rejects.toMatchObject({ statusCode: 401 })
  await expect(auth.authorize(independent.token)).resolves.toHaveProperty('user.role', 'analyst')
})
test('concurrent rotation has one CAS winner; replay revokes the successor', async () => {
  const a = await auth.issue(memory.user)
  const results = await Promise.allSettled([auth.rotate(a.refreshToken), auth.rotate(a.refreshToken)])
  expect(results.filter((result) => result.status === 'fulfilled').length).toBeLessThanOrEqual(1)
  const stored = memory.sessions.get(jwt.decode(a.token).sid)
  expect(stored.generation).toBe(1)
  expect(stored.revokedAt).toBeTruthy()
})
test('random invalid token does not revoke a valid family', async () => {
  const a = await auth.issue(memory.user)
  await expect(auth.rotate(a.refreshToken + 'bad')).rejects.toMatchObject({ statusCode: 401 })
  await expect(auth.authorize(a.token)).resolves.toHaveProperty('user')
})
test.each(['purpose', 'iss', 'aud', 'av', 'sid', 'jti', 'iat', 'id', 'exp', 'role'])(
  'access validates required claim %s',
  async (field) => {
    const a = await auth.issue(memory.user)
    const claims = jwt.decode(a.token)
    delete claims[field]
    const bad = jwt.sign(claims, process.env.JWT_SECRET, { noTimestamp: field === 'iat' })
    await expect(auth.authorize(bad)).rejects.toMatchObject({ statusCode: 401 })
  }
)
test('wrong algorithm, token purpose, signature and expired tokens are rejected', async () => {
  const a = await auth.issue(memory.user)
  const claims = jwt.decode(a.token)
  for (const bad of [
    jwt.sign(claims, process.env.JWT_SECRET, { algorithm: 'HS384' }),
    jwt.sign(claims, 'unrelated-unit-key'),
    jwt.sign({ ...claims, purpose: 'refresh' }, process.env.JWT_SECRET),
    jwt.sign({ ...claims, iss: 'untrusted-issuer' }, process.env.JWT_SECRET),
    jwt.sign({ ...claims, aud: 'another-client' }, process.env.JWT_SECRET),
    a.refreshToken,
    jwt.sign({ ...claims, iat: 1, exp: 2 }, process.env.JWT_SECRET),
  ]) {
    await expect(auth.authorize(bad)).rejects.toMatchObject({ statusCode: 401 })
  }
})
test('logout is idempotent; copied access/refresh are rejected', async () => {
  const a = await auth.issue(memory.user)
  await auth.logout(a.refreshToken)
  await auth.logout(a.refreshToken)
  await expect(auth.authorize(a.token)).rejects.toMatchObject({ statusCode: 401 })
  await expect(auth.rotate(a.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
})
test('logout-all invalidates every session within the issuing second', async () => {
  const a = await auth.issue(memory.user)
  const b = await auth.issue(memory.user)
  await auth.logoutAll(memory.user)
  await expect(auth.authorize(a.token)).rejects.toMatchObject({ statusCode: 401 })
  await expect(auth.rotate(b.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
})
test('version change and account reactivation never resurrect old sessions', async () => {
  const a = await auth.issue(memory.user)
  const user = memory.users.get(memory.user._id)
  user.authVersion++
  user.status = 'inactive'
  await expect(auth.authorize(a.token)).rejects.toMatchObject({ statusCode: 403 })
  user.status = 'active'
  await expect(auth.authorize(a.token)).rejects.toMatchObject({ statusCode: 401 })
})
test('session-store errors fail closed and issue no credentials', async () => {
  Session.create.mockRejectedValueOnce(new Error('storage unavailable'))
  await expect(auth.issue(memory.user)).rejects.toMatchObject({ statusCode: 503 })
  const a = await auth.issue(memory.user)
  Session.findById.mockImplementationOnce(() => ({ select: () => Promise.reject(new Error('storage unavailable')) }))
  await expect(auth.authorize(a.token)).rejects.toMatchObject({ statusCode: 503 })
})
test('logout or password version change racing with a refresh cannot leave an authorized successor', async () => {
  const a = await auth.issue(memory.user)
  const original = Session.findOneAndUpdate.getMockImplementation()
  Session.findOneAndUpdate.mockImplementationOnce(async (...args) => {
    const value = await original(...args)
    await auth.logoutAll(memory.user)
    return value
  })
  await expect(auth.rotate(a.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
})
test('HTTP login returns memory access token and HttpOnly scoped Strict cookie; legacy JWT rejected', async () => {
  const agent = request.agent(app)
  const result = await mutate(agent, 'login', { email: memory.user.email, password: 'CorrectPassword123' })
  expect(result.status).toBe(200)
  expect(result.body.data.refreshToken).toBeUndefined()
  const cookie = result.headers['set-cookie'].find((value) => value.startsWith('sentinel_refresh_v2='))
  expect(cookie).toContain('HttpOnly')
  expect(cookie).toContain('SameSite=Strict')
  expect(cookie).toContain('Path=/api/auth')
  const legacy = jwt.sign({ id: memory.user._id }, process.env.JWT_SECRET)
  expect(
    (
      await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + legacy)
    ).status
  ).toBe(401)
})
test('Origin, missing/incorrect CSRF and non-ASCII CSRF values reject mutations', async () => {
  const agent = request.agent(app)
  const token = await csrf(agent)
  for (const [origin, value] of [
    ['http://attacker.invalid', token],
    [process.env.CLIENT_URL, 'wrong'],
    [process.env.CLIENT_URL, 'é'.repeat(token.length)],
    [undefined, token],
  ]) {
    let call = agent.post('/api/auth/login').set('X-CSRF-Token', value)
    if (origin) call = call.set('Origin', origin)
    expect((await call.send({ email: memory.user.email, password: 'CorrectPassword123' })).status).toBe(403)
  }
})
test('production cookies require Secure; non-loopback insecure development is rejected', () => {
  const old = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  process.env.CLIENT_URL = 'https://sentinel.example.invalid'
  expect(cookies.policy().secure).toBe(true)
  expect(cookies.names().refresh).toMatch(/^__Secure-/)
  process.env.CLIENT_URL = 'http://localhost:3000'
  expect(() => cookies.policy()).toThrow('Production client origin must use HTTPS')
  process.env.NODE_ENV = 'development'
  process.env.CLIENT_URL = 'http://untrusted.invalid'
  expect(() => cookies.policy()).toThrow()
  process.env.NODE_ENV = old
  process.env.CLIENT_URL = 'http://localhost:3000'
})

test('same-second password change revokes prior credentials and issues a valid replacement', async () => {
  jest
    .useFakeTimers({ doNotFake: ['nextTick', 'setImmediate', 'setTimeout'] })
    .setSystemTime(new Date('2026-10-14T09:00:00.500Z'))
  try {
    const issued = await auth.issue(memory.user)
    const agent = request.agent(app)
    const nonce = await csrf(agent)
    const result = await agent
      .put('/api/auth/update-password')
      .set('Origin', process.env.CLIENT_URL)
      .set('X-CSRF-Token', nonce)
      .set('Authorization', 'Bearer ' + issued.token)
      .send({ currentPassword: 'CorrectPassword123', newPassword: 'New-Password-123' })
    expect(result.status).toBe(200)
    expect(jwt.decode(result.body.data.token).iat).toBe(jwt.decode(issued.token).iat)
    await expect(auth.authorize(issued.token)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.rotate(issued.refreshToken)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.authorize(result.body.data.token)).resolves.toHaveProperty('user.authVersion', 1)
  } finally {
    jest.useRealTimers()
  }
})
test('failed logout persistence cannot report success or issue new credentials', async () => {
  const agent = request.agent(app)
  const login = await mutate(agent, 'login', { email: memory.user.email, password: 'CorrectPassword123' })
  expect(login.status).toBe(200)
  Session.updateOne.mockRejectedValueOnce(new Error('Unavailable'))
  const result = await mutate(agent, 'logout')
  expect(result.status).toBe(503)
  expect(result.body.data).toBeUndefined()
})
test.each(['gen', 'purpose', 'iss', 'aud', 'jti', 'exp', 'iat'])(
  'refresh validates required claim %s without revoking a valid session',
  async (field) => {
    const issued = await auth.issue(memory.user)
    const payload = jwt.decode(issued.refreshToken)
    delete payload[field]
    const invalid = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { noTimestamp: field === 'iat' })
    await expect(auth.rotate(invalid)).rejects.toMatchObject({ statusCode: 401 })
    await expect(auth.authorize(issued.token)).resolves.toHaveProperty('user')
  }
)

test('HTTP logout-all revokes independent families and clears the refresh cookie', async () => {
  const agent = request.agent(app)
  const login = await mutate(agent, 'login', { email: memory.user.email, password: 'CorrectPassword123' })
  const other = await auth.issue(memory.user)
  const result = await mutate(agent, 'logout-all', {}, login.body.data.token)
  expect(result.status).toBe(200)
  expect(result.headers['set-cookie'].some((value) => value.includes('Expires=Thu, 01 Jan 1970'))).toBe(true)
  await expect(auth.authorize(other.token)).rejects.toMatchObject({ statusCode: 401 })
})
test('invalid stored session expiry fails closed', async () => {
  const issued = await auth.issue(memory.user)
  memory.sessions.get(jwt.decode(issued.token).sid).expiresAt = 'invalid'
  await expect(auth.authorize(issued.token)).rejects.toMatchObject({ statusCode: 401 })
})
test('account version changing during issuance prevents credentials being returned', async () => {
  const original = Session.create.getMockImplementation()
  Session.create.mockImplementationOnce(async (value) => {
    const result = await original(value)
    memory.users.get(memory.user._id).authVersion++
    return result
  })
  await expect(auth.issue(memory.user)).rejects.toMatchObject({ statusCode: 401 })
})

test('credentialed CORS allows configured origin and CSRF bootstrap rejects cross-site origin', async () => {
  const accepted = await request(app).get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)
  expect(accepted.status).toBe(200)
  expect(accepted.headers['access-control-allow-origin']).toBe(process.env.CLIENT_URL)
  expect(accepted.headers['access-control-allow-credentials']).toBe('true')
  const rejected = await request(app).get('/api/auth/csrf').set('Origin', 'https://attacker.invalid')
  expect(rejected.status).toBe(403)
  expect(rejected.headers['access-control-allow-origin']).toBeUndefined()
  expect((await request(app).get('/api/auth/csrf').set('Sec-Fetch-Site', 'cross-site')).status).toBe(403)
})

test('required shared revocation delivery outage rejects existing tokens and issues no credentials', async () => {
  const issued = await auth.issue(memory.user)
  auth.setAvailability(() => false)
  await expect(auth.authorize(issued.token)).rejects.toMatchObject({ statusCode: 503 })
  await expect(auth.rotate(issued.refreshToken)).rejects.toMatchObject({ statusCode: 503 })
  const created = Session.create.mock.calls.length
  await expect(auth.issue(memory.user)).rejects.toMatchObject({ statusCode: 503 })
  expect(Session.create).toHaveBeenCalledTimes(created)
  await expect(auth.logout(issued.refreshToken)).rejects.toMatchObject({ statusCode: 503 })
  auth.setAvailability(null)
  await expect(auth.authorize(issued.token)).resolves.toHaveProperty('user')
})
