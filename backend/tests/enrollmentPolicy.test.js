process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-enrollment-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-enrollment-tests'
process.env.HONEYPOT_API_KEY = 'unit-honeypot-secret-for-enrollment-tests'
process.env.SENTINEL_KEY = 'unit-sentinel-secret-for-enrollment-tests'
process.env.CLIENT_URL = 'http://localhost:3000'
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), stopHealthBroadcast: jest.fn() }))
const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const sessions = require('../services/authSessionService')
const { install } = require('./helpers/authMemoryStore')
const { app } = require('../server')
const logger = require('../utils/logger')
let memory
const body = { name: 'Regression Operator', email: 'operator@example.invalid', password: 'UnitOnlyPassword123' }
beforeEach(() => {
  jest.clearAllMocks()
  memory = install(User, Session)
  sessions.setAvailability(null)
  User.create.mockImplementation(async (data) => ({
    ...data,
    toJSON: () => ({ _id: '987654321098765432109876', name: data.name, email: data.email, role: data.role }),
  }))
})
afterEach(() => sessions.setAvailability(null))
async function principal(role = 'admin') {
  memory.users.get(memory.user._id).role = role
  return (await sessions.issue({ ...memory.user, role })).token
}
async function mutation(path, data, token, options = {}) {
  const agent = request.agent(app)
  const csrf = (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
  let action = agent.post('/api/auth/' + path).set('Origin', options.origin || process.env.CLIENT_URL)
  if (!options.missingCsrf) action = action.set('X-CSRF-Token', options.csrf || csrf)
  if (token) action = action.set('Authorization', 'Bearer ' + token)
  return action.send(data)
}
test.each([{}, body, { ...body, role: 'admin' }, { ...body, role: 'analyst' }, { role: { $ne: null } }])(
  'public registration is unconditionally disabled for payload %#',
  async (data) => {
    const response = await mutation('register', data)
    expect(response.status).toBe(403)
    expect(response.body.error).toBe('Public registration is disabled. Contact an administrator for access.')
    expect(User.create).not.toHaveBeenCalled()
    expect(Session.create).not.toHaveBeenCalled()
  }
)
test('even an administrator cannot use the retired public enrollment endpoint', async () => {
  expect((await mutation('register', body, await principal())).status).toBe(403)
  expect(User.create).not.toHaveBeenCalled()
})
test('unauthenticated provisioning is rejected before account lookup', async () => {
  expect((await mutation('provision', body)).status).toBe(401)
  expect(User.create).not.toHaveBeenCalled()
  expect(User.findOne).not.toHaveBeenCalled()
})
test.each(['viewer', 'analyst'])('%s cannot provision or promote through either user endpoint', async (role) => {
  const token = await principal(role)
  expect((await mutation('provision', { ...body, role: 'admin' }, token)).status).toBe(403)
  expect(
    (
      await request(app)
        .put('/api/users/' + memory.user._id)
        .set('Authorization', 'Bearer ' + token)
        .send({ role: 'admin' })
    ).status
  ).toBe(403)
  expect(
    (
      await request(app)
        .post('/api/users')
        .set('Authorization', 'Bearer ' + token)
        .send(body)
    ).status
  ).toBe(403)
  expect(User.create).not.toHaveBeenCalled()
  expect(User.findByIdAndUpdate).not.toHaveBeenCalled()
  expect(memory.users.get(memory.user._id).role).toBe(role)
})
test.each([undefined, 'viewer', 'analyst', 'admin'])(
  'administrator provisions explicit role %s with viewer default',
  async (role) => {
    const token = await principal()
    const issuedSessions = Session.create.mock.calls.length
    const response = await mutation('provision', { ...body, ...(role ? { role } : {}) }, token)
    expect(response.status).toBe(201)
    expect(response.body.data.user.role).toBe(role || 'viewer')
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({ role: role || 'viewer', status: 'active', authVersion: 0 })
    )
    expect(response.body.data).not.toHaveProperty('token')
    expect(response.body.data.user).not.toHaveProperty('password')
    expect(response.headers['set-cookie']).toBeUndefined()
    expect(response.headers['cache-control']).toBe('no-store')
    expect(Session.create.mock.calls).toHaveLength(issuedSessions)
    await expect(sessions.authorize(token)).resolves.toHaveProperty('user.role', 'admin')
  }
)
test.each(['authVersion', 'status', 'passwordChangedAt', 'isAdmin', 'permissions'])(
  'rejects mass assignment of %s',
  async (key) => {
    expect((await mutation('provision', { ...body, [key]: -1 }, await principal())).status).toBe(422)
    expect(User.create).not.toHaveBeenCalled()
  }
)
test.each([null, {}, [], 'root', 'ADMIN'])('rejects invalid role %#', async (role) => {
  expect((await mutation('provision', { ...body, role }, await principal())).status).toBe(422)
  expect(User.create).not.toHaveBeenCalled()
})
test.each([{ password: 'short' }, { name: '' }, { email: 'invalid' }, { department: null }])(
  'validates provisioning payload %#',
  async (changes) => {
    expect((await mutation('provision', { ...body, ...changes }, await principal())).status).toBe(422)
    expect(User.create).not.toHaveBeenCalled()
  }
)
test('normalizes email and handles duplicate email without mutation', async () => {
  const token = await principal()
  User.findOne.mockResolvedValue({ _id: 'existing-user' })
  const response = await mutation('provision', { ...body, email: '  Operator@Example.invalid  ' }, token)
  expect(response.status).toBe(409)
  expect(User.findOne).toHaveBeenCalledWith({ email: body.email })
  expect(User.create).not.toHaveBeenCalled()
})
test('concurrent unique-index conflict is a sanitized 409', async () => {
  User.create.mockRejectedValue(Object.assign(new Error('private database detail'), { code: 11000 }))
  expect((await mutation('provision', body, await principal())).status).toBe(409)
})
test('store outage is sanitized and never logs password/error payload', async () => {
  User.create.mockRejectedValue(new Error('private-probe-' + body.password))
  const response = await mutation('provision', body, await principal())
  expect(response.status).toBe(503)
  expect(JSON.stringify(response.body) + JSON.stringify(logger.error.mock.calls)).not.toContain(body.password)
})
test.each(['missingCsrf', 'csrf', 'origin'])('provisioning retains %s protection', async (variant) => {
  const options = {
    missingCsrf: variant === 'missingCsrf',
    ...(variant === 'csrf' ? { csrf: 'invalid' } : {}),
    ...(variant === 'origin' ? { origin: 'https://foreign.example.invalid' } : {}),
  }
  expect((await mutation('provision', body, await principal(), options)).status).toBe(403)
  expect(User.create).not.toHaveBeenCalled()
})
test.each(['inactive', 'suspended'])('%s administrator cannot provision', async (status) => {
  const token = await principal()
  memory.users.get(memory.user._id).status = status
  expect((await mutation('provision', body, token)).status).toBe(403)
  expect(User.create).not.toHaveBeenCalled()
})
test('revoked administrator session cannot provision', async () => {
  const token = await principal()
  await sessions.logoutAll({ ...memory.user, role: 'admin' })
  expect((await mutation('provision', body, token)).status).toBe(401)
  expect(User.create).not.toHaveBeenCalled()
})
test('session infrastructure outage fails closed before provisioning', async () => {
  const token = await principal()
  sessions.setAvailability(() => false)
  expect((await mutation('provision', body, token)).status).toBe(503)
  expect(User.create).not.toHaveBeenCalled()
})
