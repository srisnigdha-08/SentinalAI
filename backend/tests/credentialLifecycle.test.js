'use strict'

process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-credential-lifecycle'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-credential-lifecycle'
process.env.HONEYPOT_API_KEY = 'unit-honeypot-secret-for-credential-lifecycle'
process.env.SENTINEL_KEY = 'unit-sentinel-secret-for-credential-lifecycle'
process.env.CLIENT_URL = 'http://localhost:3000'

jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), stopHealthBroadcast: jest.fn() }))

const http = require('http')
const { Server } = require('socket.io')
const ioClient = require('../../frontend/node_modules/socket.io-client')
const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const { install } = require('./helpers/authMemoryStore')
const auth = require('../services/authSessionService')
const { app } = require('../server')

let memory

function makeUser(data) {
  const doc = {
    _id: data._id || '507f1f77bcf86cd799439011',
    name: data.name || 'Test User',
    email: data.email || 'test@example.invalid',
    password: data.password || 'CorrectPassword123',
    role: data.role || 'analyst',
    status: data.status || 'active',
    authVersion: data.authVersion ?? 0,
    ...(data.mustChangePassword !== undefined ? { mustChangePassword: data.mustChangePassword } : {}),
  }
  doc.toJSON = () => {
    const copy = { ...doc }
    delete copy.password
    return copy
  }
  doc.comparePassword = async (pwd) => pwd === (data.password || 'CorrectPassword123')
  doc.save = async () => {
    memory.users.set(doc._id, doc)
    return doc
  }
  memory.users.set(doc._id, doc)
  return doc
}

beforeEach(() => {
  jest.clearAllMocks()
  memory = install(User, Session)
  auth.attachSocketServer(null)
  auth.setAvailability(null)
})

afterEach(() => {
  auth.setAvailability(null)
})

async function csrf(agent) {
  const res = await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)
  return res.body.data.csrfToken
}

async function mutate(agent, endpoint, body = {}, token = null, method = 'post') {
  const nonce = await csrf(agent)
  let call = agent[method]('/api/auth/' + endpoint)
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', nonce)
  if (token) call = call.set('Authorization', 'Bearer ' + token)
  return call.send(body)
}

describe('Credential Lifecycle Hardening — Unit & Security Invariants', () => {
  test('1. User schema definition defaults mustChangePassword to false', () => {
    const UserReal = jest.requireActual('../models/User')
    const path = UserReal.schema.path('mustChangePassword')
    expect(path).toBeDefined()
    expect(path.defaultValue).toBe(false)
  })

  test('2. Newly provisioned users receive mustChangePassword: true', async () => {
    const adminUser = makeUser({
      _id: '507f1f77bcf86cd799439011',
      name: 'Admin Tester',
      email: 'admin@example.invalid',
      role: 'admin',
      status: 'active',
      authVersion: 0,
      mustChangePassword: false,
    })
    const issued = await auth.issue(adminUser)

    const agent = request.agent(app)
    const nonce = await csrf(agent)
    const res = await agent
      .post('/api/auth/provision')
      .set('Origin', process.env.CLIENT_URL)
      .set('X-CSRF-Token', nonce)
      .set('Authorization', 'Bearer ' + issued.token)
      .send({
        name: 'New Operator',
        email: 'operator@example.invalid',
        password: 'TemporaryPassword123',
        role: 'analyst',
        department: 'SOC',
      })

    expect(res.status).toBe(201)
    expect(res.body.success).toBe(true)
    expect(res.body.data.user.mustChangePassword).toBe(true)
    expect(res.body.data.user.password).toBeUndefined()
  })

  test('3. Default administrator creation path does not force mustChangePassword', async () => {
    const UserReal = jest.requireActual('../models/User')
    const adminDoc = new UserReal({
      name: 'System Admin',
      email: 'sysadmin@sentinel.io',
      password: 'StrongAdminPassword123!',
      role: 'admin',
      status: 'active',
    })
    expect(adminDoc.mustChangePassword).toBe(false)
  })

  test('4. Login returns correct non-sensitive credential-lifecycle state', async () => {
    makeUser({
      _id: '507f1f77bcf86cd799439022',
      name: 'Restricted User',
      email: 'restricted@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })

    const agent = request.agent(app)
    const res = await mutate(agent, 'login', {
      email: 'restricted@example.invalid',
      password: 'CorrectPassword123',
    })

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.user.mustChangePassword).toBe(true)
    expect(res.body.data.user.password).toBeUndefined()
  })

  test('5. Restricted user cannot access protected SOC endpoints (returns 403 PASSWORD_CHANGE_REQUIRED)', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439033',
      name: 'Restricted Operator',
      email: 'restricted-soc@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const res = await request(app)
      .get('/api/threats')
      .set('Authorization', 'Bearer ' + issued.token)

    expect(res.status).toBe(403)
    expect(res.body.success).toBe(false)
    expect(res.body.code).toBe('PASSWORD_CHANGE_REQUIRED')
    expect(res.body.error).toMatch(/Password change required/i)
  })

  test('6. Restricted user can access permitted lifecycle endpoints (/api/auth/me, /api/auth/logout, /api/auth/logout-all)', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439044',
      name: 'Restricted Lifecycle User',
      email: 'lifecycle@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    // /api/auth/me
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer ' + issued.token)
    expect(meRes.status).toBe(200)
    expect(meRes.body.data.user.mustChangePassword).toBe(true)

    // /api/auth/logout-all
    const agent = request.agent(app)
    const logoutAllRes = await mutate(agent, 'logout-all', {}, issued.token)
    expect(logoutAllRes.status).toBe(200)
  })

  test('7. Incorrect current password rejects update and leaves mustChangePassword unchanged', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439055',
      name: 'Wrong Pwd User',
      email: 'wrongpwd@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const agent = request.agent(app)
    const res = await mutate(
      agent,
      'update-password',
      {
        currentPassword: 'IncorrectPassword!',
        newPassword: 'BrandNewPassword123!',
      },
      issued.token,
      'put'
    )

    expect(res.status).toBe(401)
    expect(memory.users.get(restrictedUser._id).mustChangePassword).toBe(true)
  })

  test('8. Invalid new password leaves mustChangePassword unchanged', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439066',
      name: 'Short Pwd User',
      email: 'shortpwd@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const agent = request.agent(app)
    const res = await mutate(
      agent,
      'update-password',
      {
        currentPassword: 'CorrectPassword123',
        newPassword: 'short', // less than 8 chars
      },
      issued.token,
      'put'
    )

    expect(res.status).toBe(400)
    expect(memory.users.get(restrictedUser._id).mustChangePassword).toBe(true)
  })

  test('9. Successful password change clears mustChangePassword and increments authVersion', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439077',
      name: 'Success User',
      email: 'success@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const agent = request.agent(app)
    const res = await mutate(
      agent,
      'update-password',
      {
        currentPassword: 'CorrectPassword123',
        newPassword: 'BrandNewPassword123!',
      },
      issued.token,
      'put'
    )

    expect(res.status).toBe(200)
    expect(res.body.success).toBe(true)
    expect(res.body.data.user.mustChangePassword).toBe(false)
    expect(memory.users.get(restrictedUser._id).mustChangePassword).toBe(false)
    expect(memory.users.get(restrictedUser._id).authVersion).toBe(1)
  })

  test('10. Previous access token cannot be used after password change', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439088',
      name: 'Revoke User',
      email: 'revoke@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const agent = request.agent(app)
    const updateRes = await mutate(
      agent,
      'update-password',
      {
        currentPassword: 'CorrectPassword123',
        newPassword: 'BrandNewPassword123!',
      },
      issued.token,
      'put'
    )
    expect(updateRes.status).toBe(200)

    // Old token has authVersion: 0, but user now has authVersion: 1
    const oldAccessRes = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer ' + issued.token)
    expect(oldAccessRes.status).toBe(401)
  })

  test('11. Concurrent password-change attempts cannot both succeed against the same account version', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd799439099',
      name: 'CAS User',
      email: 'cas@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const agent1 = request.agent(app)
    const agent2 = request.agent(app)

    const req1 = mutate(
      agent1,
      'update-password',
      {
        currentPassword: 'CorrectPassword123',
        newPassword: 'PasswordOne12345!',
      },
      issued.token,
      'put'
    )

    const req2 = mutate(
      agent2,
      'update-password',
      {
        currentPassword: 'CorrectPassword123',
        newPassword: 'PasswordTwo12345!',
      },
      issued.token,
      'put'
    )

    const [res1, res2] = await Promise.all([req1, req2])
    const statuses = [res1.status, res2.status].sort()
    // Exactly one should succeed with 200, the other should fail with 401
    expect(statuses).toEqual([200, 401])
  })

  test('12. Refresh preserves mustChangePassword restriction on user session', async () => {
    makeUser({
      _id: '507f1f77bcf86cd7994390aa',
      name: 'Refresh Restrict User',
      email: 'refresh@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })

    const agent = request.agent(app)
    await mutate(agent, 'login', {
      email: 'refresh@example.invalid',
      password: 'CorrectPassword123',
    })

    const refreshRes = await mutate(agent, 'refresh-token', {})
    expect(refreshRes.status).toBe(200)
    expect(refreshRes.body.data.user.mustChangePassword).toBe(true)

    // Attempting to access protected SOC endpoint with refreshed token is blocked
    const threatsRes = await request(app)
      .get('/api/threats')
      .set('Authorization', 'Bearer ' + refreshRes.body.data.token)
    expect(threatsRes.status).toBe(403)
    expect(threatsRes.body.code).toBe('PASSWORD_CHANGE_REQUIRED')
  })

  test('13. Restricted users cannot establish authorized WebSocket sessions', async () => {
    const restrictedUser = makeUser({
      _id: '507f1f77bcf86cd7994390bb',
      name: 'WS Restricted User',
      email: 'ws@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })
    const issued = await auth.issue(restrictedUser)

    const server = http.createServer()
    const io = new Server(server, { cors: { origin: '*' } })
    require('../websocket/auth').install(io)

    await new Promise((resolve) => server.listen(0, resolve))
    const port = server.address().port

    const client = ioClient(`http://localhost:${port}`, {
      auth: { token: issued.token },
      transports: ['websocket'],
      reconnection: false,
    })

    const errorPromise = new Promise((resolve) => {
      client.on('connect_error', (err) => resolve(err))
    })

    const err = await errorPromise
    expect(err.message).toBe('Password change required')

    client.disconnect()
    await new Promise((resolve) => {
      io.close(() => {
        server.close(resolve)
      })
    })
  })

  test('14. Inactive status and logout retain existing security behavior', async () => {
    makeUser({
      _id: '507f1f77bcf86cd7994390cc',
      name: 'Inactive User',
      email: 'inactive@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'inactive',
      authVersion: 0,
      mustChangePassword: true,
    })

    const agent = request.agent(app)
    const res = await mutate(agent, 'login', {
      email: 'inactive@example.invalid',
      password: 'CorrectPassword123',
    })
    expect(res.status).toBe(403)
    expect(res.body.error).toMatch(/Account inactive/i)
  })

  test('15. Legacy documents without mustChangePassword field behave normally (unrestricted)', async () => {
    const legacyUser = makeUser({
      _id: '507f1f77bcf86cd7994390dd',
      name: 'Legacy User',
      email: 'legacy@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      // mustChangePassword omitted
    })
    const issued = await auth.issue(legacyUser)

    // Endpoint should allow access past protect middleware
    const res = await request(app)
      .get('/api/auth/me')
      .set('Authorization', 'Bearer ' + issued.token)

    expect(res.status).toBe(200)
    expect(res.body.data.user.mustChangePassword).toBeFalsy()
  })

  test('16. API responses never disclose password hashes or secret values', async () => {
    makeUser({
      _id: '507f1f77bcf86cd7994390ee',
      name: 'Leak Test User',
      email: 'leak@example.invalid',
      password: 'CorrectPassword123',
      role: 'analyst',
      status: 'active',
      authVersion: 0,
      mustChangePassword: true,
    })

    const agent = request.agent(app)
    const res = await mutate(agent, 'login', {
      email: 'leak@example.invalid',
      password: 'CorrectPassword123',
    })

    const bodyStr = JSON.stringify(res.body)
    expect(bodyStr).not.toContain('CorrectPassword123')
    expect(bodyStr).not.toContain('password')
    expect(res.body.data.user.password).toBeUndefined()
  })
})
