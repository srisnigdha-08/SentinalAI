process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'test-access-secret-auth-suite'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-auth-suite'
process.env.HONEYPOT_API_KEY = 'test-honeypot-secret-auth-suite'
process.env.SENTINEL_KEY = 'test-internal-secret-auth-suite'
process.env.CLIENT_URL = 'http://localhost:3000'
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../models/AuditLog')
jest.mock('../config/db', () => jest.fn())
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn() }))
const request = require('supertest')
const User = require('../models/User')
const Session = require('../models/AuthSession')
const { install, query } = require('./helpers/authMemoryStore')
const { accessToken } = require('./helpers/accessFixture')
const { app } = require('../server')
const auth = require('../services/authSessionService')
let memory
beforeEach(() => {
  jest.clearAllMocks()
  memory = install(User, Session)
})
async function login(password = 'CorrectPassword123') {
  const agent = request.agent(app)
  const csrf = (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
  return agent
    .post('/api/auth/login')
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', csrf)
    .send({ email: memory.user.email, password })
}
test('login returns access token and public user, with refresh only in cookie', async () => {
  const result = await login()
  expect(result.status).toBe(200)
  expect(result.body.data.token).toBeDefined()
  expect(result.body.data.refreshToken).toBeUndefined()
  expect(result.headers['set-cookie']).toBeDefined()
})
test('wrong password rejected', async () => {
  expect((await login('Incorrect-password')).status).toBe(401)
})
test('unknown account rejected', async () => {
  User.findOne.mockReturnValue(query(null))
  expect((await login()).status).toBe(401)
})
test('inactive account rejected', async () => {
  memory.users.get(memory.user._id).status = 'inactive'
  expect((await login()).status).toBe(403)
})
test('missing access token rejected', async () => {
  expect((await request(app).get('/api/auth/me')).status).toBe(401)
})
test('malformed access token rejected', async () => {
  expect((await request(app).get('/api/auth/me').set('Authorization', 'Bearer malformed')).status).toBe(401)
})
test('expired session token rejected', async () => {
  expect(
    (
      await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + accessToken(memory.user, -1))
    ).status
  ).toBe(401)
})
test('active server session accepted on protected route', async () => {
  const issued = await auth.issue(memory.user)
  const result = await request(app)
    .get('/api/auth/me')
    .set('Authorization', 'Bearer ' + issued.token)
  expect(result.status).toBe(200)
  expect(result.body.data.user.email).toBe(memory.user.email)
})

test('registering with {"role":"admin"} is rejected', async () => {
  const agent = request.agent(app)
  const csrf = (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
  const res = await agent
    .post('/api/auth/register')
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', csrf)
    .send({ name: 'Hacker', email: 'hacker@evil.com', password: 'Password123!', role: 'admin' })
  expect(res.status).toBe(403)
})

test('deactivated or force-logged-out user cannot refresh token', async () => {
  const agent = request.agent(app)
  const csrf = (await agent.get('/api/auth/csrf').set('Origin', process.env.CLIENT_URL)).body.data.csrfToken
  const loginRes = await agent
    .post('/api/auth/login')
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', csrf)
    .send({ email: memory.user.email, password: 'CorrectPassword123' })
  expect(loginRes.status).toBe(200)

  // Deactivate user
  memory.users.get(memory.user._id).status = 'inactive'

  // Attempt refresh
  const refreshRes = await agent
    .post('/api/auth/refresh-token')
    .set('Origin', process.env.CLIENT_URL)
    .set('X-CSRF-Token', csrf)
  expect(refreshRes.status).toBe(403)
})
