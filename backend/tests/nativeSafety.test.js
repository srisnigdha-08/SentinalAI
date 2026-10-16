process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'test-native-access-secret'
process.env.JWT_REFRESH_SECRET = 'test-native-refresh-secret'
process.env.HONEYPOT_API_KEY = 'test-native-honeypot-secret'
process.env.SENTINEL_KEY = 'test-native-sentinel-secret'
jest.mock('../config/db', () => jest.fn())
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), getStats: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({ getHealth: jest.fn().mockResolvedValue({ status: 'unreachable' }) }))
const request = require('supertest')
const User = require('../models/User')
const { app } = require('../server')
const redact = require('../utils/redact')

test('unavailable dependencies fail backend readiness', async () => {
  const response = await request(app).get('/health')
  expect(response.status).toBe(503)
  expect(response.body.status).toBe('unavailable')
})
test.each(['/api/ws/demo/start', '/api/ws/demo/stop', '/api/ai/simulate'])('no simulation route: %s', async (url) => {
  expect((await request(app).post(url)).status).toBe(404)
})
test('version changes invalidate existing access tokens', async () => {
  const Session = require('../models/AuthSession')
  const memory = require('./helpers/authMemoryStore').install(User, Session)
  const issued = await require('../services/authSessionService').issue(memory.user)
  memory.users.get(memory.user._id).authVersion++
  expect(
    (
      await request(app)
        .get('/api/auth/me')
        .set('Authorization', 'Bearer ' + issued.token)
    ).status
  ).toBe(401)
})

test('logging redacts credentials, environment secrets and bearer tokens', () => {
  const result = redact({
    password: 'anything',
    nested: { token: 'anything' },
    message: 'mongodb://user:pass@localhost/db ' + process.env.SENTINEL_KEY + ' Bearer abc.def.ghi',
  })
  for (const secret of ['anything', 'user:pass', process.env.SENTINEL_KEY, 'abc.def.ghi'])
    expect(JSON.stringify(result)).not.toContain(secret)
})
