process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'test-body-access-secret-0123456789'
process.env.JWT_REFRESH_SECRET = 'test-body-refresh-secret-0123456789'
process.env.HONEYPOT_API_KEY = 'test-body-honeypot-secret-0123456789'
process.env.SENTINEL_KEY = 'test-body-sentinel-secret-0123456789'
/**
 * F-05: a malformed JSON body returned 400 with the parser's own message ("Unexpected token ... in JSON at
 * position N", or "Expected property name ..."), which echoes fragments of the request and reveals the parser.
 * Body-parser failures now map to fixed messages; the detail is logged server-side only.
 */
jest.mock('../config/db', () => jest.fn())
jest.mock('../models/User')
jest.mock('../models/AuthSession')
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ init: jest.fn(), getStats: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({ getHealth: jest.fn().mockResolvedValue({ status: 'unreachable' }) }))

const request = require('supertest')
const { app } = require('../server')
const { errorHandler } = require('../middleware/errorHandler')
const logger = require('../utils/logger')

const PARSER_DETAIL = /unexpected|position|token|property name|JSON at|SyntaxError|body-parser|raw-body/i

test('malformed JSON: 400 with a fixed message, no parser detail or echoed input', async () => {
  const res = await request(app)
    .post('/api/auth/login')
    .set('Content-Type', 'application/json')
    .send('{"email": "secret-fragment@x", ')
  expect(res.status).toBe(400)
  expect(res.body.success).toBe(false)
  expect(res.body.error).toBe('Malformed JSON request body')
  expect(JSON.stringify(res.body)).not.toMatch(PARSER_DETAIL)
  expect(JSON.stringify(res.body)).not.toContain('secret-fragment')
})

test('malformed JSON with a non-object value under strict mode is also sanitised', async () => {
  const res = await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send('"just a string"')
  expect(res.status).toBe(400)
  expect(res.body.error).toBe('Malformed JSON request body')
})

test('body over the 10 kB limit: 413 with a fixed message', async () => {
  const res = await request(app)
    .post('/api/auth/login')
    .set('Content-Type', 'application/json')
    .send(JSON.stringify({ email: 'a'.repeat(20000) }))
  expect(res.status).toBe(413)
  expect(res.body.error).toBe('Request body too large')
  expect(JSON.stringify(res.body)).not.toMatch(/limit|10kb|bytes/i)
})

test('unsupported charset: 415 with a fixed message', async () => {
  const res = await request(app)
    .post('/api/auth/login')
    .set('Content-Type', 'application/json; charset=latin1')
    .send('{"email":"x"}')
  expect(res.status).toBe(415)
  expect(res.body.error).toBe('Unsupported request body encoding')
})

test('non-JSON content type is not parsed and never produces a 500', async () => {
  const res = await request(app).post('/api/auth/login').set('Content-Type', 'text/plain').send('email=x')
  expect(res.status).toBeGreaterThanOrEqual(400)
  expect(res.status).toBeLessThan(500)
})

test('a well-formed request still reaches validation (400/403/422 from the route, not the parser)', async () => {
  const res = await request(app).post('/api/auth/login').set('Content-Type', 'application/json').send({ email: 'x' })
  expect(res.status).toBeGreaterThanOrEqual(400)
  expect(res.status).toBeLessThan(500)
  expect(res.body.error).not.toBe('Malformed JSON request body')
})

describe('errorHandler unit cases', () => {
  const run = (err) => {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn().mockReturnThis() }
    errorHandler(err, { method: 'POST', path: '/x' }, res, () => {})
    return { status: res.status.mock.calls[0][0], body: res.json.mock.calls[0][0] }
  }

  test('parser detail is logged server-side, not returned', () => {
    const err = Object.assign(new SyntaxError('Unexpected token } in JSON at position 9'), {
      type: 'entity.parse.failed',
      status: 400,
      statusCode: 400,
      body: '{"a":1,}',
    })
    const { status, body } = run(err)
    expect(status).toBe(400)
    expect(JSON.stringify(body)).not.toMatch(PARSER_DETAIL)
    expect(logger.warn).toHaveBeenCalled()
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain('{"a":1,}') // the raw body is not logged either
  })

  test('duplicate-key error without keyValue does not crash the handler', () => {
    const { status, body } = run(Object.assign(new Error('E11000 duplicate key'), { code: 11000 }))
    expect(status).toBe(409)
    expect(body.error).toBe('Resource already exists')
  })

  test('5xx stays masked', () => {
    const { status, body } = run(new Error('connection string mongodb://user:pw@h'))
    expect(status).toBe(500)
    expect(body.error).toBe('Internal server error')
  })
})
