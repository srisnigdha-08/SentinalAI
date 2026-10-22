const request = require('supertest')
const express = require('express')
jest.mock('../../honeypot/collectors/session_collector', () => ({
  onSessionOpened: jest.fn(),
  onCommandReceived: jest.fn(),
  onSessionClosed: jest.fn(),
  onFileDownload: jest.fn(),
  onCommandFailed: jest.fn(),
  onFileUpload: jest.fn(),
  onTunnelRequest: jest.fn(),
  classifyIntent: jest.fn(() => 'UNKNOWN'),
}))
const collector = require('../../honeypot/collectors/session_collector')
const app = express()
app.use(express.json())
app.use('/ingest', require('../routes/honeypotIngest'))
app.use((error, _req, res, _next) => res.status(error.statusCode || 500).json({ error: error.message }))
beforeEach(() => {
  process.env.HONEYPOT_API_KEY = 'offline-ingestion-test-key'
  jest.clearAllMocks()
})
test('unsupported login/unknown events are rejected instead of acknowledged as persisted', async () => {
  for (const eventType of ['LOGIN_FAILED', 'LOGIN_SUCCEEDED', 'UNKNOWN']) {
    const response = await request(app)
      .post('/ingest')
      .set('X-API-Key', process.env.HONEYPOT_API_KEY)
      .send({ eventType })
    expect(response.status).toBe(400)
  }
  expect(collector.onSessionOpened).not.toHaveBeenCalled()
})
test('supported event keeps its response contract and calls the collector', async () => {
  collector.onSessionOpened.mockResolvedValue({ sessionId: 'offline-contract' })
  const response = await request(app)
    .post('/ingest')
    .set('X-API-Key', process.env.HONEYPOT_API_KEY)
    .send({ eventType: 'SESSION_OPENED', sessionId: 'offline-contract', sourceIP: '192.0.2.10' })
  expect(response.status).toBe(200)
  expect(response.body.data).toEqual({ received: true, eventType: 'SESSION_OPENED' })
  expect(collector.onSessionOpened).toHaveBeenCalledTimes(1)
})
test('servedProfile (C1) is passed to the collector when it is a known persona and rejected otherwise', async () => {
  collector.onSessionOpened.mockResolvedValue({ sessionId: 'persona' })
  const send = (servedProfile) =>
    request(app)
      .post('/ingest')
      .set('X-API-Key', process.env.HONEYPOT_API_KEY)
      .send({ eventType: 'SESSION_OPENED', sessionId: 'persona', sourceIP: '192.0.2.10', servedProfile })
  expect((await send('ubuntu_22')).status).toBe(200)
  expect(collector.onSessionOpened.mock.calls[0][0].servedProfile).toBe('ubuntu_22')
  for (const bad of ['solaris_9', '$where', 42, { $ne: null }]) {
    const res = await send(bad)
    expect(res.status).toBe(400)
    expect(res.body.error).toBe('servedProfile must be one of the deception profiles')
  }
  expect(collector.onSessionOpened).toHaveBeenCalledTimes(1)
})
test('COMMAND_FAILED marks a stored command instead of adding one (M1)', async () => {
  collector.onCommandFailed.mockResolvedValue({ sessionId: 's' })
  const res = await request(app)
    .post('/ingest')
    .set('X-API-Key', process.env.HONEYPOT_API_KEY)
    .send({ eventType: 'COMMAND_FAILED', sessionId: 's', sourceIP: '192.0.2.10', command: 'notreal' })
  expect(res.status).toBe(200)
  expect(collector.onCommandFailed).toHaveBeenCalledTimes(1)
  expect(collector.onCommandReceived).not.toHaveBeenCalled()
})
test('FILE_UPLOAD and TUNNEL_REQUEST are validated and reach their handlers (M3)', async () => {
  collector.onFileUpload.mockResolvedValue({ sessionId: 's' })
  collector.onTunnelRequest.mockResolvedValue({ sessionId: 's' })
  const send = (body) =>
    request(app)
      .post('/ingest')
      .set('X-API-Key', process.env.HONEYPOT_API_KEY)
      .send({ sessionId: 's', sourceIP: '192.0.2.10', ...body })
  expect((await send({ eventType: 'FILE_UPLOAD', filename: '/tmp/x', sha256: 'a'.repeat(64) })).status).toBe(200)
  expect((await send({ eventType: 'TUNNEL_REQUEST', dstIP: '203.0.113.9', dstPort: 25 })).status).toBe(200)
  for (const bad of [
    { eventType: 'FILE_UPLOAD' },
    { eventType: 'FILE_UPLOAD', filename: '/tmp/x', sha256: 'nothex' },
    { eventType: 'TUNNEL_REQUEST', dstIP: '203.0.113.9', dstPort: 70000 },
    { eventType: 'TUNNEL_REQUEST', dstPort: 25 },
  ])
    expect((await send(bad)).status).toBe(400)
  expect(collector.onFileUpload).toHaveBeenCalledTimes(1)
  expect(collector.onTunnelRequest).toHaveBeenCalledTimes(1)
})
test('collector failures are not successful acknowledgements', async () => {
  collector.onSessionOpened.mockRejectedValue(Object.assign(new Error('Collector unavailable'), { statusCode: 503 }))
  const response = await request(app)
    .post('/ingest')
    .set('X-API-Key', process.env.HONEYPOT_API_KEY)
    .send({ eventType: 'SESSION_OPENED', sessionId: 'offline-contract', sourceIP: '192.0.2.10' })
  expect(response.status).toBe(503)
})
test('missing/incorrect key never calls the collector', async () => {
  expect((await request(app).post('/ingest').send({ eventType: 'SESSION_OPENED' })).status).toBe(401)
  expect(
    (await request(app).post('/ingest').set('X-API-Key', 'incorrect').send({ eventType: 'SESSION_OPENED' })).status
  ).toBe(401)
  expect(collector.onSessionOpened).not.toHaveBeenCalled()
})

test('malformed telemetry is rejected before collector/model calls', async () => {
  for (const data of [
    { eventType: 'SESSION_OPENED' },
    { eventType: 'COMMAND_INPUT', sessionId: 'offline', sourceIP: '192.0.2.10', command: {} },
  ]) {
    expect((await request(app).post('/ingest').set('X-API-Key', process.env.HONEYPOT_API_KEY).send(data)).status).toBe(
      400
    )
  }
  expect(collector.onSessionOpened).not.toHaveBeenCalled()
  expect(collector.onCommandReceived).not.toHaveBeenCalled()
})

test.each(['/close', '/command', '/download'])(
  'missing session at %s is not a successful acknowledgement',
  async (path) => {
    collector.onSessionClosed.mockResolvedValue(null)
    collector.onCommandReceived.mockResolvedValue(null)
    collector.onFileDownload.mockResolvedValue(null)
    const response = await request(app)
      .post('/ingest' + path)
      .set('X-API-Key', process.env.HONEYPOT_API_KEY)
      .send({ sessionId: 'offline', sourceIP: '192.0.2.10', command: 'id', url: 'https://example.invalid/file' })
    expect(response.status).toBe(404)
  }
)

test('module-load failure gives sanitized 503 rather than fake acknowledgement', async () => {
  jest.resetModules()
  jest.doMock('../../honeypot/collectors/session_collector', () => {
    throw new Error('offline-private-module-error')
  })
  const response = await request(app)
    .post('/ingest')
    .set('X-API-Key', process.env.HONEYPOT_API_KEY)
    .send({ eventType: 'SESSION_OPENED', sessionId: 'offline', sourceIP: '192.0.2.10' })
  expect(response.status).toBe(503)
  expect(response.body.error).toBe('Honeypot collector unavailable')
})
