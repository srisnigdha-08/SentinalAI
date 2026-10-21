'use strict'
/**
 * Improvement round (backend): circuit breaker + retry, metrics access, request ids, live flow ingest,
 * drift alerting, model reload / deception recommendation proxies, and the training-sample export.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-improvements'
process.env.HONEYPOT_API_KEY = 'improvements-honeypot-key-0123456789'
const request = require('supertest')
const express = require('express')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const { CircuitBreaker, withRetry } = require('../utils/circuitBreaker')
const metrics = require('../utils/metrics')
const requestContext = require('../utils/requestContext')

describe('circuit breaker and retry', () => {
  const netErr = () => Object.assign(new Error('refused'), { code: 'ECONNREFUSED' })

  test('opens after N infrastructure failures, fails fast, then half-opens and closes on success', async () => {
    let t = 0
    const cb = new CircuitBreaker({ failureThreshold: 3, resetTimeoutMs: 1000, now: () => t })
    const failing = jest.fn().mockRejectedValue(netErr())
    for (let i = 0; i < 3; i++) await expect(cb.exec(failing)).rejects.toThrow('refused')
    expect(cb.state).toBe('open')
    await expect(cb.exec(failing)).rejects.toMatchObject({ code: 'CIRCUIT_OPEN' })
    expect(failing).toHaveBeenCalledTimes(3) // no network call while open
    t = 1000
    expect(cb.state).toBe('half-open')
    await expect(cb.exec(async () => 'ok')).resolves.toBe('ok')
    expect(cb.state).toBe('closed')
  })

  test('4xx responses neither open the circuit nor get retried', async () => {
    const cb = new CircuitBreaker({ failureThreshold: 1 })
    const rejected = Object.assign(new Error('bad input'), { response: { status: 422 } })
    const fn = jest.fn().mockRejectedValue(rejected)
    await expect(cb.exec(() => withRetry(fn, { sleep: async () => {} }))).rejects.toBe(rejected)
    expect(fn).toHaveBeenCalledTimes(1)
    expect(cb.state).toBe('closed')
  })

  test('connection errors and 503s are retried with backoff, then succeed', async () => {
    const sleeps = []
    const fn = jest
      .fn()
      .mockRejectedValueOnce(netErr())
      .mockRejectedValueOnce(Object.assign(new Error('busy'), { response: { status: 503 } }))
      .mockResolvedValue('done')
    await expect(withRetry(fn, { sleep: async (ms) => sleeps.push(ms) })).resolves.toBe('done')
    expect(fn).toHaveBeenCalledTimes(3)
    expect(sleeps).toHaveLength(2)
    expect(sleeps[1]).toBeGreaterThan(sleeps[0] / 3) // exponential with jitter
  })
})

describe('metrics and request ids', () => {
  const app = express()
  app.use(requestContext.middleware)
  app.use(metrics.httpMiddleware)
  app.get('/metrics', metrics.handler)
  app.get('/x', (req, res) => res.json({ id: requestContext.getRequestId() }))
  afterEach(() => delete process.env.METRICS_TOKEN)

  test('request id is propagated through async context and echoed', async () => {
    const r = await request(app).get('/x').set('X-Request-Id', 'proxy-request-0001')
    expect(r.headers['x-request-id']).toBe('proxy-request-0001')
    expect(r.body.id).toBe('proxy-request-0001')
    const generated = await request(app).get('/x').set('X-Request-Id', 'not valid!')
    expect(generated.body.id).not.toBe('not valid!')
    expect(generated.headers['x-request-id']).toBe(generated.body.id)
  })

  test('metrics need the bearer token when METRICS_TOKEN is set, and count requests', async () => {
    process.env.METRICS_TOKEN = 'scrape-secret-123'
    expect((await request(app).get('/metrics')).status).toBe(403)
    const r = await request(app).get('/metrics').set('Authorization', 'Bearer scrape-secret-123')
    expect(r.status).toBe(200)
    expect(r.text).toMatch(/sentinel_http_requests_total\{method="GET",route="\/x",status="200"\} \d+/)
  })
})

describe('live flow ingest (POST /ingest/flow)', () => {
  jest.resetModules()
  const runFullPipeline = jest.fn()
  jest.doMock('../services/aiEngineService', () => ({ runFullPipeline }))
  const app = express()
  app.use(express.json())
  app.use('/ingest', require('../routes/honeypotIngest'))
  app.use((err, _req, res, _next) => res.status(err.statusCode || 500).json({ error: err.message }))
  const flow = Object.fromEntries(
    [
      'flow_duration',
      'total_fwd_packets',
      'total_bwd_packets',
      'syn_flag_count',
      'ack_flag_count',
      'fwd_header_len',
      'bwd_header_len',
      'flow_bytes_per_sec',
      'flow_packets_per_sec',
      'init_win_bytes_forward',
      'fin_flag_count',
      'idle_mean',
    ].map((f, i) => [f, i + 1])
  )

  test('requires a service key, a valid IP and enough numeric fields; forwards only known fields', async () => {
    expect(
      (
        await request(app)
          .post('/ingest/flow')
          .send({ sourceIP: '198.51.100.1', ...flow })
      ).status
    ).toBe(401)
    const key = { 'X-API-Key': process.env.HONEYPOT_API_KEY }
    expect(
      (
        await request(app)
          .post('/ingest/flow')
          .set(key)
          .send({ sourceIP: 'x', ...flow })
      ).status
    ).toBe(400)
    expect(
      (await request(app).post('/ingest/flow').set(key).send({ sourceIP: '198.51.100.1', flow_duration: 1 })).status
    ).toBe(400)

    runFullPipeline.mockResolvedValue({ predictedClass: 'DDoS', threatScore: 0.97, action: 'BLOCK', _id: 'p1' })
    const r = await request(app)
      .post('/ingest/flow')
      .set(key)
      .send({ sourceIP: '198.51.100.1', ...flow, $where: 'x', label: 'DDoS', syn_flag_count: 'NaN' })
    expect(r.status).toBe(200)
    expect(r.body.data).toEqual({ predictedClass: 'DDoS', threatScore: 0.97, action: 'BLOCK', predictionId: 'p1' })
    const record = runFullPipeline.mock.calls[0][0]
    expect(record.sourceIP).toBe('198.51.100.1')
    expect(record).not.toHaveProperty('label')
    expect(record).not.toHaveProperty('$where')
    expect(record).not.toHaveProperty('syn_flag_count') // non-numeric value dropped
  })
})

describe('drift monitor alerting', () => {
  test('one alert per cooldown while the engine reports drift; none for ok', async () => {
    jest.resetModules()
    const getDrift = jest.fn()
    const createAlert = jest.fn().mockResolvedValue({ _id: 'a' })
    jest.doMock('../services/aiEngineService', () => ({ getDrift }))
    jest.doMock('../services/alertService', () => ({ createAlert }))
    jest.doMock('../websocket/socketManager', () => ({ emitNewAlert: jest.fn() }))
    const { DriftMonitorService } = require('../services/driftMonitorService')
    const svc = new DriftMonitorService({ cooldownHours: 24 })

    getDrift.mockResolvedValue({ status: 'ok' })
    expect((await svc.check(0)).alerted).toBe(false)
    getDrift.mockResolvedValue({
      status: 'drift',
      drifted_fraction: 0.2,
      samples: 500,
      top_shifts: [{ feature: 'f', mean_shift_sd: 2 }],
    })
    expect((await svc.check(1000)).alerted).toBe(true)
    expect((await svc.check(2000)).alerted).toBe(false) // cooldown
    expect((await svc.check(1000 + 25 * 3600 * 1000)).alerted).toBe(true)
    expect(createAlert).toHaveBeenCalledTimes(2)
    expect(createAlert.mock.calls[0][0]).toMatchObject({ type: 'SYSTEM_HEALTH', title: 'Model input drift detected' })
  })

  test('gauge value: -1 before any check or when not assessed, 0 ok, 1 drift', async () => {
    jest.resetModules()
    const getDrift = jest.fn()
    jest.doMock('../services/aiEngineService', () => ({ getDrift }))
    jest.doMock('../services/alertService', () => ({ createAlert: jest.fn().mockResolvedValue({}) }))
    jest.doMock('../websocket/socketManager', () => ({ emitNewAlert: jest.fn() }))
    const { DriftMonitorService } = require('../services/driftMonitorService')
    const svc = new DriftMonitorService()
    expect(svc.statusValue()).toBe(-1)
    for (const [report, value] of [
      [null, -1],
      [{ status: 'insufficient_data' }, -1],
      [{ status: 'ok' }, 0],
      [{ status: 'drift', top_shifts: [] }, 1],
    ]) {
      getDrift.mockResolvedValue(report)
      await svc.check()
      expect(svc.statusValue()).toBe(value)
    }
  })
})

describe('training sample export', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })

  test('exports only ELIGIBLE_FOR_TRAINING samples with their feature vectors', async () => {
    jest.resetModules()
    const realMongoose = require('mongoose')
    if (realMongoose.connection.readyState !== 1) await realMongoose.connect(mongoServer.getUri())
    const TrainingSample = require('../models/TrainingSample')
    const vec = Array.from({ length: 53 }, (_, i) => i / 10)
    const base = {
      featureVector: vec,
      featureSchemaVersion: 'v2.1_53feat',
      groundTruthLabel: 'DDoS',
      inputSource: 'network_traffic',
    }
    await TrainingSample.collection.insertMany([
      { ...base, status: 'ELIGIBLE_FOR_TRAINING', sampleHash: 'h1', sourcePredictionId: new mongoose.Types.ObjectId() },
      { ...base, status: 'QUARANTINED', sampleHash: 'h2', sourcePredictionId: new mongoose.Types.ObjectId() },
    ])
    const out = require('path').join(require('os').tmpdir(), `samples-${Date.now()}.jsonl`)
    const { exportEligibleSamples } = require('../utils/exportTrainingSamples')
    expect(await exportEligibleSamples(out)).toBe(1)
    const lines = require('fs').readFileSync(out, 'utf8').trim().split('\n').map(JSON.parse)
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatchObject({ sampleHash: 'h1', label: 'DDoS', featureSchemaVersion: 'v2.1_53feat' })
    expect(lines[0].featureVector).toHaveLength(53)
    require('fs').unlinkSync(out)
    await realMongoose.disconnect() // the module registry was reset, so this is a second connection
  })
})
