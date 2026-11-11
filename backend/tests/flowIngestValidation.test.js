'use strict'

process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-flow-validation'
process.env.HONEYPOT_API_KEY = 'flow-validation-honeypot-key-0123456789'

const fs = require('fs')
const path = require('path')
const express = require('express')
const request = require('supertest')

const FIXTURES = path.join(__dirname, '..', '..', 'ai-engine', 'tests', 'fixtures')
const NUMERIC = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'strict_numeric_cases.json'), 'utf8'))
const PARITY = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'feature_parity_cases.json'), 'utf8'))

describe('POST /ingest/flow numeric validation', () => {
  let app
  let runFullPipeline
  let logger
  const key = { 'X-API-Key': process.env.HONEYPOT_API_KEY }
  const fields = PARITY.fields.map((f) => f.schema)
  const flow = () => Object.fromEntries(fields.map((f, i) => [f, i + 1]))
  const post = (body) =>
    request(app)
      .post('/ingest/flow')
      .set(key)
      .send({ sourceIP: '198.51.100.1', ...body })

  beforeEach(() => {
    jest.resetModules()
    runFullPipeline = jest
      .fn()
      .mockResolvedValue({ predictedClass: 'BENIGN', threatScore: 0.1, action: 'ALLOW', _id: 'p' })
    jest.doMock('../services/aiEngineService', () => ({ runFullPipeline }))
    logger = require('../utils/logger')
    jest.spyOn(logger, 'warn').mockImplementation(() => {})
    app = express()
    app.use(express.json())
    app.use('/ingest', require('../routes/honeypotIngest'))
    app.use((err, _req, res, _next) => res.status(err.statusCode || 500).json({ error: err.message }))
  })

  afterEach(() => jest.restoreAllMocks())

  test.each(NUMERIC.valid.map((c) => [c.name, c.value, c.number]))('accepts %s', async (_name, value, number) => {
    const r = await post({ ...flow(), flow_duration: value })
    expect(r.status).toBe(200)
    expect(runFullPipeline.mock.calls[0][0].flow_duration).toBe(number)
  })

  test.each(NUMERIC.invalid.map((c) => [c.name, c.value]))('rejects %s with 400', async (_name, value) => {
    const r = await post({ ...flow(), flow_bytes_per_sec: value })
    expect(r.status).toBe(400)
    expect(runFullPipeline).not.toHaveBeenCalled()
  })

  test('the rejection names the field but never echoes the value or the source address', async () => {
    const r = await post({ ...flow(), flow_bytes_per_sec: 'attacker-text', flow_packets_per_sec: 'NaN' })
    expect(r.status).toBe(400)
    expect(JSON.stringify(r.body)).toContain('flow_bytes_per_sec')
    expect(JSON.stringify(r.body)).not.toContain('attacker-text')
    const logged = JSON.stringify(logger.warn.mock.calls)
    expect(logged).toContain('flow_bytes_per_sec')
    expect(logged).not.toContain('attacker-text')
    expect(logged).not.toContain('198.51.100.1')
  })

  test('rejected flows are counted per field', async () => {
    await post({ ...flow(), flow_bytes_per_sec: 'Infinity' })
    await post({ ...flow(), flow_bytes_per_sec: 'NaN', flow_packets_per_sec: 'NaN' })
    const text = require('../utils/metrics').render()
    expect(text).toMatch(/sentinel_flow_ingest_rejected_total\{field="flow_bytes_per_sec"\} 2/)
    expect(text).toMatch(/sentinel_flow_ingest_rejected_total\{field="flow_packets_per_sec"\} 1/)
  })

  test('an absent field is still allowed and left for the engine to report', async () => {
    const body = flow()
    delete body.idle_std
    const r = await post(body)
    expect(r.status).toBe(200)
    expect(runFullPipeline.mock.calls[0][0]).not.toHaveProperty('idle_std')
  })

  test('unknown fields are ignored without failing the flow', async () => {
    const r = await post({ ...flow(), label: 'DDoS', $where: 'x', unrelated: 'NaN' })
    expect(r.status).toBe(200)
    expect(runFullPipeline.mock.calls[0][0]).not.toHaveProperty('label')
    expect(runFullPipeline.mock.calls[0][0]).not.toHaveProperty('$where')
  })

  test('too few fields is still refused', async () => {
    expect((await post({ flow_duration: 1 })).status).toBe(400)
  })

  test.each(PARITY.cases.map((c) => [c.name, c.values]))('forwards %s unchanged', async (_name, values) => {
    const r = await post(Object.fromEntries(fields.map((f, i) => [f, values[i]])))
    expect(r.status).toBe(200)
    const record = runFullPipeline.mock.calls[0][0]
    expect(fields.map((f) => record[f])).toEqual(values)
  })
})
