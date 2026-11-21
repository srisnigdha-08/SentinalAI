'use strict'
/**
 * Offline PCAP replay, backend side (docs/CAPTURE.md, "How it is verified"):
 *   capture-service flow payload -> POST /api/honeypot/ingest/flow -> runFullPipeline -> AI engine (stubbed)
 *   -> AIPrediction (MongoDB, in memory) -> ai_prediction socket event -> Trust Meter provenance
 * plus the capture heartbeat and the Capability Status entries for replay and live capture.
 *
 * The flow payloads are the real output of ai-engine/capture for a synthetic pcap (the AI-engine suite regenerates
 * and compares the same fixture). Only the HTTP call to the engine is stubbed. No network, no capture, no firewall.
 */
process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'test-sentinel-key-pcap-replay'
process.env.HONEYPOT_API_KEY = 'pcap-replay-honeypot-key-0123456789abcdef'

const fs = require('fs')
const path = require('path')
const express = require('express')
const request = require('supertest')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const FIXTURE = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', '..', 'ai-engine', 'tests', 'fixtures', 'pcap_replay_flows.json'), 'utf8')
)
const [TCP_FLOW, UDP_FLOW] = FIXTURE.flows
const KEY = { 'X-API-Key': process.env.HONEYPOT_API_KEY }
const ENGINE_DERIVED = ['payload_entropy', 'time_of_day_sin', 'time_of_day_cos']

const AIPrediction = require('../models/AIPrediction')
const aiEngineService = require('../services/aiEngineService')
const socketManager = require('../websocket/socketManager')
const capture = require('../services/captureStatusService')
const { FLOW_FIELDS } = require('../utils/flowFields')
const { redactAIPrediction } = require('../utils/redact')
const { assessPrediction } = require('../utils/trustAssessment')

let mongo
let app
let emitted
let engineCalls

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  app = express()
  app.use(express.json())
  app.use('/ingest', require('../routes/honeypotIngest'))
  app.use((err, _req, res, _next) => res.status(err.statusCode || 500).json({ error: err.message }))
  // A minimal Socket.IO stand-in: records what each room would receive. init() also starts the 15 s health
  // broadcast, which reads io.engine; it is stopped in afterAll so no timer outlives this file.
  emitted = []
  socketManager.init({
    on: () => {},
    engine: { clientsCount: 0 },
    to: (rooms) => ({ emit: (event, data) => emitted.push({ rooms, event, data }) }),
  })
})

afterAll(async () => {
  socketManager.stopHealthBroadcast()
  await mongoose.disconnect()
  await mongo.stop()
})

beforeEach(() => {
  emitted.length = 0
  engineCalls = []
  capture._reset()
  jest.spyOn(aiEngineService, 'getAlertThreshold').mockResolvedValue(0.9)
  jest.spyOn(aiEngineService, 'getBlockThreshold').mockResolvedValue(0.92)
  jest.spyOn(aiEngineService, 'predictRecord').mockImplementation(async (record) => {
    engineCalls.push(record)
    return {
      success: true,
      result: {
        predictedClass: 'BENIGN',
        threatScore: 0.04,
        action: 'ALLOW',
        isAnomaly: false,
        anomalyScore: 0,
        classProbabilities: { BENIGN: 0.96 },
        modelVersion: 'xgb_cicids_v1',
        featureVector: Array(53).fill(0),
        featureSchemaVersion: 'v2.1_53feat',
        defaultedFeatures: [],
        incompleteInput: false,
      },
    }
  })
})

afterEach(async () => {
  jest.restoreAllMocks()
  await AIPrediction.deleteMany({})
})

const postFlow = (body) => request(app).post('/ingest/flow').set(KEY).send(body)
const predictionEvents = () => emitted.filter((e) => e.event === 'ai_prediction')

describe('PCAP replay flow -> prediction -> storage -> event', () => {
  test('a replayed TCP flow is scored, stored and pushed as pcap_replay', async () => {
    const r = await postFlow(TCP_FLOW)
    expect(r.status).toBe(200)
    expect(r.body.data).toMatchObject({ predictedClass: 'BENIGN', action: 'ALLOW' })

    // The engine receives every extracted flow field, and no provenance label (the backend keeps that).
    expect(engineCalls).toHaveLength(1)
    const sent = engineCalls[0]
    expect(sent).not.toHaveProperty('captureSource')
    const expected = FLOW_FIELDS.filter((f) => !ENGINE_DERIVED.includes(f))
    for (const f of expected) expect(sent[f]).toBe(TCP_FLOW[f])
    expect(sent.sourceIP).toBe(TCP_FLOW.sourceIP)

    const stored = await AIPrediction.find({}).lean()
    expect(stored).toHaveLength(1)
    expect(stored[0]).toMatchObject({
      inputSource: 'network_traffic',
      captureSource: 'pcap_replay',
      sourceIP: TCP_FLOW.sourceIP,
      targetIP: TCP_FLOW.destinationIP,
      modelVersion: 'xgb_cicids_v1',
    })
    expect(stored[0].rawFeatures).not.toHaveProperty('captureSource')

    const events = predictionEvents()
    expect(events.length).toBeGreaterThanOrEqual(1)
    for (const e of events) expect(e.data.captureSource).toBe('pcap_replay')
    expect(events.find((e) => e.rooms.includes('admin')).data.inputSource).toBe('network_traffic')
  })

  test('a replayed UDP flow keeps its provenance too', async () => {
    expect((await postFlow(UDP_FLOW)).status).toBe(200)
    const [p] = await AIPrediction.find({}).lean()
    expect(p.captureSource).toBe('pcap_replay')
    expect(engineCalls[0].init_win_bytes_forward).toBe(-1)
  })

  test('provenance survives the viewer redaction and reaches the Trust Meter as PCAP_REPLAY', async () => {
    await postFlow(TCP_FLOW)
    const [p] = await AIPrediction.find({}).lean()
    const viewer = redactAIPrediction(p, 'viewer')
    expect(viewer.captureSource).toBe('pcap_replay')
    expect(viewer.sourceIP).not.toBe(TCP_FLOW.sourceIP)
    const viewerEvent = predictionEvents().find((e) => e.rooms.includes('viewer'))
    expect(viewerEvent.data.captureSource).toBe('pcap_replay')
    const trust = assessPrediction(p)
    expect(JSON.stringify(trust)).toContain('PCAP_REPLAY')
  })

  test('payload-like fields in the request are never stored or forwarded', async () => {
    const r = await postFlow({ ...TCP_FLOW, payload: 'SECRET-BYTES', data: 'SECRET-BYTES', raw: 'SECRET-BYTES' })
    expect(r.status).toBe(200)
    const [p] = await AIPrediction.find({}).lean()
    expect(JSON.stringify(p)).not.toContain('SECRET-BYTES')
    expect(JSON.stringify(engineCalls)).not.toContain('SECRET-BYTES')
    expect(JSON.stringify(emitted)).not.toContain('SECRET-BYTES')
  })

  test('an unrecognised source label is stored as unknown, never as live', async () => {
    await postFlow({ ...TCP_FLOW, captureSource: 'live' })
    const [p] = await AIPrediction.find({}).lean()
    expect(p.captureSource).toBe('unknown')
  })

  test('replaying the same file twice stores two observations, both labelled pcap_replay', async () => {
    await postFlow(TCP_FLOW)
    await postFlow(TCP_FLOW)
    const stored = await AIPrediction.find({}).lean()
    expect(stored).toHaveLength(2)
    expect(stored.every((p) => p.captureSource === 'pcap_replay')).toBe(true)
    expect(String(stored[0]._id)).not.toBe(String(stored[1]._id))
  })

  test('invalid replay input is refused without reaching the engine', async () => {
    expect((await postFlow({ ...TCP_FLOW, sourceIP: 'not-an-ip' })).status).toBe(400)
    expect((await postFlow({ ...TCP_FLOW, flow_duration: 'NaN' })).status).toBe(400)
    expect(
      (await postFlow({ sourceIP: TCP_FLOW.sourceIP, captureSource: 'pcap_replay', flow_duration: 1 })).status
    ).toBe(400)
    expect((await request(app).post('/ingest/flow').send(TCP_FLOW)).status).toBe(401)
    expect(engineCalls).toHaveLength(0)
    expect(await AIPrediction.countDocuments()).toBe(0)
  })
})

describe('replay heartbeat and Capability Status', () => {
  const beat = (body) => request(app).post('/ingest/capture-heartbeat').set(KEY).send(body)
  const caps = async () => {
    const { getCapabilities } = require('../services/capabilityService')
    const r = await getCapabilities()
    return Object.fromEntries(r.items.map((i) => [i.id, i]))
  }

  test('replay and live capture are two separate entries; live is not enabled with no capture service', async () => {
    const byId = await caps()
    expect(byId.network_capture).toBeUndefined()
    expect(byId.pcap_replay.label).toBe('implemented_and_verified')
    expect(byId.pcap_replay.facts.liveTraffic).toBe(false)
    expect(byId.pcap_replay.facts.evidence).toEqual(
      expect.arrayContaining(['ai-engine/tests/test_pcap_replay_e2e.py', 'backend/tests/pcapReplayIngest.test.js'])
    )
    for (const f of byId.pcap_replay.facts.evidence)
      expect(fs.existsSync(path.join(__dirname, '..', '..', f))).toBe(true)
    expect(byId.live_capture.label).toBe('implemented_not_enabled')
    expect(byId.live_capture.facts).toMatchObject({ running: false, verified: false, interface: null })
  })

  test('a finished replay is reported on the replay entry and never turns live capture on', async () => {
    const r = await beat({
      mode: 'pcap_replay',
      status: 'finished',
      interface: 'eth0',
      counters: { packets: 9, flows: 2, posted: 2, records: 11, skipped_frames: 2 },
    })
    expect(r.status).toBe(200)
    expect(capture.getStatus()).toMatchObject({ mode: 'pcap_replay', state: 'finished' })
    const byId = await caps()
    expect(byId.pcap_replay.facts.lastReplay).toMatchObject({
      state: 'finished',
      counters: { packets: 9, flows: 2, posted: 2, records: 11, skipped_frames: 2 },
    })
    expect(byId.pcap_replay.summary).toMatch(/9 packets, 2 flows, 2 posted/)
    expect(byId.live_capture.label).toBe('implemented_not_enabled')
    expect(byId.live_capture.facts.running).toBe(false)
    expect(byId.live_capture.summary).toMatch(/offline PCAP replay/)
    expect(capture.getStatus().last.interface).toBeNull()
  })

  test('a failed replay is reported with its reason; the replay capability label is unchanged', async () => {
    expect(
      (await beat({ mode: 'pcap_replay', status: 'failed', lastError: 'pcap: not a pcap file (bad magic number)' }))
        .status
    ).toBe(200)
    expect(capture.getStatus()).toMatchObject({ mode: 'pcap_replay', state: 'failed', reason: /bad magic/ })
    const byId = await caps()
    expect(byId.pcap_replay.summary).toMatch(/Last replay failed: pcap: not a pcap file/)
    expect(byId.live_capture.label).toBe('implemented_not_enabled')
  })

  test('a live-capture "failed" report is shown as unavailable, never as running', async () => {
    await beat({ mode: 'live_passive', status: 'failed', interface: 'eth0', lastError: 'boom' })
    expect(capture.getStatus()).toMatchObject({ mode: 'unavailable', reason: 'boom' })
    expect((await caps()).live_capture.label).toBe('implemented_not_enabled')
  })

  test('malformed heartbeats are refused', async () => {
    expect((await beat({ mode: 'pcap_replay', status: 'exploded' })).status).toBe(400)
    expect((await beat({ mode: 'live', status: 'running' })).status).toBe(400)
    expect(
      (await request(app).post('/ingest/capture-heartbeat').send({ mode: 'pcap_replay', status: 'finished' })).status
    ).toBe(401)
  })
})

describe('flowId: a retried or replayed flow is stored once', () => {
  const ThreatLog = require('../models/ThreatLog')
  beforeAll(async () => {
    await AIPrediction.init() // the unique flowId index must exist before the concurrency case
  })
  afterEach(async () => {
    await ThreatLog.deleteMany({})
  })
  const attack = () =>
    aiEngineService.predictRecord.mockImplementation(async (record) => {
      engineCalls.push(record)
      return {
        success: true,
        result: {
          predictedClass: 'DDoS',
          threatScore: 0.99,
          action: 'BLOCK',
          isAnomaly: false,
          anomalyScore: 0,
          classProbabilities: { DDoS: 0.99 },
          modelVersion: 'xgb_cicids_v1',
          featureVector: Array(53).fill(0),
          featureSchemaVersion: 'v2.1_53feat',
          defaultedFeatures: [],
          incompleteInput: false,
        },
      }
    })

  test('the same flowId twice: one prediction, the engine called once, the repeat marked duplicate', async () => {
    const first = await postFlow({ ...TCP_FLOW, flowId: 'pcap-0001-abcdef' })
    const second = await postFlow({ ...TCP_FLOW, flowId: 'pcap-0001-abcdef' })
    expect(first.status).toBe(200)
    expect(first.body.data.duplicate).toBeUndefined()
    expect(second.status).toBe(200)
    expect(second.body.data).toMatchObject({ duplicate: true, predictedClass: 'BENIGN', action: 'ALLOW' })
    expect(String(second.body.data.predictionId)).toBe(String(first.body.data.predictionId))
    expect(engineCalls).toHaveLength(1)
    expect(await AIPrediction.countDocuments({})).toBe(1)
  })

  test('an attacking flow repeated with its flowId creates one threat, not two', async () => {
    attack()
    await postFlow({ ...TCP_FLOW, flowId: 'pcap-0002-abcdef' })
    const again = await postFlow({ ...TCP_FLOW, flowId: 'pcap-0002-abcdef' })
    expect(again.body.data).toMatchObject({ duplicate: true, action: 'BLOCK' })
    expect(await ThreatLog.countDocuments({})).toBe(1)
    expect(await AIPrediction.countDocuments({})).toBe(1)
  })

  test('concurrent requests for one flowId store one prediction and one threat, and both succeed', async () => {
    attack()
    const responses = await Promise.all(
      Array.from({ length: 5 }, () => postFlow({ ...TCP_FLOW, flowId: 'pcap-0003-abcdef' }))
    )
    expect(responses.map((r) => r.status)).toEqual([200, 200, 200, 200, 200])
    expect(new Set(responses.map((r) => String(r.body.data.predictionId))).size).toBe(1)
    expect(await AIPrediction.countDocuments({})).toBe(1)
    expect(await ThreatLog.countDocuments({})).toBe(1)
  })

  test('without flowId nothing changes: two posts are two predictions', async () => {
    await postFlow(TCP_FLOW)
    await postFlow(TCP_FLOW)
    expect(await AIPrediction.countDocuments({})).toBe(2)
  })

  test('a malformed flowId is refused before scoring', async () => {
    for (const flowId of ['short', 'has space in it', '$where:1', 'x'.repeat(129), 12345678, { $ne: null }]) {
      const r = await postFlow({ ...TCP_FLOW, flowId })
      expect(r.status).toBe(400)
    }
    expect(engineCalls).toHaveLength(0)
  })

  test("L2: a flow's own timestamp becomes its threat's eventTime (it used to be dropped)", async () => {
    attack()
    await postFlow({ ...TCP_FLOW, timestamp: '2026-11-20T08:30:00.000Z' })
    const t = await ThreatLog.findOne({}).lean()
    expect(t.eventTime.toISOString()).toBe('2026-11-20T08:30:00.000Z')
    expect(t.createdAt.getTime()).toBeGreaterThan(t.eventTime.getTime())
  })
})
