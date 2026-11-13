'use strict'
/**
 * Capture status, capture provenance labels, learning-evidence sources and the capability report.
 * In-memory MongoDB for the session-labelling paths; no engine, no network.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({
  getDeceptionStats: jest.fn().mockResolvedValue(null),
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}))

const capture = require('../services/captureStatusService')
const { classifySession, externalCollectionAuthorized } = require('../utils/evidenceSource')
const { assessPrediction } = require('../utils/trustAssessment')

describe('capture status', () => {
  beforeEach(() => capture._reset())
  const hb = (over = {}) => ({ mode: 'pcap_replay', status: 'running', counters: { packets: 10, flows: 2 }, ...over })

  test('no heartbeat -> unavailable with a reason', () => {
    expect(capture.getStatus()).toMatchObject({ mode: 'unavailable', fresh: false })
  })

  test('a running replay is reported as pcap_replay, never live', () => {
    capture.recordHeartbeat(hb())
    expect(capture.getStatus()).toMatchObject({ mode: 'pcap_replay', state: 'running', fresh: true })
  })

  test('live passive reports its interface; replays never carry one', () => {
    capture.recordHeartbeat(hb({ mode: 'live_passive', interface: 'eth0' }))
    expect(capture.getStatus().last.interface).toBe('eth0')
    capture.recordHeartbeat(hb({ interface: 'eth0' }))
    expect(capture.getStatus().last.interface).toBeNull()
  })

  test('a stale heartbeat becomes unavailable; a finished replay stays a (finished) replay', () => {
    const t0 = Date.parse('2026-11-13T10:00:00Z')
    capture.recordHeartbeat(hb({ mode: 'live_passive', interface: 'eth0' }), t0)
    expect(capture.getStatus(t0 + capture.FRESH_MS + 1000).mode).toBe('unavailable')
    capture.recordHeartbeat(hb({ status: 'finished' }), t0)
    expect(capture.getStatus(t0 + 10 * capture.FRESH_MS)).toMatchObject({ mode: 'pcap_replay', state: 'finished' })
  })

  test('malformed heartbeats are refused; counters are sanitised', () => {
    expect(capture.recordHeartbeat({ mode: 'live', status: 'running' })).toBeNull()
    expect(capture.recordHeartbeat({ mode: 'pcap_replay', status: 'weird' })).toBeNull()
    const h = capture.recordHeartbeat(hb({ counters: { packets: -5, flows: 'x', posted: 3.7 } }))
    expect(h.counters).toMatchObject({ packets: 0, flows: 0, posted: 3 })
  })

  test('the capture service reporting "unavailable" is shown with its reason', () => {
    capture.recordHeartbeat(hb({ mode: 'live_passive', status: 'unavailable', lastError: 'no Npcap' }))
    expect(capture.getStatus()).toMatchObject({ mode: 'unavailable', reason: 'no Npcap' })
  })
})

describe('Trust Meter capture provenance', () => {
  const base = {
    predictedClass: 'DDoS',
    threatScore: 0.95,
    classProbabilities: { DDoS: 0.95 },
    inputSource: 'network_traffic',
    modelVersion: 'xgb_cicids_v1',
  }
  test.each([
    ['live_passive', 'PROVENANCE_LIVE_PASSIVE', 'LIVE_PASSIVE'],
    ['pcap_replay', 'PROVENANCE_PCAP_REPLAY', 'PCAP_REPLAY'],
    ['dataset_replay', 'PROVENANCE_DATASET_REPLAY', 'DATASET_REPLAY'],
    ['manual', 'PROVENANCE_MANUAL', 'MANUAL'],
    [undefined, 'PROVENANCE_UNKNOWN', 'UNKNOWN'],
  ])('captureSource %p -> %s', (src, code, value) => {
    const a = assessPrediction({ ...base, captureSource: src })
    expect(a.reasons.map((r) => r.code)).toContain(code)
    expect(a.provenance).toBe(value)
  })
})

describe('learning-evidence source', () => {
  test('defaults to unknown; never external without authorised collection', () => {
    expect(classifySession({ sessionId: 's1', sourceIP: '203.0.113.5' }, {})).toBe('unknown')
    expect(externalCollectionAuthorized({ HONEYPOT_EXTERNAL_COLLECTION: 'authorized' })).toBe(false)
  })
  test('operator addresses (IPs or CIDRs) and simulator ids', () => {
    const env = { SENTINEL_OPERATOR_SOURCES: '172.29.32.0/24, 127.0.0.1' }
    expect(classifySession({ sessionId: 's', sourceIP: '172.29.32.17' }, env)).toBe('operator')
    expect(classifySession({ sessionId: 's', sourceIP: '127.0.0.1' }, env)).toBe('operator')
    expect(classifySession({ sessionId: 'arena-12', sourceIP: '203.0.113.5' }, env)).toBe('simulated')
    expect(classifySession({ sessionId: 's', sourceIP: '203.0.113.5' }, env)).toBe('unknown')
  })
  test('external only with the authorisation and a published notice', () => {
    const env = {
      HONEYPOT_EXTERNAL_COLLECTION: 'authorized',
      HONEYPOT_COLLECTION_NOTICE: 'docs/QLEARNING_EVIDENCE.md#notice',
    }
    expect(classifySession({ sessionId: 's', sourceIP: '203.0.113.5' }, env)).toBe('external')
  })
})

describe('session evidence labelling and summary (in-memory DB)', () => {
  const HoneypotSession = require('../models/HoneypotSession')
  const svc = require('../services/honeypotService')
  let mongo
  beforeAll(async () => {
    mongo = await MongoMemoryServer.create()
    await mongoose.connect(mongo.getUri())
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await mongo.stop()
  })

  test('admin relabel needs a valid source and a reason; external needs authorised collection', async () => {
    const s = await HoneypotSession.create({
      sessionId: 'lab-1',
      sourceIP: '203.0.113.9',
      status: 'closed',
      servedProfile: 'ubuntu_22',
    })
    const admin = { _id: new mongoose.Types.ObjectId() }
    await expect(svc.setSessionEvidenceSource(s._id, 'bogus', 'x', admin)).rejects.toMatchObject({ statusCode: 400 })
    await expect(svc.setSessionEvidenceSource(s._id, 'operator', '  ', admin)).rejects.toMatchObject({
      statusCode: 400,
    })
    await expect(svc.setSessionEvidenceSource(s._id, 'external', 'looks external', admin)).rejects.toMatchObject({
      statusCode: 409,
    })
    const u = await svc.setSessionEvidenceSource(s._id, 'operator', 'generated by the project team', admin)
    expect(u.evidenceSource).toBe('operator')
    expect(u.evidenceLabel).toMatchObject({ method: 'admin', reason: 'generated by the project team' })
  })

  test('summary separates sources and personas and excludes demo sessions', async () => {
    await HoneypotSession.create([
      {
        sessionId: 'lab-2',
        sourceIP: '203.0.113.10',
        status: 'closed',
        servedProfile: 'centos_7',
        evidenceSource: 'unknown',
      },
      {
        sessionId: 'demo-1',
        sourceIP: '203.0.113.11',
        status: 'closed',
        servedProfile: 'centos_7',
        evidenceSource: 'simulated',
      },
      { sessionId: 'lab-3', sourceIP: '203.0.113.12', status: 'closed', servedProfile: 'centos_7' },
    ])
    const sum = await svc.getEvidenceSummary()
    expect(sum.bySource).toMatchObject({ operator: 1, unknown: 1, unlabelled: 1 })
    expect(sum.bySource.simulated).toBeUndefined()
    expect(sum.byPersona.centos_7).toMatchObject({ unknown: 1, unlabelled: 1 })
  })

  test('windows_srv can never be recorded as the served persona', async () => {
    await expect(svc.setActiveProfile('windows_srv')).rejects.toMatchObject({ statusCode: 400 })
  })
})

describe('capability report', () => {
  test('every item has a known label; defaults are honest about what is not enabled', async () => {
    capture._reset()
    const { getCapabilities, LABELS } = require('../services/capabilityService')
    const r = await getCapabilities()
    const byId = Object.fromEntries(r.items.map((i) => [i.id, i]))
    for (const i of r.items) expect(Object.keys(LABELS)).toContain(i.label)
    expect(byId.network_capture.label).toBe('implemented_not_enabled')
    expect(byId.host_firewall.label).toBe('implemented_not_enabled')
    expect(byId.host_firewall.summary).toMatch(/SIMULATED/)
    expect(byId.windows_persona.label).toBe('not_implemented')
    expect(byId.session_ml.label).toBe('blocked')
    expect(byId.deception_arena.label).toBe('simulated')
    expect(byId.ml_generalization.facts.promoted).toBe(false)
    expect(byId.auto_block_correlation.facts.policy).toBe('correlated')
  })
})
