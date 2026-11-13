'use strict'
/**
 * Detection-to-containment correlation (services/containmentCorrelationService.js), default policy "correlated".
 * In-memory MongoDB; threats are written directly so each scenario's history is explicit. Nothing touches a
 * firewall: correlation only decides whether a containment request is made.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
// The engine client is replaced: only its two operating lines are read here (test values).
jest.mock('../services/aiEngineService', () => ({
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}))

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const corr = require('../services/containmentCorrelationService')

const LINES = { alertThreshold: 0.9, blockThreshold: 0.92 }
const NOW = new Date('2026-11-13T10:00:00Z')
const deps = (env = {}) => ({ env: { ...env }, realEnforcement: false })
const ago = (s) => new Date(NOW.getTime() - s * 1000)

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
afterEach(async () => {
  await Promise.all([ThreatLog.deleteMany({}), BlockedIP.deleteMany({}), ContainmentAction.deleteMany({})])
})

async function threat(ip, score, secondsAgo, extra = {}) {
  const t = await ThreatLog.create({
    severity: score >= 0.92 ? 'CRITICAL' : 'HIGH', sourceIP: ip, attackType: 'DDoS', aiScore: score,
    confidence: score, status: 'MONITORING', ...extra,
  })
  await ThreatLog.collection.updateOne({ _id: t._id }, { $set: { createdAt: ago(secondsAgo) } })
}
const evalFlow = (ip, score, env, extra = {}) =>
  corr.evaluate({ sourceIP: ip, attackType: 'DDoS', threatScore: score, now: NOW, ...LINES, ...extra }, deps(env))

describe('a single suspicious flow never auto-blocks', () => {
  test('first flow at the block line -> NEEDS_APPROVAL with an explanation', async () => {
    const d = await evalFlow('203.0.113.5', 0.99)
    expect(d.decision).toBe('NEEDS_APPROVAL')
    expect(d.policy).toBe('correlated')
    expect(d.evidence).toMatchObject({ flows: 1, blockLineFlows: 1, windowSeconds: 300 })
    expect(d.reasons.join(' ')).toMatch(/needs 3/)
  })

  test('below the block line -> MONITOR', async () => {
    expect((await evalFlow('203.0.113.5', 0.91)).decision).toBe('MONITOR')
  })
})

describe('correlated evidence', () => {
  test('three flows in the window, two at the block line -> AUTO_BLOCK with evidence', async () => {
    await threat('203.0.113.7', 0.95, 120)
    await threat('203.0.113.7', 0.9, 60)
    const d = await evalFlow('203.0.113.7', 0.97)
    expect(d.decision).toBe('AUTO_BLOCK')
    expect(d.evidence).toMatchObject({ flows: 3, blockLineFlows: 2, attackTypes: ['DDoS'] })
    expect(new Date(d.evidence.firstSeen).getTime()).toBe(ago(120).getTime())
  })

  test('three flows but only one at the block line -> NEEDS_APPROVAL', async () => {
    await threat('203.0.113.8', 0.9, 30)
    await threat('203.0.113.8', 0.91, 20)
    expect((await evalFlow('203.0.113.8', 0.95)).decision).toBe('NEEDS_APPROVAL')
  })

  test('flows outside the window do not count', async () => {
    await threat('203.0.113.9', 0.99, 400)
    await threat('203.0.113.9', 0.99, 350)
    expect((await evalFlow('203.0.113.9', 0.99)).decision).toBe('NEEDS_APPROVAL')
  })

  test('false positives an analyst marked are excluded (benign repeated connections)', async () => {
    await threat('203.0.113.10', 0.99, 30, { status: 'FALSE_POSITIVE' })
    await threat('203.0.113.10', 0.99, 20, { status: 'FALSE_POSITIVE' })
    expect((await evalFlow('203.0.113.10', 0.99)).decision).toBe('NEEDS_APPROVAL')
  })

  test('benign repeated connections below the alert line never accumulate', async () => {
    for (let i = 0; i < 20; i++) await threat('203.0.113.11', 0.5, 10 + i)
    expect((await evalFlow('203.0.113.11', 0.95)).evidence.flows).toBe(1)
  })

  test('distributed activity: many sources with one flow each -> no automatic block for any of them', async () => {
    for (let i = 1; i <= 25; i++) await threat(`198.51.100.${i}`, 0.99, 30)
    const decisions = await Promise.all(Array.from({ length: 25 }, (_, i) => evalFlow(`198.51.100.${i + 26}`, 0.99)))
    expect(decisions.every((d) => d.decision === 'NEEDS_APPROVAL')).toBe(true)
  })

  test('high volume from one source is handled (bounded query) and blocks', async () => {
    await ThreatLog.insertMany(
      Array.from({ length: 800 }, () => ({
        severity: 'CRITICAL', sourceIP: '203.0.113.12', attackType: 'DDoS', aiScore: 0.99, confidence: 0.99, status: 'MONITORING',
      }))
    )
    await ThreatLog.collection.updateMany({}, { $set: { createdAt: ago(5) } })
    const d = await evalFlow('203.0.113.12', 0.99)
    expect(d.decision).toBe('AUTO_BLOCK')
    expect(d.evidence.flows).toBeLessThanOrEqual(501)
  })

  test('thresholds are configurable', async () => {
    await threat('203.0.113.13', 0.99, 10)
    const env = { CORRELATION_MIN_FLOWS: '2', CORRELATION_MIN_BLOCK_LINE_FLOWS: '2' }
    expect((await evalFlow('203.0.113.13', 0.99, env)).decision).toBe('AUTO_BLOCK')
  })

  test('nonsense threshold values fall back to safe defaults (never 1 flow)', async () => {
    const d = await evalFlow('203.0.113.14', 0.99, { CORRELATION_MIN_FLOWS: '1', CORRELATION_WINDOW_SECONDS: '-5' })
    expect(d.decision).toBe('NEEDS_APPROVAL')
    expect(d.evidence.windowSeconds).toBe(300)
  })
})

describe('suppression', () => {
  test('protected targets (loopback, link-local) are never requested', async () => {
    expect((await evalFlow('127.0.0.1', 0.99)).decision).toBe('SUPPRESSED_TRUSTED')
    expect((await evalFlow('169.254.10.10', 0.99)).decision).toBe('SUPPRESSED_TRUSTED')
  })

  test('CONTAINMENT_TRUSTED_IPS accepts addresses and CIDRs (gateways, infrastructure)', async () => {
    const env = { CONTAINMENT_TRUSTED_IPS: '192.0.2.1, 10.20.0.0/16' }
    expect((await evalFlow('192.0.2.1', 0.99, env)).decision).toBe('SUPPRESSED_TRUSTED')
    expect((await evalFlow('10.20.3.4', 0.99, env)).decision).toBe('SUPPRESSED_TRUSTED')
    expect((await evalFlow('10.21.3.4', 0.99, env)).decision).toBe('NEEDS_APPROVAL')
  })

  test('already deny-listed -> SUPPRESSED_DUPLICATE', async () => {
    await BlockedIP.create({ ip: '203.0.113.20', reason: 'test' })
    expect((await evalFlow('203.0.113.20', 0.99)).decision).toBe('SUPPRESSED_DUPLICATE')
  })

  test('a containment request inside the cooldown suppresses a duplicate; a FAILED one does not', async () => {
    await ContainmentAction.collection.insertOne({ containmentId: 'c-21', target: '203.0.113.21', normalizedTarget: '203.0.113.21', enforcementStatus: 'ACTIVE', createdAt: ago(100) })
    expect((await evalFlow('203.0.113.21', 0.99)).decision).toBe('SUPPRESSED_DUPLICATE')
    await ContainmentAction.collection.insertOne({ containmentId: 'c-22', target: '203.0.113.22', normalizedTarget: '203.0.113.22', enforcementStatus: 'FAILED', createdAt: ago(100) })
    expect((await evalFlow('203.0.113.22', 0.99)).decision).toBe('NEEDS_APPROVAL')
  })
})

describe('policies', () => {
  test('single_flow (legacy) auto-blocks on one flow, for simulated enforcement only', async () => {
    expect((await evalFlow('203.0.113.30', 0.95, { AUTO_BLOCK_POLICY: 'single_flow' })).decision).toBe('AUTO_BLOCK')
  })

  test('with a real host-firewall adapter the correlated policy is forced', async () => {
    const d = await corr.evaluate(
      { sourceIP: '203.0.113.31', threatScore: 0.99, now: NOW, ...LINES },
      { env: { AUTO_BLOCK_POLICY: 'single_flow' }, realEnforcement: true }
    )
    expect(d.policy).toBe('correlated')
    expect(d.decision).toBe('NEEDS_APPROVAL')
  })

  test('evaluateSafely fails closed (NEEDS_APPROVAL) when the store errors', async () => {
    const broken = { ...deps(), BlockedIP: { exists: () => Promise.reject(new Error('db down')) } }
    const d = await corr.evaluateSafely({ sourceIP: '203.0.113.32', threatScore: 0.99, now: NOW, ...LINES }, broken)
    expect(d.decision).toBe('NEEDS_APPROVAL')
  })
})

describe('end to end through storePrediction (in-memory DB, auto-block on, mock containment)', () => {
  const aiService = require('../services/aiService')
  const SystemSetting = require('../models/SystemSetting')
  const AIPrediction = require('../models/AIPrediction')
  const containmentService = require('../services/containmentService')

  beforeEach(async () => {
    await SystemSetting.updateOne({ key: 'autoBlockEnabled' }, { $set: { value: true } }, { upsert: true })
    jest.spyOn(containmentService, 'executeAutoBlock').mockResolvedValue({ success: true })
  })
  afterEach(async () => {
    jest.restoreAllMocks()
    await Promise.all([SystemSetting.deleteMany({}), AIPrediction.deleteMany({})])
  })

  const store = (ip, score) =>
    aiService.storePrediction({
      inputSource: 'network_traffic', captureSource: 'pcap_replay', sourceIP: ip, predictedClass: 'DDoS',
      threatScore: score, action: 'BLOCK', modelVersion: 'xgb_cicids_v1',
    })

  test('flow 1 and 2 wait for approval; flow 3 (2 at the block line) requests containment', async () => {
    const ip = '203.0.113.40'
    await store(ip, 0.97)
    await store(ip, 0.95)
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
    const first = await ThreatLog.findOne({ sourceIP: ip }).sort({ createdAt: 1 }).lean()
    expect(first.status).toBe('MONITORING')
    expect(first.containmentDecision.decision).toBe('NEEDS_APPROVAL')
    await store(ip, 0.96)
    expect(containmentService.executeAutoBlock).toHaveBeenCalledTimes(1)
    const last = await ThreatLog.findOne({ sourceIP: ip }).sort({ createdAt: -1 }).lean()
    expect(last.containmentDecision).toMatchObject({ decision: 'AUTO_BLOCK', policy: 'correlated' })
    expect(last.containmentDecision.evidence.flows).toBe(3)
    const pred = await AIPrediction.findOne({ sourceIP: ip }).lean()
    expect(pred.captureSource).toBe('pcap_replay')
  })

  test('auto-block off: the decision is recorded as DISABLED and nothing is requested', async () => {
    await SystemSetting.updateOne({ key: 'autoBlockEnabled' }, { $set: { value: false } })
    await store('203.0.113.41', 0.99)
    const t = await ThreatLog.findOne({ sourceIP: '203.0.113.41' }).lean()
    expect(t.containmentDecision.decision).toBe('DISABLED')
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
  })
})
