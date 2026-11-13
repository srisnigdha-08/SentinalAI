'use strict'
/**
 * Correlated auto-block, end to end with the shipped DEFAULT policy (no AUTO_BLOCK_POLICY set):
 * storePrediction -> containmentCorrelationService -> executeAutoBlock -> requestContainment -> mock adapter.
 *
 * Unlike tests/containmentCorrelation.test.js (which stubs executeAutoBlock) and the Demo C harness (pinned to
 * AUTO_BLOCK_POLICY=single_flow), nothing on the containment path is stubbed here except the adapter, which is
 * the simulated MockContainmentAdapter or a test double of it. In-memory MongoDB; no firewall, no network.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
// Only the engine's two operating lines are read on this path (test values; the engine itself is not running).
jest.mock('../services/aiEngineService', () => ({
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}))
jest.mock('../websocket/socketManager', () => ({
  emitIPBlocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitAIPrediction: jest.fn(),
  emitContainmentUpdate: jest.fn(),
  emitToRoom: jest.fn(),
}))

const POLICY_KEYS = [
  'AUTO_BLOCK_POLICY',
  'CORRELATION_WINDOW_SECONDS',
  'CORRELATION_MIN_FLOWS',
  'CORRELATION_MIN_BLOCK_LINE_FLOWS',
  'CORRELATION_COOLDOWN_SECONDS',
  'CONTAINMENT_TRUSTED_IPS',
  'CONTAINMENT_BACKEND',
]
const saved = {}
for (const k of POLICY_KEYS) {
  saved[k] = process.env[k]
  delete process.env[k]
}

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const SystemSetting = require('../models/SystemSetting')
const Alert = require('../models/Alert')
const aiService = require('../services/aiService')
const corr = require('../services/containmentCorrelationService')
const factory = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await ContainmentAction.init()
  await BlockedIP.init()
})
afterAll(async () => {
  factory.resetContainmentAdapter()
  for (const k of POLICY_KEYS) if (saved[k] !== undefined) process.env[k] = saved[k]
  await mongoose.disconnect()
  await mongo.stop()
})
beforeEach(async () => {
  factory.resetContainmentAdapter()
  await SystemSetting.updateOne({ key: 'autoBlockEnabled' }, { $set: { value: true } }, { upsert: true })
})
afterEach(async () => {
  delete process.env.CONTAINMENT_TRUSTED_IPS
  await Promise.all(
    [ThreatLog, BlockedIP, ContainmentAction, SystemSetting, Alert, require('../models/AIPrediction')].map((m) =>
      m.deleteMany({})
    )
  )
})

const store = (ip, score) =>
  aiService.storePrediction({
    inputSource: 'network_traffic',
    captureSource: 'pcap_replay',
    sourceIP: ip,
    predictedClass: 'DDoS',
    threatScore: score,
    action: 'BLOCK',
    modelVersion: 'xgb_cicids_v1',
  })
const decisions = async (ip) =>
  (await ThreatLog.find({ sourceIP: ip }).sort({ createdAt: 1, _id: 1 }).lean()).map(
    (t) => t.containmentDecision?.decision
  )
const actionsFor = (ip) => ContainmentAction.find({ normalizedTarget: ip }).lean()

test('the shipped default is the correlated policy with 300 s / 3 flows / 2 at the block line / 600 s cooldown', () => {
  expect(corr.config(process.env)).toMatchObject({
    policy: 'correlated',
    windowSeconds: 300,
    minFlows: 3,
    minBlockLineFlows: 2,
    cooldownSeconds: 600,
    trusted: [],
  })
  expect(factory.getContainmentAdapter().getBackendType()).toBe('mock')
})

test('one suspicious flow never triggers containment, and the decision explains why', async () => {
  const ip = '203.0.113.50'
  await store(ip, 0.99)
  const t = await ThreatLog.findOne({ sourceIP: ip }).lean()
  expect(t.status).toBe('MONITORING')
  expect(t.containmentDecision).toMatchObject({ decision: 'NEEDS_APPROVAL', policy: 'correlated' })
  expect(t.containmentDecision.reasons.join(' ')).toMatch(/only 1 suspicious flow.*needs 3/)
  expect(t.containmentDecision.evidence).toMatchObject({ flows: 1, blockLineFlows: 1 })
  expect(await BlockedIP.countDocuments()).toBe(0)
  expect(await ContainmentAction.countDocuments()).toBe(0)
})

test('three flows, two at the block line: exactly one mock containment, deny-list entry and alert', async () => {
  const ip = '203.0.113.51'
  await store(ip, 0.91) // alert line only
  await store(ip, 0.95)
  expect(await decisions(ip)).toEqual([undefined, 'NEEDS_APPROVAL'])
  await store(ip, 0.97)
  expect(await decisions(ip)).toEqual([undefined, 'NEEDS_APPROVAL', 'AUTO_BLOCK'])

  const blocked = await ThreatLog.findOne({ sourceIP: ip, 'containmentDecision.decision': 'AUTO_BLOCK' }).lean()
  expect(blocked.status).toBe('BLOCKED')
  expect(blocked.containmentDecision.reasons).toEqual([
    '3 suspicious flows from this source in 300 s (needs 3)',
    '2 at or above the block line (needs 2)',
  ])
  expect(blocked.containmentDecision.evidence).toMatchObject({ flows: 3, blockLineFlows: 2, maxScore: 0.97 })
  const actions = await actionsFor(ip)
  expect(actions).toHaveLength(1)
  expect(actions[0]).toMatchObject({ enforcementBackend: 'mock', enforcementStatus: 'ACTIVE' })
  expect(await BlockedIP.countDocuments({ ip })).toBe(1)
  expect(await Alert.countDocuments({ type: 'IP_BLOCKED' })).toBe(1)
})

test('duplicate events after the block are suppressed and never create a second containment action', async () => {
  const ip = '203.0.113.52'
  for (const s of [0.95, 0.96, 0.97]) await store(ip, s)
  for (let i = 0; i < 4; i++) await store(ip, 0.99)
  const d = await decisions(ip)
  expect(d.slice(0, 3)).toEqual(['NEEDS_APPROVAL', 'NEEDS_APPROVAL', 'AUTO_BLOCK'])
  expect(d.slice(3)).toEqual(Array(4).fill('SUPPRESSED_DUPLICATE'))
  const later = await ThreatLog.findOne({ sourceIP: ip }).sort({ _id: -1 }).lean()
  expect(later.containmentDecision.reasons).toEqual(['source is already on the deny-list'])
  expect(later.status).toBe('MONITORING')
  expect(await actionsFor(ip)).toHaveLength(1)
  expect(await BlockedIP.countDocuments({ ip })).toBe(1)
})

test('concurrent flows racing past the threshold produce one active containment and one deny-list entry', async () => {
  const ip = '203.0.113.53'
  await store(ip, 0.95)
  await store(ip, 0.96)
  await Promise.all([store(ip, 0.97), store(ip, 0.98), store(ip, 0.99)])
  // One request wins: one containment action, one deny-list entry, one deny-list alert
  expect(await actionsFor(ip)).toHaveLength(1)
  expect((await actionsFor(ip))[0].enforcementStatus).toBe('ACTIVE')
  expect(await BlockedIP.countDocuments({ ip })).toBe(1)
  const denyAlerts = await Alert.find({ type: 'IP_BLOCKED' }).lean()
  expect(denyAlerts).toHaveLength(1)
  expect(denyAlerts[0].message).not.toMatch(/did not complete/)
  // The losers say what happened instead of claiming a block of their own
  const d = await decisions(ip)
  expect(d.filter((x) => x === 'AUTO_BLOCK')).toHaveLength(1)
  expect(d.filter((x) => x === 'SUPPRESSED_DUPLICATE').length + 1).toBe(d.filter((x) => x !== 'NEEDS_APPROVAL').length)
  const dup = await ThreatLog.findOne({ sourceIP: ip, 'containmentDecision.decision': 'SUPPRESSED_DUPLICATE' }).lean()
  if (dup) expect(dup.containmentDecision.reasons[0]).toMatch(/concurrent request/)
  // The deny-list entry still names the threat that created it
  const entry = await BlockedIP.findOne({ ip }).lean()
  const winner = await ThreatLog.findOne({ sourceIP: ip, 'containmentDecision.decision': 'AUTO_BLOCK' }).lean()
  expect(String(entry.threatRef)).toBe(String(winner._id))
})

test('cooldown: after an unblock the source is not re-blocked inside 600 s, and is again once it has passed', async () => {
  const ip = '203.0.113.54'
  for (const s of [0.95, 0.96, 0.97]) await store(ip, s)
  await BlockedIP.deleteMany({ ip }) // an analyst lifted the deny-list entry; the containment request is recent
  for (const s of [0.95, 0.96, 0.97]) await store(ip, s)
  const after = await ThreatLog.findOne({ sourceIP: ip }).sort({ _id: -1 }).lean()
  expect(after.containmentDecision.decision).toBe('SUPPRESSED_DUPLICATE')
  expect(after.containmentDecision.reasons[0]).toMatch(/within the last 600 s/)
  expect(await BlockedIP.countDocuments({ ip })).toBe(0)

  // Age the request and the earlier flows past the cooldown and the window: fresh evidence is needed again
  const old = new Date(Date.now() - 700 * 1000)
  await ContainmentAction.collection.updateMany({ normalizedTarget: ip }, { $set: { createdAt: old } })
  await ThreatLog.collection.updateMany({ sourceIP: ip }, { $set: { createdAt: old } })
  await ContainmentAction.updateMany({ normalizedTarget: ip }, { $set: { enforcementStatus: 'ROLLED_BACK' } })
  await store(ip, 0.97)
  expect((await ThreatLog.findOne({ sourceIP: ip }).sort({ _id: -1 }).lean()).containmentDecision.decision).toBe(
    'NEEDS_APPROVAL'
  )
  await store(ip, 0.96)
  await store(ip, 0.95)
  expect((await ThreatLog.findOne({ sourceIP: ip }).sort({ _id: -1 }).lean()).containmentDecision.decision).toBe(
    'AUTO_BLOCK'
  )
  expect(await BlockedIP.countDocuments({ ip })).toBe(1)
})

test('trusted CIDRs and protected addresses are never contained, however much evidence there is', async () => {
  process.env.CONTAINMENT_TRUSTED_IPS = '198.51.100.0/24, 192.0.2.10'
  for (const ip of ['198.51.100.77', '192.0.2.10', '127.0.0.1']) {
    for (let i = 0; i < 4; i++) await store(ip, 0.99)
    const d = await decisions(ip)
    expect(new Set(d)).toEqual(new Set(['SUPPRESSED_TRUSTED']))
  }
  const t = await ThreatLog.findOne({ sourceIP: '127.0.0.1' }).lean()
  expect(t.containmentDecision.reasons[0]).toMatch(/protected target/)
  expect(await ContainmentAction.countDocuments()).toBe(0)
  expect(await BlockedIP.countDocuments()).toBe(0)
})

test('many flows below the block line never contain', async () => {
  const ip = '203.0.113.55'
  for (let i = 0; i < 6; i++) await store(ip, 0.91)
  expect(await ContainmentAction.countDocuments()).toBe(0)
  expect(await BlockedIP.countDocuments()).toBe(0)
})

test('a rule that fails post-apply verification is removed, recorded as FAILED, and does not start a cooldown', async () => {
  class Unverifiable extends MockContainmentAdapter {
    constructor() {
      super()
      this.removed = []
    }
    get requiresPostApplyVerification() {
      return true
    }
    async verifyRule() {
      return { exists: false, active: false }
    }
    async removeRule(p) {
      this.removed.push(p.ruleName)
      return super.removeRule(p)
    }
  }
  const adapter = new Unverifiable()
  factory.setContainmentAdapter(adapter)
  const ip = '203.0.113.56'
  for (const s of [0.95, 0.96, 0.97]) await store(ip, s)
  const actions = await actionsFor(ip)
  expect(actions).toHaveLength(1)
  expect(actions[0].enforcementStatus).toBe('FAILED')
  expect(actions[0].failureReason).toMatch(/ENFORCEMENT_NOT_VERIFIED/)
  expect(adapter.removed).toHaveLength(1) // the half-created rule was taken down again
  const alert = await Alert.findOne({ type: 'IP_BLOCKED' }).lean()
  expect(alert.message).toMatch(/adapter enforcement did not complete/)

  // A FAILED request does not suppress a retry on fresh evidence (cooldown ignores FAILED/REJECTED)
  await BlockedIP.deleteMany({ ip })
  factory.resetContainmentAdapter()
  await store(ip, 0.98)
  const retry = await ThreatLog.findOne({ sourceIP: ip }).sort({ _id: -1 }).lean()
  expect(retry.containmentDecision.decision).toBe('AUTO_BLOCK')
  expect((await actionsFor(ip)).filter((a) => a.enforcementStatus === 'ACTIVE')).toHaveLength(1)
})
