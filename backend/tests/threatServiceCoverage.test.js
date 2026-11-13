'use strict'
// These tests cover the single-flow containment mechanics (block, compensation, rollback). They run under the
// explicit legacy policy; the correlated default is covered in tests/containmentCorrelation.test.js.
process.env.AUTO_BLOCK_POLICY = 'single_flow'
/**
 * F-08: services/threatService.js had 67 % line / 42 % branch coverage. In-memory MongoDB; the AI engine
 * threshold, containment and threat-intel enrichment are mocked (no network, no firewall). The thresholds used
 * here are test values passed through the mock, not the deployed operating line.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const mockEngine = { getBlockThreshold: jest.fn() }
jest.mock('../services/aiEngineService', () => mockEngine)
const mockContainment = { executeAutoBlock: jest.fn(), blockThreat: jest.fn() }
jest.mock('../services/containmentService', () => mockContainment)
const mockIntel = { enrichThreat: jest.fn().mockResolvedValue(null) }
jest.mock('../services/threatIntelService', () => mockIntel)
jest.mock('../utils/severity', () => ({ ...jest.requireActual('../utils/severity'), currentAlertLine: () => 0.5 }))

require('../models/User')
const ThreatLog = require('../models/ThreatLog')
const Alert = require('../models/Alert')
const SystemSetting = require('../models/SystemSetting')
const svc = require('../services/threatService')

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})
beforeEach(() => {
  jest.clearAllMocks()
  mockEngine.getBlockThreshold.mockResolvedValue(0.9)
})
afterEach(async () => {
  await Promise.all([ThreatLog.deleteMany({}), Alert.deleteMany({}), SystemSetting.deleteMany({})])
})

const seed = (over = {}) =>
  ThreatLog.create({
    sourceIP: '198.51.100.1',
    attackType: 'DDoS',
    severity: 'HIGH',
    status: 'DETECTED',
    aiScore: 0.4,
    ...over,
  })

describe('findThreats', () => {
  beforeEach(async () => {
    await seed({ sourceIP: '198.51.100.1', severity: 'HIGH', attackType: 'DDoS', createdAt: new Date('2026-10-01') })
    await seed({
      sourceIP: '198.51.100.2',
      severity: 'LOW',
      status: 'RESOLVED',
      attackType: 'Port Scan',
      createdAt: new Date('2026-10-10'),
    })
    await seed({
      sourceIP: '203.0.113.3',
      severity: 'CRITICAL',
      attackType: 'SQL Injection',
      targetService: 'web',
      createdAt: new Date('2026-10-20'),
    })
  })

  test('no filters: everything, newest first, with pagination metadata', async () => {
    const r = await svc.findThreats()
    expect(r.total).toBe(3)
    expect(r.data[0].sourceIP).toBe('203.0.113.3')
    expect(r).toMatchObject({ page: 1, limit: 20 })
  })

  test('severity and status are case-insensitive; unknown values are ignored', async () => {
    expect((await svc.findThreats({ severity: 'high' })).total).toBe(1)
    expect((await svc.findThreats({ status: 'resolved' })).total).toBe(1)
    expect((await svc.findThreats({ severity: 'EXTREME' })).total).toBe(3)
    expect((await svc.findThreats({ severity: { $ne: 'X' }, status: ['DETECTED'] })).total).toBe(3)
  })

  test('type, date range and search (regex-escaped) filters', async () => {
    expect((await svc.findThreats({ type: ' Port Scan ' })).total).toBe(1)
    expect((await svc.findThreats({ startDate: '2026-10-05' })).total).toBe(2)
    expect((await svc.findThreats({ endDate: '2026-10-05' })).total).toBe(1)
    expect((await svc.findThreats({ startDate: '2026-10-05', endDate: '2026-10-15' })).total).toBe(1)
    expect((await svc.findThreats({ startDate: 'not-a-date' })).total).toBe(3)
    expect((await svc.findThreats({ search: '198.51' })).total).toBe(2)
    expect((await svc.findThreats({ search: 'web' })).total).toBe(1)
    expect((await svc.findThreats({ search: '.*' })).total).toBe(0) // literal, not a regex
  })

  test('sort is limited to allowed fields; pagination is capped', async () => {
    const bySev = await svc.findThreats({ sortBy: 'sourceIP', sortOrder: 'asc' })
    expect(bySev.data[0].sourceIP).toBe('198.51.100.1')
    const bogus = await svc.findThreats({ sortBy: '$where', sortOrder: 'asc' })
    expect(bogus.total).toBe(3)
    expect((await svc.findThreats({ limit: 10000 })).limit).toBeLessThanOrEqual(100)
    expect((await svc.findThreats({ page: 2, limit: 2 })).data).toHaveLength(1)
  })
})

describe('createThreat', () => {
  test('manual (non-AI) threat: score 0, DETECTED, no auto-block, no enrichment', async () => {
    const t = await svc.createThreat({ sourceIP: '198.51.100.9', attackType: 'DDoS', severity: 'HIGH', aiScore: 0.99 })
    expect(t.aiScore).toBe(0)
    expect(t.status).toBe('DETECTED')
    expect(mockContainment.executeAutoBlock).not.toHaveBeenCalled()
    await new Promise((r) => setImmediate(r))
    expect(mockIntel.enrichThreat).not.toHaveBeenCalled()
  })

  test('a manual threat may carry an allowed status; an unknown status falls back to DETECTED', async () => {
    expect(
      (await svc.createThreat({ sourceIP: '198.51.100.10', attackType: 'DDoS', severity: 'LOW', status: 'ESCALATED' }))
        .status
    ).toBe('ESCALATED')
    expect(
      (await svc.createThreat({ sourceIP: '198.51.100.11', attackType: 'DDoS', severity: 'LOW', status: 'HACKED' }))
        .status
    ).toBe('DETECTED')
  })

  test('DEGRADED input stays DEGRADED even with a high score', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    const t = await svc.createThreat({
      sourceIP: '198.51.100.12',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.95,
      status: 'DEGRADED',
    })
    expect(t.status).toBe('DEGRADED')
  })

  test('AI score above the alert line, auto-block off: MONITORING, enriched, not blocked', async () => {
    const t = await svc.createThreat({
      sourceIP: '198.51.100.13',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.95,
      confidence: 0.8,
    })
    expect(t.status).toBe('MONITORING')
    expect(t.confidence).toBe(0.8)
    expect(t.autonomousAction.taken).toBe(false)
    expect(mockContainment.executeAutoBlock).not.toHaveBeenCalled()
    await new Promise((r) => setImmediate(r))
    expect(mockIntel.enrichThreat).toHaveBeenCalledTimes(1)
  })

  test('AI score at/above the block line with auto-block on: BLOCKED via executeAutoBlock', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    const t = await svc.createThreat({
      sourceIP: '198.51.100.14',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.9,
    })
    expect(t.status).toBe('BLOCKED')
    expect(t.preBlockStatus).toBe('MONITORING')
    expect(t.autonomousAction).toMatchObject({ taken: true, actionType: 'IP_BLOCKED' })
    expect(mockContainment.executeAutoBlock).toHaveBeenCalledWith(
      expect.objectContaining({ threatScore: 0.9, source: 'AI Engine' })
    )
  })

  test('auto-block failure is logged; the threat is still stored', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    mockContainment.executeAutoBlock.mockRejectedValueOnce(new Error('adapter offline'))
    const t = await svc.createThreat({
      sourceIP: '198.51.100.15',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.97,
    })
    expect(await ThreatLog.findById(t._id)).not.toBeNull()
    expect(require('../utils/logger').error).toHaveBeenCalledWith(expect.stringContaining('adapter offline'))
  })

  test('auto-block setting stored as a non-boolean is treated as off', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: 'true' })
    const t = await svc.createThreat({
      sourceIP: '198.51.100.16',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.99,
    })
    expect(t.status).toBe('MONITORING')
  })

  test('enrichment rejection is swallowed (background)', async () => {
    mockIntel.enrichThreat.mockRejectedValueOnce(new Error('intel down'))
    await svc.createThreat({
      sourceIP: '198.51.100.17',
      attackType: 'DDoS',
      severity: 'HIGH',
      isAiGenerated: true,
      aiScore: 0.6,
    })
    await new Promise((r) => setImmediate(r))
    await new Promise((r) => setImmediate(r))
    expect(require('../utils/logger').debug).toHaveBeenCalledWith(expect.stringContaining('intel down'))
  })
})

describe('update, delete, recent, trend, analytics, block', () => {
  test('updateThreat runs validators; deleteThreat removes the linked alerts only', async () => {
    const t = await seed()
    const other = await seed({ sourceIP: '198.51.100.30' })
    await expect(svc.updateThreat(t._id, { severity: 'EXTREME' })).rejects.toThrow()
    expect((await svc.updateThreat(t._id, { severity: 'LOW' })).severity).toBe('LOW')
    await Alert.create({
      title: 'a',
      message: 'm',
      severity: 'HIGH',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: t._id },
    })
    await Alert.create({
      title: 'b',
      message: 'm',
      severity: 'HIGH',
      type: 'THREAT_DETECTED',
      sourceRef: { refModel: 'ThreatLog', refId: other._id },
    })
    expect(await svc.deleteThreat(t._id)).not.toBeNull()
    expect(await Alert.countDocuments({})).toBe(1)
    expect(await svc.deleteThreat(t._id)).toBeNull()
  })

  test('getRecentThreats clamps the limit to 1..100', async () => {
    await Promise.all([seed(), seed(), seed()])
    expect(await svc.getRecentThreats(2)).toHaveLength(2)
    expect(await svc.getRecentThreats(0)).toHaveLength(3) // 0 -> default 10
    expect(await svc.getRecentThreats(-5)).toHaveLength(1)
    expect(await svc.getRecentThreats('abc')).toHaveLength(3)
  })

  test('getAttackVectorTrend groups by day and type', async () => {
    await seed({ attackType: 'DDoS' })
    await seed({ attackType: 'DDoS' })
    await seed({ attackType: 'Port Scan' })
    const trend = await svc.getAttackVectorTrend(7)
    const ddos = trend.find((r) => r._id.type === 'DDoS')
    expect(ddos.count).toBe(2)
    expect(await svc.getAttackVectorTrend(100000)).toEqual(expect.any(Array))
  })

  test('getDashboardAnalytics returns the full shape with 24 hourly buckets', async () => {
    await seed({ status: 'BLOCKED', severity: 'CRITICAL' })
    await seed()
    const a = await svc.getDashboardAnalytics()
    expect(a.kpis).toMatchObject({ totalToday: 2, totalAllTime: 2, blockedCount: 1, blockRate: 50 })
    expect(a.charts.hourlyToday).toHaveLength(24)
    expect(a.charts.hourlyToday.reduce((sum, h) => sum + h.count, 0)).toBe(2)
    expect(a.intelligence.topSourceIPs).toEqual(expect.any(Array))
  })

  test('blockThreatIP delegates to containmentService.blockThreat with the session', async () => {
    mockContainment.blockThreat.mockResolvedValue({ ok: true })
    await svc.blockThreatIP('id1', 'analyst1', 'sess')
    expect(mockContainment.blockThreat).toHaveBeenCalledWith('id1', 'analyst1', 'Manual threat block', 'sess')
  })
})
