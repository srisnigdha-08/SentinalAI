'use strict'
/**
 * M2: honeypot activity is recorded with one atomic pipeline update (no lost updates, attacker strings
 * stored literally). M12: stale "active" sessions are closed by the sweep with their real duration, and
 * session start time comes from Cowrie's event time. Real in-memory MongoDB.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: jest.fn().mockResolvedValue(null),
  getDeceptionScore: jest.fn().mockResolvedValue(null),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.7),
}))
jest.mock('../services/campaignService', () => ({ clusterSession: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ emitHoneypotEvent: jest.fn(), emitNewThreat: jest.fn() }))

const HoneypotSession = require('../models/HoneypotSession')
const honeypotService = require('../services/honeypotService')
const { HoneypotSweepService } = require('../services/honeypotSweepService')
const collector = require('../../honeypot/collectors/session_collector')

describe('atomic honeypot activity and stale-session sweep', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })
  beforeEach(async () => {
    await mongoose.connection.db.collection('honeypotsessions').deleteMany({})
    await mongoose.connection.db.collection('threatlogs').deleteMany({})
    await mongoose.connection.db.collection('alerts').deleteMany({})
  })

  const newSession = (sessionId, extra = {}) =>
    HoneypotSession.create({ sessionId, sourceIP: '198.51.100.20', status: 'active', ...extra })

  test('M2: 25 concurrent commands are all kept and the score is computed from all of them', async () => {
    await newSession('concurrent')
    await Promise.all(
      Array.from({ length: 25 }, (_, i) =>
        collector.onCommandReceived({
          sessionId: 'concurrent',
          sourceIP: '198.51.100.20',
          command: i === 0 ? 'cat /etc/passwd' : `echo ${i}`,
          intent: i === 0 ? 'CREDENTIAL_HARVEST' : 'UNKNOWN',
        })
      )
    )
    const s = await HoneypotSession.findOne({ sessionId: 'concurrent' })
    expect(s.commands).toHaveLength(25)
    expect(s.filesAccessed).toEqual(['/etc/passwd'])
    expect(s.deceptionScore).toBe(Math.min(100, 25 * 3 + 10)) // 85
    expect(s.engagementLevel).toBe('deep')
    expect(s.mitreTechniques.length).toBeGreaterThan(0)
  })

  test('M2: attacker strings that look like operators are stored as text', async () => {
    await newSession('literal')
    await honeypotService.recordSessionActivity(
      { sessionId: 'literal' },
      { commands: [{ command: '$commands', timestamp: new Date(), success: true, intent: null }], urls: ['$sessionId'] }
    )
    const s = await HoneypotSession.findOne({ sessionId: 'literal' }).lean()
    expect(s.commands[0].command).toBe('$commands')
    expect(s.iocExtracted.urls).toEqual(['$sessionId'])
    expect(s.sessionId).toBe('literal')
  })

  test('M2: download bonus is kept when later commands arrive', async () => {
    await newSession('download')
    await collector.onFileDownload({
      sessionId: 'download',
      sourceIP: '198.51.100.20',
      url: 'http://x.test/a',
      sha256: 'ab',
    })
    let s = await HoneypotSession.findOne({ sessionId: 'download' })
    expect(s.downloadCount).toBe(1)
    expect(s.deceptionScore).toBe(8 + 15)
    await collector.onCommandReceived({
      sessionId: 'download',
      sourceIP: '198.51.100.20',
      command: 'id',
      intent: 'RECONNAISSANCE',
    })
    s = await HoneypotSession.findOne({ sessionId: 'download' })
    expect(s.deceptionScore).toBe(3 + 8 + 15) // previously the +15 was lost on the next command
    expect(s.iocExtracted.hashes).toEqual(['ab'])
  })

  test('M6: honeypot analytics only aggregate the 7-day reporting window', async () => {
    await newSession('recent', { commands: [{ command: 'id' }], deceptionScore: 10 })
    await newSession('ancient', { commands: [{ command: 'old-cmd' }], sourceIP: '203.0.113.99', deceptionScore: 90 })
    await mongoose.connection.db
      .collection('honeypotsessions')
      .updateOne({ sessionId: 'ancient' }, { $set: { createdAt: new Date(Date.now() - 30 * 86400000) } })

    const analytics = await honeypotService.getFullAnalytics()
    expect(analytics.charts.topCommands.map((c) => c._id)).toEqual(['id'])
    expect(analytics.intelligence.topAttackers.map((a) => a._id)).toEqual(['198.51.100.20'])
    expect(analytics.kpis.avgDeceptionScore).toBe(10)
    expect(analytics.reporting.analyticsWindow.days).toBe(7)
  })

  test('M12: session start time comes from the Cowrie event, not ingestion time', async () => {
    await collector.onSessionOpened({
      sessionId: 'replayed',
      sourceIP: '198.51.100.21',
      startTime: '2017-07-07T13:30:00Z',
    })
    const s = await HoneypotSession.findOne({ sessionId: 'replayed' })
    expect(s.startTime.toISOString()).toBe('2017-07-07T13:30:00.000Z')
  })

  test('M12: the sweep closes only stale active sessions, with duration up to the last activity', async () => {
    const start = new Date(Date.now() - 10 * 3600 * 1000)
    const lastActivity = new Date(start.getTime() + 120 * 1000)
    await newSession('stale', { startTime: start })
    await newSession('fresh')
    // Backdate updatedAt directly; Mongoose timestamps would otherwise reset it.
    await mongoose.connection.db
      .collection('honeypotsessions')
      .updateOne({ sessionId: 'stale' }, { $set: { updatedAt: lastActivity } })

    const result = await new HoneypotSweepService({ staleHours: 6 }).sweepStaleSessions()
    expect(result).toEqual({ found: 1, closed: 1, failed: 0 })
    const stale = await HoneypotSession.findOne({ sessionId: 'stale' })
    expect(stale.status).toBe('closed')
    expect(stale.closureAnalysisState).toBe('complete')
    expect(stale.durationSeconds).toBe(120)
    expect((await HoneypotSession.findOne({ sessionId: 'fresh' })).status).toBe('active')
  })
})
