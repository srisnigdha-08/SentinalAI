'use strict'
/**
 * Phase 4 audit fixes (docs/HONEYPOT_STUDY_GUIDE.md) on a real in-memory MongoDB:
 * M1 one open threat per IP per window, M2 alert once, M4 capped arrays with totals, M7 persona stamped at
 * session open, H3 hourly cap on honeypot-originated auto-blocks.
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

const mockPredict = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: (...a) => mockPredict(...a),
  getDeceptionScore: jest.fn().mockResolvedValue(null),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.9),
}))
jest.mock('../services/aiService', () => ({ storePrediction: jest.fn().mockResolvedValue({}) }))
jest.mock('../services/campaignService', () => ({ clusterSession: jest.fn() }))
const mockEmitNewThreat = jest.fn()
jest.mock('../websocket/socketManager', () => ({
  emitHoneypotEvent: jest.fn(),
  emitNewThreat: (...a) => mockEmitNewThreat(...a),
  emitThreatUpdated: jest.fn(),
}))
const mockAutoBlock = jest.fn().mockResolvedValue({ success: true })
jest.mock('../services/containmentService', () => ({ executeAutoBlock: (...a) => mockAutoBlock(...a) }))

const HoneypotSession = require('../models/HoneypotSession')
const ThreatLog = require('../models/ThreatLog')
const SystemSetting = require('../models/SystemSetting')
const BlockedIP = require('../models/BlockedIP')
const honeypotService = require('../services/honeypotService')
const collector = require('../../honeypot/collectors/session_collector')

const ENV = [
  'HONEYPOT_MAX_COMMANDS',
  'HONEYPOT_MAX_CREDENTIALS',
  'HONEYPOT_AUTOBLOCK_MAX_PER_HOUR',
  'HONEYPOT_THREAT_WINDOW_MINUTES',
]

describe('Phase 4 honeypot audit fixes', () => {
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
    jest.clearAllMocks()
    for (const k of ENV) delete process.env[k]
    for (const c of ['honeypotsessions', 'threatlogs', 'alerts', 'systemsettings', 'blockedips'])
      await mongoose.connection.db.collection(c).deleteMany({})
    mockPredict.mockResolvedValue({ success: false })
  })

  const open = (sessionId, sourceIP = '198.51.100.30') => collector.onSessionOpened({ sessionId, sourceIP })

  test('M1: repeat connections from one IP share one open threat and announce it once', async () => {
    const a = await open('m1-a')
    const b = await open('m1-b')
    const c = await open('m1-c', '198.51.100.31')
    expect(String(a.linkedThreatLog)).toBe(String(b.linkedThreatLog))
    expect(String(c.linkedThreatLog)).not.toBe(String(a.linkedThreatLog))
    expect(await ThreatLog.countDocuments()).toBe(2)
    expect(mockEmitNewThreat).toHaveBeenCalledTimes(2)
  })

  test('M1: a blocked or expired threat is not reused; window 0 restores one threat per session', async () => {
    const a = await open('m1-blocked')
    await ThreatLog.updateOne({ _id: a.linkedThreatLog }, { $set: { status: 'BLOCKED' } })
    const b = await open('m1-after-block')
    expect(String(b.linkedThreatLog)).not.toBe(String(a.linkedThreatLog))
    process.env.HONEYPOT_THREAT_WINDOW_MINUTES = '0'
    const c = await open('m1-window-0')
    expect(String(c.linkedThreatLog)).not.toBe(String(b.linkedThreatLog))
  })

  test('M2: the same downloaded URL alerts once per session; a different URL alerts again', async () => {
    await open('m2')
    const dl = (url, eventId) => collector.onFileDownload({ sessionId: 'm2', sourceIP: '198.51.100.30', url, eventId })
    await dl('http://x.test/a', 'aaaaaaaaaaaaaaaa')
    await dl('http://x.test/a', 'bbbbbbbbbbbbbbbb') // distinct event, same file
    await dl('http://x.test/b', 'cccccccccccccccc')
    const titles = (await mongoose.connection.db.collection('alerts').find().toArray()).map((a) => a.message)
    expect(titles.sort()).toEqual([
      '198.51.100.30 downloaded http://x.test/a',
      '198.51.100.30 downloaded http://x.test/b',
    ])
    expect((await HoneypotSession.findOne({ sessionId: 'm2' })).downloadCount).toBe(3)
  })

  test('M4: commands and credentials are capped while totals keep counting', async () => {
    process.env.HONEYPOT_MAX_COMMANDS = '3'
    process.env.HONEYPOT_MAX_CREDENTIALS = '10'
    await open('m4')
    for (let i = 0; i < 5; i++)
      await collector.onCommandReceived({ sessionId: 'm4', sourceIP: '198.51.100.30', command: `echo ${i}` })
    let s = await HoneypotSession.findOne({ sessionId: 'm4' })
    expect(s.commands.map((c) => c.command)).toEqual(['echo 0', 'echo 1', 'echo 2'])
    expect(s.commandCount).toBe(5)
    expect(s.engagementLevel).toBe('medium') // from the total (5), not the capped array (3)
    const creds = Array.from({ length: 700 }, (_, i) => ({ username: 'root', password: `p${i}`, success: false }))
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 5, credentials: creds } })
    s = await HoneypotSession.findOne({ sessionId: 'm4' })
    expect(s.credentials).toHaveLength(10)
    expect(s.credentialCount).toBe(700)
    expect(s.credentials.every((c) => c.password === '***REDACTED***')).toBe(true)
  })

  test('M7: the persona served at session open is credited, even if it changes before close', async () => {
    await SystemSetting.create({ key: 'deceptionActiveProfile', value: 'debian_11' })
    const s = await open('m7')
    expect(s.servedProfile).toBe('debian_11')
    await SystemSetting.updateOne({ key: 'deceptionActiveProfile' }, { $set: { value: 'aws_ec2' } })
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 3 } })
    expect((await HoneypotSession.findById(s._id)).servedProfile).toBe('debian_11')
  })

  test('M7: the learner state is the persona of the session that started before, not a later one', async () => {
    const t0 = Date.now()
    await HoneypotSession.create({
      sessionId: 'earlier',
      sourceIP: '198.51.100.40',
      servedProfile: 'raspberry_pi',
      createdAt: new Date(t0 - 60000),
    })
    const s = await HoneypotSession.create({
      sessionId: 'target',
      sourceIP: '198.51.100.40',
      servedProfile: 'centos_7',
      createdAt: new Date(t0 - 30000),
    })
    await HoneypotSession.create({
      sessionId: 'later',
      sourceIP: '198.51.100.40',
      servedProfile: 'ubuntu_22',
      createdAt: new Date(t0),
    })
    const getDeceptionScore = require('../services/aiEngineService').getDeceptionScore
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 3 } })
    expect(getDeceptionScore.mock.calls[0][0]).toMatchObject({
      deceptionProfile: 'centos_7',
      previousProfile: 'raspberry_pi',
    })
  })

  test('H3: honeypot auto-blocks stop at the hourly cap; the threat is kept for manual review', async () => {
    process.env.HONEYPOT_AUTOBLOCK_MAX_PER_HOUR = '2'
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    mockPredict.mockResolvedValue({ success: true, result: { predictedClass: 'RCE Attempt', threatScore: 0.99 } })
    const close = async (sessionId, ip) => {
      const s = await open(sessionId, ip)
      await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 3 } })
    }
    await close('h3-a', '203.0.113.81')
    expect(mockAutoBlock).toHaveBeenCalledTimes(1)
    await BlockedIP.create([
      { ip: '203.0.113.90', reason: 'AI Classifier Autonomous Action (score = 0.99)', blockedAt: new Date() },
      { ip: '203.0.113.91', reason: 'AI Honeypot Session Block (threatScore = 0.99)', blockedAt: new Date() },
    ])
    await close('h3-b', '203.0.113.82')
    expect(mockAutoBlock).toHaveBeenCalledTimes(1) // budget spent: no further block
    const t = await ThreatLog.findOne({ sourceIP: '203.0.113.82' })
    expect(t.status).toBe('MONITORING')
    expect(t.aiScore).toBe(0.99)
  })
})
