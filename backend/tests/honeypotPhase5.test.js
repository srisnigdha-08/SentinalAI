'use strict'
/**
 * Phase 5 improvements (docs/HONEYPOT_STUDY_GUIDE.md) on a real in-memory MongoDB: canary-read alerts,
 * per-command MITRE techniques, client version and TTY-recording capture, attacker profiles by HASSH,
 * block approval mode, and threat-intel enrichment of honeypot threats.
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
jest.mock('../websocket/socketManager', () => ({
  emitHoneypotEvent: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitNewAlert: jest.fn(),
}))
const mockAutoBlock = jest.fn().mockResolvedValue({ success: true })
jest.mock('../services/containmentService', () => ({ executeAutoBlock: (...a) => mockAutoBlock(...a) }))
const mockEnrich = jest.fn().mockResolvedValue(null)
jest.mock('../services/threatIntelService', () => ({ enrichThreat: (...a) => mockEnrich(...a) }))

const HoneypotSession = require('../models/HoneypotSession')
const SystemSetting = require('../models/SystemSetting')
const honeypotService = require('../services/honeypotService')
const collector = require('../../honeypot/collectors/session_collector')

const alerts = () => mongoose.connection.db.collection('alerts').find().toArray()
const flush = () => new Promise((r) => setImmediate(r))

describe('Phase 5 honeypot improvements', () => {
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
    delete process.env.HONEYPOT_AUTOBLOCK_MODE
    for (const c of ['honeypotsessions', 'threatlogs', 'alerts', 'systemsettings', 'blockedips'])
      await mongoose.connection.db.collection(c).deleteMany({})
    mockPredict.mockResolvedValue({ success: false })
  })

  const open = (sessionId, sourceIP = '198.51.100.50') => collector.onSessionOpened({ sessionId, sourceIP })
  const cmd = (sessionId, command, sourceIP = '198.51.100.50') =>
    collector.onCommandReceived({ sessionId, sourceIP, command, intent: collector.classifyIntent(command) })

  test('canary read: credential harvesting, one CRITICAL alert per session, T1552.001 recorded', async () => {
    await open('c1')
    await cmd('c1', 'cat /root/.aws/credentials')
    await cmd('c1', 'cat ~/.ssh/id_rsa')
    const canary = (await alerts()).filter((a) => a.title === 'Canary file read')
    expect(canary).toHaveLength(1)
    expect(canary[0].severity).toBe('CRITICAL')
    const s = await HoneypotSession.findOne({ sessionId: 'c1' })
    expect(s.commands.every((c) => c.intent === 'CREDENTIAL_HARVEST')).toBe(true)
    expect(s.mitreTechniques.map((t) => t.id)).toEqual(expect.arrayContaining(['T1003', 'T1552.001']))
    expect(s.filesAccessed).toContain('/.aws/credentials')
  })

  test('per-command MITRE techniques accumulate with intent techniques', async () => {
    await open('m1')
    for (const c of ['uname -a', 'whoami', 'cat /etc/shadow', '(crontab -l; echo x) | crontab -']) await cmd('m1', c)
    const ids = (await HoneypotSession.findOne({ sessionId: 'm1' })).mitreTechniques.map((t) => t.id)
    expect(ids).toEqual(expect.arrayContaining(['T1082', 'T1033', 'T1003.008', 'T1053.003', 'T1595', 'T1003']))
    expect(new Set(ids).size).toBe(ids.length)
  })

  test('client version arrives with the HASSH; an empty close-time HASSH does not erase it; TTY log kept', async () => {
    const s = await open('v1')
    await collector.onClientKex({ sessionId: 'v1', hassh: 'ab'.repeat(16), clientVersion: 'SSH-2.0-libssh_0.9.6' })
    const ttylog = { sha256: 'c'.repeat(64), size: 1982, path: 'var/lib/cowrie/tty/' + 'c'.repeat(64) }
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 4, hassh: '', ttylog } })
    const done = await HoneypotSession.findById(s._id)
    expect(done).toMatchObject({ hassh: 'ab'.repeat(16), clientVersion: 'SSH-2.0-libssh_0.9.6' })
    expect(done.ttylog.toObject()).toEqual(ttylog)
  })

  test('attacker profiles group sessions by HASSH with IPs, banners, usernames and commands', async () => {
    const mk = async (sessionId, ip, hassh, clientVersion, username, commands, success) =>
      HoneypotSession.create({
        sessionId,
        sourceIP: ip,
        hassh,
        clientVersion,
        credentials: [{ username, password: '***REDACTED***', success }],
        commands: commands.map((command) => ({ command })),
      })
    await mk('a1', '203.0.113.1', 'h-bot', 'SSH-2.0-Go', 'root', ['uname -a'], true)
    await mk('a2', '203.0.113.2', 'h-bot', 'SSH-2.0-Go', 'root', ['uname -a', 'nproc'], false)
    await mk('a3', '203.0.113.3', 'h-human', 'SSH-2.0-OpenSSH_9.6', 'admin', ['ls'], true)
    await mk('a4', '203.0.113.4', null, null, 'pi', [], false) // no HASSH: not profiled
    const profiles = await honeypotService.getAttackerProfiles({ days: 7 })
    expect(profiles.map((p) => p.hassh)).toEqual(['h-bot', 'h-human'])
    expect(profiles[0]).toMatchObject({
      sessions: 2,
      distinctIPs: 2,
      clientVersions: ['SSH-2.0-Go'],
      topUsernames: [{ value: 'root', count: 2 }],
      topCommands: [
        { value: 'uname -a', count: 2 },
        { value: 'nproc', count: 1 },
      ],
      loggedInSessions: 1,
    })
  })

  test('approval mode: a block-worthy session raises one approval alert and no block', async () => {
    process.env.HONEYPOT_AUTOBLOCK_MODE = 'approve'
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    mockPredict.mockResolvedValue({ success: true, result: { predictedClass: 'RCE Attempt', threatScore: 0.99 } })
    for (const id of ['p1', 'p2']) {
      const s = await open(id, '203.0.113.70') // same IP: shared threat (M1)
      await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 3 } })
    }
    expect(mockAutoBlock).not.toHaveBeenCalled()
    const approval = (await alerts()).filter((a) => a.title === 'Honeypot block awaiting approval')
    expect(approval).toHaveLength(1)
    expect(approval[0]).toMatchObject({ type: 'AUTONOMOUS_ACTION', severity: 'HIGH' })
    expect(approval[0].message).toMatch(/HONEYPOT_AUTOBLOCK_MODE=approve/)
  })

  test('auto mode still blocks; alert-level honeypot threats are sent for threat-intel enrichment', async () => {
    await SystemSetting.create({ key: 'autoBlockEnabled', value: true })
    mockPredict.mockResolvedValue({ success: true, result: { predictedClass: 'RCE Attempt', threatScore: 0.99 } })
    const s = await open('e1', '203.0.113.71')
    await honeypotService.closeSession(s._id, { telemetry: { durationSeconds: 3 } })
    await flush()
    expect(mockAutoBlock).toHaveBeenCalledTimes(1)
    expect(mockEnrich).toHaveBeenCalledTimes(1)
    expect(mockEnrich.mock.calls[0][0].sourceIP).toBe('203.0.113.71')

    mockPredict.mockResolvedValue({ success: true, result: { predictedClass: 'BENIGN', threatScore: 0.4 } })
    const low = await open('e2', '203.0.113.72')
    await honeypotService.closeSession(low._id, { telemetry: { durationSeconds: 3 } })
    await flush()
    expect(mockEnrich).toHaveBeenCalledTimes(1) // below the alert line: not enriched
  })
})
