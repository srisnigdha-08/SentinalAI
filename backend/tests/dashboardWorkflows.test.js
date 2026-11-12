'use strict'
/**
 * The four dashboard workflows: Export Report (GET /api/reports/security-summary), Adaptive Deception refresh
 * (GET /api/honeypot/deception/status + recommendation reuse), Campaigns Refresh Feed (GET /api/campaigns/summary)
 * and Edit User (PUT /api/users/:id). In-memory MongoDB; only authentication, the socket layer and the AI engine
 * are stubbed. Every record here is disposable test data.
 */
process.env.NODE_ENV = 'test'

const express = require('express')
const request = require('supertest')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ disconnectUser: jest.fn(), emitNewThreat: jest.fn() }))
jest.mock('../services/aiEngineService', () => ({
  getHealth: jest.fn(async () => ({ status: 'ok' })),
  getDeceptionRecommendation: jest.fn(async () => ({
    nextProfile: 'ubuntu_22',
    explored: false,
    policy: 'q_learning',
    learnerStats: { provenance: { seedEpisodes: 500, sessionEpisodes: 3, synthetic: true } },
  })),
}))
jest.mock('../middleware/auth', () => ({
  protect: (req, res, next) =>
    req.headers['x-test-role']
      ? ((req.user = {
          role: req.headers['x-test-role'],
          _id: req.headers['x-test-user'] || '000000000000000000000001',
          name: 'Test Operator',
          email: 'operator@sentinel.test',
          status: 'active',
        }),
        next())
      : res.status(401).json({ success: false, error: 'Not authenticated' }),
  restrictTo:
    (...roles) =>
    (req, res, next) =>
      roles.includes(req.user.role) ? next() : res.status(403).json({ success: false, error: 'Access denied' }),
  requirePermission: () => (req, res, next) => next(),
}))

const ThreatLog = require('../models/ThreatLog')
const HoneypotSession = require('../models/HoneypotSession')
const Campaign = require('../models/Campaign')
const BlockedIP = require('../models/BlockedIP')
const DeceptionDecision = require('../models/DeceptionDecision')
const User = require('../models/User')
const AuthSession = require('../models/AuthSession')
const AuditLog = require('../models/AuditLog')
const aiEngine = require('../services/aiEngineService')
const { errorHandler } = require('../middleware/errorHandler')
const { PdfDocument } = require('../utils/pdfWriter')
const { csvCell } = require('../services/reportService')

const app = express()
  .use(express.json())
  .use('/api/reports', require('../routes/reports'))
  .use('/api/campaigns', require('../routes/campaigns'))
  .use('/api/honeypot', require('../routes/honeypot'))
  .use('/api/users', require('../routes/users'))
app.use(errorHandler || ((err, req, res, _next) => res.status(err.statusCode || 500).json({ success: false })))

let mongo
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})

const as = (role, userId) => (req) => {
  req.set('x-test-role', role)
  if (userId) req.set('x-test-user', String(userId))
  return req
}
const getBinary = (req) =>
  req.buffer(true).parse((res, cb) => {
    const chunks = []
    res.on('data', (c) => chunks.push(c))
    res.on('end', () => cb(null, Buffer.concat(chunks)))
  })

/** Structural PDF check: header, EOF, and every xref offset pointing at its "N 0 obj". */
function assertValidPdf(buf) {
  const text = buf.toString('latin1')
  expect(text.startsWith('%PDF-1.4')).toBe(true)
  expect(text.trimEnd().endsWith('%%EOF')).toBe(true)
  const startxref = Number(/startxref\n(\d+)\n%%EOF/.exec(text)[1])
  expect(text.slice(startxref, startxref + 4)).toBe('xref')
  const [, count] = /xref\n0 (\d+)\n/.exec(text.slice(startxref)).map(Number)
  const entries = text
    .slice(startxref)
    .split('\n')
    .slice(3, 2 + count)
  entries.forEach((line, i) => {
    const offset = Number(line.slice(0, 10))
    expect(text.slice(offset, offset + `${i + 1} 0 obj`.length)).toBe(`${i + 1} 0 obj`)
  })
  return text
}

describe('PDF writer', () => {
  test('produces a structurally valid multi-page PDF with escaped text', () => {
    const doc = new PdfDocument({ title: 'T (1)' })
    doc.text('Hello (world) \\ back')
    for (let i = 0; i < 120; i++) doc.text(`line ${i}`)
    const text = assertValidPdf(doc.toBuffer({ footer: 'footer' }))
    expect(text).toContain('Hello \\(world\\) \\\\ back')
    expect(/\/Count (\d+)/.exec(text)[1]).toBe('3')
    expect(text).toContain('Page 3 of 3')
  })

  test('CSV cells are quoted and spreadsheet formulas neutralised', () => {
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`)
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell(null)).toBe('')
    expect(csvCell(-5)).toBe("'-5")
  })
})

describe('Export Report: GET /api/reports/security-summary', () => {
  beforeAll(async () => {
    const now = Date.now()
    await ThreatLog.create([
      {
        severity: 'CRITICAL',
        sourceIP: '203.0.113.10',
        attackType: 'SSH Brute Force',
        status: 'BLOCKED',
        aiScore: 0.97,
      },
      { severity: 'HIGH', sourceIP: '203.0.113.11', attackType: 'SSH Brute Force', status: 'DETECTED', aiScore: 0.81 },
      { severity: 'LOW', sourceIP: '203.0.113.12', attackType: 'Port Scan', status: 'RESOLVED', aiScore: 0.2 },
    ])
    // Outside a 7-day window: counts all-time only
    await ThreatLog.collection.insertOne({
      severity: 'MEDIUM',
      sourceIP: '198.51.100.9',
      attackType: 'DDoS',
      status: 'BLOCKED',
      createdAt: new Date(now - 40 * 86400000),
      updatedAt: new Date(now - 40 * 86400000),
    })
    await BlockedIP.create({ ip: '203.0.113.10' })
    await HoneypotSession.create([
      {
        sessionId: 'real-1',
        sourceIP: '203.0.113.10',
        credentials: [{ username: 'root', password: 'hunter2-captured', success: true }],
      },
      { sessionId: 'demo-1', sourceIP: '203.0.113.99', status: 'closed' },
    ])
    await Campaign.create({ campaignId: 'CMP-1', sourceIPs: ['203.0.113.10'], lastSeen: new Date() })
  })

  test('admin downloads a valid PDF whose figures match the database', async () => {
    const res = await getBinary(as('admin')(request(app).get('/api/reports/security-summary?days=7&format=pdf')))
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toBe('application/pdf')
    expect(res.headers['cache-control']).toBe('no-store')
    expect(res.headers['content-disposition']).toMatch(
      /^attachment; filename="sentinelai-security-report-7d-[\d_-]+\.pdf"$/
    )
    const text = assertValidPdf(res.body)
    expect(text).toContain('Detections in period: 3 \\(all time: 4\\)')
    expect(text).toContain('Threats blocked in period: 1 \\(33.3% of detections in period\\)')
    expect(text).toContain('IP addresses currently on the deny list: 1')
    expect(text).toContain('Sessions in period: 2 \\(of which synthetic demo sessions: 1\\)')
    expect(text).toContain('AI engine \\(readiness probe at export\\): CONNECTED')
    expect(text).toContain('SSH-COWRIE-01')
    expect(text).toContain('Reporting period: last 7 calendar day')
    // Captured attacker passwords and account secrets never appear
    expect(text).not.toMatch(/hunter2|password|token|secret/i)
  })

  test('JSON figures equal direct database counts; analyst may export', async () => {
    const res = await as('analyst')(request(app).get('/api/reports/security-summary?format=json&days=30'))
    expect(res.status).toBe(200)
    const r = res.body.data
    expect(r.period.days).toBe(30)
    expect(r.detections.inPeriod).toBe(3)
    expect(r.detections.allTime).toBe(await ThreatLog.countDocuments())
    expect(r.detections.bySeverity).toEqual([
      { severity: 'CRITICAL', count: 1 },
      { severity: 'HIGH', count: 1 },
      { severity: 'MEDIUM', count: 0 },
      { severity: 'LOW', count: 1 },
    ])
    expect(r.detections.byType[0]).toEqual({ type: 'SSH Brute Force', count: 2 })
    expect(r.containment.blockedThreatsAllTime).toBe(2)
    expect(r.honeypot).toMatchObject({
      sessionsInPeriod: 2,
      uniqueSourceIPsInPeriod: 2,
      successfulLoginSessionsInPeriod: 1,
    })
    expect(r.recentEvents).toHaveLength(3)
    expect(JSON.stringify(r)).not.toMatch(/hunter2/)
  })

  test('CSV export is a valid attachment', async () => {
    const res = await getBinary(as('admin')(request(app).get('/api/reports/security-summary?format=csv&days=1')))
    expect(res.status).toBe(200)
    expect(res.headers['content-type']).toMatch(/^text\/csv/)
    expect(res.headers['content-disposition']).toMatch(/\.csv"$/)
    const csv = res.body.toString('utf8')
    expect(csv.charCodeAt(0)).toBe(0xfeff) // UTF-8 BOM so spreadsheets read the file as UTF-8
    expect(csv.slice(1)).toMatch(/^section,metric,value\r\n/)
    expect(csv).toContain('detections,in_period,3')
  })

  test('viewer is refused, unauthenticated is refused, bad parameters are 400', async () => {
    expect((await as('viewer')(request(app).get('/api/reports/security-summary'))).status).toBe(403)
    expect((await request(app).get('/api/reports/security-summary')).status).toBe(401)
    expect((await as('admin')(request(app).get('/api/reports/security-summary?days=5'))).status).toBe(400)
    expect((await as('admin')(request(app).get('/api/reports/security-summary?format=exe'))).status).toBe(400)
  })

  test('AI engine down still yields a report that says so', async () => {
    aiEngine.getHealth.mockResolvedValueOnce({ status: 'unreachable' })
    const res = await as('admin')(request(app).get('/api/reports/security-summary?format=json'))
    expect(res.status).toBe(200)
    expect(res.body.data.system.aiEngine).toBe('unreachable')
  })

  test('database failure is a 500 without a partial file', async () => {
    const spy = jest.spyOn(ThreatLog, 'countDocuments').mockRejectedValueOnce(new Error('db down'))
    const res = await as('admin')(request(app).get('/api/reports/security-summary'))
    spy.mockRestore()
    expect(res.status).toBe(500)
    expect(res.headers['content-type']).toMatch(/json/)
  })

  test('export writes nothing except its audit entry', async () => {
    const before = await Promise.all([ThreatLog, HoneypotSession, Campaign, BlockedIP].map((m) => m.countDocuments()))
    await getBinary(as('admin')(request(app).get('/api/reports/security-summary')))
    const after = await Promise.all([ThreatLog, HoneypotSession, Campaign, BlockedIP].map((m) => m.countDocuments()))
    expect(after).toEqual(before)
    expect(await AuditLog.countDocuments({ action: 'REPORT_EXPORTED' })).toBeGreaterThan(0)
  })
})

describe('Empty database report', () => {
  test('all figures are zero and tables say there are no records', async () => {
    await mongoose.connection.db.dropDatabase()
    const res = await getBinary(as('admin')(request(app).get('/api/reports/security-summary')))
    expect(res.status).toBe(200)
    const text = assertValidPdf(res.body)
    expect(text).toContain('Detections in period: 0 \\(all time: 0\\)')
    expect(text).toContain('\\(no records in this period\\)')
  })
})

describe('Campaigns Refresh Feed: GET /api/campaigns/summary', () => {
  beforeAll(async () => {
    await mongoose.connection.db.dropDatabase()
    const s = await HoneypotSession.create([
      { sessionId: 'c-1', sourceIP: '203.0.113.1' },
      { sessionId: 'c-2', sourceIP: '203.0.113.2' },
      { sessionId: 'c-3', sourceIP: '203.0.113.3' },
    ])
    await Campaign.create([
      {
        campaignId: 'CMP-A',
        sessions: [s[0]._id, s[1]._id],
        sourceIPs: ['203.0.113.1', '203.0.113.2'],
        maxDeceptionScore: 40,
      },
      { campaignId: 'CMP-B', sessions: [s[2]._id], sourceIPs: ['203.0.113.2', '203.0.113.3'], maxDeceptionScore: 75 },
    ])
  })

  test('totals cover every campaign and are consistent with the rows', async () => {
    const [sum, list] = await Promise.all([
      as('viewer')(request(app).get('/api/campaigns/summary')),
      as('viewer')(request(app).get('/api/campaigns')),
    ])
    expect(sum.status).toBe(200)
    expect(sum.headers['cache-control']).toBe('no-store')
    expect(sum.body.data).toMatchObject({
      total: 2,
      clusteredIPs: 3,
      maxDeceptionScore: 75,
      sessionTotal: 3,
      avgSessionsPerCampaign: 1.5,
    })
    expect(list.body.data).toHaveLength(sum.body.data.total)
    expect(list.body.data.reduce((n, c) => n + c.sessions.length, 0)).toBe(sum.body.data.sessionTotal)
  })

  test('refresh reflects new backend data, is unchanged otherwise, and never writes', async () => {
    const first = (await as('analyst')(request(app).get('/api/campaigns/summary'))).body.data
    const again = (await as('analyst')(request(app).get('/api/campaigns/summary'))).body.data
    expect(again).toEqual(first)
    expect(await Campaign.countDocuments()).toBe(2)
    await Campaign.create({ campaignId: 'CMP-C', sourceIPs: ['198.51.100.7'], maxDeceptionScore: 10 })
    const after = (await as('analyst')(request(app).get('/api/campaigns/summary'))).body.data
    expect(after.total).toBe(3)
    expect(after.clusteredIPs).toBe(4)
    const ids = (await as('analyst')(request(app).get('/api/campaigns'))).body.data.map((c) => c.campaignId)
    expect(new Set(ids).size).toBe(ids.length)
  })

  test('empty database and unauthenticated access', async () => {
    await Campaign.deleteMany({})
    const res = await as('viewer')(request(app).get('/api/campaigns/summary'))
    expect(res.body.data).toMatchObject({ total: 0, clusteredIPs: 0, avgSessionsPerCampaign: 0, latestLastSeen: null })
    expect((await request(app).get('/api/campaigns/summary')).status).toBe(401)
  })
})

describe('Adaptive Deception refresh', () => {
  beforeAll(async () => {
    await mongoose.connection.db.dropDatabase()
    await DeceptionDecision.syncIndexes()
    await DeceptionDecision.create({
      decisionId: 'old-applied-decision',
      state: 'debian_11',
      action: 'centos_7',
      status: 'APPLIED',
      appliedProfile: 'centos_7',
      closedAt: new Date(Date.now() - 60000),
    })
    await HoneypotSession.create([
      {
        sessionId: 'real-scored',
        sourceIP: '203.0.113.5',
        deceptionScoredAt: new Date(),
        recommendedProfile: 'ubuntu_22',
        deceptionPolicy: 'q_learning',
        shadowPolicy: { version: 'persona-ducb-v2', mode: 'shadow', recommendation: 'ubuntu_22', learned: true },
      },
      { sessionId: 'demo-synthetic', sourceIP: '203.0.113.6' },
    ])
  })

  test('status is read-only and reports closed decision, learning counts and v2 shadow', async () => {
    const res = await as('analyst')(request(app).get('/api/honeypot/deception/status'))
    expect(res.status).toBe(200)
    const d = res.body.data
    expect(d.activeProfile).toBe('centos_7')
    expect(d.profileSource).toBe('default')
    expect(d.pendingDecision).toBeNull()
    expect(d.lastClosedDecision).toMatchObject({ decisionId: 'old-applied-decision', status: 'APPLIED' })
    expect(d.learning).toEqual({ scoredRealSessions: 1, syntheticSessionsSkipped: 1, sessionsAwaitingScoring: 0 })
    expect(d.shadow).toMatchObject({ sessionsWithEvidence: 1, agreementsWithActivePolicy: 1 })
    expect(d.shadow.latest).toMatchObject({ recommendation: 'ubuntu_22', version: 'persona-ducb-v2' })
    expect(aiEngine.getDeceptionRecommendation).not.toHaveBeenCalled()
    expect(await DeceptionDecision.countDocuments()).toBe(1)
  })

  test('repeated refreshes reuse the single pending decision and draw from the learner only once', async () => {
    aiEngine.getDeceptionRecommendation.mockClear()
    const ids = []
    for (let i = 0; i < 4; i++) {
      const [rec, status] = await Promise.all([
        as('admin')(request(app).get('/api/honeypot/deception/recommendation')),
        as('admin')(request(app).get('/api/honeypot/deception/status')),
      ])
      expect(rec.status).toBe(200)
      expect(status.status).toBe(200)
      ids.push(rec.body.data.decisionId)
      expect(rec.body.data.decisionStatus).toBe('PENDING')
      expect(rec.body.data.profileSource).toBe('default')
    }
    expect(new Set(ids).size).toBe(1)
    expect(aiEngine.getDeceptionRecommendation).toHaveBeenCalledTimes(1)
    expect(await DeceptionDecision.countDocuments({ status: 'PENDING' })).toBe(1)
    const status = (await as('admin')(request(app).get('/api/honeypot/deception/status'))).body.data
    expect(status.pendingDecision).toMatchObject({ decisionId: ids[0], forActivePersona: true })
    // The served persona is unchanged: refreshing never records a rotation
    expect((await as('admin')(request(app).get('/api/honeypot/deception/profile'))).body.data.profile).toBe('centos_7')
  })

  test('viewer and unauthenticated callers cannot read decision state; engine outage is a 503', async () => {
    expect((await as('viewer')(request(app).get('/api/honeypot/deception/status'))).status).toBe(403)
    expect((await request(app).get('/api/honeypot/deception/status')).status).toBe(401)
    await DeceptionDecision.deleteMany({ status: 'PENDING' })
    aiEngine.getDeceptionRecommendation.mockResolvedValueOnce(null)
    expect((await as('admin')(request(app).get('/api/honeypot/deception/recommendation'))).status).toBe(503)
    expect((await as('admin')(request(app).get('/api/honeypot/deception/status'))).status).toBe(200)
  })
})

describe('Edit User: PUT /api/users/:id', () => {
  let admin
  let admin2
  let viewer
  beforeEach(async () => {
    await mongoose.connection.db.dropDatabase()
    ;[admin, admin2, viewer] = await User.create([
      { name: 'Admin One', email: 'admin1@sentinel.test', password: 'AdminPassword123!', role: 'admin' },
      {
        name: 'Admin Two',
        email: 'admin2@sentinel.test',
        password: 'AdminPassword123!',
        role: 'admin',
        status: 'inactive',
      },
      { name: 'Viewer User', email: 'viewer@sentinel.test', password: 'ViewerPassword123!', role: 'viewer' },
    ])
    await AuthSession.create({
      _id: 'viewer-session',
      user: viewer._id,
      authVersion: 0,
      refreshHash: 'x',
      expiresAt: new Date(Date.now() + 86400000),
      lastUsedAt: new Date(),
    })
  })
  const put = (id, body, actor = admin) => as('admin', actor._id)(request(app).put(`/api/users/${id}`)).send(body)

  test('valid profile edit persists and returns no secrets', async () => {
    const res = await put(viewer._id, {
      name: '  Renamed Viewer ',
      department: 'Threat Intel',
      expectedUpdatedAt: viewer.updatedAt,
    })
    expect(res.status).toBe(200)
    expect(res.body.data.changed.sort()).toEqual(['department', 'name'])
    expect(res.body.data.sessionsRevoked).toBe(false)
    expect(JSON.stringify(res.body)).not.toMatch(/"password"|\$2[aby]\$/)
    const saved = await User.findById(viewer._id)
    expect(saved).toMatchObject({ name: 'Renamed Viewer', department: 'Threat Intel', authVersion: 0 })
    expect((await AuthSession.findById('viewer-session')).revokedAt).toBeNull()
    expect(await AuditLog.countDocuments({ action: 'USER_UPDATED' })).toBe(1)
  })

  test('role change revokes the user sessions and bumps both version counters', async () => {
    const res = await put(viewer._id, { role: 'analyst' })
    expect(res.status).toBe(200)
    expect(res.body.data.sessionsRevoked).toBe(true)
    const saved = await User.findById(viewer._id)
    expect(saved).toMatchObject({ role: 'analyst', authVersion: 1, tokenVersion: 1 })
    expect((await AuthSession.findById('viewer-session')).revokedAt).toBeInstanceOf(Date)
    expect(await AuditLog.countDocuments({ action: 'USER_ROLE_CHANGED' })).toBe(1)
  })

  test('re-sending the current role is not a change and does not sign the user out', async () => {
    const res = await put(viewer._id, { role: 'viewer', status: 'active' })
    expect(res.status).toBe(200)
    expect(res.body.data.changed).toEqual([])
    expect((await User.findById(viewer._id)).authVersion).toBe(0)
    expect((await AuthSession.findById('viewer-session')).revokedAt).toBeNull()
  })

  test('email, password and unknown fields are refused without any change (mass assignment)', async () => {
    for (const body of [
      { email: 'admin1@sentinel.test' },
      { password: 'NewPassword123!' },
      { name: 'X Y', authVersion: 0 },
    ]) {
      const res = await put(viewer._id, body)
      expect(res.status).toBe(422)
    }
    const saved = await User.findById(viewer._id).select('+password')
    expect(saved).toMatchObject({ email: 'viewer@sentinel.test', name: 'Viewer User', authVersion: 0 })
    expect(await saved.comparePassword('ViewerPassword123!')).toBe(true)
  })

  test('invalid values and empty bodies are 400', async () => {
    for (const body of [
      { name: 'a' },
      { name: 'x'.repeat(51) },
      { role: 'root' },
      { status: 'gone' },
      { department: '' },
      {},
      { name: 42 },
    ]) {
      expect((await put(viewer._id, body)).status).toBe(400)
    }
    expect((await put(viewer._id, { name: 'Valid Name', expectedUpdatedAt: 'nonsense' })).status).toBe(400)
  })

  test('administrator cannot demote or deactivate itself', async () => {
    expect((await put(admin._id, { role: 'viewer' })).body.error).toMatch(/cannot demote their own/)
    expect((await put(admin._id, { status: 'inactive' })).body.error).toMatch(/cannot deactivate their own/)
    expect((await put(admin._id, { name: 'Admin Renamed' })).status).toBe(200)
    expect((await User.findById(admin._id)).role).toBe('admin')
  })

  test('the last active administrator cannot be demoted or deactivated by another admin', async () => {
    // admin2 is inactive, so admin is the only active administrator; act as a second (hypothetical) admin id
    const actor = { _id: new mongoose.Types.ObjectId() }
    const res = await put(admin._id, { role: 'analyst' }, actor)
    expect(res.status).toBe(400)
    expect(res.body.error).toMatch(/last remaining administrator/)
    expect((await User.findById(admin._id)).role).toBe('admin')
  })

  test('stale edits are refused with 409 and do not overwrite newer data', async () => {
    const opened = viewer.updatedAt
    await User.updateOne(
      { _id: viewer._id },
      { $set: { name: 'Changed Elsewhere', updatedAt: new Date(Date.now() + 5000) } }
    )
    const res = await put(viewer._id, { name: 'My Stale Edit', expectedUpdatedAt: opened })
    expect(res.status).toBe(409)
    expect((await User.findById(viewer._id)).name).toBe('Changed Elsewhere')
  })

  test('non-existent user is 404; analyst and viewer are refused', async () => {
    expect((await put(new mongoose.Types.ObjectId(), { name: 'Nobody Here' })).status).toBe(404)
    for (const role of ['analyst', 'viewer']) {
      const res = await as(role, viewer._id)(request(app).put(`/api/users/${viewer._id}`)).send({ role: 'admin' })
      expect(res.status).toBe(403)
    }
    expect((await User.findById(viewer._id)).role).toBe('viewer')
  })

  test('database error is a 500 and changes nothing', async () => {
    const spy = jest
      .spyOn(User, 'findByIdAndUpdate')
      .mockImplementationOnce(() => ({ select: () => Promise.reject(new Error('write failed')) }))
    const res = await put(viewer._id, { name: 'Will Not Save' })
    spy.mockRestore()
    expect(res.status).toBe(500)
    expect((await User.findById(viewer._id)).name).toBe('Viewer User')
  })

  test('Remove User still follows its rules', async () => {
    expect((await as('admin', admin._id)(request(app).delete(`/api/users/${admin._id}`))).status).toBe(400)
    expect((await as('analyst', admin._id)(request(app).delete(`/api/users/${viewer._id}`))).status).toBe(403)
    expect((await as('admin', admin._id)(request(app).delete(`/api/users/${viewer._id}`))).status).toBe(200)
    expect(await User.findById(viewer._id)).toBeNull()
    expect(admin2.status).toBe('inactive')
  })
})
