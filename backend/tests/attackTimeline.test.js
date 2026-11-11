'use strict'
/**
 * Attack Time Machine read API: GET /api/honeypot/sessions/:id/timeline and the list's q/sort/from/to filters.
 * Runs against an in-memory MongoDB; only authentication is stubbed (role taken from a test header).
 */
const express = require('express')
const request = require('supertest')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

process.env.SENTINEL_KEY = process.env.SENTINEL_KEY || 'unit-test-sentinel-key-attack-timeline'
process.env.NODE_ENV = 'test'

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../middleware/auth', () => ({
  protect: (req, res, next) =>
    req.headers['x-test-role']
      ? ((req.user = { role: req.headers['x-test-role'], _id: 'u1' }), next())
      : res.status(401).json({ success: false }),
  restrictTo:
    (...roles) =>
    (req, res, next) =>
      roles.includes(req.user.role) ? next() : res.status(403).json({ success: false }),
  requirePermission: () => (req, res, next) => next(),
}))

const HoneypotSession = require('../models/HoneypotSession')
const ThreatLog = require('../models/ThreatLog')
const Alert = require('../models/Alert')
const AIPrediction = require('../models/AIPrediction')
const ContainmentAction = require('../models/ContainmentAction')
const ContainmentAuditEvent = require('../models/ContainmentAuditEvent')
const BlockedIP = require('../models/BlockedIP')

const app = express().use(express.json()).use('/api/honeypot', require('../routes/honeypot'))
const get = (path, role = 'admin') => {
  const r = request(app).get('/api/honeypot' + path)
  return role ? r.set('x-test-role', role) : r
}

let mongo
let ids = {}
const T = (s) => new Date(`2026-11-01T10:30:${String(s).padStart(2, '0')}Z`)

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri())
  await Promise.all([HoneypotSession.init(), ContainmentAction.init(), ContainmentAuditEvent.init()])

  const threat = await ThreatLog.create({
    severity: 'HIGH',
    sourceIP: '203.0.113.9',
    attackType: 'SSH Intrusion Attempt',
    aiScore: 0.88,
    status: 'BLOCKED',
  })
  const [linked, other, unlinked] = await HoneypotSession.create([
    {
      sessionId: 'atm-linked',
      sourceIP: '203.0.113.9',
      startTime: T(1),
      endTime: T(30),
      durationSeconds: 29,
      status: 'closed',
      credentials: [{ username: 'root', password: 'hunter2', success: true }],
      commands: [
        { command: 'whoami', timestamp: T(12) },
        { command: 'cat /etc/passwd', timestamp: T(17), output: '<script>alert(1)</script>' },
      ],
      linkedThreatLog: threat._id,
      aiClassification: 'SSH Intrusion Attempt',
      aiThreatScore: 0.88,
      aiClassificationMethod: 'honeypot_rules',
      servedProfile: 'ubuntu_22',
    },
    // Same source IP, different session, no threat reference: must never leak into atm-linked's evidence.
    { sessionId: 'atm-other', sourceIP: '203.0.113.9', startTime: T(40), status: 'active' },
    { sessionId: 'atm-unlinked', sourceIP: '198.51.100.7', startTime: new Date('2026-10-01T00:00:00Z') },
  ])
  ids = { threat: threat._id, linked: linked._id, other: other._id, unlinked: unlinked._id }

  await AIPrediction.create([
    {
      inputSource: 'honeypot_log',
      sourceIP: '203.0.113.9',
      predictedClass: 'SSH Intrusion Attempt',
      threatScore: 0.88,
      modelType: 'rules',
      modelVersion: 'honeypot_rules_v2+honeypot_rules',
      generatedThreat: threat._id,
      rawFeatures: { sessionId: 'atm-linked' },
    },
    {
      inputSource: 'honeypot_log',
      sourceIP: '203.0.113.9',
      predictedClass: 'SSH Brute Force',
      threatScore: 0.4,
      modelType: 'rules',
      generatedThreat: threat._id,
      rawFeatures: { sessionId: 'atm-other' },
    },
  ])
  await Alert.create([
    { title: 'Session alert', message: 'from 203.0.113.9', type: 'HONEYPOT_SESSION', sourceRef: { refModel: 'HoneypotSession', refId: linked._id } },
    { title: 'Threat alert', message: 'x', type: 'THREAT_DETECTED', sourceRef: { refModel: 'ThreatLog', refId: threat._id }, targetRoles: ['admin', 'analyst', 'viewer'] },
    { title: 'Other session alert', message: 'x', type: 'HONEYPOT_SESSION', sourceRef: { refModel: 'HoneypotSession', refId: other._id } },
  ])
  const action = await ContainmentAction.create({
    target: '203.0.113.9',
    normalizedTarget: '203.0.113.9',
    enforcementBackend: 'mock',
    enforcementStatus: 'ACTIVE',
    targetMetadata: { originalThreatId: threat._id },
    requestedAt: T(35),
    appliedAt: T(36),
    enforcementDetails: { stdout: 'secret adapter output' },
  })
  await ContainmentAuditEvent.create({
    eventId: 'e1',
    seq: 1,
    containmentId: action.containmentId,
    action: 'APPLIED',
    enforcementStatus: 'ACTIVE',
    occurredAt: T(36),
    recordedAt: T(36),
  })
  await BlockedIP.create({ ip: '203.0.113.9', threatRef: threat._id, reason: 'AI Classifier' })
  // A block for the same IP's neighbour without a threat reference must not appear.
  await BlockedIP.create({ ip: '198.51.100.7', reason: 'Manual block' })
})

afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
})

describe('GET /sessions/:id/timeline', () => {
  test('requires authentication', async () => {
    expect((await get(`/sessions/${ids.linked}/timeline`, null)).status).toBe(401)
  })

  test('rejects a malformed id (no query is built from it)', async () => {
    expect((await get('/sessions/{"$ne":null}/timeline')).status).toBe(400)
  })

  test('404 for an unknown session', async () => {
    expect((await get(`/sessions/${new mongoose.Types.ObjectId()}/timeline`)).status).toBe(404)
  })

  test('admin gets the session, per-command MITRE, and only reference-linked records', async () => {
    const res = await get(`/sessions/${ids.linked}/timeline`)
    expect(res.status).toBe(200)
    const d = res.body.data
    expect(d.session.sessionId).toBe('atm-linked')
    expect(d.session.commands.map((c) => c.command)).toEqual(['whoami', 'cat /etc/passwd'])
    expect(d.session.commands[0].techniques.map((t) => t.id)).toContain('T1033')
    expect(d.session.commands[1].techniques.map((t) => t.id)).toContain('T1003.008')
    // Untrusted output is returned as data, unchanged; the UI renders it as text.
    expect(d.session.commands[1].output).toBe('<script>alert(1)</script>')
    // Passwords are never returned, even to admins.
    expect(d.session.credentials).toEqual([{ username: 'root', success: true }])
    expect(JSON.stringify(d)).not.toContain('hunter2')
    expect(d.prediction.predictedClass).toBe('SSH Intrusion Attempt')
    expect(d.prediction.rawFeatures).toBeUndefined()
    expect(d.alerts.map((a) => [a.title, a.linkedVia])).toEqual([
      ['Session alert', 'session'],
      ['Threat alert', 'threat'],
    ])
    expect(d.containment).toHaveLength(1)
    expect(d.containment[0].enforcementBackend).toBe('mock')
    expect(d.containment[0].transitions.map((t) => t.action)).toEqual(['APPLIED'])
    expect(JSON.stringify(d.containment)).not.toContain('secret adapter output')
    expect(d.blockedIPs.map((b) => b.ip)).toEqual(['203.0.113.9'])
  })

  test('a session sharing only the source IP gets none of the other session’s evidence', async () => {
    const d = (await get(`/sessions/${ids.other}/timeline`)).body.data
    expect(d.threat).toBeNull()
    expect(d.prediction).toBeNull()
    expect(d.containment).toEqual([])
    expect(d.blockedIPs).toEqual([])
    expect(d.alerts.map((a) => a.title)).toEqual(['Other session alert'])
  })

  test('viewer: redacted IP and commands, no containment, only alerts targeted at viewers', async () => {
    const res = await get(`/sessions/${ids.linked}/timeline`, 'viewer')
    expect(res.status).toBe(200)
    const d = res.body.data
    expect(d.session.sourceIP).toBe('203.0.113.xxx')
    expect(d.session.commands.every((c) => c.command === '[REDACTED_COMMAND]')).toBe(true)
    expect(d.session.commands[1].output).toBe('[REDACTED_OUTPUT]')
    expect(d.session.credentials).toEqual([{ success: true }])
    expect(d.containment).toEqual([])
    expect(d.blockedIPs).toEqual([])
    expect(d.access).toMatchObject({ containmentVisible: false, commandsVisible: false })
    expect(d.alerts.map((a) => a.title)).toEqual(['Threat alert'])
    expect(d.threat.sourceIP).toBe('203.0.113.xxx')
  })

  test('the endpoint is read-only: no collection changes after reads', async () => {
    const before = await Promise.all([HoneypotSession, Alert, ContainmentAction, BlockedIP].map((m) => m.countDocuments()))
    const s = await HoneypotSession.findById(ids.linked).lean()
    await get(`/sessions/${ids.linked}/timeline`)
    const after = await Promise.all([HoneypotSession, Alert, ContainmentAction, BlockedIP].map((m) => m.countDocuments()))
    expect(after).toEqual(before)
    expect((await HoneypotSession.findById(ids.linked).lean()).updatedAt).toEqual(s.updatedAt)
  })
})

describe('GET /sessions list filters', () => {
  test('q matches session id or source IP, escaped as a literal', async () => {
    expect((await get('/sessions?q=atm-unl')).body.data.map((s) => s.sessionId)).toEqual(['atm-unlinked'])
    expect((await get('/sessions?q=203.0.113')).body.data.map((s) => s.sessionId).sort()).toEqual(['atm-linked', 'atm-other'])
    expect((await get('/sessions?q=.*')).body.data).toEqual([])
  })

  test('sort=oldest reverses the order; default stays newest first', async () => {
    const newest = (await get('/sessions')).body.data.map((s) => s.sessionId)
    const oldest = (await get('/sessions?sort=oldest')).body.data.map((s) => s.sessionId)
    expect(oldest).toEqual([...newest].reverse())
  })

  test('from/to bound startTime; invalid dates are ignored', async () => {
    const r = await get('/sessions?from=2026-11-01T00:00:00Z&to=2026-11-02T00:00:00Z')
    expect(r.body.data.map((s) => s.sessionId).sort()).toEqual(['atm-linked', 'atm-other'])
    expect((await get('/sessions?from=not-a-date')).body.data).toHaveLength(3)
  })

  test('object-shaped query parameters are not passed to MongoDB', async () => {
    const r = await get('/sessions?q[$ne]=x&from[$gt]=1')
    expect(r.status).toBe(200)
    expect(r.body.data).toHaveLength(3)
  })
})
