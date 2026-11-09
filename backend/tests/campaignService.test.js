'use strict'
/**
 * tests/campaignService.test.js
 *
 * Tests for getJaccardSimilarity() and the OR-based clustering rule
 * (hassh match OR Jaccard similarity >= 0.65 with 3-command floor).
 *
 * Jaccard tests are pure. Clustering tests run against an in-memory MongoDB, because clusterSession now
 * selects candidates with indexed queries (same hassh or a shared command) instead of scanning (M6).
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}))

const Campaign = require('../models/Campaign')
const HoneypotSession = require('../models/HoneypotSession')
const { getJaccardSimilarity, clusterSession } = require('../services/campaignService')

// Helper: build a minimal session object
const makeSession = (sessionId, hassh, commandList) => ({
  _id: { toString: () => sessionId },
  sessionId,
  hassh,
  commands: commandList.map((c) => ({ command: c })),
  sourceIP: '1.2.3.4',
  startTime: new Date('2024-01-01T00:00:00Z'),
  endTime: new Date('2024-01-01T00:01:00Z'),
  deceptionScore: 50,
  aiThreatScore: 0.5,
})

// ── Unit tests for getJaccardSimilarity ───────────────────────────────────────
describe('getJaccardSimilarity()', () => {
  test('returns 1.0 when both sessions have no commands', () => {
    const s1 = makeSession('s1', null, [])
    const s2 = makeSession('s2', null, [])
    expect(getJaccardSimilarity(s1, s2)).toBe(1.0)
  })

  test('returns 0.0 when one session has no commands', () => {
    const s1 = makeSession('s1', null, ['uname -a'])
    const s2 = makeSession('s2', null, [])
    expect(getJaccardSimilarity(s1, s2)).toBe(0.0)
    expect(getJaccardSimilarity(s2, s1)).toBe(0.0)
  })

  test('returns 1.0 for identical command sets', () => {
    const cmds = ['uname -a', 'id', 'cat /etc/passwd']
    const s1 = makeSession('s1', null, cmds)
    const s2 = makeSession('s2', null, cmds)
    expect(getJaccardSimilarity(s1, s2)).toBe(1.0)
  })

  test('computes correct Jaccard for partial overlap', () => {
    // {A,B,C} ∩ {B,C,D} = {B,C} → 2/4 = 0.5
    const s1 = makeSession('s1', null, ['A', 'B', 'C'])
    const s2 = makeSession('s2', null, ['B', 'C', 'D'])
    expect(getJaccardSimilarity(s1, s2)).toBeCloseTo(0.5, 5)
  })

  test('returns 0.0 when there is no command overlap', () => {
    const s1 = makeSession('s1', null, ['ls', 'pwd'])
    const s2 = makeSession('s2', null, ['wget', 'curl'])
    expect(getJaccardSimilarity(s1, s2)).toBe(0.0)
  })

  test('deduplicates repeated commands before computing similarity', () => {
    // effective set for s1 = {A,B}, s2 = {A,B,C} → 2/3
    const s1 = makeSession('s1', null, ['A', 'A', 'B'])
    const s2 = makeSession('s2', null, ['A', 'B', 'C'])
    expect(getJaccardSimilarity(s1, s2)).toBeCloseTo(2 / 3, 5)
  })
})

// ── Clustering against a real database ──────────────────────────────────────
describe('clusterSession() OR-based clustering rules', () => {
  let mongoServer
  beforeAll(async () => {
    mongoServer = await MongoMemoryServer.create()
    await mongoose.connect(mongoServer.getUri())
    await HoneypotSession.syncIndexes()
    await Campaign.syncIndexes()
  }, 60000)
  afterAll(async () => {
    await mongoose.disconnect()
    if (mongoServer) await mongoServer.stop()
  })
  beforeEach(async () => {
    await Promise.all([HoneypotSession.deleteMany({}), Campaign.deleteMany({})])
  })

  const RICH_CMDS_A = ['uname -a', 'id', 'cat /etc/passwd', 'ls -la', 'whoami']
  // Jaccard(RICH_CMDS_A, RICH_CMDS_E) = 4/6 ≈ 0.667 — above 0.65
  const RICH_CMDS_E = ['uname -a', 'id', 'cat /etc/passwd', 'ls -la', 'echo hello']

  let ipSuffix = 1
  const store = (sessionId, hassh, commands, extra = {}) =>
    HoneypotSession.create({
      sessionId,
      hassh,
      sourceIP: `198.51.100.${ipSuffix++}`,
      status: 'closed',
      commands: commands.map((command) => ({ command })),
      deceptionScore: 50,
      aiThreatScore: 0.5,
      startTime: new Date(Date.now() - 3600 * 1000),
      endTime: new Date(Date.now() - 3000 * 1000),
      ...extra,
    })

  const campaignWith = (members) =>
    Campaign.create({
      campaignId: 'CAMP-AAAA',
      sessions: members.map((m) => m._id),
      sourceIPs: members.map((m) => m.sourceIP),
      maxDeceptionScore: 50,
      maxAiThreatScore: 0.5,
      firstSeen: new Date(Date.now() - 3600 * 1000),
      lastSeen: new Date(),
      threatLevel: 'MEDIUM',
    })

  test('Session A & B: same HASSH + same commands → joins the existing campaign', async () => {
    const a = await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    await campaignWith([a])
    const b = await store('session-B', 'HASSH-SAME', RICH_CMDS_A)

    const result = await clusterSession(b)
    expect(result.campaignId).toBe('CAMP-AAAA')
    const campaign = await Campaign.findOne({ campaignId: 'CAMP-AAAA' })
    expect(campaign.sessions.map(String)).toEqual([String(a._id), String(b._id)])
    expect(campaign.sourceIPs).toContain(b.sourceIP)
  })

  test('Session C: different HASSH + single "exit" command → NOT clustered (negative control)', async () => {
    const a = await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    await campaignWith([a])
    const c = await store('session-C', 'HASSH-DIFFERENT', ['exit'])

    expect(await clusterSession(c)).toBeNull()
    expect((await Campaign.findOne({ campaignId: 'CAMP-AAAA' })).sessions).toHaveLength(1)
  })

  test('Session D: same HASSH + different commands → clustered via HASSH match (not similarity)', async () => {
    const a = await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    await campaignWith([a])
    const d = await store('session-D', 'HASSH-SAME', ['echo hello'])

    expect((await clusterSession(d)).campaignId).toBe('CAMP-AAAA')
  })

  test('Session E: different HASSH + Jaccard >= 0.65 + >= 3 cmds → new campaign with a standalone session', async () => {
    const a = await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    const e = await store('session-E', 'HASSH-DIFFERENT', RICH_CMDS_E)

    const result = await clusterSession(e)
    expect(result.campaignId).toMatch(/^CAMP-/)
    expect(result.sessions.map(String).sort()).toEqual([String(a._id), String(e._id)].sort())
  })

  test('a standalone match already in an old campaign is not paired again', async () => {
    const a = await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    await Campaign.create({
      campaignId: 'CAMP-OLD',
      sessions: [a._id],
      sourceIPs: [a.sourceIP],
      firstSeen: new Date('2024-01-01'),
      lastSeen: new Date('2024-01-01'), // outside the 7-day window: not "active"
      threatLevel: 'LOW',
    })
    const e = await store('session-E', 'HASSH-DIFFERENT', RICH_CMDS_E)
    expect(await clusterSession(e)).toBeNull()
  })

  test('sessions older than 7 days are not candidates', async () => {
    await store('session-OLD', 'HASSH-SAME', RICH_CMDS_A, { createdAt: new Date(Date.now() - 8 * 86400000) })
    const b = await store('session-B', 'HASSH-SAME', RICH_CMDS_A)
    expect(await clusterSession(b)).toBeNull()
  })

  test('F & G: 2-command sessions with different HASSH → NOT clustered via similarity', async () => {
    await store('session-G', 'HASSH-G', ['uname -a', 'cat /etc/passwd'])
    const f = await store('session-F', 'HASSH-F', ['uname -a', 'cat /etc/passwd'])
    expect(await clusterSession(f)).toBeNull()
  })

  test('H & I: 2-command sessions with SAME HASSH → clustered via HASSH (floor only applies to similarity)', async () => {
    await store('session-I', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    const h = await store('session-H', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    expect((await clusterSession(h)).campaignId).toMatch(/^CAMP-/)
  })

  test('Regression sess-5726befd: 2 generic commands, different HASSH → does NOT cluster', async () => {
    await store('sess-OTHER', 'HASSH-ATTACKER-B', ['uname -a', 'cat /etc/passwd'])
    const s = await store('sess-5726befd', 'HASSH-ATTACKER-A', ['uname -a', 'cat /etc/passwd'])
    expect(await clusterSession(s)).toBeNull()
  })

  test('Regression sess-5726befd with SAME HASSH → clusters via HASSH match', async () => {
    await store('sess-OTHER', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    const s = await store('sess-5726befd', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    expect((await clusterSession(s)).campaignId).toMatch(/^CAMP-/)
  })

  test('candidate lookup uses the hassh / command indexes, not a collection scan', async () => {
    await store('session-A', 'HASSH-SAME', RICH_CMDS_A)
    const explain = await HoneypotSession.find({
      createdAt: { $gte: new Date(Date.now() - 7 * 86400000) },
      $or: [{ hassh: 'HASSH-SAME' }, { 'commands.command': { $in: RICH_CMDS_A } }],
    }).explain('queryPlanner')
    const plan = JSON.stringify(explain.queryPlanner.winningPlan)
    expect(plan).toMatch(/IXSCAN/)
    expect(plan).not.toMatch(/COLLSCAN/)
  })
})
