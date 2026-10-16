'use strict'
/**
 * tests/campaignService.test.js
 *
 * Tests for getJaccardSimilarity() and the OR-based clustering rule
 * (hassh match OR Jaccard similarity >= 0.65 with 3-command floor).
 *
 * All MongoDB I/O is mocked – these run fully offline.
 */

// ── Mock all Mongoose models before requiring the module ──────────────────────
const mockCampaignFind = jest.fn()
const mockCampaignCreate = jest.fn()
const mockSessionFind = jest.fn()

jest.mock('../models/Campaign', () => ({
  find: (...a) => mockCampaignFind(...a),
  create: (...a) => mockCampaignCreate(...a),
}))
jest.mock('../models/HoneypotSession', () => ({
  find: (...a) => mockSessionFind(...a),
}))
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}))

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

// ── Integration-level clustering tests ───────────────────────────────────────
// We test clusterSession by controlling what Campaign.find / HoneypotSession.find returns.

describe('clusterSession() OR-based clustering rules', () => {
  // Shared rich-command set (>= 3 unique commands each)
  const RICH_CMDS_A = ['uname -a', 'id', 'cat /etc/passwd', 'ls -la', 'whoami']
  const _RICH_CMDS_B = ['uname -a', 'id', 'cat /etc/passwd', 'echo hello', 'pwd']
  // Jaccard(RICH_CMDS_A, RICH_CMDS_B):
  //   intersection = {uname -a, id, cat /etc/passwd} = 3
  //   union        = 5+5-3 = 7
  //   similarity   = 3/7 ≈ 0.428 — below 0.65 threshold

  // High-overlap set for Session E (>= 0.65)
  const RICH_CMDS_E = ['uname -a', 'id', 'cat /etc/passwd', 'ls -la', 'echo hello']
  // Jaccard(RICH_CMDS_A, RICH_CMDS_E) = 4/6 ≈ 0.667 — above 0.65

  beforeEach(() => {
    jest.clearAllMocks()
  })

  // ── Session A & B: same HASSH + same commands → clustered ──────────────────
  test('Session A & B: same HASSH + same commands → clusters together', async () => {
    const sessionB = makeSession('session-B', 'HASSH-SAME', RICH_CMDS_A)
    const sessionA = makeSession('session-A', 'HASSH-SAME', RICH_CMDS_A)

    const mockCampaign = {
      _id: 'campaign-1',
      campaignId: 'CAMP-AAAA',
      sessions: [sessionA],
      sourceIPs: ['1.2.3.4'],
      maxDeceptionScore: 50,
      maxAiThreatScore: 0.5,
      firstSeen: new Date('2024-01-01'),
      lastSeen: new Date('2024-01-01'),
      threatLevel: 'MEDIUM',
      save: jest.fn().mockResolvedValue(true),
    }
    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([mockCampaign]) })

    const result = await clusterSession(sessionB)
    expect(mockCampaign.save).toHaveBeenCalled()
    expect(result.campaignId).toBe('CAMP-AAAA')
  })

  // ── Session C: different HASSH + isolated command 'exit' → NOT clustered ───
  test('Session C: different HASSH + single "exit" command → NOT clustered (negative control)', async () => {
    const sessionC = makeSession('session-C', 'HASSH-DIFFERENT', ['exit'])

    const existingSession = makeSession('session-A', 'HASSH-SAME', RICH_CMDS_A)
    const mockCampaign = {
      campaignId: 'CAMP-AAAA',
      sessions: [existingSession],
      sourceIPs: ['1.2.3.4'],
      maxDeceptionScore: 50,
      maxAiThreatScore: 0.5,
      firstSeen: new Date('2024-01-01'),
      lastSeen: new Date('2024-01-01'),
      threatLevel: 'MEDIUM',
      save: jest.fn(),
    }
    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([mockCampaign]) })
    // No standalone sessions
    mockSessionFind.mockResolvedValue([])

    const result = await clusterSession(sessionC)
    expect(mockCampaign.save).not.toHaveBeenCalled()
    expect(result).toBeNull()
  })

  // ── Session D: same HASSH + different commands → clustered via HASSH alone ──
  test('Session D: same HASSH + different commands → clustered via HASSH match (not similarity)', async () => {
    const sessionD = makeSession('session-D', 'HASSH-SAME', ['echo hello'])

    const existingSession = makeSession('session-A', 'HASSH-SAME', RICH_CMDS_A)
    const mockCampaign = {
      campaignId: 'CAMP-AAAA',
      sessions: [existingSession],
      sourceIPs: ['1.2.3.4'],
      maxDeceptionScore: 50,
      maxAiThreatScore: 0.5,
      firstSeen: new Date('2024-01-01'),
      lastSeen: new Date('2024-01-01'),
      threatLevel: 'MEDIUM',
      save: jest.fn().mockResolvedValue(true),
    }
    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([mockCampaign]) })

    const result = await clusterSession(sessionD)
    expect(mockCampaign.save).toHaveBeenCalled()
    expect(result.campaignId).toBe('CAMP-AAAA')
  })

  // ── Session E: different HASSH + similar commands (>= 0.65) → clustered via similarity ──
  test('Session E: different HASSH + Jaccard >= 0.65 + >= 3 cmds → clustered via similarity', async () => {
    const sessionE = makeSession('session-E', 'HASSH-DIFFERENT', RICH_CMDS_E)
    const standaloneA = makeSession('session-A', 'HASSH-SAME', RICH_CMDS_A)

    // No campaigns match (hassh mismatch, similarity below threshold in campaign)
    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([]) })
    // Only session-A is standalone
    mockSessionFind.mockResolvedValue([standaloneA])

    const newCamp = { campaignId: 'CAMP-NEW1', sessions: [standaloneA._id, sessionE._id] }
    mockCampaignCreate.mockResolvedValue(newCamp)

    // Also need Campaign.find({}, 'sessions') to return [] (no existing campaigns)
    mockCampaignFind
      .mockReturnValueOnce({ populate: jest.fn().mockResolvedValue([]) }) // recent campaigns
      .mockResolvedValueOnce([]) // all campaigns for exclusion list

    const result = await clusterSession(sessionE)
    expect(mockCampaignCreate).toHaveBeenCalled()
    expect(result.campaignId).toBe('CAMP-NEW1')
  })
})

// ── 3-command minimum floor tests ────────────────────────────────────────────
describe('3-command floor: blocks similarity clustering for short sessions', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  // ── Session F & G: < 3 unique commands, different HASSH → NOT clustered ────
  test('F & G: 2-command sessions with different HASSH → NOT clustered via similarity', async () => {
    const sessionF = makeSession('session-F', 'HASSH-F', ['uname -a', 'cat /etc/passwd'])
    const standaloneG = makeSession('session-G', 'HASSH-G', ['uname -a', 'cat /etc/passwd'])

    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([]) })
    mockSessionFind.mockResolvedValue([standaloneG])
    // Campaign.find({}, 'sessions') for exclusion list
    mockCampaignFind.mockReturnValueOnce({ populate: jest.fn().mockResolvedValue([]) }).mockResolvedValueOnce([])

    const result = await clusterSession(sessionF)
    expect(mockCampaignCreate).not.toHaveBeenCalled()
    expect(result).toBeNull()
  })

  // ── Session H & I: < 3 unique commands, SAME HASSH → clustered via HASSH ──
  test('H & I: 2-command sessions with SAME HASSH → clustered via HASSH (floor only applies to similarity)', async () => {
    const sessionH = makeSession('session-H', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    const standaloneI = makeSession('session-I', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])

    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([]) })
    mockSessionFind.mockResolvedValue([standaloneI])

    const newCamp = { campaignId: 'CAMP-HASSH', sessions: [standaloneI._id, sessionH._id] }
    mockCampaignCreate.mockResolvedValue(newCamp)

    mockCampaignFind.mockReturnValueOnce({ populate: jest.fn().mockResolvedValue([]) }).mockResolvedValueOnce([])

    const result = await clusterSession(sessionH)
    expect(mockCampaignCreate).toHaveBeenCalled()
    expect(result.campaignId).toBe('CAMP-HASSH')
  })
})

// ── sess-5726befd regression test ────────────────────────────────────────────
describe('Regression: sess-5726befd false-positive clustering', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  test('2-command generic recon session with different HASSH → does NOT cluster via similarity', async () => {
    // The original false-positive: two distinct SSH clients both ran these 2 generic commands.
    // Before the floor fix, Jaccard({"uname -a","cat /etc/passwd"}, {"uname -a","cat /etc/passwd"}) = 1.0,
    // which crossed the 0.65 threshold and incorrectly linked them.
    const sess5726 = makeSession('sess-5726befd', 'HASSH-ATTACKER-A', ['uname -a', 'cat /etc/passwd'])
    const otherSess = makeSession('sess-OTHER', 'HASSH-ATTACKER-B', ['uname -a', 'cat /etc/passwd'])

    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([]) })
    mockSessionFind.mockResolvedValue([otherSess])

    mockCampaignFind.mockReturnValueOnce({ populate: jest.fn().mockResolvedValue([]) }).mockResolvedValueOnce([])

    const result = await clusterSession(sess5726)
    expect(mockCampaignCreate).not.toHaveBeenCalled()
    expect(result).toBeNull()
  })

  test('sess-5726befd with SAME HASSH → correctly clusters via HASSH match', async () => {
    // If the HASSH had actually matched, clustering should still work (HASSH is exempt from floor).
    const sess5726 = makeSession('sess-5726befd', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])
    const otherSess = makeSession('sess-OTHER', 'HASSH-SHARED', ['uname -a', 'cat /etc/passwd'])

    mockCampaignFind.mockReturnValue({ populate: jest.fn().mockResolvedValue([]) })
    mockSessionFind.mockResolvedValue([otherSess])

    const newCamp = { campaignId: 'CAMP-5726', sessions: [otherSess._id, sess5726._id] }
    mockCampaignCreate.mockResolvedValue(newCamp)

    mockCampaignFind.mockReturnValueOnce({ populate: jest.fn().mockResolvedValue([]) }).mockResolvedValueOnce([])

    const result = await clusterSession(sess5726)
    expect(mockCampaignCreate).toHaveBeenCalled()
    expect(result.campaignId).toBe('CAMP-5726')
  })
})
