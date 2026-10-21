'use strict'
/**
 * tests/honeypotService.test.js
 *
 * Verifies closeSession() correctly triggers AI classification,
 * deception scoring, and campaign clustering (all HTTP calls mocked).
 */

// ── Mock all external deps before requiring the module ───────────────────────
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))

// Mock the AI engine service
const mockPredictHoneypot = jest.fn()
const mockGetDeceptionScore = jest.fn()

jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: (...a) => mockPredictHoneypot(...a),
  getDeceptionScore: (...a) => mockGetDeceptionScore(...a),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
  getAlertThreshold: jest.fn().mockResolvedValue(0.7),
}))

jest.mock('../models/SystemSetting', () => ({
  findOne: jest.fn().mockResolvedValue({ key: 'autoBlockEnabled', value: false }),
  findOneAndUpdate: jest.fn().mockResolvedValue({}),
}))

jest.mock('../models/BlockedIP', () => ({
  findOne: jest.fn().mockResolvedValue(null),
  findOneAndUpdate: jest.fn().mockResolvedValue({}),
}))

jest.mock('../models/ThreatLog', () => ({
  findByIdAndUpdate: jest.fn().mockResolvedValue({}),
  findById: jest.fn(),
}))

jest.mock('../services/containmentService', () => ({ executeAutoBlock: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitThreatUpdated: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitNewAlert: jest.fn(),
}))
jest.mock('../services/alertService', () => ({ createAlert: jest.fn() }))

jest.mock('../services/aiService', () => ({
  storePrediction: jest.fn().mockResolvedValue({}),
}))

// Mock campaign service (lazy-loaded inside closeSession via require())
const mockClusterSession = jest.fn()
jest.mock('../services/campaignService', () => ({
  clusterSession: (...a) => mockClusterSession(...a),
}))

// Mock HoneypotSession model
const mockSessionSave = jest.fn().mockResolvedValue(true)
const mockSession = {
  _id: 'session-doc-id',
  sessionId: 'sess-TEST-0001',
  sourceIP: '10.0.0.1',
  status: 'active',
  startTime: new Date(Date.now() - 60000), // 60s ago
  endTime: null,
  durationSeconds: null,
  commands: [{ command: 'uname -a' }, { command: 'id' }],
  credentials: [{ success: true }],
  iocExtracted: { urls: [] },
  filesAccessed: [],
  aiClassification: null,
  aiThreatScore: 0,
  qDeceptionScore: 0,
  recommendedProfile: 'ubuntu_22',
  save: mockSessionSave,
}

jest.mock('../models/HoneypotSession', () => ({
  findById: jest.fn(),
  findOneAndUpdate: jest.fn(),
  updateOne: jest.fn(),
  countDocuments: jest.fn(),
  find: jest.fn(),
  distinct: jest.fn(),
  aggregate: jest.fn(),
}))

const HoneypotSession = require('../models/HoneypotSession')
const { closeSession, findSessions } = require('../services/honeypotService')
const aiService = require('../services/aiService')
const SystemSetting = require('../models/SystemSetting')
const ThreatLog = require('../models/ThreatLog')
const containmentService = require('../services/containmentService')

describe('honeypotService.closeSession()', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    // Reset session state to a fresh open session for each test
    Object.assign(mockSession, {
      status: 'active',
      endTime: null,
      durationSeconds: null,
      aiClassification: null,
      aiThreatScore: 0,
      qDeceptionScore: 0,
      linkedThreatLog: null,
      closureAnalysisState: 'idle',
      credentials: [{ success: true }],
    })
    aiService.storePrediction.mockResolvedValue({})
    SystemSetting.findOne.mockResolvedValue({ key: 'autoBlockEnabled', value: false })
    HoneypotSession.findById.mockResolvedValue(mockSession)
    HoneypotSession.findOneAndUpdate.mockImplementation(async (filter, update) => {
      if (filter.closureAnalysisState.$nin.includes(mockSession.closureAnalysisState)) return null
      Object.assign(mockSession, update.$set)
      return mockSession
    })
    HoneypotSession.updateOne.mockResolvedValue({ modifiedCount: 1 })
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
  })

  test('returns null when session is not found', async () => {
    HoneypotSession.findById.mockResolvedValue(null)
    const result = await closeSession('nonexistent-id')
    expect(result).toBeNull()
  })

  test('repeated closure returns the same record without repeated inference, learning or credentials', async () => {
    const first = await closeSession('session-doc-id', {
      telemetry: { durationSeconds: 0, credentials: [{ success: false }] },
    })
    const end = first.endTime
    const second = await closeSession('session-doc-id', { telemetry: { credentials: [{ success: false }] } })
    expect(second).toBe(first)
    expect(second.endTime).toBe(end)
    expect(second.durationSeconds).toBe(0)
    expect(second.credentials).toHaveLength(2)
    expect(mockPredictHoneypot).toHaveBeenCalledTimes(1)
    expect(mockGetDeceptionScore).toHaveBeenCalledTimes(1)
    expect(aiService.storePrediction).not.toHaveBeenCalled()
  })

  test('concurrent closure loses its database claim before inference or external side effects', async () => {
    let release
    mockPredictHoneypot.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = resolve
        })
    )
    const first = closeSession('session-doc-id')
    while (!release) await Promise.resolve()
    await expect(closeSession('session-doc-id')).rejects.toMatchObject({ statusCode: 409 })
    release({ success: false })
    await first
    expect(mockPredictHoneypot).toHaveBeenCalledTimes(1)
    expect(mockGetDeceptionScore).toHaveBeenCalledTimes(1)
  })

  test('an interrupted analysis records failure and ordinary retries cannot repeat side effects', async () => {
    mockPredictHoneypot.mockRejectedValue(new Error('offline inference failure'))
    await expect(closeSession('session-doc-id')).rejects.toThrow('offline inference failure')
    expect(HoneypotSession.updateOne).toHaveBeenCalledWith(
      expect.objectContaining({ closureAnalysisState: 'processing' }),
      { $set: { closureAnalysisState: 'failed' } }
    )
    mockSession.closureAnalysisState = 'failed'
    await expect(closeSession('session-doc-id')).rejects.toMatchObject({ statusCode: 409 })
    expect(mockPredictHoneypot).toHaveBeenCalledTimes(1)
  })

  test('explicit reclassification preserves original closure time and existing containment', async () => {
    mockSession.closureAnalysisState = 'complete'
    mockSession.endTime = new Date('2026-10-14T00:00:00Z')
    mockSession.durationSeconds = 60
    mockSession.linkedThreatLog = 'existing-threat-id'
    const threat = { status: 'BLOCKED', save: jest.fn().mockResolvedValue(true) }
    ThreatLog.findById.mockResolvedValue(threat)
    SystemSetting.findOne.mockResolvedValue({ value: true })
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'SSH Brute Force', threatScore: 0.96 },
    })
    await closeSession('session-doc-id', { reclassify: true })
    expect(mockSession.endTime.toISOString()).toBe('2026-10-14T00:00:00.000Z')
    expect(mockSession.durationSeconds).toBe(60)
    expect(threat.status).toBe('BLOCKED')
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
  })

  test('fallback does not duplicate block alerts for an IP that is already blocked', async () => {
    SystemSetting.findOne.mockResolvedValue({ value: true })
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'SSH Brute Force', threatScore: 0.96 },
    })
    const blocks = require('../models/BlockedIP')
    blocks.findOneAndUpdate.mockResolvedValue({ lastErrorObject: { updatedExisting: true } })
    await closeSession('session-doc-id')
    expect(blocks.findOneAndUpdate).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ $setOnInsert: expect.anything() }),
      expect.objectContaining({ includeResultMetadata: true })
    )
    expect(require('../services/alertService').createAlert).not.toHaveBeenCalled()
    expect(require('../websocket/socketManager').emitIPBlocked).not.toHaveBeenCalled()
    expect(mockGetDeceptionScore).toHaveBeenCalledTimes(1)
  })

  test('links the threat created by prediction storage without repeating containment or alerts', async () => {
    aiService.storePrediction.mockResolvedValue({ generatedThreat: 'new-threat-id' })
    SystemSetting.findOne.mockResolvedValue({ key: 'autoBlockEnabled', value: true })
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'SSH Brute Force', threatScore: 0.96, inferenceTimeMs: 0 },
    })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    const result = await closeSession('session-doc-id')

    expect(result.linkedThreatLog).toBe('new-threat-id')
    expect(aiService.storePrediction).toHaveBeenCalledWith(expect.objectContaining({ inferenceTimeMs: 0 }))
    expect(ThreatLog.findById).not.toHaveBeenCalled()
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
    expect(require('../models/BlockedIP').findOneAndUpdate).not.toHaveBeenCalled()
    expect(require('../services/alertService').createAlert).not.toHaveBeenCalled()
    expect(mockSessionSave).toHaveBeenCalledTimes(1)
  })

  test.each([false, true])('preserves existing containment when autoBlockEnabled is %s', async (enabled) => {
    mockSession.linkedThreatLog = 'existing-threat-id'
    const threat = { status: 'BLOCKED', save: jest.fn().mockResolvedValue(true) }
    ThreatLog.findById.mockResolvedValue(threat)
    SystemSetting.findOne.mockResolvedValue({ key: 'autoBlockEnabled', value: enabled })
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'SSH Brute Force', threatScore: enabled ? 0.96 : 0.5 },
    })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    await closeSession('session-doc-id')

    expect(threat.status).toBe('BLOCKED')
    expect(threat.save).toHaveBeenCalledTimes(1)
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
    expect(aiService.storePrediction).toHaveBeenCalledWith(expect.objectContaining({ inferenceTimeMs: null }))
  })

  test('sets status to "closed" and records endTime + durationSeconds', async () => {
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    const result = await closeSession('session-doc-id')

    expect(result.status).toBe('closed')
    expect(result.endTime).toBeInstanceOf(Date)
    expect(typeof result.durationSeconds).toBe('number')
    expect(result.durationSeconds).toBeGreaterThanOrEqual(0)
  })

  test('calls aiEngineService.predictHoneypotSession with correct payload', async () => {
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    await closeSession('session-doc-id')

    expect(mockPredictHoneypot).toHaveBeenCalledTimes(1)
    const payload = mockPredictHoneypot.mock.calls[0][0]
    expect(payload).toMatchObject({
      sessionId: 'sess-TEST-0001',
      sourceIP: '10.0.0.1',
      commands: expect.any(Array),
    })
  })

  test('writes AI classification and threat score to session when AI returns success', async () => {
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'SSH Brute Force', threatScore: 0.87 },
    })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    const result = await closeSession('session-doc-id')

    expect(result.aiClassification).toBe('SSH Brute Force')
    expect(result.aiThreatScore).toBe(0.87)
  })

  test('successful model inference replaces the heuristic annotation while preserving operator notes', async () => {
    mockSession.linkedThreatLog = 'linked-annotation-threat'
    const threat = {
      notes: '[SESSION_OPEN_HEURISTIC] Initial fixed signal\nOperator note retained',
      status: 'MONITORING',
      save: jest.fn().mockResolvedValue(true),
    }
    ThreatLog.findById.mockResolvedValue(threat)
    mockPredictHoneypot.mockResolvedValue({ success: true, result: { predictedClass: 'Port Scan', threatScore: 0.6 } })
    await closeSession('session-doc-id')
    expect(threat.notes).toBe(
      '[RF_IF_RECLASSIFIED] RF/IF inference replaced the initial fixed SSH session-open signal.\nOperator note retained'
    )
    expect(threat.aiScore).toBe(0.6)
    expect(threat.status).toBe('DETECTED')
    expect(containmentService.executeAutoBlock).not.toHaveBeenCalled()
  })

  test('unavailable inference leaves the fixed heuristic annotation and score unchanged', async () => {
    mockSession.linkedThreatLog = 'linked-annotation-threat'
    const threat = { notes: '[SESSION_OPEN_HEURISTIC] Initial fixed signal', aiScore: 0.75, status: 'MONITORING' }
    ThreatLog.findById.mockResolvedValue(threat)
    mockPredictHoneypot.mockResolvedValue({ success: false })
    await closeSession('session-doc-id')
    expect(threat.notes).toBe('[SESSION_OPEN_HEURISTIC] Initial fixed signal')
    expect(threat.aiScore).toBe(0.75)
    expect(threat.status).toBe('MONITORING')
  })

  test('calls aiEngineService.getDeceptionScore and writes qDeceptionScore', async () => {
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({
      success: true,
      result: { deceptionScore: 72, nextProfile: 'debian_11' },
    })
    mockClusterSession.mockResolvedValue(null)

    const result = await closeSession('session-doc-id')

    expect(mockGetDeceptionScore).toHaveBeenCalledTimes(1)
    expect(result.qDeceptionScore).toBe(72)
    expect(result.recommendedProfile).toBe('debian_11')
  })

  test('calls campaignService.clusterSession with the updated session', async () => {
    mockPredictHoneypot.mockResolvedValue({
      success: true,
      result: { predictedClass: 'Port Scan', threatScore: 0.4 },
    })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    await closeSession('session-doc-id')

    expect(mockClusterSession).toHaveBeenCalledTimes(1)
    // The argument passed to clusterSession should be the session object
    const sessionArg = mockClusterSession.mock.calls[0][0]
    expect(sessionArg.sessionId).toBe('sess-TEST-0001')
    expect(sessionArg.status).toBe('closed')
  })

  test('saves the session exactly once (after AI calls complete)', async () => {
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockResolvedValue(null)

    await closeSession('session-doc-id')

    // save() should be called exactly once after both AI calls resolve
    expect(mockSessionSave).toHaveBeenCalledTimes(1)
  })

  test('does not throw if campaignService.clusterSession rejects (error is swallowed)', async () => {
    mockPredictHoneypot.mockResolvedValue({ success: false })
    mockGetDeceptionScore.mockResolvedValue({ success: false })
    mockClusterSession.mockRejectedValue(new Error('Clustering DB error'))

    await expect(closeSession('session-doc-id')).resolves.not.toThrow()
  })
})

describe('honeypot session status filters', () => {
  test.each(['active', 'closed', 'analysed'])('filters the persisted %s status', async (status) => {
    HoneypotSession.countDocuments.mockResolvedValue(0)
    const query = {}
    for (const method of ['sort', 'skip', 'limit', 'populate']) query[method] = jest.fn().mockReturnValue(query)
    query.lean = jest.fn().mockResolvedValue([])
    HoneypotSession.find.mockReturnValue(query)

    await findSessions({ status })

    expect(HoneypotSession.find).toHaveBeenLastCalledWith({ status })
  })
})
