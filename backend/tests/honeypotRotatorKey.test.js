'use strict'
/**
 * C3: the deception rotator runs on the honeypot host, the machine expected to be attacked, so it uses
 * HONEYPOT_API_KEY on two narrow endpoints instead of an admin login. Only the honeypot key is accepted
 * (not the AI engine's SENTINEL_KEY), and the only write is recording one of the six personas.
 */
process.env.NODE_ENV = 'test'
process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'
process.env.JWT_REFRESH_SECRET = 'unit-refresh-secret-for-session-tests'
process.env.HONEYPOT_API_KEY = 'test-honeypot-api-key'
process.env.SENTINEL_KEY = 'test-sentinel-api-key'

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn(), findOneAndUpdate: jest.fn() }))
const mockActiveSessions = jest.fn()
jest.mock('../models/HoneypotSession', () => ({ countDocuments: (...a) => mockActiveSessions(...a) }))
const mockRecommendation = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  getDeceptionRecommendation: (...a) => mockRecommendation(...a),
}))
// RL-001: the routes go through the decision service; here it wraps the mocked engine call (no database)
const mockApply = jest.fn()
const mockFail = jest.fn()
jest.mock('../services/deceptionDecisionService', () => ({
  currentDecision: async (profile) => {
    const rec = await mockRecommendation(profile)
    return rec
      ? {
          decision: {
            decisionId: 'decision-1',
            action: rec.nextProfile,
            explored: rec.explored,
            policy: rec.policy || 'q_learning',
          },
          reused: false,
        }
      : null
  },
  applyDecision: (...a) => mockApply(...a),
  failDecision: (...a) => mockFail(...a),
}))
const mockLogAudit = jest.fn().mockResolvedValue(null)
jest.mock('../utils/auditLogger', () => ({ logAudit: (...a) => mockLogAudit(...a) }))

const request = require('supertest')
const { app } = require('../server')
const SystemSetting = require('../models/SystemSetting')

const REC = '/api/honeypot/ingest/deception/recommendation'
const PROFILE = '/api/honeypot/ingest/deception/profile'

describe('rotator endpoints on the honeypot key', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    SystemSetting.findOne.mockResolvedValue({ key: 'deceptionActiveProfile', value: 'centos_7' })
    SystemSetting.findOneAndUpdate.mockResolvedValue({})
    mockRecommendation.mockResolvedValue({ nextProfile: 'ubuntu_22', explored: false, policy: 'q_learning' })
    mockActiveSessions.mockResolvedValue(2)
  })

  test.each([
    ['no key', undefined],
    ['wrong key', 'nope'],
    ['the AI engine key', 'test-sentinel-api-key'],
  ])('rejects %s', async (_label, key) => {
    for (const [method, path] of [
      ['get', REC],
      ['put', PROFILE],
    ]) {
      const req = request(app)[method](path)
      if (key) req.set('x-api-key', key)
      const res = await req.send({ profile: 'ubuntu_22' })
      expect(res.status).toBe(401)
    }
    expect(SystemSetting.findOneAndUpdate).not.toHaveBeenCalled()
  })

  test('returns the recommendation for the recorded persona', async () => {
    const res = await request(app).get(REC).set('x-api-key', 'test-honeypot-api-key')
    expect(res.status).toBe(200)
    expect(res.body.data).toEqual({
      activeProfile: 'centos_7',
      nextProfile: 'ubuntu_22',
      explored: false,
      policy: 'q_learning',
      decisionId: 'decision-1', // RL-001: the rotator applies this decision, not a fresh draw
      decisionReused: false,
      activeSessions: 2, // M7: the rotator waits while attackers are connected
    })
    expect(mockActiveSessions).toHaveBeenCalledWith({ status: 'active' })
    expect(mockRecommendation).toHaveBeenCalledWith('centos_7')
  })

  test('records a valid persona and audits it as the rotator service', async () => {
    const res = await request(app).put(PROFILE).set('x-api-key', 'test-honeypot-api-key').send({ profile: 'ubuntu_22' })
    expect(res.status).toBe(200)
    expect(SystemSetting.findOneAndUpdate).toHaveBeenCalledWith(
      { key: 'deceptionActiveProfile' },
      { value: 'ubuntu_22' },
      expect.anything()
    )
    expect(mockLogAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'SETTINGS_CHANGED',
        actor: { id: 'honeypot-rotator', role: 'service' },
        details: expect.objectContaining({ from: 'centos_7', to: 'ubuntu_22' }),
      })
    )
  })

  test('rejects anything but the six personas', async () => {
    for (const profile of ['', 'kali', { $ne: null }]) {
      const res = await request(app).put(PROFILE).set('x-api-key', 'test-honeypot-api-key').send({ profile })
      expect(res.status).toBe(400)
    }
    expect(SystemSetting.findOneAndUpdate).not.toHaveBeenCalled()
  })

  test('recording with a decisionId applies that decision (compare-and-set) before recording the persona', async () => {
    mockApply.mockResolvedValue({ decisionId: 'decision-1', status: 'APPLIED' })
    const res = await request(app)
      .put(PROFILE)
      .set('x-api-key', 'test-honeypot-api-key')
      .send({ profile: 'ubuntu_22', decisionId: 'decision-1' })
    expect(res.status).toBe(200)
    expect(res.body.data.decisionId).toBe('decision-1')
    expect(mockApply).toHaveBeenCalledWith('decision-1', 'ubuntu_22', 'centos_7', 'honeypot-rotator')
    expect(SystemSetting.findOneAndUpdate).toHaveBeenCalled()
  })

  test('a stale or mismatched decision is refused with 409 and nothing is recorded', async () => {
    mockApply.mockRejectedValue(Object.assign(new Error('Decision is not pending'), { statusCode: 409 }))
    const res = await request(app)
      .put(PROFILE)
      .set('x-api-key', 'test-honeypot-api-key')
      .send({ profile: 'ubuntu_22', decisionId: 'old-decision' })
    expect(res.status).toBe(409)
    expect(SystemSetting.findOneAndUpdate).not.toHaveBeenCalled()
  })

  test('a failed application is reported on the honeypot key only', async () => {
    mockFail.mockResolvedValue({ decisionId: 'decision-1', status: 'FAILED' })
    const path = '/api/honeypot/ingest/deception/decision/decision-1/fail'
    expect((await request(app).post(path).send({ reason: 'x' })).status).toBe(401)
    expect((await request(app).post(path).set('x-api-key', 'test-sentinel-api-key').send({ reason: 'x' })).status).toBe(
      401
    )
    const res = await request(app)
      .post(path)
      .set('x-api-key', 'test-honeypot-api-key')
      .send({ reason: 'restart failed' })
    expect(res.status).toBe(200)
    expect(res.body.data).toEqual({ decisionId: 'decision-1', status: 'FAILED' })
    expect(mockFail).toHaveBeenCalledWith('decision-1', 'restart failed')
  })

  test('reports an unreachable AI engine', async () => {
    mockRecommendation.mockResolvedValue(null)
    const res = await request(app).get(REC).set('x-api-key', 'test-honeypot-api-key')
    expect(res.status).toBe(503)
  })
})
