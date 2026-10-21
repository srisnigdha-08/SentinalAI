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
const mockRecommendation = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  getDeceptionRecommendation: (...a) => mockRecommendation(...a),
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
    })
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

  test('reports an unreachable AI engine', async () => {
    mockRecommendation.mockResolvedValue(null)
    const res = await request(app).get(REC).set('x-api-key', 'test-honeypot-api-key')
    expect(res.status).toBe(503)
  })
})
