'use strict'
/**
 * The Q-learner's action must be the persona Cowrie actually served. The active profile is recorded
 * in SystemSetting (falling back to DECEPTION_ACTIVE_PROFILE, then centos_7), stamped on the session
 * as servedProfile, and the previous session's servedProfile is sent as the learner's state.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const mockGetDeceptionScore = jest.fn()
jest.mock('../services/aiEngineService', () => ({
  predictHoneypotSession: jest.fn().mockResolvedValue({ success: false }),
  getDeceptionScore: (...a) => mockGetDeceptionScore(...a),
  getBlockThreshold: jest.fn().mockResolvedValue(0.92),
}))
jest.mock('../models/SystemSetting', () => ({ findOne: jest.fn(), findOneAndUpdate: jest.fn() }))
jest.mock('../services/campaignService', () => ({ clusterSession: jest.fn() }))
jest.mock('../models/HoneypotSession', () => ({
  findById: jest.fn(),
  findOne: jest.fn(),
  findOneAndUpdate: jest.fn(),
  updateOne: jest.fn().mockResolvedValue({ modifiedCount: 1 }),
}))

const SystemSetting = require('../models/SystemSetting')
const HoneypotSession = require('../models/HoneypotSession')
const honeypotService = require('../services/honeypotService')

const previousQuery = (result) => ({
  sort: () => ({ select: () => ({ lean: async () => result }) }),
})

describe('active deception profile', () => {
  const originalEnv = process.env.DECEPTION_ACTIVE_PROFILE
  beforeEach(() => {
    jest.clearAllMocks()
    delete process.env.DECEPTION_ACTIVE_PROFILE
  })
  afterAll(() => {
    if (originalEnv === undefined) delete process.env.DECEPTION_ACTIVE_PROFILE
    else process.env.DECEPTION_ACTIVE_PROFILE = originalEnv
  })

  test('resolves setting, then env, then centos_7 default', async () => {
    SystemSetting.findOne.mockResolvedValue({ key: 'deceptionActiveProfile', value: 'debian_11' })
    await expect(honeypotService.getActiveProfile()).resolves.toEqual({ profile: 'debian_11', source: 'setting' })

    SystemSetting.findOne.mockResolvedValue(null)
    process.env.DECEPTION_ACTIVE_PROFILE = 'aws_ec2'
    await expect(honeypotService.getActiveProfile()).resolves.toEqual({ profile: 'aws_ec2', source: 'env' })

    delete process.env.DECEPTION_ACTIVE_PROFILE
    await expect(honeypotService.getActiveProfile()).resolves.toEqual({ profile: 'centos_7', source: 'default' })
  })

  test('ignores an invalid stored value', async () => {
    SystemSetting.findOne.mockResolvedValue({ key: 'deceptionActiveProfile', value: 'not_a_profile' })
    await expect(honeypotService.getActiveProfile()).resolves.toMatchObject({ profile: 'centos_7' })
  })

  test('setActiveProfile rejects unknown profiles with 400 and stores valid ones', async () => {
    await expect(honeypotService.setActiveProfile('$where')).rejects.toMatchObject({ statusCode: 400 })
    expect(SystemSetting.findOneAndUpdate).not.toHaveBeenCalled()

    await honeypotService.setActiveProfile('windows_srv')
    expect(SystemSetting.findOneAndUpdate).toHaveBeenCalledWith(
      { key: 'deceptionActiveProfile' },
      { value: 'windows_srv' },
      { upsert: true, new: true }
    )
  })

  test('closeSession sends the served profile as action and the previous session profile as state', async () => {
    const session = {
      _id: 'sess-db-1',
      sessionId: 'sess-1',
      sourceIP: '198.51.100.5',
      startTime: new Date(Date.now() - 30000),
      commands: [],
      credentials: [],
      iocExtracted: { urls: [] },
      closureAnalysisState: 'idle',
      save: jest.fn().mockResolvedValue(true),
    }
    HoneypotSession.findById.mockResolvedValue(session)
    HoneypotSession.findOneAndUpdate.mockImplementation(async (_f, update) => Object.assign(session, update.$set))
    HoneypotSession.findOne.mockReturnValue(previousQuery({ servedProfile: 'centos_7' }))
    SystemSetting.findOne.mockImplementation(async ({ key }) =>
      key === 'deceptionActiveProfile' ? { key, value: 'debian_11' } : { key, value: false }
    )
    mockGetDeceptionScore.mockResolvedValue({
      success: true,
      result: { deceptionScore: 40, nextProfile: 'ubuntu_22' },
    })

    await honeypotService.closeSession('sess-db-1')

    expect(session.servedProfile).toBe('debian_11')
    expect(mockGetDeceptionScore).toHaveBeenCalledWith(
      expect.objectContaining({ deceptionProfile: 'debian_11', previousProfile: 'centos_7' })
    )
    expect(session.recommendedProfile).toBe('ubuntu_22')
  })
})
