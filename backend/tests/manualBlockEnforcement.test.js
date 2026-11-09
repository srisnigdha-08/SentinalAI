'use strict'

// Manual Block / block-ip / unblock-ip reach the containment adapter (CORE-001b), without re-syncing
// legacy BlockedIP/ThreatLog state that the manual paths already own.

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../models/ContainmentAction', () => ({ find: jest.fn(), findOne: jest.fn() }))
jest.mock('../models/BlockedIP', () => ({}))
jest.mock('../models/ThreatLog', () => ({}))

const ContainmentAction = require('../models/ContainmentAction')
const containmentService = require('../services/containmentService')

const analyst = { _id: '64b000000000000000000001', role: 'analyst', name: 'Arjun', status: 'active' }

describe('manual block enforcement through the adapter', () => {
  afterEach(() => jest.restoreAllMocks())

  test('enforceManualBlock requests a policy-governed block without re-syncing legacy state', async () => {
    const spy = jest
      .spyOn(containmentService, 'requestContainment')
      .mockResolvedValue({ action: { enforcementStatus: 'ACTIVE', enforcementBackend: 'mock', containmentId: 'c1' } })

    const res = await containmentService.enforceManualBlock({ ip: '203.0.113.9', requester: analyst, reason: 'x' })

    expect(res).toEqual({ status: 'ACTIVE', backend: 'mock', containmentId: 'c1' })
    expect(spy).toHaveBeenCalledWith(
      expect.objectContaining({
        target: '203.0.113.9',
        requester: analyst,
        emitEvents: false,
        syncLegacyState: false,
        durationSeconds: containmentService.MANUAL_BLOCK_DURATION_SECONDS,
      })
    )
    // Not the 1-hour default: reconciliation must not lift an analyst's block after an hour
    expect(containmentService.MANUAL_BLOCK_DURATION_SECONDS).toBeGreaterThan(3600)
  })

  test('an adapter or policy failure is reported, never thrown (deny-list entry stays)', async () => {
    const err = Object.assign(new Error('Adapter enforcement failed: boom'), {
      action: { enforcementStatus: 'FAILED' },
    })
    jest.spyOn(containmentService, 'requestContainment').mockRejectedValue(err)

    const res = await containmentService.enforceManualBlock({ ip: '203.0.113.9', requester: analyst, reason: 'x' })

    expect(res).toMatchObject({ status: 'FAILED', error: expect.stringMatching(/boom/) })
  })

  test('releaseManualBlock removes only the adapter rule of every active action on the IP', async () => {
    ContainmentAction.find.mockResolvedValue([{ containmentId: 'c1' }, { containmentId: 'c2' }])
    const spy = jest
      .spyOn(containmentService, 'rollbackContainment')
      .mockResolvedValueOnce({ success: true })
      .mockRejectedValueOnce(new Error('netsh failed'))

    const res = await containmentService.releaseManualBlock({ ip: '203.0.113.9', operator: analyst })

    expect(ContainmentAction.find).toHaveBeenCalledWith(expect.objectContaining({ normalizedTarget: '203.0.113.9' }))
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ containmentId: 'c1', releaseLegacyState: false }))
    expect(res).toEqual([
      { containmentId: 'c1', status: 'ROLLED_BACK' },
      { containmentId: 'c2', status: 'ROLLBACK_FAILED', error: 'netsh failed' },
    ])
  })

  test('releaseManualBlock never throws when the lookup fails', async () => {
    ContainmentAction.find.mockRejectedValue(new Error('db down'))
    await expect(containmentService.releaseManualBlock({ ip: '203.0.113.9', operator: analyst })).resolves.toEqual([
      { status: 'UNKNOWN', error: 'db down' },
    ])
  })
})
