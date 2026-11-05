'use strict'

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({ emitIPBlocked: jest.fn(), emitNewAlert: jest.fn() }))
jest.mock('../services/alertService', () => ({ createAlert: jest.fn().mockResolvedValue({ _id: 'a1' }) }))
jest.mock('../models/BlockedIP', () => ({ findOneAndUpdate: jest.fn(), findOne: jest.fn() }))
jest.mock('../models/ThreatLog', () => ({ find: jest.fn(), findById: jest.fn() }))
jest.mock('../models/ContainmentAction', () => ({}))

const { checkTargetSafety, evaluatePolicy } = require('../services/containmentPolicyService')
const containmentService = require('../services/containmentService')
const BlockedIP = require('../models/BlockedIP')
const socketManager = require('../websocket/socketManager')

const analyst = { _id: 'u1', role: 'analyst', name: 'A' }

describe('operator-protected containment targets (CONTAINMENT_PROTECTED_TARGETS)', () => {
  const saved = process.env.CONTAINMENT_PROTECTED_TARGETS
  beforeEach(() => {
    process.env.CONTAINMENT_PROTECTED_TARGETS = '192.168.56.1, 10.20.0.0/24, not-an-ip'
    jest.clearAllMocks()
  })
  afterAll(() => {
    if (saved === undefined) delete process.env.CONTAINMENT_PROTECTED_TARGETS
    else process.env.CONTAINMENT_PROTECTED_TARGETS = saved
  })

  test('single protected host and hosts inside a protected CIDR are refused', () => {
    expect(checkTargetSafety('192.168.56.1').isSafe).toBe(false)
    expect(checkTargetSafety('10.20.0.77').isSafe).toBe(false)
    expect(checkTargetSafety('10.20.1.77').isSafe).toBe(true)
    expect(checkTargetSafety('203.0.113.7').isSafe).toBe(true)
  })

  test('a CIDR target overlapping a protected host is refused by the full policy', () => {
    const res = evaluatePolicy({
      target: '192.168.56.0/24',
      requester: { ...analyst, role: 'admin' },
      durationSeconds: 3600,
    })
    expect(res.decision).toBe('DENIED')
    expect(res.reason).toMatch(/operator-protected/)
  })

  test('loopback remains protected without any configuration', () => {
    delete process.env.CONTAINMENT_PROTECTED_TARGETS
    expect(checkTargetSafety('127.0.0.1').isSafe).toBe(false)
    expect(checkTargetSafety('198.51.100.4').isSafe).toBe(true)
  })

  test('auto-block of a protected IP is refused, reverted and never recorded or announced', async () => {
    const threat = {
      _id: 't1',
      sourceIP: '192.168.56.1',
      aiScore: 0.97,
      status: 'BLOCKED',
      preBlockStatus: 'MONITORING',
      autonomousAction: { taken: true, actionType: 'IP_BLOCKED', actionTime: new Date() },
      notes: '',
      save: jest.fn().mockResolvedValue(true),
    }
    const res = await containmentService.executeAutoBlock({ threat, threatScore: 0.97, source: 'AI Engine' })

    expect(res).toMatchObject({ success: false, refused: true })
    expect(threat.status).toBe('MONITORING')
    expect(threat.autonomousAction.taken).toBe(false)
    expect(BlockedIP.findOneAndUpdate).not.toHaveBeenCalled()
    expect(socketManager.emitIPBlocked).not.toHaveBeenCalled()
  })

  test('manual block-ip of a protected IP is rejected with 403 before any write', async () => {
    await expect(
      containmentService.blockIPManual({ ip: '10.20.0.5', reason: 'x', analystId: 'u1' })
    ).rejects.toMatchObject({ statusCode: 403 })
    expect(BlockedIP.findOne).not.toHaveBeenCalled()
    expect(BlockedIP.findOneAndUpdate).not.toHaveBeenCalled()
  })
})
