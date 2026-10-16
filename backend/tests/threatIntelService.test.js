'use strict'
/**
 * tests/threatIntelService.test.js
 *
 * Automated tests for Phase 2.4B: AbuseIPDB Asynchronous Threat-Intelligence Enrichment
 *
 * Verifies:
 * TEST 5: AbuseIPDB lookup happens asynchronously
 * TEST 6: Valid AbuseIPDB response is persisted
 * TEST 7: Cache hit avoids unnecessary external request
 * TEST 8: Cache miss performs lookup
 * TEST 9: Timeout does not fail detection
 * TEST 10: HTTP 429 does not fail detection
 * TEST 11: HTTP 401/403 does not fail detection
 * TEST 12: Malformed response does not fail detection
 * TEST 13: Missing API key does not fail detection
 * TEST 14: Private IP does not trigger external lookup
 * TEST 15: Malformed IP does not trigger external lookup
 * TEST 16: AbuseIPDB cannot change ThreatScore
 * TEST 17: AbuseIPDB cannot change action
 * TEST 18: AbuseIPDB cannot create BlockedIP
 * TEST 19: AbuseIPDB cannot invoke containmentService
 * TEST 20: Only threat_intel_updated is emitted for successful enrichment
 */

const axios = require('axios')
jest.mock('axios')

const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}
jest.mock('../utils/logger', () => mockLogger)

const mockSocketManager = {
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitThreatIntelUpdated: jest.fn(),
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  emitNewAlert: jest.fn(),
}
jest.mock('../websocket/socketManager', () => mockSocketManager)

const mockBlockedIP = {
  create: jest.fn(),
  findOneAndUpdate: jest.fn(),
}
jest.mock('../models/BlockedIP', () => mockBlockedIP)

const mockContainmentService = {
  executeAutoBlock: jest.fn(),
  blockThreat: jest.fn(),
  unblockIP: jest.fn(),
}
jest.mock('../services/containmentService', () => mockContainmentService)

const mockThreatLogFindByIdAndUpdate = jest.fn()
jest.mock('../models/ThreatLog', () => ({
  findByIdAndUpdate: (...args) => mockThreatLogFindByIdAndUpdate(...args),
}))

const threatIntelService = require('../services/threatIntelService')

describe('Phase 2.4B: AbuseIPDB Asynchronous Threat-Intelligence Enrichment', () => {
  const originalEnvKey = process.env.ABUSEIPDB_API_KEY

  beforeEach(() => {
    jest.clearAllMocks()
    threatIntelService.clearCache()
    process.env.ABUSEIPDB_API_KEY = 'test-valid-abuseipdb-key-12345'
  })

  afterAll(() => {
    process.env.ABUSEIPDB_API_KEY = originalEnvKey
  })

  // ── TEST 14: Private IP does not trigger external lookup ───────────────────
  test('TEST 14: Private IP does not trigger external lookup', async () => {
    const privateIPs = [
      '10.0.0.1',
      '10.255.255.254',
      '172.16.0.1',
      '172.31.255.254',
      '192.168.1.100',
      '192.168.0.1',
      '127.0.0.1',
      '169.254.1.1',
      '::1',
      'fe80::1',
      'fc00::1',
    ]

    for (const ip of privateIPs) {
      const res = await threatIntelService.queryAbuseIPDB(ip)
      expect(res.status).toBe('UNAVAILABLE')
      expect(res.errorCode).toBe('PRIVATE_IP')
      expect(axios.get).not.toHaveBeenCalled()
    }
  })

  // ── TEST 15: Malformed IP does not trigger external lookup ──────────────────
  test('TEST 15: Malformed IP does not trigger external lookup', async () => {
    const malformedIPs = [
      '',
      '   ',
      'not-an-ip',
      '999.999.999.999',
      'http://1.1.1.1',
      '1.2.3.4.5',
      'attacker.com',
      null,
      undefined,
    ]

    for (const ip of malformedIPs) {
      const res = await threatIntelService.queryAbuseIPDB(ip)
      expect(res.status).toBe('UNAVAILABLE')
      expect(res.errorCode).toBe('INVALID_IP')
      expect(axios.get).not.toHaveBeenCalled()
    }
  })

  // ── TEST 13: Missing API key does not fail detection ───────────────────────
  test('TEST 13: Missing API key does not fail detection', async () => {
    delete process.env.ABUSEIPDB_API_KEY
    const res = await threatIntelService.queryAbuseIPDB('185.220.101.5')

    expect(res.status).toBe('UNAVAILABLE')
    expect(res.errorCode).toBe('NO_API_KEY')
    expect(axios.get).not.toHaveBeenCalled()
  })

  // ── TEST 8: Cache miss performs lookup ──────────────────────────────────────
  test('TEST 8: Cache miss performs lookup on valid public IP', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: {
        data: {
          ipAddress: '185.220.101.5',
          abuseConfidenceScore: 88,
          totalReports: 142,
          lastReportedAt: '2026-10-05T12:00:00Z',
          countryCode: 'DE',
          isp: 'Tor Exit Node Operator',
          domain: 'torproject.org',
        },
      },
    })

    const res = await threatIntelService.queryAbuseIPDB('185.220.101.5')

    expect(axios.get).toHaveBeenCalledTimes(1)
    expect(axios.get).toHaveBeenCalledWith(
      'https://api.abuseipdb.com/api/v2/check',
      expect.objectContaining({
        headers: expect.objectContaining({ Key: 'test-valid-abuseipdb-key-12345' }),
        params: { ipAddress: '185.220.101.5', maxAgeInDays: 90 },
        timeout: 2500,
      })
    )
    expect(res.status).toBe('SUCCESS')
    expect(res.abuseConfidenceScore).toBe(88)
    expect(res.totalReports).toBe(142)
    expect(res.countryCode).toBe('DE')
    expect(res.isp).toBe('Tor Exit Node Operator')
    expect(res.cached).toBe(false)
  })

  // ── TEST 7: Cache hit avoids unnecessary external request ───────────────────
  test('TEST 7: Cache hit avoids unnecessary external request', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: {
        data: {
          ipAddress: '185.220.101.5',
          abuseConfidenceScore: 75,
          totalReports: 50,
          lastReportedAt: '2026-10-05T10:00:00Z',
        },
      },
    })

    const first = await threatIntelService.queryAbuseIPDB('185.220.101.5')
    expect(first.status).toBe('SUCCESS')
    expect(axios.get).toHaveBeenCalledTimes(1)

    // Second call for the same IP must hit cache
    const second = await threatIntelService.queryAbuseIPDB('185.220.101.5')
    expect(second.status).toBe('SUCCESS')
    expect(second.abuseConfidenceScore).toBe(75)
    expect(second.cached).toBe(true)
    expect(axios.get).toHaveBeenCalledTimes(1) // No new HTTP request
  })

  // ── TEST 9: Timeout does not fail detection ────────────────────────────────
  test('TEST 9: Timeout does not fail detection and records TIMEOUT', async () => {
    const timeoutErr = new Error('timeout of 2500ms exceeded')
    timeoutErr.code = 'ECONNABORTED'
    axios.get.mockRejectedValueOnce(timeoutErr)

    const res = await threatIntelService.queryAbuseIPDB('185.220.101.6')

    expect(res.status).toBe('FAILED')
    expect(res.errorCode).toBe('TIMEOUT')
  })

  // ── TEST 10: HTTP 429 does not fail detection ──────────────────────────────
  test('TEST 10: HTTP 429 does not fail detection and records RATE_LIMITED', async () => {
    const rateLimitErr = new Error('Request failed with status code 429')
    rateLimitErr.response = { status: 429 }
    axios.get.mockRejectedValueOnce(rateLimitErr)

    const res = await threatIntelService.queryAbuseIPDB('185.220.101.7')

    expect(res.status).toBe('UNAVAILABLE')
    expect(res.errorCode).toBe('RATE_LIMITED')
  })

  // ── TEST 11: HTTP 401/403 does not fail detection ──────────────────────────
  test('TEST 11: HTTP 401/403 does not fail detection and records AUTH_ERROR', async () => {
    const authErr = new Error('Request failed with status code 401')
    authErr.response = { status: 401 }
    axios.get.mockRejectedValueOnce(authErr)

    const res = await threatIntelService.queryAbuseIPDB('185.220.101.8')

    expect(res.status).toBe('UNAVAILABLE')
    expect(res.errorCode).toBe('AUTH_ERROR')
  })

  // ── TEST 12: Malformed response does not fail detection ────────────────────
  test('TEST 12: Malformed response does not fail detection', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { notExpected: true }, // missing 'data' key
    })

    const res = await threatIntelService.queryAbuseIPDB('185.220.101.9')

    expect(res.status).toBe('FAILED')
    expect(res.errorCode).toBe('HTTP_200')
  })

  // ── TEST 6: Valid AbuseIPDB response is persisted ──────────────────────────
  test('TEST 6: Valid AbuseIPDB response is persisted to ThreatLog.threatIntel', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: {
        data: {
          ipAddress: '185.220.101.10',
          abuseConfidenceScore: 95,
          totalReports: 250,
          countryCode: 'RU',
          isp: 'Bad ISP',
        },
      },
    })

    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d1',
      sourceIP: '185.220.101.10',
      aiScore: 0.85,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce({
      ...mockThreat,
      threatIntel: {
        provider: 'AbuseIPDB',
        status: 'SUCCESS',
        abuseConfidenceScore: 95,
        totalReports: 250,
        countryCode: 'RU',
        isp: 'Bad ISP',
      },
    })

    const updated = await threatIntelService.enrichThreat(mockThreat)

    expect(mockThreatLogFindByIdAndUpdate).toHaveBeenCalledTimes(1)
    expect(mockThreatLogFindByIdAndUpdate).toHaveBeenCalledWith(
      '64f1a2b3c4d5e6f7a8b9c0d1',
      {
        $set: {
          threatIntel: expect.objectContaining({
            provider: 'AbuseIPDB',
            status: 'SUCCESS',
            abuseConfidenceScore: 95,
            totalReports: 250,
            countryCode: 'RU',
            isp: 'Bad ISP',
          }),
        },
      },
      { new: true, runValidators: true }
    )
    expect(updated).not.toBeNull()
  })

  // ── TEST 5: AbuseIPDB lookup happens asynchronously ─────────────────────────
  test('TEST 5: AbuseIPDB lookup executes asynchronously without blocking caller', async () => {
    axios.get.mockImplementation(
      () =>
        new Promise((resolve) => {
          setTimeout(() => {
            resolve({
              status: 200,
              data: { data: { abuseConfidenceScore: 50, totalReports: 10 } },
            })
          }, 50)
        })
    )

    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d2',
      sourceIP: '185.220.101.11',
      aiScore: 0.75,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce(mockThreat)

    // enrichThreat returns a Promise, allowing non-blocking execution via setImmediate / background call
    const promise = threatIntelService.enrichThreat(mockThreat)
    expect(promise).toBeInstanceOf(Promise)

    const result = await promise
    expect(result).toBeDefined()
  })

  // ── TEST 16: AbuseIPDB cannot change ThreatScore ───────────────────────────
  test('TEST 16: AbuseIPDB cannot change ThreatScore', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { data: { abuseConfidenceScore: 100 } }, // 100% abuse confidence
    })

    const initialScore = 0.75
    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d3',
      sourceIP: '185.220.101.12',
      aiScore: initialScore,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockImplementation((id, update) => {
      // Ensure the update only sets threatIntel, never aiScore or threatScore
      expect(update.$set.aiScore).toBeUndefined()
      expect(update.$set.threatScore).toBeUndefined()
      return Promise.resolve({ ...mockThreat, threatIntel: update.$set.threatIntel })
    })

    const enriched = await threatIntelService.enrichThreat(mockThreat)

    // The threat's aiScore must remain strictly unchanged
    expect(mockThreat.aiScore).toBe(initialScore)
    expect(enriched.aiScore).toBe(initialScore)
  })

  // ── TEST 17: AbuseIPDB cannot change action ────────────────────────────────
  test('TEST 17: AbuseIPDB cannot change action or status', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { data: { abuseConfidenceScore: 100 } }, // 100% abuse confidence
    })

    const initialStatus = 'MONITORING'
    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d4',
      sourceIP: '185.220.101.13',
      aiScore: 0.75,
      severity: 'HIGH',
      status: initialStatus,
    }

    mockThreatLogFindByIdAndUpdate.mockImplementation((id, update) => {
      // Verify update payload NEVER sets status or action
      expect(update.$set.status).toBeUndefined()
      expect(update.$set.action).toBeUndefined()
      return Promise.resolve({ ...mockThreat, threatIntel: update.$set.threatIntel })
    })

    const enriched = await threatIntelService.enrichThreat(mockThreat)
    expect(mockThreat.status).toBe(initialStatus)
    expect(enriched.status).toBe(initialStatus)
  })

  // ── TEST 18: AbuseIPDB cannot create BlockedIP ─────────────────────────────
  test('TEST 18: AbuseIPDB cannot create BlockedIP', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { data: { abuseConfidenceScore: 100 } }, // maximum malice
    })

    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d5',
      sourceIP: '185.220.101.14',
      aiScore: 0.75,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce(mockThreat)

    await threatIntelService.enrichThreat(mockThreat)

    // BlockedIP model must never be called
    expect(mockBlockedIP.create).not.toHaveBeenCalled()
    expect(mockBlockedIP.findOneAndUpdate).not.toHaveBeenCalled()
  })

  // ── TEST 19: AbuseIPDB cannot invoke containmentService ────────────────────
  test('TEST 19: AbuseIPDB cannot invoke containmentService', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { data: { abuseConfidenceScore: 100 } },
    })

    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d6',
      sourceIP: '185.220.101.15',
      aiScore: 0.75,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce(mockThreat)

    await threatIntelService.enrichThreat(mockThreat)

    // containmentService must never be called
    expect(mockContainmentService.executeAutoBlock).not.toHaveBeenCalled()
    expect(mockContainmentService.blockThreat).not.toHaveBeenCalled()
  })

  // ── TEST 20: Only threat_intel_updated is emitted for successful enrichment ─
  test('TEST 20: Only threat_intel_updated is emitted for successful enrichment', async () => {
    axios.get.mockResolvedValueOnce({
      status: 200,
      data: { data: { abuseConfidenceScore: 82, totalReports: 90 } },
    })

    const mockThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d7',
      sourceIP: '185.220.101.16',
      aiScore: 0.8,
      severity: 'HIGH',
      status: 'MONITORING',
    }

    mockThreatLogFindByIdAndUpdate.mockResolvedValueOnce({
      ...mockThreat,
      threatIntel: { status: 'SUCCESS', abuseConfidenceScore: 82 },
    })

    await threatIntelService.enrichThreat(mockThreat)

    // Must emit threat_intel_updated
    expect(mockSocketManager.emitThreatIntelUpdated).toHaveBeenCalledTimes(1)
    expect(mockSocketManager.emitThreatIntelUpdated).toHaveBeenCalledWith(
      expect.objectContaining({
        threatId: '64f1a2b3c4d5e6f7a8b9c0d7',
        sourceIP: '185.220.101.16',
        threatIntel: expect.objectContaining({
          status: 'SUCCESS',
          abuseConfidenceScore: 82,
        }),
      })
    )

    // Must NOT emit new_threat, new_alert, or ip_blocked
    expect(mockSocketManager.emitNewThreat).not.toHaveBeenCalled()
    expect(mockSocketManager.emitNewAlert).not.toHaveBeenCalled()
    expect(mockSocketManager.emitIPBlocked).not.toHaveBeenCalled()
  })

  // ── Trigger Policy Test: Low scores (< 0.70) are not enriched ──────────────
  test('Trigger Policy: Threats with aiScore < 0.70 are not enriched', async () => {
    const lowThreat = {
      _id: '64f1a2b3c4d5e6f7a8b9c0d8',
      sourceIP: '185.220.101.17',
      aiScore: 0.45,
      severity: 'LOW',
      status: 'DETECTED',
    }

    const result = await threatIntelService.enrichThreat(lowThreat)

    expect(result).toBeNull()
    expect(axios.get).not.toHaveBeenCalled()
    expect(mockThreatLogFindByIdAndUpdate).not.toHaveBeenCalled()
  })
})
