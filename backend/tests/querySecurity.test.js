'use strict'
/**
 * tests/querySecurity.test.js
 *
 * Security test suite for Phase 1.4:
 * Backend Input & Database Query Security
 */

process.env.JWT_SECRET = 'test-jwt-secret-query-sec'
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-query-sec'
process.env.NODE_ENV = 'test'
process.env.HONEYPOT_API_KEY = 'test-hp-key-query-sec'
process.env.SENTINEL_KEY = 'test-sentinel-key-query-sec'
process.env.PORT = '0'

const {
  escapeRegex,
  parsePagination,
  parseSort,
  parseDate,
  isValidIP,
  isValidObjectId,
} = require('../utils/querySecurity')
const { validateRegister, validateLogin, validateObjectId } = require('../middleware/validate')

describe('Phase 1.4: Query Security Utilities', () => {
  describe('escapeRegex', () => {
    test('escapes regex metacharacters correctly', () => {
      const input = '.*+?^${}()|[]\\'
      const escaped = escapeRegex(input)
      expect(escaped).toBe('\\.\\*\\+\\?\\^\\$\\{\\}\\(\\)\\|\\[\\]\\\\')
    })

    test('prevents unescaped bracket crash injection', () => {
      const input = '['
      const escaped = escapeRegex(input)
      expect(escaped).toBe('\\[')
      expect(() => new RegExp(escaped)).not.toThrow()
    })

    test('truncates strings longer than maxLength', () => {
      const longInput = 'a'.repeat(150)
      const escaped = escapeRegex(longInput, 100)
      expect(escaped.length).toBe(100)
    })

    test('returns null for non-string or empty inputs', () => {
      expect(escapeRegex(null)).toBeNull()
      expect(escapeRegex(undefined)).toBeNull()
      expect(escapeRegex('')).toBeNull()
      expect(escapeRegex('   ')).toBeNull()
      expect(escapeRegex(12345)).toBeNull()
      expect(escapeRegex({ $ne: '' })).toBeNull()
      expect(escapeRegex(['a', 'b'])).toBeNull()
    })
  })

  describe('parsePagination', () => {
    test('uses defaultLimit when limit is not provided or invalid', () => {
      expect(parsePagination({}).limit).toBe(20)
      expect(parsePagination({ limit: 'invalid' }).limit).toBe(20)
      expect(parsePagination({ limit: -10 }).limit).toBe(20)
      expect(parsePagination({ limit: 0 }).limit).toBe(20)
    })

    test('caps limit at maxLimit', () => {
      expect(parsePagination({ limit: 500 }).limit).toBe(100)
      expect(parsePagination({ limit: 99999, maxLimit: 50 }).limit).toBe(50)
    })

    test('accepts valid limits within bounds', () => {
      expect(parsePagination({ limit: 45 }).limit).toBe(45)
      expect(parsePagination({ limit: '10' }).limit).toBe(10)
    })

    test('normalizes page and calculates skip correctly', () => {
      const p1 = parsePagination({ page: 1, limit: 20 })
      expect(p1.page).toBe(1)
      expect(p1.skip).toBe(0)

      const p3 = parsePagination({ page: 3, limit: 25 })
      expect(p3.page).toBe(3)
      expect(p3.skip).toBe(50)

      const pNeg = parsePagination({ page: -5, limit: 10 })
      expect(pNeg.page).toBe(1)
      expect(pNeg.skip).toBe(0)

      const pHuge = parsePagination({ page: 50000, limit: 10 })
      expect(pHuge.page).toBe(10000)
    })
  })

  describe('parseSort', () => {
    const allowed = ['createdAt', 'aiScore', 'severity']

    test('allows whitelisted sort fields and valid sort orders', () => {
      expect(parseSort('aiScore', 'asc', allowed)).toEqual({ aiScore: 1 })
      expect(parseSort('severity', 'desc', allowed)).toEqual({ severity: -1 })
      expect(parseSort('createdAt', 1, allowed)).toEqual({ createdAt: 1 })
      expect(parseSort('createdAt', -1, allowed)).toEqual({ createdAt: -1 })
    })

    test('falls back to defaultField when field is not whitelisted', () => {
      expect(parseSort('$where', 'asc', allowed, 'createdAt')).toEqual({ createdAt: 1 })
      expect(parseSort('__proto__', 'desc', allowed, 'createdAt')).toEqual({ createdAt: -1 })
      expect(parseSort('unauthorizedField', 'asc', allowed, 'createdAt')).toEqual({ createdAt: 1 })
    })

    test('defaults sortOrder to -1 (descending) when invalid', () => {
      expect(parseSort('aiScore', 'invalidOrder', allowed)).toEqual({ aiScore: -1 })
      expect(parseSort('aiScore', null, allowed)).toEqual({ aiScore: -1 })
    })
  })

  describe('parseDate', () => {
    test('parses valid ISO date strings', () => {
      const d = parseDate('2026-09-24T12:00:00.000Z')
      expect(d).toBeInstanceOf(Date)
      expect(d.toISOString()).toBe('2026-09-24T12:00:00.000Z')
    })

    test('returns null for invalid or malicious date strings', () => {
      expect(parseDate('not-a-date')).toBeNull()
      expect(parseDate({ $gt: '' })).toBeNull()
      expect(parseDate(null)).toBeNull()
      expect(parseDate(undefined)).toBeNull()
    })
  })

  describe('isValidIP', () => {
    test('validates legitimate IPv4 and IPv6 addresses', () => {
      expect(isValidIP('192.168.1.1')).toBe(true)
      expect(isValidIP('10.0.0.1')).toBe(true)
      expect(isValidIP('127.0.0.1')).toBe(true)
      expect(isValidIP('::1')).toBe(true)
      expect(isValidIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true)
    })

    test('rejects invalid or injection IPs', () => {
      expect(isValidIP('999.999.999.999')).toBe(false)
      expect(isValidIP('192.168.1.1; rm -rf /')).toBe(false)
      expect(isValidIP('192.168.1.1/24')).toBe(false)
      expect(isValidIP('')).toBe(false)
      expect(isValidIP(null)).toBe(false)
      expect(isValidIP({})).toBe(false)
    })
  })

  describe('isValidObjectId', () => {
    test('validates 24-character hexadecimal MongoDB ObjectIds', () => {
      expect(isValidObjectId('507f1f77bcf86cd799439011')).toBe(true)
      expect(isValidObjectId('000000000000000000000000')).toBe(true)
      expect(isValidObjectId('abcdef1234567890ABCDEF12')).toBe(true)
    })

    test('rejects invalid ObjectId strings and objects', () => {
      expect(isValidObjectId('507f1f77bcf86cd79943901')).toBe(false) // 23 chars
      expect(isValidObjectId('507f1f77bcf86cd7994390111')).toBe(false) // 25 chars
      expect(isValidObjectId('507f1f77bcf86cd79943901z')).toBe(false) // non-hex
      expect(isValidObjectId('')).toBe(false)
      expect(isValidObjectId(null)).toBe(false)
      expect(isValidObjectId({})).toBe(false)
    })
  })
})

describe('Phase 1.4: Middleware Validation', () => {
  const mockRes = () => {
    const res = {}
    res.status = jest.fn().mockReturnValue(res)
    res.json = jest.fn().mockReturnValue(res)
    return res
  }

  test('validateObjectId blocks invalid parameter IDs', () => {
    const req = { params: { id: 'invalid-id' } }
    const res = mockRes()
    const next = jest.fn()

    validateObjectId(req, res, next)
    expect(res.status).toHaveBeenCalledWith(400)
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'Invalid ID' }))
    expect(next).not.toHaveBeenCalled()
  })

  test('validateObjectId allows valid 24-hex IDs', () => {
    const req = { params: { id: '507f1f77bcf86cd799439011' } }
    const res = mockRes()
    const next = jest.fn()

    validateObjectId(req, res, next)
    expect(next).toHaveBeenCalled()
    expect(res.status).not.toHaveBeenCalled()
  })

  test('validateLogin rejects non-string and oversized credentials', () => {
    const res = mockRes()
    const next = jest.fn()

    validateLogin({ body: { email: { $gt: '' }, password: 'validPassword123' } }, res, next)
    expect(res.status).toHaveBeenCalledWith(422)

    const res2 = mockRes()
    validateLogin({ body: { email: 'a'.repeat(105) + '@test.com', password: 'validPassword123' } }, res2, next)
    expect(res2.status).toHaveBeenCalledWith(422)
  })

  test('validateRegister enforces length and type limits', () => {
    const res = mockRes()
    const next = jest.fn()

    validateRegister({ body: { name: 'A', email: 'valid@sentinel.io', password: 'password123' } }, res, next)
    expect(res.status).toHaveBeenCalledWith(422)

    const res2 = mockRes()
    validateRegister({ body: { name: 'Valid Admin', email: 'valid@sentinel.io', password: 'short' } }, res2, next)
    expect(res2.status).toHaveBeenCalledWith(422)

    const res3 = mockRes()
    validateRegister({ body: { name: { $ne: '' }, email: 'valid@sentinel.io', password: 'password123' } }, res3, next)
    expect(res3.status).toHaveBeenCalledWith(422)
  })

  test('validates scalar values and rejects MongoDB operator injection objects', () => {
    // Array where scalar expected
    expect(isValidIP(['192.168.1.1'])).toBe(false)
    expect(escapeRegex(['admin', 'root'])).toBeNull()

    // Object injection where scalar expected
    expect(isValidIP({ $regex: '.*' })).toBe(false)
    expect(escapeRegex({ $gt: '' })).toBeNull()
    expect(isValidObjectId({ $ne: null })).toBe(false)
    expect(parseDate({ $gte: '2026-01-01' })).toBeNull()
  })

  test('parsePagination safely handles extreme and malformed inputs', () => {
    // limit=999999 capped to 100
    expect(parsePagination({ limit: 999999 }).limit).toBe(100)
    // negative limits normalized to defaultLimit
    expect(parsePagination({ limit: -100 }).limit).toBe(20)
    // invalid page strings / negative page numbers normalized to 1
    expect(parsePagination({ page: -5 }).page).toBe(1)
    expect(parsePagination({ page: 'not-a-number' }).page).toBe(1)
    // float limits parsed safely
    expect(parsePagination({ limit: '50.5' }).limit).toBe(50)
  })
})
