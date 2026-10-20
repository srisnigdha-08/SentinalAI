'use strict'
/**
 * L5: login for an unknown email still runs one bcrypt comparison (no account-enumeration timing gap).
 * L10: alert retention (TTL default) is configurable through ALERT_RETENTION_DAYS.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../utils/auditLogger', () => ({ logAudit: jest.fn().mockResolvedValue({}) }))
jest.mock('../models/User', () => ({ findOne: jest.fn() }))

const bcrypt = require('bcryptjs')
const User = require('../models/User')
const { login } = require('../controllers/authController')

const res = () => {
  const r = { status: jest.fn(() => r), json: jest.fn(() => r), set: jest.fn(() => r), cookie: jest.fn(() => r) }
  return r
}

describe('L5: login timing does not reveal unknown accounts', () => {
  test('an unknown email still performs a bcrypt comparison and gets the generic error', async () => {
    User.findOne.mockReturnValue({ select: () => Promise.resolve(null) })
    const compare = jest.spyOn(bcrypt, 'compare')
    const r = res()
    await login({ body: { email: 'nobody@example.test', password: 'guess' }, ip: '203.0.113.1' }, r, jest.fn())
    expect(compare).toHaveBeenCalledTimes(1)
    expect(compare.mock.calls[0][0]).toBe('guess')
    expect(r.status).toHaveBeenCalledWith(401)
    expect(r.json.mock.calls[0][0].error).toBe('Invalid credentials')
    compare.mockRestore()
  }, 20000)
})

describe('L10: configurable alert retention', () => {
  const load = () => {
    let Alert
    jest.isolateModules(() => {
      Alert = jest.requireActual('../models/Alert')
    })
    return Alert
  }
  const days = (alert) => Math.round((alert.expiresAt - Date.now()) / 86400000)

  afterEach(() => {
    delete process.env.ALERT_RETENTION_DAYS
  })

  test('defaults to 7 days and follows ALERT_RETENTION_DAYS', () => {
    const Alert = load()
    expect(days(new Alert({ title: 't', message: 'm', severity: 'LOW', type: 'SYSTEM_HEALTH' }))).toBe(7)
    process.env.ALERT_RETENTION_DAYS = '30'
    expect(days(new Alert({ title: 't', message: 'm', severity: 'LOW', type: 'SYSTEM_HEALTH' }))).toBe(30)
  })

  test('out-of-range values fall back to 7', () => {
    const Alert = load()
    process.env.ALERT_RETENTION_DAYS = '0'
    expect(days(new Alert({ title: 't', message: 'm', severity: 'LOW', type: 'SYSTEM_HEALTH' }))).toBe(7)
    process.env.ALERT_RETENTION_DAYS = 'abc'
    expect(days(new Alert({ title: 't', message: 'm', severity: 'LOW', type: 'SYSTEM_HEALTH' }))).toBe(7)
  })
})
