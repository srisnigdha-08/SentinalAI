'use strict'
/**
 * SEC-004: anyone holding HONEYPOT_API_KEY can open a session for any source address and push its score over the
 * block line. Under the mock adapter that only writes database records; with real enforcement it would create a host
 * firewall rule against, for example, the gateway. Startup now refuses real enforcement unless the operator's own
 * hosts are protected and honeypot-driven blocks wait for an analyst. Configuration only: no adapter runs here.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
const { validateEnv, ConfigurationError } = require('../config/validateEnv')

const base = {
  NODE_ENV: 'development',
  JWT_SECRET: 'unit-only-access-value-0123456789',
  JWT_REFRESH_SECRET: 'unit-only-refresh-value-0123456789',
  HONEYPOT_API_KEY: 'unit-only-honeypot-value-0123456789',
  SENTINEL_KEY: 'unit-only-sentinel-value-0123456789',
}
const real = { CONTAINMENT_BACKEND: 'windows-firewall', ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'true' }
const safe = { CONTAINMENT_PROTECTED_TARGETS: '192.168.56.0/24', HONEYPOT_AUTOBLOCK_MODE: 'approve' }

test('mock enforcement (the default) needs none of the real-enforcement settings', () => {
  expect(validateEnv(base)).toBe(true)
  expect(validateEnv({ ...base, CONTAINMENT_BACKEND: 'mock' })).toBe(true)
})

test('the windows-firewall backend without the enable flag stays mock, so it is not refused', () => {
  expect(validateEnv({ ...base, CONTAINMENT_BACKEND: 'windows-firewall' })).toBe(true)
})

test('real enforcement without protected targets is refused at startup', () => {
  const env = { ...base, ...real, HONEYPOT_AUTOBLOCK_MODE: 'approve' }
  expect(() => validateEnv(env)).toThrow(ConfigurationError)
  expect(() => validateEnv(env)).toThrow(/CONTAINMENT_PROTECTED_TARGETS/)
  expect(() => validateEnv({ ...env, CONTAINMENT_PROTECTED_TARGETS: '   ' })).toThrow(/CONTAINMENT_PROTECTED_TARGETS/)
})

test('real enforcement without analyst approval of honeypot blocks is refused at startup', () => {
  const env = { ...base, ...real, CONTAINMENT_PROTECTED_TARGETS: '10.0.0.1' }
  expect(() => validateEnv(env)).toThrow(/HONEYPOT_AUTOBLOCK_MODE/)
  expect(() => validateEnv({ ...env, HONEYPOT_AUTOBLOCK_MODE: 'auto' })).toThrow(/HONEYPOT_AUTOBLOCK_MODE/)
})

test('real enforcement with both safeguards passes validation', () => {
  expect(validateEnv({ ...base, ...real, ...safe })).toBe(true)
})

test('CONTAINMENT_DRY_RUN forces the mock adapter, so the safeguards are not required', () => {
  expect(validateEnv({ ...base, ...real, CONTAINMENT_DRY_RUN: 'true' })).toBe(true)
})
