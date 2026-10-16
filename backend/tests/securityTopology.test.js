const express = require('express')
const { topology, trustedProxy, secureTransport, requireSecureApi } = require('../config/securityTopology')
jest.mock('../utils/logger', () => ({ error: jest.fn() }))
test('production requires an explicit revocation topology; development preserves single-process native mode', () => {
  expect(topology({ NODE_ENV: 'development' }).mode).toBe('single')
  expect(() => topology({ NODE_ENV: 'production' })).toThrow(/AUTH_REVOCATION_MODE/)
  expect(topology({ NODE_ENV: 'production', AUTH_REVOCATION_MODE: 'mongo-stream', API_WORKERS: '2' }).mode).toBe(
    'mongo-stream'
  )
})
test.each([{ API_WORKERS: '2' }, { WEB_CONCURRENCY: '2' }, { NODE_APP_INSTANCE: '0' }])(
  'declared multiple workers cannot silently use local revocation: %j',
  (extra) => {
    expect(() => topology({ NODE_ENV: 'development', AUTH_REVOCATION_MODE: 'single', ...extra })).toThrow(
      /Multiple API workers/
    )
  }
)
test.each([
  { NODE_ENV: 'prod' },
  { API_WORKERS: '0' },
  { WEB_CONCURRENCY: 'garbage' },
  { AUTH_REVOCATION_MODE: 'unknown' },
])('invalid topology fails explicitly: %j', (env) => {
  expect(() => topology(env)).toThrow()
})
test.each(['1', 'true', '*', 'loopback', '127.0.0.1/33', '::1/129', '127.0.0.1,'])(
  'production rejects broad/invalid proxy policy %s',
  (value) => {
    expect(() => trustedProxy({ NODE_ENV: 'production', TRUST_PROXY: value })).toThrow()
  }
)
test('production trusts the explicit proxy, not forged forwarding headers from another peer', () => {
  const app = express()
  app.set('trust proxy', trustedProxy({ NODE_ENV: 'production', TRUST_PROXY: '127.0.0.1/32,::1/128' }))
  const trust = app.get('trust proxy fn')
  const env = { NODE_ENV: 'production' }
  expect(
    secureTransport({ socket: { remoteAddress: '192.0.2.77' }, headers: { 'x-forwarded-proto': 'https' } }, trust, env)
  ).toBe(false)
  expect(
    secureTransport({ socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-proto': 'https' } }, trust, env)
  ).toBe(true)
  expect(
    secureTransport(
      { socket: { remoteAddress: '127.0.0.1' }, headers: { 'x-forwarded-proto': 'https,http' } },
      trust,
      env
    )
  ).toBe(false)
  expect(secureTransport({ socket: { encrypted: true }, headers: {} }, trust, env)).toBe(true)
})
test('production API guard rejects plaintext without an auth or cookie response', () => {
  const previous = process.env.NODE_ENV
  process.env.NODE_ENV = 'production'
  try {
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() }
    const next = jest.fn()
    requireSecureApi({ socket: {}, headers: {}, app: { get: () => () => false } }, res, next)
    expect(res.status).toHaveBeenCalledWith(426)
    expect(next).not.toHaveBeenCalled()
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
  } finally {
    process.env.NODE_ENV = previous
  }
})
