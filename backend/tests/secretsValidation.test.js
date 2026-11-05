'use strict'
/**
 * tests/secretsValidation.test.js
 *
 * Verifies that:
 * 1. SentinelAI fails safely when required secrets (JWT_SECRET, JWT_REFRESH_SECRET,
 *    HONEYPOT_API_KEY, SENTINEL_KEY) are missing, too short, or contain insecure placeholders.
 * 2. Secrets across different security boundaries (JWT vs Refresh, Honeypot vs Sentinel) cannot be identical.
 * 3. Default administrator auto-provisioning is skipped safely when ADMIN_INITIAL_PASSWORD is unset.
 * 4. Administrator auto-provisioning succeeds with proper hashing when ADMIN_INITIAL_PASSWORD is provided.
 */

// Set test environment
process.env.NODE_ENV = 'test'

const { validateEnv, ConfigurationError } = require('../config/validateEnv')
const connectDB = require('../config/db')
const User = require('../models/User')

jest.mock('../models/User')
jest.mock('../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
}))

describe('Phase 1.2: Environment Secrets Validation & Safe Failure', () => {
  const validBaseEnv = {
    NODE_ENV: 'production',
    PORT: '5000',
    JWT_SECRET: 'super-secure-production-jwt-access-secret-32bytes',
    JWT_REFRESH_SECRET: 'super-secure-production-jwt-refresh-secret-32bytes',
    HONEYPOT_API_KEY: 'honeypot-internal-secret-key-32bytes-long',
    SENTINEL_KEY: 'sentinel-internal-secret-key-32bytes-long',
  }

  test('succeeds when all required secrets are valid, distinct, and strong', () => {
    expect(() => validateEnv(validBaseEnv)).not.toThrow()
  })

  // ── JWT_SECRET ──
  test('fails safely when JWT_SECRET is missing', () => {
    const env = { ...validBaseEnv, JWT_SECRET: '' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/JWT_SECRET is required/i)
  })

  test('fails safely when JWT_SECRET is too short', () => {
    const env = { ...validBaseEnv, JWT_SECRET: 'short' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/at least 16 characters/i)
  })

  test('fails safely when JWT_SECRET contains an insecure placeholder', () => {
    const env = { ...validBaseEnv, JWT_SECRET: 'CHANGE_ME_use_openssl_rand_hex_32' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/insecure default\/placeholder/i)
  })

  // ── JWT_REFRESH_SECRET ──
  test('fails safely when JWT_REFRESH_SECRET is missing', () => {
    const env = { ...validBaseEnv, JWT_REFRESH_SECRET: '' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/JWT_REFRESH_SECRET is required/i)
  })

  test('fails safely when JWT_REFRESH_SECRET is too short', () => {
    const env = { ...validBaseEnv, JWT_REFRESH_SECRET: 'short' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/at least 16 characters/i)
  })

  test('fails safely when JWT_REFRESH_SECRET is identical to JWT_SECRET', () => {
    const env = { ...validBaseEnv, JWT_REFRESH_SECRET: validBaseEnv.JWT_SECRET }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/must be distinct from JWT_SECRET/i)
  })

  // ── HONEYPOT_API_KEY ──
  test('fails safely when HONEYPOT_API_KEY is missing', () => {
    const env = { ...validBaseEnv, HONEYPOT_API_KEY: '' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/HONEYPOT_API_KEY is required/i)
  })

  test('fails safely when HONEYPOT_API_KEY is too short', () => {
    const env = { ...validBaseEnv, HONEYPOT_API_KEY: 'short-key' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/at least 16 characters/i)
  })

  test('fails safely when HONEYPOT_API_KEY contains an insecure placeholder', () => {
    const env = { ...validBaseEnv, HONEYPOT_API_KEY: 'CHANGE_ME_honeypot_api_key_min_32' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/insecure default\/placeholder/i)
  })

  // ── SENTINEL_KEY ──
  test('fails safely when SENTINEL_KEY is missing', () => {
    const env = { ...validBaseEnv, SENTINEL_KEY: '' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/SENTINEL_KEY is required/i)
  })

  test('fails safely when SENTINEL_KEY is too short', () => {
    const env = { ...validBaseEnv, SENTINEL_KEY: 'short-key' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/at least 16 characters/i)
  })

  test('fails safely when SENTINEL_KEY is identical to HONEYPOT_API_KEY across boundaries', () => {
    const env = { ...validBaseEnv, SENTINEL_KEY: validBaseEnv.HONEYPOT_API_KEY }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/must be distinct from HONEYPOT_API_KEY/i)
  })

  // ── ADMIN_INITIAL_PASSWORD ──
  test('fails safely when ADMIN_INITIAL_PASSWORD is provided but too short', () => {
    const env = { ...validBaseEnv, ADMIN_INITIAL_PASSWORD: 'short' }
    expect(() => validateEnv(env)).toThrow(ConfigurationError)
    expect(() => validateEnv(env)).toThrow(/ADMIN_INITIAL_PASSWORD must be at least 8 characters/i)
  })

  test('fails safely when ADMIN_INITIAL_PASSWORD is the template placeholder', () => {
    const env = { ...validBaseEnv, ADMIN_INITIAL_PASSWORD: 'CHANGE_ME_secure_initial_password_min_8_chars' }
    expect(() => validateEnv(env)).toThrow(/ADMIN_INITIAL_PASSWORD contains an insecure default/i)
  })

  // ── .env.demo.example Placeholders ──
  test('fails safely when any secret contains .env.demo.example placeholder values', () => {
    const demoPlaceholders = [
      { key: 'JWT_SECRET', val: 'replace_with_generated_random_jwt_access_secret_64_hex_chars' },
      { key: 'JWT_REFRESH_SECRET', val: 'replace_with_generated_random_jwt_refresh_secret_64_hex_chars' },
      { key: 'HONEYPOT_API_KEY', val: 'replace_with_generated_random_honeypot_api_key_64_hex_chars' },
      { key: 'SENTINEL_KEY', val: 'replace_with_generated_random_sentinel_internal_key_64_hex_chars' },
    ]

    for (const { key, val } of demoPlaceholders) {
      const env = { ...validBaseEnv, [key]: val }
      expect(() => validateEnv(env)).toThrow(ConfigurationError)
      expect(() => validateEnv(env)).toThrow(/contains an insecure default\/placeholder/i)
    }
  })
})

describe('Phase 1.2: Administrator Bootstrap Flow', () => {
  const originalEnv = { ...process.env }

  afterEach(() => {
    process.env = { ...originalEnv }
    jest.clearAllMocks()
  })

  test('skips admin creation and does NOT create a user when ADMIN_INITIAL_PASSWORD is unset', async () => {
    delete process.env.ADMIN_INITIAL_PASSWORD
    User.countDocuments = jest.fn().mockResolvedValue(0)
    User.create = jest.fn()

    await connectDB.ensureDefaultAdmin()

    expect(User.countDocuments).not.toHaveBeenCalled()
    expect(User.create).not.toHaveBeenCalled()
  })

  test('provisions admin user when ADMIN_INITIAL_PASSWORD is explicitly configured', async () => {
    process.env.ADMIN_INITIAL_PASSWORD = 'ExplicitSecurePassword123!'
    process.env.ADMIN_EMAIL = 'custom-admin@sentinel.io'
    User.countDocuments = jest.fn().mockResolvedValue(0)
    User.create = jest.fn().mockResolvedValue({ _id: 'admin-id-123' })

    await connectDB.ensureDefaultAdmin()

    expect(User.countDocuments).toHaveBeenCalledWith({ email: 'custom-admin@sentinel.io' })
    expect(User.create).toHaveBeenCalledWith(
      expect.objectContaining({
        email: 'custom-admin@sentinel.io',
        password: 'ExplicitSecurePassword123!',
        role: 'admin',
      })
    )
  })

  test('does not duplicate admin if already existing in database', async () => {
    process.env.ADMIN_INITIAL_PASSWORD = 'ExplicitSecurePassword123!'
    process.env.ADMIN_EMAIL = 'admin@sentinel.io'
    User.countDocuments = jest.fn().mockResolvedValue(1)
    User.create = jest.fn()

    await connectDB.ensureDefaultAdmin()

    expect(User.countDocuments).toHaveBeenCalledWith({ email: 'admin@sentinel.io' })
    expect(User.create).not.toHaveBeenCalled()
  })
})
