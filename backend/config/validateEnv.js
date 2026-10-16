'use strict'

const logger = require('../utils/logger')

class ConfigurationError extends Error {
  constructor(message) {
    super(message)
    this.name = 'ConfigurationError'
  }
}

const INSECURE_PLACEHOLDERS = [
  'change_me',
  'changeme',
  'your_jwt_secret',
  'your_secret',
  'your_internal',
  'default_secret',
  'placeholder',
  '4cd01f3e7b8c2a9d6e4f3a1b0c9d8e7f',
  '8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b',
  '6f53e2d8c91a0b3f4e7d8c2b1a5e0d4c',
]

const isPlaceholder = (val) => {
  if (!val) return false
  const lower = val.toLowerCase().trim()
  return INSECURE_PLACEHOLDERS.some((p) => lower.includes(p))
}

/**
 * Validates presence and security of required secrets upon startup.
 * Fails safely by throwing ConfigurationError if any required secret is missing or insecure.
 */
const validateEnv = (env = process.env) => {
  const errors = []
  const isTest = env.NODE_ENV === 'test'
  const minSecretLen = isTest ? 8 : 16

  // 1. JWT_SECRET
  if (!env.JWT_SECRET || !env.JWT_SECRET.trim()) {
    errors.push('JWT_SECRET is required and cannot be empty.')
  } else if (env.JWT_SECRET.trim().length < minSecretLen) {
    errors.push(`JWT_SECRET must be at least ${minSecretLen} characters long.`)
  } else if (!isTest && isPlaceholder(env.JWT_SECRET)) {
    errors.push('JWT_SECRET contains an insecure default/placeholder value.')
  }

  // 2. JWT_REFRESH_SECRET
  if (!env.JWT_REFRESH_SECRET || !env.JWT_REFRESH_SECRET.trim()) {
    errors.push('JWT_REFRESH_SECRET is required and cannot be empty.')
  } else if (env.JWT_REFRESH_SECRET.trim().length < minSecretLen) {
    errors.push(`JWT_REFRESH_SECRET must be at least ${minSecretLen} characters long.`)
  } else if (!isTest && isPlaceholder(env.JWT_REFRESH_SECRET)) {
    errors.push('JWT_REFRESH_SECRET contains an insecure default/placeholder value.')
  } else if (env.JWT_SECRET && env.JWT_REFRESH_SECRET && env.JWT_SECRET === env.JWT_REFRESH_SECRET) {
    errors.push('JWT_REFRESH_SECRET must be distinct from JWT_SECRET.')
  }

  // 3. HONEYPOT_API_KEY
  if (!env.HONEYPOT_API_KEY || !env.HONEYPOT_API_KEY.trim()) {
    errors.push('HONEYPOT_API_KEY is required and cannot be empty.')
  } else if (env.HONEYPOT_API_KEY.trim().length < minSecretLen) {
    errors.push(`HONEYPOT_API_KEY must be at least ${minSecretLen} characters long.`)
  } else if (!isTest && isPlaceholder(env.HONEYPOT_API_KEY)) {
    errors.push('HONEYPOT_API_KEY contains an insecure default/placeholder value.')
  }

  // 4. SENTINEL_KEY
  if (!env.SENTINEL_KEY || !env.SENTINEL_KEY.trim()) {
    errors.push('SENTINEL_KEY is required and cannot be empty.')
  } else if (env.SENTINEL_KEY.trim().length < minSecretLen) {
    errors.push(`SENTINEL_KEY must be at least ${minSecretLen} characters long.`)
  } else if (!isTest && isPlaceholder(env.SENTINEL_KEY)) {
    errors.push('SENTINEL_KEY contains an insecure default/placeholder value.')
  } else if (env.HONEYPOT_API_KEY && env.SENTINEL_KEY && env.HONEYPOT_API_KEY === env.SENTINEL_KEY && !isTest) {
    errors.push('SENTINEL_KEY must be distinct from HONEYPOT_API_KEY across security boundaries.')
  }

  // Optional: check ADMIN_INITIAL_PASSWORD complexity if provided
  if (env.ADMIN_INITIAL_PASSWORD && env.ADMIN_INITIAL_PASSWORD.trim().length < 8) {
    errors.push('ADMIN_INITIAL_PASSWORD must be at least 8 characters long.')
  }

  if (errors.length > 0) {
    const errorMsg = `CRITICAL CONFIGURATION ERROR: Invalid environment configuration:\n  - ${errors.join('\n  - ')}`
    if (logger && typeof logger.error === 'function') {
      logger.error(errorMsg)
    }
    throw new ConfigurationError(errorMsg)
  }

  return true
}

module.exports = { validateEnv, ConfigurationError }
