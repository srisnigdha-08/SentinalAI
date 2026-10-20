'use strict'

const crypto = require('crypto')

// Constant-time comparison of a presented API key against a configured secret.
const keyMatches = (presented, expected) => {
  if (typeof presented !== 'string' || typeof expected !== 'string' || !presented || !expected) return false
  const a = Buffer.from(presented)
  const b = Buffer.from(expected)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

const isHoneypotKey = (key) => keyMatches(key, process.env.HONEYPOT_API_KEY)
const isSentinelKey = (key) => keyMatches(key, process.env.SENTINEL_KEY)

module.exports = { keyMatches, isHoneypotKey, isSentinelKey }
