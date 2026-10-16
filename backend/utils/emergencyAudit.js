'use strict'

const fs = require('fs')
const path = require('path')
const logger = require('./logger')

const LOGS_DIR = path.join(__dirname, '..', 'logs')
const EMERGENCY_AUDIT_PATH = path.join(LOGS_DIR, 'emergency_audit.log')
const MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024 // 10 MB rotation threshold

const SENSITIVE_KEYS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'token',
  'refreshtoken',
  'secret',
  'jwt_secret',
  'apikey',
  'x-api-key',
  'authorization',
  'cookie',
])

function sanitizeRecord(obj, depth = 0) {
  if (depth > 5 || obj === null || obj === undefined) return obj
  if (typeof obj !== 'object') return obj

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeRecord(item, depth + 1))
  }

  const clean = {}
  for (const [key, value] of Object.entries(obj)) {
    const lowerKey = key.toLowerCase()
    if (['__proto__', 'constructor', 'prototype'].includes(lowerKey)) continue
    if (Array.from(SENSITIVE_KEYS).some((s) => lowerKey.includes(s))) {
      clean[key] = '[REDACTED]'
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = sanitizeRecord(value, depth + 1)
    } else {
      clean[key] = value
    }
  }
  return clean
}

/**
 * Ensures the target log directory exists.
 */
function ensureLogDir() {
  if (!fs.existsSync(LOGS_DIR)) {
    fs.mkdirSync(LOGS_DIR, { recursive: true })
  }
}

/**
 * Simple file rotation when exceeding MAX_LOG_SIZE_BYTES.
 */
function checkRotation() {
  try {
    if (fs.existsSync(EMERGENCY_AUDIT_PATH)) {
      const stats = fs.statSync(EMERGENCY_AUDIT_PATH)
      if (stats.size >= MAX_LOG_SIZE_BYTES) {
        const rotatedPath = path.join(LOGS_DIR, `emergency_audit.${Date.now()}.log`)
        fs.renameSync(EMERGENCY_AUDIT_PATH, rotatedPath)
      }
    }
  } catch (err) {
    logger.warn(`[EmergencyAudit] Log rotation check failed: ${err.message}`)
  }
}

/**
 * Writes an emergency audit event synchronously with file sync to guarantee disk durability.
 *
 * @param {Object} eventData - Security audit payload
 * @returns {Object} { success: boolean, path?: string, error?: string, bytesWritten?: number }
 */
function writeEmergencyAudit(eventData) {
  const timestamp = new Date().toISOString()
  const sanitized = sanitizeRecord(eventData)
  const line = JSON.stringify({ timestamp, auditType: 'EMERGENCY_AUDIT_FALLBACK', ...sanitized }) + '\n'

  let fd = null
  try {
    ensureLogDir()
    checkRotation()

    fd = fs.openSync(EMERGENCY_AUDIT_PATH, 'a', 0o600) // Restricted permissions rw-------
    const buffer = Buffer.from(line, 'utf8')
    const bytesWritten = fs.writeSync(fd, buffer, 0, buffer.length, null)
    fs.fsyncSync(fd) // Flush OS disk cache to physical medium
    fs.closeSync(fd)
    fd = null

    return {
      success: true,
      path: EMERGENCY_AUDIT_PATH,
      bytesWritten,
      durable: true,
    }
  } catch (err) {
    if (fd !== null) {
      try {
        fs.closeSync(fd)
      } catch (_) {}
    }
    logger.error(`[EmergencyAudit] CRITICAL: Failed to write emergency audit log to disk: ${err.message}`)
    return {
      success: false,
      error: err.message,
      durable: false,
    }
  }
}

module.exports = {
  writeEmergencyAudit,
  EMERGENCY_AUDIT_PATH,
  sanitizeRecord,
}
