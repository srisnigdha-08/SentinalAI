'use strict'

const fs = require('fs')
const path = require('path')
const logger = require('./logger')

const { logDir } = require('./logPaths')

// Rank 8: resolved at write time through utils/logPaths.js (EMERGENCY_AUDIT_DIR, then LOG_DIR, then backend/logs).
// Under Jest it can never resolve to the real backend/logs, so tests cannot append to or rotate real audit files.
const logsDir = () => logDir('EMERGENCY_AUDIT_DIR')
const auditPath = () => path.join(logsDir(), 'emergency_audit.log')
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

const MAX_ROTATED_FILES = 5 // Bounded retention threshold: keep at most 5 rotated logs

/**
 * Ensures the target log directory exists.
 */
function ensureLogDir() {
  if (!fs.existsSync(logsDir())) {
    fs.mkdirSync(logsDir(), { recursive: true })
  }
}

/**
 * Bounded file rotation when exceeding MAX_LOG_SIZE_BYTES.
 * Prunes oldest rotated archives to guarantee bounded disk usage.
 */
function checkRotation() {
  try {
    if (fs.existsSync(auditPath())) {
      const stats = fs.statSync(auditPath())
      if (stats.size >= MAX_LOG_SIZE_BYTES) {
        // Enforce bounded retention: prune oldest rotated files if count exceeds limit
        const files = fs
          .readdirSync(logsDir())
          .filter((f) => f.startsWith('emergency_audit.') && f.endsWith('.log'))
          .map((f) => ({
            name: f,
            path: path.join(logsDir(), f),
            mtime: fs.statSync(path.join(logsDir(), f)).mtimeMs,
          }))
          .sort((a, b) => a.mtime - b.mtime)

        while (files.length >= MAX_ROTATED_FILES) {
          const oldest = files.shift()
          try {
            fs.unlinkSync(oldest.path)
          } catch (_) {}
        }

        const rotatedPath = path.join(logsDir(), `emergency_audit.${Date.now()}.log`)
        fs.renameSync(auditPath(), rotatedPath)
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

    fd = fs.openSync(auditPath(), 'a', 0o600) // Restricted permissions rw-------
    const buffer = Buffer.from(line, 'utf8')
    const bytesWritten = fs.writeSync(fd, buffer, 0, buffer.length, null)
    fs.fsyncSync(fd) // Flush OS disk cache to physical medium
    fs.closeSync(fd)
    fd = null

    return {
      success: true,
      path: auditPath(),
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
  sanitizeRecord,
  auditPath,
}
// Backward compatible: EMERGENCY_AUDIT_PATH is still exported, now resolved when read (Rank 8).
Object.defineProperty(module.exports, 'EMERGENCY_AUDIT_PATH', { enumerable: true, get: auditPath })
