'use strict'

const logger = require('./logger')

const REDACTED_KEYS = new Set([
  'password',
  'currentpassword',
  'newpassword',
  'token',
  'refreshtoken',
  'refreshhash',
  'secret',
  'cookie',
  'authorization',
  'x-api-key',
  'apikey',
])

/**
 * Strips CRLF characters to prevent Log Injection / Log Forging attacks.
 */
function sanitizeLogString(str, maxLength = 256) {
  if (typeof str !== 'string') return String(str)
  return str.replace(/[\r\n\t]/g, ' ').slice(0, maxLength)
}

/**
 * Recursively sanitizes objects to redact sensitive secrets and bound values.
 */
function sanitizeAuditPayload(data, depth = 0) {
  if (depth > 4 || data === null || data === undefined) return data
  if (typeof data !== 'object') {
    if (typeof data === 'string') return sanitizeLogString(data)
    return data
  }

  if (Array.isArray(data)) {
    return data.slice(0, 50).map((item) => sanitizeAuditPayload(item, depth + 1))
  }

  const clean = {}
  for (const [key, value] of Object.entries(data)) {
    const lowerKey = key.toLowerCase()
    if (['__proto__', 'constructor', 'prototype'].includes(lowerKey)) continue

    if (REDACTED_KEYS.has(lowerKey)) {
      clean[key] = '***REDACTED***'
    } else if (typeof value === 'object' && value !== null) {
      clean[key] = sanitizeAuditPayload(value, depth + 1)
    } else if (typeof value === 'string') {
      clean[key] = sanitizeLogString(value)
    } else {
      clean[key] = value
    }
  }
  return clean
}

class SecurityAuditLogger {
  constructor() {
    this.auditMetrics = {
      authFailures: 0,
      sessionExpirations: 0,
      refreshReplays: 0,
      authorizationDenials: 0,
      containmentRequests: 0,
      containmentFailures: 0,
      inferenceFailures: 0,
      totalEvents: 0,
    }
  }

  logEvent({ eventType, action, status = 'EXECUTED', actor = null, target = null, details = {} }) {
    this.auditMetrics.totalEvents++
    const cleanEventType = sanitizeLogString(eventType || 'SECURITY_AUDIT')
    const cleanAction = sanitizeLogString(action || 'UNKNOWN')

    // Track metrics
    if (cleanEventType === 'AUTH_FAILURE') this.auditMetrics.authFailures++
    if (cleanEventType === 'SESSION_EXPIRED') this.auditMetrics.sessionExpirations++
    if (cleanEventType === 'REFRESH_REPLAY') this.auditMetrics.refreshReplays++
    if (cleanEventType === 'AUTHORIZATION_DENIAL') this.auditMetrics.authorizationDenials++
    if (cleanEventType === 'CONTAINMENT_REQUEST') this.auditMetrics.containmentRequests++
    if (cleanEventType === 'CONTAINMENT_FAILURE') this.auditMetrics.containmentFailures++
    if (cleanEventType === 'INFERENCE_FAILURE') this.auditMetrics.inferenceFailures++

    const entry = {
      timestamp: new Date().toISOString(),
      eventType: cleanEventType,
      action: cleanAction,
      status: sanitizeLogString(status),
      actor: actor ? sanitizeAuditPayload(actor) : null,
      target: target ? sanitizeLogString(target) : null,
      details: sanitizeAuditPayload(details),
    }

    const logStr = JSON.stringify(entry)
    logger.info(`[SecurityAudit] ${logStr}`)
    return entry
  }

  getMetrics() {
    return { ...this.auditMetrics }
  }

  resetMetrics() {
    for (const k of Object.keys(this.auditMetrics)) {
      this.auditMetrics[k] = 0
    }
  }
}

const defaultSecurityAuditLogger = new SecurityAuditLogger()

module.exports = {
  SecurityAuditLogger,
  defaultSecurityAuditLogger,
  sanitizeLogString,
  sanitizeAuditPayload,
}
