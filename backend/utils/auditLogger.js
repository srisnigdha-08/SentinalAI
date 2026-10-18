'use strict'

const AuditLog = require('../models/AuditLog')
const { defaultSecurityAuditLogger } = require('./securityAuditLogger')
const logger = require('./logger')

const denialCache = new Map()
const DEDUP_WINDOW_MS = 5000

function shouldDedupe(entry) {
  if (entry.status !== 'DENIED') return false
  const actorId = entry.actor?._id?.toString() || entry.actor?.id?.toString() || entry.ip || 'anon'
  const targetId = typeof entry.target === 'string' ? entry.target : entry.target?.identifier || entry.target?.id || ''
  const key = `${actorId}:${entry.action}:${targetId}`
  const now = Date.now()
  const lastTime = denialCache.get(key)
  if (lastTime && now - lastTime < DEDUP_WINDOW_MS) {
    return true
  }
  denialCache.set(key, now)
  if (denialCache.size > 500) {
    for (const [k, t] of denialCache.entries()) {
      if (now - t > DEDUP_WINDOW_MS) denialCache.delete(k)
    }
  }
  return false
}

async function logAudit({
  action,
  eventType = 'SECURITY_AUDIT',
  actor = null,
  target = null,
  status = 'SUCCESS',
  details = {},
  ip = null,
  userAgent = null,
  session = null,
}) {
  try {
    if (shouldDedupe({ actor, action, target, status, ip })) {
      logger.debug(`[AuditLog] Deduplicated rapid denial log for action: ${action}`)
      return null
    }

    // 1. Log to structured security event logger
    defaultSecurityAuditLogger.logEvent({
      eventType,
      action,
      status,
      actor,
      target: typeof target === 'string' ? target : target?.identifier || target?.id || null,
      details,
    })

    // 2. Persist to MongoDB AuditLog collection
    const docData = {
      action,
      eventType,
      actor: actor
        ? {
            id: actor._id?.toString() || actor.id?.toString() || null,
            email: actor.email || null,
            role: actor.role || null,
          }
        : null,
      target: target ? (typeof target === 'string' ? { identifier: target } : target) : null,
      status,
      details,
      ip,
      userAgent,
    }

    const entry = session
      ? (await AuditLog.create([docData], { session }))[0]
      : await AuditLog.create(docData)
    return entry
  } catch (err) {
    logger.error('[AuditLog] Failed to persist audit entry: ' + err.message)
    throw err
  }
}

module.exports = { logAudit, denialCache }
