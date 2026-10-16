'use strict'

const logger = require('./logger')

/**
 * Sanitizes details object by redacting sensitive keys.
 */
const sanitizeDetails = (obj) => {
  if (!obj || typeof obj !== 'object') return obj
  const sensitiveKeys = ['password', 'token', 'secret', 'authorization', 'cookie']
  const clean = Array.isArray(obj) ? [] : {}

  for (const [k, v] of Object.entries(obj)) {
    if (sensitiveKeys.some((s) => k.toLowerCase().includes(s))) {
      clean[k] = '[REDACTED]'
    } else if (v && typeof v === 'object') {
      clean[k] = sanitizeDetails(v)
    } else {
      clean[k] = v
    }
  }
  return clean
}

/**
 * Logs a structured audit event for containment operations.
 *
 * @param {Object} event
 * @param {string} event.action - e.g. 'CONTAINMENT_REQUESTED', 'POLICY_DENIED', 'RULE_APPLIED', 'RULE_ROLLED_BACK'
 * @param {string} event.containmentId
 * @param {string} [event.correlationId]
 * @param {string} event.target
 * @param {string} [event.actionType='block_ip']
 * @param {string} [event.policyDecision]
 * @param {string} [event.enforcementBackend]
 * @param {string} [event.enforcementStatus]
 * @param {string|null} [event.operatorId]
 * @param {string|null} [event.operatorEmail]
 * @param {string|null} [event.operatorRole]
 * @param {Object} [event.details]
 */
const logContainmentAudit = ({
  action,
  containmentId,
  correlationId,
  target,
  actionType = 'block_ip',
  policyDecision,
  enforcementBackend,
  enforcementStatus,
  operatorId = null,
  operatorEmail = null,
  operatorRole = null,
  details = {},
}) => {
  const auditEntry = {
    timestamp: new Date().toISOString(),
    auditType: 'CONTAINMENT_AUDIT',
    action,
    containmentId,
    correlationId: correlationId || null,
    target,
    actionType,
    policyDecision: policyDecision || null,
    enforcementBackend: enforcementBackend || null,
    enforcementStatus: enforcementStatus || null,
    operator: {
      id: operatorId,
      email: operatorEmail,
      role: operatorRole,
    },
    details: sanitizeDetails(details),
  }

  logger.info(`[AUDIT] ${action} - target=${target} id=${containmentId} status=${enforcementStatus}`, auditEntry)
  return auditEntry
}

module.exports = {
  sanitizeDetails,
  logContainmentAudit,
}
