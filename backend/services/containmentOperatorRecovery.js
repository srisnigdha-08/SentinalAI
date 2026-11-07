'use strict'
/**
 * CONT-R2: operator-initiated recovery of one containment action stuck before ACTIVE/FAILED
 * (VALIDATING / APPROVED / APPLYING), for an administrator who does not want to wait for the reconciliation pass.
 *
 * Two steps, both admin-only:
 *   1. diagnose (read-only): loads the action, asks the adapter whether the rule exists (inspectRule), and states
 *      what recovery would do. Nothing is changed. Only when the outcome is safe to act on does it return a
 *      confirmation token, signed and bound to the administrator, the action's version and status, and the
 *      observed rule state, valid for 5 minutes and usable once.
 *   2. recover: requires a trusted Origin (routes) and that token. It claims the action with a compare-and-set on
 *      the version the diagnosis saw (any change in between -> 409, diagnose again), then runs exactly the logic of
 *      the reconciliation pass (ContainmentReconciliationService._recoverOne), which inspects the rule again.
 *
 * Safety rules, same as automatic recovery:
 *   - an UNKNOWN rule state never releases anything: diagnosis issues no token, and if the state turns UNKNOWN
 *     between diagnosis and recovery the action keeps its lock (outcome RULE_STATE_UNKNOWN, recorded);
 *   - a PRESENT rule is removed and confirmed ABSENT before the action is released as FAILED;
 *   - an action updated within the last MIN_AGE_MS may still be running in its request: no token;
 *   - an action recorded for another enforcement backend is not touched.
 * Real firewall enforcement is whatever the configured adapter is; this module adds no enforcement path.
 */
const crypto = require('crypto')
const ContainmentAction = require('../models/ContainmentAction')
const { getContainmentAdapter } = require('./containment/adapterFactory')
const { logContainmentAudit } = require('../utils/containmentAudit')
const logger = require('../utils/logger')

const IN_FLIGHT = ['VALIDATING', 'APPROVED', 'APPLYING']
const MIN_AGE_MS = Number(process.env.CONTAINMENT_OPERATOR_RECOVERY_MIN_AGE_MS) || 60000
const TOKEN_TTL_MS = 5 * 60000
const RELEASED = ['NOT_APPLIED', 'RULE_ABSENT', 'RULE_REMOVED']
const usedTokens = new Map() // jti -> expiry (single use)

class RecoveryError extends Error {
  constructor(message, statusCode, code) {
    super(message)
    this.statusCode = statusCode
    this.code = code
  }
}

const key = () => {
  const secret = process.env.JWT_REFRESH_SECRET
  if (!secret) throw new RecoveryError('Recovery tokens unavailable', 503, 'RECOVERY_UNAVAILABLE')
  return crypto.createHmac('sha256', secret).update('sentinel-containment-recovery-v1').digest()
}
const sign = (body) => crypto.createHmac('sha256', key()).update(body).digest('base64url')

function issueToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url')
  return `${body}.${sign(body)}`
}

function readToken(token) {
  if (typeof token !== 'string' || token.length > 2048 || !token.includes('.')) return null
  const [body, sig] = token.split('.')
  const expected = sign(body)
  if (!sig || sig.length !== expected.length) return null
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null
  try {
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'))
  } catch {
    return null
  }
}

const userId = (user) => String(user?._id || user?.id || '')

async function findAction(id) {
  if (typeof id !== 'string' || id.length > 128) return null
  let action = await ContainmentAction.findOne({ containmentId: id })
  if (!action && /^[0-9a-fA-F]{24}$/.test(id)) action = await ContainmentAction.findById(id)
  return action
}

const ruleFor = (action) => ({
  containmentId: action.containmentId,
  ruleId: action.enforcementDetails?.ruleId || undefined,
  target: action.normalizedTarget,
  ruleName: action.enforcementDetails?.ruleName || `SentinelAI-Rule-${action.containmentId}`,
})

/** Read-only diagnosis. Never changes the action or the firewall. */
async function diagnose(id, user, now = Date.now()) {
  const action = await findAction(id)
  if (!action) throw new RecoveryError('Containment action not found', 404, 'NOT_FOUND')
  const adapter = getContainmentAdapter()
  const ageMs = now - new Date(action.updatedAt).getTime()
  const result = {
    containmentId: action.containmentId,
    target: action.normalizedTarget,
    enforcementStatus: action.enforcementStatus,
    enforcementBackend: action.enforcementBackend || null,
    currentBackend: adapter.getBackendType(),
    stuckForSeconds: Math.max(0, Math.round(ageMs / 1000)),
    recoveryAttempts: action.recovery?.attempts || 0,
    lastOutcome: action.recovery?.lastOutcome || null,
    ruleState: null,
    plannedOutcome: null,
    recoverable: false,
    notRecoverableReason: null,
    confirmationToken: null,
    tokenExpiresAt: null,
  }
  const refuse = (reason) => {
    result.notRecoverableReason = reason
    return result
  }

  if (!IN_FLIGHT.includes(action.enforcementStatus))
    return refuse(`Status ${action.enforcementStatus} is not an interrupted request (only ${IN_FLIGHT.join(', ')})`)
  if (ageMs < MIN_AGE_MS)
    return refuse(
      `Updated ${Math.round(ageMs / 1000)} s ago; its request may still be running (minimum ${MIN_AGE_MS / 1000} s)`
    )
  if (action.enforcementBackend && action.enforcementBackend !== adapter.getBackendType())
    return refuse(`Recorded for backend ${action.enforcementBackend}, current backend ${adapter.getBackendType()}`)

  if (action.enforcementStatus === 'APPLYING') {
    try {
      result.ruleState = (await adapter.inspectRule(ruleFor(action)))?.state || 'UNKNOWN'
    } catch (err) {
      result.ruleState = 'UNKNOWN'
      logger.warn(`[OperatorRecovery] inspectRule failed for ${action.containmentId}: ${err.message}`)
    }
    if (result.ruleState === 'PRESENT') result.plannedOutcome = 'REMOVE_RULE_THEN_RELEASE'
    else if (result.ruleState === 'ABSENT') result.plannedOutcome = 'RELEASE (no rule exists)'
    else return refuse('Rule state is UNKNOWN: nothing is released until the adapter can confirm it')
  } else {
    result.ruleState = 'NOT_APPLIED'
    result.plannedOutcome = 'RELEASE (adapter was never called)'
  }

  result.recoverable = true
  const exp = now + TOKEN_TTL_MS
  result.confirmationToken = issueToken({
    cid: action.containmentId,
    v: action.__v,
    st: action.enforcementStatus,
    rs: result.ruleState,
    uid: userId(user),
    exp,
    jti: crypto.randomUUID(),
  })
  result.tokenExpiresAt = new Date(exp).toISOString()
  logContainmentAudit({
    action: 'OPERATOR_RECOVERY_DIAGNOSED',
    containmentId: action.containmentId,
    target: action.normalizedTarget,
    enforcementStatus: action.enforcementStatus,
    operatorId: userId(user),
    operatorEmail: user?.email,
    operatorRole: user?.role,
    details: { ruleState: result.ruleState, plannedOutcome: result.plannedOutcome },
  })
  return result
}

/** Executes the recovery the diagnosis described, if nothing changed since. */
async function recover(id, { confirmationToken, reason } = {}, user, now = Date.now()) {
  const cleanReason = typeof reason === 'string' ? reason.trim() : ''
  if (cleanReason.length < 3 || cleanReason.length > 500)
    throw new RecoveryError('A reason of 3-500 characters is required', 422, 'REASON_REQUIRED')
  const claims = readToken(confirmationToken)
  if (!claims) throw new RecoveryError('Invalid confirmation token', 403, 'TOKEN_INVALID')
  if (claims.exp < now) throw new RecoveryError('Confirmation token expired; diagnose again', 403, 'TOKEN_EXPIRED')
  if (claims.uid !== userId(user))
    throw new RecoveryError('Confirmation token was issued to another administrator', 403, 'TOKEN_INVALID')

  const action = await findAction(id)
  if (!action || action.containmentId !== claims.cid)
    throw new RecoveryError('Confirmation token does not match this action', 403, 'TOKEN_INVALID')

  for (const [jti, exp] of usedTokens) if (exp < now) usedTokens.delete(jti)
  if (usedTokens.has(claims.jti)) throw new RecoveryError('Confirmation token already used', 409, 'TOKEN_USED')
  usedTokens.set(claims.jti, claims.exp)

  // Claim: only if the action is exactly as diagnosed. __v + 1 fences the original request, as the pass does.
  const claimed = await ContainmentAction.findOneAndUpdate(
    { _id: action._id, __v: claims.v, enforcementStatus: claims.st },
    {
      $inc: { 'recovery.attempts': 1, __v: 1 },
      $set: {
        'recovery.lastAttemptAt': new Date(now),
        'recovery.lastOperator': { id: userId(user), email: user?.email || null, reason: cleanReason },
      },
    },
    { new: true }
  )
  if (!claimed) throw new RecoveryError('The action changed after the diagnosis; diagnose again', 409, 'STATE_CHANGED')

  const { defaultReconciliationService } = require('./containmentReconciliationService')
  let outcome
  let detail = null
  try {
    ;({ outcome, detail } = await defaultReconciliationService._recoverOne(claimed))
  } catch (err) {
    outcome = 'ADAPTER_UNAVAILABLE'
    detail = err.message
  }
  // The rule state may have changed since the diagnosis; _recoverOne inspected it again. Report a difference.
  const released = RELEASED.includes(outcome)
  claimed.recovery.lastOutcome = outcome
  claimed.recovery.lastDetail = detail ? String(detail).slice(0, 500) : null
  if (released) {
    claimed.transitionTo('FAILED', {
      failureReason: `Recovered by operator (${outcome}): ${cleanReason}`.slice(0, 500),
    })
  }
  await claimed.save()

  const auditBase = {
    containmentId: claimed.containmentId,
    target: claimed.normalizedTarget,
    enforcementStatus: claimed.enforcementStatus,
    operatorId: userId(user),
    operatorEmail: user?.email,
    operatorRole: user?.role,
    details: { outcome, detail, diagnosedRuleState: claims.rs, reason: cleanReason },
  }
  logContainmentAudit({ action: released ? 'OPERATOR_RECOVERY_RELEASED' : 'OPERATOR_RECOVERY_DEFERRED', ...auditBase })
  try {
    const { logAudit } = require('../utils/auditLogger')
    await logAudit({
      action: 'CONTAINMENT_OPERATOR_RECOVERY',
      actor: user,
      target: { type: 'ContainmentAction', id: claimed.containmentId, identifier: claimed.normalizedTarget },
      status: released ? 'EXECUTED' : 'FAILED',
      details: auditBase.details,
    })
  } catch (err) {
    // The containment audit trail above already holds the record; the general log entry is secondary.
    logger.error(`[OperatorRecovery] AuditLog write failed for ${claimed.containmentId}: ${err.message}`)
  }
  return {
    containmentId: claimed.containmentId,
    outcome,
    released,
    enforcementStatus: claimed.enforcementStatus,
    lockHeld: !released,
    detail,
  }
}

module.exports = { diagnose, recover, RecoveryError, MIN_AGE_MS, _usedTokens: usedTokens }
