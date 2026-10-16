'use strict'
/**
 * services/containmentService.js
 *
 * Centralized containment state machine, policy governance, and
 * compensating rollback service for SentinelAI (Phase 2.2 + Phase 4 Hardening).
 *
 * Key guarantees:
 * 1. Typed containment lifecycle: REQUESTED -> VALIDATING -> APPROVED -> APPLYING -> ACTIVE.
 * 2. Deterministic policy engine checks (self-lockout, loopback, gateway, broad CIDR prevention).
 * 3. Pluggable enforcement adapters (Mock default, simulated, Windows Firewall safety-gated).
 * 4. Application-level compensating rollback for multi-document operations in standalone MongoDB.
 * 5. Exact state restoration: MONITORING -> BLOCKED -> MONITORING, DETECTED -> BLOCKED -> DETECTED.
 * 6. Preservation of analyst triage states: RESOLVED and FALSE_POSITIVE are never converted to BLOCKED.
 * 7. Historical containment scoping via containmentId.
 * 8. Backward compatibility with legacy BlockedIP and ThreatLog queries.
 */

const ThreatLog = require('../models/ThreatLog')
const BlockedIP = require('../models/BlockedIP')
const ContainmentAction = require('../models/ContainmentAction')
const { evaluatePolicy, normalizeTarget } = require('./containmentPolicyService')
const { getContainmentAdapter } = require('./containment/adapterFactory')
const { logContainmentAudit } = require('../utils/containmentAudit')
const logger = require('../utils/logger')
const { isValidIP } = require('../utils/querySecurity')
const { v4: uuidv4 } = require('uuid')

/**
 * Executes a fully typed, policy-governed containment request (Phase 4).
 *
 * @param {Object} params
 * @param {string} params.target - Raw IP or CIDR target
 * @param {string} [params.actionType='block_ip'] - 'block_ip' | 'isolate_host' | 'rate_limit'
 * @param {number} [params.durationSeconds] - TTL in seconds
 * @param {boolean} [params.isPermanent=false] - Explicit permanent block flag
 * @param {string} [params.reason] - Human-readable justification
 * @param {Object} params.requester - Authenticated user object
 * @param {string} [params.idempotencyKey] - Optional client idempotency key
 * @param {string} [params.threatRef] - Optional ObjectId of related ThreatLog
 * @param {Object} [params.metadata] - Additional threat/target metadata
 * @returns {Promise<Object>}
 */
const requestContainment = async ({
  target,
  actionType = 'block_ip',
  durationSeconds,
  isPermanent = false,
  reason,
  requester,
  idempotencyKey,
  threatRef,
  metadata = {},
}) => {
  const correlationId = uuidv4()
  const cleanReason = (typeof reason === 'string' ? reason.trim().slice(0, 200) : '') || 'Containment policy action'

  // Step 1: Idempotency Key deduplication
  if (idempotencyKey) {
    const existingKeyAction = await ContainmentAction.findOne({ idempotencyKey })
    if (existingKeyAction) {
      logContainmentAudit({
        action: 'IDEMPOTENT_HIT',
        containmentId: existingKeyAction.containmentId,
        correlationId,
        target: existingKeyAction.target,
        enforcementStatus: existingKeyAction.enforcementStatus,
        operatorId: requester?._id || requester?.id,
        details: { idempotencyKey },
      })
      return { success: true, action: existingKeyAction, idempotent: true }
    }
  }

  // Step 2: Policy Evaluation (Pure deterministic checks)
  const policyResult = evaluatePolicy({
    target,
    actionType,
    durationSeconds,
    isPermanent,
    requester,
  })

  const targetInfo = policyResult.targetInfo || {}
  const normalized = targetInfo.normalizedTarget || normalizeTarget(target)
  const targetType = targetInfo.targetType || 'ipv4'

  // Step 3: Check for existing ACTIVE action on identical normalized target
  const existingActive = await ContainmentAction.findOne({
    normalizedTarget: normalized,
    enforcementStatus: 'ACTIVE',
  })

  if (existingActive) {
    logContainmentAudit({
      action: 'ALREADY_ACTIVE_HIT',
      containmentId: existingActive.containmentId,
      correlationId,
      target: normalized,
      enforcementStatus: 'ACTIVE',
      operatorId: requester?._id || requester?.id,
      details: { message: 'Target is already actively contained' },
    })
    return { success: true, action: existingActive, alreadyActive: true }
  }

  // Step 4: Create ContainmentAction in REQUESTED status
  const adapter = getContainmentAdapter()
  const actionDoc = new ContainmentAction({
    idempotencyKey: idempotencyKey || undefined,
    target,
    normalizedTarget: normalized,
    targetType,
    actionType,
    policyDecision: policyResult.decision,
    policyReason: policyResult.reason,
    enforcementBackend: adapter.getBackendType(),
    enforcementStatus: 'REQUESTED',
    correlationId,
    targetMetadata: {
      hostname: metadata.hostname || null,
      threatCategory: metadata.threatCategory || null,
      originalThreatId: threatRef || null,
      severity: metadata.severity || null,
    },
    requestedBy: requester?._id || requester?.id || null,
    requestedByName: requester?.name || 'System',
    requestedByRole: requester?.role || 'system',
    expiresAt: policyResult.expiration?.expiresAt || null,
  })

  logContainmentAudit({
    action: 'CONTAINMENT_REQUESTED',
    containmentId: actionDoc.containmentId,
    correlationId,
    target: normalized,
    actionType,
    policyDecision: policyResult.decision,
    enforcementBackend: adapter.getBackendType(),
    enforcementStatus: 'REQUESTED',
    operatorId: requester?._id || requester?.id,
    operatorEmail: requester?.email,
    operatorRole: requester?.role,
    details: { reason: cleanReason, durationSeconds, isPermanent },
  })

  // Step 5: Transition REQUESTED -> VALIDATING
  actionDoc.transitionTo('VALIDATING')
  await actionDoc.save()

  // Step 6: Handle Policy Denial / Safety Exclusions
  if (policyResult.decision !== 'ALLOWED') {
    actionDoc.transitionTo('REJECTED', {
      failureReason: policyResult.reason,
    })
    await actionDoc.save()

    logContainmentAudit({
      action: 'CONTAINMENT_REJECTED',
      containmentId: actionDoc.containmentId,
      correlationId,
      target: normalized,
      actionType,
      policyDecision: policyResult.decision,
      enforcementStatus: 'REJECTED',
      operatorId: requester?._id || requester?.id,
      operatorEmail: requester?.email,
      details: { reason: policyResult.reason },
    })

    const error = new Error(`Containment policy rejected: ${policyResult.reason}`)
    error.statusCode = 403
    error.action = actionDoc
    throw error
  }

  // Step 7: Transition VALIDATING -> APPROVED
  actionDoc.transitionTo('APPROVED', {
    approvedBy: requester?._id || requester?.id || null,
  })
  await actionDoc.save()

  // Step 8: Transition APPROVED -> APPLYING
  actionDoc.transitionTo('APPLYING')
  await actionDoc.save()

  // Step 9: Invoke Adapter
  let adapterResult
  try {
    adapterResult = await adapter.applyRule({
      containmentId: actionDoc.containmentId,
      target: normalized,
      targetType,
      ruleName: `SentinelAI-Rule-${actionDoc.containmentId}`,
    })
  } catch (adapterErr) {
    adapterResult = {
      success: false,
      stderr: adapterErr.message,
      exitCode: 1,
      executionDurationMs: 0,
    }
  }

  // Step 10: Process Adapter Result
  if (!adapterResult.success) {
    actionDoc.transitionTo('FAILED', {
      failureReason: adapterResult.stderr || 'Adapter enforcement failed',
      enforcementDetails: {
        adapterName: adapter.constructor.name,
        ruleName: adapterResult.ruleName,
        ruleId: adapterResult.ruleId,
        exitCode: adapterResult.exitCode,
        stdout: adapterResult.stdout,
        stderr: adapterResult.stderr,
        executionDurationMs: adapterResult.executionDurationMs,
      },
    })
    await actionDoc.save()

    logContainmentAudit({
      action: 'ENFORCEMENT_FAILED',
      containmentId: actionDoc.containmentId,
      correlationId,
      target: normalized,
      enforcementStatus: 'FAILED',
      operatorId: requester?._id || requester?.id,
      details: { stderr: adapterResult.stderr, exitCode: adapterResult.exitCode },
    })

    const error = new Error(`Adapter enforcement failed: ${adapterResult.stderr || 'Unknown adapter error'}`)
    error.statusCode = 502
    error.action = actionDoc
    throw error
  }

  // Step 11: Transition APPLYING -> ACTIVE
  actionDoc.transitionTo('ACTIVE', {
    appliedAt: new Date(),
    enforcementDetails: {
      adapterName: adapter.constructor.name,
      ruleName: adapterResult.ruleName,
      ruleId: adapterResult.ruleId,
      exitCode: 0,
      stdout: adapterResult.stdout,
      stderr: '',
      executionDurationMs: adapterResult.executionDurationMs,
    },
  })
  await actionDoc.save()

  logContainmentAudit({
    action: 'CONTAINMENT_ACTIVE',
    containmentId: actionDoc.containmentId,
    correlationId,
    target: normalized,
    actionType,
    enforcementBackend: adapter.getBackendType(),
    enforcementStatus: 'ACTIVE',
    operatorId: requester?._id || requester?.id,
    operatorEmail: requester?.email,
    details: {
      ruleId: adapterResult.ruleId,
      executionDurationMs: adapterResult.executionDurationMs,
      expiresAt: actionDoc.expiresAt,
    },
  })

  // Step 12: Maintain Backward Compatibility with BlockedIP
  try {
    await BlockedIP.findOneAndUpdate(
      { ip: normalized },
      {
        ip: normalized,
        reason: cleanReason,
        blockedAt: new Date(),
        blockedBy: requester?._id || requester?.id || null,
        threatRef: threatRef || null,
      },
      { upsert: true, new: true }
    )
  } catch (blockedIpErr) {
    logger.warn(`[Containment] BlockedIP sync warning: ${blockedIpErr.message}`)
  }

  // Step 13: Transition matching candidate ThreatLogs
  try {
    const candidateThreats = await ThreatLog.find({
      sourceIP: normalized,
      status: { $in: ['DETECTED', 'MONITORING', 'ESCALATED'] },
    })
    for (const t of candidateThreats) {
      t.preBlockStatus = t.status
      t.status = 'BLOCKED'
      t.containmentId = actionDoc._id
      t.handledBy = requester?._id || requester?.id
      t.autonomousAction = {
        taken: true,
        actionType: 'IP_BLOCKED',
        actionTime: new Date(),
      }
      await t.save()
    }
  } catch (threatErr) {
    logger.warn(`[Containment] Candidate threat update warning: ${threatErr.message}`)
  }

  // Step 14: Emit WebSocket events
  try {
    const socketManager = require('../websocket/socketManager')
    socketManager.emitIPBlocked(normalized, requester?.name || 'System', threatRef || null)
  } catch (socketErr) {
    logger.warn(`[Containment] Socket emission warning: ${socketErr.message}`)
  }

  return { success: true, action: actionDoc }
}

/**
 * Rolls back an active containment action (Phase 4).
 *
 * @param {Object} params
 * @param {string} params.containmentId
 * @param {Object} params.operator
 * @param {string} [params.reason]
 * @returns {Promise<Object>}
 */
const rollbackContainment = async ({ containmentId, operator, reason }) => {
  const actionDoc = await ContainmentAction.findOne({ containmentId })
  if (!actionDoc) {
    const err = new Error(`Containment action '${containmentId}' not found`)
    err.statusCode = 404
    throw err
  }

  if (actionDoc.enforcementStatus !== 'ACTIVE' && actionDoc.enforcementStatus !== 'ROLLBACK_FAILED') {
    const err = new Error(
      `Cannot rollback containment action in status '${actionDoc.enforcementStatus}'. Only ACTIVE or ROLLBACK_FAILED actions can be rolled back.`
    )
    err.statusCode = 400
    throw err
  }

  const correlationId = uuidv4()
  const cleanReason = reason || 'Manual operator rollback'

  // Step 1: Transition to ROLLING_BACK
  actionDoc.transitionTo('ROLLING_BACK')
  await actionDoc.save()

  logContainmentAudit({
    action: 'ROLLBACK_INITIATED',
    containmentId: actionDoc.containmentId,
    correlationId,
    target: actionDoc.normalizedTarget,
    enforcementStatus: 'ROLLING_BACK',
    operatorId: operator?._id || operator?.id,
    operatorEmail: operator?.email,
    details: { reason: cleanReason },
  })

  // Step 2: Invoke Adapter Rule Removal
  const adapter = getContainmentAdapter()
  let removeResult
  try {
    removeResult = await adapter.removeRule({
      containmentId: actionDoc.containmentId,
      ruleId: actionDoc.enforcementDetails?.ruleId,
      target: actionDoc.normalizedTarget,
      ruleName: actionDoc.enforcementDetails?.ruleName,
    })
  } catch (adapterErr) {
    removeResult = {
      success: false,
      stderr: adapterErr.message,
      exitCode: 1,
      executionDurationMs: 0,
    }
  }

  // Step 3: Process Removal Result
  if (!removeResult.success) {
    actionDoc.transitionTo('ROLLBACK_FAILED', {
      failureReason: removeResult.stderr || 'Adapter rollback failed',
      rollbackDetails: {
        ruleId: actionDoc.enforcementDetails?.ruleId,
        exitCode: removeResult.exitCode,
        stdout: removeResult.stdout,
        stderr: removeResult.stderr,
        executionDurationMs: removeResult.executionDurationMs,
        reason: cleanReason,
      },
    })
    await actionDoc.save()

    logContainmentAudit({
      action: 'ROLLBACK_FAILED',
      containmentId: actionDoc.containmentId,
      correlationId,
      target: actionDoc.normalizedTarget,
      enforcementStatus: 'ROLLBACK_FAILED',
      operatorId: operator?._id || operator?.id,
      details: { stderr: removeResult.stderr },
    })

    const err = new Error(`Adapter rollback failed: ${removeResult.stderr || 'Unknown adapter error'}`)
    err.statusCode = 502
    err.action = actionDoc
    throw err
  }

  // Step 4: Transition ROLLING_BACK -> ROLLED_BACK
  actionDoc.transitionTo('ROLLED_BACK', {
    rolledBackAt: new Date(),
    rollbackDetails: {
      ruleId: actionDoc.enforcementDetails?.ruleId,
      exitCode: 0,
      stdout: removeResult.stdout,
      stderr: '',
      executionDurationMs: removeResult.executionDurationMs,
      reason: cleanReason,
    },
  })
  await actionDoc.save()

  // Step 5: Clean up legacy BlockedIP
  try {
    await BlockedIP.deleteOne({ ip: actionDoc.normalizedTarget })
  } catch (e) {
    logger.warn(`[Containment] BlockedIP deletion warning: ${e.message}`)
  }

  // Step 6: Restore candidate ThreatLogs
  try {
    const threatsToRestore = await ThreatLog.find({
      sourceIP: actionDoc.normalizedTarget,
      status: 'BLOCKED',
    })
    for (const t of threatsToRestore) {
      t.status = t.preBlockStatus || (t.aiScore >= 0.7 ? 'MONITORING' : 'DETECTED')
      t.preBlockStatus = null
      t.containmentId = null
      t.autonomousAction = { taken: false, actionType: null, actionTime: null }
      await t.save()
    }
  } catch (e) {
    logger.warn(`[Containment] ThreatLog restoration warning: ${e.message}`)
  }

  // Step 7: Emit WebSocket event
  try {
    const socketManager = require('../websocket/socketManager')
    socketManager.emitIPUnblocked(actionDoc.normalizedTarget, operator?.name || 'Operator')
  } catch (e) {
    logger.warn(`[Containment] Socket emission warning: ${e.message}`)
  }

  logContainmentAudit({
    action: 'CONTAINMENT_ROLLED_BACK',
    containmentId: actionDoc.containmentId,
    correlationId,
    target: actionDoc.normalizedTarget,
    enforcementStatus: 'ROLLED_BACK',
    operatorId: operator?._id || operator?.id,
    operatorEmail: operator?.email,
    details: { reason: cleanReason },
  })

  return { success: true, action: actionDoc }
}

/**
 * Returns current status of containment subsystem.
 */
const getContainmentStatus = async () => {
  const adapter = getContainmentAdapter()
  const activeCount = await ContainmentAction.countDocuments({ enforcementStatus: 'ACTIVE' })
  const failedCount = await ContainmentAction.countDocuments({
    enforcementStatus: { $in: ['FAILED', 'ROLLBACK_FAILED'] },
  })

  return {
    backend: adapter.getBackendType(),
    adapterName: adapter.constructor.name,
    realEnforcementEnabled: process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true',
    activeContainmentCount: activeCount,
    failedContainmentCount: failedCount,
    timestamp: new Date().toISOString(),
  }
}

// ============================================================================
// LEGACY COMPATIBILITY METHODS (Fully Preserved with Existing Invariants)
// ============================================================================

/**
 * Manually block an individual threat by ID (Analyst action).
 * Order: ThreatLog state transition -> BlockedIP upsert.
 * Compensation: If BlockedIP fails, ThreatLog is reverted to prior state (Scenario A).
 */
const blockThreat = async (threatId, analystId, reason = 'Manual threat block') => {
  const threat = await ThreatLog.findById(threatId)
  if (!threat) return null

  // Protection of analyst terminal states
  if (threat.status === 'RESOLVED' || threat.status === 'FALSE_POSITIVE') {
    logger.warn(`[Containment] Cannot block threat ${threatId}: Threat is in analyst terminal state ${threat.status}`)
    return threat
  }

  // Idempotency: if already BLOCKED, preserve existing preBlockStatus and ensure BlockedIP exists
  if (threat.status === 'BLOCKED') {
    await BlockedIP.findOneAndUpdate(
      { ip: threat.sourceIP },
      {
        ip: threat.sourceIP,
        reason: reason || 'Manual threat block',
        blockedAt: new Date(),
        blockedBy: analystId,
        threatRef: threat._id,
      },
      { upsert: true, new: true }
    )
    return threat
  }

  // Snapshot prior state for compensating rollback
  const priorStatus = threat.status
  const priorPreBlockStatus = threat.preBlockStatus
  const priorContainmentId = threat.containmentId
  const priorHandledBy = threat.handledBy
  const priorAutonomousAction = threat.autonomousAction
    ? {
        taken: threat.autonomousAction.taken,
        actionType: threat.autonomousAction.actionType,
        actionTime: threat.autonomousAction.actionTime,
      }
    : { taken: false, actionType: null, actionTime: null }

  // Step 1: Update ThreatLog state to BLOCKED
  threat.preBlockStatus = priorStatus
  threat.status = 'BLOCKED'
  threat.handledBy = analystId
  threat.autonomousAction = {
    taken: true,
    actionType: 'IP_BLOCKED',
    actionTime: new Date(),
  }
  await threat.save()

  // Step 2: Upsert BlockedIP (Scenario A compensation on failure)
  let blockedDoc
  try {
    blockedDoc = await BlockedIP.findOneAndUpdate(
      { ip: threat.sourceIP },
      {
        ip: threat.sourceIP,
        reason: reason || 'Manual threat block',
        blockedAt: new Date(),
        blockedBy: analystId,
        threatRef: threat._id,
      },
      { upsert: true, new: true }
    )
    threat.containmentId = blockedDoc._id
    await threat.save()
  } catch (blockedIpErr) {
    logger.error(
      `[Containment] BlockedIP operation failed for ${threat.sourceIP}: ${blockedIpErr.message}. Attempting compensating rollback on ThreatLog ${threat._id}...`
    )
    try {
      threat.status = priorStatus
      threat.preBlockStatus = priorPreBlockStatus
      threat.containmentId = priorContainmentId
      threat.handledBy = priorHandledBy
      threat.autonomousAction = priorAutonomousAction
      await threat.save()
      logger.info(`[Containment] ThreatLog ${threat._id} successfully compensated back to ${priorStatus}`)
    } catch (compErr) {
      logger.error(
        `[CRITICAL] [Containment Compensation Failure] Failed to compensate ThreatLog ${threat._id}: ${compErr.message}. Inconsistency may exist! Original error: ${blockedIpErr.message}`
      )
      const err = new Error(`Containment failed and compensation failed: ${compErr.message}`)
      err.originalError = blockedIpErr
      err.compensationError = compErr
      err.isInconsistent = true
      throw err
    }
    throw blockedIpErr
  }

  return threat
}

/**
 * Manually block an IP address across all active candidate threats (Analyst action).
 * Order: BlockedIP upsert -> candidate ThreatLogs update.
 * Compensation: If ThreatLog update fails, BlockedIP is restored or removed (Scenario B).
 */
const blockIPManual = async ({ ip, reason, analystId, analystName, analystEmail }) => {
  if (!ip || typeof ip !== 'string' || !isValidIP(ip.trim())) {
    throw new Error('Valid IP address is required')
  }
  const cleanIP = ip.trim()
  const cleanReason = (typeof reason === 'string' ? reason.trim().slice(0, 200) : '') || 'Manual analyst block'

  // Snapshot existing BlockedIP state to support Scenario B compensation
  const foundBlocked = await BlockedIP.findOne({ ip: cleanIP })
  const existingBlockedDoc = foundBlocked ? (foundBlocked.toObject ? foundBlocked.toObject() : foundBlocked) : null

  // Find candidate ThreatLogs to transition
  // Strictly protect RESOLVED and FALSE_POSITIVE; exclude already BLOCKED to avoid overwriting preBlockStatus
  const candidateThreats = await ThreatLog.find({
    sourceIP: cleanIP,
    status: { $in: ['DETECTED', 'MONITORING', 'ESCALATED'] },
  })

  // Step 1: Upsert BlockedIP record
  let blockedRecord
  try {
    blockedRecord = await BlockedIP.findOneAndUpdate(
      { ip: cleanIP },
      {
        ip: cleanIP,
        reason: cleanReason,
        blockedAt: new Date(),
        blockedBy: analystId,
        threatRef: candidateThreats.length > 0 ? candidateThreats[0]._id : null,
      },
      { upsert: true, new: true }
    )
  } catch (err) {
    logger.error(`[Containment] Failed to create/update BlockedIP for ${cleanIP}: ${err.message}`)
    throw err
  }

  // Step 2: Transition candidate ThreatLogs with containmentId
  const updatedThreats = []
  try {
    for (const t of candidateThreats) {
      t.preBlockStatus = t.status // preserve DETECTED / MONITORING / ESCALATED
      t.status = 'BLOCKED'
      t.containmentId = blockedRecord._id
      t.handledBy = analystId
      t.autonomousAction = {
        taken: true,
        actionType: 'IP_BLOCKED',
        actionTime: new Date(),
      }
      await t.save()
      updatedThreats.push(t)
    }
  } catch (threatErr) {
    logger.error(
      `[Containment] ThreatLog update failed during blockIPManual for ${cleanIP}: ${threatErr.message}. Attempting compensating rollback on BlockedIP...`
    )
    try {
      // Rollback any threats that were partially updated
      for (const t of updatedThreats) {
        t.status = t.preBlockStatus || 'DETECTED'
        t.preBlockStatus = null
        t.containmentId = null
        t.autonomousAction = { taken: false, actionType: null, actionTime: null }
        await t.save()
      }

      // Compensate BlockedIP: restore previous document if existed, or delete if newly created
      if (existingBlockedDoc) {
        await BlockedIP.findOneAndReplace({ _id: existingBlockedDoc._id }, existingBlockedDoc)
        logger.info(`[Containment] Successfully restored previous BlockedIP record for ${cleanIP}`)
      } else {
        await BlockedIP.findByIdAndDelete(blockedRecord._id)
        logger.info(`[Containment] Successfully removed newly created BlockedIP record for ${cleanIP}`)
      }
    } catch (compErr) {
      logger.error(
        `[CRITICAL] [Containment Compensation Failure] Failed to compensate BlockedIP/ThreatLogs for ${cleanIP}: ${compErr.message}. Original error: ${threatErr.message}`
      )
      const err = new Error(`Containment failed and compensation failed: ${compErr.message}`)
      err.originalError = threatErr
      err.compensationError = compErr
      err.isInconsistent = true
      throw err
    }
    throw threatErr
  }

  return { blockedIP: blockedRecord, updatedThreats }
}

/**
 * Manually unblock an IP address and restore pre-block state (Analyst action).
 * Order: BlockedIP deletion -> scoped ThreatLogs restoration.
 * Compensation: If ThreatLog restoration fails, BlockedIP is re-inserted and threats re-blocked.
 */
const unblockIPManual = async ({ ip, analystId, analystName, analystEmail }) => {
  if (!ip || typeof ip !== 'string' || !isValidIP(ip.trim())) {
    throw new Error('Valid IP address is required')
  }
  const cleanIP = ip.trim()

  const blockedDoc = await BlockedIP.findOne({ ip: cleanIP })
  if (!blockedDoc) {
    return { notFound: true, message: 'IP is not blocked' }
  }

  const savedBlockedDoc = blockedDoc.toObject ? blockedDoc.toObject() : { ...blockedDoc }

  // Scoped query: identify ThreatLogs specifically tagged with this containment event
  let threatsToRestore = await ThreatLog.find({
    sourceIP: cleanIP,
    status: 'BLOCKED',
    containmentId: blockedDoc._id,
  })

  // Fallback for legacy single-threat containment if containmentId was null but threatRef matched
  if (threatsToRestore.length === 0 && blockedDoc.threatRef) {
    const singleThreat = await ThreatLog.findOne({
      _id: blockedDoc.threatRef,
      sourceIP: cleanIP,
      status: 'BLOCKED',
    })
    if (singleThreat) threatsToRestore = [singleThreat]
  }

  // Step 1: Delete BlockedIP
  await BlockedIP.deleteOne({ _id: blockedDoc._id })

  // Step 2: Restore ThreatLogs to exact preBlockStatus
  const restoredThreats = []
  try {
    for (const t of threatsToRestore) {
      const targetStatus = t.preBlockStatus || (t.aiScore >= 0.7 ? 'MONITORING' : 'DETECTED')
      t.status = targetStatus
      t.preBlockStatus = null
      t.containmentId = null
      t.autonomousAction = { taken: false, actionType: null, actionTime: null }
      await t.save()
      restoredThreats.push(t)
    }
  } catch (restoreErr) {
    logger.error(
      `[Containment] ThreatLog restoration failed during unblock of ${cleanIP}: ${restoreErr.message}. Attempting compensating rollback by restoring BlockedIP...`
    )
    try {
      // Re-insert BlockedIP to prevent unverified traffic bypass
      const { _id, ...docData } = savedBlockedDoc
      await BlockedIP.findOneAndUpdate({ ip: cleanIP }, docData, { upsert: true, new: true })
      // Re-block any threats that were partially restored
      for (const t of restoredThreats) {
        t.status = 'BLOCKED'
        t.containmentId = blockedDoc._id
        t.autonomousAction = { taken: true, actionType: 'IP_BLOCKED', actionTime: new Date() }
        await t.save()
      }
      logger.info(`[Containment] Successfully compensated unblock failure: BlockedIP restored for ${cleanIP}`)
    } catch (compErr) {
      logger.error(
        `[CRITICAL] [Containment Compensation Failure] Failed to re-insert BlockedIP during unblock rollback for ${cleanIP}: ${compErr.message}. Original error: ${restoreErr.message}`
      )
      const err = new Error(`Unblock failed and compensation failed: ${compErr.message}`)
      err.originalError = restoreErr
      err.compensationError = compErr
      err.isInconsistent = true
      throw err
    }
    throw restoreErr
  }

  return { success: true, unblockedIP: cleanIP, restoredThreats }
}

/**
 * Execute automated containment for high-confidence threats (AI Engine / Honeypot).
 * Updates BlockedIP and associates containmentId.
 * Compensation: If BlockedIP fails, ThreatLog status is rolled back to priorStatus.
 */
const executeAutoBlock = async ({ threat, threatScore, source = 'AI Engine', sourceRef = null }) => {
  const priorStatus = threat.preBlockStatus || (threat.aiScore >= 0.7 ? 'MONITORING' : 'DETECTED')
  const priorAutonomousAction = threat.autonomousAction
    ? {
        taken: threat.autonomousAction.taken,
        actionType: threat.autonomousAction.actionType,
        actionTime: threat.autonomousAction.actionTime,
      }
    : { taken: false, actionType: null, actionTime: null }

  let blockedDoc
  try {
    blockedDoc = await BlockedIP.findOneAndUpdate(
      { ip: threat.sourceIP },
      {
        ip: threat.sourceIP,
        reason: `${source} Autonomous Action (score = ${threatScore})`,
        blockedAt: new Date(),
        blockedBy: null,
        threatRef: threat._id,
      },
      { upsert: true, new: true }
    )
    threat.containmentId = blockedDoc._id
    await threat.save()
  } catch (blockedErr) {
    logger.error(
      `[Containment] Auto-block BlockedIP write failed for ${threat.sourceIP}: ${blockedErr.message}. Attempting compensating rollback on ThreatLog...`
    )
    try {
      threat.status = priorStatus
      threat.preBlockStatus = null
      threat.containmentId = null
      threat.autonomousAction = priorAutonomousAction
      await threat.save()
      logger.info(`[Containment] Auto-block ThreatLog ${threat._id} compensated back to ${priorStatus}`)
    } catch (compErr) {
      logger.error(
        `[CRITICAL] [Containment Compensation Failure] Failed to compensate auto-blocked ThreatLog ${threat._id}: ${compErr.message}. Original error: ${blockedErr.message}`
      )
      const err = new Error(`Auto-block containment and compensation failed: ${compErr.message}`)
      err.originalError = blockedErr
      err.compensationError = compErr
      err.isInconsistent = true
      throw err
    }
    throw blockedErr
  }

  // Socket & Alert emission ONLY after containment succeeds
  try {
    const socketManager = require('../websocket/socketManager')
    const alertService = require('./alertService')

    socketManager.emitIPBlocked(threat.sourceIP, source, threat._id)

    const alert = await alertService.createAlert({
      title: 'IP Address Blocked (Auto)',
      message: `IP ${threat.sourceIP} blocked automatically by ${source} (Score: ${Math.round(threatScore * 100)}%)`,
      severity: 'HIGH',
      type: 'IP_BLOCKED',
      sourceRef: sourceRef || { refModel: 'ThreatLog', refId: threat._id },
    })
    socketManager.emitNewAlert(alert)
  } catch (e) {
    logger.error(`[AI Auto-Block] Alert/Socket emission failed: ${e.message}`)
  }

  return { success: true, blockedDoc, threat }
}

module.exports = {
  requestContainment,
  rollbackContainment,
  getContainmentStatus,
  blockThreat,
  blockIPManual,
  unblockIPManual,
  executeAutoBlock,
}
