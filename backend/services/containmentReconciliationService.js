'use strict'

const ContainmentAction = require('../models/ContainmentAction')
const { getContainmentAdapter } = require('./containment/adapterFactory')
const BlockedIP = require('../models/BlockedIP')
const ThreatLog = require('../models/ThreatLog')
const logger = require('../utils/logger')
const { logContainmentAudit } = require('../utils/containmentAudit')
const { restoreStatusFor } = require('../utils/severity')

/**
 * ContainmentReconciliationService
 *
 * Scans for expired containment rules and automatically performs
 * safe adapter rollback, database updates, and event emission.
 */
// CONT-002: an action left in EXPIRING or ROLLING_BACK (adapter threw, MongoDB failed between two saves, process
// stopped mid-rollback) keeps its targetLock forever unless something picks it up again. After this grace period
// without an update it is treated as abandoned and its removal is completed (removeRule is idempotent).
const STUCK_GRACE_MS = () => parseInt(process.env.CONTAINMENT_STUCK_GRACE_MS, 10) || 5 * 60000

class ContainmentReconciliationService {
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 60000 // 1 minute default
    this.stuckGraceMs = options.stuckGraceMs || STUCK_GRACE_MS()
    this.timer = null
    this.isRunning = false
  }

  /**
   * Reconciles all currently expired active containment actions.
   *
   * @returns {Promise<{
   *   processed: number,
   *   successful: number,
   *   failed: number,
   *   actions: Array<Object>
   * }>}
   */
  async reconcileExpiredActions() {
    const now = new Date()
    const adapter = getContainmentAdapter()

    // Find all active or previously failed rollback actions past their expiration date
    const due = await ContainmentAction.find({
      enforcementStatus: { $in: ['ACTIVE', 'ROLLBACK_FAILED'] },
      expiresAt: { $ne: null, $lte: now },
    })
    // Removals that were started (by this reconciler or an operator rollback) and abandoned (CONT-002)
    const abandoned = await ContainmentAction.find({
      enforcementStatus: { $in: ['EXPIRING', 'ROLLING_BACK'] },
      updatedAt: { $lte: new Date(now.getTime() - this.stuckGraceMs) },
    })
    const byId = new Map()
    for (const action of [...(due || []), ...(abandoned || [])]) byId.set(action.containmentId, action)
    const expiredActions = [...byId.values()]

    if (expiredActions.length === 0) {
      return { processed: 0, successful: 0, failed: 0, actions: [] }
    }

    logger.info(`[ContainmentReconciliation] Found ${expiredActions.length} expired containment actions to reconcile`)

    let successful = 0
    let failed = 0
    const processedSummaries = []

    for (const action of expiredActions) {
      try {
        if (action.enforcementStatus === 'ACTIVE') {
          // Step 1: Transition ACTIVE -> EXPIRING
          action.transitionTo('EXPIRING')
          await action.save()
        }

        // Step 2: Transition to ROLLING_BACK (an abandoned rollback is already there)
        if (action.enforcementStatus !== 'ROLLING_BACK') {
          action.transitionTo('ROLLING_BACK')
          await action.save()
        }

        // Step 3: Invoke adapter rule removal. A throw is a failed removal, as in rollbackContainment, so the
        // action ends ROLLBACK_FAILED and is retried instead of staying ROLLING_BACK (CONT-002).
        let removeResult
        try {
          removeResult = await adapter.removeRule({
            containmentId: action.containmentId,
            ruleId: action.enforcementDetails?.ruleId,
            target: action.normalizedTarget,
            ruleName: action.enforcementDetails?.ruleName,
          })
        } catch (adapterErr) {
          removeResult = { success: false, stderr: adapterErr.message, exitCode: 1, executionDurationMs: 0 }
        }

        if (!removeResult.success) {
          logger.error(
            `[ContainmentReconciliation] Adapter removal failed for ${action.containmentId}: ${removeResult.stderr}`
          )
          action.transitionTo('ROLLBACK_FAILED', {
            rollbackDetails: {
              exitCode: removeResult.exitCode,
              stdout: removeResult.stdout,
              stderr: removeResult.stderr,
              executionDurationMs: removeResult.executionDurationMs,
              reason: 'TTL expiration removal failed in adapter',
            },
            failureReason: removeResult.stderr,
          })
          await action.save()
          failed++
          processedSummaries.push({ containmentId: action.containmentId, status: 'ROLLBACK_FAILED' })
          continue
        }

        // Step 4: Adapter removal succeeded -> Transition to ROLLED_BACK
        action.transitionTo('ROLLED_BACK', {
          rolledBackAt: new Date(),
          rollbackDetails: {
            exitCode: 0,
            stdout: removeResult.stdout,
            stderr: '',
            executionDurationMs: removeResult.executionDurationMs,
            reason: 'TTL expired - automatic reconciliation rollback',
          },
        })
        await action.save()

        // Step 5: Clean up legacy BlockedIP
        await BlockedIP.deleteOne({ ip: action.normalizedTarget })

        // Step 6: Restore candidate ThreatLogs
        const threatsToRestore = await ThreatLog.find({
          sourceIP: action.normalizedTarget,
          status: 'BLOCKED',
        })
        for (const t of threatsToRestore) {
          t.status = restoreStatusFor(t)
          t.preBlockStatus = null
          t.containmentId = null
          t.autonomousAction = { taken: false, actionType: null, actionTime: null }
          await t.save()
        }

        // Step 7: Emit events
        try {
          const socketManager = require('../websocket/socketManager')
          socketManager.emitIPUnblocked(action.normalizedTarget, 'System (TTL Expired)')
        } catch (e) {
          logger.warn(`[ContainmentReconciliation] Socket emission error: ${e.message}`)
        }

        successful++
        processedSummaries.push({ containmentId: action.containmentId, status: 'ROLLED_BACK' })
        logger.info(
          `[ContainmentReconciliation] Successfully rolled back expired containment ${action.containmentId} for ${action.normalizedTarget}`
        )
      } catch (err) {
        logger.error(`[ContainmentReconciliation] Error reconciling action ${action.containmentId}: ${err.message}`)
        failed++
        processedSummaries.push({ containmentId: action.containmentId, status: 'ERROR', error: err.message })
      }
    }

    return {
      processed: expiredActions.length,
      successful,
      failed,
      actions: processedSummaries,
    }
  }

  /**
   * CONT-003: recover requests interrupted before they reached ACTIVE or FAILED. They hold targetLock, so until now
   * the address could never be contained again. The adapter is only called once an action is APPLYING, so:
   *   VALIDATING / APPROVED -> FAILED (NOT_APPLIED), lock released.
   *   APPLYING: ask the adapter (inspectRule):
   *     ABSENT  -> FAILED (RULE_ABSENT), lock released.
   *     PRESENT -> remove the rule, confirm ABSENT, then FAILED (RULE_REMOVED). The half-finished rule is not adopted
   *                as ACTIVE: the requester got an error, no BlockedIP/threat/audit state was written, and no
   *                dashboard or unblock path would know about it. A new detection requests containment afresh.
   *     UNKNOWN, adapter unavailable, removal not confirmed, or recorded for another backend -> lock KEPT, outcome
   *                recorded, retried after the grace period. An unknown answer is never treated as "no rule".
   * Each action is claimed with a compare-and-set on its updatedAt, so concurrent or repeated passes act once.
   */
  async recoverAbandonedApplications() {
    const now = new Date()
    const cutoff = new Date(now.getTime() - this.stuckGraceMs)
    const candidates = await ContainmentAction.find({
      enforcementStatus: { $in: ['VALIDATING', 'APPROVED', 'APPLYING'] },
      updatedAt: { $lte: cutoff },
    })
      .select('_id updatedAt')
      .lean()

    const summary = { processed: 0, released: 0, unresolved: 0, actions: [] }
    for (const candidate of candidates) {
      const action = await ContainmentAction.findOneAndUpdate(
        {
          _id: candidate._id,
          updatedAt: candidate.updatedAt,
          enforcementStatus: { $in: ['VALIDATING', 'APPROVED', 'APPLYING'] },
        },
        { $inc: { 'recovery.attempts': 1 }, $set: { 'recovery.lastAttemptAt': now } },
        { new: true }
      )
      if (!action) continue // another pass claimed it, or the request finished meanwhile
      summary.processed++
      let outcome
      let detail = null
      try {
        ;({ outcome, detail } = await this._recoverOne(action))
      } catch (err) {
        outcome = 'ADAPTER_UNAVAILABLE'
        detail = err.message
      }
      const released = ['NOT_APPLIED', 'RULE_ABSENT', 'RULE_REMOVED'].includes(outcome)
      action.recovery.lastOutcome = outcome
      action.recovery.lastDetail = detail ? String(detail).slice(0, 500) : null
      if (released) {
        action.transitionTo('FAILED', { failureReason: `Interrupted before activation; recovered (${outcome})` })
      }
      await action.save()
      logContainmentAudit({
        action: released ? 'CONTAINMENT_RECOVERED' : 'CONTAINMENT_RECOVERY_DEFERRED',
        containmentId: action.containmentId,
        target: action.normalizedTarget,
        enforcementStatus: action.enforcementStatus,
        details: { outcome, detail, attempts: action.recovery.attempts },
      })
      if (released) summary.released++
      else {
        summary.unresolved++
        logger.warn(
          `[ContainmentReconciliation] ${action.containmentId} (${action.normalizedTarget}) still locked: ${outcome}`
        )
      }
      summary.actions.push({ containmentId: action.containmentId, outcome })
    }
    return summary
  }

  async _recoverOne(action) {
    if (action.enforcementStatus !== 'APPLYING') return { outcome: 'NOT_APPLIED' }
    const adapter = getContainmentAdapter()
    if (action.enforcementBackend && action.enforcementBackend !== adapter.getBackendType()) {
      return {
        outcome: 'BACKEND_MISMATCH',
        detail: `recorded ${action.enforcementBackend}, current ${adapter.getBackendType()}`,
      }
    }
    // Same identifiers requestContainment passed to applyRule
    const rule = {
      containmentId: action.containmentId,
      ruleId: action.enforcementDetails?.ruleId || undefined,
      target: action.normalizedTarget,
      ruleName: action.enforcementDetails?.ruleName || `SentinelAI-Rule-${action.containmentId}`,
    }
    const inspect = async () => (await adapter.inspectRule(rule))?.state
    const state = await inspect()
    if (state === 'ABSENT') return { outcome: 'RULE_ABSENT' }
    if (state !== 'PRESENT') return { outcome: 'RULE_STATE_UNKNOWN', detail: `inspectRule answered ${state}` }

    const removed = await adapter.removeRule(rule)
    if (!removed?.success) return { outcome: 'RULE_REMOVAL_FAILED', detail: removed?.stderr || 'removeRule failed' }
    const after = await inspect()
    if (after !== 'ABSENT')
      return { outcome: 'RULE_REMOVAL_FAILED', detail: `after removal inspectRule answered ${after}` }
    return { outcome: 'RULE_REMOVED' }
  }

  /** One periodic pass: TTL reconciliation, then recovery of interrupted applications. */
  async runOnce() {
    const ttl = await this.reconcileExpiredActions()
    const recovered = await this.recoverAbandonedApplications()
    return { ttl, recovered }
  }

  start() {
    if (this.isRunning) return
    this.isRunning = true
    this.timer = setInterval(async () => {
      try {
        await this.runOnce()
      } catch (err) {
        logger.error(`[ContainmentReconciliation] Unexpected error in interval: ${err.message}`)
      }
    }, this.intervalMs)
    this.timer.unref?.()
    logger.info(`[ContainmentReconciliation] Service started (interval: ${this.intervalMs}ms)`)
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
    this.isRunning = false
    logger.info('[ContainmentReconciliation] Service stopped')
  }
}

const defaultReconciliationService = new ContainmentReconciliationService()

module.exports = {
  ContainmentReconciliationService,
  defaultReconciliationService,
}
