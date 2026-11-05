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
// Statuses of a request that holds targetLock but has not reached ACTIVE or FAILED
const IN_FLIGHT_STATUSES = ['VALIDATING', 'APPROVED', 'APPLYING']
// CONT-007: late-rule retry back-off, 1, 2, 4 ... minutes, capped at an hour
const LATE_RULE_BASE_DELAY_MS = 60000
const LATE_RULE_MAX_DELAY_MS = 60 * 60000
// CONT-005: how long the original request gets to write the deny-list/threat state itself after ACTIVE
const LEGACY_SYNC_GRACE_MS = () => parseInt(process.env.CONTAINMENT_LEGACY_SYNC_GRACE_MS, 10) || 60000

class ContainmentReconciliationService {
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 60000 // 1 minute default
    this.stuckGraceMs = options.stuckGraceMs || STUCK_GRACE_MS()
    this.legacySyncGraceMs = options.legacySyncGraceMs || LEGACY_SYNC_GRACE_MS()
    // from the last periodic pass
    this.lastCounts = { stuck: 0, lateRulesUnremoved: 0, legacySyncPending: 0, needsInvestigation: 0 }
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
      return { processed: 0, successful: 0, failed: 0, skipped: 0, actions: [] }
    }

    logger.info(`[ContainmentReconciliation] Found ${expiredActions.length} expired containment actions to reconcile`)

    let successful = 0
    let failed = 0
    let skipped = 0
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
        if (err?.name === 'VersionError') {
          // CONT-006: an operator rollback (or another worker) changed this action after it was loaded; that path
          // owns the release now. Not a failure: nothing was done here and the version check prevented a conflict.
          logger.info(`[ContainmentReconciliation] ${action.containmentId} changed concurrently; left to its owner`)
          skipped++
          processedSummaries.push({ containmentId: action.containmentId, status: 'SKIPPED_CONCURRENT' })
          continue
        }
        logger.error(`[ContainmentReconciliation] Error reconciling action ${action.containmentId}: ${err.message}`)
        failed++
        processedSummaries.push({ containmentId: action.containmentId, status: 'ERROR', error: err.message })
      }
    }

    return {
      processed: expiredActions.length,
      successful,
      failed,
      skipped,
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
      enforcementStatus: { $in: IN_FLIGHT_STATUSES },
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
          enforcementStatus: { $in: IN_FLIGHT_STATUSES },
        },
        // __v + 1 fences the original request: its next version-checked save fails instead of overwriting recovery
        { $inc: { 'recovery.attempts': 1, __v: 1 }, $set: { 'recovery.lastAttemptAt': now } },
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

  /**
   * CONT-003: rules created by a request after recovery had released its action, whose removal the request could not
   * confirm (recovery.lateRule PRESENT_UNREMOVED). Removed and confirmed ABSENT -> REMOVED; anything else stays
   * flagged (never assumed gone) and is retried on the next pass.
   */
  async removeLateRules(now = new Date()) {
    // CONT-007: only rules whose back-off has elapsed, so an unavailable adapter is not hit on every pass
    const flagged = await ContainmentAction.find({
      'recovery.lateRule': 'PRESENT_UNREMOVED',
      $or: [{ 'recovery.lateRuleNextAttemptAt': null }, { 'recovery.lateRuleNextAttemptAt': { $lte: now } }],
    })
    const summary = { processed: 0, removed: 0, unresolved: 0 }
    const adapter = getContainmentAdapter()
    for (const action of flagged || []) {
      summary.processed++
      const rule = {
        containmentId: action.containmentId,
        ruleId: action.enforcementDetails?.ruleId || undefined,
        target: action.normalizedTarget,
        ruleName: action.enforcementDetails?.ruleName || `SentinelAI-Rule-${action.containmentId}`,
      }
      let state = null
      try {
        if (action.enforcementBackend && action.enforcementBackend !== adapter.getBackendType()) {
          state = 'BACKEND_MISMATCH'
        } else {
          state = (await adapter.inspectRule(rule))?.state
          if (state === 'PRESENT') {
            await adapter.removeRule(rule)
            state = (await adapter.inspectRule(rule))?.state
          }
        }
      } catch (err) {
        state = `UNAVAILABLE: ${err.message}`
      }
      if (state === 'ABSENT') {
        await ContainmentAction.updateOne(
          { _id: action._id, 'recovery.lateRule': 'PRESENT_UNREMOVED' },
          {
            $set: {
              'recovery.lateRule': 'REMOVED',
              'recovery.lateRuleAt': now,
              'recovery.lateRuleNextAttemptAt': null,
              'recovery.lateRuleLastError': null,
            },
          }
        )
        summary.removed++
        logContainmentAudit({ action: 'LATE_RULE_REMOVED', containmentId: action.containmentId, target: rule.target })
      } else {
        summary.unresolved++
        const attempts = (action.recovery?.lateRuleAttempts || 0) + 1
        const delay = Math.min(LATE_RULE_BASE_DELAY_MS * 2 ** (attempts - 1), LATE_RULE_MAX_DELAY_MS)
        // The flag stays PRESENT_UNREMOVED however many attempts fail: the rule may still be enforced
        await ContainmentAction.updateOne(
          { _id: action._id, 'recovery.lateRule': 'PRESENT_UNREMOVED' },
          {
            $set: {
              'recovery.lateRuleAttempts': attempts,
              'recovery.lateRuleNextAttemptAt': new Date(now.getTime() + delay),
              'recovery.lateRuleLastError': String(state || 'no answer').slice(0, 500),
            },
          }
        )
        logger.warn(
          `[ContainmentReconciliation] late rule of ${action.containmentId} (${rule.target}) still unconfirmed: ${state}; ` +
            `attempt ${attempts}, next in ${Math.round(delay / 1000)} s`
        )
      }
    }
    return summary
  }

  /**
   * CONT-005: ACTIVE actions whose deny-list entry / threat statuses were not written (MongoDB failure or a stop right
   * after the ACTIVE save). Re-runs the idempotent sync once the original request had its chance (legacySyncGraceMs).
   * Claimed per action without a version bump, so a concurrent rollback is not fenced; if the action stopped being
   * ACTIVE while the sync ran, the sync is undone (releaseLegacyBlockState) so a released address is not re-blocked.
   */
  async resyncLegacyState(now = new Date()) {
    const containment = require('./containmentService')
    const cutoff = new Date(now.getTime() - this.legacySyncGraceMs)
    const candidates = await ContainmentAction.find({
      enforcementStatus: 'ACTIVE',
      'legacySync.pending': true,
      updatedAt: { $lte: cutoff },
    })
      .select('_id legacySync')
      .lean()
    const summary = { processed: 0, synced: 0, failed: 0, compensated: 0 }
    for (const candidate of candidates) {
      const action = await ContainmentAction.findOneAndUpdate(
        {
          _id: candidate._id,
          enforcementStatus: 'ACTIVE',
          'legacySync.pending': true,
          'legacySync.lastAttemptAt': candidate.legacySync?.lastAttemptAt ?? null,
        },
        { $set: { 'legacySync.lastAttemptAt': now }, $inc: { 'legacySync.attempts': 1 } },
        { new: true }
      )
      if (!action) continue // claimed by another pass, or released meanwhile
      summary.processed++
      const result = await containment.syncLegacyBlockState({
        normalized: action.normalizedTarget,
        cleanReason: action.legacySync.reason || `Containment ${action.containmentId}`,
        requester: action.requestedBy ? { id: String(action.requestedBy) } : null,
        threatRef: action.legacySync.threatRef || null,
        actionDoc: action,
      })
      const fresh = await ContainmentAction.findById(action._id).lean()
      if (fresh && fresh.enforcementStatus !== 'ACTIVE') {
        await containment.releaseLegacyBlockState(fresh, null) // released while syncing: undo what was written
        await containment.markLegacySync(action._id, { ok: true })
        summary.compensated++
        continue
      }
      await containment.markLegacySync(action._id, result)
      if (result.ok) {
        summary.synced++
        logContainmentAudit({
          action: 'LEGACY_STATE_RESYNCED',
          containmentId: action.containmentId,
          target: action.normalizedTarget,
        })
      } else {
        summary.failed++
        logger.warn(
          `[ContainmentReconciliation] deny-list sync of ${action.containmentId} still failing: ${result.error}`
        )
      }
    }
    return summary
  }

  /**
   * Operator view of recovery problems (read-only; GET /api/containment/recovery). Lists requests stuck in
   * VALIDATING/APPROVED/APPLYING past the grace period and rules flagged by a fenced request, with how long each has
   * been stuck, the recovery attempts, the last outcome and whether the rule state was verified. Nothing here
   * releases a lock: an action whose rule state cannot be verified keeps it until the adapter answers.
   */
  async getRecoveryReport(now = new Date()) {
    const VERIFIED = { NOT_APPLIED: 'not applied', RULE_ABSENT: 'absent', RULE_REMOVED: 'removed' }
    const cutoff = new Date(now.getTime() - this.stuckGraceMs)
    const [stuck, late, legacy] = await Promise.all([
      ContainmentAction.find({ enforcementStatus: { $in: IN_FLIGHT_STATUSES }, updatedAt: { $lte: cutoff } })
        .sort({ updatedAt: 1 })
        .limit(100)
        .lean(),
      ContainmentAction.find({ 'recovery.lateRule': 'PRESENT_UNREMOVED' }).limit(100).lean(),
      // CONT-005: ACTIVE actions whose deny-list entry / threat statuses are not written yet
      ContainmentAction.find({ enforcementStatus: 'ACTIVE', 'legacySync.pending': true }).limit(100).lean(),
    ])
    const view = (a) => {
      const recovery = a.recovery || {}
      const ruleState = VERIFIED[recovery.lastOutcome] || null
      const legacySyncPending = Boolean(a.legacySync?.pending) && a.enforcementStatus === 'ACTIVE'
      return {
        containmentId: a.containmentId,
        target: a.normalizedTarget,
        enforcementStatus: a.enforcementStatus,
        enforcementBackend: a.enforcementBackend,
        stuckForSeconds: Math.round((now - new Date(a.updatedAt)) / 1000),
        recoveryAttempts: recovery.attempts || 0,
        lastAttemptAt: recovery.lastAttemptAt || null,
        lastOutcome: recovery.lastOutcome || null,
        lastDetail: recovery.lastDetail || null,
        lateRule: recovery.lateRule || null,
        lateRuleAttempts: recovery.lateRuleAttempts || 0,
        lateRuleNextAttemptAt: recovery.lateRuleNextAttemptAt || null,
        lateRuleLastError: recovery.lateRuleLastError || null,
        legacySyncPending,
        legacySyncAttempts: legacySyncPending ? a.legacySync.attempts || 0 : 0,
        legacySyncLastError: legacySyncPending ? a.legacySync.lastError || null : null,
        ruleVerified: Boolean(ruleState) && recovery.lateRule !== 'PRESENT_UNREMOVED',
        // Not yet attempted means the next pass will try; anything attempted and still here needs a person
        needsInvestigation:
          recovery.lateRule === 'PRESENT_UNREMOVED' ||
          (IN_FLIGHT_STATUSES.includes(a.enforcementStatus) && (recovery.attempts || 0) > 0) ||
          (legacySyncPending && (a.legacySync.attempts || 0) > 0),
      }
    }
    // One row per action even if it is in more than one list
    const byId = new Map()
    for (const a of [...stuck, ...late, ...legacy]) byId.set(String(a._id), a)
    const items = [...byId.values()].map(view)
    return {
      generatedAt: now,
      graceSeconds: Math.round(this.stuckGraceMs / 1000),
      counts: {
        stuck: stuck.length,
        lateRulesUnremoved: late.length,
        legacySyncPending: legacy.length,
        needsInvestigation: items.filter((i) => i.needsInvestigation).length,
      },
      items,
    }
  }

  /** One periodic pass: TTL reconciliation, recovery of interrupted applications, then late-rule removal. */
  async runOnce() {
    const ttl = await this.reconcileExpiredActions()
    const recovered = await this.recoverAbandonedApplications()
    const lateRules = await this.removeLateRules()
    const legacySync = await this.resyncLegacyState()
    try {
      this.lastCounts = (await this.getRecoveryReport()).counts // read by the Prometheus gauge
    } catch (err) {
      logger.warn(`[ContainmentReconciliation] recovery report failed: ${err.message}`)
    }
    return { ttl, recovered, lateRules, legacySync }
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
