'use strict'

const logger = require('../utils/logger')

/**
 * Opt-in periodic retention (M5). Runs retentionService.applyRetention (archive first, then delete) every
 * RETENTION_INTERVAL_HOURS, but only when RETENTION_ENABLED=true as well, so enabling the policy and
 * scheduling it are two deliberate decisions. The first run is one interval after start, never at startup
 * (retentionService constraint 7). demo-* sessions and audit logs stay excluded by the service itself.
 */
class RetentionScheduler {
  constructor(options = {}) {
    this.intervalHours = options.intervalHours ?? parseFloat(process.env.RETENTION_INTERVAL_HOURS)
    this.enabled = options.enabled ?? process.env.RETENTION_ENABLED === 'true'
    this.run = options.run || ((opts) => require('./retentionService').applyRetention(opts))
    this.timer = null
    this.running = false
  }

  configured() {
    return this.enabled && Number.isFinite(this.intervalHours) && this.intervalHours > 0
  }

  async runOnce() {
    if (this.running) return null
    this.running = true
    try {
      const result = await this.run({ dryRun: false, actor: { id: 'retention-scheduler', role: 'service' } })
      logger.info(`[RetentionScheduler] Run complete: ${JSON.stringify(result?.deleted || result?.reason || {})}`)
      return result
    } catch (err) {
      logger.error(`[RetentionScheduler] Run failed: ${err.message}`)
      return null
    } finally {
      this.running = false
    }
  }

  start() {
    if (this.timer || !this.configured()) {
      if (!this.configured())
        logger.info('[RetentionScheduler] Not scheduled (needs RETENTION_ENABLED=true and RETENTION_INTERVAL_HOURS)')
      return false
    }
    this.timer = setInterval(() => this.runOnce(), this.intervalHours * 3600 * 1000)
    this.timer.unref?.()
    logger.info(`[RetentionScheduler] Retention scheduled every ${this.intervalHours} h (first run after one interval)`)
    return true
  }

  stop() {
    if (this.timer) clearInterval(this.timer)
    this.timer = null
  }
}

const defaultRetentionScheduler = new RetentionScheduler()

module.exports = { RetentionScheduler, defaultRetentionScheduler }
