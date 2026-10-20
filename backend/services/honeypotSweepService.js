'use strict'

const HoneypotSession = require('../models/HoneypotSession')
const logger = require('../utils/logger')

/**
 * HoneypotSweepService
 *
 * Closes honeypot sessions that stayed "active" with no activity for HONEYPOT_STALE_SESSION_HOURS
 * (default 6). This happens when the Cowrie parser restarts (its in-memory session state is lost)
 * or a close event is never delivered. Sessions go through the normal closure analysis, with the
 * duration measured to their last recorded activity, not to the sweep time, so the Q-learner's
 * reward is not inflated by the time the session sat abandoned.
 */
class HoneypotSweepService {
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 15 * 60 * 1000
    this.staleMs = (options.staleHours || parseFloat(process.env.HONEYPOT_STALE_SESSION_HOURS) || 6) * 3600 * 1000
    this.batchSize = options.batchSize || 50
    this.timer = null
    this.isRunning = false
  }

  async sweepStaleSessions(now = new Date()) {
    const honeypotService = require('./honeypotService')
    const cutoff = new Date(now.getTime() - this.staleMs)
    const stale = await HoneypotSession.find({ status: 'active', updatedAt: { $lt: cutoff } })
      .sort({ updatedAt: 1 })
      .limit(this.batchSize)
      .select('_id sessionId startTime updatedAt')
      .lean()

    let closed = 0
    let failed = 0
    for (const s of stale) {
      const lastActivity = s.updatedAt || now
      const durationSeconds = Math.max(0, Math.floor((lastActivity - (s.startTime || lastActivity)) / 1000))
      try {
        await honeypotService.closeSession(s._id, { telemetry: { durationSeconds } })
        closed++
      } catch (err) {
        // 409: already being closed by a late close event, or a failed closure awaiting review.
        if (err.statusCode !== 409) failed++
        logger.warn(`[HoneypotSweep] Could not close stale session ${s.sessionId}: ${err.message}`)
      }
    }
    if (stale.length)
      logger.info(`[HoneypotSweep] Stale sessions: ${stale.length}, closed: ${closed}, failed: ${failed}`)
    return { found: stale.length, closed, failed }
  }

  start() {
    if (this.isRunning) return
    this.isRunning = true
    this.timer = setInterval(async () => {
      try {
        await this.sweepStaleSessions()
      } catch (err) {
        logger.error(`[HoneypotSweep] Unexpected error in interval: ${err.message}`)
      }
    }, this.intervalMs)
    this.timer.unref?.()
    logger.info(
      `[HoneypotSweep] Service started (interval: ${this.intervalMs}ms, stale after ${this.staleMs / 3600000}h)`
    )
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
    this.isRunning = false
  }
}

const defaultHoneypotSweepService = new HoneypotSweepService()

module.exports = { HoneypotSweepService, defaultHoneypotSweepService }
