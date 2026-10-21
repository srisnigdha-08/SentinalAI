'use strict'

const logger = require('../utils/logger')

/**
 * DriftMonitorService
 *
 * Polls the AI engine's /model/drift report (recent traffic vs. the model's training statistics) and
 * raises one SYSTEM_HEALTH alert per DRIFT_ALERT_COOLDOWN_HOURS (default 24) while the engine reports
 * "drift". Drift is the signal to re-evaluate and retrain (ai-engine/training/retrain_from_samples.py);
 * nothing is changed automatically.
 */
class DriftMonitorService {
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 30 * 60 * 1000
    this.cooldownMs = (options.cooldownHours || parseFloat(process.env.DRIFT_ALERT_COOLDOWN_HOURS) || 24) * 3600 * 1000
    this.lastAlertAt = null // never alerted
    this.lastReport = null
    this.timer = null
    this.isRunning = false
  }

  async check(now = Date.now()) {
    const aiSvc = require('./aiEngineService')
    const report = await aiSvc.getDrift()
    this.lastReport = report
    if (!report || report.status !== 'drift') return { alerted: false, status: report?.status || 'unreachable' }
    if (this.lastAlertAt !== null && now - this.lastAlertAt < this.cooldownMs)
      return { alerted: false, status: 'drift', cooldown: true }

    this.lastAlertAt = now
    const alertService = require('./alertService')
    const socketManager = require('../websocket/socketManager')
    const top = (report.top_shifts || [])
      .slice(0, 3)
      .map((f) => `${f.feature} (${f.mean_shift_sd} sd)`)
      .join(', ')
    const alert = await alertService.createAlert({
      title: 'Model input drift detected',
      message:
        `${Math.round((report.drifted_fraction || 0) * 100)}% of features drifted over the last ${report.samples} flows ` +
        `(top: ${top || 'n/a'}). Re-evaluate the model and consider retraining.`,
      severity: 'MEDIUM',
      type: 'SYSTEM_HEALTH',
      targetRoles: ['admin', 'analyst'],
    })
    socketManager.emitNewAlert(alert)
    logger.warn(`[Drift] Drift alert raised: ${report.drifted_features?.length || 0} drifted features`)
    return { alerted: true, status: 'drift' }
  }

  start() {
    if (this.isRunning) return
    this.isRunning = true
    this.timer = setInterval(async () => {
      try {
        await this.check()
      } catch (err) {
        logger.error(`[Drift] Unexpected error in interval: ${err.message}`)
      }
    }, this.intervalMs)
    this.timer.unref?.()
    logger.info(`[Drift] Monitor started (interval: ${this.intervalMs}ms)`)
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer)
      this.timer = null
    }
    this.isRunning = false
  }
}

const defaultDriftMonitorService = new DriftMonitorService()

module.exports = { DriftMonitorService, defaultDriftMonitorService }
