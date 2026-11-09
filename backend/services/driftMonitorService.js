'use strict'

const logger = require('../utils/logger')

/**
 * DriftMonitorService
 *
 * Polls the AI engine's /model/drift report (recent traffic vs. the model's training statistics) and
 * raises one SYSTEM_HEALTH alert per DRIFT_ALERT_COOLDOWN_HOURS (default 24) while the engine reports
 * "drift". Drift is the signal to re-evaluate and retrain (ai-engine/training/retrain_from_samples.py);
 * nothing is changed automatically.
 *
 * Sustained drift (U2): after DRIFT_RETRAIN_AFTER_CHECKS consecutive drift reports (default 3, i.e. 90 minutes
 * at the 30-minute interval) an admin-only "Retraining recommended" alert is raised once per cooldown with the
 * exact commands. A human still runs them: promotion is gated and never automatic.
 */
class DriftMonitorService {
  constructor(options = {}) {
    this.intervalMs = options.intervalMs || 30 * 60 * 1000
    this.cooldownMs = (options.cooldownHours || parseFloat(process.env.DRIFT_ALERT_COOLDOWN_HOURS) || 24) * 3600 * 1000
    this.lastAlertAt = null // never alerted
    this.retrainAfter = options.retrainAfter || parseInt(process.env.DRIFT_RETRAIN_AFTER_CHECKS, 10) || 3
    this.consecutiveDrift = 0
    this.lastRetrainAlertAt = null
    this.lastReport = null
    this.timer = null
    this.isRunning = false
  }

  async check(now = Date.now()) {
    const aiSvc = require('./aiEngineService')
    const report = await aiSvc.getDrift()
    this.lastReport = report
    if (!report || report.status !== 'drift') {
      // Only a clean report resets the streak; an unreachable engine or too few samples says nothing either way
      if (report?.status === 'ok') this.consecutiveDrift = 0
      return { alerted: false, status: report?.status || 'unreachable' }
    }
    this.consecutiveDrift += 1
    const retrainRecommended = await this.recommendRetraining(report, now)
    if (this.lastAlertAt !== null && now - this.lastAlertAt < this.cooldownMs)
      return { alerted: false, status: 'drift', cooldown: true, retrainRecommended }

    this.lastAlertAt = now
    const alertService = require('./alertService')
    const socketManager = require('../websocket/socketManager')
    const top = (report.top_shifts || [])
      .slice(0, 3)
      .map((f) => `${f.feature} (${f.psi !== undefined ? `PSI ${f.psi}` : `${f.mean_shift_sd} sd`})`)
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
    return { alerted: true, status: 'drift', retrainRecommended }
  }

  /** Raise the admin-only retraining recommendation once the drift streak is long enough (U2). */
  async recommendRetraining(report, now) {
    if (this.consecutiveDrift < this.retrainAfter) return false
    if (this.lastRetrainAlertAt !== null && now - this.lastRetrainAlertAt < this.cooldownMs) return false
    this.lastRetrainAlertAt = now
    const alertService = require('./alertService')
    const socketManager = require('../websocket/socketManager')
    const alert = await alertService.createAlert({
      title: 'Retraining recommended: sustained model input drift',
      message:
        `Drift reported on ${this.consecutiveDrift} consecutive checks (${report.method || 'drift report'}, ` +
        `${report.drifted_features?.length || 0} features). Export verified samples ` +
        '(node backend/utils/exportTrainingSamples.js --out samples.jsonl), then run ' +
        'python ai-engine/training/retrain_from_samples.py --samples samples.jsonl and review its gate report ' +
        'before any --promote.',
      severity: 'MEDIUM',
      type: 'SYSTEM_HEALTH',
      targetRoles: ['admin'],
    })
    socketManager.emitNewAlert(alert)
    logger.warn(`[Drift] Retraining recommended after ${this.consecutiveDrift} consecutive drift checks`)
    return true
  }

  /** Last check as a gauge value: 1 drift, 0 ok, -1 not assessed (no check yet, too few samples, engine down). */
  statusValue() {
    const status = this.lastReport?.status
    if (status === 'drift') return 1
    if (status === 'ok') return 0
    return -1
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
