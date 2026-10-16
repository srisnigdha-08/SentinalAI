'use strict'

const logger = require('./logger')

class GracefulShutdownManager {
  constructor(options = {}) {
    this.server = options.server || null
    this.io = options.io || null
    this.mongoose = options.mongoose || null
    this.services = options.services || []
    this.drainTimeoutMs = options.drainTimeoutMs || 5000
    this.emergencyTimeoutMs = options.emergencyTimeoutMs || 10000
    this.onExit = options.onExit || ((code) => process.exit(code))

    this.state = 'idle' // 'idle' | 'shutting_down' | 'closed'
    this.inFlightRequests = 0
    this._drainResolvers = []
    this.shutdownStartTime = null
    this.shutdownReport = null
  }

  setServer(server) {
    this.server = server
  }

  setIO(io) {
    this.io = io
  }

  setMongoose(mongoose) {
    this.mongoose = mongoose
  }

  registerService(service) {
    if (service && typeof service.stop === 'function') {
      this.services.push(service)
    }
  }

  // Express middleware to track in-flight requests and reject new work during shutdown
  middleware() {
    return (req, res, next) => {
      if (this.state === 'shutting_down' || this.state === 'closed') {
        res.set('Connection', 'close')
        return res.status(503).json({
          success: false,
          error: 'Server is shutting down',
          code: 503,
          timestamp: new Date().toISOString(),
        })
      }

      this.inFlightRequests++
      const decrement = () => {
        res.removeListener('finish', decrement)
        res.removeListener('close', decrement)
        this.inFlightRequests = Math.max(0, this.inFlightRequests - 1)
        if (this.inFlightRequests === 0 && this._drainResolvers.length > 0) {
          const resolvers = this._drainResolvers
          this._drainResolvers = []
          resolvers.forEach((r) => r())
        }
      }

      res.on('finish', decrement)
      res.on('close', decrement)
      next()
    }
  }

  async drainRequests() {
    if (this.inFlightRequests === 0) return true
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        logger.warn(`[Shutdown] In-flight request drain timeout (${this.inFlightRequests} remaining)`)
        resolve(false)
      }, this.drainTimeoutMs)
      timer.unref?.()

      this._drainResolvers.push(() => {
        clearTimeout(timer)
        resolve(true)
      })
    })
  }

  async shutdown(signal = 'SIGINT') {
    // Idempotency: Ignore duplicate shutdown triggers
    if (this.state !== 'idle') {
      logger.warn(`[Shutdown] Duplicate shutdown signal (${signal}) ignored; currently in state: ${this.state}`)
      return this.shutdownReport
    }

    this.state = 'shutting_down'
    this.shutdownStartTime = Date.now()
    logger.info(`[Shutdown] Initiating graceful shutdown (Signal: ${signal})`)

    // Emergency failsafe timeout in case cleanup hangs
    const emergencyTimer = setTimeout(() => {
      logger.error(`[Shutdown] Emergency timeout (${this.emergencyTimeoutMs}ms) exceeded; forcing exit`)
      this.onExit(1)
    }, this.emergencyTimeoutMs)
    emergencyTimer.unref?.()

    const report = {
      signal,
      startTime: new Date(this.shutdownStartTime).toISOString(),
      steps: {},
      success: false,
    }

    try {
      // Step 1: Stop registered background services/timers (reconciliation, health broadcast, revocation)
      logger.info('[Shutdown] Step 1: Stopping background services and timers')
      for (const svc of this.services) {
        try {
          await svc.stop()
          report.steps[svc.name || 'unnamed_service'] = 'stopped'
        } catch (err) {
          logger.warn(`[Shutdown] Error stopping service: ${err.message}`)
          report.steps[svc.name || 'unnamed_service'] = `error: ${err.message}`
        }
      }

      // Step 2: Gracefully close WebSockets
      if (this.io) {
        logger.info('[Shutdown] Step 2: Disconnecting WebSockets')
        try {
          if (typeof this.io.disconnectSockets === 'function') {
            this.io.disconnectSockets(true)
          }
          if (typeof this.io.close === 'function') {
            await new Promise((resolve) => this.io.close(resolve))
          }
          report.steps.websocket = 'closed'
        } catch (err) {
          logger.warn(`[Shutdown] WebSocket close error: ${err.message}`)
          report.steps.websocket = `error: ${err.message}`
        }
      }

      // Step 3: Drain in-flight HTTP requests
      logger.info(`[Shutdown] Step 3: Draining in-flight requests (current: ${this.inFlightRequests})`)
      const drained = await this.drainRequests()
      report.steps.drainRequests = drained ? 'drained' : 'timeout'

      // Step 4: Close HTTP Server
      if (this.server) {
        logger.info('[Shutdown] Step 4: Closing HTTP server')
        try {
          if (typeof this.server.closeIdleConnections === 'function') {
            this.server.closeIdleConnections()
          }
          await new Promise((resolve, reject) => {
            this.server.close((err) => (err ? reject(err) : resolve()))
          })
          report.steps.httpServer = 'closed'
        } catch (err) {
          logger.warn(`[Shutdown] HTTP server close error: ${err.message}`)
          report.steps.httpServer = `error: ${err.message}`
        }
      }

      // Step 5: Close MongoDB connection
      if (this.mongoose && this.mongoose.connection) {
        logger.info('[Shutdown] Step 5: Closing MongoDB connection')
        try {
          if (this.mongoose.connection.readyState !== 0) {
            await this.mongoose.connection.close(false)
          }
          report.steps.database = 'closed'
        } catch (err) {
          logger.warn(`[Shutdown] MongoDB close error: ${err.message}`)
          report.steps.database = `error: ${err.message}`
        }
      }

      clearTimeout(emergencyTimer)
      this.state = 'closed'
      report.success = true
      report.durationMs = Date.now() - this.shutdownStartTime
      logger.info(`[Shutdown] Graceful shutdown completed in ${report.durationMs}ms`)
      this.shutdownReport = report
      return report
    } catch (fatalErr) {
      clearTimeout(emergencyTimer)
      logger.error(`[Shutdown] Fatal error during shutdown: ${fatalErr.message}`)
      report.error = fatalErr.message
      this.shutdownReport = report
      throw fatalErr
    }
  }

  attachSignalHandlers() {
    const handler = (sig) => {
      this.shutdown(sig)
        .then(() => this.onExit(0))
        .catch(() => this.onExit(1))
    }

    process.on('SIGTERM', () => handler('SIGTERM'))
    process.on('SIGINT', () => handler('SIGINT'))
    process.on('message', (msg) => {
      if (msg === 'shutdown' || (typeof msg === 'object' && msg && msg.action === 'shutdown')) {
        handler('IPC_SHUTDOWN')
      }
    })
    process.on('unhandledRejection', (err) => {
      logger.error('[Shutdown] Unhandled rejection: ' + (err?.message || err))
      handler('UNHANDLED')
    })
  }
}

const defaultShutdownManager = new GracefulShutdownManager()

module.exports = {
  GracefulShutdownManager,
  defaultShutdownManager,
}
