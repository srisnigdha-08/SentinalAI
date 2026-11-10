'use strict'

const logger = require('./logger')

class GracefulShutdownManager {
  constructor(options = {}) {
    this.server = options.server || null
    this.io = options.io || null
    this.mongoose = options.mongoose || null
    this.services = options.services || []
    this.finalizers = [] // run after requests drained, before MongoDB closes (e.g. flush durable audit writes)
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

  registerFinalizer(finalizer) {
    if (finalizer && typeof finalizer.run === 'function') this.finalizers.push(finalizer)
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

  // Resolves once the HTTP server has stopped accepting and every connection has ended. A server that is not
  // listening (already closed, or never started) is reported as such instead of as an error (F-04).
  _closeHttpServer() {
    const server = this.server
    if (server.listening === false) return Promise.resolve('not_listening')
    return new Promise((resolve, reject) => {
      server.close((err) => {
        if (!err) return resolve('closed')
        if (err.code === 'ERR_SERVER_NOT_RUNNING') return resolve('not_listening')
        reject(err)
      })
    })
  }

  _exit(code) {
    if (this._exitCode !== undefined) return
    this._exitCode = code
    this.onExit(code)
  }

  shutdown(signal = 'SIGINT') {
    // Idempotent: a repeated signal (Ctrl-C twice, SIGTERM after IPC) joins the shutdown already running instead of
    // starting a second one or exiting before cleanup has finished.
    if (this._shutdownPromise) {
      logger.warn(`[Shutdown] Duplicate shutdown signal (${signal}) ignored; currently in state: ${this.state}`)
      return this._shutdownPromise
    }
    this._shutdownPromise = this._runShutdown(signal)
    return this._shutdownPromise
  }

  async _runShutdown(signal) {
    this.state = 'shutting_down'
    this.shutdownStartTime = Date.now()
    logger.info(`[Shutdown] Initiating graceful shutdown (Signal: ${signal})`)

    // Emergency failsafe timeout in case cleanup hangs
    const emergencyTimer = setTimeout(() => {
      logger.error(`[Shutdown] Emergency timeout (${this.emergencyTimeoutMs}ms) exceeded; forcing exit`)
      this._exit(1)
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

      // Step 2: Stop accepting new HTTP connections. This comes before the Socket.IO close because io.close() also
      // closes the attached HTTP server: closing Socket.IO first made the later server.close() fail with
      // "Server is not running" and logged a false shutdown error (F-04).
      let httpClosed = null
      if (this.server) {
        logger.info('[Shutdown] Step 2: Stopping new HTTP connections')
        httpClosed = this._closeHttpServer().then(
          (state) => ({ state }),
          (err) => ({ err })
        )
      }

      // Step 3: Gracefully close WebSockets (upgraded connections keep the HTTP server open until they end)
      if (this.io) {
        logger.info('[Shutdown] Step 3: Disconnecting WebSockets')
        try {
          if (typeof this.io.disconnectSockets === 'function') {
            this.io.disconnectSockets(true)
          }
          if (typeof this.io.close === 'function') {
            // Its callback receives ERR_SERVER_NOT_RUNNING here, because step 2 already closed the HTTP server.
            await new Promise((resolve) => this.io.close(() => resolve()))
          }
          report.steps.websocket = 'closed'
        } catch (err) {
          logger.warn(`[Shutdown] WebSocket close error: ${err.message}`)
          report.steps.websocket = `error: ${err.message}`
        }
      }

      // Step 4: Drain in-flight HTTP requests
      logger.info(`[Shutdown] Step 4: Draining in-flight requests (current: ${this.inFlightRequests})`)
      const drained = await this.drainRequests()
      report.steps.drainRequests = drained ? 'drained' : 'timeout'

      // Step 5: Wait for the HTTP server to finish closing
      if (httpClosed) {
        logger.info('[Shutdown] Step 5: Closing HTTP server')
        if (typeof this.server.closeIdleConnections === 'function') {
          this.server.closeIdleConnections() // keep-alive sockets that went idle while draining
        }
        if (!drained && typeof this.server.closeAllConnections === 'function') {
          this.server.closeAllConnections()
        }
        const result = await httpClosed
        if (result.err) {
          logger.warn(`[Shutdown] HTTP server close error: ${result.err.message}`)
          report.steps.httpServer = `error: ${result.err.message}`
        } else {
          report.steps.httpServer = result.state === 'closed' ? 'closed' : 'already_closed'
        }
      }

      // Step 6: Finalizers that still need MongoDB (in-flight audit writes). Errors are reported, never fatal.
      for (const fin of this.finalizers) {
        const key = 'finalizer_' + (fin.name || 'unnamed')
        try {
          await fin.run()
          report.steps[key] = 'done'
        } catch (err) {
          logger.warn(`[Shutdown] Finalizer ${fin.name || 'unnamed'} failed: ${err.message}`)
          report.steps[key] = `error: ${err.message}`
        }
      }

      // Step 7: Close MongoDB connection
      if (this.mongoose && this.mongoose.connection) {
        logger.info('[Shutdown] Step 7: Closing MongoDB connection')
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
    if (this._signalHandlersAttached) return
    this._signalHandlersAttached = true
    // Every trigger joins the same shutdown and the process exits exactly once. A shutdown caused by an unhandled
    // rejection exits non-zero even when cleanup succeeds, so a supervisor sees the failure.
    const handler = (sig, exitCode = 0) => {
      this.shutdown(sig)
        .then(() => this._exit(exitCode))
        .catch(() => this._exit(1))
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
      handler('UNHANDLED', 1)
    })
  }
}

const defaultShutdownManager = new GracefulShutdownManager()

module.exports = {
  GracefulShutdownManager,
  defaultShutdownManager,
}
