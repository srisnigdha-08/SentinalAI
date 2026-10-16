'use strict'

const { GracefulShutdownManager } = require('../utils/gracefulShutdown')

describe('Phase 6C — Graceful Backend Lifecycle & Shutdown Tests', () => {
  let manager
  let mockServer
  let mockIO
  let mockMongoose
  let mockService1
  let mockService2
  let exitCalls

  beforeEach(() => {
    exitCalls = []
    mockServer = {
      close: jest.fn((cb) => cb && cb()),
      closeIdleConnections: jest.fn(),
    }
    mockIO = {
      disconnectSockets: jest.fn(),
      close: jest.fn((cb) => cb && cb()),
    }
    mockMongoose = {
      connection: {
        readyState: 1,
        close: jest.fn().mockResolvedValue(true),
      },
    }
    mockService1 = {
      name: 'service1',
      stop: jest.fn().mockResolvedValue(true),
    }
    mockService2 = {
      name: 'service2',
      stop: jest.fn().mockResolvedValue(true),
    }

    manager = new GracefulShutdownManager({
      server: mockServer,
      io: mockIO,
      mongoose: mockMongoose,
      services: [mockService1, mockService2],
      drainTimeoutMs: 500,
      emergencyTimeoutMs: 1500,
      onExit: (code) => exitCalls.push(code),
    })
  })

  test('executes coordinated shutdown in strict sequence', async () => {
    const report = await manager.shutdown('SIGTERM')

    expect(report.success).toBe(true)
    expect(report.signal).toBe('SIGTERM')
    expect(manager.state).toBe('closed')

    // Step 1: Background services stopped
    expect(mockService1.stop).toHaveBeenCalledTimes(1)
    expect(mockService2.stop).toHaveBeenCalledTimes(1)
    expect(report.steps.service1).toBe('stopped')
    expect(report.steps.service2).toBe('stopped')

    // Step 2: WebSockets disconnected
    expect(mockIO.disconnectSockets).toHaveBeenCalledWith(true)
    expect(mockIO.close).toHaveBeenCalledTimes(1)
    expect(report.steps.websocket).toBe('closed')

    // Step 3: Draining in-flight requests
    expect(report.steps.drainRequests).toBe('drained')

    // Step 4: HTTP server closed
    expect(mockServer.closeIdleConnections).toHaveBeenCalledTimes(1)
    expect(mockServer.close).toHaveBeenCalledTimes(1)
    expect(report.steps.httpServer).toBe('closed')

    // Step 5: Database closed
    expect(mockMongoose.connection.close).toHaveBeenCalledWith(false)
    expect(report.steps.database).toBe('closed')
  })

  test('shutdown is strictly idempotent; duplicate calls ignore duplicate cleanup', async () => {
    const report1 = await manager.shutdown('SIGINT')
    const report2 = await manager.shutdown('SIGTERM')

    expect(report1.success).toBe(true)
    expect(mockServer.close).toHaveBeenCalledTimes(1)
    expect(mockMongoose.connection.close).toHaveBeenCalledTimes(1)
    expect(mockService1.stop).toHaveBeenCalledTimes(1)
    expect(report2).toBe(report1)
  })

  test('middleware passes requests during normal operation and tracks in-flight count', () => {
    const mw = manager.middleware()
    const req = {}
    const resListeners = {}
    const res = {
      on: (event, cb) => {
        resListeners[event] = cb
      },
      removeListener: jest.fn(),
      set: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    }
    const next = jest.fn()

    expect(manager.inFlightRequests).toBe(0)
    mw(req, res, next)
    expect(next).toHaveBeenCalledTimes(1)
    expect(manager.inFlightRequests).toBe(1)

    // When response finishes, count decrements
    resListeners['finish']()
    expect(manager.inFlightRequests).toBe(0)
  })

  test('middleware rejects incoming requests with 503 during shutdown', async () => {
    const mw = manager.middleware()

    // Trigger shutdown
    const shutdownPromise = manager.shutdown('SIGINT')

    // Now test a request arriving during shutdown
    const req = {}
    const res = {
      set: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    }
    const next = jest.fn()

    mw(req, res, next)

    expect(next).not.toHaveBeenCalled()
    expect(res.set).toHaveBeenCalledWith('Connection', 'close')
    expect(res.status).toHaveBeenCalledWith(503)
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({
        success: false,
        error: 'Server is shutting down',
        code: 503,
      })
    )

    await shutdownPromise
  })

  test('in-flight request draining resolves when all in-flight requests complete', async () => {
    const mw = manager.middleware()
    const req = {}
    const resListeners = {}
    const res = {
      on: (event, cb) => {
        resListeners[event] = cb
      },
      removeListener: jest.fn(),
      set: jest.fn(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    }
    const next = jest.fn()

    mw(req, res, next)
    expect(manager.inFlightRequests).toBe(1)

    // Start shutdown while request is active
    let drained = false
    const shutdownPromise = manager.shutdown('SIGINT').then(() => {
      drained = true
    })

    // Brief check: not yet drained
    expect(drained).toBe(false)

    // Complete the in-flight request
    resListeners['finish']()
    await shutdownPromise

    expect(drained).toBe(true)
    expect(manager.state).toBe('closed')
  })

  test('resilient to individual service failures during stop()', async () => {
    mockService1.stop.mockRejectedValue(new Error('Service failure simulation'))

    const report = await manager.shutdown('SIGTERM')

    expect(report.success).toBe(true)
    expect(report.steps.service1).toBe('error: Service failure simulation')
    expect(report.steps.service2).toBe('stopped')
    expect(mockServer.close).toHaveBeenCalledTimes(1)
    expect(mockMongoose.connection.close).toHaveBeenCalledTimes(1)
  })

  test('handles uninitialized components (null server, null io, null mongoose) safely', async () => {
    const bareManager = new GracefulShutdownManager({
      server: null,
      io: null,
      mongoose: null,
      services: [],
      drainTimeoutMs: 100,
    })

    const report = await bareManager.shutdown('SIGINT')
    expect(report.success).toBe(true)
    expect(bareManager.state).toBe('closed')
  })
})
