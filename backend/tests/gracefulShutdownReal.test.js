'use strict'
/**
 * F-04: graceful shutdown against a real http.Server and a real Socket.IO server (the mocks in
 * gracefulShutdown.test.js cannot see the interaction that caused the defect):
 *   - io.close() also closes the attached HTTP server, so the later server.close() failed with
 *     ERR_SERVER_NOT_RUNNING and the report logged a false "HTTP server close error";
 *   - a repeated signal resolved immediately and exited 0 while the first shutdown was still running;
 *   - a shutdown caused by an unhandled rejection exited 0.
 */
jest.mock('../utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn(), debug: jest.fn() }))
const http = require('http')
const { Server } = require('socket.io')
const logger = require('../utils/logger')
const { GracefulShutdownManager } = require('../utils/gracefulShutdown')

const listen = (server) => new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server.address().port)))

async function realStack(handler) {
  const exits = []
  const manager = new GracefulShutdownManager({
    drainTimeoutMs: 2000,
    emergencyTimeoutMs: 8000,
    onExit: (c) => exits.push(c),
  })
  const mw = manager.middleware()
  const server = http.createServer((req, res) => mw(req, res, () => handler(req, res)))
  const io = new Server(server)
  manager.setServer(server)
  manager.setIO(io)
  const port = await listen(server)
  return { manager, server, io, port, exits }
}

afterEach(() => jest.clearAllMocks())

test('real HTTP + Socket.IO: shutdown reports every step closed, with no false HTTP close error', async () => {
  const { manager, server, port } = await realStack((req, res) => res.end('ok'))
  // A raw engine.io WebSocket (Node's built-in client): an upgraded connection held open on the HTTP server.
  const client = new WebSocket(`ws://127.0.0.1:${port}/socket.io/?EIO=4&transport=websocket`)
  await new Promise((resolve, reject) => {
    client.addEventListener('message', resolve, { once: true }) // engine.io "open" packet
    client.addEventListener('error', reject, { once: true })
  })
  const disconnected = new Promise((resolve) => client.addEventListener('close', resolve, { once: true }))

  const report = await manager.shutdown('SIGTERM')
  await disconnected

  expect(report.success).toBe(true)
  expect(report.steps.websocket).toBe('closed')
  expect(report.steps.httpServer).toBe('closed')
  expect(server.listening).toBe(false)
  const warnings = logger.warn.mock.calls.map((c) => String(c[0]))
  expect(warnings.filter((w) => /HTTP server close error/.test(w))).toEqual([])
})

test('an in-flight request completes during shutdown and new connections are refused', async () => {
  let release
  const { manager, port } = await realStack((req, res) => {
    release = () => res.end('finished')
  })
  const inFlight = fetch(`http://127.0.0.1:${port}/slow`).then((r) => r.text())
  await new Promise((r) => setTimeout(r, 100))
  const shutdown = manager.shutdown('SIGTERM')
  await new Promise((r) => setTimeout(r, 100))
  await expect(fetch(`http://127.0.0.1:${port}/new`)).rejects.toThrow()
  release()
  expect(await inFlight).toBe('finished')
  const report = await shutdown
  expect(report.steps.drainRequests).toBe('drained')
  expect(report.steps.httpServer).toBe('closed')
})

test('a server that was never started or already closed is reported as already_closed, not an error', async () => {
  const { manager, server } = await realStack((req, res) => res.end())
  await new Promise((r) => server.close(r))
  const report = await manager.shutdown('SIGTERM')
  expect(report.steps.httpServer).toBe('already_closed')
  expect(report.success).toBe(true)
})

test('finalizers run after requests drained and before MongoDB closes; a failing one does not stop the close', async () => {
  const order = []
  const mongoose = { connection: { readyState: 1, close: jest.fn(async () => order.push('database')) } }
  const manager = new GracefulShutdownManager({ mongoose, emergencyTimeoutMs: 8000, onExit: () => {} })
  expect(typeof manager.registerFinalizer).toBe('function')
  manager.registerFinalizer({ name: 'audit', run: async () => order.push('audit') })
  manager.registerFinalizer({
    name: 'broken',
    run: async () => {
      throw new Error('flush failed')
    },
  })
  const report = await manager.shutdown('SIGTERM')
  expect(order).toEqual(['audit', 'database'])
  expect(report.steps.finalizer_audit).toBe('done')
  expect(report.steps.finalizer_broken).toBe('error: flush failed')
  expect(report.steps.database).toBe('closed')
})

test('server.js registers the containment audit flush as a shutdown finalizer', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'server.js'), 'utf8')
  expect(src).toMatch(/registerFinalizer\(\{\s*name: 'containmentAudit'/)
})

describe('signal handling', () => {
  let before
  const EVENTS = ['SIGTERM', 'SIGINT', 'message', 'unhandledRejection']
  beforeEach(() => {
    before = Object.fromEntries(EVENTS.map((e) => [e, process.listeners(e)]))
  })
  afterEach(() => {
    for (const e of EVENTS)
      for (const l of process.listeners(e)) if (!before[e].includes(l)) process.removeListener(e, l)
  })

  test('repeated signals join one shutdown and exit exactly once, after cleanup', async () => {
    let finishStop
    const service = { name: 'slow', stop: jest.fn(() => new Promise((r) => (finishStop = r))) }
    const exits = []
    const manager = new GracefulShutdownManager({
      services: [service],
      emergencyTimeoutMs: 8000,
      onExit: (c) => exits.push(c),
    })
    manager.attachSignalHandlers()
    manager.attachSignalHandlers() // attaching twice must not register duplicate handlers

    process.emit('SIGTERM', 'SIGTERM')
    process.emit('SIGINT', 'SIGINT')
    process.emit('message', 'shutdown')
    await new Promise((r) => setTimeout(r, 50))
    expect(exits).toEqual([]) // nobody exits while the first shutdown is still stopping services
    expect(service.stop).toHaveBeenCalledTimes(1)

    finishStop()
    await new Promise((r) => setTimeout(r, 50))
    expect(exits).toEqual([0])
  })

  test('a shutdown caused by an unhandled rejection exits with code 1', async () => {
    const exits = []
    const manager = new GracefulShutdownManager({ emergencyTimeoutMs: 8000, onExit: (c) => exits.push(c) })
    manager.attachSignalHandlers()
    process.emit('unhandledRejection', new Error('boom'), Promise.resolve())
    await new Promise((r) => setTimeout(r, 50))
    expect(exits).toEqual([1])
  })

  test('the emergency timer and the normal path never both exit', async () => {
    const exits = []
    const service = { name: 'hung', stop: () => new Promise(() => {}) }
    const manager = new GracefulShutdownManager({
      services: [service],
      emergencyTimeoutMs: 100,
      onExit: (c) => exits.push(c),
    })
    manager.attachSignalHandlers()
    process.emit('SIGTERM', 'SIGTERM')
    await new Promise((r) => setTimeout(r, 300))
    process.emit('SIGTERM', 'SIGTERM')
    await new Promise((r) => setTimeout(r, 50))
    expect(exits).toEqual([1])
  })
})
