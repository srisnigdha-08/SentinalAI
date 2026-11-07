'use strict'
/**
 * F-08: server startup, database failure and graceful shutdown of the REAL backend process (server.js), which
 * the supertest suites cannot exercise: they import the app without listening, connecting or attaching signal
 * handlers. Disposable mongod (mongodb-memory-server), generated test-only secrets, an empty dotenv file (the
 * developer's backend/.env is never read), the AI engine pointed at a closed port, and the mock containment
 * backend with real firewall enforcement disabled.
 *
 * This runs in a child process, so it is a behavioural test: Jest's coverage numbers do not include it.
 */
const { spawn } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')
const net = require('net')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.setTimeout(120000)

const freePort = () =>
  new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
  })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
async function waitFor(fn, ms, step = 250) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    try {
      if (await fn()) return true
    } catch {}
    await sleep(step)
  }
  return false
}

let mongo
let child
let base
let tmp
let output = ''
let secrets

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  const port = await freePort()
  base = `http://127.0.0.1:${port}`
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-lifecycle-'))
  const emptyEnv = path.join(tmp, 'empty.env')
  fs.writeFileSync(emptyEnv, '')
  const rnd = () => crypto.randomBytes(24).toString('hex')
  secrets = { JWT_SECRET: rnd(), JWT_REFRESH_SECRET: rnd(), HONEYPOT_API_KEY: rnd(), SENTINEL_KEY: rnd() }
  const env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    NODE_ENV: 'development',
    PORT: String(port),
    HOST: '127.0.0.1',
    DOTENV_CONFIG_PATH: emptyEnv,
    MONGO_URI: mongo.getUri('sentinel_lifecycle_test'),
    ...secrets,
    CLIENT_URL: 'http://127.0.0.1:15399',
    AI_ENGINE_URL: 'http://127.0.0.1:9',
    CONTAINMENT_BACKEND: 'mock',
    ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'false',
    LOG_LEVEL: 'info',
  }
  child = spawn(process.execPath, ['server.js'], {
    cwd: path.join(__dirname, '..'),
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  })
  child.stdout.on('data', (d) => (output += d))
  child.stderr.on('data', (d) => (output += d))
})

afterAll(async () => {
  if (child && child.exitCode === null) child.kill()
  await mongo?.stop()
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true })
})

const get = (p) => fetch(base + p).then(async (r) => ({ status: r.status, body: await r.json().catch(() => null) }))

test('starts, listens on loopback, and reports live / ready (degraded: AI engine down) / strict health', async () => {
  const up = await waitFor(async () => (await get('/health/live')).status === 200, 60000)
  expect(up).toBe(true)
  expect((await get('/health/live')).body.status).toBe('alive')
  const ready = await waitFor(async () => (await get('/health/ready')).status === 200, 30000)
  expect(ready).toBe(true)
  const r = await get('/health/ready')
  expect(r.body).toMatchObject({ status: 'degraded', dependencies: { database: 'connected', aiEngine: 'unavailable' } })
  expect((await get('/health')).status).toBe(503) // strict: AI engine required
})

test('MongoDB stops: not ready, still alive, requests fail cleanly; it comes back: ready again', async () => {
  await mongo.stop({ doCleanup: false })
  const notReady = await waitFor(async () => (await get('/health/ready')).status === 503, 40000)
  expect(notReady).toBe(true)
  expect((await get('/health/live')).status).toBe(200)
  expect((await get('/health/ready')).body.dependencies.database).toBe('disconnected')
  const r = await get('/api/threats')
  expect(r.status).toBeGreaterThanOrEqual(400) // 401 without a token, never a hang
  expect(child.exitCode).toBeNull() // the process did not crash

  await mongo.start(true) // same port
  const back = await waitFor(async () => (await get('/health/ready')).status === 200, 60000)
  expect(back).toBe(true)
})

test('graceful shutdown over IPC: exit 0, every step closed, no false close error, no secret in the log', async () => {
  const exited = new Promise((resolve) => child.on('exit', (code) => resolve(code)))
  const t0 = Date.now()
  child.send('shutdown')
  const code = await Promise.race([exited, sleep(30000).then(() => 'TIMEOUT')])
  expect(code).toBe(0)
  expect(Date.now() - t0).toBeLessThan(15000)
  expect(output).toMatch(/Graceful shutdown completed/)
  expect(output).not.toMatch(/HTTP server close error/)
  expect(output).not.toMatch(/Unhandled rejection|uncaughtException/i)
  for (const value of Object.values(secrets)) expect(output.includes(value)).toBe(false)
})
