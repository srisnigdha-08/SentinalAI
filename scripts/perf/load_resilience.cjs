/**
 * Load and failure-recovery harness (batch 13). Real AI engine + backend + a throwaway mongod, isolated from every
 * existing database and service:
 *
 *   mongod (own binary, 127.0.0.1:27419, temp dbpath)  <-  backend :15200  ->  fault proxy :18201  ->  engine :18200
 *
 * Load:      POST /api/ai/analyze with real CICIDS2017 flows (replay_cicids.load_curated_sample) at 1/5/10/20 clients;
 *            every response, AIPrediction, ThreatLog and Socket.IO event is reconciled (no loss, no duplicates,
 *            per-role redaction).
 * Failures:  slow engine (delay below and above the backend's 10 s timeout), engine unreachable (circuit breaker,
 *            degraded threats, /health), recovery; explanation with the engine down; MongoDB killed and restarted
 *            (backend error handling and reconnection). Containment uses the mock adapter only.
 *
 * Safety: generated secrets/passwords (never printed); DOTENV_CONFIG_PATH -> empty file; database name must contain
 * "loadtest"; the throwaway mongod's data directory is deleted at the end. RATE_LIMIT_MAX is raised for this
 * throwaway backend only, because the harness simulates many users from one IP (the per-IP limit is deliberate).
 *
 *   node scripts/perf/load_resilience.cjs [--per-client 10] [--levels 1,5,10,20] [--quick]
 */
const { spawn, spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const http = require('http')
const os = require('os')
const path = require('path')
const { pathToFileURL } = require('url')

const root = path.resolve(__dirname, '../..')
const req = (mod) => require(path.join(root, 'backend/node_modules', mod))
const mongoose = req('mongoose')
const { io: socketClient } = require(path.join(root, 'frontend/node_modules/socket.io-client'))

const arg = (n, d) => (process.argv.indexOf('--' + n) > 0 ? process.argv[process.argv.indexOf('--' + n) + 1] : d)
const PER_CLIENT = parseInt(arg('per-client', '10'), 10)
const LEVELS = arg('levels', '1,5,10,20').split(',').map(Number)
const QUICK = process.argv.includes('--quick')
const ENGINE_PORT = 18200
const PROXY_PORT = 18201
const BACKEND_PORT = 15200
const MONGO_PORT = 27419
const ORIGIN = 'http://localhost:3998'
const BASE = `http://127.0.0.1:${BACKEND_PORT}`
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '_')
const DB = 'sentinelai_loadtest_' + stamp
const runDir = path.join(__dirname, 'runs', stamp)
fs.mkdirSync(runDir, { recursive: true })

const secret = () => crypto.randomBytes(32).toString('hex')
const S = { SENTINEL_KEY: secret(), HONEYPOT_API_KEY: secret(), JWT_SECRET: secret(), JWT_REFRESH_SECRET: secret() }
const users = {
  admin: { name: 'Load Admin', email: 'admin@loadtest.test', role: 'admin', password: 'La1!' + secret() },
  analyst: { name: 'Load Analyst', email: 'analyst@loadtest.test', role: 'analyst', password: 'La1!' + secret() },
  viewer: { name: 'Load Viewer', email: 'viewer@loadtest.test', role: 'viewer', password: 'La1!' + secret() },
}
const redact = (text) => {
  let t = String(text)
  for (const v of [...Object.values(S), ...Object.values(users).map((u) => u.password)]) t = t.split(v).join('<redacted>')
  return t.replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, '<jwt>')
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const pct = (xs, p) => {
  if (!xs.length) return null
  const s = [...xs].sort((a, b) => a - b)
  return Math.round(s[Math.min(s.length - 1, Math.round((p / 100) * (s.length - 1)))] * 10) / 10
}
const results = []
const check = async (area, name, fn) => {
  const t0 = Date.now()
  try {
    const detail = await fn()
    results.push({ area, name, status: 'PASS', ms: Date.now() - t0, detail: detail ?? null })
    console.log(`PASS  ${area}  ${name}${detail ? '  ' + JSON.stringify(detail).slice(0, 300) : ''}`)
  } catch (e) {
    results.push({ area, name, status: 'FAIL', ms: Date.now() - t0, detail: redact(e.message) })
    console.log(`FAIL  ${area}  ${name}: ${redact(e.message)}`)
  }
}
const assert = (c, m) => {
  if (!c) throw new Error(m)
}
const waitFor = async (fn, ms, label) => {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => null)
    if (v) return v
    if (Date.now() > end) throw new Error('timed out waiting for ' + label)
    await sleep(250)
  }
}

const procs = new Map()
const tmpDirs = []
const service = (name, cmd, args, cwd, env) => {
  const log = fs.createWriteStream(path.join(runDir, name + '.log'), { flags: 'a' })
  const p = spawn(cmd, args, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
  p.stdout.on('data', (d) => log.write(redact(d)))
  p.stderr.on('data', (d) => log.write(redact(d)))
  procs.set(name, p)
  return p
}
const stop = async (name) => {
  const p = procs.get(name)
  if (!p || p.exitCode !== null) return
  if (process.platform === 'win32') spawnSync('taskkill', ['/PID', String(p.pid), '/T', '/F'])
  else p.kill('SIGKILL')
  await new Promise((r) => (p.exitCode !== null ? r() : p.once('exit', r)))
  procs.delete(name)
}
const baseEnv = () => {
  const keep = ['PATH', 'Path', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'HOME', 'COMSPEC', 'PATHEXT', 'WINDIR']
  const env = {}
  for (const k of keep) if (process.env[k]) env[k] = process.env[k]
  return { ...env, NO_PROXY: '127.0.0.1,localhost', HTTP_PROXY: '', HTTPS_PROXY: '' }
}

class Client {
  constructor() {
    this.cookies = {}
    this.token = null
  }
  async call(method, route, body, extra = {}, timeoutMs = 60000) {
    const headers = { Origin: ORIGIN, ...extra }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (this.token) headers.Authorization = 'Bearer ' + this.token
    const cookie = Object.entries(this.cookies).map(([k, v]) => k + '=' + v).join('; ')
    if (cookie) headers.Cookie = cookie
    const t0 = performance.now()
    const res = await fetch(BASE + route, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs) })
    for (const c of res.headers.getSetCookie?.() || []) {
      const [kv] = c.split(';')
      const i = kv.indexOf('=')
      this.cookies[kv.slice(0, i)] = kv.slice(i + 1)
    }
    let json = null
    try {
      json = await res.json()
    } catch {}
    return { status: res.status, body: json, ms: performance.now() - t0 }
  }
  async mutate(method, route, body) {
    const csrf = (await this.call('GET', '/api/auth/csrf')).body.data.csrfToken
    return this.call(method, route, body, { 'X-CSRF-Token': csrf })
  }
  async login(u) {
    const r = await this.mutate('POST', '/api/auth/login', { email: u.email, password: u.password })
    assert(r.status === 200, 'login ' + u.role + ' -> ' + r.status)
    this.token = r.body.data.token
  }
}

// ── fault-injection proxy between backend and engine ───────────────────────────────────────────────────────────
const fault = { mode: 'pass', delayMs: 0, seen: 0 }
const proxy = http.createServer((inReq, inRes) => {
  fault.seen++
  const forward = () => {
    if (fault.mode === 'error500') {
      inRes.writeHead(500, { 'Content-Type': 'application/json' })
      return inRes.end('{"detail":"injected"}')
    }
    const out = http.request({ host: '127.0.0.1', port: ENGINE_PORT, path: inReq.url, method: inReq.method, headers: inReq.headers }, (r) => {
      inRes.writeHead(r.statusCode, r.headers)
      r.pipe(inRes)
    })
    out.on('error', () => {
      inRes.writeHead(502)
      inRes.end()
    })
    inReq.pipe(out)
  }
  if (fault.mode === 'delay') setTimeout(forward, fault.delayMs)
  else forward()
})
let proxyOpen = false
const proxyUp = () => new Promise((r) => (proxyOpen ? r() : proxy.listen(PROXY_PORT, '127.0.0.1', () => ((proxyOpen = true), r()))))
const proxyDown = () => new Promise((r) => {
  if (!proxyOpen) return r()
  proxy.close(() => ((proxyOpen = false), r()))
  proxy.closeAllConnections?.()
})

// ── main ───────────────────────────────────────────────────────────────────────────────────────────────────────
async function main() {
  assert(DB.includes('loadtest'), 'database guard')
  const pyExe = path.join(root, 'ai-engine/.venv/Scripts/python.exe')
  const python = fs.existsSync(pyExe) ? pyExe : path.join(root, 'ai-engine/.venv/bin/python')
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-load-'))
  tmpDirs.push(tmp)
  const emptyEnv = path.join(tmp, 'empty.env')
  fs.writeFileSync(emptyEnv, '')
  const mongodBin = [path.join(root, 'backend/node_modules/.cache/mongodb-memory-server/mongod-x64-win32-8.2.6.exe'),
    path.join(os.homedir(), '.cache/mongodb-binaries/mongod-x64-win32-8.2.6.exe')].find((p) => fs.existsSync(p))
  assert(mongodBin, 'no throwaway mongod binary found (run the backend test suite once to download it)')
  const dbPath = path.join(tmp, 'db')
  fs.mkdirSync(dbPath)
  const startMongo = () => service('mongod', mongodBin, ['--port', String(MONGO_PORT), '--bind_ip', '127.0.0.1', '--dbpath', dbPath], tmp, baseEnv())
  const MONGO_URI = `mongodb://127.0.0.1:${MONGO_PORT}/${DB}`

  // Real CICIDS2017 flows (labels kept apart; payloads carry raw features only)
  const flowsFile = path.join(tmp, 'flows.json')
  const exp = spawnSync(python, ['-I', '-c', `
import json, sys
sys.path.insert(0, '.')
from pathlib import Path
from demo.replay_cicids import load_curated_sample
rows = load_curated_sample(Path('datasets/cicids2017'), 200)
json.dump([{"label": r["ground_truth_label"], "features": r["raw_features"]} for r in rows], open(sys.argv[1], "w"))
print(len(rows))`, flowsFile], { cwd: path.join(root, 'ai-engine'), encoding: 'utf8', env: { ...baseEnv(), PYTHONIOENCODING: 'utf-8' } })
  assert(exp.status === 0, 'flow export failed: ' + (exp.stderr || '').slice(-400))
  const flows = JSON.parse(fs.readFileSync(flowsFile, 'utf8'))

  startMongo()
  await waitFor(async () => {
    await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 1000 })
    return true
  }, 30000, 'throwaway mongod')
  const User = require(path.join(root, 'backend/models/User'))
  for (const u of Object.values(users)) await User.create({ ...u, mustChangePassword: false })
  const ThreatLog = require(path.join(root, 'backend/models/ThreatLog'))
  const AIPrediction = require(path.join(root, 'backend/models/AIPrediction'))

  const engineEnv = { ...baseEnv(), SENTINEL_KEY: S.SENTINEL_KEY, SENTINEL_ADMIN_KEY: secret(), SENTINEL_API: BASE + '/api',
    MODEL_DIR: path.join(root, 'ai-engine/models'), Q_TABLE_PATH: path.join(tmp, 'q_table.json'), CORS_ORIGINS: ORIGIN, PYTHONDONTWRITEBYTECODE: '1' }
  const t0 = Date.now()
  service('engine', python, ['-m', 'uvicorn', 'inference.main:app', '--host', '127.0.0.1', '--port', String(ENGINE_PORT)], path.join(root, 'ai-engine'), engineEnv)
  await proxyUp()
  const backendEnv = { ...baseEnv(), DOTENV_CONFIG_PATH: emptyEnv, NODE_ENV: 'development', HOST: '127.0.0.1', PORT: String(BACKEND_PORT),
    MONGO_URI, CLIENT_URL: ORIGIN, AI_ENGINE_URL: `http://127.0.0.1:${PROXY_PORT}`, AI_ENGINE_ADMIN_KEY: engineEnv.SENTINEL_ADMIN_KEY,
    CONTAINMENT_BACKEND: 'mock', ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'false', LOG_LEVEL: 'info',
    RATE_LIMIT_MAX: '1000000', AI_CIRCUIT_RESET_MS: '5000', ...S }
  const startBackend = () => service('backend', process.execPath, ['server.js'], path.join(root, 'backend'), backendEnv)
  startBackend()
  await check('start', 'engine ready and backend healthy', async () => {
    await waitFor(async () => (await fetch(`http://127.0.0.1:${ENGINE_PORT}/ready`)).status === 200, 120000, 'engine')
    const engineMs = Date.now() - t0
    await waitFor(async () => (await fetch(BASE + '/health')).status === 200, 60000, 'backend')
    return { engineReadyMs: engineMs, bothReadyMs: Date.now() - t0, flows: flows.length, labels: [...new Set(flows.map((f) => f.label))] }
  })

  const admin = new Client()
  const analyst = new Client()
  const viewer = new Client()
  await admin.login(users.admin)
  await analyst.login(users.analyst)
  await viewer.login(users.viewer)

  // Sockets per role; count new_threat by threat id
  const sockets = {}
  const socketLog = []
  const seen = { admin: new Map(), analyst: new Map(), viewer: new Map() }
  // The dashboard's own retry policy, not a copy of it
  const { serverDisconnectRetryDelay } = await import(pathToFileURL(path.join(root, 'frontend/src/utils/socketReconnect.js')).href)
  const openSocket = (role, token, log = socketLog) => {
    const s = socketClient(BASE, { auth: { token }, transports: ['websocket'], reconnection: true, reconnectionDelay: 500, extraHeaders: { Origin: ORIGIN } })
    // Same lifecycle as the dashboard's SocketContext: join the role rooms on every connect, and retry the handshake
    // after the server-side refusals Socket.IO does not retry by itself (WS-001)
    let retries = 0
    let retryTimer = null
    const retry = (reason) => {
      const delay = serverDisconnectRetryDelay(reason, retries++)
      if (delay !== null) { clearTimeout(retryTimer); retryTimer = setTimeout(() => s.connect(), delay) }
    }
    s.on('connect', () => {
      retries = 0
      s.emit('join_room', { role })
      s.emit('subscribe_threats')
    })
    s.on('disconnect', (reason) => {
      log.push({ role, at: Date.now(), event: 'disconnect', reason })
      retry(reason)
    })
    s.on('connect_error', (e) => {
      log.push({ role, at: Date.now(), event: 'connect_error', reason: e.message })
      retry(e.message)
    })
    s.io.on('reconnect', () => log.push({ role, at: Date.now(), event: 'reconnect' }))
    s.stopRetrying = () => clearTimeout(retryTimer)
    return s
  }
  for (const [role, c] of [['admin', admin], ['analyst', analyst], ['viewer', viewer]]) {
    const s = openSocket(role, c.token)
    s.on('new_threat', (p) => seen[role].set(p._id, [...(seen[role].get(p._id) || []), p]))
    sockets[role] = s
    await waitFor(async () => s.connected, 10000, role + ' socket')
  }

  // ── load ──
  let ipSeq = 0
  const nextIp = () => `198.51.100.${4 + (ipSeq++ % 250)}` // TEST-NET-2, never a real host
  const levelStats = []
  for (const clients of LEVELS) {
    await check('load', `analyze at ${clients} concurrent client(s) x ${PER_CLIENT}`, async () => {
      const lat = []
      const codes = {}
      const before = await AIPrediction.countDocuments({})
      const t1 = performance.now()
      await Promise.all(Array.from({ length: clients }, async (_, cid) => {
        for (let i = 0; i < PER_CLIENT; i++) {
          const f = flows[(cid * PER_CLIENT + i + clients * 7) % flows.length]
          const r = await analyst.call('POST', '/api/ai/analyze', { ...f.features, sourceIP: nextIp() }).catch((e) => ({ status: 'ERR:' + e.name, ms: 0 }))
          codes[r.status] = (codes[r.status] || 0) + 1
          if (r.status === 200) lat.push(r.ms)
        }
      }))
      const wall = (performance.now() - t1) / 1000
      const stored = (await AIPrediction.countDocuments({})) - before
      const row = { clients, requests: clients * PER_CLIENT, codes, stored, rps: Math.round((lat.length / wall) * 10) / 10,
        p50: pct(lat, 50), p95: pct(lat, 95), p99: pct(lat, 99), max: lat.length ? Math.round(Math.max(...lat)) : null }
      levelStats.push(row)
      assert(codes[200] === clients * PER_CLIENT, 'non-200 responses: ' + JSON.stringify(codes))
      assert(stored === clients * PER_CLIENT, `stored ${stored} predictions for ${clients * PER_CLIENT} requests`)
      return row
    })
  }

  await check('consistency', 'every threat links one prediction; no duplicate ThreatLogs; events match per role', async () => {
    await sleep(1500)
    const threats = await ThreatLog.find({}).lean()
    const linked = threats.filter((t) => t.predictionId)
    const dupPred = linked.length - new Set(linked.map((t) => String(t.predictionId))).size
    assert(dupPred === 0, dupPred + ' predictions produced more than one ThreatLog')
    const preds = await AIPrediction.find({}).lean()
    const shouldThreat = preds.filter((p) => !['BENIGN', 'Unknown'].includes(p.predictedClass) && p.threatScore >= 0.9).length
    const ids = new Set(threats.map((t) => String(t._id)))
    const roles = {}
    for (const role of ['admin', 'analyst', 'viewer']) {
      const m = seen[role]
      const dup = [...m.values()].filter((v) => v.length > 1).length
      const missing = [...ids].filter((id) => !m.has(id)).length
      const unredacted = role === 'viewer' ? [...m.values()].filter((v) => /^198\.51\.100\.\d+$/.test(v[0].sourceIP)).length : 0
      const redactedForPrivileged = role !== 'viewer' ? [...m.values()].filter((v) => !/^198\.51\.100\.\d+$/.test(v[0].sourceIP)).length : 0
      roles[role] = { events: m.size, duplicates: dup, missing, unredacted, redactedForPrivileged }
    }
    const bad = Object.entries(roles).filter(([, r]) => r.duplicates || r.missing || r.unredacted || r.redactedForPrivileged)
    assert(bad.length === 0, 'per-role delivery problems: ' + JSON.stringify(roles))
    return { predictions: preds.length, threatLogs: threats.length, expectedFromPredictions: shouldThreat, roles }
  })

  // ── failures and recovery ──
  const flowOf = (k) => ({ ...flows[k % flows.length].features, sourceIP: nextIp() })
  await check('failure', 'slow engine (3 s): requests wait and succeed, nothing degraded', async () => {
    fault.mode = 'delay'
    fault.delayMs = 3000
    const r = await analyst.call('POST', '/api/ai/analyze', flowOf(1))
    fault.mode = 'pass'
    assert(r.status === 200, 'status ' + r.status)
    const res = r.body?.data?.result || r.body?.data || {}
    assert(!/UNINSPECTED|DEGRADED|UNAVAILABLE/.test(JSON.stringify(res).slice(0, 2000)) || res.predictedClass !== 'UNINSPECTED_TRAFFIC', 'degraded although the engine answered')
    return { ms: Math.round(r.ms) }
  })

  let degradedBefore = await ThreatLog.countDocuments({ attackType: 'UNINSPECTED_TRAFFIC' })
  await check('failure', 'engine slower than the 10 s client timeout: request degrades (held, not blocked) instead of hanging', async () => {
    fault.mode = 'delay'
    fault.delayMs = 15000
    const r = await analyst.call('POST', '/api/ai/analyze', flowOf(2), {}, 90000)
    fault.mode = 'pass'
    const deg = await ThreatLog.find({ attackType: 'UNINSPECTED_TRAFFIC' }).sort({ createdAt: -1 }).lean()
    assert(r.status === 200, 'status ' + r.status)
    assert(deg.length === degradedBefore + 1, 'expected one degraded threat, got ' + (deg.length - degradedBefore))
    assert(deg[0].status !== 'BLOCKED', 'degraded flow was blocked')
    degradedBefore = deg.length
    return { ms: Math.round(r.ms), severity: deg[0].severity, status: deg[0].status }
  })

  await check('failure', 'engine unreachable: circuit opens after repeated failures, later requests fail fast and degrade', async () => {
    await proxyDown()
    const lat = []
    for (let i = 0; i < 8; i++) {
      const r = await analyst.call('POST', '/api/ai/analyze', flowOf(10 + i))
      assert(r.status === 200, 'status ' + r.status)
      lat.push(Math.round(r.ms))
    }
    const health = await fetch(BASE + '/health')
    const alerts = await mongoose.connection.db.collection('alerts').countDocuments({ type: 'SYSTEM_HEALTH' })
    const deg = (await ThreatLog.countDocuments({ attackType: 'UNINSPECTED_TRAFFIC' })) - degradedBefore
    degradedBefore += deg
    assert(deg === 8, 'expected 8 degraded threats, got ' + deg)
    assert(health.status === 503, '/health ' + health.status)
    return { latenciesMs: lat, healthStatus: health.status, healthAlerts: alerts }
  })

  await check('failure', 'explanation while the engine is down: clear 503 ENGINE_UNAVAILABLE', async () => {
    const t = await ThreatLog.findOne({ predictionId: { $ne: null }, attackType: { $ne: 'UNINSPECTED_TRAFFIC' } }).lean()
    assert(t, 'no explainable threat')
    const r = await analyst.call('GET', `/api/threats/${t._id}/explanation`)
    assert(r.status === 503 && r.body?.errors?.reason === 'ENGINE_UNAVAILABLE', 'got ' + r.status + ' ' + JSON.stringify(r.body?.errors))
    return { ms: Math.round(r.ms), reason: r.body.errors.reason }
  })

  await check('recovery', 'engine back: circuit closes and scoring resumes without a backend restart', async () => {
    await proxyUp()
    const r = await waitFor(async () => {
      const x = await analyst.call('POST', '/api/ai/analyze', flowOf(30))
      const res = x.body?.data?.result || {}
      return x.status === 200 && res.predictedClass && res.predictedClass !== 'UNINSPECTED_TRAFFIC' ? x : null
    }, 30000, 'scoring to resume')
    const health = await waitFor(async () => ((await fetch(BASE + '/health')).status === 200 ? 200 : null), 30000, 'health ok')
    const t = await ThreatLog.findOne({ predictionId: { $ne: null }, attackType: { $ne: 'UNINSPECTED_TRAFFIC' } }).lean()
    const e = await analyst.call('GET', `/api/threats/${t._id}/explanation`)
    assert(e.status === 200, 'explanation after recovery ' + e.status)
    return { firstSuccessMs: Math.round(r.ms), health, explanation: e.status }
  })

  if (!QUICK) {
    await check('failure', 'MongoDB killed: API answers with an error (no hang); health reports it', async () => {
      await stop('mongod')
      await sleep(1500)
      const r = await analyst.call('POST', '/api/ai/analyze', flowOf(40), {}, 60000)
      const h = await fetch(BASE + '/health').then((x) => x.status)
      const list = await analyst.call('GET', '/api/threats?limit=5', undefined, {}, 60000)
      assert(list.status >= 500 || list.status === 503, 'threat list with the DB down returned ' + list.status)
      assert(h === 503, '/health with the DB down ' + h)
      // Stay down until the 15 s session re-check has disconnected every socket, then long enough for their first
      // handshake retries to be refused (auth service unavailable) while the database is still away
      await waitFor(async () => Object.values(sockets).every((s) => !s.connected), 30000, 'server-side socket disconnects')
      await sleep(8000)
      const refused = socketLog.filter((e) => e.event === 'connect_error' && e.reason === 'Authentication service unavailable').length
      return { analyzeStatus: r.status, analyzeMs: Math.round(r.ms), listStatus: list.status, listMs: Math.round(list.ms), health: h, refusedHandshakesWhileDown: refused }
    })

    await check('recovery', 'MongoDB back: backend reconnects by itself and serves data again', async () => {
      startMongo()
      const t1 = Date.now()
      await waitFor(async () => {
        const r = await analyst.call('GET', '/api/threats?limit=5')
        return r.status === 200 ? true : null
      }, 60000, 'threat list to recover')
      const recoveredMs = Date.now() - t1
      const r = await analyst.call('POST', '/api/ai/analyze', flowOf(41))
      assert(r.status === 200, 'analyze after recovery ' + r.status)
      const h = await waitFor(async () => ((await fetch(BASE + '/health')).status === 200 ? 200 : null), 30000, 'health')
      return { recoveredMs, analyze: r.status, health: h }
    })
  }

  await check('sockets', 'a revoked or expired session cannot reconnect through the retry path', async () => {
    // Revoked: a second analyst session logs out; the server disconnects its socket, the retry is refused, it stays out
    const extra = new Client()
    await extra.login(users.analyst)
    const log = []
    const s = openSocket('analyst', extra.token, log)
    const events = []
    s.on('new_threat', (p) => events.push(p._id))
    await waitFor(async () => s.connected, 10000, 'second analyst socket')
    const out = await extra.mutate('POST', '/api/auth/logout', {})
    assert(out.status === 200, 'logout ' + out.status)
    await waitFor(async () => !s.connected, 10000, 'server to disconnect the revoked session')
    await sleep(6000) // past the first retry (1.5-2.5 s) and well into the second
    const r = await analyst.call('POST', '/api/ai/analyze', { ...flows.find((f) => f.label === 'DDoS').features, sourceIP: nextIp() })
    assert(r.status === 200, 'analyze ' + r.status)
    await sleep(1000)
    const refusals = log.filter((e) => e.event === 'connect_error').map((e) => e.reason)
    assert(!s.connected && events.length === 0, 'revoked session reconnected or received a threat')
    assert(refusals.length >= 1 && refusals.every((m) => m === 'Authentication rejected'), 'refusals ' + refusals)
    assert(refusals.length === 1, 'a rejected token was retried ' + refusals.length + ' times')
    s.stopRetrying(); s.close()
    // Expired: a correctly signed access token past its exp is refused at the handshake and not retried
    const jwt = req('jsonwebtoken')
    const claims = JSON.parse(Buffer.from(analyst.token.split('.')[1], 'base64url').toString())
    const now = Math.floor(Date.now() / 1000)
    const expired = jwt.sign({ ...claims, iat: now - 3600, exp: now - 60 }, S.JWT_SECRET, { algorithm: 'HS256' })
    const elog = []
    const e = openSocket('analyst', expired, elog)
    await sleep(6000)
    const eRefusals = elog.filter((x) => x.event === 'connect_error').map((x) => x.reason)
    e.stopRetrying(); e.close()
    assert(!elog.some((x) => x.event === 'reconnect') && eRefusals.length === 1 && eRefusals[0] === 'Authentication rejected',
      'expired token: ' + JSON.stringify(elog.map((x) => x.event + ':' + (x.reason || ''))))
    return { revoked: { disconnects: log.filter((x) => x.event === 'disconnect').map((x) => x.reason), refusals, eventsAfterLogout: events.length },
      expired: { refusals: eRefusals } }
  })

  await check('sockets', 'after the outages every role socket is connected again and receives threats (rooms rejoined)', async () => {
    await waitFor(async () => Object.values(sockets).every((s) => s.connected), 45000, 'sockets to reconnect')
    await sleep(500)
    const before = Object.fromEntries(Object.keys(seen).map((r) => [r, seen[r].size]))
    const r = await analyst.call('POST', '/api/ai/analyze', { ...flows.find((f) => f.label === 'DDoS').features, sourceIP: nextIp() })
    assert(r.status === 200, 'analyze ' + r.status)
    await waitFor(async () => Object.keys(seen).every((role) => seen[role].size > before[role]), 10000, 'post-reconnect threat event on every socket')
    const disconnects = socketLog.filter((e) => e.event === 'disconnect')
    return { reconnected: Object.keys(sockets), disconnects: disconnects.map((e) => `${e.role}:${e.reason}`) }
  })

  for (const s of Object.values(sockets)) s.close()
  return levelStats
}

main()
  .catch((e) => {
    results.push({ area: 'harness', name: 'run', status: 'FAIL', detail: redact(e.stack || e.message) })
    console.log('FAIL  harness: ' + redact(e.message))
  })
  .finally(async () => {
    await mongoose.connection.db?.dropDatabase().catch(() => {})
    await mongoose.disconnect().catch(() => {})
    await proxyDown().catch(() => {})
    for (const name of [...procs.keys()]) await stop(name) // stop mongod before deleting its files (Windows locks them)
    for (const d of tmpDirs) fs.rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 })
    const pass = results.filter((r) => r.status === 'PASS').length
    const fail = results.length - pass
    fs.writeFileSync(path.join(runDir, 'results.json'), redact(JSON.stringify({ database: DB, pass, fail, results }, null, 2)))
    console.log(`\n${pass} passed, ${fail} failed — evidence: ${path.relative(root, runDir)}`)
    process.exit(fail ? 1 : 0)
  })
