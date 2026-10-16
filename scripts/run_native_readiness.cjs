// Approved, isolated native acceptance only. Never reads existing env/credentials or old database storage.
const fs = require('node:fs')
const path = require('node:path')
const net = require('node:net')
const https = require('node:https')
const http = require('node:http')
const crypto = require('node:crypto')
const { spawn, spawnSync } = require('node:child_process')
const { MongoClient, ObjectId } = require('../backend/node_modules/mongodb')
const jwt = require('../backend/node_modules/jsonwebtoken')
const socketClient = require('../frontend/node_modules/socket.io-client').io
const root = path.resolve(__dirname, '..')
const storage = path.join(root, '.test-runtime/native-readiness-20261014-01')
const database = 'sentinelai_native_readiness_20261014'
const binary = 'C:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete.native-integration\\mongodb-acceptance-20261014\\binaries\\mongod.exe'
const python = path.join(root, 'ai-engine/.venv/Scripts/python.exe')
const origin = 'https://127.0.0.1:13443'
const ports = [27030, 18000, 15001, 15002, 13443, 13080]
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const owned = [], sockets = [], results = []
let credentials, ca, agent, admin, appDB, mongo, ai, browser, runDir, aiExecutable
const assert = (value, code) => { if (!value) throw new Error(code) }
const protect = (input, decrypt = false) => {
  const method = decrypt ? 'Unprotect' : 'Protect'
  const inputExpr = decrypt ? '[Convert]::FromBase64String([Console]::In.ReadToEnd())' : '[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd())'
  const outputExpr = decrypt ? '[Text.Encoding]::UTF8.GetString($output)' : '[Convert]::ToBase64String($output)'
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `Add-Type -AssemblyName System.Security; $bytes=${inputExpr}; $output=[Security.Cryptography.ProtectedData]::${method}($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write(${outputExpr})`], { input, encoding: 'utf8', windowsHide: true })
  assert(result.status === 0, 'DPAPI storage failed'); return result.stdout
}
const sanitize = value => {
  for (const secret of Object.values(credentials || {})) if (typeof secret === 'string' && secret.length > 12) value = value.split(secret).join('[REDACTED]')
  return value.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[JWT REDACTED]').replace(/mongodb:\/\/[^\s"']+/g, '[Mongo URI redacted]')
}
function evidence(name, value) { fs.writeFileSync(path.join(runDir, name), sanitize(typeof value === 'string' ? value : JSON.stringify(value, null, 2))) }
async function check(name, category, fn) {
  const started = Date.now()
  try { const detail = await fn(); results.push({ name, category, status: 'PASS', durationMs: Date.now() - started, detail }); console.log('PASS ' + name) }
  catch (error) { results.push({ name, category, status: 'FAIL', durationMs: Date.now() - started, error: sanitize(error.message) }); console.log('FAIL ' + name + ': ' + sanitize(error.message)); process.exitCode = 1 }
  evidence('results.json', results)
}
async function wait(fn, timeout = 30000, label = 'Readiness timeout') {
  const end = Date.now() + timeout
  while (Date.now() < end) { try { const value = await fn(); if (value) return value } catch {} await delay(250) }
  throw new Error(label)
}
async function freePort(port) {
  return new Promise((resolve, reject) => { const probe = net.createServer(); probe.on('error', () => reject(new Error('Approved port occupied: ' + port))); probe.listen(port, '127.0.0.1', () => probe.close(resolve)) })
}
function child(name, executable, args, env = {}, cwd = root, ipc = false) {
  let process
  try { process = spawn(executable, args, { cwd, windowsHide: true, env: { ...global.process.env, HTTP_PROXY: '', HTTPS_PROXY: '', ALL_PROXY: '', NO_PROXY: 'localhost,127.0.0.1', ...env }, stdio: ['ignore', 'pipe', 'pipe', ...(ipc ? ['ipc'] : [])] }) }
  catch (error) { throw new Error('Owned service spawn failed: ' + name + ' (' + error.code + ')') }
  let output = ''
  process.stdout.on('data', chunk => { output += chunk }); process.stderr.on('data', chunk => { output += chunk })
  process.on('error', () => {})
  owned.push({ name, executable, args: [...args], process, output: () => output })
  evidence('processes.json', owned.map(item => ({ name: item.name, pid: item.process.pid, parentPid: global.process.pid, executable: item.executable, args: item.args, exited: item.process.exitCode })))
  return process
}
async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode) return
  process.kill()
  await Promise.race([new Promise(resolve => process.once('exit', resolve)), delay(6000)])
  assert(process.exitCode !== null || process.signalCode, 'Owned process did not stop')
}
function startMongo() {
  mongo = child('MongoDB', binary, ['--auth', '--replSet', 'sentinel_native_test', '--keyFile', path.join(storage, 'runtime/replica-keyfile'), '--bind_ip', '127.0.0.1', '--port', '27030', '--dbpath', path.join(storage, 'data'), '--logpath', path.join(storage, 'logs/mongod.log'), '--logappend'])
}
function startAI() {
  ai = child('AI engine', aiExecutable, ['-m', 'uvicorn', 'inference.main:app', '--host', '127.0.0.1', '--port', '18000'], { SENTINEL_KEY: credentials.SENTINEL_KEY, MODEL_DIR: path.join(root, 'ai-engine/models'), SENTINEL_API: origin + '/api', SSL_CERT_FILE: path.join(storage, 'tls/ca.pem'), CORS_ORIGINS: origin, PYTHONDONTWRITEBYTECODE: '1', PYTHONPATH: path.join(root, 'ai-engine/.venv/Lib/site-packages') }, path.join(root, 'ai-engine'))
}
async function request(route, { method = 'GET', body, headers = {}, direct, jar, worker = 'A', raw } = {}) {
  const url = direct ? new URL(route, direct) : new URL(route, origin)
  const transport = url.protocol === 'https:' ? https : http
  const payload = raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body)
  const sent = { ...(payload !== undefined ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}), ...headers }
  if (!direct) sent['X-Test-Upstream'] = worker
  if (jar) sent.Cookie = Object.entries(jar.cookies).map(([k, v]) => k + '=' + v).join('; ')
  return new Promise((resolve, reject) => {
    const req = transport.request(url, { method, headers: sent, agent: url.protocol === 'https:' ? agent : undefined, timeout: 12000 }, res => {
      let data = ''; res.on('data', chunk => { data += chunk }); res.on('end', () => {
        if (jar) for (const cookie of res.headers['set-cookie'] || []) { const part = cookie.split(';')[0], pos = part.indexOf('='); jar.cookies[part.slice(0, pos)] = part.slice(pos + 1) }
        let parsed; try { parsed = JSON.parse(data) } catch {}
        resolve({ status: res.statusCode, data: parsed, text: data, headers: res.headers })
      })
    })
    req.on('timeout', () => req.destroy(new Error('Request timeout'))); req.on('error', reject); req.end(payload)
  })
}
const me = (token, worker = 'B') => request('/api/auth/me', { worker, headers: { Authorization: 'Bearer ' + token } })
async function mutation(jar, endpoint, body, method = 'POST', extra = {}) {
  const csrf = await request('/api/auth/csrf', { jar })
  assert(csrf.status === 200, 'CSRF readiness failed')
  return request('/api/auth/' + endpoint, { jar, method, body, headers: { Origin: origin, 'X-CSRF-Token': csrf.data.data.csrfToken, ...(jar.token ? { Authorization: 'Bearer ' + jar.token } : {}) }, ...extra })
}
async function account(label, role = 'analyst') {
  const jar = { cookies: {}, email: 'native-' + label + '-' + crypto.randomUUID() + '@example.invalid', password: credentials.userPassword }
  const response = await mutation(jar, 'register', { name: 'NATIVE READINESS ' + label, email: jar.email, password: jar.password, role })
  assert(response.status === 201, 'Registration status ' + response.status)
  jar.token = response.data.data.token; jar.id = response.data.data.user._id
  return jar
}
async function login(jar) {
  const response = await mutation(jar, 'login', { email: jar.email, password: jar.password })
  assert(response.status === 200, 'Login status ' + response.status); jar.token = response.data.data.token; return response
}
async function connect(token, worker = 'B') {
  const socket = socketClient(origin, { auth: { token }, transports: ['websocket'], reconnection: false, ca, rejectUnauthorized: true, extraHeaders: { Origin: origin, 'X-Test-Upstream': worker }, timeout: 8000 })
  sockets.push(socket)
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('connect_error', () => reject(new Error('Socket authorization failed'))) })
  socket.emit('join_room', {})
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Socket room join failed')), 5000); socket.once('connected', () => { clearTimeout(timer); resolve() }) })
  return socket
}
async function revoked(socket, action, limit = 4500) {
  const started = Date.now()
  const completion = new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Remote socket revocation timeout')), limit); socket.once('disconnect', reason => { clearTimeout(timer); resolve(reason) }) })
  await action(); const reason = await completion
  assert(!socket.connected, 'Socket remained connected'); return { deliveryMs: Date.now() - started, reason }
}
async function main() {
  assert(process.argv.includes('--create') !== process.argv.includes('--resume'), 'Use exactly --create or scoped --resume')
  for (const port of ports) await freePort(port)
  for (let current = path.dirname(storage);; current = path.dirname(current)) { if (fs.existsSync(current)) assert(!fs.lstatSync(current).isSymbolicLink(), 'Redirected storage parent'); if (current === path.dirname(current)) break }
  const resume = process.argv.includes('--resume')
  if (!resume) {
    assert(!fs.existsSync(storage), 'Approved directory already exists')
    fs.mkdirSync(storage)
    for (const name of ['data', 'logs', 'evidence', 'runtime', 'tls']) fs.mkdirSync(path.join(storage, name))
    credentials = Object.fromEntries(['admin', 'application', 'userPassword', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'SENTINEL_KEY', 'HONEYPOT_API_KEY'].map(name => [name, crypto.randomBytes(32).toString('hex')]))
    credentials.replicaKey = crypto.randomBytes(512).toString('base64')
    const tls = spawnSync(python, [path.join(root, 'scripts/native_test_certificate.py')], { encoding: 'utf8', windowsHide: true })
    assert(tls.status === 0, 'TLS certificate generation failed')
    Object.assign(credentials, JSON.parse(tls.stdout))
    fs.writeFileSync(path.join(storage, 'credentials.dpapi'), protect(JSON.stringify(credentials)), { flag: 'wx' })
    fs.writeFileSync(path.join(storage, 'ownership.json'), JSON.stringify({ storage, database, ports, replicaSet: 'sentinel_native_test' }), { flag: 'wx' })
    fs.writeFileSync(path.join(storage, 'tls/ca.pem'), credentials.ca, { flag: 'wx' }); fs.writeFileSync(path.join(storage, 'tls/server.pem'), credentials.cert, { flag: 'wx' })
  } else {
    const owner = JSON.parse(fs.readFileSync(path.join(storage, 'ownership.json')))
    assert(owner.storage === storage && owner.database === database && JSON.stringify(owner.ports) === JSON.stringify(ports), 'Ownership mismatch')
    credentials = JSON.parse(protect(fs.readFileSync(path.join(storage, 'credentials.dpapi'), 'utf8'), true))
  }
  for (const name of ['', 'data', 'logs', 'evidence', 'runtime', 'tls']) { const ownedPath = path.join(storage, name); assert(!fs.lstatSync(ownedPath).isSymbolicLink() && fs.realpathSync(ownedPath).toLowerCase() === ownedPath.toLowerCase(), 'Owned storage redirect') }
  runDir = path.join(storage, 'evidence', 'run-' + Date.now()); fs.mkdirSync(runDir)
  const pythonBase = spawnSync(python, ['-c', 'import sys; print(sys._base_executable)'], { encoding: 'utf8', windowsHide: true })
  assert(pythonBase.status === 0 && fs.existsSync(pythonBase.stdout.trim()), 'Owned Python interpreter unavailable')
  aiExecutable = pythonBase.stdout.trim() // Avoid the Windows venv redirector child: the owned handle is the actual interpreter.
  ca = credentials.ca; agent = new https.Agent({ ca, rejectUnauthorized: true })
  const version = spawnSync(binary, ['--version'], { encoding: 'utf8', windowsHide: true }); assert(version.status === 0 && version.stdout.includes('v7.0.45'), 'Reviewed MongoDB binary unavailable')
  const keyFile = path.join(storage, 'runtime/replica-keyfile'); assert(!fs.existsSync(keyFile), 'Unexpected existing runtime keyfile')
  fs.writeFileSync(keyFile, credentials.replicaKey, { flag: 'wx' })
  const identity = spawnSync('whoami.exe', [], { encoding: 'utf8', windowsHide: true }).stdout.trim()
  const acl = spawnSync('icacls.exe', [keyFile, '/inheritance:r', '/grant:r', identity + ':F'], { encoding: 'utf8', windowsHide: true }); assert(acl.status === 0, 'Keyfile ACL restriction failed')
  startMongo()
  if (!resume) {
    const bootstrap = new MongoClient('mongodb://127.0.0.1:27030/admin?directConnection=true', { serverSelectionTimeoutMS: 500 })
    try {
      await wait(async () => { await bootstrap.connect(); return (await bootstrap.db('admin').command({ ping: 1 })).ok }, 30000, 'New MongoDB startup failed')
      await bootstrap.db('admin').command({ replSetInitiate: { _id: 'sentinel_native_test', members: [{ _id: 0, host: '127.0.0.1:27030' }] } })
      await wait(async () => (await bootstrap.db('admin').command({ hello: 1 })).isWritablePrimary, 30000, 'New replica set primary unavailable')
      await bootstrap.db('admin').command({ createUser: 'native_readiness_admin', pwd: credentials.admin, roles: [{ role: 'root', db: 'admin' }] })
    } finally { await bootstrap.close() }
  }
  const adminURI = `mongodb://native_readiness_admin:${credentials.admin}@127.0.0.1:27030/admin?directConnection=true`
  admin = new MongoClient(adminURI, { serverSelectionTimeoutMS: 1000 })
  await wait(async () => { await admin.connect(); return (await admin.db('admin').command({ hello: 1 })).isWritablePrimary }, 45000, 'Authenticated owned MongoDB startup failed')
  if (!resume) await admin.db(database).command({ createUser: 'native_readiness_application', pwd: credentials.application, roles: [{ role: 'readWrite', db: database }] })
  const uri = `mongodb://native_readiness_application:${credentials.application}@127.0.0.1:27030/${database}?authSource=${database}&replicaSet=sentinel_native_test`
  appDB = new MongoClient(uri, { serverSelectionTimeoutMS: 1500 }); await appDB.connect()
  const db = appDB.db(database)
  await check('MongoDB authentication, scope, primary and storage', 'real database', async () => {
    const config = (await admin.db('admin').command({ getCmdLineOpts: 1 })).parsed
    assert(config.net.bindIp === '127.0.0.1' && config.net.port === 27030 && config.security.authorization === 'enabled' && path.resolve(config.storage.dbPath) === path.join(storage, 'data'), 'Database configuration mismatch')
    const hello = await admin.db('admin').command({ hello: 1 }); assert(hello.isWritablePrimary && hello.setName === 'sentinel_native_test', 'Replica topology mismatch')
    const anonymous = new MongoClient('mongodb://127.0.0.1:27030/?directConnection=true'); let denied = false
    try { await anonymous.db(database).collection('users').findOne() } catch (e) { denied = e.code === 13 } finally { await anonymous.close() }
    assert(denied, 'Anonymous data access accepted')
    let outsideDenied = false; try { await appDB.db('unapproved_database').collection('users').findOne() } catch (e) { outsideDenied = e.code === 13 }
    assert(outsideDenied, 'Application role escaped database')
    return { version: '7.0.45', database, authenticated: true, loopback: true, replicaSet: hello.setName }
  })
  const build = path.join(runDir, 'frontend-build')
  const buildResult = spawnSync(process.execPath, ['node_modules/vite/bin/vite.js', 'build', '--outDir', build], { cwd: path.join(root, 'frontend'), encoding: 'utf8', windowsHide: true, env: { ...process.env, VITE_API_BASE_URL: '/api', VITE_SOCKET_URL: origin } })
  evidence('frontend-build.log', buildResult.stdout + buildResult.stderr); assert(buildResult.status === 0, 'Acceptance frontend build failed')
  startAI(); await wait(async () => (await request('/ready', { direct: 'http://127.0.0.1:18000' })).status === 200, 180000, 'Genuine models unavailable')
  const shared = { MONGO_URI: uri, JWT_SECRET: credentials.JWT_SECRET, JWT_REFRESH_SECRET: credentials.JWT_REFRESH_SECRET, SENTINEL_KEY: credentials.SENTINEL_KEY, HONEYPOT_API_KEY: credentials.HONEYPOT_API_KEY,
    NODE_ENV: 'production', AUTH_REVOCATION_MODE: 'mongo-stream', API_WORKERS: '2', TRUST_PROXY: '127.0.0.2/32', HOST: '127.0.0.1', CLIENT_URL: origin, AI_ENGINE_URL: 'http://127.0.0.1:18000', ABUSEIPDB_API_KEY: '', ADMIN_INITIAL_PASSWORD: '', LOG_DIR: path.join(storage, 'logs/backend'), RATE_LIMIT_MAX: '10000' }
  const workerA = child('API worker A', process.execPath, ['backend/server.js'], { ...shared, PORT: '15001' })
  await wait(async () => (await request('/health', { direct: 'http://127.0.0.1:15001' })).status === 200, 30000, 'Worker A readiness failed')
  const workerB = child('API worker B', process.execPath, ['backend/server.js'], { ...shared, PORT: '15002' })
  await wait(async () => (await request('/health', { direct: 'http://127.0.0.1:15002' })).status === 200, 30000, 'Worker B readiness failed')
  assert(workerA.pid !== workerB.pid, 'Workers are not separate processes')
  const proxy = child('TLS proxy', process.execPath, ['scripts/native_readiness_proxy.cjs'], {}, root, true)
  proxy.send({ key: credentials.key, cert: credentials.cert, build })
  await wait(async () => (await request('/health')).status === 200)
  evidence('topology.json', { workerAPid: workerA.pid, workerBPid: workerB.pid, listeners: ports.map(port => ({ host: '127.0.0.1', port })), trustedProxySource: '127.0.0.2', tls: 'Dedicated test CA; hostname verification enabled', browserSPKI: credentials.spki })
  if (process.argv.includes('--focus-contract')) {
    const user = await account('ai-contract-regression')
    await check('Invalid feature input is sanitized 422 through the actual backend and AI', 'real API and model validation; no prediction writes', async () => {
      const before = await db.collection('aipredictions').countDocuments()
      const response = await request('/api/ai/analyze', { method: 'POST', body: { sourceIP: '192.0.2.30', flow_duration: 'invalid-native-feature' }, headers: { Authorization: 'Bearer ' + user.token } })
      assert(response.status === 422 && !response.text.includes('invalid-native-feature'), 'Invalid input masqueraded as outage or leaked input')
      assert(await db.collection('aipredictions').countDocuments() === before, 'Invalid input persisted a prediction')
    })
    await check('AI internal credential mismatch fails readiness and correct credentials recover', 'real AI authentication and owned worker B restart', async () => {
      assert((await request('/health', { worker: 'B' })).data.aiEngine.details.authenticated === true, 'Valid internal authentication not verified')
      await stop(workerB)
      credentials.probeKey = crypto.randomBytes(32).toString('hex')
      const bad = child('API worker B invalid-key fixture', process.execPath, ['backend/server.js'], { ...shared, PORT: '15002', SENTINEL_KEY: credentials.probeKey })
      await wait(async () => { const reply = await request('/health', { worker: 'B' }); return reply.status === 503 && reply.data?.service === 'SentinelAI API' && reply.data.database.status === 'connected' }, 45000, 'Incorrect internal key claimed readiness')
      assert((await me(user.token)).status === 200, 'Persisted reads unnecessarily depended on AI credentials')
      await stop(bad)
      child('API worker B recovered credential', process.execPath, ['backend/server.js'], { ...shared, PORT: '15002' })
      await wait(async () => (await request('/health', { worker: 'B' })).status === 200, 45000, 'Correct internal credential did not recover')
    })
    await analyticsChecks(db, user.token)
    return
  }
  if (process.argv.includes('--focus-browser') || process.argv.includes('--focus-empty')) { await stop(ai); await browserChecks(db); return }
  await check('Production TLS proxy, direct HTTP and spoofed protocol rejection', 'real HTTPS and two API processes', async () => {
    assert((await request('/api/auth/csrf')).status === 200, 'Trusted TLS proxy rejected')
    assert((await request('/api/auth/csrf', { direct: 'http://127.0.0.1:15001' })).status === 426, 'Plain HTTP accepted')
    assert((await request('/api/auth/csrf', { direct: 'http://127.0.0.1:15002', headers: { 'X-Forwarded-Proto': 'https' } })).status === 426, 'Spoofed protocol accepted')
    return { actualTLS: true, certificateVerified: true, directAndSpoofed: 426 }
  })
  await check('Origin, signed CSRF, duplicate cookies and credentialed CORS', 'real HTTPS', async () => {
    const jar = { cookies: {} }; const csrf = await request('/api/auth/csrf', { jar })
    const valid = { Origin: origin, 'X-CSRF-Token': csrf.data.data.csrfToken }
    assert((await request('/api/auth/login', { jar, method: 'POST', body: {}, headers: { ...valid, Origin: 'https://evil.example.invalid' } })).status === 403, 'Foreign Origin accepted')
    assert((await request('/api/auth/login', { jar, method: 'POST', body: {}, headers: { Origin: origin, 'X-CSRF-Token': 'invalid' } })).status === 403, 'Invalid CSRF accepted')
    const cookie = Object.entries(jar.cookies)[0].join('=')
    assert((await request('/api/auth/login', { method: 'POST', body: {}, headers: { ...valid, Cookie: cookie + '; ' + cookie } })).status === 403, 'Duplicate nonce accepted')
    const allowed = await request('/api/auth/csrf', { headers: { Origin: origin } })
    assert(allowed.headers['access-control-allow-origin'] === origin && allowed.headers['access-control-allow-credentials'] === 'true', 'Credentialed CORS mismatch')
    const denied = await request('/api/auth/csrf', { headers: { Origin: 'https://evil.example.invalid' } })
    assert(denied.status === 403 && !denied.headers['access-control-allow-origin'], 'Foreign CORS accepted')
  })
  await check('Registration, cross-worker authorization and secure absolute-lifetime cookies', 'real database and HTTPS', async () => {
    const user = await account('cookies'); const response = await login(user)
    assert((await me(user.token)).status === 200, 'Cross-worker session missing')
    assert(!Object.hasOwn(response.data.data, 'refreshToken'), 'Refresh exposed in JSON')
    const refresh = response.headers['set-cookie'].find(c => c.startsWith('__Secure-sentinel_refresh='))
    assert(/HttpOnly/.test(refresh) && /Secure/.test(refresh) && /SameSite=Strict/.test(refresh) && /Path=\/api\/auth/.test(refresh), 'Refresh flags mismatch')
    const access = jwt.decode(user.token), absolute = jwt.decode(decodeURIComponent(user.cookies.__Secure_sentinel_refresh || user.cookies['__Secure-sentinel_refresh']))
    assert(access.exp - access.iat === 900 && absolute.exp - absolute.iat === 2592000, 'Lifetime changed')
    const rotated = await mutation(user, 'refresh-token'); assert(rotated.status === 200, 'Rotation failed')
    const next = jwt.decode(decodeURIComponent(user.cookies['__Secure-sentinel_refresh'])); assert(next.exp === absolute.exp, 'Absolute expiry extended')
    return { accessSeconds: 900, absoluteSessionSeconds: 2592000, refreshInBody: false }
  })
  await check('Concurrent refresh CAS winner and replay family revocation across workers', 'real database concurrency', async () => {
    const user = await account('rotation'); const csrf = await request('/api/auth/csrf', { jar: user })
    const headers = { Origin: origin, 'X-CSRF-Token': csrf.data.data.csrfToken }
    const pair = await Promise.all(['A', 'B'].map(worker => request('/api/auth/refresh-token', { jar: { cookies: { ...user.cookies } }, method: 'POST', headers, worker })))
    assert(pair.filter(r => r.status === 200).length === 1 && pair.filter(r => r.status === 401).length === 1, 'Refresh was not atomic')
    assert((await me(pair.find(r => r.status === 200).data.data.token)).status === 401, 'Replay winner retained authority')
    return { statuses: pair.map(r => r.status), winnerRevoked: true }
  })
  await check('Logout on A disconnects authenticated socket on B', 'two real API processes', async () => {
    const user = await account('logout'); const socket = await connect(user.token)
    const detail = await revoked(socket, async () => assert((await mutation(user, 'logout')).status === 200, 'Logout failed'))
    assert((await me(user.token)).status === 401, 'Logout access remains valid'); return detail
  })
  await check('Logout-all on A revokes separate session/socket on B', 'two real API processes', async () => {
    const user = await account('logoutall'); const other = { ...user, cookies: {} }; await login(other)
    const socket = await connect(other.token)
    const detail = await revoked(socket, async () => assert((await mutation(user, 'logout-all')).status === 200, 'Logout-all failed'))
    assert((await me(other.token)).status === 401, 'Other session remains valid'); return detail
  })
  await check('Password change revokes remote session without same-second timestamp dependence', 'two real API processes', async () => {
    const user = await account('password'); const other = { ...user, cookies: {} }; await login(other); const socket = await connect(other.token)
    const original = await db.collection('users').findOne({ _id: new ObjectId(user.id) })
    const detail = await revoked(socket, async () => {
      const changed = await mutation(user, 'update-password', { currentPassword: user.password, newPassword: crypto.randomBytes(24).toString('hex') }, 'PUT')
      assert(changed.status === 200, 'Password change failed'); assert((await me(changed.data.data.token)).status === 200, 'Replacement rejected')
    })
    const changed = await db.collection('users').findOne({ _id: new ObjectId(user.id) }); assert(changed.authVersion === original.authVersion + 1 && (await me(other.token)).status === 401, 'Password version revocation failed'); return detail
  })
  for (const operation of ['disable', 'role downgrade', 'delete']) await check('Account ' + operation + ' disconnects worker B', 'real database change stream and two API processes', async () => {
    const user = await account(operation.replace(' ', '-')); const socket = await connect(user.token)
    const detail = await revoked(socket, async () => {
      const filter = { _id: new ObjectId(user.id) }
      if (operation === 'delete') await db.collection('users').deleteOne(filter)
      else await db.collection('users').updateOne(filter, { $set: operation === 'disable' ? { status: 'inactive' } : { role: 'viewer' }, $inc: { authVersion: 1 } })
    })
    assert((await me(user.token)).status !== 200, 'Account security mutation retained authority'); return { ...detail, fixtureMutation: operation }
  })
  await check('Socket expiry and unauthorized packet rejection', 'real socket and signed short-lifetime fixture', async () => {
    const user = await account('expiry'), claims = jwt.decode(user.token); claims.exp = Math.floor(Date.now() / 1000) + 2
    const socket = await connect(jwt.sign(claims, credentials.JWT_SECRET, { algorithm: 'HS256' }))
    const detail = await revoked(socket, async () => {}, 4000)
    let snapshots = 0; socket.on('stats_snapshot', () => snapshots++); socket.emit('request_stats'); await delay(100)
    assert(snapshots === 0, 'Expired socket delivered protected event'); return { ...detail, productionLifetimeUnchanged: true }
  })
  await check('Handshake/logout and refresh/logout concurrent revocation races', 'two processes and real database concurrency', async () => {
    const user = await account('races')
    const connecting = connect(user.token).catch(() => null)
    const csrf = await request('/api/auth/csrf', { jar: user }); const headers = { Origin: origin, 'X-CSRF-Token': csrf.data.data.csrfToken }
    const [rotation, logout] = await Promise.all([request('/api/auth/refresh-token', { jar: { cookies: { ...user.cookies } }, method: 'POST', headers, worker: 'B' }), request('/api/auth/logout', { jar: { cookies: { ...user.cookies } }, method: 'POST', headers })])
    assert(logout.status === 200, 'Race logout failed')
    if (rotation.status === 200) assert((await me(rotation.data.data.token)).status === 401, 'Race successor survived')
    const socket = await connecting; if (socket) await wait(() => !socket.connected, 4500, 'Racing socket survived')
    assert((await me(user.token)).status === 401, 'Racing access survived'); return { refreshStatus: rotation.status, logoutStatus: logout.status }
  })
  await check('Access purpose, issuer, audience and algorithm reject signed invalid tokens', 'real HTTP authorization', async () => {
    const user = await account('claims')
    for (const [field, value] of [['purpose', 'refresh'], ['iss', 'other-issuer'], ['aud', 'other-audience']]) {
      const claims = { ...jwt.decode(user.token), [field]: value }
      assert((await me(jwt.sign(claims, credentials.JWT_SECRET, { algorithm: 'HS256' }))).status === 401, 'Invalid claim accepted: ' + field)
    }
    assert((await me(jwt.sign(jwt.decode(user.token), credentials.JWT_SECRET, { algorithm: 'HS384' }))).status === 401, 'Unexpected algorithm accepted')
  })
  const administrator = await account('authorized-administrator-fixture')
  await db.collection('users').updateOne({ _id: new ObjectId(administrator.id) }, { $set: { role: 'admin' }, $inc: { authVersion: 1 } })
  await login(administrator)
  await check('Administrator API role/status/delete operations revoke remote sessions', 'real administrator HTTP API and two processes', async () => {
    for (const mutation of ['role', 'status', 'delete']) {
      const user = await account('admin-operation-' + mutation), socket = await connect(user.token)
      await revoked(socket, async () => {
        const reply = await request('/api/users/' + user.id, { method: mutation === 'delete' ? 'DELETE' : 'PUT', body: mutation === 'delete' ? undefined : mutation === 'role' ? { role: 'viewer' } : { status: 'inactive' }, headers: { Authorization: 'Bearer ' + administrator.token } })
        assert(reply.status === 200, 'Administrator operation failed: ' + mutation)
      })
      assert((await me(user.token)).status !== 200, 'Administrator mutation did not revoke access')
    }
  })
  const modelUser = await account('model-persistence')
  const modelSocket = await connect(modelUser.token, 'A'); const delivered = []
  modelSocket.onAny(event => { if (['new_threat', 'new_alert', 'ai_prediction'].includes(event)) delivered.push(event) })
  const sampleFile = path.join(runDir, 'samples.json')
  const dataset = spawnSync(python, [path.join(root, 'scripts/acceptance_dataset.py'), sampleFile], { encoding: 'utf8', windowsHide: true, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } })
  assert(dataset.status === 0, 'Archived dataset sample extraction failed'); evidence('dataset.log', dataset.stdout + dataset.stderr)
  const samples = JSON.parse(fs.readFileSync(sampleFile)), decisions = []
  await check('RF/IF loading, real 53-feature predictions, scores, database and application read-back', 'real models, database and HTTP API', async () => {
    const info = await request('/model/info', { direct: 'http://127.0.0.1:18000', headers: { 'X-API-Key': credentials.SENTINEL_KEY } }); assert(info.status === 200, 'Model metadata unavailable'); evidence('model-info.json', info.data)
    for (const sample of samples) {
      const direct = await request('/predict/internal', { direct: 'http://127.0.0.1:18000', method: 'POST', body: sample, headers: { 'X-API-Key': credentials.SENTINEL_KEY } })
      assert(direct.status === 200 && direct.data.result.featureVector.length === 53, '53-feature inference failed')
      const through = await request('/api/ai/analyze', { method: 'POST', body: sample, headers: { Authorization: 'Bearer ' + modelUser.token } })
      assert(through.status === 200, 'AI application path status ' + through.status)
      const result = through.data.data.result, expected = direct.data.result
      assert(result.predictedClass === expected.predictedClass && result.threatScore === expected.threatScore && result.action === expected.action, 'AI path score or decision mismatch')
      const stored = await db.collection('aipredictions').findOne({ _id: new ObjectId(result._id) })
      assert(stored && stored.threatScore === result.threatScore && stored.featureVector.length === 53 && stored.rawFeatures.acceptanceTest === true, 'Prediction persistence mismatch')
      decisions.push({ row: sample.provenance.rowIndex, label: sample.provenance.label, action: result.action, threatScore: result.threatScore, predictionId: result._id })
    }
    const logs = await request('/api/ai/predictions?limit=100', { headers: { Authorization: 'Bearer ' + modelUser.token } }); assert(logs.status === 200 && decisions.every(d => logs.data.data.some(record => record._id === d.predictionId && record.threatScore === d.threatScore)), 'Prediction read API mismatch')
    const threats = await request('/api/threats?limit=100', { headers: { Authorization: 'Bearer ' + modelUser.token } }); assert(threats.status === 200, 'Threat read API failed')
    evidence('real-model-decisions.json', decisions); evidence('prediction-read-summary.json', { status: logs.status, persisted: decisions.length });
    assert(new Set(decisions.map(item => item.action)).size === 3, 'Archived rows did not naturally exercise all three actions')
    assert(await db.collection('blockedips').countDocuments() === 0, 'Unexpected containment record')
    return { realRows: decisions.length, features: 53, actions: [...new Set(decisions.map(item => item.action))], noContainment: true }
  })
  await check('Real AI callback, alert persistence and worker-A WebSocket delivery', 'real models, HTTPS callback, database and socket', async () => {
    const attack = samples.find(sample => decisions.find(d => d.row === sample.provenance.rowIndex && d.action === 'BLOCK'))
    assert(attack, 'No genuine BLOCK sample found')
    const before = await db.collection('aipredictions').countDocuments()
    const response = await request('/predict', { direct: 'http://127.0.0.1:18000', method: 'POST', body: attack, headers: { 'X-API-Key': credentials.SENTINEL_KEY } }); assert(response.status === 200, 'Real notification inference failed')
    await wait(async () => (await db.collection('aipredictions').countDocuments()) === before + 1, 15000, 'AI callback did not persist')
    assert(await db.collection('alerts').countDocuments() > 0, 'No alert persisted')
    await wait(() => delivered.includes('new_threat') && delivered.includes('new_alert'), 5000, 'Business events not delivered')
    return { events: [...new Set(delivered)], callbackPredictionDelta: 1, enforcement: 'not performed' }
  })
  await check('Actual AI invalid/nonfinite/malformed input and optional defaults', 'real AI HTTP validation', async () => {
    for (const raw of ['{"flow_duration":NaN}', '{"flow_duration":Infinity}', '{"flow_duration":"bad"}', '{"flow_duration":[]}', '{']) {
      const response = await request('/predict/eval', { direct: 'http://127.0.0.1:18000', method: 'POST', raw, headers: { 'X-API-Key': credentials.SENTINEL_KEY } }); assert(response.status === 422 && !response.text.includes('"input"'), 'Invalid input was not sanitized 422')
    }
    assert((await request('/predict/eval', { direct: 'http://127.0.0.1:18000', method: 'POST', body: {}, headers: { 'X-API-Key': credentials.SENTINEL_KEY } })).status === 200, 'Optional defaults changed')
  })
  await check('IST metadata and real MongoDB boundary grouping', 'real database aggregation, labeled reporting fixtures', async () => {
    const time = require('../backend/utils/reportingTime')
    for (const now of ['2026-01-01T00:00:00Z', '2024-02-29T00:00:00Z', '2026-10-14T18:29:59.999Z', '2026-10-14T18:30:00Z']) {
      const range = time.filter(1, new Date(now)), week = time.filter(7, new Date(now)), marker = 'reporting-fixture-' + crypto.randomUUID()
      const instants = [new Date(range.$gte.getTime() - 1), range.$gte, new Date(range.$gte.getTime() + 1800000), new Date(range.$lt.getTime() - 1), range.$lt, new Date(range.$lt.getTime() + 1)]
      await db.collection('native_reporting_fixtures').insertMany(instants.map(createdAt => ({ marker, createdAt, acceptanceTest: true, category: 'synthetic boundary regression; not telemetry' })))
      const grouped = await db.collection('native_reporting_fixtures').aggregate([{ $match: { marker, createdAt: range } }, { $group: { _id: time.hourGroup(), count: { $sum: 1 } } }, { $sort: { _id: 1 } }]).toArray()
      assert(grouped.reduce((n, group) => n + group.count, 0) === 3, 'IST half-open bounds mismatch')
      assert(week.$lt - week.$gte === 7 * 86400000 && grouped[0]._id === 0 && grouped[grouped.length - 1]._id === 23, 'IST hour or seven-day mismatch')
    }
    for (const route of ['/api/threats/analytics/summary', '/api/threats/vector-trend', '/api/ai/stats', '/api/honeypot/analytics']) {
      const response = await request(route, { headers: { Authorization: 'Bearer ' + modelUser.token } })
      assert(response.status === 200, 'Analytics route unavailable: ' + route)
      assert(JSON.stringify(response.data).includes('Asia/Kolkata'), 'Analytics timezone missing: ' + route)
    }
    return { intervals: 4, fixtureCollection: 'native_reporting_fixtures', storedUTCInstants: true, futurePolicy: 'Calendar-day range includes later instants within today; excludes next day' }
  })
  await browserChecks(db)
  await check('AI outage and recovery leave persisted data intact', 'real owned AI process outage', async () => {
    await stop(ai)
    assert((await request('/health')).status === 503, 'Missing AI did not fail readiness')
    assert((await request('/api/ai/analyze', { method: 'POST', body: samples[0], headers: { Authorization: 'Bearer ' + modelUser.token } })).status === 503, 'Missing AI prediction claimed success')
    assert((await request('/api/threats', { headers: { Authorization: 'Bearer ' + modelUser.token } })).status === 200, 'Persisted read unavailable during AI outage')
    startAI(); await wait(async () => (await request('/health')).status === 200, 180000, 'AI did not recover')
  })
  await check('Shared MongoDB outage disconnects remote sockets and denies authorization; recovery', 'real replica-set outage and two API processes', async () => {
    const user = await account('database-outage'); const socket = await connect(user.token)
    const detail = await revoked(socket, async () => { try { await admin.db('admin').command({ shutdown: 1 }) } catch {} await wait(() => mongo.exitCode !== null || mongo.signalCode, 10000, 'Owned MongoDB did not stop') }, 4500)
    assert((await me(user.token)).status === 503, 'Database outage did not fail auth closed')
    assert((await mutation(user, 'logout')).status === 503, 'Logout falsely confirmed during outage')
    startMongo(); await wait(async () => (await request('/health', { worker: 'B' })).status === 200, 45000, 'Shared revocation did not recover')
    assert((await me(user.token)).status === 200, 'Fresh authorization did not recover')
    const fresh = await connect(user.token); fresh.disconnect(); return { ...detail, outageAuthStatus: 503, recovered: true }
  })
  evidence('collection-counts.json', await Promise.all((await db.listCollections().toArray()).map(async collection => ({ collection: collection.name, records: await db.collection(collection.name).countDocuments() }))))
}
async function analyticsChecks(db, token) {
  await check('Actual analytics and WebSocket counters match their reported UTC ranges and IST grouping', 'real persisted model records, MongoDB aggregation and socket', async () => {
    const headers = { Authorization: 'Bearer ' + token }
    const threat = (await request('/api/threats/analytics/summary', { headers })).data.data
    const range = metadata => ({ $gte: new Date(metadata.rangeStart), $lt: new Date(metadata.rangeEnd) })
    const counted = await db.collection('threatlogs').countDocuments({ createdAt: range(threat.reporting.today) })
    assert(threat.kpis.totalToday === counted && threat.charts.hourlyToday.reduce((sum, hour) => sum + hour.count, 0) === counted, 'Dashboard range/chart totals mismatch')
    const grouped = await db.collection('threatlogs').aggregate([{ $match: { createdAt: range(threat.reporting.today) } }, { $group: { _id: { $hour: { date: '$createdAt', timezone: 'Asia/Kolkata' } }, count: { $sum: 1 } } }]).toArray()
    assert(grouped.every(group => threat.charts.hourlyToday[group._id].count === group.count), 'Actual IST hours disagree')
    const aiStats = (await request('/api/ai/stats', { headers })).data.data
    assert(aiStats.summary.weekPredictions === await db.collection('aipredictions').countDocuments({ createdAt: range(aiStats.reporting.sevenDay) }), 'AI seven-day metadata mismatch')
    const honeypot = (await request('/api/honeypot/analytics', { headers })).data.data
    assert(honeypot.kpis.totalToday === await db.collection('honeypotsessions').countDocuments({ createdAt: range(honeypot.reporting.today) }), 'Honeypot counter metadata mismatch')
    const socket = await connect(token, 'A')
    const snapshot = new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Stats snapshot unavailable')), 5000); socket.once('stats_snapshot', data => { clearTimeout(timer); resolve(data) }) })
    socket.emit('request_stats'); const stats = await snapshot
    assert(stats.totalToday === await db.collection('threatlogs').countDocuments({ createdAt: range(stats.reporting) }) && stats.reporting.timeZone === 'Asia/Kolkata', 'Socket UTC bounds mismatch')
    socket.disconnect()
    evidence('analytics-consistency.json', { threatToday: counted, hourlyGroups: grouped, aiSevenDays: aiStats.summary.weekPredictions, honeypotToday: honeypot.kpis.totalToday, websocketToday: stats.totalToday, reporting: threat.reporting })
    return { threatToday: counted, aiSevenDays: aiStats.summary.weekPredictions, honeypotToday: honeypot.kpis.totalToday, fixtureWrites: false }
  })
}
async function browserChecks(db) {
  const puppeteer = require('../backend/node_modules/puppeteer-core')
  browser = await puppeteer.launch({ headless: true, pipe: true, protocolTimeout: 60000, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe', userDataDir: path.join(storage, 'browser-' + Date.now()), args: ['--no-first-run', '--disable-background-networking', '--disable-gpu', '--ignore-certificate-errors-spki-list=' + credentials.spki] })
  const browserProcess = browser.process()
  owned.push({ name: 'Chrome browser', executable: browserProcess.spawnfile, args: browserProcess.spawnargs.slice(1), process: browserProcess, output: () => '' })
  evidence('browser-ownership.json', { pid: browserProcess.pid, parentPid: process.pid, cdpTransport: 'owned pipes; no DevTools TCP listener', profile: browserProcess.spawnargs.find(arg => arg.startsWith('--user-data-dir=')), certificateTrust: 'dedicated leaf SPKI only' })
  let user = await account('browser')
  let page = await browser.newPage(); await page.emulateTimezone('UTC')
  let errors = 0; page.on('pageerror', () => errors++)
  await page.evaluateOnNewDocument(() => { localStorage.setItem('sentinel_token', 'legacy-test-fixture'); localStorage.setItem('sentinel_refresh', 'legacy-test-fixture'); localStorage.setItem('sentinel_user', '{}') })
  async function signin(target) {
    await target.goto(origin + '/login', { waitUntil: 'networkidle2' })
    await target.waitForSelector('input[type=email]'); await target.type('input[type=email]', user.email); await target.type('input[type=password]', user.password)
    await target.click('button'); await target.waitForFunction(() => location.pathname === '/dashboard', { timeout: 15000 })
  }
  await check('HTTPS actual frontend sign-in, legacy cleanup, secure cookies, reload and real dashboard/logs', 'real Chrome, HTTPS, API and database', async () => {
    await signin(page)
    const clean = await page.evaluate(() => !['sentinel_token', 'sentinel_refresh', 'sentinel_user'].some(key => localStorage.getItem(key)))
    assert(clean, 'Legacy tokens retained')
    const cookie = (await browser.cookies()).find(c => c.name === '__Secure-sentinel_refresh')
    assert(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === 'Strict' && cookie.path === '/api/auth', 'Browser refresh cookie flags mismatch')
    assert(!await page.evaluate(() => document.cookie.includes('sentinel_refresh')), 'HttpOnly cookie visible to JS')
    await page.reload({ waitUntil: 'networkidle2' }); assert(new URL(page.url()).pathname === '/dashboard', 'Reload bootstrap failed')
    await page.screenshot({ path: path.join(runDir, 'dashboard.png'), fullPage: true })
    await page.goto(origin + '/dashboard/threats', { waitUntil: 'networkidle2' }); assert(new URL(page.url()).pathname !== '/login', 'Threat view lost authentication')
    const text = await page.evaluate(() => document.body.innerText)
    assert(text.includes('192.0.2.'), 'Real stored source did not render in threat logs')
    const latest = await db.collection('threatlogs').findOne({}, { sort: { createdAt: -1 } })
    const expectedTime = new Date(latest.createdAt).toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false })
    assert(text.includes(expectedTime), 'Browser UTC locale did not render the stored UTC instant in IST')
    await page.screenshot({ path: path.join(runDir, 'threat-logs.png'), fullPage: true })
    assert(errors === 0, 'Browser runtime exception'); return { chrome: await browser.version(), browserTimezone: 'UTC', applicationReporting: 'Asia/Kolkata', runtimeErrors: errors }
  })
  if (process.argv.includes('--focus-browser') || process.argv.includes('--focus-empty')) await check('Actual browser shows AI Unavailable and empty honeypot state during owned AI outage', 'real Chrome and backend responses; no synthetic telemetry', async () => {
    await page.goto(origin + '/dashboard', { waitUntil: 'networkidle2' })
    await page.waitForFunction(() => document.body.innerText.includes('AI Engine: Unavailable'))
    assert((await request('/health')).status === 503, 'Unavailable AI claimed health')
    await page.screenshot({ path: path.join(runDir, 'ai-unavailable.png'), fullPage: true })
    await page.goto(origin + '/dashboard/honeypot', { waitUntil: 'networkidle2' })
    await page.waitForFunction(() => document.body.innerText.includes('No attacks detected yet'))
    const response = await request('/api/honeypot/sessions', { headers: { Authorization: 'Bearer ' + user.token } })
    assert(response.status === 200 && response.data.data.length === 0 && await db.collection('honeypotsessions').countDocuments() === 0, 'Empty honeypot state did not match backend records')
    await page.screenshot({ path: path.join(runDir, 'honeypot-empty.png'), fullPage: true })
  })
  if (process.argv.includes('--focus-empty')) { await browser.close(); browser = null; return }
  await check('Actual cross-tab refresh serialization and browser logout-all', 'real Chrome tabs, cookie rotation and database', async () => {
    const second = await browser.newPage(); await second.goto(origin + '/dashboard', { waitUntil: 'networkidle2' })
    const before = await db.collection('authsessions').find({ user: new ObjectId(user.id), revokedAt: null }).toArray()
    await Promise.all([page.reload({ waitUntil: 'networkidle2' }), second.reload({ waitUntil: 'networkidle2' })])
    const after = await db.collection('authsessions').find({ user: new ObjectId(user.id), revokedAt: null }).toArray()
    assert(after.length >= 1 && after.some(s => before.some(old => old._id === s._id && s.generation >= old.generation + 2)), 'Cross-tab refresh did not rotate safely')
    await page.goto(origin + '/dashboard', { waitUntil: 'networkidle2' })
    await page.waitForFunction(() => [...document.querySelectorAll('button')].some(button => button.textContent.toLowerCase().includes('logout all sessions')))
    await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.toLowerCase().includes('logout all sessions')).click())
    await wait(async () => new URL(second.url()).pathname === '/login', 10000, 'Other tab did not logout')
    await wait(async () => (await db.collection('authsessions').countDocuments({ user: new ObjectId(user.id), revokedAt: null })) === 0 && !await page.evaluate(() => localStorage.getItem('sentinel_logout_pending')), 12000, 'Browser logout-all left active sessions or was unconfirmed')
    await second.close()
  })
  await check('Actual browser short-lived access expiry refresh and socket renewal', 'real Chrome; explicitly signed short-expiry fixture', async () => {
    await page.close()
    const isolated = await browser.createBrowserContext()
    page = await isolated.newPage()
    user = await account('browser-short-expiry')
    const cdp = await page.createCDPSession(); let shortened = false, refreshed = 0, socketConnections = 0
    await cdp.send('Network.enable')
    cdp.on('Network.webSocketCreated', () => socketConnections++)
    page.on('response', response => { if (response.url().endsWith('/auth/refresh-token') && response.status() === 200) refreshed++ })
    await page.setRequestInterception(true)
    const intercept = async intercepted => {
      if (!intercepted.url().endsWith('/api/auth/login')) { await intercepted.continue(); return }
      try {
        const reply = await request('/api/auth/login', { method: 'POST', raw: intercepted.postData(), headers: { ...intercepted.headers(), 'accept-encoding': 'identity' } })
        const parsed = reply.data
        if (reply.status === 200 && parsed.data?.token) { const claims = jwt.decode(parsed.data.token); claims.exp = Math.floor(Date.now() / 1000) + 1; parsed.data.token = jwt.sign(claims, credentials.JWT_SECRET, { algorithm: 'HS256' }); shortened = true }
        const headers = { ...reply.headers }; for (const name of ['content-length', 'content-encoding', 'transfer-encoding']) delete headers[name]
        await intercepted.respond({ status: reply.status, headers, contentType: 'application/json', body: JSON.stringify(parsed) })
      } catch { await intercepted.abort('failed').catch(() => {}) }
    }
    page.on('request', intercept)
    await signin(page); await wait(() => shortened && refreshed > 0 && socketConnections >= 2, 12000, 'Frontend did not refresh short expiry and renew socket')
    page.off('request', intercept); await page.setRequestInterception(false); await cdp.detach()
    await delay(2500); assert(new URL(page.url()).pathname === '/dashboard', 'Expiry lost authenticated UI')
    return { shortenedResponseFixture: true, realRefreshResponses: refreshed, observedSocketConnections: socketConnections, productionAccessSeconds: 900 }
  })
  await check('Browser unconfirmed logout remains signed out and pending until retry', 'real Chrome with explicit network-failure injection', async () => {
    await page.setRequestInterception(true)
    const intercept = request => request.url().endsWith('/auth/logout') ? request.abort('failed') : request.continue()
    page.on('request', intercept)
    await page.evaluate(() => [...document.querySelectorAll('button')].find(button => button.textContent.trim() === 'Logout').click())
    await wait(async () => new URL(page.url()).pathname === '/login', 10000, 'Logout did not clear local state')
    const pending = await page.evaluate(() => localStorage.getItem('sentinel_logout_pending') !== null)
    assert(pending, 'Failed logout was falsely confirmed')
    page.off('request', intercept); await page.setRequestInterception(false)
    await page.reload({ waitUntil: 'networkidle2' })
    await wait(async () => !await page.evaluate(() => localStorage.getItem('sentinel_logout_pending')), 12000, 'Pending logout retry did not complete')
    assert(new URL(page.url()).pathname === '/login', 'Unconfirmed logout silently signed back in')
  })
  await browser.close(); browser = null
}
main().catch(error => { console.log('SETUP/RUN BLOCKER: ' + sanitize(error.message)); process.exitCode = 1; if (runDir) evidence('blocker.json', { status: 'BLOCKED', error: sanitize(error.message) }) }).finally(async () => {
  for (const socket of sockets) socket.disconnect()
  if (browser) await browser.close().catch(() => {})
  for (const item of [...owned].reverse()) if (item.process !== mongo) await stop(item.process).catch(() => {})
  if (admin) { try { await admin.db('admin').command({ shutdown: 1 }) } catch {} }
  await appDB?.close().catch(() => {}); await admin?.close().catch(() => {})
  await stop(mongo).catch(() => {})
  const keyFile = path.join(storage, 'runtime/replica-keyfile')
  if (credentials && fs.existsSync(keyFile) && (!mongo || mongo.exitCode !== null || mongo.signalCode)) fs.unlinkSync(keyFile)
  if (runDir) {
    for (let index = 0; index < owned.length; index++) evidence('process-' + index + '.log', owned[index].output())
    const closed = []; for (const port of ports) { try { await freePort(port); closed.push(port) } catch {} }
    evidence('shutdown.json', { approvedPorts: ports, closedPorts: closed, ownedProcesses: owned.map(item => ({ name: item.name, pid: item.process.pid, exitCode: item.process.exitCode, signal: item.process.signalCode })), keyfileRemoved: !fs.existsSync(keyFile) })
    assert(closed.length === ports.length, 'Approved owned listener remains open')
    console.log(JSON.stringify({ passed: results.filter(r => r.status === 'PASS').length, failed: results.filter(r => r.status === 'FAIL').length, evidence: runDir, ownedPortsClosed: closed.length }))
  }
  agent?.destroy()
}).catch(() => { process.exitCode = 1; console.log('Owned shutdown verification failed; inspect sanitized evidence') })
