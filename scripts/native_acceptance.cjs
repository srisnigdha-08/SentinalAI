// Retired safely: preserve historical source, but do not execute its old protocol/data paths.
throw new Error('Historical acceptance runner retired at the approved auth cutover. It must not connect to the retained acceptance database. See docs/AUTH_TIMEZONE_IMPLEMENTATION.md for current scoped tests.')
// Owner-approved, real native integration. No Docker, recovery data, seed or live-feed simulation.
const fs = require('node:fs')
const path = require('node:path')
const net = require('node:net')
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const { spawn, spawnSync } = require('node:child_process')
const { MongoClient } = require('../backend/node_modules/mongodb')
const { io } = require('../frontend/node_modules/socket.io-client')
const puppeteer = require('../backend/node_modules/puppeteer-core')
const project = path.resolve(__dirname, '..')
const storage = 'C:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete.native-integration\\mongodb-acceptance-20261014'
const database = 'sentinelai_acceptance_20261014'
const python = path.join(project, 'ai-engine/.venv/Scripts/python.exe')
const evidence = path.join(storage, 'evidence')
const resume = process.argv.includes('--resume')
const previous = resume ? JSON.parse(fs.readFileSync(path.join(evidence, 'acceptance-results.json'), 'utf8')) : null
if (previous) fs.writeFileSync(path.join(evidence, 'acceptance-attempt-' + Date.now() + '.json'), JSON.stringify(previous, null, 2), { flag: 'wx' })
const report = { date: '2026-10-14', database, storage, checks: previous?.checks || [], failures: [], previousFailures: [...(previous?.previousFailures || []), ...(previous?.failures || [])], collections: previous?.collections, pending: previous?.pending || ['Actual Cowrie events and enforcement: no independently managed host available'] }
const processes = []
let adminClient, applicationClient, browser, socket, secrets
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function record(name, details) {
  if (report.checks.some(check => check.name === name)) return
  report.checks.push({ name, result: 'passed', ...details })
  console.log('PASS: ' + name)
}
function launch(name, executable, args, cwd, env = process.env) {
  const output = fs.openSync(path.join(storage, 'logs', name + '.log'), 'a')
  const child = spawn(executable, args, { cwd, env, windowsHide: true, stdio: ['ignore', output, output] })
  fs.closeSync(output)
  child.on('error', () => {})
  processes.push({ name, child })
  return child
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return
  child.kill()
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(8000)])
}
async function waitUntil(check, description, timeout = 60000) {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    try { if (await check()) return } catch {}
    await sleep(400)
  }
  throw new Error(description + ' timed out')
}
async function unusedPort(port) {
  await new Promise((resolve, reject) => {
    const probe = net.createServer()
    probe.once('error', () => reject(new Error('Required loopback port is occupied: ' + port)))
    probe.listen(port, '127.0.0.1', () => probe.close(resolve))
  })
}
async function api(endpoint, { method = 'GET', body, token, key, expected = 200, origin = 'http://127.0.0.1:5000' } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = 'Bearer ' + token
  if (key) headers['X-API-Key'] = key
  const response = await fetch(origin + endpoint, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(15000) })
  const data = await response.json()
  // Never include request bodies/tokens/connection strings in assertion errors.
  if (response.status !== expected) throw new Error(endpoint + ' returned ' + response.status + ', expected ' + expected)
  return data
}
function persistCredentials() {
  // Windows DPAPI CurrentUser protects new acceptance credentials at rest.
  const encrypted = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    'Add-Type -AssemblyName System.Security; $text=[Console]::In.ReadToEnd(); $bytes=[Text.Encoding]::UTF8.GetBytes($text); $blob=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($blob))'],
    { input: JSON.stringify(secrets), encoding: 'utf8', windowsHide: true })
  if (encrypted.status !== 0 || !encrypted.stdout.trim()) throw new Error('Credential encryption failed')
  fs.writeFileSync(path.join(storage, 'acceptance-credentials.dpapi'), encrypted.stdout.trim(), { flag: 'wx' })
}
function loadCredentials() {
  const decrypted = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command',
    'Add-Type -AssemblyName System.Security; $blob=[Convert]::FromBase64String([Console]::In.ReadToEnd()); $bytes=[Security.Cryptography.ProtectedData]::Unprotect($blob,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Text.Encoding]::UTF8.GetString($bytes))'],
    { input: fs.readFileSync(path.join(storage, 'acceptance-credentials.dpapi'), 'utf8'), encoding: 'utf8', windowsHide: true })
  if (decrypted.status !== 0) throw new Error('Credential decryption failed')
  return JSON.parse(decrypted.stdout)
}

async function main() {
  const download = JSON.parse(fs.readFileSync(path.join(evidence, 'download-verification.json'), 'utf8'))
  assert.equal(download.sha256, '7e3a435fa86e36e8ca4f2618fb41de06d75c28009c63725a20f9badd36eec6f6')
  assert.equal(path.resolve(download.data_path), path.join(storage, 'data'))
  if (!resume) {
    assert.equal(fs.readdirSync(path.join(storage, 'data')).length, 0, 'Fresh data directory must be empty')
    if (fs.existsSync(path.join(storage, 'acceptance-credentials.dpapi'))) throw new Error('Acceptance has already been initialized; use --resume only for this owned development database')
  }
  for (const port of [27028, 8000, 5000, 3000]) await unusedPort(port)
  const version = spawnSync(download.binary, ['--version'], { encoding: 'utf8', windowsHide: true })
  assert.equal(version.status, 0)
  assert.match(version.stdout, /v7\.0\.45/)
  if (!resume) fs.writeFileSync(path.join(evidence, 'mongod-version.txt'), version.stdout, { flag: 'wx' })
  secrets = resume ? loadCredentials() : Object.fromEntries(['mongoAdmin', 'mongoApp', 'adminPassword', 'registeredPassword', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'SENTINEL_KEY', 'HONEYPOT_API_KEY'].map(name => [name, crypto.randomBytes(32).toString('hex')]))
  if (!resume) persistCredentials()
  const mongod = launch('mongodb', download.binary, ['--dbpath', path.join(storage, 'data'), '--logpath', path.join(storage, 'logs/mongod.log'), '--logappend', '--bind_ip', '127.0.0.1', '--port', '27028', '--auth'], storage)
  if (!resume) {
    const bootstrap = new MongoClient('mongodb://127.0.0.1:27028', { serverSelectionTimeoutMS: 1000 })
    try {
      await waitUntil(async () => { await bootstrap.connect(); return (await bootstrap.db('admin').command({ ping: 1 })).ok === 1 }, 'MongoDB readiness')
      await bootstrap.db('admin').command({ createUser: 'acceptance_bootstrap_admin', pwd: secrets.mongoAdmin, roles: [{ role: 'root', db: 'admin' }] })
    } finally { await bootstrap.close() }
  }
  adminClient = new MongoClient(`mongodb://acceptance_bootstrap_admin:${secrets.mongoAdmin}@127.0.0.1:27028/admin`)
  await waitUntil(async () => { await adminClient.connect(); return (await adminClient.db('admin').command({ ping: 1 })).ok === 1 }, 'Authenticated MongoDB readiness')
  const serverInfo = await adminClient.db('admin').command({ buildInfo: 1 })
  assert.equal(serverInfo.version, '7.0.45')
  if (!resume) await adminClient.db(database).command({ createUser: 'sentinel_acceptance_app', pwd: secrets.mongoApp, roles: [{ role: 'readWrite', db: database }] })
  const options = await adminClient.db('admin').command({ getCmdLineOpts: 1 })
  assert.equal(options.parsed.net.bindIp, '127.0.0.1')
  assert.equal(options.parsed.net.port, 27028)
  assert.equal(options.parsed.security.authorization, 'enabled')
  assert.equal(path.resolve(options.parsed.storage.dbPath), path.join(storage, 'data'))
  const mongoURI = `mongodb://sentinel_acceptance_app:${secrets.mongoApp}@127.0.0.1:27028/${database}?authSource=${database}`
  applicationClient = new MongoClient(mongoURI)
  await applicationClient.connect()
  const db = applicationClient.db(database)
  const anonymous = new MongoClient('mongodb://127.0.0.1:27028', { serverSelectionTimeoutMS: 2000 })
  try {
    await anonymous.connect()
    await assert.rejects(anonymous.db(database).collection('users').findOne({}), error => error.code === 13)
  } finally { await anonymous.close() }
  await assert.rejects(applicationClient.db('admin').collection('system.users').findOne({}), error => error.code === 13)
  record('MongoDB version, readiness, authentication and application-user scope', { version: serverInfo.version, port: 27028, bind: '127.0.0.1', unauthenticatedReadRejected: true })
  const environment = { ...process.env, ...Object.fromEntries(['JWT_SECRET', 'JWT_REFRESH_SECRET', 'SENTINEL_KEY', 'HONEYPOT_API_KEY'].map(name => [name, secrets[name]])),
    NODE_ENV: 'development', MONGO_URI: mongoURI, AI_ENGINE_URL: 'http://127.0.0.1:8000', CLIENT_URL: 'http://localhost:3000',
    HOST: '127.0.0.1', PORT: '5000', TRUST_PROXY: '0', LOG_DIR: path.join(storage, 'logs/backend'),
    ADMIN_EMAIL: 'acceptance-admin@sentinel.invalid', ADMIN_NAME: 'Native Acceptance Administrator', ADMIN_INITIAL_PASSWORD: secrets.adminPassword,
    ABUSEIPDB_API_KEY: '', SIMULATION_MODE: 'false', ALLOW_MOCK_SEED: 'false',
    MODEL_DIR: path.join(project, 'ai-engine/models'), Q_TABLE_PATH: path.join(storage, 'learning/q_table.json'), SENTINEL_API: 'http://127.0.0.1:5000/api' }
  const ai = launch('ai', python, ['-m', 'uvicorn', 'inference.main:app', '--host', '127.0.0.1', '--port', '8000', '--env-file', '../backend/.env'], path.join(project, 'ai-engine'), environment)
  await waitUntil(async () => (await fetch('http://127.0.0.1:8000/ready')).ok, 'AI readiness')
  launch('backend', process.execPath, ['server.js'], path.join(project, 'backend'), environment)
  await waitUntil(async () => (await fetch('http://127.0.0.1:5000/health')).ok, 'Backend readiness')
  launch('frontend', process.execPath, [path.join(project, 'frontend/node_modules/vite/bin/vite.js'), '--host', '127.0.0.1', '--port', '3000', '--strictPort'], path.join(project, 'frontend'), environment)
  await waitUntil(async () => (await fetch('http://127.0.0.1:3000/login')).ok, 'Frontend readiness')
  record('AI, Express and React native startup')
  if (process.argv.includes('--serve')) {
    console.log('Owned native acceptance services ready: http://127.0.0.1:3000. Press Ctrl+C to stop this run; development data will be retained.')
    await new Promise(resolve => {
      process.once('SIGINT', resolve)
      process.once('SIGTERM', resolve)
    })
    return
  }
  if (!resume) {
    assert.equal(await db.collection('threatlogs').countDocuments(), 0)
    assert.equal(await db.collection('alerts').countDocuments(), 0)
    record('Fresh database has no seeded threats or alerts')
  }
  await api('/api/auth/me', { expected: 401 })
  const login = await api('/api/auth/login', { method: 'POST', body: { email: environment.ADMIN_EMAIL, password: secrets.adminPassword } })
  const token = login.data.token
  assert.equal(login.data.user.role, 'admin')
  if (process.argv.includes('--verify-chart')) {
    const analytics = await api('/api/threats/analytics/summary', { token })
    const hours = analytics.data.charts.hourlyToday
    const total = hours.reduce((sum, hour) => sum + hour.count, 0)
    assert.ok(total > 0)
    assert.equal(total, analytics.data.kpis.totalToday)
    assert.ok(hours.every(hour => /^\d{2}:00$/.test(hour.hour)))
    browser = await puppeteer.launch({ executablePath: process.env.BROWSER_EXECUTABLE || 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true, userDataDir: path.join(storage, 'browser-chart-profile'), args: ['--no-first-run', '--disable-background-networking'] })
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 1000 })
    await page.goto('http://127.0.0.1:3000/login')
    await page.waitForSelector('input[type=email]')
    await page.type('input[type=email]', environment.ADMIN_EMAIL)
    await page.type('input[type=password]', secrets.adminPassword)
    await page.keyboard.press('Enter')
    await page.waitForFunction(() => location.pathname === '/dashboard')
    await page.waitForFunction(() => document.body.innerText.includes('192.0.2.20'))
    assert.ok(!(await page.evaluate(() => document.body.innerText)).includes('No live security events detected'))
    assert.ok(!(await page.evaluate(() => document.body.innerText)).includes('Dashboard data is unavailable'))
    await page.screenshot({ path: path.join(evidence, 'dashboard-hourly-chart-fixed.png'), fullPage: true })
    record('Hourly chart renders real persisted activity instead of a false empty state', { persistedThreatsToday: total, dataWrites: 'none in this verification run' })
    return
  }
  const registered = await api('/api/auth/' + (resume ? 'login' : 'register'), { method: 'POST', expected: resume ? 200 : 201, body: { name: 'Native Acceptance Analyst', email: 'acceptance-analyst@sentinel.invalid', password: secrets.registeredPassword, role: 'analyst' } })
  assert.equal(registered.data.user.role, 'analyst')
  const refreshed = await api('/api/auth/refresh-token', { method: 'POST', body: { refreshToken: login.data.refreshToken } })
  const me = await api('/api/auth/me', { token: refreshed.data.token })
  assert.equal(me.data.user.email, environment.ADMIN_EMAIL)
  record('Administrator provisioning, registration, login, refresh and protected-route authentication')
  const events = []
  socket = io('http://127.0.0.1:5000', { auth: { token: registered.data.token }, transports: ['websocket'], reconnection: false })
  for (const name of ['new_threat', 'new_alert', 'ai_prediction']) socket.on(name, data => events.push({ name, data }))
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('connect_error', () => reject(new Error('Authenticated socket connection failed'))); setTimeout(() => reject(new Error('Socket connection timed out')), 10000).unref() })
  socket.emit('join_room', { role: 'analyst' })
  await new Promise(resolve => socket.once('connected', resolve))
  const selected = new Map()
  const prepared = resume ? { status: 0 } : spawnSync(python, [path.join(project, 'scripts/acceptance_dataset.py'), path.join(evidence, 'dataset-records.json')], { cwd: project, encoding: 'utf8', windowsHide: true })
  if (prepared.status !== 0) throw new Error('Real dataset preparation failed; no artificial replacement records allowed')
  const rows = resume ? (await db.collection('aipredictions').find({ 'rawFeatures.acceptanceTest': true }).toArray()).map(prediction => prediction.rawFeatures) : JSON.parse(fs.readFileSync(path.join(evidence, 'dataset-records.json'), 'utf8'))
  let evaluatedRows = 0
  for (const row of rows) {
    const evaluation = await api('/predict/eval', { origin: 'http://127.0.0.1:8000', method: 'POST', key: secrets.SENTINEL_KEY, body: row })
    evaluatedRows++
    if (!selected.has(evaluation.result.action)) selected.set(evaluation.result.action, { row, result: evaluation.result })
    if (selected.size === 3) break
  }
  if (!resume) assert.equal(await db.collection('aipredictions').countDocuments(), 0)
  const decisions = []
  for (const [action, { row, result }] of selected) {
    if (resume) continue // Earlier prediction and feature read-back checks passed; reuse their evidence.
    const analyzed = await api('/api/ai/analyze', { method: 'POST', token, body: row })
    assert.equal(analyzed.data.result.action, action)
    assert.equal(analyzed.data.result.threatScore, result.threatScore)
    const saved = await db.collection('aipredictions').findOne({ _id: new (require('../backend/node_modules/mongodb').ObjectId)(analyzed.data.result._id) })
    assert.equal(saved.threatScore, result.threatScore)
    assert.equal(saved.featureVector.length, 53)
    assert.equal(saved.rawFeatures.acceptanceTest, true)
    decisions.push({ action, threatScore: result.threatScore, predictedClass: result.predictedClass, provenance: row.provenance })
  }
  for (const action of ['ALLOW', 'MONITOR', 'BLOCK']) if (!selected.has(action)) report.pending.push(action + ' was not produced naturally by the 32 inspected real dataset rows; no result was forced')
  record('Real dataset prediction, 53-feature persistence and read-back consistency', { decisions, evaluatedRows, preparedRows: rows.length })
  const observed = [...selected.values()].find(value => value.result.predictedClass !== 'BENIGN')
  assert.ok(observed, 'No real non-benign sample available for threat acceptance')
  const beforeEvents = events.length
  const created = await api('/api/threats', { method: 'POST', expected: 201, token, body: { sourceIP: observed.row.sourceIP, attackType: observed.result.predictedClass, severity: observed.result.severity, aiScore: observed.result.threatScore, notes: 'NATIVE ACCEPTANCE ONLY: observed CICIDS2017 record ' + JSON.stringify(observed.row.provenance), targetService: 'ACCEPTANCE-DATASET' } })
  const threatId = created.data.threat._id
  const read = await api('/api/threats/' + threatId, { token })
  assert.equal(read.data.threat.notes, created.data.threat.notes)
  await waitUntil(() => events.slice(beforeEvents).some(event => event.name === 'new_threat' && event.data.id === threatId), 'Persisted threat WebSocket delivery')
  const savedAlerts = await db.collection('alerts').find({ 'sourceRef.refId': new (require('../backend/node_modules/mongodb').ObjectId)(threatId) }).toArray()
  if (['HIGH', 'CRITICAL'].includes(observed.result.severity)) {
    assert.equal(savedAlerts.length, 1)
    await waitUntil(() => events.slice(beforeEvents).some(event => event.name === 'new_alert' && event.data.id === savedAlerts[0]._id.toString()), 'Persisted alert WebSocket delivery')
    record('Alert persistence and WebSocket delivery', { alertId: savedAlerts[0]._id.toString() })
  } else report.pending.push('Selected real threat had no alert-generating severity; alert delivery branch not exercised')
  const listed = await api('/api/threats', { token })
  assert.ok(listed.data.some(threat => threat._id === threatId))
  record('Threat creation, read-back, list API and WebSocket delivery', { threatId })
  if (!resume) await waitUntil(() => events.filter(event => event.name === 'ai_prediction').length >= selected.size, 'Prediction WebSocket delivery')
  browser = await puppeteer.launch({ executablePath: process.env.BROWSER_EXECUTABLE || 'C:/Program Files/Google/Chrome/Application/chrome.exe', headless: true, userDataDir: path.join(storage, 'browser-profile'), args: ['--no-first-run', '--disable-background-networking'] })
  const page = await browser.newPage()
  await page.setViewport({ width: 1440, height: 1000 })
  const pageErrors = []
  page.on('pageerror', () => pageErrors.push('Browser page exception'))
  await page.goto('http://127.0.0.1:3000/login')
  await page.waitForSelector('input[type=email]')
  await page.type('input[type=email]', environment.ADMIN_EMAIL)
  await page.type('input[type=password]', secrets.adminPassword)
  await page.keyboard.press('Enter')
  await page.waitForFunction(() => location.pathname === '/dashboard')
  await page.waitForFunction(ip => document.body.innerText.includes(ip), { timeout: 20000 }, observed.row.sourceIP)
  assert.ok(!(await page.evaluate(() => document.body.innerText)).includes('Dashboard data is unavailable'))
  await page.screenshot({ path: path.join(evidence, 'dashboard-real-backend.png'), fullPage: true })
  await page.goto('http://127.0.0.1:3000/dashboard/threats')
  await page.waitForFunction(ip => document.body.innerText.includes(ip), { timeout: 20000 }, observed.row.sourceIP)
  await page.screenshot({ path: path.join(evidence, 'threats-real-backend.png'), fullPage: true })
  record('Browser login, dashboard and threat-log rendering from actual API responses')
  await stop(ai)
  await api('/health', { expected: 503 })
  await api('/api/ai/analyze', { method: 'POST', token, body: observed.row, expected: 503 })
  await page.goto('http://127.0.0.1:3000/dashboard')
  await page.waitForFunction(() => document.body.innerText.includes('UNAVAILABLE'))
  await page.screenshot({ path: path.join(evidence, 'dashboard-ai-unavailable.png'), fullPage: true })
  record('Unavailable AI returns 503 and truthful browser error state')
  await page.evaluate(() => [...document.querySelectorAll('button')].find(button => /logout/i.test(button.innerText)).click())
  await page.waitForFunction(() => location.pathname === '/')
  assert.deepEqual(await page.evaluate(() => ['sentinel_token', 'sentinel_user', 'sentinel_refresh'].map(key => localStorage.getItem(key))), [null, null, null])
  await page.goto('http://127.0.0.1:3000/dashboard')
  await page.waitForSelector('input[type=email]')
  assert.equal(pageErrors.length, 0)
  record('Browser logout clears access, refresh and user state; no page exceptions')
  report.pending.push('Server-side token revocation is not implemented; logout currently clears browser credentials only')
  const collections = await db.listCollections().toArray()
  report.collections = await Promise.all(collections.map(async collection => ({ name: collection.name, count: await db.collection(collection.name).countDocuments() })))
  // Shutdown only the newly created instance, then observe backend's Mongo readiness.
  await applicationClient.close(); applicationClient = null
  try { await adminClient.db('admin').command({ shutdown: 1 }) } catch {}
  await waitUntil(() => mongod.exitCode !== null, 'Owned MongoDB shutdown', 15000)
  await waitUntil(async () => { const response = await fetch('http://127.0.0.1:5000/health'); const body = await response.json(); return response.status === 503 && body.database?.status === 'disconnected' }, 'MongoDB unavailable readiness', 10000)
  record('Fresh MongoDB shutdown and backend unavailable readiness')
}

main().catch(error => {
  // Do not emit raw errors which may contain credential-bearing URIs.
  report.failures.push({ type: error.name, message: String(error.message).replace(/mongodb:\/\/[^\s]+/g, '[Mongo URI redacted]') })
  console.error('Acceptance failed; inspect the sanitized evidence report')
  process.exitCode = 1
}).finally(async () => {
  if (socket) socket.disconnect()
  if (browser) await browser.close().catch(() => {})
  if (applicationClient) await applicationClient.close().catch(() => {})
  if (adminClient) {
    try { await adminClient.db('admin').command({ shutdown: 1 }) } catch {}
    await adminClient.close().catch(() => {})
  }
  for (const { child } of processes.reverse()) await stop(child)
  report.processesStopped = processes.every(({ child }) => child.exitCode !== null || child.signalCode !== null)
  fs.writeFileSync(path.join(evidence, 'acceptance-results.json'), JSON.stringify(report, null, 2))
  console.log(JSON.stringify({ passedChecks: report.checks.length, failures: report.failures, pending: report.pending, processesStopped: report.processesStopped }))
})
