// Retired safely: preserve historical source, but do not execute its old protocol/data paths.
throw new Error('Pre-cutover defect characterization is historical. Run backend authHardening/reportingTime regressions for the implemented policy; see docs/AUTH_TIMEZONE_IMPLEMENTATION.md.')
// Isolated security characterization. No service startup, MongoDB connection or acceptance-data access.
const fs = require('node:fs')
const path = require('node:path')
const crypto = require('node:crypto')
const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const root = path.resolve(__dirname, '..')
const jwt = require('../backend/node_modules/jsonwebtoken')
const loggerFile = require.resolve('../backend/utils/logger')
require.cache[loggerFile] = { id: loggerFile, filename: loggerFile, loaded: true,
  exports: { info() {}, warn() {}, error() {}, debug() {} } }

async function timezoneProbe() {
  const ThreatLog = require('../backend/models/ThreatLog')
  const threatService = require('../backend/services/threatService')
  const NativeDate = Date
  const instant = NativeDate.parse('2026-10-13T20:00:00.000Z')
  global.Date = class extends NativeDate {
    constructor(...args) { super(...(args.length ? args : [instant])) }
    static now() { return instant }
  }
  const countQueries = []
  const aggregateQueries = []
  ThreatLog.countDocuments = async query => { countQueries.push(query); return 0 }
  ThreatLog.aggregate = async pipeline => { aggregateQueries.push(pipeline); return [] }
  await threatService.getDashboardAnalytics()
  const hourly = aggregateQueries.find(pipeline => pipeline.some(stage => stage.$group?._id?.$hour))
  const weekly = aggregateQueries.find(pipeline => pipeline.some(stage => stage.$group?._id?.$dateToString))
  const hour = hourly.find(stage => stage.$group).$group._id.$hour
  const day = weekly.find(stage => stage.$group).$group._id.$dateToString
  console.log(JSON.stringify({ hostZone: process.env.TZ, instant: new Date().toISOString(),
    currentDayStartUTC: countQueries[0].createdAt.$gte.toISOString(),
    hourlyTimezoneExplicit: typeof hour === 'object' && Boolean(hour.timezone),
    dailyTimezoneExplicit: Boolean(day.timezone),
    unqualifiedClock: new Date().toLocaleTimeString('en-IN', { hour12: false }),
    explicitISTClock: new Date().toLocaleTimeString('en-IN', { hour12: false, timeZone: 'Asia/Kolkata' }),
    currentUTCHour: new Date().getUTCHours(),
    ISTHour: new Date().toLocaleString('en-IN', { hour: '2-digit', hour12: false, timeZone: 'Asia/Kolkata' }) }))
}

async function review() {
  process.env.NODE_ENV = 'test'
  process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex')
  process.env.JWT_REFRESH_SECRET = crypto.randomBytes(32).toString('hex')
  const User = require('../backend/models/User')
  const auth = require('../backend/controllers/authController')
  const { protect } = require('../backend/middleware/auth')
  const results = { date: '2026-10-14', scope: 'Offline characterization; current behavior, not security acceptance',
    controls: [], reproducedFindings: [], sourceFindings: [], dataAccess: 'No database, acceptance storage or original environment files accessed' }
  const user = new User({ name: 'Offline Review User', email: 'offline-review@example.invalid',
    password: 'not-a-persisted-account', role: 'analyst', status: 'active' })
  user.save = async () => user
  user.comparePassword = async () => true
  User.findOne = () => ({ select: async () => user })
  User.findById = () => ({ select: async () => user, then: (resolve, reject) => Promise.resolve(user).then(resolve, reject) })
  function response() {
    return { statusCode: 200, status(code) { this.statusCode = code; return this }, json(body) { this.body = body; return this } }
  }
  async function call(handler, body) {
    const res = response()
    await handler({ body }, res, error => { throw error })
    return res
  }
  const originalNow = Date.now
  const second = Math.floor(originalNow() / 1000)
  Date.now = () => second * 1000 + 100
  try {
    const firstLogin = await call(auth.login, { email: user.email, password: 'offline-input' })
    const secondLogin = await call(auth.login, { email: user.email, password: 'offline-input' })
    assert.equal(firstLogin.statusCode, 200)
    assert.equal(secondLogin.statusCode, 200)
    assert.equal(firstLogin.body.data.refreshToken, secondLogin.body.data.refreshToken)
    results.reproducedFindings.push({ id: 'AUTH-04', name: 'Same-user logins within one second receive identical refresh tokens', confirmed: true })
    const refresh = firstLogin.body.data.refreshToken
    const issuedAccess = jwt.decode(firstLogin.body.data.token)
    const issuedRefresh = jwt.decode(refresh)
    results.currentLifetimesSeconds = { access: issuedAccess.exp - issuedAccess.iat, refresh: issuedRefresh.exp - issuedRefresh.iat }
    const firstRefresh = await call(auth.refreshToken, { refreshToken: refresh })
    const secondRefresh = await call(auth.refreshToken, { refreshToken: refresh })
    assert.equal(firstRefresh.statusCode, 200)
    assert.equal(secondRefresh.statusCode, 200)
    assert.equal(firstRefresh.body.data.refreshToken, undefined)
    results.reproducedFindings.push({ id: 'AUTH-01', name: 'Refresh token replay accepted; no rotated refresh token returned', confirmed: true, observedStatuses: [200, 200] })
    const invalid = jwt.sign({ id: user.id }, 'different-offline-key', { expiresIn: '30d' })
    assert.equal((await call(auth.refreshToken, { refreshToken: invalid })).statusCode, 401)
    results.controls.push('Refresh signed with a different key rejected')
    const expired = jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET, { expiresIn: -1 })
    assert.equal((await call(auth.refreshToken, { refreshToken: expired })).statusCode, 401)
    results.controls.push('Expired refresh rejected')
    user.passwordChangedAt = new Date(second * 1000 + 500)
    assert.equal(user.changedPasswordAfter(second), false)
    assert.equal((await call(auth.refreshToken, { refreshToken: refresh })).statusCode, 200)
    const res = response()
    let authorized = false
    await protect({ headers: { authorization: 'Bearer ' + firstLogin.body.data.token } }, res, () => { authorized = true })
    assert.equal(authorized, true)
    results.reproducedFindings.push({ id: 'AUTH-02', name: 'Same-second password change leaves older access and refresh tokens valid', confirmed: true })
    user.passwordChangedAt = new Date((second + 1) * 1000)
    assert.equal((await call(auth.refreshToken, { refreshToken: refresh })).statusCode, 401)
    results.controls.push('Password change in a later second rejects older refresh')
    user.passwordChangedAt = undefined
    user.status = 'inactive'
    assert.equal((await call(auth.refreshToken, { refreshToken: refresh })).statusCode, 401)
    results.controls.push('Inactive account refresh rejected')
  } finally { Date.now = originalNow }
  const authRoutes = fs.readFileSync(path.join(root, 'backend/routes/auth.js'), 'utf8')
  const server = fs.readFileSync(path.join(root, 'backend/server.js'), 'utf8')
  const sockets = fs.readFileSync(path.join(root, 'backend/websocket/socketManager.js'), 'utf8')
  const frontendAuth = fs.readFileSync(path.join(root, 'frontend/src/context/AuthContext.jsx'), 'utf8')
  const clock = fs.readFileSync(path.join(root, 'frontend/src/components/StatusBar.jsx'), 'utf8')
  assert.ok(!authRoutes.includes("router.post('/logout'"))
  assert.ok(!frontendAuth.includes('authAPI.logout'))
  assert.ok(server.includes('io.use('))
  results.sourceFindings.push({ id: 'AUTH-03', name: 'No server logout/revocation endpoint; browser clears local state only', evidence: ['backend/routes/auth.js', 'frontend/src/context/AuthContext.jsx'] })
  results.sourceFindings.push({ id: 'AUTH-05', name: 'Socket checks at handshake; no expiry timer or session revalidation in current server/socket manager', evidence: ['backend/server.js', 'backend/websocket/socketManager.js'], validation: 'Source review; long-lived expiry not dynamically tested' })
  results.sourceFindings.push({ id: 'AUTH-06', name: 'Bearer access and refresh tokens stored in script-readable localStorage', evidence: ['frontend/src/pages/Login.jsx', 'frontend/src/context/AuthContext.jsx'], validation: 'Source review; XSS exploit not attempted' })
  assert.ok(!clock.includes('timeZone:'))
  results.timezone = []
  for (const zone of ['UTC', 'Asia/Kolkata']) {
    const probe = spawnSync(process.execPath, [__filename, '--timezone-probe'], { cwd: root,
      env: { ...process.env, TZ: zone }, encoding: 'utf8', windowsHide: true })
    if (probe.status !== 0) throw new Error('Isolated timezone probe failed')
    results.timezone.push(JSON.parse(probe.stdout))
  }
  assert.notEqual(results.timezone[0].currentDayStartUTC, results.timezone[1].currentDayStartUTC)
  assert.ok(results.timezone.every(probe => !probe.hourlyTimezoneExplicit && !probe.dailyTimezoneExplicit))
  assert.equal(results.timezone[0].explicitISTClock, results.timezone[1].explicitISTClock)
  assert.notEqual(results.timezone[0].unqualifiedClock, results.timezone[1].unqualifiedClock)
  const destination = path.join(root, '.test-runtime/security-review-20261014.json')
  fs.mkdirSync(path.dirname(destination), { recursive: true })
  fs.writeFileSync(destination, JSON.stringify(results, null, 2))
  console.log(JSON.stringify({ controlChecksPassed: results.controls.length, reproducedSecurityFindings: results.reproducedFindings.length,
    additionalSourceFindings: results.sourceFindings.length, timezoneMismatchReproduced: true, evidence: destination }))
}

(process.argv.includes('--timezone-probe') ? timezoneProbe() : review()).catch(error => {
  // A failure should not emit token values from assertion operands.
  console.error('Review check failed: ' + error.name)
  console.error(String(error.stack).split('\n').filter(line => /^\s+at /.test(line)).slice(0, 4).join('\n'))
  process.exitCode = 1
})
