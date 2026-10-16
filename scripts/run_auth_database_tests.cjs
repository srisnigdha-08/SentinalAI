// Operates only the separately approved regression instance. Never connects to retained acceptance data.
const fs = require('node:fs')
const path = require('node:path')
const net = require('node:net')
const crypto = require('node:crypto')
const { spawn, spawnSync } = require('node:child_process')
const { MongoClient } = require('../backend/node_modules/mongodb')
const root = path.resolve(__dirname, '..')
const storage = path.join(root, '.test-runtime/auth-timezone-db-20261014-01')
const binary = 'C:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete.native-integration\\mongodb-acceptance-20261014\\binaries\\mongod.exe'
const database = 'sentinelai_auth_timezone_test_20261014'
const resume = process.argv.includes('--resume')
const tests = process.argv.filter(arg => /^tests\/[a-zA-Z]+.*\.test\.js$/.test(arg))
if (!tests.length) tests.push('tests/authPersistence.test.js')
const protect = (input, decrypt = false) => {
  const script = decrypt
    ? 'Add-Type -AssemblyName System.Security; $blob=[Convert]::FromBase64String([Console]::In.ReadToEnd()); [Console]::Out.Write([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($blob,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)))'
    : 'Add-Type -AssemblyName System.Security; $bytes=[Text.Encoding]::UTF8.GetBytes([Console]::In.ReadToEnd()); [Console]::Out.Write([Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)))'
  const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { input, encoding: 'utf8', windowsHide: true })
  if (result.status !== 0) throw new Error('Secure test credential storage failed')
  return result.stdout
}
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
let processDB, admin, credentials
async function main() {
  await new Promise((resolve, reject) => { const probe = net.createServer(); probe.once('error', () => reject(new Error('Port 27029 occupied'))); probe.listen(27029, '127.0.0.1', () => probe.close(resolve)) })
  for (let current = path.dirname(storage);; current = path.dirname(current)) {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) throw new Error('Reparse path rejected')
    if (current === path.dirname(current)) break
  }
  if (fs.existsSync(storage)) {
    for (const owned of [storage, ...['data', 'logs', 'evidence'].map(name => path.join(storage, name))]) {
      if (fs.lstatSync(owned).isSymbolicLink() || fs.realpathSync(owned).toLowerCase() !== path.resolve(owned).toLowerCase()) throw new Error('Owned test storage contains a redirected path')
    }
  }
  const credentialFile = path.join(storage, 'credentials.dpapi')
  if (resume) {
    credentials = JSON.parse(protect(fs.readFileSync(credentialFile, 'utf8'), true))
    const ownership = JSON.parse(fs.readFileSync(path.join(storage, 'ownership.json'), 'utf8'))
    if (ownership.database !== database || ownership.storage !== storage || ownership.port !== 27029) throw new Error('Test storage ownership mismatch')
  } else {
    if (fs.existsSync(storage)) throw new Error('Test directory exists; no reuse without --resume ownership checks')
    fs.mkdirSync(storage)
    for (const directory of ['data', 'logs', 'evidence']) fs.mkdirSync(path.join(storage, directory))
    credentials = Object.fromEntries(['admin', 'application', 'JWT_SECRET', 'JWT_REFRESH_SECRET', 'SENTINEL_KEY', 'HONEYPOT_API_KEY'].map(name => [name, crypto.randomBytes(32).toString('hex')]))
    fs.writeFileSync(credentialFile, protect(JSON.stringify(credentials)), { flag: 'wx' })
    fs.writeFileSync(path.join(storage, 'ownership.json'), JSON.stringify({ storage, database, port: 27029 }), { flag: 'wx' })
  }
  const version = spawnSync(binary, ['--version'], { encoding: 'utf8', windowsHide: true })
  if (version.status !== 0 || !version.stdout.includes('v7.0.45')) throw new Error('Reviewed MongoDB version unavailable')
  const log = fs.openSync(path.join(storage, 'logs/process.log'), 'a')
  processDB = spawn(binary, ['--auth', '--bind_ip', '127.0.0.1', '--port', '27029', '--dbpath', path.join(storage, 'data'), '--logpath', path.join(storage, 'logs/mongod.log'), '--logappend'], { windowsHide: true, stdio: ['ignore', log, log] })
  fs.closeSync(log)
  if (!resume) {
    const bootstrap = new MongoClient('mongodb://127.0.0.1:27029', { serverSelectionTimeoutMS: 500 })
    try {
      for (let attempt = 0; attempt < 60; attempt++) {
        try { await bootstrap.connect(); await bootstrap.db('admin').command({ ping: 1 }); break } catch { await delay(250) }
      }
      await bootstrap.db('admin').command({ createUser: 'auth_test_admin', pwd: credentials.admin, roles: [{ role: 'root', db: 'admin' }] })
    } finally { await bootstrap.close() }
  }
  admin = new MongoClient(`mongodb://auth_test_admin:${credentials.admin}@127.0.0.1:27029/admin`, { serverSelectionTimeoutMS: 500 })
  let ready = false
  for (let attempt = 0; attempt < 60; attempt++) { try { await admin.connect(); await admin.db('admin').command({ ping: 1 }); ready = true; break } catch { await delay(250) } }
  if (!ready) throw new Error('Authenticated test MongoDB unavailable')
  if (!resume) await admin.db(database).command({ createUser: 'auth_test_application', pwd: credentials.application, roles: [{ role: 'readWrite', db: database }] })
  const options = (await admin.db('admin').command({ getCmdLineOpts: 1 })).parsed
  if (options.net.bindIp !== '127.0.0.1' || options.net.port !== 27029 || options.security.authorization !== 'enabled' || path.resolve(options.storage.dbPath) !== path.join(storage, 'data')) throw new Error('Test MongoDB configuration differs from approval')
  const uri = `mongodb://auth_test_application:${credentials.application}@127.0.0.1:27029/${database}?authSource=${database}`
  const outputName = 'jest-' + Date.now() + '.json'
  const testProcess = spawn(process.execPath, ['node_modules/jest/bin/jest.js', '--runInBand', '--forceExit', '--runTestsByPath', ...tests, '--json', '--outputFile', path.join(storage, 'evidence', outputName)], {
    cwd: path.join(root, 'backend'), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ...credentials, AUTH_TEST_MONGO_URI: uri, MONGO_URI: uri, NODE_ENV: 'test',
      CLIENT_URL: 'http://127.0.0.1:3000', LOG_DIR: path.join(storage, 'logs/backend'),
      ABUSEIPDB_API_KEY: '', ADMIN_INITIAL_PASSWORD: '', AI_ENGINE_URL: 'http://127.0.0.1:1',
      TEMP: path.join(root, 'backend/.test-runtime'), TMP: path.join(root, 'backend/.test-runtime') } })
  let output = ''
  testProcess.stdout.on('data', data => { output += data })
  testProcess.stderr.on('data', data => { output += data })
  const code = await new Promise(resolve => testProcess.once('exit', resolve))
  for (const secret of Object.values(credentials)) output = output.split(secret).join('[REDACTED]')
  output = output.replace(/mongodb:\/\/[^\s]+/g, '[Mongo URI redacted]')
  fs.writeFileSync(path.join(storage, 'evidence', outputName + '.log'), output)
  const redact = value => {
    for (const secret of Object.values(credentials)) value = value.split(secret).join('[REDACTED]')
    return value.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '[JWT REDACTED]').replace(/mongodb:\/\/[^\s]+/g, '[Mongo URI redacted]')
  }
  const resultFile = path.join(storage, 'evidence', outputName)
  if (fs.existsSync(resultFile)) fs.writeFileSync(resultFile, redact(fs.readFileSync(resultFile, 'utf8')))
  const summary = fs.existsSync(resultFile) ? JSON.parse(fs.readFileSync(resultFile, 'utf8')) : null
  console.log(summary ? JSON.stringify({ passed: summary.numPassedTests, failed: summary.numFailedTests, skipped: summary.numPendingTests }) : 'No Jest result was produced')
  if (code !== 0) console.log(redact(output).slice(-8000))
  process.exitCode = code
  console.log(JSON.stringify({ database, port: 27029, storage, evidence: outputName, exitCode: code }))
}
main().catch(error => { console.error('Test runner failed: ' + error.name); process.exitCode = 1 }).finally(async () => {
  if (admin) { try { await admin.db('admin').command({ shutdown: 1 }) } catch {}; await admin.close().catch(() => {}) }
  if (processDB && processDB.exitCode === null) {
    await Promise.race([new Promise(resolve => processDB.once('exit', resolve)), delay(5000)])
    if (processDB.exitCode === null) processDB.kill()
  }
  console.log('Owned test instance stopped; fixtures retained; acceptance database never connected')
})
