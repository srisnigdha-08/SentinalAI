'use strict'
/**
 * OPS-003 check: runs run_integration.cjs against a throwaway `mongod --auth` provisioned by
 * deployment/mongo-init.js, with the backend connected as the least-privilege `sentinel_app` user.
 * Proves (or disproves) that the role in mongo-init.js covers every collection the services write.
 *
 *   node scripts/integration/run_with_mongo_auth.cjs [--mongod "C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe"]
 *                                                    [--mongosh mongosh] [--cowrie]
 *
 * The instance listens on 127.0.0.1:27031 with a temp dbpath that is deleted afterwards. Passwords are generated
 * per run and never printed. The developer's MongoDB service on 27017 is not touched.
 */
const { spawn, spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')

const arg = (name, dflt) => {
  const i = process.argv.indexOf('--' + name)
  return i > 0 ? process.argv[i + 1] : dflt
}
const MONGOD = arg('mongod', process.platform === 'win32' ? 'C:\\Program Files\\MongoDB\\Server\\7.0\\bin\\mongod.exe' : 'mongod')
const MONGOSH = arg('mongosh', 'mongosh')
const PORT = 27031
const DB = 'sentinelai_integration_auth'
const pw = () => crypto.randomBytes(24).toString('hex')
const rootPw = pw()
const appPw = pw()
const auditPw = pw()
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-mongo-auth-'))
fs.mkdirSync(path.join(dir, 'data'))

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const sh = (args, env = {}) =>
  spawnSync(MONGOSH, ['--quiet', `mongodb://127.0.0.1:${PORT}/admin`, ...args], { encoding: 'utf8', env: { ...process.env, ...env } })

;(async () => {
  const mongod = spawn(MONGOD, ['--auth', '--bind_ip', '127.0.0.1', '--port', String(PORT), '--dbpath', path.join(dir, 'data'), '--logpath', path.join(dir, 'mongod.log')], { windowsHide: true, stdio: 'ignore' })
  let code = 1
  try {
    for (let i = 0; i < 60; i++) {
      if (sh(['--eval', 'db.runCommand({ping:1}).ok']).stdout.trim() === '1') break
      await sleep(500)
    }
    // Localhost exception: the first user may be created without credentials, exactly once
    const root = sh(['--eval', `db.createUser({user:'root',pwd:process.env.ROOT_PW,roles:['root']}).ok`], { ROOT_PW: rootPw })
    if (root.status !== 0) throw new Error('root user: ' + root.stderr.slice(0, 200))
    // mongo-init.js reads the target database and both passwords from the environment
    const init = spawnSync(MONGOSH, ['--quiet', `mongodb://root:${rootPw}@127.0.0.1:${PORT}/admin`, path.join(__dirname, '../../deployment/mongo-init.js')], {
      encoding: 'utf8',
      env: { ...process.env, SENTINEL_DB_NAME: DB, SENTINEL_APP_PASSWORD: appPw, SENTINEL_AUDIT_PASSWORD: auditPw },
    })
    fs.writeFileSync(path.join(dir, 'init.log'), (init.stdout + init.stderr).split(appPw).join('<redacted>').split(auditPw).join('<redacted>'))
    if (init.status !== 0) throw new Error('mongo-init.js exit ' + init.status + ': ' + init.stderr.slice(0, 300))
    const unauth = sh(['--eval', `db.getSiblingDB('${DB}').users.findOne()`])
    console.log('unauthenticated read refused: ' + (unauth.status !== 0 || /requires authentication|Unauthorized/i.test(unauth.stdout + unauth.stderr)))
    const run = spawnSync(process.execPath, [path.join(__dirname, 'run_integration.cjs'), '--mongo', `mongodb://sentinel_app:${appPw}@127.0.0.1:${PORT}/?authSource=${DB}`, '--db', DB, '--rows', '10', '--keep', ...process.argv.filter((a) => a === '--cowrie')], { stdio: 'inherit' })
    code = run.status
  } catch (e) {
    console.error('auth run failed: ' + e.message.split(rootPw).join('<redacted>'))
  } finally {
    mongod.kill()
    await sleep(2000)
    fs.rmSync(dir, { recursive: true, force: true })
  }
  process.exit(code)
})()
