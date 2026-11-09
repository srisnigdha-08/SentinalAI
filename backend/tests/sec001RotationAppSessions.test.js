'use strict'
/**
 * SEC-001 rotation tool (scripts/security/sec001_rotate.cjs) against the application's own auth code, on a
 * disposable in-memory MongoDB with a synthetic account: a session issued before the rotation must stop working
 * for both its access and its refresh token, the temporary password must sign in, and the account must be held
 * at the forced password change. No real database or credential is touched.
 */
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-sec001-access-secret-0123456789abcdef'
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-sec001-refresh-secret-0123456789abcde'
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.setTimeout(60000)

const User = require('../models/User')
const sessions = require('../services/authSessionService')
const TOOL = path.join(__dirname, '..', '..', 'scripts', 'security', 'sec001_rotate.cjs')
const LEAKED = 'Synthetic-Leaked-Password-1!'
const DB = 'sec001_app_sessions'

let mongo
let tmp
beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  await mongoose.connect(mongo.getUri(DB))
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec001-app-'))
})
afterAll(async () => {
  await mongoose.disconnect()
  await mongo.stop()
  fs.rmSync(tmp, { recursive: true, force: true })
})

test('old access and refresh tokens die, the temporary password signs in, the change is forced', async () => {
  const user = await User.create({ name: 'Admin', email: 'admin@sentinel.io', password: LEAKED, role: 'admin' })
  const before = await sessions.issue(user)
  await expect(sessions.authorize(before.token)).resolves.toBeTruthy() // valid before the rotation

  const targets = path.join(tmp, 'targets.json')
  fs.writeFileSync(targets, JSON.stringify([{ db: DB, email: 'admin@sentinel.io' }]))
  const backup = path.join(tmp, 'backup', DB)
  fs.mkdirSync(backup, { recursive: true })
  fs.writeFileSync(path.join(backup, 'users.bson'), 'synthetic')
  fs.writeFileSync(path.join(backup, 'authsessions.bson'), 'synthetic')
  const uri = mongo.getUri()
  // spawnSync blocks the event loop, so Jest's own timeout cannot fire while the tool is stuck.
  const run = (argv) =>
    spawnSync(process.execPath, [TOOL, ...argv], { encoding: 'utf8', timeout: 45000, killSignal: 'SIGKILL' })
  const pre = run(['preflight', '--mongo', uri, '--targets-file', targets])
  expect(pre.status).toBe(0)
  const fingerprint = pre.stdout.match(/fingerprint: ([0-9a-f]{16})/)[1]
  const credsDir = path.join(tmp, 'creds')
  const r = run([
    'apply',
    '--mongo',
    uri,
    '--targets-file',
    targets,
    '--confirm',
    fingerprint,
    '--authorize',
    'ROTATE 9 SEC-001 ACCOUNTS',
    '--backup-dir',
    path.join(tmp, 'backup'),
    '--credentials-dir',
    credsDir,
  ])
  expect(r.status).toBe(0)

  // the session issued before the rotation: access token and refresh token both refused
  await expect(sessions.authorize(before.token)).rejects.toThrow()
  await expect(sessions.rotate(before.refreshToken)).rejects.toThrow()

  // the temporary password works, the leaked one does not, and the account must set its own password
  const file = fs.readdirSync(credsDir).find((f) => f.startsWith('sec001-credentials-'))
  const temp = JSON.parse(fs.readFileSync(path.join(credsDir, file), 'utf8')).byRecord[`${DB}/admin@sentinel.io`]
  const after = await User.findById(user._id).select('+password')
  expect(await after.comparePassword(temp)).toBe(true)
  expect(await after.comparePassword(LEAKED)).toBe(false)
  expect(after.mustChangePassword).toBe(true)
  const fresh = await sessions.issue(after) // what a sign-in with the temporary password issues
  await expect(sessions.authorize(fresh.token)).resolves.toBeTruthy()
})
