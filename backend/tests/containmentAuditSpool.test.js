'use strict'
/**
 * Crash durability of the containment audit trail. Every event is appended and fsynced to a per-database spool file
 * before the MongoDB write is attempted, and replayed on the next connection. These tests kill real child processes;
 * MongoDB is disposable. Guarantee under test: once logContainmentAudit has returned, the event survives a process
 * crash, is stored once, and keeps its order. A torn final line (crash during the write) loses only that line.
 */
const { runChild } = require('../../scripts/test-support/run_child.cjs')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { MongoMemoryServer } = require('mongodb-memory-server')
const { MongoClient } = require('mongodb')

jest.setTimeout(60000)
const BACKEND = path.join(__dirname, '..')
let mongo
let client
let dir
let dbName
let n = 0

beforeAll(async () => {
  mongo = await MongoMemoryServer.create()
  client = await MongoClient.connect(mongo.getUri())
})
afterAll(async () => {
  await client.close()
  await mongo.stop()
})
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-spool-'))
  dbName = 'spool_' + ++n
})
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }))

const uri = (db = dbName) => mongo.getUri(db)
const spool = (db = dbName) => path.join(dir, `containment-audit-spool-${db}.jsonl`)
const events = (db = dbName) => client.db(db).collection('containment_audit_events').find().sort({ seq: 1 }).toArray()

const PRELUDE = `
  const mongoose = require('mongoose');
  const audit = require('./utils/containmentAudit');
  const log = (action, id) => audit.logContainmentAudit({ action, containmentId: id, target: '198.51.100.9' });
  const die = () => process.kill(process.pid, 'SIGKILL');
`
async function child(body, { db = dbName, env = {}, timeoutMs = 30000 } = {}) {
  const script = `${PRELUDE}(async () => { await mongoose.connect(process.env.MONGO_URI); ${body} })()
    .catch((e) => { console.error(e); process.exit(3) })`
  const result = await runChild(process.execPath, ['-e', script], {
    cwd: BACKEND,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      MONGO_URI: uri(db),
      CONTAINMENT_AUDIT_SPOOL_DIR: dir,
      ...env,
    },
    timeoutMs,
  })
  if (result.error) {
    throw new Error(
      `child did not finish within ${timeoutMs} ms (${result.error.code}):\n${result.stdout}\n${result.stderr}`
    )
  }
  return result
}
const RECOVER =
  'await audit.recoverContainmentAuditSpool(); await audit.settleContainmentAudit(); await mongoose.disconnect(); process.exit(0);'
const ACTIONS = ['CONTAINMENT_REQUESTED', 'CONTAINMENT_ACTIVE', 'ROLLBACK_INITIATED']
const logAll = ACTIONS.map((a) => `log('${a}', 'CTN-1');`).join(' ')

test('a child that never finishes fails fast and by name instead of freezing Jest', async () => {
  const started = Date.now()
  await expect(child('await new Promise(() => setInterval(() => {}, 1000));', { timeoutMs: 2000 })).rejects.toThrow(
    /did not finish within 2000 ms/
  )
  expect(Date.now() - started).toBeLessThan(15000)
})

test('no test can block Jest indefinitely on a synchronous child process', () => {
  const dirs = [__dirname, path.join(__dirname, 'helpers')]
  const unbounded = dirs
    .flatMap((d) => fs.readdirSync(d).map((name) => path.join(d, name)))
    .filter((file) => file.endsWith('.js') && file !== __filename)
    .filter((file) => {
      const text = fs.readFileSync(file, 'utf8')
      return /\b(spawnSync|execSync|execFileSync)\(/.test(text) && !/\btimeout:/.test(text)
    })
  expect(unbounded.map((file) => path.basename(file))).toEqual([])
})

test('a child that makes MongoDB log more than a pipe holds still finishes (CI run 42645350654)', async () => {
  const r = await child(
    `for (let i = 0; i < 300; i++) await mongoose.connection.db.createCollection('c' + i); await mongoose.disconnect(); process.exit(0);`
  )
  expect(r.status).toBe(0)
})

test('no test blocks this process on a child while holding an in-process MongoDB', () => {
  const dirs = [__dirname, path.join(__dirname, 'helpers'), path.join(__dirname, '..', '..', 'scripts', 'security')]
  const blocking = dirs
    .flatMap((d) => fs.readdirSync(d).map((name) => path.join(d, name)))
    .filter((file) => /\.test\.(js|cjs)$/.test(file) && file !== __filename)
    .filter((file) => {
      const text = fs.readFileSync(file, 'utf8')
      return /MongoMemory/.test(text) && /\b(spawnSync|execSync)\(|\bexecFileSync\((?!'icacls')/.test(text)
    })
  expect(blocking.map((file) => path.basename(file))).toEqual([])
  expect(fs.readFileSync(__filename, 'utf8')).not.toMatch(/require\('child_process'\)/)
})

test('killed during a MongoDB outage: events survive, are stored once and in order', async () => {
  const crashed = await child(`mongoose.connection.readyState = 0; ${logAll} die();`)
  expect(crashed.status === 0).toBe(false)
  expect(fs.readFileSync(spool(), 'utf8').trim().split('\n')).toHaveLength(3)
  expect(await events()).toHaveLength(0)

  const recovered = await child(RECOVER)
  expect(recovered.status).toBe(0)
  const stored = await events()
  expect(stored.map((e) => e.action)).toEqual(ACTIONS)
  expect(stored.every((e) => e.target === '198.51.100.9')).toBe(true)
  expect(fs.statSync(spool()).size).toBe(0) // drained
})

test('killed immediately after logging with MongoDB up: nothing is lost and nothing is duplicated', async () => {
  await child(`${logAll} die();`)
  expect((await child(RECOVER)).status).toBe(0)
  expect((await events()).map((e) => e.action)).toEqual(ACTIONS)
})

test('replaying a spool whose events are already stored adds nothing', async () => {
  expect((await child(`${logAll} await audit.settleContainmentAudit(); die();`)).status === 0).toBe(false)
  const before = await events()
  expect(before).toHaveLength(3)
  expect((await child(RECOVER)).status).toBe(0)
  expect((await child(RECOVER)).status).toBe(0)
  expect((await events()).map((e) => e.eventId)).toEqual(before.map((e) => e.eventId))
})

test('a torn final line from a crash mid-write loses only that line', async () => {
  await child(`mongoose.connection.readyState = 0; ${logAll} die();`)
  fs.appendFileSync(spool(), '{"action":"CONTAINMENT_ROLLED_BA')
  expect((await child(RECOVER)).status).toBe(0)
  expect((await events()).map((e) => e.action)).toEqual(ACTIONS)
})

test('normal operation leaves the spool empty', async () => {
  expect(
    (await child(`${logAll} await audit.settleContainmentAudit(); await mongoose.disconnect(); process.exit(0);`))
      .status
  ).toBe(0)
  expect(fs.statSync(spool()).size).toBe(0)
  expect(await events()).toHaveLength(3)
})

test('a spool is bound to its database: another database never replays it', async () => {
  await child(`mongoose.connection.readyState = 0; ${logAll} die();`)
  const other = dbName + '_other'
  expect((await child(RECOVER, { db: other })).status).toBe(0)
  expect(await events(other)).toHaveLength(0)
  expect(fs.readFileSync(spool(), 'utf8').trim().split('\n')).toHaveLength(3) // untouched
})

test('the size cap is enforced and counted; the event still goes to MongoDB', async () => {
  const r = await child(
    `${logAll} await audit.settleContainmentAudit(); console.log('STATE ' + JSON.stringify(audit.containmentAuditBacklog())); await mongoose.disconnect(); process.exit(0);`,
    { env: { CONTAINMENT_AUDIT_SPOOL_MAX_BYTES: '10' } }
  )
  expect(r.status).toBe(0)
  expect(JSON.parse(r.stdout.match(/STATE (.*)/)[1]).spoolFailures).toBe(3)
  expect(await events()).toHaveLength(3)
})

test('an unusable spool location never blocks the audit path', async () => {
  const file = path.join(dir, 'not-a-directory')
  fs.writeFileSync(file, 'x')
  const r = await child(
    `${logAll} await audit.settleContainmentAudit(); console.log('STATE ' + JSON.stringify(audit.containmentAuditBacklog())); await mongoose.disconnect(); process.exit(0);`,
    { env: { CONTAINMENT_AUDIT_SPOOL_DIR: file } }
  )
  expect(r.status).toBe(0)
  expect(JSON.parse(r.stdout.match(/STATE (.*)/)[1]).spoolFailures).toBe(3)
  expect(await events()).toHaveLength(3)
})
