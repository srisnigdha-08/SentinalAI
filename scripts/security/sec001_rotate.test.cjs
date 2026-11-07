'use strict'
// sec001_rotate.cjs on synthetic accounts in a disposable MongoDB. No real database or credential is touched.
// Run: node --test scripts/security/sec001_rotate.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawnSync, execFileSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..', '..')
const req = (m) => require(require.resolve(m, { paths: [path.join(ROOT, 'backend')] }))
const { MongoMemoryServer } = req('mongodb-memory-server')
const { MongoClient, ObjectId } = req('mongodb')
const bcrypt = req('bcryptjs')
const TOOL = path.join(__dirname, 'sec001_rotate.cjs')
const CHECK = path.join(__dirname, 'sec001_check.cjs')
const PHRASE = 'ROTATE 9 SEC-001 ACCOUNTS'
const LEAKED = 'Synthetic-Leaked-Password-1!'

let mongo
let client
let tmp
test.before(async () => {
  mongo = await MongoMemoryServer.create()
  client = await MongoClient.connect(mongo.getUri())
})
test.after(async () => {
  await client?.close()
  await mongo?.stop()
})

async function setup() {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec001-rot-'))
  for (const db of ['rot_a', 'rot_b']) await client.db(db).dropDatabase()
  const leakedHash = await bcrypt.hash(LEAKED, 4)
  const otherHash = await bcrypt.hash('Synthetic-Unrelated-Password-2!', 4)
  const ids = { a1: new ObjectId(), a2: new ObjectId(), aOther: new ObjectId(), b1: new ObjectId(), bOther: new ObjectId() }
  const user = (id, email, role, password, extra = {}) => ({
    _id: id, name: email.split('@')[0], email, role, status: 'active', password, authVersion: 2, tokenVersion: 2,
    mustChangePassword: false, department: 'SOC', loginCount: 7, lastLogin: new Date('2026-10-18T10:00:00Z'),
    createdAt: new Date('2026-10-01T00:00:00Z'), updatedAt: new Date('2026-10-18T10:00:00Z'), ...extra,
  })
  await client.db('rot_a').collection('users').insertMany([
    user(ids.a1, 'admin@sentinel.io', 'admin', leakedHash),
    user(ids.a2, 'sara@sentinel.io', 'viewer', leakedHash),
    user(ids.aOther, 'admin1@sentinel.io', 'admin', otherHash), // not a target
  ])
  await client.db('rot_b').collection('users').insertMany([
    user(ids.b1, 'pallavi@sentinel.io', 'analyst', leakedHash, { passwordChangedAt: new Date('2026-10-23') }),
    user(ids.bOther, 'other@sentinel.io', 'analyst', otherHash),
  ])
  const future = new Date(Date.now() + 86400e3)
  const sess = (u, db, n) =>
    client.db(db).collection('authsessions').insertMany(
      Array.from({ length: n }, (_, i) => ({ _id: `${u}-${i}`, user: ids[u], authVersion: 2, generation: 0, refreshHash: 'h', expiresAt: future, lastUsedAt: new Date('2026-10-18'), revokedAt: null, revocationReason: null, createdAt: new Date('2026-10-18'), updatedAt: new Date('2026-10-18') }))
    )
  await sess('a1', 'rot_a', 5)
  await sess('a2', 'rot_a', 2)
  await sess('aOther', 'rot_a', 3)
  await sess('bOther', 'rot_b', 1)
  const targets = path.join(tmp, 'targets.json')
  fs.writeFileSync(targets, JSON.stringify([
    { db: 'rot_a', email: 'admin@sentinel.io' }, { db: 'rot_a', email: 'sara@sentinel.io' }, { db: 'rot_b', email: 'pallavi@sentinel.io' },
  ]))
  const backup = path.join(tmp, 'backup', 'dump')
  for (const db of ['rot_a', 'rot_b']) {
    fs.mkdirSync(path.join(backup, db), { recursive: true })
    fs.writeFileSync(path.join(backup, db, 'users.bson'), 'synthetic')
    fs.writeFileSync(path.join(backup, db, 'authsessions.bson'), 'synthetic')
  }
  return { ids, targets, backup: path.join(tmp, 'backup'), creds: path.join(tmp, 'creds') }
}

const run = (argv, env = {}) =>
  spawnSync(process.execPath, [TOOL, ...argv], { encoding: 'utf8', env: { ...process.env, ...env } })
const snapshot = async () => {
  const out = {}
  for (const db of ['rot_a', 'rot_b'])
    for (const c of ['users', 'authsessions']) out[`${db}.${c}`] = await client.db(db).collection(c).find().sort({ _id: 1 }).toArray()
  return out
}
const fp = (stdout) => stdout.match(/fingerprint: ([0-9a-f]{16})/)[1]
const applyArgs = (s, fingerprint, extra = []) => [
  'apply', '--mongo', mongo.getUri(), '--targets-file', s.targets, '--confirm', fingerprint, '--authorize', PHRASE,
  '--backup-dir', s.backup, '--credentials-dir', s.creds, ...extra,
]
const credsFile = (s) => path.join(s.creds, fs.readdirSync(s.creds).find((f) => f.startsWith('sec001-credentials-')))
const journalFile = (s) => path.join(s.creds, fs.readdirSync(s.creds).find((f) => f.startsWith('sec001-journal-') && f.endsWith('.json')))

test('preflight is read-only, reports the plan and a fingerprint, writes no file', async () => {
  const s = await setup()
  const before = await snapshot()
  const r = run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets])
  assert.strictEqual(r.status, 0, r.stdout + r.stderr)
  assert.match(r.stdout, /rot_a\s+admin@sentinel\.io\s+found.*authVersion 2 -> 3\s+sessions to revoke: 5/)
  assert.match(r.stdout, /rot_b\s+pallavi@sentinel\.io\s+found/)
  assert.match(r.stdout, /fingerprint: [0-9a-f]{16}/)
  assert.deepStrictEqual(await snapshot(), before)
  assert.ok(!fs.existsSync(s.creds))
})

test('apply refuses before any write: wrong fingerprint, missing phrase, no backup, missing target, remote host', async () => {
  const s = await setup()
  const before = await snapshot()
  const f = fp(run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets]).stdout)
  assert.strictEqual(run(applyArgs(s, '0000000000000000')).status, 1)
  const noPhrase = applyArgs(s, f).filter((x, i, a) => x !== '--authorize' && a[i - 1] !== '--authorize')
  assert.strictEqual(run(noPhrase).status, 1)
  const noBackup = applyArgs(s, f).map((x) => (x === s.backup ? path.join(tmp, 'nope') : x))
  assert.strictEqual(run(noBackup).status, 2)
  fs.rmSync(path.join(s.backup, 'dump', 'rot_b'), { recursive: true })
  const partialBackup = run(applyArgs(s, f))
  assert.strictEqual(partialBackup.status, 2)
  assert.match(partialBackup.stderr, /no verified backup \(users \+ authsessions\) found for: rot_b/)
  const remote = run(['preflight', '--mongo', 'mongodb://10.0.0.5:27017', '--targets-file', s.targets])
  assert.strictEqual(remote.status, 2)
  assert.match(remote.stderr, /non-loopback/)
  const t = JSON.parse(fs.readFileSync(s.targets, 'utf8'))
  t.push({ db: 'rot_b', email: 'ghost@sentinel.io' })
  fs.writeFileSync(s.targets, JSON.stringify(t))
  const missing = run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets])
  assert.strictEqual(missing.status, 1)
  assert.match(missing.stdout, /ghost@sentinel\.io\s+NOT FOUND/)
  assert.deepStrictEqual(await snapshot(), before)
  assert.ok(!fs.existsSync(s.creds) || fs.readdirSync(s.creds).length === 0)
})

test('apply: rotates exactly the targets, revokes their sessions, preserves everything else', async () => {
  const s = await setup()
  const before = await snapshot()
  const f = fp(run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets]).stdout)
  const r = run(applyArgs(s, f))
  assert.strictEqual(r.status, 0, r.stdout + r.stderr)
  assert.match(r.stdout, /3\/3 record\(s\) rotated and sessions revoked; problems: 0/)

  const creds = JSON.parse(fs.readFileSync(credsFile(s), 'utf8')).byRecord
  const passwords = Object.values(creds)
  assert.strictEqual(new Set(passwords).size, 3) // unique
  for (const pw of passwords) {
    assert.ok(pw.length === 20 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw))
    assert.ok(!(r.stdout + r.stderr).includes(pw), 'a password was printed')
  }
  const after = await snapshot()
  const byId = (rows) => Object.fromEntries(rows.map((x) => [String(x._id), x]))
  for (const db of ['rot_a', 'rot_b']) {
    const old = byId(before[`${db}.users`])
    for (const u of after[`${db}.users`]) {
      const o = old[String(u._id)]
      const key = `${db}/${u.email}`
      if (creds[key]) {
        assert.ok(await bcrypt.compare(creds[key], u.password), 'new password must work')
        assert.ok(!(await bcrypt.compare(LEAKED, u.password)), 'leaked password must fail')
        assert.ok(u.password.startsWith('$2') && u.password.includes('$12$'), 'cost 12 as the app')
        assert.strictEqual(u.authVersion, o.authVersion + 1)
        assert.strictEqual(u.tokenVersion, o.tokenVersion + 1)
        assert.strictEqual(u.mustChangePassword, true)
        assert.ok(u.passwordChangedAt > new Date(Date.now() - 60e3))
        const strip = ({ password, authVersion, tokenVersion, mustChangePassword, passwordChangedAt, ...rest }) => rest
        assert.deepStrictEqual(strip(u), strip(o), `${key}: other fields changed`)
      } else {
        assert.deepStrictEqual(u, o, `${key}: non-target account changed`)
      }
    }
    const oldS = byId(before[`${db}.authsessions`])
    const targetIds = new Set([String(s.ids.a1), String(s.ids.a2), String(s.ids.b1)])
    for (const x of after[`${db}.authsessions`]) {
      if (targetIds.has(String(x.user))) {
        assert.ok(x.revokedAt instanceof Date)
        assert.strictEqual(x.revocationReason, 'sec001-rotation')
        const { revokedAt, revocationReason, ...rest } = x
        const { revokedAt: r0, revocationReason: rr0, ...rest0 } = oldS[x._id]
        assert.deepStrictEqual(rest, rest0)
      } else assert.deepStrictEqual(x, oldS[x._id], 'non-target session changed')
    }
  }

  // owner-only ACL on the credentials file
  if (process.platform === 'win32') {
    const acl = execFileSync('icacls', [credsFile(s)], { encoding: 'utf8' })
    const grants = acl.split(/\r?\n/).filter((l) => /:\(/.test(l))
    assert.strictEqual(grants.length, 1, acl)
    assert.match(grants[0], new RegExp(process.env.USERNAME, 'i'))
  }

  // the existing read-only checker agrees
  const cand = path.join(tmp, 'cand.txt')
  fs.writeFileSync(cand, LEAKED + '\n')
  const chk = spawnSync(process.execPath, [CHECK, '--mongo', mongo.getUri(), '--db', 'rot_a', '--db', 'rot_b', '--candidates-file', cand,
    '--affected', 'rot_a/admin@sentinel.io', '--affected', 'rot_a/sara@sentinel.io', '--affected', 'rot_b/pallavi@sentinel.io'], { encoding: 'utf8' })
  assert.strictEqual(chk.status, 0, chk.stdout)
  assert.match(chk.stdout, /affected records: 3 checked, 0 open/)

  // a second apply with the old fingerprint is refused (state changed): no double rotation
  assert.strictEqual(run(applyArgs(s, f)).status, 1)
})

test('partial failure: resume finishes with the same passwords; a further resume changes nothing', async () => {
  const s = await setup()
  const f = fp(run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets]).stdout)
  const r1 = run(applyArgs(s, f), { SEC001_TEST_FAIL_AFTER: '1' })
  assert.strictEqual(r1.status, 2)
  assert.match(r1.stderr, /simulated failure/)
  const j = JSON.parse(fs.readFileSync(journalFile(s), 'utf8'))
  assert.deepStrictEqual(j.entries.map((e) => e.state), ['done', 'pending', 'pending'])
  const creds = JSON.parse(fs.readFileSync(credsFile(s), 'utf8')).byRecord

  const r2 = run(['resume', '--mongo', mongo.getUri(), '--journal', journalFile(s)])
  assert.strictEqual(r2.status, 0, r2.stdout + r2.stderr)
  assert.match(r2.stdout, /3\/3 record\(s\) rotated/)
  for (const [key, pw] of Object.entries(creds)) {
    const [db, email] = key.split('/')
    const u = await client.db(db).collection('users').findOne({ email })
    assert.ok(await bcrypt.compare(pw, u.password), key)
    assert.strictEqual(u.authVersion, 3, `${key} rotated exactly once`)
  }
  assert.strictEqual(fs.readdirSync(s.creds).filter((x) => x.startsWith('sec001-credentials-')).length, 1)

  const snap = await snapshot()
  const r3 = run(['resume', '--mongo', mongo.getUri(), '--journal', journalFile(s)])
  assert.strictEqual(r3.status, 0)
  assert.deepStrictEqual(await snapshot(), snap, 'idempotent: nothing changes on a further resume')
})

test('crash between the password write and the session revocation: resume revokes only pre-rotation sessions', async () => {
  const s = await setup()
  const f = fp(run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets]).stdout)
  run(applyArgs(s, f), { SEC001_TEST_FAIL_AFTER: '0' }) // journal + credentials written, nothing applied
  const jf = journalFile(s)
  const j = JSON.parse(fs.readFileSync(jf, 'utf8'))
  const e = j.entries[0]
  const rotatedAt = new Date(Date.now() - 1000)
  // the password write happened, the process died before revoking sessions and before saving the journal
  await client.db(e.db).collection('users').updateOne({ _id: new ObjectId(e.id) },
    { $set: { password: e.newHash, passwordChangedAt: rotatedAt, mustChangePassword: true }, $inc: { authVersion: 1, tokenVersion: 1 } })
  // the owner already signed in with the temporary password: that session is legitimate
  await client.db(e.db).collection('authsessions').insertOne({ _id: 'fresh', user: new ObjectId(e.id), authVersion: 3, generation: 0, refreshHash: 'h',
    expiresAt: new Date(Date.now() + 86400e3), lastUsedAt: new Date(), revokedAt: null, revocationReason: null, createdAt: new Date(), updatedAt: new Date() })
  const r = run(['resume', '--mongo', mongo.getUri(), '--journal', jf])
  assert.strictEqual(r.status, 0, r.stdout + r.stderr)
  assert.match(r.stdout, /admin@sentinel\.io\s+ALREADY_ROTATED\s+sessions revoked: 5/)
  const u = await client.db(e.db).collection('users').findOne({ _id: new ObjectId(e.id) })
  assert.strictEqual(u.authVersion, 3, 'not rotated twice')
  assert.strictEqual((await client.db(e.db).collection('authsessions').findOne({ _id: 'fresh' })).revokedAt, null)
})

test('a record changed by someone else during an interrupted run is reported CONFLICT and never overwritten', async () => {
  const s = await setup()
  const f = fp(run(['preflight', '--mongo', mongo.getUri(), '--targets-file', s.targets]).stdout)
  run(applyArgs(s, f), { SEC001_TEST_FAIL_AFTER: '1' })
  const theirHash = await bcrypt.hash('Synthetic-Changed-By-Owner-3!', 4)
  await client.db('rot_a').collection('users').updateOne({ email: 'sara@sentinel.io' }, { $set: { password: theirHash } })
  const r = run(['resume', '--mongo', mongo.getUri(), '--journal', journalFile(s)])
  assert.strictEqual(r.status, 1)
  assert.match(r.stdout, /sara@sentinel\.io\s+CONFLICT/)
  const sara = await client.db('rot_a').collection('users').findOne({ email: 'sara@sentinel.io' })
  assert.strictEqual(sara.password, theirHash, 'the concurrent change was overwritten')
  assert.match(r.stdout, /2\/3 record\(s\) rotated/)
})

test('the default target list is exactly the nine runbook records', () => {
  const { DEFAULT_TARGETS, generatePassword } = require(TOOL)
  assert.deepStrictEqual(DEFAULT_TARGETS.map((t) => t.join('/')), [
    'sentinel-db/admin@sentinel.io', 'sentinel-db/arjun@sentinel.io', 'sentinel-db/priya@sentinel.io', 'sentinel-db/sara@sentinel.io',
    'sentinel-demo/admin@sentinel.io', 'sentinel-demo/arjun@sentinel.io', 'sentinel-demo/priya@sentinel.io', 'sentinel-demo/sara@sentinel.io',
    'sentinel-demo/pallavi@sentinel.io',
  ])
  const many = new Set(Array.from({ length: 2000 }, generatePassword))
  assert.strictEqual(many.size, 2000)
})

test('archive backups count only when mongorestore --dryRun shows users and authsessions of that database', async (t) => {
  const dump = 'C:/Program Files/MongoDB/Tools/100/bin/mongodump.exe'
  if (process.platform !== 'win32' || !fs.existsSync(dump)) return t.skip('mongodump not installed here')
  await setup()
  const { checkBackup } = require(TOOL)
  const dir = path.join(tmp, 'archives')
  fs.mkdirSync(dir)
  const archive = (db, file) => execFileSync(dump, ['--uri=' + mongo.getUri(), '--db=' + db, '--archive=' + path.join(dir, file), '--gzip'], { stdio: 'ignore' })
  archive('rot_a', 'rot_a-20261107.archive.gz')
  archive('rot_a', 'rot_b-20261107.archive.gz') // mislabelled: holds rot_a, named rot_b
  assert.doesNotThrow(() => checkBackup(dir, ['rot_a'], { uri: mongo.getUri() }))
  assert.throws(() => checkBackup(dir, ['rot_a', 'rot_b'], { uri: mongo.getUri() }), /no verified backup .* rot_b/)
  const before = await snapshot()
  checkBackup(dir, ['rot_a'], { uri: mongo.getUri() })
  assert.deepStrictEqual(await snapshot(), before, 'the dry run restored something')
})
