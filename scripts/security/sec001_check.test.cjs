'use strict'
// Tests for sec001_check.cjs with synthetic accounts and synthetic "leaked" values on a disposable MongoDB.
// No real credential is used. Run: node --test scripts/security/sec001_check.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..', '..')
const req = (m) => require(require.resolve(m, { paths: [path.join(ROOT, 'backend')] }))
const { candidatesFromText } = require('./sec001_check.cjs')

test('candidate extraction: quoted password assignments only; variables and placeholders ignored', () => {
  const text = [
    "const adminPassword = 'Synthetic-Leak-1!'",
    '  password: "Synthetic-Leak-2!",',
    "$VerifyPassword = 'Synthetic-Leak-3!'",
    "const password = process.env.ADMIN_PASSWORD",
    "password: '${PASS}'",
    "password: '<your password>'",
    "const name = 'not a secret'",
  ].join('\n')
  assert.deepStrictEqual([...candidatesFromText(text)].sort(), ['Synthetic-Leak-1!', 'Synthetic-Leak-2!', 'Synthetic-Leak-3!'])
})

test('checker: flags valid leaked passwords and pre-change sessions, prints no secret, writes nothing', async () => {
  const { MongoMemoryServer } = req('mongodb-memory-server')
  const { MongoClient, ObjectId } = req('mongodb')
  const bcrypt = req('bcryptjs')
  const mongo = await MongoMemoryServer.create()
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec001-test-'))
  try {
    const leaked = 'Synthetic-Leaked-Value-9!'
    const candidatesFile = path.join(tmp, 'candidates.txt')
    fs.writeFileSync(candidatesFile, leaked + '\n')
    const client = await MongoClient.connect(mongo.getUri())
    const db = client.db('sec001_synthetic')
    const hashLeaked = await bcrypt.hash(leaked, 4)
    const hashOther = await bcrypt.hash('Synthetic-Rotated-Value-1!', 4)
    const changedAt = new Date(Date.now() - 3600e3)
    const users = [
      { _id: new ObjectId(), email: 'still-leaked@x.test', role: 'admin', status: 'active', password: hashLeaked },
      { _id: new ObjectId(), email: 'rotated@x.test', role: 'analyst', status: 'active', password: hashOther, passwordChangedAt: changedAt },
      { _id: new ObjectId(), email: 'rotated-old-session@x.test', role: 'viewer', status: 'active', password: hashOther, passwordChangedAt: changedAt },
    ]
    await db.collection('users').insertMany(users)
    const future = new Date(Date.now() + 86400e3)
    await db.collection('authsessions').insertMany([
      { user: users[1]._id, revokedAt: null, expiresAt: future, createdAt: new Date() }, // after the change: fine
      { user: users[2]._id, revokedAt: null, expiresAt: future, createdAt: new Date(changedAt - 60e3) }, // before: open
      { user: users[2]._id, revokedAt: new Date(), expiresAt: future, createdAt: new Date(changedAt - 60e3) }, // revoked
    ])
    const before = JSON.stringify(await db.collection('users').find().toArray()) + (await db.collection('authsessions').countDocuments())

    const run = (dbName) =>
      spawnSync(process.execPath, [path.join(__dirname, 'sec001_check.cjs'), '--mongo', mongo.getUri(), '--db', dbName, '--candidates-file', candidatesFile,
        ...['still-leaked', 'rotated', 'rotated-old-session'].flatMap((u) => ['--affected', 'sec001_synthetic/' + u + '@x.test'])], { encoding: 'utf8' })
    const r = run('sec001_synthetic')
    const out = r.stdout + r.stderr
    assert.strictEqual(r.status, 1, out)
    assert.match(out, /OPEN\s+still-leaked@x\.test.*leaked password valid: YES/)
    assert.match(out, /ok\s+rotated@x\.test.*leaked password valid: no .*pre-change: 0/)
    assert.match(out, /OPEN\s+rotated-old-session@x\.test.*leaked password valid: no .*pre-change: 1/)
    assert.match(out, /NOT resolved: 2 record/)
    assert.ok(!out.includes(leaked), 'candidate value printed')
    assert.ok(!out.includes(hashLeaked.slice(7, 20)), 'hash printed')

    const after = JSON.stringify(await db.collection('users').find().toArray()) + (await db.collection('authsessions').countDocuments())
    assert.strictEqual(after, before, 'the checker changed data')

    // all clear -> exit 0
    await client.db('sec001_clean').collection('users').insertOne({ email: 'ok@x.test', role: 'viewer', status: 'active', password: hashOther })
    const clean = run('sec001_clean')
    assert.strictEqual(clean.status, 0, clean.stdout + clean.stderr)
    await client.close()
  } finally {
    await mongo.stop()
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('only affected records decide: unaffected accounts with sessions are "not affected"; a missed affected record fails', async () => {
  const { MongoMemoryServer } = req('mongodb-memory-server')
  const { MongoClient, ObjectId } = req('mongodb')
  const bcrypt = req('bcryptjs')
  const mongo = await MongoMemoryServer.create()
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec001-scope-'))
  try {
    const leaked = 'Synthetic-Leaked-Value-7!'
    const cand = path.join(tmp, 'c.txt')
    fs.writeFileSync(cand, leaked + '\n')
    const client = await MongoClient.connect(mongo.getUri())
    const db = client.db('scope_db')
    const changedAt = new Date(Date.now() - 3600e3)
    const rotated = await bcrypt.hash('Synthetic-New-Value-1!', 4)
    const ids = [new ObjectId(), new ObjectId()]
    await db.collection('users').insertMany([
      { _id: ids[0], email: 'affected@x.test', role: 'admin', status: 'active', password: rotated, passwordChangedAt: changedAt },
      { _id: ids[1], email: 'unaffected@x.test', role: 'admin', status: 'active', password: rotated }, // never leaked
    ])
    const future = new Date(Date.now() + 86400e3)
    await db.collection('authsessions').insertMany([
      { user: ids[1], revokedAt: null, expiresAt: future, createdAt: new Date() },
      { user: ids[1], revokedAt: null, expiresAt: future, createdAt: new Date() },
    ])
    const run = (affected) =>
      spawnSync(process.execPath, [path.join(__dirname, 'sec001_check.cjs'), '--mongo', mongo.getUri(), '--db', 'scope_db',
        '--candidates-file', cand, ...affected.flatMap((a) => ['--affected', a])], { encoding: 'utf8' })

    const ok = run(['scope_db/affected@x.test'])
    assert.strictEqual(ok.status, 0, ok.stdout + ok.stderr)
    assert.match(ok.stdout, /ok\s+affected@x\.test/)
    assert.match(ok.stdout, /n\/a\s+unaffected@x\.test/)
    assert.match(ok.stdout, /affected records: 1 checked, 0 open/)

    // an affected record listed but absent from the database is never silently "resolved"
    const missing = run(['scope_db/affected@x.test', 'scope_db/gone@x.test'])
    assert.strictEqual(missing.status, 1, missing.stdout)
    assert.match(missing.stdout, /MISSING\s+gone@x\.test/)

    // a leaked password that still works counts even when the record is not on the affected list
    await db.collection('users').insertOne({ email: 'surprise@x.test', role: 'viewer', status: 'active', password: await bcrypt.hash(leaked, 4) })
    const surprise = run(['scope_db/affected@x.test'])
    assert.strictEqual(surprise.status, 1)
    assert.match(surprise.stdout, /OPEN\s+surprise@x\.test.*leaked password valid: YES/)
    await client.close()
  } finally {
    await mongo.stop()
    fs.rmSync(tmp, { recursive: true, force: true })
  }
})

test('no candidates -> error exit, never "resolved"', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sec001-empty-'))
  const f = path.join(tmp, 'c.txt')
  fs.writeFileSync(f, '')
  const r = spawnSync(process.execPath, [path.join(__dirname, 'sec001_check.cjs'), '--mongo', 'mongodb://127.0.0.1:1', '--candidates-file', f], { encoding: 'utf8' })
  fs.rmSync(tmp, { recursive: true, force: true })
  assert.strictEqual(r.status, 2)
  assert.match(r.stderr, /refusing to report "resolved"/)
})
