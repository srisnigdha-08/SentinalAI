'use strict'
// node --test scripts/demo/backup-local-db.test.cjs — disposable in-memory MongoDB and a temporary folder only.
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const os = require('os')
const path = require('path')

const MODULES = path.join(__dirname, '..', '..', 'backend', 'node_modules')
const { MongoMemoryServer } = require(path.join(MODULES, 'mongodb-memory-server'))
const { MongoClient } = require(path.join(MODULES, 'mongodb'))
const { backup, verify, drill, selectExpired, DRILL_PREFIX } = require('./backup-local-db.cjs')

let server
let client
let out

test.before(async () => {
  server = await MongoMemoryServer.create()
  client = await new MongoClient(server.getUri()).connect()
  out = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-backup-test-'))
  const db = client.db('sentinel-demo')
  await db.collection('threatlogs').insertMany(Array.from({ length: 1203 }, (_, i) => ({ i, at: new Date(), score: i / 10 })))
  await db.collection('containmentactions').createIndex({ targetLock: 1 }, { unique: true, sparse: true })
  await db.collection('containmentactions').insertMany([{ targetLock: 'a' }, { other: 1 }, { other: 2 }])
  await db.collection('authsessions').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 })
  await db.collection('authsessions').insertOne({ expiresAt: new Date('2000-01-01') })
})

test.after(async () => {
  await client?.close()
  await server?.stop()
  fs.rmSync(out, { recursive: true, force: true })
})

test('pruning keeps the newest N of this database only and never touches other folders', () => {
  const names = [
    'sentinel-demo-20261101T010000000Z',
    'sentinel-demo-20261103T010000000Z',
    'sentinel-demo-20261102T010000000Z',
    'sentinel-db-20261101T010000000Z',
    'sentinel-demo-20261104T010000000Z.partial',
    'unrelated',
  ]
  assert.deepEqual(selectExpired(names, 'sentinel-demo', 2), ['sentinel-demo-20261101T010000000Z'])
  assert.deepEqual(selectExpired(names, 'sentinel-demo', 5), [])
  assert.throws(() => selectExpired(names, 'sentinel-demo', 0))
})

test('backup writes a verified folder with every document and index option', async () => {
  const r = await backup({ db: 'sentinel-demo', out, keep: 3 }, client)
  assert.equal(r.collections, 3)
  assert.equal(r.documents, 1207)
  assert.deepEqual(await verify(r.folder), [])
  const meta = JSON.parse(fs.readFileSync(path.join(r.folder, 'containmentactions.metadata.json'), 'utf8'))
  const lock = meta.indexes.find((i) => i.key.targetLock === 1)
  assert.equal(lock.unique, true)
  assert.equal(lock.sparse, true)
  assert.equal(fs.readdirSync(out).some((n) => n.endsWith('.partial')), false)
})

test('verify reports tampering and truncation', async () => {
  const r = await backup({ db: 'sentinel-demo', out, keep: 5 }, client)
  const file = path.join(r.folder, 'threatlogs.bson')
  fs.writeFileSync(file, fs.readFileSync(file).subarray(0, 100))
  const problems = await verify(r.folder)
  assert.ok(problems.some((p) => p.includes('threatlogs: BSON checksum mismatch')))
  assert.ok(problems.some((p) => p.includes('threatlogs.bson')))
  fs.rmSync(r.folder, { recursive: true })
})

test('only --keep backups remain after repeated runs, even when they follow each other immediately', async () => {
  // No pause between runs: second-resolution folder names collided here on a fast CI runner.
  for (let i = 0; i < 3; i++) await backup({ db: 'sentinel-demo', out, keep: 2 }, client)
  assert.equal(fs.readdirSync(out).filter((n) => n.startsWith('sentinel-demo-')).length, 2)
})

test('folder names are matched with the database name escaped, never as a pattern', () => {
  const names = ['sentinel_demo-20261101T010000000Z', 'sentinelXdemo-20261101T010000000Z']
  assert.deepEqual(selectExpired(names, 'sentinel_demo', 1), [])
  assert.deepEqual(selectExpired([...names, 'sentinel_demo-20261102T010000000Z'], 'sentinel_demo', 1), [
    'sentinel_demo-20261101T010000000Z',
  ])
})

test('drill restores into a scratch database, matches counts and indexes, and drops it', async () => {
  const [latest] = fs.readdirSync(out).filter((n) => n.startsWith('sentinel-demo-')).sort().reverse()
  const report = await drill(path.join(out, latest), client)
  assert.deepEqual(report.problems, [])
  assert.equal(report.collections.threatlogs.documents, 1203)
  assert.equal(report.collections.authsessions.documents, 1) // counted before the TTL index exists
  assert.equal(report.collections.containmentactions.missingIndexes, 0)
  const names = (await client.db().admin().listDatabases()).databases.map((d) => d.name)
  assert.equal(names.some((n) => n.startsWith(DRILL_PREFIX)), false)
  assert.equal(await client.db('sentinel-demo').collection('threatlogs').countDocuments(), 1203) // source untouched
})

test('drill refuses a scratch database that already has data', async () => {
  const [latest] = fs.readdirSync(out).filter((n) => n.startsWith('sentinel-demo-')).sort().reverse()
  const now = new Date('2030-01-01T00:00:00Z')
  const name = DRILL_PREFIX + '20300101T000000000Z'
  await client.db(name).collection('keep').insertOne({ x: 1 })
  await assert.rejects(drill(path.join(out, latest), client, now), /already has collections/)
  assert.equal(await client.db(name).collection('keep').countDocuments(), 1)
  await client.db(name).dropDatabase()
})
