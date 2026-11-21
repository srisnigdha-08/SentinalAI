#!/usr/bin/env node
'use strict'
/**
 * Backups of a local (standalone, Windows-service) MongoDB database, for the demo and development machines where the
 * MongoDB Database Tools are not installed. The Compose replica set has its own encrypted tool: scripts/deploy/db_backup.cjs.
 *
 *   node scripts/demo/backup-local-db.cjs backup [--db sentinel-demo] [--out DIR] [--keep 7]
 *   node scripts/demo/backup-local-db.cjs verify --backup DIR
 *   node scripts/demo/backup-local-db.cjs drill  --backup DIR
 *
 * backup  streams every collection to <collection>.bson with its index definitions (every option, e.g. sparse/TTL),
 *         writes manifest.json (document counts, SHA-256 per file), verifies the folder, then deletes older backups of
 *         the same database beyond --keep. Only folders this script named are ever deleted.
 * verify  re-hashes the files and re-counts the BSON documents against the manifest. Reads files only.
 * drill   the monthly restore test: restores into a NEW database named sentinel-restore-check-<UTC> (refused if it
 *         already has collections), compares document counts and index keys with the manifest, then drops that scratch
 *         database. It never writes to the source database or any other database.
 *
 * The connection comes from MONGO_URI (default mongodb://127.0.0.1:27017); it is never printed. Default output folder:
 * %USERPROFILE%\.sentinelai\backups (outside the repository). A backup contains password hashes, sessions and raw
 * attacker data: keep it on this machine or an encrypted drive and never commit it.
 */
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')

const BACKEND_MODULES = path.join(__dirname, '..', '..', 'backend', 'node_modules')
const { MongoClient } = require(path.join(BACKEND_MODULES, 'mongodb'))
const BSON = require(path.join(BACKEND_MODULES, 'bson'))

const DB_NAME = /^[A-Za-z0-9_-]{1,63}$/
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')
// <db>-YYYYMMDDTHHMMSSmmmZ: millisecond resolution, so two backups in the same second get different folders.
const FOLDER = (db) => new RegExp(`^${escapeRegExp(db)}-\\d{8}T\\d{9}Z$`)
const DRILL_PREFIX = 'sentinel-restore-check-'
const BATCH = 500

const stamp = (d = new Date()) => d.toISOString().replace(/[-:.]/g, '')
const baseUri = () => {
  const uri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017'
  // Connect to the server only; the database is chosen explicitly with --db / the manifest.
  const u = new URL(uri)
  u.pathname = '/'
  return u.toString()
}

function args(argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true
    else out._.push(argv[i])
  }
  return out
}

const sha256 = (file) =>
  new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256')
    fs.createReadStream(file)
      .on('data', (d) => h.update(d))
      .on('end', () => resolve(h.digest('hex')))
      .on('error', reject)
  })

/** Counts the BSON documents in a file by walking their length prefixes (no document is deserialised). */
function countBsonDocuments(file) {
  const buf = fs.readFileSync(file)
  let offset = 0
  let n = 0
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error(`${path.basename(file)}: truncated document header`)
    const size = buf.readInt32LE(offset)
    if (size < 5 || offset + size > buf.length) throw new Error(`${path.basename(file)}: corrupt document length`)
    offset += size
    n++
  }
  return n
}

function* readBsonDocuments(file) {
  const buf = fs.readFileSync(file)
  let offset = 0
  while (offset < buf.length) {
    const size = buf.readInt32LE(offset)
    yield BSON.deserialize(buf.subarray(offset, offset + size), { promoteValues: false, promoteBuffers: false })
    offset += size
  }
}

/** Oldest-first list of this database's backup folders beyond `keep`; only names matching FOLDER(db) are considered. */
function selectExpired(names, db, keep) {
  if (!Number.isInteger(keep) || keep < 1) throw new Error('--keep must be a whole number of at least 1')
  const own = names.filter((n) => FOLDER(db).test(n)).sort()
  return own.slice(0, Math.max(0, own.length - keep))
}

async function backup({ db, out, keep }, client) {
  if (!DB_NAME.test(db)) throw new Error('invalid --db name')
  fs.mkdirSync(out, { recursive: true })
  const folder = path.join(out, `${db}-${stamp()}`)
  if (fs.existsSync(folder)) throw new Error(`backup folder already exists: ${folder}`)
  const tmp = folder + '.partial'
  fs.mkdirSync(tmp)
  const database = client.db(db)
  const collections = (await database.listCollections({ type: 'collection' }, { nameOnly: true }).toArray())
    .map((c) => c.name)
    .filter((n) => !n.startsWith('system.'))
    .sort()
  if (!collections.length) throw new Error(`database ${db} has no collections (wrong --db?)`)
  const manifest = { format: 'sentinel-local-backup/1', database: db, createdAt: new Date().toISOString(), collections: {} }
  for (const name of collections) {
    const col = database.collection(name)
    const indexes = (await col.indexes()).map(({ ns, ...idx }) => idx) // eslint-disable-line no-unused-vars
    fs.writeFileSync(path.join(tmp, `${name}.metadata.json`), JSON.stringify({ indexes }, null, 2))
    const bsonPath = path.join(tmp, `${name}.bson`)
    const fd = fs.openSync(bsonPath, 'w')
    let count = 0
    try {
      for await (const doc of col.find({}, { batchSize: BATCH })) {
        fs.writeSync(fd, BSON.serialize(doc))
        count++
      }
    } finally {
      fs.closeSync(fd)
    }
    manifest.collections[name] = {
      documents: count,
      bsonSha256: await sha256(bsonPath),
      metadataSha256: await sha256(path.join(tmp, `${name}.metadata.json`)),
    }
  }
  fs.writeFileSync(path.join(tmp, 'manifest.json'), JSON.stringify(manifest, null, 2))
  const problems = await verify(tmp)
  if (problems.length) throw new Error('backup failed verification: ' + problems.join('; '))
  fs.renameSync(tmp, folder) // only a verified backup gets a final name, so pruning never counts a partial one
  const removed = []
  for (const name of selectExpired(fs.readdirSync(out), db, keep)) {
    fs.rmSync(path.join(out, name), { recursive: true, force: true })
    removed.push(name)
  }
  return { folder, collections: collections.length, documents: Object.values(manifest.collections).reduce((s, c) => s + c.documents, 0), removed }
}

/** Returns a list of problems (empty when the backup is intact). Reads files only. */
async function verify(dir) {
  const problems = []
  const manifestPath = path.join(dir, 'manifest.json')
  if (!fs.existsSync(manifestPath)) return ['manifest.json is missing']
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
  for (const [name, entry] of Object.entries(manifest.collections || {})) {
    const bsonPath = path.join(dir, `${name}.bson`)
    const metaPath = path.join(dir, `${name}.metadata.json`)
    if (!fs.existsSync(bsonPath) || !fs.existsSync(metaPath)) {
      problems.push(`${name}: file missing`)
      continue
    }
    if ((await sha256(bsonPath)) !== entry.bsonSha256) problems.push(`${name}: BSON checksum mismatch`)
    if ((await sha256(metaPath)) !== entry.metadataSha256) problems.push(`${name}: metadata checksum mismatch`)
    try {
      const n = countBsonDocuments(bsonPath)
      if (n !== entry.documents) problems.push(`${name}: ${n} documents in file, manifest says ${entry.documents}`)
    } catch (e) {
      problems.push(e.message)
    }
  }
  return problems
}

const indexKey = (idx) =>
  JSON.stringify([idx.key, Boolean(idx.unique), Boolean(idx.sparse), idx.expireAfterSeconds ?? null, idx.partialFilterExpression ?? null])

async function drill(dir, client, now = new Date()) {
  const problems = await verify(dir)
  if (problems.length) throw new Error('backup failed verification: ' + problems.join('; '))
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'))
  const target = DRILL_PREFIX + stamp(now)
  const database = client.db(target)
  if ((await database.listCollections({}, { nameOnly: true }).toArray()).length)
    throw new Error(`refusing: ${target} already has collections`)
  const report = { target, collections: {}, problems: [] }
  try {
    for (const [name, entry] of Object.entries(manifest.collections)) {
      const col = database.collection(name)
      await database.createCollection(name)
      let batch = []
      for (const doc of readBsonDocuments(path.join(dir, `${name}.bson`))) {
        batch.push(doc)
        if (batch.length >= BATCH) {
          await col.insertMany(batch, { ordered: true })
          batch = []
        }
      }
      if (batch.length) await col.insertMany(batch, { ordered: true })
      // Count before building indexes: a restored TTL index could start deleting expired documents.
      const restoredCount = await col.countDocuments({})
      const { indexes } = JSON.parse(fs.readFileSync(path.join(dir, `${name}.metadata.json`), 'utf8'))
      const toCreate = indexes.filter((i) => i.name !== '_id_').map(({ v, ...spec }) => spec) // eslint-disable-line no-unused-vars
      if (toCreate.length) await col.createIndexes(toCreate)
      const expected = new Set(indexes.map(indexKey))
      const restored = new Set((await col.indexes()).map(indexKey))
      const missingIndexes = [...expected].filter((k) => !restored.has(k)).length
      report.collections[name] = { documents: restoredCount, expected: entry.documents, missingIndexes }
      if (restoredCount !== entry.documents) report.problems.push(`${name}: restored ${restoredCount} of ${entry.documents}`)
      if (missingIndexes) report.problems.push(`${name}: ${missingIndexes} index(es) not restored identically`)
    }
  } finally {
    // The scratch database was created by this run (it was empty above); drop it so drills leave nothing behind.
    if (target.startsWith(DRILL_PREFIX)) await database.dropDatabase()
  }
  return report
}

async function main(argv = process.argv.slice(2)) {
  const a = args(argv)
  const command = a._[0]
  if (command === 'verify') {
    if (!a.backup) throw new Error('verify needs --backup DIR')
    const problems = await verify(path.resolve(a.backup))
    console.log(problems.length ? 'VERIFY FAILED\n- ' + problems.join('\n- ') : 'VERIFY OK')
    return problems.length ? 1 : 0
  }
  if (command !== 'backup' && command !== 'drill') {
    console.error('usage: backup [--db NAME] [--out DIR] [--keep N] | verify --backup DIR | drill --backup DIR')
    return 2
  }
  const client = await new MongoClient(baseUri(), { serverSelectionTimeoutMS: 5000, appName: 'sentinel-local-backup' }).connect()
  try {
    if (command === 'backup') {
      const r = await backup(
        {
          db: a.db || 'sentinel-demo',
          out: path.resolve(a.out || path.join(os.homedir(), '.sentinelai', 'backups')),
          keep: a.keep === undefined ? 7 : Number(a.keep),
        },
        client
      )
      console.log(`BACKUP OK  ${r.folder}  (${r.collections} collections, ${r.documents} documents)`)
      if (r.removed.length) console.log(`Removed ${r.removed.length} older backup(s): ${r.removed.join(', ')}`)
      return 0
    }
    if (!a.backup) throw new Error('drill needs --backup DIR')
    const r = await drill(path.resolve(a.backup), client)
    for (const [name, c] of Object.entries(r.collections))
      console.log(`  ${name}: ${c.documents}/${c.expected} documents, ${c.missingIndexes} index differences`)
    console.log(r.problems.length ? 'DRILL FAILED\n- ' + r.problems.join('\n- ') : `DRILL OK (scratch database ${r.target} restored, compared and dropped)`)
    return r.problems.length ? 1 : 0
  } finally {
    await client.close()
  }
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('ERROR: ' + err.message)
      process.exit(1)
    }
  )
}

module.exports = { backup, verify, drill, selectExpired, countBsonDocuments, main, DRILL_PREFIX }
