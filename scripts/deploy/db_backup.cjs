#!/usr/bin/env node
'use strict'
/**
 * Encrypted, oplog-consistent backup and restore of the Compose replica set.
 *
 *   node scripts/deploy/db_backup.cjs backup  --project P --compose-file F... --compose-env E --out DIR --recipient age1... [--keep N]
 *   node scripts/deploy/db_backup.cjs verify  --backup FILE
 *   node scripts/deploy/db_backup.cjs restore --project P --compose-file F... --compose-env E --backup FILE --identity KEY --confirm-restore P
 *
 * Backups need only the age public key; the private key is used only to restore and is refused if it sits with the
 * backups. Plaintext exists only in the pipe between mongodump and age, and is never written to disk. A restore replaces
 * every database in the backup, so it runs only against a named Compose project, confirmed by repeating that name.
 * It is a full restore because mongorestore rejects --oplogReplay combined with a namespace filter. The target must be
 * empty: --drop replaces the users mid-restore and invalidates the restore's own login, which left a partial restore
 * when tested, and without --drop existing documents would be silently kept.
 */
const { spawn, spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

// mongorestore prints the oplog count before its index rebuild lines, so a short tail loses it (run 42637455517).
const STDERR_KEPT_CHARS = 256 * 1024
const NAME = /^sentinel-backup-\d{8}T\d{6}Z\.archive\.gz\.age$/
const DUMP_COMMAND = 'mongodump -u sentinel_backup -p "$SENTINEL_BACKUP_PASSWORD" --authenticationDatabase admin --oplog --archive --gzip --quiet'
const RESTORE_COMMAND = 'mongorestore -u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --oplogReplay --archive --gzip'
const EMPTY_TARGET_COMMAND =
  'mongosh --quiet -u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin admin --eval "const used = db.adminCommand({ listDatabases: 1 }).databases.map((d) => d.name).filter((n) => ![\'admin\', \'config\', \'local\'].includes(n)); print(used.join(\',\')); quit(used.length ? 3 : 0)"'

const recipientProblem = (value) => {
  if (/^AGE-SECRET-KEY-/i.test(value || '')) return 'give the age public key: a private key must never be used to encrypt'
  return /^age1[0-9a-z]{58}$/.test(value || '') ? null : 'recipient is not an age public key (age1...)'
}

function keySeparationProblem(backupFile, identityFile) {
  const dir = path.resolve(path.dirname(backupFile)) + path.sep
  const identity = path.resolve(identityFile)
  return identity.startsWith(dir) ? 'the recovery key must not be stored with the backups' : null
}

const backupName = (date = new Date()) =>
  `sentinel-backup-${date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')}.archive.gz.age`

function selectExpired(names, keep) {
  if (!Number.isInteger(keep) || keep < 1) throw new Error('keep must be at least 1')
  const backups = names.filter((n) => NAME.test(n)).sort()
  return backups.slice(0, Math.max(0, backups.length - keep))
}

const sha256File = (file) =>
  new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    fs.createReadStream(file)
      .on('data', (d) => hash.update(d))
      .on('end', () => resolve(hash.digest('hex')))
      .on('error', reject)
  })

async function writeChecksum(file) {
  const digest = await sha256File(file)
  fs.writeFileSync(`${file}.sha256`, `${digest}  ${path.basename(file)}\n`, { mode: 0o600 })
  return digest
}

async function verifyChecksum(file) {
  if (!fs.existsSync(`${file}.sha256`)) throw new Error('backup has no checksum file')
  const expected = fs.readFileSync(`${file}.sha256`, 'utf8').split(/\s+/)[0]
  if ((await sha256File(file)) !== expected) throw new Error('backup checksum does not match: refusing to use it')
  return true
}

const appliedOplogEntries = (output) => {
  const match = /applied (\d+) oplog entries/.exec(output)
  return match ? Number(match[1]) : null
}

const composeArgs = (o, ...rest) => ['compose', '-p', o.project, '--env-file', o.envFile, ...o.files.flatMap((f) => ['-f', f]), ...rest]

/** Pipes source into sink and rejects, with both stderr tails, if either process fails. */
function pipe(source, sink, label) {
  const collect = (proc) => {
    let err = ''
    proc.stderr.on('data', (d) => (err = (err + d).slice(-STDERR_KEPT_CHARS)))
    return new Promise((resolve, reject) => {
      proc.on('error', reject)
      proc.on('close', (code) => resolve({ code, err }))
    })
  }
  const done = Promise.all([collect(source), collect(sink)])
  sink.stdin.on('error', () => {}) // EPIPE when the sink exits first; its exit code reports the failure
  source.stdout.pipe(sink.stdin)
  return done.then(([a, b]) => {
    if (a.code !== 0 || b.code !== 0) throw new Error(`${label} failed: ${a.code}/${b.code} ${a.err.slice(-2000)} ${b.err.slice(-2000)}`.trim())
    return b.err
  })
}

async function backup(o) {
  fs.mkdirSync(o.out, { recursive: true, mode: 0o700 })
  const name = backupName()
  const file = path.join(o.out, name)
  const part = `${file}.part`
  const started = Date.now()
  const dump = spawn('docker', composeArgs(o, 'exec', '-T', 'mongo', 'sh', '-c', DUMP_COMMAND), { cwd: o.cwd, stdio: ['ignore', 'pipe', 'pipe'] })
  const age = spawn(o.ageBin, ['-r', o.recipient, '-o', part], { stdio: ['pipe', 'ignore', 'pipe'] })
  try {
    await pipe(dump, age, 'backup')
  } catch (err) {
    fs.rmSync(part, { force: true })
    throw err
  }
  fs.chmodSync(part, 0o600)
  fs.renameSync(part, file)
  const digest = await writeChecksum(file)
  const removed = o.keep ? selectExpired(fs.readdirSync(o.out), o.keep) : []
  for (const old of removed) {
    fs.rmSync(path.join(o.out, old))
    fs.rmSync(path.join(o.out, `${old}.sha256`), { force: true })
  }
  return { file, bytes: fs.statSync(file).size, sha256: digest, seconds: (Date.now() - started) / 1000, removed }
}

async function restore(o) {
  const separated = keySeparationProblem(o.backup, o.identity)
  if (separated) throw new Error(separated)
  if (process.platform !== 'win32' && fs.statSync(o.identity).mode & 0o077) throw new Error('the recovery key is readable by other users')
  await verifyChecksum(o.backup)
  const empty = spawnSync('docker', composeArgs(o, 'exec', '-T', 'mongo', 'sh', '-c', EMPTY_TARGET_COMMAND), { cwd: o.cwd, encoding: 'utf8' })
  if (empty.status === 3) throw new Error(`the target is not empty (${empty.stdout.trim()}): restore only onto a new volume`)
  if (empty.status !== 0) throw new Error(`could not inspect the target: ${(empty.stderr || '').slice(-300)}`)
  const started = Date.now()
  const age = spawn(o.ageBin, ['-d', '-i', o.identity, o.backup], { stdio: ['ignore', 'pipe', 'pipe'] })
  const load = spawn('docker', composeArgs(o, 'exec', '-T', 'mongo', 'sh', '-c', RESTORE_COMMAND), { cwd: o.cwd, stdio: ['pipe', 'ignore', 'pipe'] })
  const output = await pipe(age, load, 'restore')
  return { seconds: (Date.now() - started) / 1000, appliedOplogEntries: appliedOplogEntries(output) }
}

function parse(argv) {
  const o = { files: [], ageBin: process.env.AGE_BIN || 'age', command: argv[0] }
  const single = { '--project': 'project', '--compose-env': 'envFile', '--out': 'out', '--recipient': 'recipient', '--keep': 'keep', '--backup': 'backup', '--identity': 'identity', '--confirm-restore': 'confirm', '--cwd': 'cwd' }
  for (let i = 1; i < argv.length; i += 2) {
    if (argv[i] === '--compose-file') o.files.push(argv[i + 1])
    else if (single[argv[i]]) o[single[argv[i]]] = argv[i + 1]
    else throw new Error(`Unknown option ${argv[i]}`)
  }
  if (o.keep !== undefined) o.keep = Number(o.keep)
  return o
}

function validate(o) {
  if (!['backup', 'verify', 'restore'].includes(o.command)) return 'Usage: db_backup.cjs backup|verify|restore (see the file header)'
  if (o.command === 'verify') return o.backup ? null : '--backup is required'
  if (!o.project || !o.envFile || !o.files.length) return '--project, --compose-env and --compose-file are required'
  if (o.command === 'backup') {
    if (!o.out) return '--out is required'
    return recipientProblem(o.recipient)
  }
  if (!o.backup || !o.identity) return '--backup and --identity are required'
  return o.confirm === o.project ? null : 'a restore replaces data: repeat the project name with --confirm-restore'
}

if (require.main === module) {
  let options
  let problem
  try {
    options = parse(process.argv.slice(2))
    problem = validate(options)
  } catch (err) {
    problem = err.message
  }
  if (problem) {
    console.error(problem)
    process.exit(2)
  }
  const action = options.command === 'backup' ? backup(options) : options.command === 'restore' ? restore(options) : verifyChecksum(options.backup).then(() => ({ verified: true }))
  action.then(
    (result) => console.log(JSON.stringify(result)),
    (err) => {
      console.error(err.message)
      process.exit(1)
    }
  )
}

module.exports = { DUMP_COMMAND, RESTORE_COMMAND, EMPTY_TARGET_COMMAND, appliedOplogEntries, pipe, recipientProblem, keySeparationProblem, backupName, selectExpired, writeChecksum, verifyChecksum }
