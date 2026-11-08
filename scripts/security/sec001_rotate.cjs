#!/usr/bin/env node
'use strict'
/**
 * SEC-001 credential rotation for exactly the nine affected account records (owner-run).
 *
 * Does what the application's own password change does (controllers/authController.updatePassword), per record:
 *   - new bcrypt hash, cost 12 (as models/User.js), of a fresh random password;
 *   - passwordChangedAt = now; mustChangePassword = true (the generated password is a one-time temporary: the
 *     user can sign in only to set their own);
 *   - authVersion + 1 (and tokenVersion + 1): every existing access and refresh token stops working at once,
 *     because every request compares the session's version with the user's (services/authSessionService.load);
 *   - every unrevoked session marked revoked, revocationReason 'sec001-rotation'.
 * Nothing else in any document changes; no other account is read beyond the target lookup.
 *
 * MODES
 *   preflight (default)  Read-only. Resolves the targets, checks each exists exactly once, prints the exact planned
 *                        changes and a fingerprint of the current state. Writes nothing, generates nothing.
 *   apply                Needs ALL of: --confirm <fingerprint from preflight> (refused if anything changed since),
 *                        --authorize "ROTATE 9 SEC-001 ACCOUNTS", --backup-dir <dir with a mongodump of every target
 *                        database>, --credentials-dir <owner-only directory>, and a loopback MongoDB.
 *                        Before the first database write it creates the credentials file (owner-only ACL) and a
 *                        journal. Each record is changed by a conditional update that only matches the password hash
 *                        seen at preflight, so a concurrent change is never overwritten.
 *   resume --journal <file>  Finishes an interrupted apply with the SAME generated passwords: records already rotated
 *                        are verified and only their sessions are re-revoked; untouched ones are rotated; a record
 *                        changed by someone else is skipped and reported (CONFLICT), never overwritten.
 *
 * Passwords are never printed or logged; only the credentials file holds them. Exit: 0 ok, 1 incomplete/refused, 2 error.
 */
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { execFileSync, spawnSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..', '..')
const req = (m) => require(require.resolve(m, { paths: [path.join(ROOT, 'backend')] }))

const DEFAULT_TARGETS = [
  ['sentinel-db', 'admin@sentinel.io'],
  ['sentinel-db', 'arjun@sentinel.io'],
  ['sentinel-db', 'priya@sentinel.io'],
  ['sentinel-db', 'sara@sentinel.io'],
  ['sentinel-demo', 'admin@sentinel.io'],
  ['sentinel-demo', 'arjun@sentinel.io'],
  ['sentinel-demo', 'priya@sentinel.io'],
  ['sentinel-demo', 'sara@sentinel.io'],
  ['sentinel-demo', 'pallavi@sentinel.io'],
]
const AUTHORIZE_PHRASE = 'ROTATE 9 SEC-001 ACCOUNTS'
const BCRYPT_COST = 12
const REVOCATION_REASON = 'sec001-rotation'

function args() {
  const a = process.argv.slice(2)
  const out = { mode: 'preflight' }
  if (a[0] && !a[0].startsWith('--')) out.mode = a.shift()
  for (let i = 0; i < a.length; i++) {
    if (!a[i].startsWith('--')) continue
    const k = a[i].slice(2)
    out[k] = a[i + 1] && !a[i + 1].startsWith('--') ? a[++i] : true
  }
  return out
}

function loadTargets(opts) {
  if (!opts['targets-file']) return { list: DEFAULT_TARGETS, custom: false }
  const list = JSON.parse(fs.readFileSync(opts['targets-file'], 'utf8')).map((t) => [t.db, t.email])
  return { list, custom: true }
}

function assertLoopback(uri) {
  const host = new URL(uri.replace(/^mongodb(\+srv)?:/, 'http:')).hostname
  if (!['127.0.0.1', 'localhost', '[::1]', '::1'].includes(host))
    throw new Error(`refusing a non-loopback MongoDB host (${host})`)
  if (/^mongodb\+srv:/.test(uri)) throw new Error('refusing mongodb+srv URIs')
}

// 20 characters from a 70-symbol alphabet (~122 bits), at least one upper, lower, digit and symbol.
function generatePassword() {
  const sets = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!#%+=?@^_~-']
  const all = sets.join('')
  for (;;) {
    const pw = Array.from({ length: 20 }, () => all[crypto.randomInt(all.length)]).join('')
    if (sets.every((s) => [...pw].some((c) => s.includes(c)))) return pw
  }
}

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex')

async function resolveTargets(client, list) {
  const rows = []
  for (const [db, email] of list) {
    const users = await client
      .db(db)
      .collection('users')
      .find(
        { email: String(email).toLowerCase() },
        { projection: { _id: 1, email: 1, role: 1, status: 1, password: 1, authVersion: 1, tokenVersion: 1 } }
      )
      .toArray()
    const openSessions = users.length === 1
      ? await client.db(db).collection('authsessions').countDocuments({ user: users[0]._id, revokedAt: null })
      : 0
    rows.push({ db, email: String(email).toLowerCase(), matches: users.length, user: users[0], openSessions })
  }
  return rows
}

function fingerprintOf(rows) {
  // Changes when any target's id, password hash or authVersion changes (or the target set changes).
  const material = rows
    .map((r) => [r.db, r.email, String(r.user?._id), sha(String(r.user?.password)), r.user?.authVersion ?? 0].join('|'))
    .sort()
    .join('\n')
  return sha(material).slice(0, 16)
}

function printPlan(rows) {
  console.log('Planned changes per record (nothing else in any document changes):')
  console.log('  users:        password <- new bcrypt(cost 12) of a generated 20-char password;')
  console.log('                passwordChangedAt <- now; mustChangePassword <- true; authVersion +1; tokenVersion +1')
  console.log(`  authsessions: every unrevoked session of the user: revokedAt <- now, revocationReason <- '${REVOCATION_REASON}'`)
  console.log('')
  for (const r of rows) {
    const state = r.matches === 1 ? 'found' : r.matches === 0 ? 'NOT FOUND' : `AMBIGUOUS (${r.matches})`
    const u = r.user || {}
    console.log(
      `  ${r.db.padEnd(14)} ${r.email.padEnd(24)} ${state.padEnd(10)} role=${String(u.role).padEnd(8)} status=${String(u.status).padEnd(9)} ` +
        `authVersion ${u.authVersion ?? 0} -> ${(u.authVersion ?? 0) + 1}  sessions to revoke: ${r.openSessions}`
    )
  }
}

// ---------- owner-only files ----------
function restrictToOwner(target) {
  if (process.platform === 'win32') {
    const who = `${process.env.USERDOMAIN || os.hostname()}\\${process.env.USERNAME || os.userInfo().username}`
    // Directories pass the owner-only entry on to new files. Without an inheritable entry a new file takes the
    // process token's default ACL, which can include a logon-session SID that icacls cannot remove by name.
    const grant = fs.statSync(target).isDirectory() ? `${who}:(OI)(CI)F` : `${who}:F`
    execFileSync('icacls', [target, '/inheritance:r', '/grant:r', grant], { stdio: 'ignore' })
    // New files also get explicit ACEs from the process token (e.g. BUILTIN\Administrators, NT AUTHORITY\SYSTEM);
    // /grant:r leaves those, so every principal other than the owner is removed explicitly.
    const principals = (acl) =>
      acl
        .split(/\r?\n/)
        .map((l) => (l.startsWith(target) ? l.slice(target.length) : l).trim())
        .map((l) => l.match(/^(.+?):\(/)?.[1])
        .filter(Boolean)
    for (const p of principals(execFileSync('icacls', [target], { encoding: 'utf8' }))) {
      if (p.toLowerCase() !== who.toLowerCase()) execFileSync('icacls', [target, '/remove:g', p], { stdio: 'ignore' })
    }
    const left = principals(execFileSync('icacls', [target], { encoding: 'utf8' }))
    // Several entries are fine (Windows can keep "this folder" and "inherit" entries apart); all must be the owner's.
    if (!left.length || left.some((p) => p.toLowerCase() !== who.toLowerCase()))
      throw new Error(`could not restrict ${target} to ${who}`)
  } else {
    fs.chmodSync(target, fs.statSync(target).isDirectory() ? 0o700 : 0o600)
  }
}

// The file is created empty, restricted and verified first; only then are the passwords written into it.
function writeOwnerOnly(file, content) {
  fs.closeSync(fs.openSync(file, 'wx', 0o600)) // never overwrite an existing file
  restrictToOwner(file)
  const fd = fs.openSync(file, 'r+')
  try {
    fs.writeSync(fd, content)
    fs.fsyncSync(fd)
  } finally {
    fs.closeSync(fd)
  }
}

// Atomic replace that keeps the owner-only ACL: the temp file is restricted before it replaces the journal.
function saveJournal(file, journal) {
  const tmp = file + '.tmp'
  fs.rmSync(tmp, { force: true })
  writeOwnerOnly(tmp, JSON.stringify(journal, null, 2))
  fs.renameSync(tmp, file)
}

function findMongorestore(explicit) {
  const candidates = [explicit, 'C:\\Program Files\\MongoDB\\Tools\\100\\bin\\mongorestore.exe'].filter(Boolean)
  for (const c of candidates) if (fs.existsSync(c)) return c
  try {
    execFileSync('mongorestore', ['--version'], { stdio: 'ignore' })
    return 'mongorestore'
  } catch {
    return null
  }
}

// A database counts as backed up when either
//   - a mongodump --out layout holds <db>/users.bson(.gz) and <db>/authsessions.bson(.gz) (any depth up to 3), or
//   - an archive named <db>-*.archive[.gz] is confirmed by `mongorestore --dryRun` (restores nothing) to contain
//     both <db>.users and <db>.authsessions. A file name alone is never accepted for an archive.
function checkBackup(dir, dbs, { uri, mongorestore } = {}) {
  if (!dir || !fs.existsSync(dir)) throw new Error('--backup-dir is required and must exist')
  const layout = new Map()
  const archives = []
  const walk = (d, depth) => {
    if (depth > 3) return
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name)
      if (e.isDirectory()) walk(p, depth + 1)
      else if (fs.statSync(p).size > 0) {
        const m = e.name.match(/^(users|authsessions)\.bson(\.gz)?$/)
        if (m) layout.set(path.basename(d), new Set([...(layout.get(path.basename(d)) || []), m[1]]))
        if (/\.archive(\.gz)?$/.test(e.name)) archives.push(p)
      }
    }
  }
  walk(dir, 0)
  const ok = new Set([...layout].filter(([, s]) => s.has('users') && s.has('authsessions')).map(([db]) => db))
  const tool = findMongorestore(mongorestore)
  for (const db of dbs.filter((d) => !ok.has(d))) {
    for (const a of archives.filter((p) => path.basename(p).startsWith(db + '-'))) {
      if (!tool) throw new Error('mongorestore not found; needed to verify archive backups (--mongorestore <path>)')
      const argv = [`--uri=${uri}`, `--archive=${a}`, '--dryRun', '-v', `--nsInclude=${db}.*`]
      if (a.endsWith('.gz')) argv.push('--gzip')
      const r = spawnSync(tool, argv, { encoding: 'utf8' }) // mongorestore logs to stderr
      const out = String(r.stdout || '') + String(r.stderr || '')
      const has = (c) => new RegExp('`' + db.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\.' + c + '`').test(out)
      if (/dry run completed/.test(out) && has('users') && has('authsessions')) {
        ok.add(db)
        break
      }
    }
  }
  const missing = dbs.filter((d) => !ok.has(d))
  if (missing.length) throw new Error(`no verified backup (users + authsessions) found for: ${missing.join(', ')}`)
}

// ---------- per-record operations ----------
async function rotateOne(client, entry, bcrypt, now) {
  const users = client.db(entry.db).collection('users')
  const res = await users.updateOne(
    { _id: entry._id, password: entry.oldHash }, // only the state seen at preflight
    {
      $set: { password: entry.newHash, passwordChangedAt: now, mustChangePassword: true },
      $inc: { authVersion: 1, tokenVersion: 1 },
    }
  )
  return res.modifiedCount === 1
}

// Only sessions created before the rotation: a session opened afterwards with the new temporary password is legitimate.
async function revokeSessions(client, entry, now, rotatedAt = now) {
  const r = await client
    .db(entry.db)
    .collection('authsessions')
    .updateMany(
      { user: entry._id, revokedAt: null, createdAt: { $lte: rotatedAt } },
      { $set: { revokedAt: now, revocationReason: REVOCATION_REASON } }
    )
  return r.modifiedCount
}

async function process9(client, journal, journalFile, credentials, bcrypt, opts) {
  const failAfter = journal.custom && process.env.SEC001_TEST_FAIL_AFTER ? Number(process.env.SEC001_TEST_FAIL_AFTER) : Infinity
  let done = 0
  let problems = 0
  for (const entry of journal.entries) {
    const { ObjectId } = req('mongodb')
    const e = { ...entry, _id: new ObjectId(entry.id) }
    const now = new Date()
    if (entry.state === 'done') {
      // re-check sessions only (a resume after a crash between the two writes)
      const extra = await revokeSessions(client, e, now, new Date(entry.at))
      if (extra) console.log(`  ${entry.db.padEnd(14)} ${entry.email.padEnd(24)} late sessions revoked: ${extra}`)
      continue
    }
    if (done >= failAfter) throw new Error('simulated failure (test only)')
    const current = await client.db(e.db).collection('users').findOne({ _id: e._id }, { projection: { password: 1, passwordChangedAt: 1 } })
    let outcome
    if (!current) outcome = 'MISSING'
    else if (current.password === e.oldHash) outcome = (await rotateOne(client, e, bcrypt, now)) ? 'ROTATED' : 'CONFLICT'
    else if (await bcrypt.compare(credentials[`${e.db}/${e.email}`], current.password)) outcome = 'ALREADY_ROTATED'
    else outcome = 'CONFLICT'
    let revoked = 0
    if (outcome === 'ROTATED') revoked = await revokeSessions(client, e, now)
    else if (outcome === 'ALREADY_ROTATED') revoked = await revokeSessions(client, e, now, current.passwordChangedAt || now)
    else problems++
    entry.state = outcome === 'ROTATED' || outcome === 'ALREADY_ROTATED' ? 'done' : outcome.toLowerCase()
    // the rotation time: later resumes only revoke sessions created before it
    entry.at = (outcome === 'ALREADY_ROTATED' && current.passwordChangedAt ? new Date(current.passwordChangedAt) : now).toISOString()
    entry.revoked = (entry.revoked || 0) + revoked
    saveJournal(journalFile, journal)
    done++
    console.log(`  ${entry.db.padEnd(14)} ${entry.email.padEnd(24)} ${outcome.padEnd(16)} sessions revoked: ${revoked}`)
  }
  return problems
}

async function main() {
  const opts = args()
  const uri = opts.mongo || 'mongodb://127.0.0.1:27017'
  assertLoopback(uri)
  const bcrypt = req('bcryptjs')
  const { MongoClient } = req('mongodb')
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 })
  await client.connect()
  try {
    if (opts.mode === 'resume') {
      const journalFile = opts.journal
      if (!journalFile || !fs.existsSync(journalFile)) throw new Error('resume needs --journal <file>')
      const journal = JSON.parse(fs.readFileSync(journalFile, 'utf8'))
      const credentials = JSON.parse(fs.readFileSync(journal.credentialsFile, 'utf8')).byRecord
      console.log(`SEC-001 rotation RESUME (plan ${journal.fingerprint})`)
      const problems = await process9(client, journal, journalFile, credentials, bcrypt, opts)
      return finish(journal, problems)
    }

    const { list, custom } = loadTargets(opts)
    const rows = await resolveTargets(client, list)
    const fingerprint = fingerprintOf(rows)
    console.log(`SEC-001 rotation ${opts.mode.toUpperCase()} — ${rows.length} target record(s), MongoDB ${uri}`)
    printPlan(rows)
    const bad = rows.filter((r) => r.matches !== 1)
    console.log(`\nfingerprint: ${fingerprint}`)
    if (bad.length) {
      console.log(`REFUSED: ${bad.length} target(s) not found exactly once; nothing will be changed.`)
      return 1
    }
    if (opts.mode === 'preflight') {
      console.log('Preflight only: nothing was written. Apply needs this fingerprint, the authorization phrase and a backup.')
      return 0
    }
    if (opts.mode !== 'apply') throw new Error(`unknown mode ${opts.mode}`)

    // ---- apply guards (all before any write) ----
    if (opts.confirm !== fingerprint) {
      console.log('REFUSED: --confirm does not match the current fingerprint (state changed since preflight, or missing).')
      return 1
    }
    if (opts.authorize !== AUTHORIZE_PHRASE) {
      console.log(`REFUSED: --authorize must be exactly "${AUTHORIZE_PHRASE}".`)
      return 1
    }
    checkBackup(opts['backup-dir'], [...new Set(rows.map((r) => r.db))], { uri, mongorestore: opts.mongorestore })
    const credDir = opts['credentials-dir']
    if (!credDir) throw new Error('--credentials-dir is required')
    fs.mkdirSync(credDir, { recursive: true })
    restrictToOwner(credDir)
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    const credentialsFile = path.join(credDir, `sec001-credentials-${fingerprint}-${stamp}.json`)
    const journalFile = path.join(credDir, `sec001-journal-${fingerprint}-${stamp}.json`)

    // Generate and persist every password BEFORE the first database write.
    const byRecord = {}
    const entries = []
    for (const r of rows) {
      const pw = generatePassword()
      byRecord[`${r.db}/${r.email}`] = pw
      entries.push({
        db: r.db,
        email: r.email,
        id: String(r.user._id),
        oldHash: r.user.password,
        newHash: await bcrypt.hash(pw, BCRYPT_COST),
        state: 'pending',
      })
    }
    writeOwnerOnly(
      credentialsFile,
      JSON.stringify(
        {
          note: 'SEC-001 temporary passwords. Each user must set a new password at first sign-in. Move to a password manager, then delete this file.',
          createdAt: new Date().toISOString(),
          byRecord,
        },
        null,
        2
      )
    )
    const journal = { fingerprint, custom, credentialsFile, createdAt: new Date().toISOString(), entries }
    writeOwnerOnly(journalFile, JSON.stringify(journal, null, 2))
    console.log(`\ncredentials file (owner-only): ${credentialsFile}`)
    console.log(`journal (resume with: resume --journal <this>): ${journalFile}`)
    const problems = await process9(client, journal, journalFile, byRecord, bcrypt, opts)
    return finish(journal, problems)
  } finally {
    await client.close()
  }
}

function finish(journal, problems) {
  const done = journal.entries.filter((e) => e.state === 'done').length
  console.log(`\n${done}/${journal.entries.length} record(s) rotated and sessions revoked; problems: ${problems}`)
  if (problems) console.log('Not complete: see CONFLICT / MISSING lines; nothing was overwritten. Investigate before resuming.')
  return done === journal.entries.length ? 0 : 1
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`SEC-001 rotation stopped: ${err.message}`)
      process.exit(2)
    }
  )
}
module.exports = {
  generatePassword,
  fingerprintOf,
  assertLoopback,
  checkBackup,
  restrictToOwner,
  writeOwnerOnly,
  DEFAULT_TARGETS,
  AUTHORIZE_PHRASE,
}
