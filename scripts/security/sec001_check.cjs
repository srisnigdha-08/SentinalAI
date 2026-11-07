#!/usr/bin/env node
'use strict'
/**
 * SEC-001 read-only verification (owner-run). Answers, per account record:
 *   - does any password leaked in Git history still unlock it?           (bcrypt compare; match flag only)
 *   - how many unrevoked, unexpired sessions predate its last password change?
 *
 * Never prints, logs or writes a password, hash or token. Only reads (find / countDocuments); it creates, updates
 * and deletes nothing. The leaked candidates are read in memory from the two SEC-001 commits in this repository;
 * only their number is printed.
 *
 *   node scripts/security/sec001_check.cjs                         # sentinel-db and sentinel-demo on 127.0.0.1:27017
 *   node scripts/security/sec001_check.cjs --mongo <uri> --db sentinel-db [--db sentinel-demo]
 *
 * Exit code: 0 = no leaked password valid and no pre-change session open; 1 = SEC-001 not resolved; 2 = error.
 * (--candidates-file <path> replaces the Git source; used by the tests with synthetic values only.)
 */
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..', '..')
const req = (m) => require(require.resolve(m, { paths: [path.join(ROOT, 'backend')] }))
const SOURCES = [
  ['315700c', 'scratch/run_browser_script.mjs'],
  ['a7fa029', 'scratch/run_all_verify.ps1'],
]
const ASSIGN = /\b[$\w.]*pass(?:word|wd)?\w*['"]?\s*[:=]\s*(['"`])([^'"`\r\n]{6,200})\1/gi

function arg(name, all = false) {
  const out = []
  process.argv.forEach((a, i) => a === name && process.argv[i + 1] && out.push(process.argv[i + 1]))
  return all ? out : out[0]
}

function candidatesFromText(text) {
  const values = new Set()
  for (const m of text.matchAll(ASSIGN)) {
    const v = m[2]
    if (/^\$|\$\{|^<|^(?:your|change|example|placeholder)/i.test(v)) continue // variables, templates, placeholders
    values.add(v)
  }
  return values
}

function loadCandidates() {
  const file = arg('--candidates-file')
  if (file) return new Set(fs.readFileSync(file, 'utf8').split(/\r?\n/).filter(Boolean))
  const all = new Set()
  for (const [commit, p] of SOURCES) {
    const text = execFileSync('git', ['-C', ROOT, 'show', `${commit}:${p}`], { encoding: 'utf8', maxBuffer: 16 << 20 })
    for (const v of candidatesFromText(text)) all.add(v)
  }
  return all
}

async function checkDatabase(client, dbName, candidates, bcrypt) {
  const db = client.db(dbName)
  const users = await db
    .collection('users')
    .find({}, { projection: { email: 1, role: 1, status: 1, password: 1, passwordChangedAt: 1, lastLogin: 1 } })
    .toArray()
  const now = new Date()
  const rows = []
  for (const u of users) {
    let leakedValid = false
    if (typeof u.password === 'string') {
      for (const c of candidates) {
        if (await bcrypt.compare(c, u.password)) {
          leakedValid = true
          break
        }
      }
    }
    const open = { user: u._id, revokedAt: null, expiresAt: { $gt: now } }
    const openSessions = await db.collection('authsessions').countDocuments(open)
    const preChange = u.passwordChangedAt
      ? await db.collection('authsessions').countDocuments({ ...open, createdAt: { $lt: u.passwordChangedAt } })
      : openSessions
    rows.push({
      db: dbName,
      email: u.email,
      role: u.role,
      status: u.status,
      leakedValid,
      passwordChanged: u.passwordChangedAt ? u.passwordChangedAt.toISOString().slice(0, 10) : 'never',
      openSessions,
      preChangeOpen: preChange,
    })
  }
  return rows
}

async function main() {
  const uri = arg('--mongo') || 'mongodb://127.0.0.1:27017'
  const dbs = arg('--db', true)
  const names = dbs.length ? dbs : ['sentinel-db', 'sentinel-demo']
  const bcrypt = req('bcryptjs')
  const { MongoClient } = req('mongodb')
  const candidates = loadCandidates()
  console.log(`SEC-001 check (read-only). Leaked candidate values loaded: ${candidates.size} (not shown).`)
  if (!candidates.size) throw new Error('no candidate values found; refusing to report "resolved"')
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000, readPreference: 'primaryPreferred' })
  await client.connect()
  let unresolved = 0
  try {
    for (const name of names) {
      const rows = await checkDatabase(client, name, candidates, bcrypt)
      console.log(`\n${name}: ${rows.length} account(s)`)
      for (const r of rows) {
        const bad = r.leakedValid || r.preChangeOpen > 0
        if (bad) unresolved++
        console.log(
          `  ${bad ? 'OPEN    ' : 'ok      '} ${r.email.padEnd(28)} ${String(r.role).padEnd(8)} ${String(r.status).padEnd(9)} ` +
            `leaked password valid: ${r.leakedValid ? 'YES' : 'no '}  password changed: ${r.passwordChanged}  ` +
            `open sessions: ${r.openSessions} (pre-change: ${r.preChangeOpen})`
        )
      }
    }
  } finally {
    await client.close()
  }
  console.log(
    unresolved
      ? `\nSEC-001 NOT resolved: ${unresolved} account record(s) still affected.`
      : '\nNo leaked password is valid and no pre-change session is open in the checked databases.'
  )
  return unresolved ? 1 : 0
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`SEC-001 check failed: ${err.message}`)
      process.exit(2)
    }
  )
}
module.exports = { candidatesFromText, checkDatabase }
