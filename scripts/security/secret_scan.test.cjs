'use strict'
// node --test scripts/security/secret_scan.test.cjs
const test = require('node:test')
const assert = require('node:assert/strict')
const { execFileSync, spawnSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { scanText } = require('./secret_scan.cjs')

const rules = (file, text) => scanText(file, text).map((h) => h.rule)
const SCANNER = path.join(__dirname, 'secret_scan.cjs')
// Built by concatenation so this file holds no literal private-key header for scanners to flag
const KEY_HEADER = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'
const LEAK = '9f2c4e7a1b3d5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061728394a5b6c7d8e'

test('the shapes of the SEC-001 leak are caught', () => {
  assert.deepEqual(rules('scratch/run.mjs', `  HONEYPOT_API_KEY: '${LEAK}',`), ['secret-assignment'])
  assert.deepEqual(rules('scratch/run.ps1', '$env:VERIFY_ADMIN_PASSWORD = "Sunflower#Ridge2026"'), ['secret-assignment'])
  assert.deepEqual(rules('deployment/.env', 'JWT_SECRET=4b1d9e0c7a2f58e3b6d4c1a09f8e7d6c'), ['secret-assignment'])
  assert.deepEqual(rules('a.json', '{ "password": "Q7v!pL2rX9zz" }'), ['secret-assignment'])
  assert.deepEqual(rules('a.js', `const SENTINEL_KEY = '${LEAK}'`), ['secret-assignment']) // env-style *_KEY
  assert.deepEqual(rules('a.js', "const cacheKey = 'user:1234:profile'"), []) // camelCase identifier
})

test('credentialed URIs of any scheme, private keys and token formats are caught', () => {
  assert.deepEqual(rules('backend/config/x.js', "const u = 'mongodb://app:Q7v!pL2rX9@db:27017/sentinel-db'"), ['uri-password'])
  assert.deepEqual(rules('x.py', 'URL = "postgres://svc:Kp9#xLm2qW@db/app"'), ['uri-password'])
  assert.deepEqual(rules('k.txt', KEY_HEADER), ['private-key'])
  assert.deepEqual(rules('a.js', "const t = 'ghp_" + 'a'.repeat(36) + "'"), ['github-token'])
})

test('test data is recognised by whole words only', () => {
  assert.deepEqual(rules('a.js', "const PASSWORD = 'Contest2026!'"), ['secret-assignment']) // "test" inside a word
  assert.deepEqual(rules('a.js', "const PASSWORD = 'LatestKey#2026'"), ['secret-assignment'])
  assert.deepEqual(rules('a.js', "const PASSWORD = 'unit-access-secret'"), [])
})

test('references, placeholders, paths, test files and reasoned markers are not findings', () => {
  for (const [file, line] of [
    ['a.js', 'const HONEYPOT_API_KEY = process.env.HONEYPOT_API_KEY'],
    ['a.py', 'headers = {"X-API-Key": api_key}'],
    ['docker-compose.yml', '      MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD:?set it}'],
    ['docker-compose.yml', '      - ./deployment/metrics_token:/etc/prometheus/metrics_token:ro'],
    ['.env.example', 'HONEYPOT_API_KEY=CHANGE_ME_generate_with_openssl_rand_hex_32'],
    ['backend/tests/x.test.js', "process.env.JWT_SECRET = 'unit-access-secret-for-session-tests'"],
    ['a.js', "const SECRET = 'Qv8!kLm2Zx9#' // secret-scan: allow (documented example)"],
    ['a.js', "MONGO_URI: 'mongodb://${user}:${pass}@mongo:27017/db'"],
  ]) {
    assert.deepEqual(rules(file, line), [], `${file}: ${line}`)
  }
})

test('an allow marker without a reason does not suppress a finding', () => {
  assert.deepEqual(rules('a.js', "const SECRET = 'Qv8!kLm2Zx9#' // secret-scan: allow"), ['secret-assignment'])
  assert.deepEqual(rules('a.js', "const SECRET = 'Qv8!kLm2Zx9#' // secret-scan: allow ()"), ['secret-assignment'])
})

test('allow-list entries are exact paths (a sibling file is still scanned)', () => {
  assert.deepEqual(rules('honeypot/build_honeyfs.py', KEY_HEADER), [])
  assert.deepEqual(rules('honeypot/build_honeyfs.py.orig.py', KEY_HEADER), ['private-key'])
})

test('backup copies are scanned as the file type they copy', () => {
  assert.deepEqual(rules('backend/server.js.bak-phase6-20261015', `const SENTINEL_KEY = '${LEAK}'`), ['secret-assignment'])
  assert.deepEqual(rules('deployment/.env.bak', 'JWT_SECRET=4b1d9e0c7a2f58e3b6d4c1a09f8e7d6c'), ['secret-assignment'])
})

// A throwaway repository: commit a secret, delete it in the next commit, scan the range.
function tempRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-scan-test-'))
  const g = (...a) => execFileSync('git', ['-C', dir, ...a], { encoding: 'utf8' })
  g('init', '-q')
  g('config', 'user.email', 'scan@example.invalid')
  g('config', 'user.name', 'scan test')
  g('config', 'core.autocrlf', 'false')
  fs.mkdirSync(path.join(dir, 'scripts', 'security'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'README.md'), 'start\n')
  g('add', '.')
  g('commit', '-qm', 'base')
  return { dir, g }
}
const run = (dir, args) => spawnSync(process.execPath, [SCANNER, ...args], { cwd: dir, encoding: 'utf8' })

test('a secret added and then deleted inside the pushed range is reported, without any part of its value', () => {
  const { dir, g } = tempRepo()
  const base = g('rev-parse', 'HEAD').trim()
  fs.writeFileSync(path.join(dir, 'deploy.sh'), `export HONEYPOT_API_KEY="${LEAK}"\n`)
  g('add', '.')
  g('commit', '-qm', 'add key')
  fs.unlinkSync(path.join(dir, 'deploy.sh'))
  g('add', '-A')
  g('commit', '-qm', 'remove key')
  assert.equal(run(dir, []).status, 0, 'the final tree is clean')
  const r = run(dir, ['--range', `${base}..HEAD`])
  assert.equal(r.status, 1)
  assert.match(r.stdout, /deploy\.sh:1 +\[secret-assignment\] +HONEYPOT_API_KEY = \(64 chars\)/)
  for (let i = 0; i + 4 <= LEAK.length; i++) assert.ok(!r.stdout.includes(LEAK.slice(i, i + 4)), 'output contains part of the value')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('baseline entries (commit, file, rule) are not reported again; new ones are', () => {
  const { dir, g } = tempRepo()
  fs.writeFileSync(path.join(dir, 'old.sh'), `export API_KEY="${LEAK}"\n`)
  g('add', '.')
  g('commit', '-qm', 'old leak')
  assert.equal(run(dir, ['--history', '--write-baseline']).status, 0)
  assert.equal(run(dir, ['--history']).status, 0, 'baselined history passes')
  fs.writeFileSync(path.join(dir, 'new.sh'), 'export DB_PASSWORD="Kp9#xLm2qWzz"\n')
  g('add', '.')
  g('commit', '-qm', 'new leak')
  const r = run(dir, ['--history'])
  assert.equal(r.status, 1)
  assert.match(r.stdout, /new\.sh:1/)
  assert.doesNotMatch(r.stdout, /old\.sh/)
  fs.rmSync(dir, { recursive: true, force: true })
})
