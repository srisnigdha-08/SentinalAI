'use strict'
// Checks the replica-set overlay's rules and the verifier's comparisons without Docker.
// Run: node --test scripts/deploy/replicaset_verify.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')
const v = require('./replicaset_verify.cjs')

const ROOT = path.join(__dirname, '..', '..')
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8')

const goodConfig = () => ({
  secrets: { mongo_keyfile: { file: '/tmp/key' } },
  services: {
    mongo: {
      entrypoint: ['sh', '/usr/local/bin/mongo-replicaset-entrypoint.sh'],
      command: ['mongod', '--replSet', 'rs0', '--keyFile', '/data/mongo-keyfile', '--bind_ip_all'],
      secrets: [{ source: 'mongo_keyfile' }],
      healthcheck: { test: ['CMD-SHELL', "test -f /tmp/sentinel-mongo-configured && mongosh --eval \"h.setName === 'rs0' && h.isWritablePrimary\""] },
      environment: { MONGO_INITDB_ROOT_USERNAME: 'root' },
    },
    backend: {
      environment: {
        MONGO_URI: 'mongodb://sentinel_app:x@mongo:27017/sentinel-db?authSource=sentinel-db&replicaSet=rs0',
        MONGO_USE_TRANSACTIONS: 'true',
        AUTH_REVOCATION_MODE: 'mongo-stream',
      },
    },
  },
})

test('the intended overlay has no problems', () => {
  assert.deepEqual(v.replicaConfigProblems(goodConfig()), [])
})

for (const [name, mutate] of [
  ['MongoDB published to the host', (c) => (c.services.mongo.ports = [{ host_ip: '127.0.0.1', target: 27017 }])],
  ['no replica-set name', (c) => (c.services.mongo.command = ['mongod', '--keyFile', '/data/mongo-keyfile'])],
  ['no internal authentication', (c) => (c.services.mongo.command = ['mongod', '--replSet', 'rs0'])],
  ['keyfile not delivered as a secret', (c) => (c.services.mongo.secrets = [])],
  ['keyfile placed in the environment', (c) => (c.services.mongo.environment.MONGO_KEYFILE_CONTENT = 'x')],
  ['healthcheck ignores configuration', (c) => (c.services.mongo.healthcheck.test = ['CMD', "h.setName === 'rs0' && h.isWritablePrimary"])],
  ['healthcheck is not primary-aware', (c) => (c.services.mongo.healthcheck.test = ['CMD-SHELL', 'test -f /tmp/sentinel-mongo-configured && mongosh --eval "ping"'])],
  ['URI without the replica set', (c) => (c.services.backend.environment.MONGO_URI = 'mongodb://x@mongo:27017/sentinel-db')],
  ['app connecting as root', (c) => (c.services.backend.environment.MONGO_URI = 'mongodb://root:x@mongo:27017/admin?replicaSet=rs0')],
  ['transactions off', (c) => (c.services.backend.environment.MONGO_USE_TRANSACTIONS = 'false')],
  ['single-process revocation', (c) => (c.services.backend.environment.AUTH_REVOCATION_MODE = 'single')],
]) {
  test(`configuration check catches: ${name}`, () => {
    const config = goodConfig()
    mutate(config)
    assert.ok(v.replicaConfigProblems(config).length >= 1)
  })
}

test('integrity comparison finds any count or index difference', () => {
  const base = { users: { n: 2, i: [['_id_', '{"_id":1}', false, false], ['email_1', '{"email":1}', true, false]] } }
  const copy = () => JSON.parse(JSON.stringify(base))
  assert.deepEqual(v.integrityProblems(base, copy()), [])
  assert.equal(v.integrityProblems(base, {}).length, 1)
  const fewer = copy()
  fewer.users.n = 1
  assert.equal(v.integrityProblems(base, fewer).length, 1)
  const noIndex = copy()
  noIndex.users.i.pop()
  assert.equal(v.integrityProblems(base, noIndex).length, 1)
  const notUnique = copy()
  notUnique.users.i[1][2] = false
  assert.equal(v.integrityProblems(base, notUnique).length, 1)
  assert.equal(v.integrityProblems(base, { ...copy(), extra: { n: 0, i: [] } }).length, 1)
})

test('audit sequence check needs increasing unique values covered by the counter', () => {
  assert.deepEqual(v.sequenceProblems([1, 2, 3], 3), [])
  assert.equal(v.sequenceProblems([], 0).length, 1)
  assert.equal(v.sequenceProblems([1, 1, 2], 2).length, 1)
  assert.equal(v.sequenceProblems([1, 3, 2], 3).length, 1)
  assert.equal(v.sequenceProblems([1, 2, 3], 2).length, 1)
})

test('the entrypoint secures the keyfile and never prints the password', () => {
  const entrypoint = read('deployment/mongo-replicaset-entrypoint.sh')
  assert.match(entrypoint, /install -o mongodb -g mongodb -m 400 \/run\/secrets\/mongo_keyfile/)
  assert.match(entrypoint, /rm -f "\$CONFIGURED"/, 'a marker left from an earlier start would report healthy too soon')
  assert.ok(entrypoint.indexOf('touch "$CONFIGURED"') > entrypoint.indexOf('mongo-init.js'))
  assert.doesNotMatch(entrypoint, /echo[^\n]*PASSWORD/)
  assert.doesNotMatch(entrypoint, /set -[a-z]*x/, 'tracing would write the password to the log')
})

test('the overlay preserves the other stacks and keeps the keyfile out of Git', () => {
  const overlay = read('docker-compose.replicaset.yml')
  assert.doesNotMatch(overlay, /27017:27017|^\s+ports:/m, 'MongoDB must never be published')
  assert.doesNotMatch(overlay, /ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT|windows-firewall/)
  assert.match(overlay, /MONGO_KEYFILE:\?/)
  assert.match(read('docker-compose.tls.yml'), /AUTH_REVOCATION_MODE: single/)
  assert.doesNotMatch(read('docker-compose.yml'), /replSet|keyFile/)
  assert.match(read('.gitignore'), /^deployment\/replicaset\/$/m)
  const tracked = spawnSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).stdout.split('\n')
  assert.deepEqual(tracked.filter((f) => f.startsWith('deployment/replicaset/') || /keyfile$/i.test(f)), [])
})

test('the workflow proves replica-set cleanup after failure', () => {
  const workflow = read('.github/workflows/deployment.yml')
  assert.ok(workflow.includes('\n  replicaset:'), 'deployment.yml has no replicaset job')
  const job = workflow.slice(workflow.indexOf('\n  replicaset:'))
  assert.match(job, /replicaset_verify\.cjs --inject-failure/)
  assert.match(job, /if: always\(\)[\s\S]*down -v --remove-orphans/)
})

test('refuses to start containers outside CI without --disposable', () => {
  const env = { ...process.env }
  delete env.CI
  const r = spawnSync(process.execPath, [path.join(__dirname, 'replicaset_verify.cjs')], { encoding: 'utf8', env })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Refusing to run outside CI/)
})
