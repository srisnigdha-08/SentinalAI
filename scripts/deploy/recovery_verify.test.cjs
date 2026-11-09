'use strict'
// Rules of the recovery verifier and hardening overlay, without Docker.
// Run: node --test scripts/deploy/recovery_verify.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const https = require('https')
const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')
const v = require('./recovery_verify.cjs')
const { tlsRequest } = require('./tls_verify.cjs')

const ROOT = path.join(__dirname, '..', '..')
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8')

const limits = { mem_limit: 1, cpus: 1, pids_limit: 64 }
const goodConfig = () => ({
  services: {
    mongo: { ...limits, cap_drop: ['ALL'], cap_add: ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'], security_opt: ['no-new-privileges:true'] },
    'ai-engine': { ...limits, read_only: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'] },
    backend: { ...limits, read_only: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'] },
    frontend: { ...limits, read_only: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], user: '101:101' },
  },
})

test('the intended hardening has no problems', () => {
  assert.deepEqual(v.hardeningProblems(goodConfig()), [])
})

for (const [name, mutate] of [
  ['a service with no memory limit', (c) => delete c.services.backend.mem_limit],
  ['a service with no CPU limit', (c) => delete c.services.frontend.cpus],
  ['a service with no process limit', (c) => delete c.services.mongo.pids_limit],
  ['backend keeps capabilities', (c) => (c.services.backend.cap_drop = [])],
  ['backend filesystem writable', (c) => delete c.services.backend.read_only],
  ['privilege gain allowed', (c) => (c.services.mongo.security_opt = [])],
  ['MongoDB given an extra capability', (c) => c.services.mongo.cap_add.push('SYS_ADMIN')],
]) {
  test(`hardening check catches: ${name}`, () => {
    const config = goodConfig()
    mutate(config)
    assert.ok(v.hardeningProblems(config).length >= 1)
  })
}

test('audit consistency needs every acknowledged action, in order, without duplicates', () => {
  const good = { acknowledged: ['a', 'b'], stored: ['a', 'b', 'c'], sequence: [1, 2, 3], counter: 3, duplicates: 0, inFlight: 2 }
  assert.deepEqual(v.auditProblems(good), [])
  assert.equal(v.auditProblems({ ...good, stored: ['a'] }).length, 1)
  assert.equal(v.auditProblems({ ...good, sequence: [1, 3, 2] }).length, 2)
  assert.equal(v.auditProblems({ ...good, sequence: [1, 2, 4], counter: 4 }).length, 1, 'a gap inside the trail is a loss')
  assert.equal(v.auditProblems({ ...good, duplicates: 1 }).length, 1)
  assert.equal(v.auditProblems({ ...good, counter: 2 }).length, 1)
  assert.equal(v.auditProblems({ ...good, counter: 9 }).length, 1, 'a counter far past the trail means lost events')
  assert.deepEqual(v.auditProblems({ ...good, counter: 5 }), [], 'in-flight increments at the cut are allowed')
})

test('recovery objectives are explicit and never promise zero loss without a usable spool', () => {
  assert.ok(Object.keys(v.RTO_TARGETS_SECONDS).length >= 5)
  for (const seconds of Object.values(v.RTO_TARGETS_SECONDS)) assert.ok(seconds > 0 && seconds <= 900)
  const text = v.RPO_STATEMENTS.join(' ')
  assert.match(text, /spool/i)
  assert.match(text, /not crash-safe/i)
  assert.match(text, /last successful backup/i)
  assert.deepEqual(v.rtoProblems({ a: 10 }, { a: 20 }), [])
  assert.equal(v.rtoProblems({ a: 30 }, { a: 20 }).length, 1)
  assert.equal(v.rtoProblems({}, { a: 20 }).length, 1, 'an unmeasured objective fails')
})

test('memory growth check allows noise and catches a leak', () => {
  assert.deepEqual(v.memoryProblems([200, 210, 205, 215]), [])
  assert.equal(v.memoryProblems([200, 300, 400, 500]).length, 1)
  assert.equal(v.memoryProblems([200]).length, 1, 'too few samples proves nothing')
})

test('the expired certificate helper makes a certificate clients really reject', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-expired-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const expired = v.issueExpired(dir, 'sentinel.test')
  const server = https.createServer({ key: fs.readFileSync(expired.key), cert: fs.readFileSync(expired.cert) }, (_, res) => res.end('x'))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())
  const target = { host: '127.0.0.1', port: server.address().port, servername: 'sentinel.test', ca: fs.readFileSync(expired.cert) }
  await assert.rejects(tlsRequest(target, 'GET', '/'), /expired/i)
})

test('every failure scenario has recovery assertions', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  const scenarios = [...source.matchAll(/await scenario\('([^']+)'/g)].map((m) => m[1])
  assert.ok(scenarios.length >= 11, `only ${scenarios.length} scenarios`)
  assert.match(source, /const scenario = async[\s\S]{0,900}assertRecovered/)
})

test('the failure injections stay bounded', () => {
  assert.match(read('scripts/deploy/compose.spool-limit.yml'), /\/spool-limit:size=16k/)
  assert.doesNotMatch(read('scripts/deploy/recovery_verify.cjs'), /fallocate|\/dev\/sda|dd if=\/dev\/zero of=\//)
  const overlay = read('docker-compose.hardening.yml')
  assert.equal((overlay.match(/mem_limit:/g) || []).length, 4)
  assert.equal((overlay.match(/pids_limit:/g) || []).length, 4)
})

test('runtime image fixes stay away from the ML environment', () => {
  const ai = read('ai-engine/Dockerfile')
  assert.match(ai, /--only-upgrade zlib1g/)
  assert.match(ai, /pip install --no-cache-dir -r requirements\.txt/)
  assert.match(read('ai-engine/requirements.txt'), /^fastapi==0\.109\.2/m, 'Starlette moves only with FastAPI, which stays pinned in this phase')
  const backend = read('backend/Dockerfile')
  assert.match(backend, /CMD \["node", "server\.js"\]/)
  assert.match(backend, /node_modules\/npm/)
  assert.ok(backend.indexOf('npm ci') < backend.indexOf('rm -rf /usr/local/lib/node_modules/npm'), 'npm is needed for the install above')
})

test('the scan covers MongoDB and the age install is digest-pinned', () => {
  assert.match(read('scripts/deploy/scan_images.sh'), /scan mongo HIGH 0/)
  const install = read('scripts/deploy/install_age.sh')
  assert.match(install, /SHA256='[0-9a-f]{64}'/)
  assert.match(install, /sha256sum -c/)
})

test('workflows: recovery proves cleanup; nightly can run manually and is not scheduled', () => {
  const deployment = read('.github/workflows/deployment.yml')
  assert.ok(deployment.includes('\n  recovery:'), 'deployment.yml has no recovery job')
  const job = deployment.slice(deployment.indexOf('\n  recovery:'))
  assert.match(job, /recovery_verify\.cjs --inject-failure/)
  assert.match(job, /fetch-depth: 0/, 'the rollback test builds the previous commit')
  assert.match(job, /if: always\(\)[\s\S]*down -v --remove-orphans/)
  const nightly = read('.github/workflows/reliability.yml')
  assert.match(nightly, /workflow_dispatch:/)
  assert.doesNotMatch(nightly, /^\s*schedule:/m, 'a schedule needs separate approval')
  assert.match(nightly, /timeout-minutes: \d+/)
  assert.match(nightly, /--soak-minutes/)
})

test('refuses to start containers outside CI without --disposable', () => {
  const env = { ...process.env }
  delete env.CI
  const r = spawnSync(process.execPath, [path.join(__dirname, 'recovery_verify.cjs')], { encoding: 'utf8', env })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Refusing to run outside CI/)
})
