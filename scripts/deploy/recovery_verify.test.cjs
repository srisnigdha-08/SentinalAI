'use strict'
// Rules of the recovery verifier and hardening overlay, without Docker.
// Run: node --test scripts/deploy/recovery_verify.test.cjs
const test = require('node:test')
const { describe } = test
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

describe('audit sequence gaps need recorded evidence', () => {
  const trail = (over = {}) => ({ acknowledged: ['a', 'b'], stored: ['a', 'b', 'c'], sequence: [1, 2, 4, 5], counter: 5, duplicates: 0, inFlight: 2, ...over })
  const window24 = { from: 2, to: 4, count: 1 }

  test('a gap inside a recorded window and budget is valid', () => {
    assert.deepEqual(v.auditProblems(trail({ gapAllowances: [window24] })), [])
  })

  test('an unexplained gap fails', () => {
    const problems = v.auditProblems(trail())
    assert.equal(problems.length, 1)
    assert.match(problems[0], /no recorded cause/)
  })

  test('a window elsewhere in the trail explains nothing', () => {
    assert.match(v.auditProblems(trail({ gapAllowances: [{ from: 10, to: 12, count: 1 }] }))[0], /no recorded cause/)
  })

  test('the boundaries of a window are exact', () => {
    const missingThree = (from, to) => v.auditProblems(trail({ gapAllowances: [{ from, to, count: 1 }] }))
    assert.deepEqual(missingThree(2, 3), [], 'the missing number is 3, inside (2, 3]')
    assert.match(missingThree(3, 4)[0], /no recorded cause/, 'from is exclusive')
    assert.match(missingThree(1, 2)[0], /no recorded cause/, 'to is inclusive of 2 only')
  })

  test('more gaps than a window allows are excessive', () => {
    const problems = v.auditProblems(trail({ sequence: [1, 5], counter: 5, gapAllowances: [{ from: 1, to: 5, count: 2 }] }))
    assert.equal(problems.length, 1)
    assert.match(problems[0], /1 number\(s\) beyond the allowance/)
  })

  test('one window cannot pay for a gap in another place', () => {
    const problems = v.auditProblems(trail({ sequence: [1, 3, 5, 7, 8], counter: 8, gapAllowances: [{ from: 1, to: 3, count: 1 }] }))
    assert.match(problems.join(), /2 number\(s\) with no recorded cause/)
  })

  test('checking a trail never uses up the recorded allowance', () => {
    const allowances = [{ ...window24 }]
    v.auditProblems(trail({ gapAllowances: allowances }))
    assert.deepEqual(allowances, [window24])
    assert.deepEqual(v.auditProblems(trail({ gapAllowances: allowances })), [])
  })

  test('an allowance never excuses a missing acknowledged action', () => {
    const problems = v.auditProblems(trail({ stored: ['a'], gapAllowances: [window24] }))
    assert.deepEqual(problems, ['1 acknowledged action(s) have no audit event'])
  })

  test('an allowance never excuses duplicates', () => {
    assert.deepEqual(v.auditProblems(trail({ duplicates: 1, gapAllowances: [window24] })), ['1 duplicate event id(s)'])
  })

  test('an allowance never excuses a non-increasing or repeated sequence', () => {
    assert.match(v.auditProblems(trail({ sequence: [1, 2, 2, 4, 5], gapAllowances: [window24] })).join(), /not strictly increasing/)
    assert.match(v.auditProblems(trail({ sequence: [1, 2, 5, 4], gapAllowances: [{ from: 2, to: 5, count: 2 }] })).join(), /not strictly increasing/)
  })

  test('an allowance never excuses an inconsistent counter', () => {
    assert.match(v.auditProblems(trail({ counter: 4, gapAllowances: [window24] })).join(), /behind the newest/)
    assert.match(v.auditProblems(trail({ counter: 8, gapAllowances: [window24] })).join(), /far ahead/)
  })

  test('a restore allows exactly the numbers its verified counter says were taken but never stored', () => {
    assert.deepEqual(v.restoreGapAllowance({ sequence: [1, 2, 130], counter: 131 }), { from: 130, to: 131, count: 1 })
    assert.equal(v.restoreGapAllowance({ sequence: [1, 2, 130], counter: 130 }), null, 'a level counter explains nothing')
    assert.equal(v.restoreGapAllowance({ sequence: [1, 2, 130], counter: 129 }), null, 'a counter behind the trail explains nothing')
    assert.equal(v.restoreGapAllowance({ sequence: [], counter: 3 }), null, 'an empty trail explains nothing')
  })

  test('the restore seen in CI: the one number its counter recorded is valid, and nothing past it', () => {
    const restored = { sequence: [129, 130], counter: 131 }
    const gapAllowances = [v.restoreGapAllowance(restored)]
    const after = (sequence) => v.auditProblems({ acknowledged: [], stored: [], sequence, counter: sequence[sequence.length - 1], duplicates: 0, gapAllowances })
    assert.deepEqual(after([129, 130, 132]), [], '131 was taken before the backup and never stored')
    assert.match(after([129, 130, 133]).join(), /1 number\(s\) with no recorded cause/, '132 has no explanation')
    assert.match(after([127, 130, 132]).join(), /2 number\(s\) with no recorded cause/, 'a gap before the backup boundary has no explanation')
  })

  test('a crash allows a gap only when it was verified and audit writes were in flight', () => {
    const verified = { verified: true, auditWritesInFlight: true, before: 10, after: 16 }
    assert.deepEqual(v.crashGapAllowance(verified), { from: 10, to: 16, count: v.MAX_ORPHANED_PER_CRASH })
    assert.equal(v.MAX_ORPHANED_PER_CRASH, 2, 'one traffic request at a time: the current action and the tail of the previous one')
    assert.equal(v.crashGapAllowance({ ...verified, verified: false }), null, 'an unverified crash explains nothing')
    assert.equal(v.crashGapAllowance({ ...verified, auditWritesInFlight: false }), null, 'no writes in flight, no orphaned number')
    assert.equal(v.crashGapAllowance({ ...verified, after: 10 }), null, 'a counter that did not move took no number')
    assert.equal(v.crashGapAllowance({ ...verified, after: 9 }), null)
  })

  test('the verifier records allowances only from that evidence and applies them everywhere', () => {
    const source = read('scripts/deploy/recovery_verify.cjs')
    assert.equal((source.match(/gapAllowances\.push\(/g) || []).length, 2, 'one for a verified crash, one for a verified restore')
    assert.match(source, /crashAndRecover\('backend_crash', 'backend', \{ auditWritesInFlight: true \}\)/)
    assert.match(source, /crashAndRecover\('mongo_crash', 'mongo', \{ auditWritesInFlight: true \}\)/)
    assert.match(source, /crashAndRecover\('spool_replay_restart', 'backend'\)/, 'audit writes are refused here, so no number can be taken')
    assert.equal((source.match(/auditProblems\(\{ \.\.\.[^}]*gapAllowances[^}]*\}\)/g) || []).length, 3, 'every trail check uses the same evidence')
    assert.match(source, /if \(restoredBoundary && problems\.length === 0\) gapAllowances\.push/, 'only a restored trail that passed its own check')
    const crash = source.slice(source.indexOf('const crashAndRecover = async'), source.indexOf('const socketCloseSeconds'))
    assert.ok(crash.indexOf('auditState().counter') < crash.indexOf('hostKill(service)'), 'the counter is read before the crash')
  })
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

test('only a service that reports healthy counts as recovered', () => {
  assert.deepEqual(v.unhealthyServices({ mongo: 'healthy', backend: 'healthy' }), [])
  assert.deepEqual(v.unhealthyServices({ mongo: 'healthy', backend: 'unhealthy' }), ['backend'])
  assert.deepEqual(v.unhealthyServices({ backend: 'starting', frontend: '' }), ['backend', 'frontend'])
})

test('a crash counts only when it was seen and Docker restarted the container', () => {
  assert.deepEqual(v.crashProblems({ observedNotReady: true, restartsBefore: 2, restartsAfter: 3 }), [])
  assert.equal(v.crashProblems({ observedNotReady: false, restartsBefore: 2, restartsAfter: 3 }).length, 1)
  assert.equal(v.crashProblems({ observedNotReady: true, restartsBefore: 2, restartsAfter: 2 }).length, 1)
})

test('recovery checks wait out a stale Docker health flag instead of failing on it (run 42633735070)', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  const body = source.slice(source.indexOf('const assertRecovered = async'), source.indexOf('const scenario = async'))
  assert.ok(body.indexOf('dockerHealthRecovered') >= 0, 'the health flag must be an explicit assertion')
  assert.ok(body.indexOf('dockerHealthRecovered') < body.indexOf('start(STACK'), 'up --wait fails at once on a stale flag')
  assert.match(source, /DOCKER_HEALTH_WAIT_MS = 30000/, 'one probe cycle: 15 s interval, 5 s timeout, and margin')
})

test('crash timing cannot start before the crash is visible', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  assert.equal((source.match(/hostKill\(/g) || []).length, 1, 'only the shared crash helper may kill, so every crash is checked')
  assert.match(source, /measure\('socket_close|socketCloseSeconds/)
  assert.doesNotMatch(source, /measure\('socket_close/, 'a socket already closed would measure as 0 s')
  assert.match(source, /closedAt\(\) - injectedAt/)
})

test('recovery timers begin before the action they measure', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  assert.match(source, /measure\('ai_engine', async \(\) => \{\s*must\(STACK, 'start', 'ai-engine'\)/)
  assert.match(source, /measure\('mongo_outage', async \(\) => \{\s*must\(STACK, 'start', 'mongo'\)/)
  assert.match(source, /measure\('daemon_restart', async \(\) => \{\s*const restarted = spawnSync\('sudo'/)
  const disaster = source.slice(source.indexOf("measure('disaster_restore'"))
  assert.doesNotMatch(disaster.slice(0, disaster.indexOf("check('stack is ready after disaster recovery'")), /wrongKey/, 'the wrong-key test is not part of recovery')
  assert.match(disaster.slice(0, disaster.indexOf('backupTool')), /start\(STACK, 'mongo'\)/)
})

test('backup evidence shows oplog replay and a forced spool replay', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  assert.match(source, /appliedOplogEntries/)
  assert.match(source, /acknowledged during the backup/)
  assert.match(source, /await scenario\('Audit spool replay after a crash'/)
  const spool = source.slice(source.indexOf("await scenario('Audit spool replay after a crash'"))
  assert.ok(spool.indexOf('revokePrivilegesFromRole') < spool.indexOf('crashAndRecover'))
  assert.match(spool, /grantPrivilegesToRole/)
  assert.match(spool, /finally/, 'the privilege must come back even if the scenario fails')
})

test('cleanup of temporary secrets is asserted', () => {
  const source = read('scripts/deploy/recovery_verify.cjs')
  assert.match(source, /temporary secrets and working files removed/)
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
