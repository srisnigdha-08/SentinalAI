#!/usr/bin/env node
'use strict'
/**
 * Verifies the real Docker Compose stack end to end on disposable infrastructure (GitHub Actions).
 *
 * Builds the actual images and runs them under an isolated project name with generated secrets, then checks: loopback
 * publishing, health, MongoDB authentication, least-privilege application permissions, containment audit persistence,
 * restart, graceful shutdown, volume persistence, and updating database roles on an existing volume. All containers
 * and volumes of this project are removed at the end. Real firewall enforcement is never enabled; the check fails if it
 * is. Refuses to run outside CI unless --disposable is given.
 */
const { spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')

const ROOT = path.resolve(__dirname, '..', '..')
const PROJECT = 'sentinelai-verify'
const API = 'http://127.0.0.1:5000'
const WEB = 'http://127.0.0.1:8080'
const ORIGIN = 'http://localhost:8080'
const ADMIN_EMAIL = 'ci-admin@sentinel.test'
const SERVICES = ['mongo', 'ai-engine', 'backend', 'frontend']

const hex = () => crypto.randomBytes(32).toString('hex')

function buildSecrets() {
  return {
    MONGO_ROOT_PASSWORD: hex(),
    MONGO_APP_PASSWORD: hex(),
    MONGO_AUDIT_PASSWORD: hex(),
    SENTINEL_KEY: hex(),
    SENTINEL_ADMIN_KEY: hex(),
    HONEYPOT_API_KEY: hex(),
    JWT_SECRET: hex(),
    JWT_REFRESH_SECRET: hex(),
    METRICS_TOKEN: hex(),
    ADMIN_INITIAL_PASSWORD: 'Ci' + hex() + 'aA1',
  }
}

const redactor = (secrets) => (text) =>
  Object.values(secrets).reduce((out, value) => out.split(value).join('[REDACTED]'), String(text))

/** Problems with the ports `docker compose config` will publish: anything not bound to loopback, and MongoDB at all. */
function publishProblems(config) {
  const problems = []
  for (const [name, service] of Object.entries(config.services || {})) {
    for (const port of service.ports || []) {
      if (name === 'mongo') problems.push('mongo must not publish a port')
      if (port.host_ip !== '127.0.0.1') problems.push(`${name} publishes ${port.published} on ${port.host_ip || 'all interfaces'}`)
    }
  }
  return problems
}

/** Live publishers from `docker compose ps --format json` (one JSON object per line). */
function livePublishProblems(psOutput) {
  const problems = []
  for (const line of String(psOutput).split('\n').filter((l) => l.trim().startsWith('{'))) {
    const c = JSON.parse(line)
    for (const p of c.Publishers || []) {
      if (p.PublishedPort && p.URL !== '127.0.0.1') problems.push(`${c.Service} is published on ${p.URL}:${p.PublishedPort}`)
    }
  }
  return problems
}

const enforcementProblems = (config) => {
  const env = config.services?.backend?.environment || {}
  return env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true' || env.CONTAINMENT_BACKEND === 'windows-firewall'
    ? ['backend enables real firewall enforcement']
    : []
}

/** What teardown left behind, given one docker listing per resource kind. A listing that failed proves nothing. */
function leftoverProblems(listings) {
  const problems = []
  for (const [kind, result] of Object.entries(listings)) {
    const found = (result.stdout || '').trim()
    if (result.status !== 0) problems.push(`could not list ${kind}`)
    else if (found) problems.push(`${kind} left: ${found.split('\n').join(' ')}`)
  }
  return problems
}

const ALL_DENIED_JS = `
const out = {}; const t = (n, f) => { try { f(); out[n] = 'ALLOWED' } catch (e) { out[n] = e.code } };
t('audit_update', () => db.containment_audit_events.updateOne({}, { $set: { x: 1 } }));
t('audit_delete', () => db.containment_audit_events.deleteOne({}));
t('audit_drop', () => db.containment_audit_events.drop());
t('counter_remove', () => db.counters.deleteOne({}));
t('auditlog_update', () => db.auditlogs.updateOne({}, { $set: { x: 1 } }));
t('auditlog_delete', () => db.auditlogs.deleteOne({}));
t('unlisted_insert', () => db.not_a_listed_collection.insertOne({ a: 1 }));
t('create_user', () => db.createUser({ user: 'intruder', pwd: 'x'.repeat(16), roles: [] }));
t('other_database', () => db.getSiblingDB('admin').getCollection('system.users').findOne());
print(JSON.stringify(out));`

async function main() {
  if (!process.env.CI && !process.argv.includes('--disposable')) {
    console.error('Refusing to run outside CI without --disposable: this builds and starts containers.')
    return 2
  }
  const secrets = buildSecrets()
  const clean = redactor(secrets)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-compose-'))
  const envFile = path.join(tmp, 'compose.env')
  fs.writeFileSync(
    envFile,
    Object.entries({ ...secrets, ADMIN_EMAIL }).map(([k, v]) => `${k}=${v}`).join('\n') + '\n',
    { mode: 0o600 }
  )

  let failures = 0
  const check = (name, ok, detail = '') => {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== '' ? `  [${clean(detail)}]` : ''}`)
    if (!ok) failures++
    return ok
  }
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  const compose = (...args) => {
    const r = spawnSync('docker', ['compose', '-p', PROJECT, '--env-file', envFile, '-f', 'docker-compose.yml', ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
    })
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
  }
  const mustCompose = (...args) => {
    const r = compose(...args)
    if (r.status !== 0) throw new Error(`docker compose ${args.join(' ')} failed: ${clean(r.stderr).slice(-2000)}`)
    return r
  }
  const IDENTITIES = {
    none: '',
    app: '-u sentinel_app -p "$SENTINEL_APP_PASSWORD" --authenticationDatabase sentinel-db',
    root: '-u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin',
  }
  const mongo = (who, js) => {
    const r = compose('exec', '-T', '-e', `JS=${js}`, 'mongo', 'sh', '-c', `mongosh --quiet ${IDENTITIES[who]} sentinel-db --eval "$JS"`)
    return { status: r.status, out: r.stdout.trim().split('\n').pop() || '', err: r.stderr }
  }
  const waitFor = async (fn, ms, step = 1000) => {
    const end = Date.now() + ms
    while (Date.now() < end) {
      try {
        if (await fn()) return true
      } catch {
        // not ready yet
      }
      await sleep(step)
    }
    return false
  }
  const request = async (base, method, p, { token, body, csrf, cookie } = {}) => {
    const headers = { Origin: ORIGIN }
    if (body) headers['Content-Type'] = 'application/json'
    if (token) headers.Authorization = `Bearer ${token}`
    if (csrf) headers['X-CSRF-Token'] = csrf
    if (cookie) headers.Cookie = cookie
    const res = await fetch(base + p, { method, headers, body: body ? JSON.stringify(body) : undefined })
    let json = null
    try {
      json = await res.json()
    } catch {
      // not JSON
    }
    return { status: res.status, json, headers: res.headers }
  }
  const signIn = async () => {
    const c = await request(API, 'GET', '/api/auth/csrf')
    const cookie = (c.headers.getSetCookie() || []).map((x) => x.split(';')[0]).join('; ')
    return request(API, 'POST', '/api/auth/login', {
      csrf: c.json.data.csrfToken,
      cookie,
      body: { email: ADMIN_EMAIL, password: secrets.ADMIN_INITIAL_PASSWORD },
    })
  }
  const ready = () => waitFor(async () => (await request(API, 'GET', '/health/ready')).status === 200, 180000, 2000)
  const trail = async (token, id) => (await request(API, 'GET', `/api/containment/actions/${id}/audit`, { token })).json?.data
  const contain = (token, target) =>
    request(API, 'POST', '/api/containment/actions', {
      token,
      body: { target, actionType: 'block_ip', reason: 'compose verification', durationSeconds: 600 },
    })
  const expectAllDenied = (label) => {
    const r = mongo('app', ALL_DENIED_JS)
    let result = {}
    try {
      result = JSON.parse(r.out)
    } catch {
      return check(`${label}: permission probe ran`, false, r.err.slice(-300))
    }
    const wrong = Object.entries(result).filter(([, code]) => code !== 13)
    return check(`${label}: ${Object.keys(result).length} unauthorized operations denied (code 13)`, wrong.length === 0 && Object.keys(result).length === 9, JSON.stringify(wrong))
  }

  try {
    compose('down', '-v', '--remove-orphans')

    console.log('\n== Configuration')
    const config = JSON.parse(mustCompose('config', '--format', 'json').stdout)
    const exposed = publishProblems(config)
    check('every published port is loopback only; MongoDB is not published', exposed.length === 0, exposed.join('; '))
    check('real firewall enforcement is not configured', enforcementProblems(config).length === 0)

    console.log('\n== Fresh database initialization')
    const t0 = Date.now()
    mustCompose('up', '-d', '--build', '--wait', '--wait-timeout', '600', ...SERVICES)
    check('real images built and every service healthy', true, `${Math.round((Date.now() - t0) / 1000)} s`)
    // Lets CI prove the teardown below on a run that really fails with the whole stack up.
    if (process.argv.includes('--inject-failure')) throw new Error('injected failure (cleanup test)')
    const live = livePublishProblems(mustCompose('ps', '--format', 'json').stdout)
    check('running containers publish on loopback only', live.length === 0, live.join('; '))
    check('backend runs as non-root', compose('exec', '-T', 'backend', 'id', '-u').stdout.trim() !== '0')
    check('AI engine runs as non-root', compose('exec', '-T', 'ai-engine', 'id', '-u').stdout.trim() !== '0')
    check('AI engine filesystem is read-only', compose('exec', '-T', 'ai-engine', 'sh', '-c', 'touch /app/probe').status !== 0)

    console.log('\n== Health and API')
    const liveness = await request(API, 'GET', '/health/live')
    check('liveness', liveness.status === 200 && liveness.json?.status === 'alive')
    const readiness = await request(API, 'GET', '/health/ready')
    check('readiness with the real AI engine', readiness.status === 200 && readiness.json?.status === 'ready', JSON.stringify(readiness.json?.dependencies))
    check('dashboard is served', (await fetch(WEB + '/')).status === 200)
    check('API reachable through the dashboard proxy', (await request(WEB, 'GET', '/api/auth/csrf')).status === 200)

    console.log('\n== MongoDB authentication and least privilege')
    const anonymous = mongo('none', 'print(db.users.countDocuments())')
    check('unauthenticated database access is refused', anonymous.status !== 0 || /Unauthorized|requires authentication/i.test(anonymous.out + anonymous.err))
    check('the application user can read its database', mongo('app', 'print(db.users.countDocuments())').status === 0)
    expectAllDenied('fresh volume')

    console.log('\n== Containment and audit persistence (mock adapter)')
    let login = await signIn()
    check('administrator signs in', login.status === 200, login.status)
    let token = login.json?.data?.token
    const status = await request(API, 'GET', '/api/containment/status', { token })
    check('real enforcement is off at runtime', status.json?.data?.realEnforcementEnabled === false && status.json?.data?.backend === 'mock', JSON.stringify({ real: status.json?.data?.realEnforcementEnabled, backend: status.json?.data?.backend }))
    const flow = await request(API, 'POST', '/api/ai/analyze', {
      token,
      body: { sourceIP: '198.51.100.250', flow_duration: 1000, total_fwd_packets: 3, total_bwd_packets: 1, flow_bytes_per_sec: 100 },
    })
    const aiResult = flow.json?.data?.result
    check('AI analysis served by the real engine, not degraded', flow.status === 200 && !['UNAVAILABLE', 'DEGRADED'].includes(aiResult?.status) && aiResult?.predictedClass !== 'UNINSPECTED_TRAFFIC', `${flow.status} ${aiResult?.status}`)
    const first = await contain(token, '198.51.100.77')
    const firstId = first.json?.data?.action?.containmentId
    check('containment becomes ACTIVE on the mock adapter', first.status === 201 && first.json?.data?.action?.enforcementStatus === 'ACTIVE' && first.json?.data?.action?.enforcementBackend === 'mock', first.status)
    const stored = await waitFor(async () => (await trail(token, firstId))?.events?.length >= 2, 30000)
    check('audit events stored through the least-privilege role', stored)
    const counted = mongo('root', `print(db.containment_audit_events.countDocuments({ containmentId: '${firstId}' }) + ' ' + (db.counters.findOne({ _id: 'containment_audit_events' }) || {}).seq)`)
    check('events and sequence counter are in MongoDB', /^[2-9]\d* [1-9]\d*$/.test(counted.out), counted.out)

    console.log('\n== Restart')
    mustCompose('restart', 'backend')
    check('backend is ready after a restart', await ready())
    check('existing session survives the restart', (await request(API, 'GET', '/api/auth/me', { token })).status === 200)
    check('audit trail intact after the restart', (await trail(token, firstId))?.events?.length >= 2)

    console.log('\n== Graceful shutdown')
    const id = mustCompose('ps', '-q', 'backend').stdout.trim()
    const stopStart = Date.now()
    const since = new Date(stopStart).toISOString() // only this stop, not the shutdown from the restart above
    mustCompose('stop', '-t', '25', 'backend')
    const stopMs = Date.now() - stopStart
    const code = spawnSync('docker', ['inspect', '-f', '{{.State.ExitCode}}', id], { encoding: 'utf8' }).stdout.trim()
    check('SIGTERM exits 0 within the grace period', code === '0' && stopMs < 25000, `exit ${code}, ${stopMs} ms`)
    const stopLog = compose('logs', '--since', since, 'backend').stdout
    check('shutdown completed all steps', /Graceful shutdown completed/.test(stopLog))
    check('no false HTTP close error', !/HTTP server close error/.test(stopLog))

    console.log('\n== Volume persistence')
    mustCompose('down')
    mustCompose('up', '-d', '--wait', '--wait-timeout', '300', ...SERVICES)
    check('stack returns on the same volumes', await ready())
    login = await signIn()
    check('existing account signs in after recreation', login.status === 200, login.status)
    token = login.json?.data?.token
    check('audit trail survives container recreation', (await trail(token, firstId))?.events?.length >= 2)

    console.log('\n== Updating roles on an existing volume')
    const revoked = mongo('root', "db.revokePrivilegesFromRole('sentinel_app_role', [{ resource: { db: 'sentinel-db', collection: 'containment_audit_events' }, actions: ['insert'] }, { resource: { db: 'sentinel-db', collection: 'counters' }, actions: ['insert', 'update'] }]); print('revoked')")
    check('volume returned to the old role state', revoked.out === 'revoked', revoked.err.slice(-200))
    const before = await contain(token, '198.51.100.78')
    const beforeId = before.json?.data?.action?.containmentId
    check('containment is not blocked by the audit failure', before.status === 201, before.status)
    const queued = await waitFor(async () => (await trail(token, beforeId))?.pendingDurableWrites > 0, 30000)
    check('old role: events are queued, not stored (defect reproduced)', queued && (await trail(token, beforeId)).events.length === 0)
    const spool = compose('exec', '-T', 'backend', 'sh', '-c', 'wc -c < logs/containment-audit-spool-sentinel-db.jsonl')
    check('queued events are in the crash spool on the volume', Number(spool.stdout.trim()) > 0, `${spool.stdout.trim()} bytes`)
    const update = compose('exec', '-T', 'mongo', 'sh', '-c', 'mongosh --quiet -u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --file /docker-entrypoint-initdb.d/mongo-init.js')
    check('role update procedure runs against the existing volume', update.status === 0 && /Updated existing role 'sentinel_app_role'/.test(update.stdout), update.stderr.slice(-300))
    const flushed = await waitFor(async () => {
      const t = await trail(token, beforeId)
      return t?.events?.length >= 2 && t.pendingDurableWrites === 0
    }, 90000, 2000)
    check('queued events are stored after the update, without a restart', flushed)
    login = await signIn()
    check('application still connects and signs in after the update', login.status === 200, login.status)
    expectAllDenied('updated volume')
  } catch (err) {
    check(`verification stopped: ${err.message}`, false)
  } finally {
    if (failures) {
      for (const s of SERVICES) console.log(`\n--- ${s} log tail ---\n${clean(compose('logs', '--tail', '40', s).stdout)}`)
    }
    compose('down', '-v', '--remove-orphans')
    const list = (...args) => spawnSync('docker', [...args, '--filter', `label=com.docker.compose.project=${PROJECT}`], { encoding: 'utf8' })
    const leftovers = leftoverProblems({
      containers: list('ps', '-aq'),
      networks: list('network', 'ls', '-q'),
      volumes: list('volume', 'ls', '-q'),
    })
    check('disposable containers, networks and volumes removed', leftovers.length === 0, leftovers.join('; '))
    fs.rmSync(tmp, { recursive: true, force: true })
  }
  console.log(`\n${failures ? `${failures} check(s) failed` : 'All deployment checks passed'}`)
  return failures ? 1 : 0
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('compose verification error: ' + err.message)
      process.exit(2)
    }
  )
}
module.exports = { buildSecrets, redactor, publishProblems, livePublishProblems, enforcementProblems, leftoverProblems }
