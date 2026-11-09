#!/usr/bin/env node
'use strict'
/**
 * Failure injection, recovery, backup and rollback for the combined HTTPS + replica-set + hardened stack, on disposable
 * infrastructure only (GitHub Actions). Secrets, certificates, age keys and all data are generated for the run. Every
 * injection is bounded, every scenario ends with recovery assertions, and real firewall enforcement is never enabled.
 * Refuses to run outside CI unless --disposable is given.
 */
const { spawn, spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const net = require('net')
const os = require('os')
const path = require('path')
const { PROJECT, ALL_DENIED_JS, buildSecrets, redactor, publishProblems, enforcementProblems, leftoverProblems } = require('./compose_verify.cjs')
const { tlsConfigProblems, issueCerts, tlsRequest, wsConnect } = require('./tls_verify.cjs')
const { replicaConfigProblems } = require('./replicaset_verify.cjs')

const ROOT = path.resolve(__dirname, '..', '..')
const HOST = 'sentinel.test'
const PORT = 8443
const ORIGIN = `https://${HOST}:${PORT}`
const ADMIN_EMAIL = 'ci-admin@sentinel.test'
const SERVICES = ['mongo', 'ai-engine', 'backend', 'frontend']
const BASE = ['docker-compose.yml', 'docker-compose.tls.yml', 'docker-compose.replicaset.yml']
const STACK = [...BASE, 'docker-compose.hardening.yml', 'scripts/deploy/compose.recovery-test.yml']
const SPOOL_LIMIT = [...STACK, 'scripts/deploy/compose.spool-limit.yml']
const METRICS_TOKEN_FILE = path.join(ROOT, 'deployment', 'metrics_token')
const ROLLBACK_REF = process.env.ROLLBACK_REF || '8b9db80'
const FILLER_DOCUMENTS = 100000
const MONGO_CAPS = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID']

const RTO_TARGETS_SECONDS = {
  backend_crash: 120,
  mongo_crash: 180,
  mongo_outage: 180,
  network_partition: 60,
  ai_engine: 120,
  daemon_restart: 300,
  disaster_restore: 600,
}
const RPO_STATEMENTS = [
  'Acknowledged containment audit events: none lost across a process crash while the spool is writable on its durable volume (asserted here).',
  'If the spool is full or unwritable, an event is logged and counted and still sent to MongoDB, but until MongoDB stores it the event is not crash-safe: no zero-loss claim is made for that window.',
  'If the spool volume itself is destroyed, queued events on it are lost with it.',
  'Whole-database loss: restored to the last successful backup, consistent at the end of that backup. Writes after it are lost, so the RPO equals the backup interval the operator chooses.',
]

function hardeningProblems(config) {
  const problems = []
  for (const name of SERVICES) {
    const s = config.services?.[name] || {}
    for (const key of ['mem_limit', 'cpus', 'pids_limit']) if (!s[key]) problems.push(`${name}: no ${key}`)
    if (!(s.cap_drop || []).includes('ALL')) problems.push(`${name}: keeps capabilities`)
    if (!(s.security_opt || []).includes('no-new-privileges:true')) problems.push(`${name}: can gain privileges`)
  }
  if (config.services?.backend?.read_only !== true) problems.push('backend: writable filesystem')
  const extra = (config.services?.mongo?.cap_add || []).filter((c) => !MONGO_CAPS.includes(c))
  if (extra.length) problems.push(`mongo: extra capabilities ${extra}`)
  return problems
}

function auditProblems({ acknowledged, stored, sequence, counter, duplicates, inFlight = 4 }) {
  const problems = []
  const present = new Set(stored)
  const missing = acknowledged.filter((id) => !present.has(id))
  if (missing.length) problems.push(`${missing.length} acknowledged action(s) have no audit event`)
  if (sequence.some((value, i) => i > 0 && value <= sequence[i - 1])) problems.push('sequence is not strictly increasing')
  if (sequence.some((value, i) => i > 0 && value > sequence[i - 1] + 1)) problems.push('gap inside the audit sequence')
  if (duplicates) problems.push(`${duplicates} duplicate event id(s)`)
  const newest = sequence[sequence.length - 1] ?? 0
  if ((counter ?? 0) < newest) problems.push('counter is behind the newest event')
  if ((counter ?? 0) - newest > inFlight) problems.push('counter is far ahead of the stored trail')
  return problems
}

function rtoProblems(measured, targets) {
  return Object.entries(targets).flatMap(([name, limit]) =>
    measured[name] === undefined ? [`${name}: not measured`] : measured[name] > limit ? [`${name}: ${measured[name]} s exceeds ${limit} s`] : []
  )
}

function memoryProblems(samples) {
  if (samples.length < 3) return ['too few memory samples']
  const start = Math.min(...samples.slice(0, 2))
  const end = samples[samples.length - 1]
  return end > start * 1.5 + 64 ? [`backend memory grew from ${start} to ${end} MiB`] : []
}

/** A self-signed certificate whose validity ended years ago; openssl ca is the portable way to set past dates. */
function issueExpired(dir, name) {
  const key = path.join(dir, 'expired.key')
  const cert = path.join(dir, 'expired.pem')
  const csr = path.join(dir, 'expired.csr')
  const config = path.join(dir, 'expired.cnf')
  const database = path.join(dir, 'index.txt').replace(/\\/g, '/')
  const serial = path.join(dir, 'serial').replace(/\\/g, '/')
  fs.writeFileSync(database, '')
  fs.writeFileSync(serial, '01\n')
  fs.writeFileSync(
    config,
    `[ca]\ndefault_ca=d\n[d]\ndatabase=${database}\nserial=${serial}\nnew_certs_dir=${dir.replace(/\\/g, '/')}\ndefault_md=sha256\npolicy=p\nx509_extensions=e\n[p]\ncommonName=supplied\n[e]\nsubjectAltName=DNS:${name}\nbasicConstraints=CA:TRUE\n`
  )
  const openssl = (...args) => {
    const r = spawnSync('openssl', args, { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${(r.stderr || '').slice(-300)}`)
  }
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', `/CN=${name}`)
  openssl('ca', '-batch', '-notext', '-selfsign', '-config', config, '-keyfile', key, '-in', csr, '-out', cert, '-startdate', '20200101000000Z', '-enddate', '20200102000000Z')
  return { key, cert }
}

const SNAPSHOT = `const d=db.getSiblingDB('sentinel-db');const r={};for(const c of d.getCollectionNames().sort()){r[c]={n:d[c].countDocuments(),i:d[c].getIndexes().map(x=>[x.name,JSON.stringify(x.key),!!x.unique,!!x.sparse]).sort()}};print(JSON.stringify(r))`
const AUDIT_STATE_JS = `print(JSON.stringify({stored:db.containment_audit_events.distinct('containmentId'),sequence:db.containment_audit_events.find({},{seq:1}).sort({seq:1}).toArray().map(e=>e.seq),counter:(db.counters.findOne({_id:'containment_audit_events'})||{}).seq||0,duplicates:db.containment_audit_events.aggregate([{$group:{_id:'$eventId',n:{$sum:1}}},{$match:{n:{$gt:1}}},{$count:'c'}]).toArray().length}))`

async function main() {
  if (!process.env.CI && !process.argv.includes('--disposable')) {
    console.error('Refusing to run outside CI without --disposable: this builds and starts containers.')
    return 2
  }
  if (fs.existsSync(METRICS_TOKEN_FILE)) {
    console.error('Refusing to overwrite deployment/metrics_token.')
    return 2
  }
  const soakArg = process.argv.find((a) => a.startsWith('--soak-minutes='))
  const soakMinutes = soakArg ? Number(soakArg.split('=')[1]) : 0
  if (soakArg && !(soakMinutes > 0 && soakMinutes <= 60)) {
    console.error('--soak-minutes must be between 1 and 60.')
    return 2
  }
  const secrets = { ...buildSecrets(), MONGO_BACKUP_PASSWORD: crypto.randomBytes(32).toString('hex') }
  const clean = redactor(secrets)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-recovery-'))
  const certs = issueCerts(tmp, [HOST, 'localhost'])
  const keyfile = path.join(tmp, 'mongo-keyfile')
  fs.writeFileSync(keyfile, crypto.randomBytes(756).toString('base64'), { mode: 0o400 })
  const envFile = path.join(tmp, 'compose.env')
  fs.writeFileSync(
    envFile,
    Object.entries({ ...secrets, ADMIN_EMAIL, TLS_PUBLIC_ORIGIN: ORIGIN, TLS_CERT_DIR: certs.dir, MONGO_KEYFILE: keyfile }).map(([k, v]) => `${k}=${v}`).join('\n') + '\n',
    { mode: 0o600 }
  )
  const target = { host: '127.0.0.1', port: PORT, servername: HOST, ca: fs.readFileSync(certs.ca) }
  const rollbackDir = path.join(tmp, 'rollback')

  let failures = 0
  const rto = {}
  const check = (name, ok, detail = '') => {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== '' ? `  [${clean(detail)}]` : ''}`)
    if (!ok) failures++
    return ok
  }
  const section = (title) => console.log(`\n== ${title}`)
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  const docker = (...args) => spawnSync('docker', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
  const run = (files, args, cwd = ROOT) => {
    const r = spawnSync('docker', ['compose', '-p', PROJECT, '--env-file', envFile, ...files.flatMap((f) => ['-f', f]), ...args], { cwd, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
  }
  const must = (files, ...args) => {
    const r = run(files, args)
    if (r.status !== 0) throw new Error(`docker compose ${args.join(' ')} failed: ${clean(r.stderr).slice(-2000)}`)
    return r
  }
  const start = (files, ...services) => must(files, 'up', '-d', '--wait', '--wait-timeout', '600', ...services)
  const mongo = (js, who = 'root') => {
    const auth = who === 'root' ? '-u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin' : '-u sentinel_app -p "$SENTINEL_APP_PASSWORD" --authenticationDatabase sentinel-db'
    const r = run(STACK, ['exec', '-T', '-e', `JS=${js}`, 'mongo', 'sh', '-c', `mongosh --quiet ${auth} sentinel-db --eval "$JS"`])
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
  const api = (method, urlPath, { origin = ORIGIN, headers = {}, body } = {}) =>
    tlsRequest(target, method, urlPath, { headers: { ...(origin ? { Origin: origin } : {}), ...headers }, body })
  const cookiesOf = (res) => (res.headers['set-cookie'] || []).map((c) => c.split(';')[0])
  const bearer = (token) => ({ Authorization: `Bearer ${token}` })
  const signIn = async () => {
    const csrf = await api('GET', '/api/auth/csrf')
    const jar = cookiesOf(csrf)
    const login = await api('POST', '/api/auth/login', { headers: { 'X-CSRF-Token': csrf.json.data.csrfToken, Cookie: jar.join('; ') }, body: { email: ADMIN_EMAIL, password: secrets.ADMIN_INITIAL_PASSWORD } })
    return { login, token: login.json?.data?.token }
  }
  const readiness = () => {
    const r = run(STACK, ['exec', '-T', 'backend', 'node', '-e', "fetch('http://127.0.0.1:5000/health/ready').then(async r=>console.log(r.status+' '+await r.text()))"])
    const line = r.stdout.trim().split('\n').pop() || ''
    const space = line.indexOf(' ')
    let body = {}
    try {
      body = JSON.parse(line.slice(space + 1))
    } catch {
      // backend not answering
    }
    return { code: Number(line.slice(0, space)), body, line }
  }
  const waitReady = (ms = 240000) => waitFor(() => readiness().body.status === 'ready', ms, 1000)
  const metrics = () => run(STACK, ['exec', '-T', 'backend', 'node', '-e', "fetch('http://127.0.0.1:5000/metrics',{headers:{Authorization:'Bearer '+process.env.METRICS_TOKEN}}).then(r=>r.text()).then(console.log)"]).stdout
  const prometheus = async (p) => (await fetch(`http://127.0.0.1:9090${p}`)).json()
  const alertState = async (name) => ((await prometheus('/api/v1/alerts')).data.alerts.find((a) => a.labels.alertname === name) || {}).state
  let address = 100
  let block = '198.51.100'
  const nextTarget = () => {
    if (address > 250) {
      address = 1
      block = '203.0.113'
    }
    return `${block}.${address++}`
  }
  const contain = (token, ip = nextTarget()) => api('POST', '/api/containment/actions', { headers: bearer(token), body: { target: ip, actionType: 'block_ip', reason: 'recovery verification', durationSeconds: 900 } })
  const startTraffic = (token, { max = 40, intervalMs = 200 } = {}) => {
    const records = []
    let running = true
    const done = (async () => {
      while (running && records.length < max) {
        const started = Date.now()
        try {
          const r = await contain(token)
          records.push({ status: r.status, id: r.json?.data?.action?.containmentId, startedAt: started, ackedAt: Date.now() })
        } catch (err) {
          records.push({ status: 0, error: err.message, startedAt: started, ackedAt: Date.now() })
        }
        await sleep(intervalMs)
      }
    })()
    return {
      records,
      stop: async () => {
        running = false
        await done
      },
    }
  }
  const acknowledged = (records) => records.filter((r) => r.status === 201).map((r) => r.id)
  const auditState = () => JSON.parse(mongo(AUDIT_STATE_JS).out || '{"stored":[],"sequence":[],"counter":0,"duplicates":0}')
  const assertAudit = async (label, records, inFlight) => {
    const ids = acknowledged(records)
    let problems = ['not checked']
    await waitFor(() => {
      problems = auditProblems({ ...auditState(), acknowledged: ids, inFlight })
      return problems.length === 0
    }, 60000, 2000)
    check(`${label}: all ${ids.length} acknowledged actions audited, in order, with no duplicates`, problems.length === 0, problems.join('; '))
  }
  const hostKill = (service) => {
    const id = must(STACK, 'ps', '-q', service).stdout.trim()
    const pid = docker('inspect', '-f', '{{.State.Pid}}', id).stdout.trim()
    const r = spawnSync('sudo', ['-n', 'kill', '-9', pid], { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`could not kill ${service}: ${r.stderr}`)
  }
  const liveSocket = async (token) => {
    const socket = await wsConnect(target, { origin: ORIGIN })
    await socket.next()
    socket.send(`40${JSON.stringify({ token })}`)
    return { socket, reply: await socket.next() }
  }
  const measure = async (name, wait) => {
    const t0 = Date.now()
    const ok = await wait()
    const seconds = Math.round((Date.now() - t0) / 100) / 10
    if (ok) rto[name] = seconds
    return { ok, seconds }
  }
  const assertRecovered = async (name) => {
    start(STACK, ...SERVICES)
    check(`${name}: stack is ready again`, await waitReady(), readiness().line)
    const session = await signIn()
    check(`${name}: sign-in works after recovery`, session.login.status === 200, session.login.status)
    const state = auditState()
    const problems = auditProblems({ ...state, acknowledged: [] })
    check(`${name}: audit trail is consistent after recovery`, problems.length === 0, problems.join('; '))
    const leftover = run(STACK, ['ps', '-a', '--format', '{{.Service}} {{.State}}']).stdout.split('\n').filter((l) => SERVICES.some((s) => l.startsWith(`${s} `)) && !/running/.test(l))
    check(`${name}: every service is running`, leftover.length === 0, leftover.join('; '))
  }
  const scenario = async (name, fn) => {
    section(name)
    try {
      await fn()
    } catch (err) {
      check(`${name}: scenario completed`, false, err.message)
    }
    await assertRecovered(name).catch((err) => check(`${name}: recovery assertions completed`, false, err.message))
  }
  const owned = (dir, file) => {
    const r = docker('run', '--rm', '--user', '0', '--entrypoint', 'sh', '-v', `${dir}:/tls`, `${PROJECT}-frontend`, '-c', `chown 101:101 /tls/${file} && chmod 400 /tls/${file}`)
    if (r.status !== 0) throw new Error(`could not set key ownership: ${r.stderr.slice(-300)}`)
  }
  const installPair = (cert, key) => {
    fs.copyFileSync(cert, `${certs.cert}.new`)
    fs.renameSync(`${certs.cert}.new`, certs.cert)
    fs.copyFileSync(key, path.join(certs.dir, 'privkey.new'))
    owned(certs.dir, 'privkey.new')
    fs.renameSync(path.join(certs.dir, 'privkey.new'), certs.key)
  }
  const fingerprint = () =>
    new Promise((resolve, reject) => {
      const socket = require('tls').connect({ host: target.host, port: target.port, servername: HOST, rejectUnauthorized: false }, () => {
        const value = socket.getPeerCertificate().fingerprint256
        socket.destroy()
        resolve(value)
      })
      socket.on('error', reject)
    })
  const backupTool = (...args) =>
    new Promise((resolve) => {
      const p = spawn(process.execPath, [path.join(__dirname, 'db_backup.cjs'), ...args], { cwd: ROOT, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] })
      let out = ''
      let err = ''
      p.stdout.on('data', (d) => (out += d))
      p.stderr.on('data', (d) => (err += d))
      p.on('close', (code) => resolve({ code, out, err: clean(err) }))
    })
  const composeFlags = STACK.flatMap((f) => ['--compose-file', f])

  try {
    run([...SPOOL_LIMIT], ['--profile', 'monitoring', 'down', '-v', '--remove-orphans'])
    fs.writeFileSync(METRICS_TOKEN_FILE, secrets.METRICS_TOKEN, { mode: 0o644 })

    section('Configuration and hardening')
    const config = JSON.parse(must(STACK, 'config', '--format', 'json').stdout)
    const issues = [...hardeningProblems(config), ...replicaConfigProblems(config), ...tlsConfigProblems(config), ...publishProblems(config), ...enforcementProblems(config)]
    check('combined stack: HTTPS, replica set, least capability, resource limits, nothing but loopback HTTPS published', issues.length === 0, issues.join('; '))

    must(STACK, 'build')
    owned(certs.dir, 'privkey.pem')
    const t0 = Date.now()
    start(STACK, ...SERVICES)
    check('hardened stack builds and every service is healthy', true, `${Math.round((Date.now() - t0) / 1000)} s`)
    if (process.argv.includes('--inject-failure')) throw new Error('injected failure (cleanup test)')
    must(STACK, '--profile', 'monitoring', 'up', '-d', '--no-deps', 'prometheus')

    const inspect = (service) => JSON.parse(docker('inspect', must(STACK, 'ps', '-q', service).stdout.trim()).stdout)[0].HostConfig
    for (const service of SERVICES) {
      const host = inspect(service)
      check(`${service}: limits applied at runtime`, host.Memory > 0 && host.NanoCpus > 0 && host.PidsLimit > 0 && (host.CapDrop || []).includes('ALL') && (host.SecurityOpt || []).includes('no-new-privileges:true'), JSON.stringify({ memory: host.Memory, pids: host.PidsLimit }))
    }
    const uids = Object.fromEntries(SERVICES.map((s) => [s, run(STACK, ['exec', '-T', s, 'sh', '-c', 'grep "^Uid:" /proc/1/status']).stdout.split(/\s+/)[1]]))
    check('no service runs as root', Object.values(uids).every((u) => u && u !== '0'), JSON.stringify(uids))
    check('backend filesystem is read-only', run(STACK, ['exec', '-T', 'backend', 'sh', '-c', 'touch /app/backend/probe']).status !== 0)
    check('npm is gone from the backend image', run(STACK, ['exec', '-T', 'backend', 'sh', '-c', 'command -v npm']).status !== 0)
    const models = run(STACK, ['logs', 'ai-engine']).stdout
    check('AI engine still verifies its registered models and golden set', /sha256 verified/.test(models) && /Golden-set check passed/.test(models))
    const ready = await waitFor(async () => (await prometheus('/api/v1/targets')).data.activeTargets.every((t) => t.health === 'up'), 90000, 3000)
    check('Prometheus scrapes the backend and AI engine with the token', ready)

    if (soakMinutes) {
      section(`Soak (${soakMinutes} min, bounded traffic)`)
      const samples = []
      let notReady = 0
      const session = await signIn()
      const restarts = () => SERVICES.map((s) => docker('inspect', '-f', '{{.RestartCount}}', must(STACK, 'ps', '-q', s).stdout.trim()).stdout.trim()).join(',')
      const before = restarts()
      let token = session.token
      const traffic = []
      for (let minute = 0; minute < soakMinutes; minute++) {
        token = (await signIn()).token // access tokens are short-lived
        const t = startTraffic(token, { max: 3, intervalMs: 15000 })
        await sleep(50000)
        await t.stop()
        traffic.push(...t.records)
        if (readiness().body.status !== 'ready') notReady++
        const used = docker('stats', '--no-stream', '--format', '{{.MemUsage}}', must(STACK, 'ps', '-q', 'backend').stdout.trim()).stdout.split('/')[0].trim()
        samples.push(parseFloat(used) * (/GiB/.test(used) ? 1024 : 1))
      }
      console.log(`backend memory samples (MiB): ${samples.join(' ')}`)
      const growth = memoryProblems(samples)
      check('backend memory stays bounded', growth.length === 0, growth.join('; '))
      check('readiness held throughout', notReady === 0, notReady)
      check('no container restarted', restarts() === before, restarts())
      await assertAudit('soak', traffic)
      return failures ? 1 : 0
    }

    section('Network isolation by IP address')
    const ipOf = (service, network) => JSON.parse(docker('inspect', must(STACK, 'ps', '-q', service).stdout.trim()).stdout)[0].NetworkSettings.Networks[`${PROJECT}_${network}`].IPAddress
    const tcp = (network, ip, port) => {
      const script = "const s=require('net').connect({host:process.argv[1],port:+process.argv[2],timeout:4000});s.on('connect',()=>{console.log('OPEN');process.exit(0)});s.on('timeout',()=>{console.log('CLOSED');process.exit(0)});s.on('error',()=>{console.log('CLOSED');process.exit(0)})"
      return docker('run', '--rm', '--network', `${PROJECT}_${network}`, `${PROJECT}-backend`, 'node', '-e', script, ip, String(port)).stdout.trim()
    }
    const mongoIp = ipOf('mongo', 'default')
    const aiIp = ipOf('ai-engine', 'default')
    const backendDefault = ipOf('backend', 'default')
    const backendProxy = ipOf('backend', 'proxy')
    check('control: a container on the database network reaches MongoDB by IP', tcp('default', mongoIp, 27017) === 'OPEN')
    check('control: a container on the proxy network reaches the backend by IP', tcp('proxy', backendProxy, 5000) === 'OPEN')
    check('proxy network cannot reach MongoDB by IP', tcp('proxy', mongoIp, 27017) === 'CLOSED')
    check('proxy network cannot reach the AI engine by IP', tcp('proxy', aiIp, 8000) === 'CLOSED')
    check('ingress network cannot reach MongoDB by IP', tcp('ingress', mongoIp, 27017) === 'CLOSED')
    check('ingress network cannot reach the backend by IP', tcp('ingress', backendDefault, 5000) === 'CLOSED' && tcp('ingress', backendProxy, 5000) === 'CLOSED')

    await scenario('AI engine degradation', async () => {
      const { token } = await signIn()
      must(STACK, 'stop', 'ai-engine')
      const degraded = await waitFor(() => readiness().body.status === 'degraded', 60000, 2000)
      check('readiness reports degraded, not down', degraded && readiness().code === 200, readiness().line)
      const results = []
      for (let i = 0; i < 3; i++) results.push((await api('POST', '/api/ai/analyze', { headers: bearer(token), body: { sourceIP: `198.51.100.${10 + i}`, flow_duration: 1000, total_fwd_packets: 3, total_bwd_packets: 1, flow_bytes_per_sec: 100 } })).json?.data?.result)
      check('inference is marked unavailable and only ever MONITOR', results.every((r) => r && r.action === 'MONITOR' && ['UNAVAILABLE', 'DEGRADED'].includes(r.status)), JSON.stringify(results.map((r) => [r?.status, r?.action])))
      const pending = await waitFor(async () => ['pending', 'firing'].includes(await alertState('SentinelAIEngineDown')), 90000, 3000)
      check('the AI engine alert is raised', pending, await alertState('SentinelAIEngineDown'))
      must(STACK, 'start', 'ai-engine')
      const back = await measure('ai_engine', () => waitReady())
      check('AI engine recovers', back.ok, `${back.seconds} s`)
      const real = await waitFor(async () => {
        const r = (await api('POST', '/api/ai/analyze', { headers: bearer(token), body: { sourceIP: '198.51.100.20', flow_duration: 1000, total_fwd_packets: 3, total_bwd_packets: 1, flow_bytes_per_sec: 100 } })).json?.data?.result
        return r && !r.status && Number.isFinite(r.threatScore)
      }, 90000, 3000)
      check('real scores return after recovery', real)
    })

    await scenario('Backend crash during containment', async () => {
      const { token } = await signIn()
      const traffic = startTraffic(token, { max: 60, intervalMs: 100 })
      await sleep(2500)
      hostKill('backend')
      const back = await measure('backend_crash', () => waitReady())
      check('backend returns on its own after SIGKILL', back.ok, `${back.seconds} s`)
      await traffic.stop()
      check('traffic was acknowledged before the crash', acknowledged(traffic.records).length > 0, acknowledged(traffic.records).length)
      await assertAudit('backend crash', traffic.records)
    })

    await scenario('MongoDB crash during audit writes', async () => {
      const { token } = await signIn()
      const traffic = startTraffic(token, { max: 60, intervalMs: 100 })
      await sleep(2500)
      hostKill('mongo')
      const back = await measure('mongo_crash', () => waitReady())
      check('MongoDB returns on its own after SIGKILL', back.ok, `${back.seconds} s`)
      await traffic.stop()
      check('traffic was acknowledged before the crash', acknowledged(traffic.records).length > 0, acknowledged(traffic.records).length)
      await assertAudit('MongoDB crash', traffic.records)
    })

    await scenario('MongoDB outage with sessions open', async () => {
      const session = await signIn()
      const { socket, reply } = await liveSocket(session.token)
      check('socket connected before the outage', reply.startsWith('40'), reply.slice(0, 16))
      must(STACK, 'stop', 'mongo')
      check('readiness fails closed', await waitFor(() => readiness().code === 503, 60000, 2000), readiness().line)
      const closed = await measure('socket_close_on_outage', () => socket.closed(30000).then(() => true, () => false))
      check('open sockets are closed during the outage', closed.ok, `${closed.seconds} s`)
      socket.destroy()
      check('requests are refused rather than served from stale state', (await api('GET', '/api/auth/me', { headers: bearer(session.token) })).status === 503)
      const firing = await waitFor(async () => (await alertState('SentinelMongoDisconnected')) === 'firing', 120000, 3000)
      check('the MongoDB alert fires', firing, await alertState('SentinelMongoDisconnected'))
      must(STACK, 'start', 'mongo')
      const back = await measure('mongo_outage', () => waitReady())
      check('service recovers with no backend restart', back.ok, `${back.seconds} s`)
    })

    await scenario('Session revocation during a database partition', async () => {
      const session = await signIn()
      const { socket, reply } = await liveSocket(session.token)
      check('socket connected before the partition', reply.startsWith('40'), reply.slice(0, 16))
      const backend = must(STACK, 'ps', '-q', 'backend').stdout.trim()
      const net_ = `${PROJECT}_default`
      if (docker('network', 'disconnect', net_, backend).status !== 0) throw new Error('could not disconnect the backend')
      check('readiness fails closed during the partition', await waitFor(() => readiness().code === 503, 60000, 2000), readiness().line)
      const changed = mongo(`const u=db.users.findOne({email:'${ADMIN_EMAIL}'});print(db.authsessions.updateMany({user:u._id,revokedAt:null},{$set:{revokedAt:new Date(),revocationReason:'partition-test'}}).modifiedCount)`).out
      check('session revoked in the database while the backend cannot see it', Number(changed) >= 1, changed)
      const closed = await measure('socket_close_on_partition', () => socket.closed(45000).then(() => true, () => false))
      check('the socket does not outlive the partition', closed.ok, `${closed.seconds} s`)
      socket.destroy()
      if (docker('network', 'connect', '--alias', 'backend', net_, backend).status !== 0) throw new Error('could not reconnect the backend')
      const back = await measure('network_partition', () => waitReady())
      check('service recovers after reconnection', back.ok, `${back.seconds} s`)
      check('the revoked token stays refused after recovery', (await api('GET', '/api/auth/me', { headers: bearer(session.token) })).status === 401)
    })

    await scenario('Containment operator recovery', async () => {
      const { token } = await signIn()
      const ip = nextTarget()
      const created = await contain(token, ip)
      const id = created.json?.data?.action?.containmentId
      check('containment created', created.status === 201, created.status)
      mongo(`db.containmentactions.updateOne({containmentId:'${id}'},{$set:{enforcementStatus:'APPLYING',updatedAt:new Date(Date.now()-120000)}})`)
      const diagnosis = await api('GET', `/api/containment/actions/${id}/recovery-diagnosis`, { headers: bearer(token) })
      const confirmationToken = diagnosis.json?.data?.confirmationToken
      check('diagnosis offers a safe recovery', diagnosis.status === 200 && diagnosis.json?.data?.recoverable === true && Boolean(confirmationToken), JSON.stringify(diagnosis.json?.data?.plannedOutcome))
      const body = { confirmationToken, reason: 'recovery verification' }
      check('recovery from a foreign Origin is refused', (await api('POST', `/api/containment/actions/${id}/recover`, { origin: 'https://evil.test', headers: bearer(token), body })).status === 403)
      const done = await api('POST', `/api/containment/actions/${id}/recover`, { headers: bearer(token), body })
      check('recovery releases the stuck action', done.status === 200 && done.json?.data?.released === true && done.json?.data?.enforcementStatus === 'FAILED', JSON.stringify(done.json?.data?.outcome))
      check('the confirmation token cannot be reused', (await api('POST', `/api/containment/actions/${id}/recover`, { headers: bearer(token), body })).status >= 400)
      check('the released target can be contained again', (await contain(token, ip)).status === 201)
    })

    await scenario('Audit spool capacity (16 KiB, memory-backed)', async () => {
      start(SPOOL_LIMIT, 'backend')
      const { token } = await signIn()
      run(SPOOL_LIMIT, ['exec', '-T', 'backend', 'sh', '-c', 'head -c 40960 /dev/zero > /spool-limit/filler'])
      const size = run(SPOOL_LIMIT, ['exec', '-T', 'backend', 'sh', '-c', 'df -k /spool-limit | tail -1']).stdout.trim().split(/\s+/)
      check('the spool mount is full and bounded', size[1] === '16' && size[3] === '0', size.join(' '))
      const lossBefore = Number((metrics().match(/sentinel_containment_audit_loss_total\{reason="spool_unavailable"\} (\d+)/) || [])[1] ?? -1)
      check('the loss counter is exported at zero before any loss', lossBefore === 0, lossBefore)
      const first = await contain(token)
      check('containment still succeeds with the spool full', first.status === 201, first.status)
      const lossAfter = Number((metrics().match(/sentinel_containment_audit_loss_total\{reason="spool_unavailable"\} (\d+)/) || [])[1] ?? -1)
      check('the lost durability layer is counted', lossAfter > 0, lossAfter)
      const id = first.json?.data?.action?.containmentId
      check('the event still reaches MongoDB', await waitFor(() => Number(mongo(`print(db.containment_audit_events.countDocuments({containmentId:'${id}'}))`).out) >= 2, 30000, 2000))
      const firing = await waitFor(async () => (await alertState('SentinelContainmentAuditLoss')) === 'firing', 120000, 3000)
      check('the audit loss alert fires on the first loss', firing, await alertState('SentinelContainmentAuditLoss'))
      run(SPOOL_LIMIT, ['exec', '-T', 'backend', 'sh', '-c', 'rm -f /spool-limit/filler'])
      const lossHeld = Number((metrics().match(/sentinel_containment_audit_loss_total\{reason="spool_unavailable"\} (\d+)/) || [])[1] ?? -1)
      const after = await contain(token)
      const lossEnd = Number((metrics().match(/sentinel_containment_audit_loss_total\{reason="spool_unavailable"\} (\d+)/) || [])[1] ?? -1)
      check('writes to the spool resume once space returns', after.status === 201 && lossEnd === lossHeld, `${lossHeld} then ${lossEnd}`)
      start(STACK, 'backend')
    })

    await scenario('Certificate rotation', async () => {
      const before = await fingerprint()
      const original = { cert: path.join(tmp, 'original.pem'), key: path.join(tmp, 'original.key'), ca: target.ca }
      fs.copyFileSync(certs.cert, original.cert)
      const reissued = issueCerts(path.join(tmp, 'rotated'), [HOST, 'localhost'])
      installPair(reissued.cert, reissued.key)
      const reload = () => run(STACK, ['exec', '-T', 'frontend', 'nginx', '-s', 'reload'])
      check('nginx accepts the new pair', run(STACK, ['exec', '-T', 'frontend', 'nginx', '-t']).status === 0)
      check('reload succeeds without a restart', reload().status === 0)
      const rotated = await waitFor(async () => (await fingerprint()) !== before, 15000)
      check('new connections present the new certificate', rotated)
      await tlsRequest(target, 'GET', '/').then(
        () => check('clients pinned to the old CA reject the new certificate', false),
        (err) => check('clients pinned to the old CA reject the new certificate', /certificate|issuer/i.test(err.message), err.message)
      )
      target.ca = fs.readFileSync(reissued.ca)
      check('clients trusting the new CA connect', (await tlsRequest(target, 'GET', '/')).status === 200)
      const good = await fingerprint()
      fs.writeFileSync(certs.cert, 'not a certificate\n')
      check('a broken certificate fails the configuration test', run(STACK, ['exec', '-T', 'frontend', 'nginx', '-t']).status !== 0)
      reload()
      await sleep(1500)
      check('a broken reload leaves the working certificate in service', (await fingerprint()) === good)
      fs.copyFileSync(reissued.cert, certs.cert)
      const expired = issueExpired(fs.mkdtempSync(path.join(tmp, 'expired-')), HOST)
      installPair(expired.cert, expired.key)
      reload()
      await waitFor(async () => (await fingerprint()) !== good, 15000)
      const saved = target.ca
      target.ca = fs.readFileSync(expired.cert)
      await tlsRequest(target, 'GET', '/').then(
        () => check('an expired certificate is rejected by clients', false),
        (err) => check('an expired certificate is rejected by clients', /expired/i.test(err.message), err.message)
      )
      target.ca = saved
      installPair(reissued.cert, reissued.key)
      check('the valid certificate is restored', reload().status === 0 && (await waitFor(async () => (await fingerprint()) === good, 15000)))
    })

    await scenario('Docker daemon restart (host reboot)', async () => {
      const restarted = spawnSync('sudo', ['-n', 'systemctl', 'restart', 'docker'], { encoding: 'utf8' })
      if (restarted.status !== 0) throw new Error(`could not restart Docker: ${restarted.stderr}`)
      const back = await measure('daemon_restart', () => waitReady(280000))
      check('the stack returns with no manual step', back.ok, `${back.seconds} s`)
      const session = await signIn()
      check('existing data is intact', session.login.status === 200, session.login.status)
      must(STACK, '--profile', 'monitoring', 'up', '-d', '--no-deps', 'prometheus')
    })

    await scenario('Encrypted backup under live traffic, then disaster recovery', async () => {
      const ageBin = process.env.AGE_BIN || 'age'
      const keygen = path.join(path.dirname(ageBin), 'age-keygen')
      const keys = path.join(tmp, 'keys')
      const backups = path.join(tmp, 'backups')
      fs.mkdirSync(keys, { mode: 0o700 })
      const identity = path.join(keys, 'recovery.key')
      const made = spawnSync(keygen, ['-o', identity], { encoding: 'utf8' })
      if (made.status !== 0) throw new Error(`age-keygen failed: ${made.stderr}`)
      const recipient = spawnSync(keygen, ['-y', identity], { encoding: 'utf8' }).stdout.trim()
      const filled = mongo(`for(let b=0;b<${FILLER_DOCUMENTS / 1000};b++){db.reliability_fill.insertMany(Array.from({length:1000},(_,i)=>({b,i,pad:'x'.repeat(256)})))};print(db.reliability_fill.countDocuments())`)
      check(`${FILLER_DOCUMENTS} synthetic documents loaded`, filled.out === String(FILLER_DOCUMENTS), filled.out)
      const { token } = await signIn()
      const traffic = startTraffic(token, { max: 150, intervalMs: 150 })
      await sleep(1500)
      const dumpStarted = Date.now()
      const made2 = await backupTool('backup', '--project', PROJECT, ...composeFlags, '--compose-env', envFile, '--out', backups, '--recipient', recipient, '--keep', '3', '--cwd', ROOT)
      const dumpEnded = Date.now()
      await traffic.stop()
      check('encrypted backup completes under live traffic', made2.code === 0, made2.err.slice(-300) || made2.out)
      const summary = JSON.parse(made2.out || '{}')
      console.log(`backup: ${summary.bytes} bytes in ${summary.seconds} s`)
      const before = traffic.records.filter((r) => r.status === 201 && r.ackedAt < dumpStarted)
      const during = traffic.records.filter((r) => r.status === 201 && r.ackedAt >= dumpStarted && r.ackedAt <= dumpEnded)
      check('containment traffic ran during the backup', before.length > 0 && during.length > 0, `${before.length} before, ${during.length} during`)
      const contents = fs.readFileSync(summary.file)
      check('the backup file is age ciphertext', contents.subarray(0, 21).toString() === 'age-encryption.org/v1')
      check('no plaintext marker appears in the backup', !contents.includes('sentinel-db') && !contents.includes(ADMIN_EMAIL))
      check('only the backup and its checksum are in the backup directory, not the key', fs.readdirSync(backups).sort().join() === [path.basename(summary.file), `${path.basename(summary.file)}.sha256`].sort().join())
      check('checksum verification passes', (await backupTool('verify', '--backup', summary.file)).code === 0)

      const tampered = path.join(tmp, 'tampered')
      fs.mkdirSync(tampered)
      const copy = path.join(tampered, path.basename(summary.file))
      fs.copyFileSync(summary.file, copy)
      fs.copyFileSync(`${summary.file}.sha256`, `${copy}.sha256`)
      const altered = fs.readFileSync(copy)
      altered[altered.length - 20] ^= 1
      fs.writeFileSync(copy, altered)
      const restoreArgs = (file, key) => ['restore', '--project', PROJECT, ...composeFlags, '--compose-env', envFile, '--backup', file, '--identity', key, '--confirm-restore', PROJECT, '--cwd', ROOT]
      const refusedTamper = await backupTool(...restoreArgs(copy, identity))
      check('a tampered backup is refused before decryption', refusedTamper.code !== 0 && /checksum/.test(refusedTamper.err), refusedTamper.err.slice(-120))
      const wrongKey = path.join(keys, 'wrong.key')
      spawnSync(keygen, ['-o', wrongKey], { encoding: 'utf8' })
      const refusedFull = await backupTool(...restoreArgs(summary.file, identity))
      check('a restore onto a volume that already has data is refused', refusedFull.code !== 0 && /not empty/.test(refusedFull.err), refusedFull.err.slice(-120))
      const sideBySide = path.join(backups, 'recovery.key')
      fs.copyFileSync(identity, sideBySide)
      fs.chmodSync(sideBySide, 0o600)
      const refusedSide = await backupTool(...restoreArgs(summary.file, sideBySide))
      fs.rmSync(sideBySide)
      check('a recovery key stored with the backups is refused', refusedSide.code !== 0 && /must not be stored/.test(refusedSide.err), refusedSide.err.slice(-120))

      must(STACK, 'stop', 'backend')
      const live = JSON.parse(mongo(SNAPSHOT).out)
      must(STACK, 'down', '-v')
      const recovered = await measure('disaster_restore', async () => {
        start(STACK, 'mongo')
        const refusedKey = await backupTool(...restoreArgs(summary.file, wrongKey))
        check('the wrong key cannot restore, and writes nothing', refusedKey.code !== 0 && mongo('print(db.getSiblingDB(\'sentinel-db\').getCollectionNames().length)').out === '0', refusedKey.err.slice(-120))
        const loaded = await backupTool(...restoreArgs(summary.file, identity))
        check('encrypted backup restored onto a brand-new volume with oplog replay', loaded.code === 0, loaded.err.slice(-300))
        if (loaded.code !== 0) return false
        must(STACK, 'restart', 'mongo')
        start(STACK, ...SERVICES)
        return waitReady()
      })
      check('stack is ready after disaster recovery', recovered.ok, `${recovered.seconds} s`)
      const state = auditState()
      const problems = auditProblems({ ...state, acknowledged: acknowledged(before), inFlight: 6 })
      check('restored trail: everything acknowledged before the backup is present, ordered, gap-free and unique', problems.length === 0, problems.join('; ') || JSON.stringify({ events: state.sequence.length, counter: state.counter }))
      const restored = JSON.parse(mongo(SNAPSHOT).out)
      check('filler data restored completely', restored.reliability_fill?.n === FILLER_DOCUMENTS, restored.reliability_fill?.n)
      const indexIssues = Object.keys(live).filter((c) => JSON.stringify(live[c].i) !== JSON.stringify(restored[c]?.i))
      check('every index is restored, including unique and sparse', indexIssues.length === 0, indexIssues.join(','))
      const newest = auditState().counter
      const after = await signIn()
      check('accounts from the backup sign in', after.login.status === 200, after.login.status)
      await contain(after.token)
      check('audit sequence continues past the restored events', await waitFor(() => auditState().counter > newest, 30000, 2000))
      const denied = JSON.parse(mongo(ALL_DENIED_JS, 'app').out || '{}')
      check('least-privilege denials hold on the restored data', Object.keys(denied).length === 9 && Object.values(denied).every((c) => c === 13), JSON.stringify(denied))
      const backupUser = run(STACK, ['exec', '-T', 'mongo', 'sh', '-c', `mongosh --quiet -u sentinel_backup -p "$SENTINEL_BACKUP_PASSWORD" --authenticationDatabase admin sentinel-db --eval "try{db.users.updateOne({},{\\$set:{x:1}});print('ALLOWED')}catch(e){print(e.code)}"`]).stdout.trim()
      check('the backup user cannot change data', backupUser.split('\n').pop() === '13', backupUser)
    })

    await scenario('Rollback and forward upgrade', async () => {
      const added = spawnSync('git', ['worktree', 'add', '--detach', rollbackDir, ROLLBACK_REF], { cwd: ROOT, encoding: 'utf8' })
      if (added.status !== 0) throw new Error(`git worktree failed: ${added.stderr}`)
      const session = await signIn()
      const marker = await contain(session.token)
      check('data written on the current version', marker.status === 201, marker.status)
      const id = marker.json?.data?.action?.containmentId
      must(STACK, 'down')
      const previous = (args) => {
        const r = run(BASE, args, rollbackDir)
        if (r.status !== 0) throw new Error(`previous version ${args.join(' ')} failed: ${clean(r.stderr).slice(-1500)}`)
      }
      previous(['build'])
      previous(['up', '-d', '--wait', '--wait-timeout', '600', ...SERVICES])
      check('previous version starts on current data', true, ROLLBACK_REF)
      const old = await signIn()
      check('previous version: sign-in works', old.login.status === 200, old.login.status)
      const trail = await api('GET', `/api/containment/actions/${id}/audit`, { headers: bearer(old.token) })
      check('previous version: reads the current audit trail', trail.status === 200 && trail.json?.data?.events?.length >= 2, trail.status)
      const oldWrite = await contain(old.token)
      check('previous version: can write', oldWrite.status === 201, oldWrite.status)
      await sleep(3000)
      previous(['down'])
      must(STACK, 'build')
      start(STACK, ...SERVICES)
      const again = await signIn()
      check('current version returns on the same data', again.login.status === 200, again.login.status)
      const backTrail = await api('GET', `/api/containment/actions/${oldWrite.json?.data?.action?.containmentId}/audit`, { headers: bearer(again.token) })
      check('current version reads what the previous version wrote', backTrail.status === 200 && backTrail.json?.data?.events?.length >= 2, backTrail.status)
    })

    section('Recovery objectives')
    for (const [name, seconds] of Object.entries(rto)) console.log(`RTO measured  ${name}: ${seconds} s${RTO_TARGETS_SECONDS[name] ? ` (target ${RTO_TARGETS_SECONDS[name]} s)` : ''}`)
    for (const statement of RPO_STATEMENTS) console.log(`RPO  ${statement}`)
    const rtoIssues = rtoProblems(rto, RTO_TARGETS_SECONDS)
    check('every recovery time objective was measured and met', rtoIssues.length === 0, rtoIssues.join('; '))
  } catch (err) {
    check(`verification stopped: ${err.message}`, false)
  } finally {
    if (failures) {
      for (const s of SERVICES) console.log(`\n--- ${s} log tail ---\n${clean(run(STACK, ['logs', '--tail', '40', s]).stdout)}`)
    }
    run(SPOOL_LIMIT, ['--profile', 'monitoring', 'down', '-v', '--remove-orphans'])
    if (fs.existsSync(rollbackDir)) spawnSync('git', ['worktree', 'remove', '--force', rollbackDir], { cwd: ROOT })
    fs.rmSync(METRICS_TOKEN_FILE, { force: true })
    const list = (...args) => spawnSync('docker', [...args, '--filter', `label=com.docker.compose.project=${PROJECT}`], { encoding: 'utf8' })
    const leftovers = leftoverProblems({ containers: list('ps', '-aq'), networks: list('network', 'ls', '-q'), volumes: list('volume', 'ls', '-q') })
    check('disposable containers, networks and volumes removed', leftovers.length === 0, leftovers.join('; '))
    fs.rmSync(tmp, { recursive: true, force: true })
  }
  console.log(`\n${failures ? `${failures} check(s) failed` : 'All recovery checks passed'}`)
  return failures ? 1 : 0
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('recovery verification error: ' + err.message)
      process.exit(2)
    }
  )
}
module.exports = { RTO_TARGETS_SECONDS, RPO_STATEMENTS, hardeningProblems, auditProblems, rtoProblems, memoryProblems, issueExpired }
