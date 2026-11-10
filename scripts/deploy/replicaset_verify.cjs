#!/usr/bin/env node
'use strict'
/**
 * Verifies the single-node replica-set overlay end to end on disposable infrastructure (GitHub Actions).
 *
 * Uses only generated secrets, a throwaway CA and synthetic data: migrates a standalone volume, initialises a fresh one,
 * tests least privilege, real transactions, revocation through the change stream, MongoDB outage and recovery, backup,
 * restore and disaster recovery, and confirms TLS and the containment audit trail still work. MongoDB is never published
 * and real firewall enforcement is never enabled. Refuses to run outside CI unless --disposable is given.
 */
const { spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { PROJECT, ALL_DENIED_JS, buildSecrets, redactor, publishProblems, enforcementProblems, leftoverProblems } = require('./compose_verify.cjs')
const { tlsConfigProblems, cookieProblems, issueCerts, tlsRequest, wsConnect, portOpen } = require('./tls_verify.cjs')

const ROOT = path.resolve(__dirname, '..', '..')
const HOST = 'sentinel.test'
const PORT = 8443
const ORIGIN = `https://${HOST}:${PORT}`
const ADMIN_EMAIL = 'ci-admin@sentinel.test'
const SERVICES = ['mongo', 'ai-engine', 'backend', 'frontend']
const DEV = ['docker-compose.yml']
const STANDALONE = ['docker-compose.yml', 'docker-compose.tls.yml']
const REPLICA = [...STANDALONE, 'docker-compose.replicaset.yml']

function replicaConfigProblems(config) {
  const problems = []
  const { mongo = {}, backend = {} } = config.services || {}
  const env = backend.environment || {}
  const command = mongo.command || []
  const value = (flag) => command[command.indexOf(flag) + 1]
  const health = (mongo.healthcheck?.test || []).join(' ')
  if ((mongo.ports || []).length) problems.push('MongoDB is published')
  if (!command.includes('--replSet') || value('--replSet') !== 'rs0') problems.push('mongod is not started as rs0')
  if (!command.includes('--keyFile')) problems.push('internal authentication is not enabled')
  if (!(mongo.secrets || []).some((s) => s.source === 'mongo_keyfile')) problems.push('the keyfile is not delivered as a secret')
  if (Object.keys(mongo.environment || {}).some((k) => /KEYFILE/i.test(k))) problems.push('the keyfile is in the environment')
  if (!/sentinel-mongo-configured/.test(health)) problems.push('healthcheck does not wait for configuration')
  if (!/setName === 'rs0'/.test(health) || !/isWritablePrimary/.test(health)) problems.push('healthcheck is not primary-aware')
  if (!/replicaSet=rs0/.test(env.MONGO_URI || '')) problems.push('MONGO_URI does not name the replica set')
  if (!/^mongodb:\/\/sentinel_app:/.test(env.MONGO_URI || '')) problems.push('the backend is not using the least-privilege user')
  if (env.MONGO_USE_TRANSACTIONS !== 'true') problems.push('transactions are off')
  if (env.AUTH_REVOCATION_MODE !== 'mongo-stream') problems.push('revocation is not using the change stream')
  return problems
}

function integrityProblems(before, after) {
  const problems = []
  for (const name of new Set([...Object.keys(before), ...Object.keys(after)])) {
    if (!before[name] || !after[name]) problems.push(`${name}: only on one side`)
    else if (before[name].n !== after[name].n) problems.push(`${name}: ${before[name].n} documents became ${after[name].n}`)
    else if (JSON.stringify(before[name].i) !== JSON.stringify(after[name].i)) problems.push(`${name}: indexes differ`)
  }
  return problems
}

function sequenceProblems(sequence, counter) {
  if (!sequence.length) return ['no audit events']
  const problems = []
  if (sequence.some((value, i) => i > 0 && value <= sequence[i - 1])) problems.push('sequence is not strictly increasing')
  if (counter < sequence[sequence.length - 1]) problems.push('counter is behind the newest event')
  return problems
}

const SNAPSHOT = (name) => `const d=db.getSiblingDB('${name}');const r={};for(const c of d.getCollectionNames().sort()){r[c]={n:d[c].countDocuments(),i:d[c].getIndexes().map(x=>[x.name,JSON.stringify(x.key),!!x.unique,!!x.sparse]).sort()}};print(JSON.stringify(r))`
const REPLICA_DENIED_JS = `const out={};const t=(n,f)=>{try{f();out[n]='ALLOWED'}catch(e){out[n]=e.code}};
t('status',()=>db.adminCommand({replSetGetStatus:1}));
t('stepdown',()=>db.adminCommand({replSetStepDown:1}));
t('reconfig',()=>db.adminCommand({replSetReconfig:{_id:'rs0',version:9,members:[]}}));
t('oplog',()=>db.getSiblingDB('local').getCollection('oplog.rs').findOne());
t('watch_cluster',()=>{const c=db.getMongo().watch();c.tryNext();c.close()});
t('watch_admin',()=>{const c=db.getSiblingDB('admin').watch();c.tryNext();c.close()});
t('watch_other',()=>{const c=db.getSiblingDB('other_database').watch();c.tryNext();c.close()});
print(JSON.stringify(out));`
const TRANSACTIONS_JS = `const out={};const tag='tx-'+Date.now();
const count=(c,v)=>db.getCollection(c).countDocuments({probe:v});
const run=(v,finish)=>{const s=db.getMongo().startSession();const d=s.getDatabase('sentinel-db');s.startTransaction();d.alerts.insertOne({probe:v});d.threatlogs.insertOne({probe:v});const hidden=count('alerts',v);finish(s,d);return hidden};
out.hidden=run(tag+'c',(s)=>s.commitTransaction());out.committed=[count('alerts',tag+'c'),count('threatlogs',tag+'c')];
run(tag+'a',(s)=>s.abortTransaction());out.aborted=[count('alerts',tag+'a'),count('threatlogs',tag+'a')];
try{run(tag+'r',(s,d)=>{d.containment_audit_events.updateOne({},{$set:{x:1}});s.commitTransaction()});out.denied='ALLOWED'}catch(e){out.denied=e.code}
out.rolledBack=[count('alerts',tag+'r'),count('threatlogs',tag+'r')];
db.alerts.deleteMany({probe:{$regex:'^'+tag}});db.threatlogs.deleteMany({probe:{$regex:'^'+tag}});
print(JSON.stringify(out));`
// The server reports these as 64-bit Long values, which print in a form Number() cannot read.
const TX_COUNT_JS = (field) => `print(String(db.serverStatus().transactions.${field}))`
const SEQUENCE_JS = "print(JSON.stringify([db.containment_audit_events.find().sort({seq:1}).toArray().map(e=>e.seq),(db.counters.findOne({_id:'containment_audit_events'})||{}).seq]))"

async function main() {
  if (!process.env.CI && !process.argv.includes('--disposable')) {
    console.error('Refusing to run outside CI without --disposable: this builds and starts containers.')
    return 2
  }
  // Added here so it is generated per run and removed from all output like the others.
  const secrets = { ...buildSecrets(), SYNTHETIC_OPERATOR_PASSWORD: 'Ci' + crypto.randomBytes(24).toString('hex') + 'aA1' }
  const clean = redactor(secrets)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-rs-'))
  const certs = issueCerts(tmp, [HOST, 'localhost'])
  const keyfile = path.join(tmp, 'mongo-keyfile')
  const keyMaterial = crypto.randomBytes(756).toString('base64')
  fs.writeFileSync(keyfile, keyMaterial, { mode: 0o400 })
  const envFile = path.join(tmp, 'compose.env')
  fs.writeFileSync(
    envFile,
    Object.entries({ ...secrets, ADMIN_EMAIL, TLS_PUBLIC_ORIGIN: ORIGIN, TLS_CERT_DIR: certs.dir, MONGO_KEYFILE: keyfile })
      .map(([k, v]) => `${k}=${v}`)
      .join('\n') + '\n',
    { mode: 0o600 }
  )
  const target = { host: '127.0.0.1', port: PORT, servername: HOST, ca: fs.readFileSync(certs.ca) }

  let failures = 0
  const check = (name, ok, detail = '') => {
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail !== '' ? `  [${clean(detail)}]` : ''}`)
    if (!ok) failures++
    return ok
  }
  const section = (title) => console.log(`\n== ${title}`)
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  const raw = (files, args, options = {}) =>
    spawnSync('docker', ['compose', '-p', PROJECT, '--env-file', envFile, ...files.flatMap((f) => ['-f', f]), ...args], {
      cwd: ROOT,
      maxBuffer: 512 * 1024 * 1024,
      ...options,
    })
  const run = (files, args) => {
    const r = raw(files, args, { encoding: 'utf8' })
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
  }
  const must = (files, ...args) => {
    const r = run(files, args)
    if (r.status !== 0) throw new Error(`docker compose ${args.join(' ')} failed: ${clean(r.stderr).slice(-2000)}`)
    return r
  }
  const IDENTITIES = {
    none: '',
    app: '-u sentinel_app -p "$SENTINEL_APP_PASSWORD" --authenticationDatabase sentinel-db',
    root: '-u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin',
  }
  const ROOT_TOOL = '-u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --quiet'
  const mongo = (files, who, js) => {
    const r = run(files, ['exec', '-T', '-e', `JS=${js}`, 'mongo', 'sh', '-c', `mongosh --quiet ${IDENTITIES[who]} sentinel-db --eval "$JS"`])
    return { status: r.status, out: r.stdout.trim().split('\n').pop() || '', err: r.stderr }
  }
  const snapshot = (files, name = 'sentinel-db') => JSON.parse(mongo(files, 'root', SNAPSHOT(name)).out || '{}')
  const dump = (files) => {
    const r = raw(files, ['exec', '-T', 'mongo', 'sh', '-c', `mongodump ${ROOT_TOOL} --db sentinel-db --archive`])
    if (r.status !== 0) throw new Error(`mongodump failed: ${clean(r.stderr.toString()).slice(-500)}`)
    return r.stdout
  }
  const restore = (files, archive, options) => {
    const r = raw(files, ['exec', '-T', 'mongo', 'sh', '-c', `mongorestore ${ROOT_TOOL} --archive ${options}`], { input: archive })
    return { status: r.status, err: clean((r.stderr || '').toString()) }
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
  const signIn = async (email = ADMIN_EMAIL, password = secrets.ADMIN_INITIAL_PASSWORD) => {
    const csrf = await api('GET', '/api/auth/csrf')
    const jar = cookiesOf(csrf)
    const login = await api('POST', '/api/auth/login', { headers: { 'X-CSRF-Token': csrf.json.data.csrfToken, Cookie: jar.join('; ') }, body: { email, password } })
    return { csrf, login, csrfToken: csrf.json.data.csrfToken, jar: [...jar, ...cookiesOf(login)], token: login.json?.data?.token }
  }
  const proxyReady = () => waitFor(async () => (await api('GET', '/api/auth/csrf')).status === 200, 180000, 2000)
  const provision = (session, email) =>
    api('POST', '/api/auth/provision', {
      headers: { ...bearer(session.token), 'X-CSRF-Token': session.csrfToken, Cookie: session.jar.join('; ') },
      body: { name: 'Synthetic Operator', email, password: secrets.SYNTHETIC_OPERATOR_PASSWORD, role: 'viewer', department: 'SOC' },
    })
  const contain = (token, address) => api('POST', '/api/containment/actions', { headers: bearer(token), body: { target: address, actionType: 'block_ip', reason: 'replica verification', durationSeconds: 600 } })
  const trail = async (token, id) => (await api('GET', `/api/containment/actions/${id}/audit`, { headers: bearer(token) })).json?.data
  const containAndAudit = async (token, address) => {
    const action = await contain(token, address)
    const id = action.json?.data?.action?.containmentId
    const stored = await waitFor(async () => (await trail(token, id))?.events?.length >= 2, 30000)
    return { action, id, stored }
  }
  const sequence = (files) => {
    const [seqs, counter] = JSON.parse(mongo(files, 'root', SEQUENCE_JS).out || '[[],0]')
    return { seqs, counter, problems: sequenceProblems(seqs, counter ?? -1) }
  }
  const readiness = (files) => {
    const r = run(files, ['exec', '-T', 'backend', 'node', '-e', "fetch('http://127.0.0.1:5000/health/ready').then(async r=>console.log(r.status+' '+await r.text()))"])
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
  const liveSocket = async (token) => {
    const socket = await wsConnect(target, { origin: ORIGIN })
    await socket.next()
    socket.send(`40${JSON.stringify({ token })}`)
    return { socket, reply: await socket.next() }
  }
  const denials = (files, label) => {
    const r = mongo(files, 'app', ALL_DENIED_JS)
    let result = {}
    try {
      result = JSON.parse(r.out)
    } catch {
      return check(`${label}: permission probe ran`, false, r.err.slice(-300))
    }
    const wrong = Object.entries(result).filter(([, code]) => code !== 13)
    return check(`${label}: ${Object.keys(result).length} unauthorized operations denied (code 13)`, wrong.length === 0 && Object.keys(result).length === 9, JSON.stringify(wrong))
  }
  const start = (files, ...services) => must(files, 'up', '-d', '--wait', '--wait-timeout', '600', ...services)

  try {
    run(REPLICA, ['down', '-v', '--remove-orphans'])

    section('Configuration')
    const config = JSON.parse(must(REPLICA, 'config', '--format', 'json').stdout)
    const configIssues = [...replicaConfigProblems(config), ...tlsConfigProblems(config), ...publishProblems(config), ...enforcementProblems(config)]
    check('overlay: replica set, keyfile, primary-aware health, transactions, change stream, TLS kept, MongoDB unpublished', configIssues.length === 0, configIssues.join('; '))
    const dev = JSON.parse(run(DEV, ['config', '--format', 'json']).stdout)
    check('development stack is unchanged', dev.services.backend.environment.NODE_ENV === 'development' && !dev.services.mongo.command && !dev.services.backend.environment.MONGO_USE_TRANSACTIONS)
    const tlsOnly = JSON.parse(run(STANDALONE, ['config', '--format', 'json']).stdout)
    check('TLS-only stack is unchanged', tlsOnly.services.backend.environment.AUTH_REVOCATION_MODE === 'single' && !/replicaSet/.test(tlsOnly.services.backend.environment.MONGO_URI))

    must(REPLICA, 'build')
    const owned = spawnSync('docker', ['run', '--rm', '--user', '0', '--entrypoint', 'sh', '-v', `${certs.dir}:/tls`, `${PROJECT}-frontend`, '-c', 'chown 101:101 /tls/privkey.pem && chmod 400 /tls/privkey.pem'], { encoding: 'utf8' })
    if (owned.status !== 0) throw new Error(`could not set key ownership: ${owned.stderr.slice(-300)}`)

    section('Migration rehearsal from a standalone volume (synthetic data)')
    start(STANDALONE, ...SERVICES)
    check('standalone TLS stack starts', true)
    const oldSession = await signIn()
    check('standalone: administrator signs in', oldSession.login.status === 200, oldSession.login.status)
    const migrated = 'migrated-operator@sentinel.test'
    const provisioned = await provision(oldSession, migrated)
    check('standalone: synthetic operator provisioned', provisioned.status === 201, provisioned.status)
    const oldAction = await containAndAudit(oldSession.token, '198.51.100.90')
    check('standalone: containment and audit trail written', oldAction.action.status === 201 && oldAction.stored, oldAction.action.status)
    must(STANDALONE, 'stop', 'backend')
    const beforeMigration = snapshot(STANDALONE)
    must(STANDALONE, 'down')
    start(REPLICA, 'mongo')
    const statusOld = JSON.parse(mongo(REPLICA, 'root', "const s=rs.status();print(JSON.stringify({set:s.set,state:s.members[0].stateStr,n:s.members.length}))").out || '{}')
    check('existing data files became a single-node primary', statusOld.set === 'rs0' && statusOld.state === 'PRIMARY' && statusOld.n === 1, JSON.stringify(statusOld))
    const migrationDiff = integrityProblems(beforeMigration, snapshot(REPLICA))
    check('every collection and index is unchanged by migration', migrationDiff.length === 0, migrationDiff.join('; '))
    const roleText = mongo(REPLICA, 'root', "print(JSON.stringify(db.getRole('sentinel_app_role',{showPrivileges:true}).privileges.filter(p=>p.resource.collection==='')[0].actions.includes('changeStream')))")
    check('role update reached the existing volume before health passed', roleText.out === 'true', roleText.out)
    start(REPLICA, ...SERVICES)
    if (process.argv.includes('--inject-failure')) throw new Error('injected failure (cleanup test)')
    const signedAfter = await signIn(migrated, secrets.SYNTHETIC_OPERATOR_PASSWORD)
    check('migrated operator signs in', signedAfter.login.status === 200, signedAfter.login.status)
    const adminAfter = await signIn()
    check('migrated administrator signs in', adminAfter.login.status === 200, adminAfter.login.status)
    check('audit trail survives migration', (await trail(adminAfter.token, oldAction.id))?.events?.length >= 2)
    const afterSeq = await containAndAudit(adminAfter.token, '198.51.100.91')
    const migratedSeq = sequence(REPLICA)
    check('audit sequence continues after migration', afterSeq.stored && migratedSeq.problems.length === 0, JSON.stringify(migratedSeq))
    denials(REPLICA, 'migrated volume')

    section('Fresh volume initialisation')
    must(REPLICA, 'down', '-v')
    start(REPLICA, ...SERVICES)
    check('fresh volume: every service healthy', true)
    const facts = JSON.parse(mongo(REPLICA, 'root', "const s=rs.status();const o=db.adminCommand({getCmdLineOpts:1}).parsed;print(JSON.stringify({set:s.set,state:s.members[0].stateStr,host:rs.conf().members[0].host,n:s.members.length,key:o.security&&o.security.keyFile,repl:o.replication&&o.replication.replSet}))").out || '{}')
    check('single-node primary with the expected member', facts.set === 'rs0' && facts.state === 'PRIMARY' && facts.host === 'mongo:27017' && facts.n === 1, JSON.stringify(facts))
    check('internal authentication uses the keyfile', facts.key === '/data/mongo-keyfile' && facts.repl === 'rs0', JSON.stringify(facts))
    const stat = run(REPLICA, ['exec', '-T', 'mongo', 'stat', '-c', '%a %U', '/data/mongo-keyfile']).stdout.trim()
    check('keyfile is mode 400, owned by mongodb', stat === '400 mongodb', stat)
    const id = must(REPLICA, 'ps', '-q', 'mongo').stdout.trim()
    const inspect = spawnSync('docker', ['inspect', id], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }).stdout
    check('keyfile contents are absent from the container configuration', !inspect.includes(keyMaterial.slice(0, 48)))
    const logs = run(REPLICA, ['logs', 'mongo']).stdout
    check('MongoDB log carries no secret', !Object.values(secrets).some((s) => logs.includes(s)) && !logs.includes(keyMaterial.slice(0, 48)))
    const anonymous = mongo(REPLICA, 'none', 'print(db.users.countDocuments())')
    check('unauthenticated access is refused', anonymous.status !== 0 || /Unauthorized|requires authentication/i.test(anonymous.out + anonymous.err))
    check('port 27017 is closed on the host', !(await portOpen('127.0.0.1', 27017)))
    const mode = run(REPLICA, ['logs', 'backend']).stdout
    check('backend is using change-stream revocation', /Authentication revocation mode: mongo-stream/.test(mode))
    const fresh = readiness(REPLICA)
    check('readiness: database, AI engine and revocation available', fresh.code === 200 && fresh.body.status === 'ready', fresh.line)

    section('Least privilege')
    denials(REPLICA, 'fresh volume')
    const replicaDenied = JSON.parse(mongo(REPLICA, 'app', REPLICA_DENIED_JS).out || '{}')
    const allowedAdmin = Object.entries(replicaDenied).filter(([, code]) => code !== 13)
    check('replica-set administration and wider change streams are denied (code 13)', Object.keys(replicaDenied).length === 7 && allowedAdmin.length === 0, JSON.stringify(replicaDenied))

    section('Transactions')
    const tx = JSON.parse(mongo(REPLICA, 'app', TRANSACTIONS_JS).out || '{}')
    check('uncommitted writes are invisible', tx.hidden === 0, tx.hidden)
    check('commit stores both documents', String(tx.committed) === '1,1', String(tx.committed))
    check('abort discards both documents', String(tx.aborted) === '0,0', String(tx.aborted))
    check('an engine refusal inside a transaction is denied and rolls back', tx.denied === 13 && String(tx.rolledBack) === '0,0', JSON.stringify(tx))
    const txCount = (field) => Number(mongo(REPLICA, 'root', TX_COUNT_JS(field)).out)
    const session = await signIn()
    const committedBefore = txCount('totalCommitted')
    const txUser = 'transaction-operator@sentinel.test'
    const created = await provision(session, txUser)
    check('application commits through its transactional path', created.status === 201 && txCount('totalCommitted') > committedBefore, created.status)
    const audited = mongo(REPLICA, 'root', "print(db.auditlogs.countDocuments({action:'USER_CREATED'}))").out
    check('account and its audit entry were both stored', Number(audited) >= 1, audited)
    const privilege = "[{resource:{db:'sentinel-db',collection:'auditlogs'},actions:['insert']}]"
    mongo(REPLICA, 'root', `db.revokePrivilegesFromRole('sentinel_app_role',${privilege})`)
    const abortedBefore = txCount('totalAborted')
    const rollbackUser = 'rollback-operator@sentinel.test'
    const refused = await provision(session, rollbackUser)
    const rolledBack = mongo(REPLICA, 'root', `print(db.users.countDocuments({email:'${rollbackUser}'}))`).out
    check('application rolls back the account when its audit write is refused', refused.status >= 500 && rolledBack === '0' && txCount('totalAborted') > abortedBefore, `${refused.status} users=${rolledBack}`)
    mongo(REPLICA, 'root', `db.grantPrivilegesToRole('sentinel_app_role',${privilege})`)

    section('Revocation through the change stream')
    const revoke = "const u=db.users.findOne({email:'" + ADMIN_EMAIL + "'});print(db.authsessions.updateMany({user:u._id,revokedAt:null},{$set:{revokedAt:new Date(),revocationReason:'ci'}}).modifiedCount)"
    const revokeAndExpectClose = async (label) => {
      const live = await signIn()
      const { socket, reply } = await liveSocket(live.token)
      check(`${label}: wss connects`, reply.startsWith('40'), reply.slice(0, 20))
      const changed = mongo(REPLICA, 'root', revoke).out
      await socket.closed(5000).then(
        () => check(`${label}: a database change made outside the backend closes the socket`, Number(changed) >= 1, changed),
        (err) => check(`${label}: a database change made outside the backend closes the socket`, false, err.message)
      )
      socket.destroy()
      check(`${label}: the revoked token is refused`, (await api('GET', '/api/auth/me', { headers: bearer(live.token) })).status === 401)
    }
    await revokeAndExpectClose('session revocation')
    const forUser = await signIn()
    const userSocket = await liveSocket(forUser.token)
    mongo(REPLICA, 'root', `db.users.updateOne({email:'${ADMIN_EMAIL}'},{$inc:{authVersion:1}})`)
    await userSocket.socket.closed(5000).then(
      () => check('user revocation: an authVersion change closes the socket', true),
      (err) => check('user revocation: an authVersion change closes the socket', false, err.message)
    )
    userSocket.socket.destroy()
    const signOut = await signIn()
    const outSocket = await liveSocket(signOut.token)
    const logout = await api('POST', '/api/auth/logout', { headers: { 'X-CSRF-Token': signOut.csrfToken, Cookie: signOut.jar.join('; ') } })
    await outSocket.socket.closed(5000).then(
      () => check('sign-out closes the socket', logout.status === 200, logout.status),
      (err) => check('sign-out closes the socket', false, err.message)
    )
    outSocket.socket.destroy()

    section('TLS and containment audit on the replica set')
    check('HTTPS with a verified certificate', (await tlsRequest(target, 'GET', '/')).status === 200)
    await tlsRequest({ ...target, ca: undefined }, 'GET', '/').then(
      () => check('untrusted CA is rejected', false),
      (err) => check('untrusted CA is rejected', /certificate|self.signed|issuer/i.test(err.message), err.message)
    )
    const csrf = await api('GET', '/api/auth/csrf')
    check('secure cookie attributes are unchanged', cookieProblems(csrf.headers['set-cookie'], '__Secure-sentinel_csrf').length === 0)
    const probe = (network, url) => {
      const script = "fetch(process.argv[1],{headers:{'x-forwarded-proto':'https'}}).then(r=>console.log('HTTP '+r.status),e=>console.log('ERR '+((e.cause&&e.cause.code)||e.message)))"
      return (spawnSync('docker', ['run', '--rm', '--network', `${PROJECT}_${network}`, `${PROJECT}-backend`, 'node', '-e', script, url], { encoding: 'utf8' }).stdout || '').trim()
    }
    const direct = probe('default', 'http://backend:5000/api/auth/csrf')
    check('spoofed headers straight to the backend still get 426', direct === 'HTTP 426', direct)
    const proxyToMongo = probe('proxy', 'http://mongo:27017/')
    check('the proxy network still cannot reach MongoDB', /^ERR/.test(proxyToMongo), proxyToMongo)
    const operator = await signIn()
    const action = await containAndAudit(operator.token, '198.51.100.92')
    check('containment becomes ACTIVE on the mock adapter', action.action.status === 201 && action.action.json?.data?.action?.enforcementStatus === 'ACTIVE' && action.action.json?.data?.action?.enforcementBackend === 'mock', action.action.status)
    check('audit events stored through the least-privilege role', action.stored)
    const status = await api('GET', '/api/containment/status', { headers: bearer(operator.token) })
    check('real enforcement is off at runtime', status.json?.data?.realEnforcementEnabled === false, JSON.stringify(status.json?.data?.realEnforcementEnabled))

    section('MongoDB outage and recovery')
    must(REPLICA, 'stop', 'mongo')
    const down = await waitFor(() => readiness(REPLICA).code === 503, 60000, 2000)
    const during = readiness(REPLICA)
    check('readiness fails closed during the outage', down && during.body.status === 'unavailable', during.line)
    const live = run(REPLICA, ['exec', '-T', 'backend', 'node', '-e', "fetch('http://127.0.0.1:5000/health/live').then(r=>console.log(r.status))"]).stdout.trim()
    check('the process stays alive during the outage', live === '200', live)
    must(REPLICA, 'start', 'mongo')
    const back = await waitFor(() => readiness(REPLICA).code === 200, 180000, 2000)
    check('readiness recovers with no backend restart', back, readiness(REPLICA).line)
    await revokeAndExpectClose('after recovery')
    must(REPLICA, 'restart', 'mongo')
    check('readiness recovers from a MongoDB restart', await waitFor(() => readiness(REPLICA).code === 200, 180000, 2000))
    const postRestart = await signIn()
    check('sign-in works after the restart', postRestart.login.status === 200, postRestart.login.status)
    const afterOutage = await containAndAudit(postRestart.token, '198.51.100.93')
    const outageSeq = sequence(REPLICA)
    check('audit sequence stays valid across outage and restart', afterOutage.stored && outageSeq.problems.length === 0, JSON.stringify(outageSeq))

    section('Backup, restore and disaster recovery')
    must(REPLICA, 'stop', 'backend')
    const expected = snapshot(REPLICA)
    const archive = dump(REPLICA)
    check('backup taken', archive.length > 0, `${archive.length} bytes`)
    const copied = restore(REPLICA, archive, "--nsFrom 'sentinel-db.*' --nsTo 'sentinel-restore-check.*'")
    check('restored into a separate database', copied.status === 0, copied.err.slice(-300))
    const copyDiff = integrityProblems(expected, snapshot(REPLICA, 'sentinel-restore-check'))
    check('every count and index matches in the copy', copyDiff.length === 0, copyDiff.join('; '))
    check('the unique sparse containment lock index was restored', JSON.stringify(expected.containmentactions?.i || []).includes('"targetLock'), JSON.stringify(expected.containmentactions?.i?.length))
    mongo(REPLICA, 'root', "db.getSiblingDB('sentinel-restore-check').dropDatabase()")
    must(REPLICA, 'down', '-v')
    start(REPLICA, 'mongo')
    const replaced = restore(REPLICA, archive, "--drop --nsInclude 'sentinel-db.*'")
    check('restored onto a brand-new volume', replaced.status === 0, replaced.err.slice(-300))
    const disasterDiff = integrityProblems(expected, snapshot(REPLICA))
    check('every count and index matches after disaster recovery', disasterDiff.length === 0, disasterDiff.join('; '))
    start(REPLICA, ...SERVICES)
    const restoredUser = await signIn(txUser, secrets.SYNTHETIC_OPERATOR_PASSWORD)
    check('an account that exists only in the backup signs in', restoredUser.login.status === 200, restoredUser.login.status)
    const restoredAdmin = await signIn()
    check('administrator signs in after recovery', restoredAdmin.login.status === 200, restoredAdmin.login.status)
    check('audit trail is intact after recovery', (await trail(restoredAdmin.token, afterOutage.id))?.events?.length >= 2)
    const beforeNext = sequence(REPLICA).counter
    const postRecovery = await containAndAudit(restoredAdmin.token, '198.51.100.94')
    const finalSeq = sequence(REPLICA)
    check('audit sequence continues past the restored events', postRecovery.stored && finalSeq.problems.length === 0 && finalSeq.counter > beforeNext, JSON.stringify({ before: beforeNext, after: finalSeq.counter }))
    denials(REPLICA, 'restored volume')
    check('API is served through the proxy after recovery', await proxyReady())
  } catch (err) {
    check(`verification stopped: ${err.message}`, false)
  } finally {
    if (failures) {
      for (const s of SERVICES) console.log(`\n--- ${s} log tail ---\n${clean(run(REPLICA, ['logs', '--tail', '40', s]).stdout)}`)
    }
    run(REPLICA, ['down', '-v', '--remove-orphans'])
    const list = (...args) => spawnSync('docker', [...args, '--filter', `label=com.docker.compose.project=${PROJECT}`], { encoding: 'utf8' })
    const leftovers = leftoverProblems({ containers: list('ps', '-aq'), networks: list('network', 'ls', '-q'), volumes: list('volume', 'ls', '-q') })
    check('disposable containers, networks and volumes removed', leftovers.length === 0, leftovers.join('; '))
    fs.rmSync(tmp, { recursive: true, force: true })
  }
  console.log(`\n${failures ? `${failures} check(s) failed` : 'All replica-set checks passed'}`)
  return failures ? 1 : 0
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('replica-set verification error: ' + err.message)
      process.exit(2)
    }
  )
}
module.exports = { replicaConfigProblems, integrityProblems, sequenceProblems, REPLICA_DENIED_JS, TRANSACTIONS_JS, TX_COUNT_JS, SEQUENCE_JS }
