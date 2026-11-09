#!/usr/bin/env node
'use strict'
/**
 * Verifies the production TLS overlay end to end on disposable infrastructure (GitHub Actions).
 *
 * Builds the real images, runs them with docker-compose.tls.yml, a throwaway CA and generated secrets, and talks to
 * nginx the way a browser would: certificate checks, TLS versions, security headers, CSRF-protected sign-in, secure
 * cookies, Socket.IO over wss, spoofed forwarding headers, attempts to bypass the proxy, restart and cleanup.
 * Real firewall enforcement is never enabled. Refuses to run outside CI unless --disposable is given.
 */
const { spawnSync } = require('child_process')
const crypto = require('crypto')
const fs = require('fs')
const https = require('https')
const net = require('net')
const os = require('os')
const path = require('path')
const tls = require('tls')
const {
  PROJECT,
  buildSecrets,
  redactor,
  publishProblems,
  livePublishProblems,
  enforcementProblems,
  leftoverProblems,
} = require('./compose_verify.cjs')

const ROOT = path.resolve(__dirname, '..', '..')
const HOST = 'sentinel.test'
const PORT = 8443
const ORIGIN = `https://${HOST}:${PORT}`
const ADMIN_EMAIL = 'ci-admin@sentinel.test'
const SERVICES = ['mongo', 'ai-engine', 'backend', 'frontend']
const SPOOFED_IP = '203.0.113.9'
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

const ipNumber = (ip) => ip.split('.').reduce((total, part) => total * 256 + Number(part), 0)
function inCidr(ip, cidr) {
  const [base, bits] = cidr.split('/')
  const size = 2 ** (32 - Number(bits))
  const start = Math.floor(ipNumber(base) / size) * size
  return ipNumber(ip) >= start && ipNumber(ip) < start + size
}

/** Rules the merged Compose configuration must satisfy before anything is started. */
function tlsConfigProblems(config) {
  const problems = []
  const { backend = {}, frontend = {} } = config.services || {}
  const env = backend.environment || {}
  const ports = frontend.ports || []
  const proxyIp = frontend.networks?.proxy?.ipv4_address
  if ((backend.ports || []).length) problems.push('backend publishes a port')
  if (ports.length !== 1 || String(ports[0].target) !== '8443' || ports[0].host_ip !== '127.0.0.1')
    problems.push('frontend must publish only 8443, on loopback')
  if (env.NODE_ENV !== 'production') problems.push('backend is not in production mode')
  if (!/^https:\/\//.test(env.CLIENT_URL || '')) problems.push('CLIENT_URL is not https')
  if (!proxyIp || env.TRUST_PROXY !== `${proxyIp}/32`) problems.push('TRUST_PROXY is not exactly the proxy address')
  if (!['single', 'mongo-stream'].includes(env.AUTH_REVOCATION_MODE)) problems.push('AUTH_REVOCATION_MODE is not set')
  if (config.networks?.proxy?.internal !== true) problems.push('the proxy network has a route out')
  const pool = config.networks?.proxy?.ipam?.config?.[0] || {}
  if (!pool.ip_range || (proxyIp && inCidr(proxyIp, pool.ip_range)))
    problems.push('another container can be assigned the proxy address')
  if (proxyIp && (!pool.subnet || !inCidr(proxyIp, pool.subnet))) problems.push('the proxy address is outside its subnet')
  if (frontend.networks && 'default' in frontend.networks) problems.push('the proxy can reach the database network')
  if (!/^[1-9]\d*(:[1-9]\d*)?$/.test(frontend.user || '')) problems.push('nginx is not configured as non-root')
  if (frontend.read_only !== true) problems.push('nginx filesystem is writable')
  if (!(frontend.cap_drop || []).includes('ALL')) problems.push('nginx keeps Linux capabilities')
  if (!(frontend.security_opt || []).includes('no-new-privileges:true')) problems.push('nginx can gain privileges')
  return problems
}

function cookieProblems(setCookies, name) {
  const found = (setCookies || []).filter((c) => c.startsWith(`${name}=`))
  if (found.length !== 1) return [`expected one ${name} cookie, found ${found.length}`]
  const attributes = found[0].split(';').map((part) => part.trim().toLowerCase())
  return ['secure', 'httponly', 'samesite=strict'].filter((a) => !attributes.includes(a)).map((a) => `${name} lacks ${a}`)
}

/** rawHeaders is the flat [name, value, ...] list, which still shows a header that was sent twice. */
function headerProblems(rawHeaders, { hsts }) {
  const values = {}
  for (let i = 0; i < rawHeaders.length; i += 2) (values[rawHeaders[i].toLowerCase()] ||= []).push(rawHeaders[i + 1])
  const problems = []
  const once = (name, pattern) => {
    const got = values[name] || []
    if (got.length !== 1 || !pattern.test(got[0])) problems.push(`${name}: ${got.length} value(s)`)
  }
  once('content-security-policy', /frame-ancestors 'none'/)
  once('x-content-type-options', /^nosniff$/)
  once('referrer-policy', /^same-origin$/)
  if (hsts) once('strict-transport-security', /^max-age=\d{7,}/)
  else if (values['strict-transport-security']) problems.push('HSTS sent where it must not be')
  if (/\d/.test((values.server || []).join(''))) problems.push('server version disclosed')
  return problems
}

function encodeClientFrame(text) {
  const payload = Buffer.from(text)
  const length = payload.length
  let head
  if (length < 126) head = Buffer.from([0x81, 0x80 | length])
  else if (length < 65536) {
    head = Buffer.alloc(4)
    head[0] = 0x81
    head[1] = 0x80 | 126
    head.writeUInt16BE(length, 2)
  } else {
    head = Buffer.alloc(10)
    head[0] = 0x81
    head[1] = 0x80 | 127
    head.writeBigUInt64BE(BigInt(length), 2)
  }
  const mask = crypto.randomBytes(4)
  const masked = Buffer.from(payload.map((byte, i) => byte ^ mask[i % 4]))
  return Buffer.concat([head, mask, masked])
}

function decodeServerFrames(buffer) {
  const frames = []
  let offset = 0
  while (buffer.length - offset >= 2) {
    let length = buffer[offset + 1] & 0x7f
    let header = 2
    if (length === 126) {
      if (buffer.length - offset < 4) break
      length = buffer.readUInt16BE(offset + 2)
      header = 4
    } else if (length === 127) {
      if (buffer.length - offset < 10) break
      length = Number(buffer.readBigUInt64BE(offset + 2))
      header = 10
    }
    if (buffer.length - offset < header + length) break
    frames.push({ opcode: buffer[offset] & 0x0f, text: buffer.subarray(offset + header, offset + header + length).toString() })
    offset += header + length
  }
  return { frames, rest: buffer.subarray(offset) }
}

/** A throwaway CA and server certificate. The CA key is deleted before returning, so nothing can be issued later. */
function issueCerts(dir, names) {
  const tlsDir = path.join(dir, 'tls')
  const caDir = path.join(dir, 'ca')
  fs.mkdirSync(tlsDir, { recursive: true })
  fs.mkdirSync(caDir, { recursive: true })
  const paths = {
    dir: tlsDir,
    ca: path.join(caDir, 'ca.pem'),
    cert: path.join(tlsDir, 'fullchain.pem'),
    key: path.join(tlsDir, 'privkey.pem'),
  }
  const caKey = path.join(caDir, 'ca.key')
  const csr = path.join(caDir, 'server.csr')
  const ext = path.join(caDir, 'server.ext')
  fs.writeFileSync(ext, `subjectAltName=${names.map((n) => `DNS:${n}`).join(',')}\nextendedKeyUsage=serverAuth\n`)
  const openssl = (...args) => {
    const r = spawnSync('openssl', args, { encoding: 'utf8' })
    if (r.status !== 0) throw new Error(`openssl ${args[0]} failed: ${(r.stderr || r.error?.message || '').slice(-300)}`)
  }
  openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', paths.ca, '-days', '2', '-subj', '/CN=SentinelAI disposable CI CA', '-addext', 'basicConstraints=critical,CA:TRUE')
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', paths.key, '-out', csr, '-subj', `/CN=${names[0]}`)
  openssl('x509', '-req', '-in', csr, '-CA', paths.ca, '-CAkey', caKey, '-CAcreateserial', '-out', paths.cert, '-days', '2', '-extfile', ext)
  fs.rmSync(caKey)
  fs.chmodSync(tlsDir, 0o755) // the mount is read as uid 101
  fs.chmodSync(paths.cert, 0o644)
  return paths
}

function tlsRequest(target, method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body)
    const req = https.request(
      {
        host: target.host,
        port: target.port,
        servername: target.servername,
        ca: target.ca,
        agent: false,
        method,
        path: urlPath,
        headers: {
          Host: `${target.servername}:${target.port}`,
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
          ...headers,
        },
      },
      (res) => {
        const chunks = []
        res.on('data', (chunk) => chunks.push(chunk))
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString()
          let json = null
          try {
            json = JSON.parse(text)
          } catch {
            // not JSON
          }
          resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, text, json })
        })
      }
    )
    req.setTimeout(20000, () => req.destroy(new Error('request timed out')))
    req.on('error', reject)
    req.end(payload)
  })
}

function protocolProbe(target, version) {
  return new Promise((resolve) => {
    const legacy = version === 'TLSv1' || version === 'TLSv1.1'
    const socket = tls.connect(
      {
        host: target.host,
        port: target.port,
        servername: target.servername,
        ca: target.ca,
        minVersion: version,
        maxVersion: version,
        // Lets this client really offer the old version, so a refusal is the server's and not our own OpenSSL policy.
        ...(legacy ? { ciphers: 'ALL:@SECLEVEL=0' } : {}),
      },
      () => {
        const protocol = socket.getProtocol()
        socket.destroy()
        resolve({ accepted: true, protocol })
      }
    )
    socket.setTimeout(15000, () => socket.destroy(new Error('timed out')))
    socket.on('error', (err) => {
      const error = `${err.code || ''} ${err.message}`
      resolve({ accepted: false, error, refusedByServer: /ALERT_PROTOCOL_VERSION|alert protocol version/i.test(error) })
    })
  })
}

function wsConnect(target, { origin }) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64')
    const req = https.request({
      host: target.host,
      port: target.port,
      servername: target.servername,
      ca: target.ca,
      agent: false,
      path: '/socket.io/?EIO=4&transport=websocket',
      headers: {
        Host: `${target.servername}:${target.port}`,
        Origin: origin,
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': key,
      },
    })
    req.setTimeout(20000, () => req.destroy(new Error('upgrade timed out')))
    req.on('error', reject)
    req.on('response', (res) => {
      res.resume()
      resolve({ upgraded: false, status: res.statusCode })
    })
    req.on('upgrade', (res, socket, head) => {
      req.setTimeout(0)
      const expected = crypto.createHash('sha1').update(key + WS_GUID).digest('base64')
      const queue = []
      const waiters = []
      let buffer = Buffer.alloc(0)
      let isClosed = false
      const closeWaiters = []
      const markClosed = () => {
        isClosed = true
        closeWaiters.splice(0).forEach((done) => done())
        waiters.splice(0).forEach((w) => w.reject(new Error('socket closed')))
      }
      const consume = (chunk) => {
        const decoded = decodeServerFrames(Buffer.concat([buffer, chunk]))
        buffer = decoded.rest
        for (const frame of decoded.frames) {
          if (frame.opcode === 8) {
            socket.end()
            continue
          }
          if (frame.opcode !== 1) continue
          if (frame.text === '2') {
            socket.write(encodeClientFrame('3')) // engine.io heartbeat
            continue
          }
          const waiter = waiters.shift()
          if (waiter) waiter.resolve(frame.text)
          else queue.push(frame.text)
        }
      }
      socket.on('data', consume)
      socket.on('close', markClosed)
      socket.on('error', () => {})
      if (head?.length) consume(head)
      resolve({
        upgraded: res.headers['sec-websocket-accept'] === expected,
        status: 101,
        send: (text) => socket.write(encodeClientFrame(text)),
        next: (ms = 10000) =>
          new Promise((done, fail) => {
            if (queue.length) return done(queue.shift())
            if (isClosed) return fail(new Error('socket closed'))
            const timer = setTimeout(() => fail(new Error('no message arrived')), ms)
            waiters.push({
              resolve: (text) => (clearTimeout(timer), done(text)),
              reject: (err) => (clearTimeout(timer), fail(err)),
            })
          }),
        closed: (ms = 10000) =>
          new Promise((done, fail) => {
            if (isClosed) return done()
            const timer = setTimeout(() => fail(new Error('socket stayed open')), ms)
            closeWaiters.push(() => (clearTimeout(timer), done()))
          }),
        destroy: () => socket.destroy(),
      })
    })
    req.end()
  })
}

function portOpen(host, port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port, timeout: 3000 })
    const finish = (open) => {
      socket.destroy()
      resolve(open)
    }
    socket.on('connect', () => finish(true))
    socket.on('timeout', () => finish(false))
    socket.on('error', () => finish(false))
  })
}

async function main() {
  if (!process.env.CI && !process.argv.includes('--disposable')) {
    console.error('Refusing to run outside CI without --disposable: this builds and starts containers.')
    return 2
  }
  const secrets = buildSecrets()
  const clean = redactor(secrets)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-tls-'))
  const certs = issueCerts(tmp, [HOST, 'localhost'])
  const envFile = path.join(tmp, 'compose.env')
  fs.writeFileSync(
    envFile,
    Object.entries({ ...secrets, ADMIN_EMAIL, TLS_PUBLIC_ORIGIN: ORIGIN, TLS_CERT_DIR: certs.dir })
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
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  const run = (files, args) => {
    const r = spawnSync('docker', ['compose', '-p', PROJECT, '--env-file', envFile, ...files.flatMap((f) => ['-f', f]), ...args], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 256 * 1024 * 1024,
    })
    return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' }
  }
  const OVERLAY = ['docker-compose.yml', 'docker-compose.tls.yml']
  const compose = (...args) => run(OVERLAY, args)
  const mustCompose = (...args) => {
    const r = compose(...args)
    if (r.status !== 0) throw new Error(`docker compose ${args.join(' ')} failed: ${clean(r.stderr).slice(-2000)}`)
    return r
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
  const signIn = async (headers = {}) => {
    const csrf = await api('GET', '/api/auth/csrf')
    const jar = cookiesOf(csrf)
    const login = await api('POST', '/api/auth/login', {
      headers: { 'X-CSRF-Token': csrf.json.data.csrfToken, Cookie: jar.join('; '), ...headers },
      body: { email: ADMIN_EMAIL, password: secrets.ADMIN_INITIAL_PASSWORD },
    })
    return { csrf, login, csrfToken: csrf.json.data.csrfToken, jar: [...jar, ...cookiesOf(login)], token: login.json?.data?.token }
  }
  const proxyReady = () => waitFor(async () => (await api('GET', '/api/auth/csrf')).status === 200, 180000, 2000)
  const mongoRoot = (js) => {
    const r = compose('exec', '-T', '-e', `JS=${js}`, 'mongo', 'sh', '-c', 'mongosh --quiet -u root -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin sentinel-db --eval "$JS"')
    return r.stdout.trim().split('\n').pop() || ''
  }
  // Runs inside a throwaway container with no secrets, attached to one network, as a hostile neighbour would be.
  const PROBE = "const o=JSON.parse(process.env.PROBE);fetch(o.url,{headers:o.headers}).then(r=>console.log('HTTP '+r.status),e=>console.log('ERR '+((e.cause&&e.cause.code)||e.message)))"
  const probeFrom = (network, url, headers = {}) => {
    const r = spawnSync('docker', ['run', '--rm', '--network', `${PROJECT}_${network}`, '-e', `PROBE=${JSON.stringify({ url, headers })}`, `${PROJECT}-backend`, 'node', '-e', PROBE], { encoding: 'utf8' })
    return (r.stdout || '').trim().split('\n').pop() || `no output: ${(r.stderr || '').slice(-200)}`
  }
  const SPOOF = { 'X-Forwarded-Proto': 'https', 'X-Forwarded-For': SPOOFED_IP, Origin: ORIGIN }

  try {
    run(OVERLAY, ['down', '-v', '--remove-orphans'])

    console.log('\n== Configuration')
    const config = JSON.parse(mustCompose('config', '--format', 'json').stdout)
    const configProblems = [...tlsConfigProblems(config), ...publishProblems(config), ...enforcementProblems(config)]
    check('overlay: production mode, loopback HTTPS only, exact proxy trust, hardened non-root nginx', configProblems.length === 0, configProblems.join('; '))
    const dev = JSON.parse(run(['docker-compose.yml'], ['config', '--format', 'json']).stdout)
    const devPorts = (dev.services.backend.ports || []).map((p) => p.target)
    check('development configuration is unchanged', dev.services.backend.environment.NODE_ENV === 'development' && String(devPorts) === '5000' && !dev.services.frontend.user)

    console.log('\n== Startup')
    const t0 = Date.now()
    mustCompose('build')
    // The disposable key is handed to nginx's uid the way the overlay's header tells an operator to.
    const owned = spawnSync('docker', ['run', '--rm', '--user', '0', '--entrypoint', 'sh', '-v', `${certs.dir}:/tls`, `${PROJECT}-frontend`, '-c', 'chown 101:101 /tls/privkey.pem && chmod 400 /tls/privkey.pem'], { encoding: 'utf8' })
    if (owned.status !== 0) throw new Error(`could not set key ownership: ${owned.stderr.slice(-300)}`)
    mustCompose('up', '-d', '--wait', '--wait-timeout', '600', ...SERVICES)
    check('real images built and every service healthy in production mode', true, `${Math.round((Date.now() - t0) / 1000)} s`)
    if (process.argv.includes('--inject-failure')) throw new Error('injected failure (cleanup test)')
    const nodeEnv = compose('exec', '-T', 'backend', 'sh', '-c', 'echo "$NODE_ENV"').stdout.trim()
    check('backend is running in production mode', nodeEnv === 'production', nodeEnv)
    const ready = compose('exec', '-T', 'backend', 'node', '-e', "fetch('http://127.0.0.1:5000/health/ready').then(r=>r.text()).then(console.log)").stdout.trim()
    check('backend readiness: database, AI engine and revocation available', /"status":"ready"/.test(ready), ready)
    const procStatus = compose('exec', '-T', 'frontend', 'sh', '-c', 'grep "^Uid:" /proc/1/status').stdout
    check('nginx master runs as uid 101', /^Uid:\s+101\s/.test(procStatus), procStatus.trim())
    check('nginx filesystem is read-only', compose('exec', '-T', 'frontend', 'sh', '-c', 'touch /etc/nginx/probe').status !== 0)
    check('backend runs as non-root', compose('exec', '-T', 'backend', 'id', '-u').stdout.trim() !== '0')

    console.log('\n== Exposure from the host')
    const live = livePublishProblems(mustCompose('ps', '--format', 'json').stdout)
    check('running containers publish on loopback only', live.length === 0, live.join('; '))
    for (const port of [5000, 8080, 8000, 27017, 8081]) check(`port ${port} is closed on the host`, !(await portOpen('127.0.0.1', port)))
    const externalIps = Object.entries(os.networkInterfaces())
      .filter(([name]) => !/^(docker|br-|veth)/.test(name))
      .flatMap(([, addresses]) => addresses)
      .filter((address) => address.family === 'IPv4' && !address.internal)
      .map((address) => address.address)
    check('the runner has a non-loopback address to test against', externalIps.length > 0, externalIps.length)
    for (const ip of externalIps) check('HTTPS is not reachable on the external interface', !(await portOpen(ip, PORT)))

    console.log('\n== Certificates and TLS versions')
    check('dashboard served over verified HTTPS', (await tlsRequest(target, 'GET', '/')).status === 200)
    await tlsRequest({ ...target, ca: undefined }, 'GET', '/').then(
      () => check('untrusted CA is rejected', false),
      (err) => check('untrusted CA is rejected', /certificate|self.signed|issuer/i.test(err.message), err.message)
    )
    await tlsRequest({ ...target, servername: 'wrong.test' }, 'GET', '/').then(
      () => check('wrong hostname is rejected', false),
      (err) => check('wrong hostname is rejected', /altnames|alt name/i.test(err.message), err.message)
    )
    for (const version of ['TLSv1.2', 'TLSv1.3']) {
      const result = await protocolProbe(target, version)
      check(`${version} accepted`, result.accepted && result.protocol === version, result.protocol || result.error)
    }
    for (const version of ['TLSv1', 'TLSv1.1']) {
      const result = await protocolProbe(target, version)
      check(`${version} refused by the server`, !result.accepted && result.refusedByServer, result.error || result.protocol)
    }

    console.log('\n== Security headers')
    const page = await tlsRequest(target, 'GET', '/')
    const pageHeaders = headerProblems(page.rawHeaders, { hsts: true })
    check('dashboard: CSP, nosniff, referrer policy and HSTS each sent once; no version disclosed', pageHeaders.length === 0, pageHeaders.join('; '))
    const apiResponse = await api('GET', '/api/auth/csrf')
    const apiHeaders = headerProblems(apiResponse.rawHeaders, { hsts: true })
    check('API responses: same headers, not duplicated by the backend', apiHeaders.length === 0, apiHeaders.join('; '))
    const local = await tlsRequest({ ...target, servername: 'localhost' }, 'GET', '/')
    const localHeaders = headerProblems(local.rawHeaders, { hsts: false })
    check('no HSTS for localhost, so the development dashboard keeps working', localHeaders.length === 0, localHeaders.join('; '))

    console.log('\n== Authentication and CSRF')
    const session = await signIn()
    let token = session.token
    const csrfCookie = cookieProblems(session.csrf.headers['set-cookie'], '__Secure-sentinel_csrf')
    check('CSRF cookie is Secure, HttpOnly and SameSite=Strict', csrfCookie.length === 0, csrfCookie.join('; '))
    check('administrator signs in over HTTPS', session.login.status === 200, session.login.status)
    const refreshCookie = cookieProblems(session.login.headers['set-cookie'], '__Secure-sentinel_refresh')
    check('refresh cookie is Secure, HttpOnly and SameSite=Strict', refreshCookie.length === 0, refreshCookie.join('; '))
    const credentials = { email: ADMIN_EMAIL, password: secrets.ADMIN_INITIAL_PASSWORD }
    check('foreign Origin cannot get a CSRF token', (await api('GET', '/api/auth/csrf', { origin: 'https://evil.test' })).status === 403)
    check('sign-in without a CSRF token is refused', (await api('POST', '/api/auth/login', { headers: { Cookie: session.jar.join('; ') }, body: credentials })).status === 403)
    check('sign-in from a foreign Origin is refused', (await api('POST', '/api/auth/login', { origin: 'https://evil.test', headers: { 'X-CSRF-Token': session.csrfToken, Cookie: session.jar.join('; ') }, body: credentials })).status === 403)
    check('sign-in with a tampered CSRF token is refused', (await api('POST', '/api/auth/login', { headers: { 'X-CSRF-Token': 'a'.repeat(64) + '.' + 'b'.repeat(64), Cookie: session.jar.join('; ') }, body: credentials })).status === 403)
    check('refresh without a CSRF token is refused', (await api('POST', '/api/auth/refresh-token', { headers: { Cookie: session.jar.join('; ') } })).status === 403)
    const refreshed = await api('POST', '/api/auth/refresh-token', { headers: { 'X-CSRF-Token': session.csrfToken, Cookie: session.jar.join('; ') } })
    check('refresh with CSRF token and cookie succeeds', refreshed.status === 200 && Boolean(refreshed.json?.data?.token), refreshed.status)
    if (refreshed.json?.data?.token) token = refreshed.json.data.token

    console.log('\n== API requests')
    check('authenticated profile', (await api('GET', '/api/auth/me', { headers: bearer(token) })).status === 200)
    check('unauthenticated request refused', (await api('GET', '/api/auth/me')).status === 401)
    check('threat list', (await api('GET', '/api/threats?limit=1', { headers: bearer(token) })).status === 200)
    const status = await api('GET', '/api/containment/status', { headers: bearer(token) })
    check('real enforcement is off at runtime', status.json?.data?.realEnforcementEnabled === false && status.json?.data?.backend === 'mock', JSON.stringify({ real: status.json?.data?.realEnforcementEnabled, backend: status.json?.data?.backend }))
    const flow = await api('POST', '/api/ai/analyze', { headers: bearer(token), body: { sourceIP: '198.51.100.251', flow_duration: 1000, total_fwd_packets: 3, total_bwd_packets: 1, flow_bytes_per_sec: 100 } })
    check('AI analysis through the proxy with a real score', flow.status === 200 && Number.isFinite(flow.json?.data?.result?.threatScore) && !flow.json.data.result.status, `${flow.status} ${flow.json?.data?.result?.status ?? 'ok'}`)

    console.log('\n== Forwarding headers')
    const spoofed = await signIn({ 'X-Forwarded-For': SPOOFED_IP, 'X-Forwarded-Proto': 'http' })
    check('a client-sent X-Forwarded-Proto cannot downgrade the request', spoofed.login.status === 200, spoofed.login.status)
    const ips = JSON.parse(mongoRoot("print(JSON.stringify(db.auditlogs.find({action:'LOGIN_SUCCESS'}).sort({_id:-1}).limit(5).toArray().map(d=>d.ip)))") || '[]')
    check('audit log records the real peer', ips.length >= 2 && ips.every((ip) => net.isIP(ip)), ips.join(' '))
    const spoofCount = mongoRoot(`print(db.auditlogs.countDocuments({ip:'${SPOOFED_IP}'}))`)
    check('a client-sent X-Forwarded-For never reaches the audit log', spoofCount === '0', spoofCount)

    console.log('\n== Bypassing the proxy from other containers')
    for (const network of ['default', 'proxy']) {
      const direct = probeFrom(network, 'http://backend:5000/api/auth/csrf', SPOOF)
      check(`${network} network: spoofed headers straight to the API get 426`, direct === 'HTTP 426', direct)
      const plain = probeFrom(network, 'http://backend:5000/api/auth/csrf', { Origin: ORIGIN })
      check(`${network} network: plain request straight to the API gets 426`, plain === 'HTTP 426', plain)
      const socketProbe = probeFrom(network, 'http://backend:5000/socket.io/?EIO=4&transport=polling', SPOOF)
      check(`${network} network: spoofed headers cannot open a socket`, socketProbe === 'HTTP 403', socketProbe)
    }
    const ingress = probeFrom('ingress', 'http://backend:5000/health/live')
    check('ingress network cannot reach the backend', /^ERR/.test(ingress), ingress)
    for (const [service, port] of [['mongo', 27017], ['ai-engine', 8000]]) {
      const result = probeFrom('proxy', `http://${service}:${port}/`)
      check(`proxy network cannot reach ${service}`, /^ERR (ENOTFOUND|EAI_AGAIN)/.test(result), result)
    }

    console.log('\n== Socket.IO over TLS')
    const polling = await api('GET', '/socket.io/?EIO=4&transport=polling')
    check('polling handshake through the proxy', polling.status === 200 && polling.text.startsWith('0{'), polling.status)
    check('polling from a foreign Origin is refused', (await api('GET', '/socket.io/?EIO=4&transport=polling', { origin: 'https://evil.test' })).status === 403)
    const foreign = await wsConnect(target, { origin: 'https://evil.test' })
    // engine.io answers a refused upgrade with 400, where a refused polling request gets 403. The next check is the
    // control: the identical request from the allowed Origin upgrades.
    check('wss from a foreign Origin is refused', foreign.upgraded === false && foreign.status === 400, foreign.status)
    const anonymous = await wsConnect(target, { origin: ORIGIN })
    check('wss upgrade through the proxy', anonymous.upgraded === true, anonymous.status)
    await anonymous.next()
    anonymous.send('40{}')
    const anonymousReply = await anonymous.next()
    check('wss without a token is refused', anonymousReply.startsWith('44'), anonymousReply.slice(0, 80))
    anonymous.destroy()
    const live2 = await signIn()
    const socket = await wsConnect(target, { origin: ORIGIN })
    await socket.next()
    socket.send(`40${JSON.stringify({ token: live2.token })}`)
    const accepted = await socket.next()
    check('wss with a valid token connects', accepted.startsWith('40'), accepted.slice(0, 20))
    const logout = await api('POST', '/api/auth/logout', { headers: { 'X-CSRF-Token': live2.csrfToken, Cookie: live2.jar.join('; ') } })
    check('sign-out succeeds', logout.status === 200, logout.status)
    await socket.closed(10000).then(
      () => check('sign-out disconnects the live socket', true),
      (err) => check('sign-out disconnects the live socket', false, err.message)
    )
    socket.destroy()

    console.log('\n== Restart')
    mustCompose('restart', 'backend')
    check('API returns through the proxy after a backend restart', await proxyReady())
    check('session survives the backend restart', (await api('GET', '/api/auth/me', { headers: bearer(token) })).status === 200)
    mustCompose('up', '-d', '--force-recreate', '--no-deps', '--wait', '--wait-timeout', '180', 'backend')
    check('proxy finds a recreated backend container', await proxyReady())
    mustCompose('restart', 'frontend')
    check('HTTPS returns after an nginx restart', await proxyReady())
    check('session works through the restarted proxy', (await api('GET', '/api/auth/me', { headers: bearer(token) })).status === 200)
    mustCompose('down')
    mustCompose('up', '-d', '--wait', '--wait-timeout', '300', ...SERVICES)
    check('stack returns on the same volumes', await proxyReady())
    const again = await signIn()
    check('existing account signs in after recreation', again.login.status === 200, again.login.status)
    const graceful = compose('logs', 'backend').stdout
    check('backend logged no startup configuration error', !/CRITICAL CONFIGURATION ERROR|ConfigurationError/.test(graceful))
  } catch (err) {
    check(`verification stopped: ${err.message}`, false)
  } finally {
    if (failures) {
      for (const s of SERVICES) console.log(`\n--- ${s} log tail ---\n${clean(compose('logs', '--tail', '40', s).stdout)}`)
    }
    run(OVERLAY, ['down', '-v', '--remove-orphans'])
    const list = (...args) => spawnSync('docker', [...args, '--filter', `label=com.docker.compose.project=${PROJECT}`], { encoding: 'utf8' })
    const leftovers = leftoverProblems({
      containers: list('ps', '-aq'),
      networks: list('network', 'ls', '-q'),
      volumes: list('volume', 'ls', '-q'),
    })
    check('disposable containers, networks and volumes removed', leftovers.length === 0, leftovers.join('; '))
    fs.rmSync(tmp, { recursive: true, force: true })
  }
  console.log(`\n${failures ? `${failures} check(s) failed` : 'All TLS checks passed'}`)
  return failures ? 1 : 0
}

if (require.main === module) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error('TLS verification error: ' + err.message)
      process.exit(2)
    }
  )
}
module.exports = {
  WS_GUID,
  tlsConfigProblems,
  cookieProblems,
  headerProblems,
  encodeClientFrame,
  decodeServerFrames,
  issueCerts,
  tlsRequest,
  protocolProbe,
  wsConnect,
  portOpen,
}
