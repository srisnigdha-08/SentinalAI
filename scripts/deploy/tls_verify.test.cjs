'use strict'
// Checks the TLS overlay's safety rules and the verifier's HTTPS client without Docker.
// Run: node --test scripts/deploy/tls_verify.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const crypto = require('crypto')
const fs = require('fs')
const https = require('https')
const os = require('os')
const path = require('path')
const tls = require('tls')
const { spawnSync } = require('child_process')
const v = require('./tls_verify.cjs')

const ROOT = path.join(__dirname, '..', '..')
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8')

const goodConfig = () => ({
  networks: {
    proxy: { internal: true, ipam: { config: [{ subnet: '172.30.250.0/29', ip_range: '172.30.250.4/30' }] } },
    ingress: {},
  },
  services: {
    backend: {
      environment: {
        NODE_ENV: 'production',
        CLIENT_URL: 'https://sentinel.test:8443',
        TRUST_PROXY: '172.30.250.2/32',
        AUTH_REVOCATION_MODE: 'single',
      },
      networks: { default: null, proxy: null },
    },
    frontend: {
      user: '101:101',
      read_only: true,
      cap_drop: ['ALL'],
      security_opt: ['no-new-privileges:true'],
      ports: [{ host_ip: '127.0.0.1', target: 8443, published: '8443' }],
      networks: { ingress: null, proxy: { ipv4_address: '172.30.250.2' } },
    },
  },
})

test('the intended overlay configuration has no problems', () => {
  assert.deepEqual(v.tlsConfigProblems(goodConfig()), [])
})

for (const [name, mutate] of [
  ['backend publishes a port', (c) => (c.services.backend.ports = [{ host_ip: '127.0.0.1', target: 5000 }])],
  ['HTTPS not on loopback', (c) => (c.services.frontend.ports[0].host_ip = '0.0.0.0')],
  ['a second published port', (c) => c.services.frontend.ports.push({ host_ip: '127.0.0.1', target: 8080 })],
  ['development mode', (c) => (c.services.backend.environment.NODE_ENV = 'development')],
  ['a plain HTTP origin', (c) => (c.services.backend.environment.CLIENT_URL = 'http://sentinel.test')],
  ['trust that is not the proxy', (c) => (c.services.backend.environment.TRUST_PROXY = '172.30.250.0/29')],
  ['hop-count trust', (c) => (c.services.backend.environment.TRUST_PROXY = '1')],
  ['no revocation mode', (c) => delete c.services.backend.environment.AUTH_REVOCATION_MODE],
  ['proxy network with a route out', (c) => (c.networks.proxy.internal = false)],
  ['proxy joined to the database network', (c) => (c.services.frontend.networks.default = null)],
  ['nginx as root', (c) => delete c.services.frontend.user],
  ['uid 0', (c) => (c.services.frontend.user = '0:0')],
  ['writable filesystem', (c) => (c.services.frontend.read_only = false)],
  ['capabilities kept', (c) => (c.services.frontend.cap_drop = [])],
  ['privilege gain allowed', (c) => (c.services.frontend.security_opt = [])],
  // Run 42609479868: with no range, the backend was handed the proxy's address and nginx could not start.
  ['no dynamic range, so another container can take the trusted address', (c) => delete c.networks.proxy.ipam.config[0].ip_range],
  ['proxy address inside the dynamic range', (c) => {
    c.services.frontend.networks.proxy.ipv4_address = '172.30.250.5'
    c.services.backend.environment.TRUST_PROXY = '172.30.250.5/32'
  }],
  ['proxy address outside the subnet', (c) => {
    c.services.frontend.networks.proxy.ipv4_address = '172.30.250.20'
    c.services.backend.environment.TRUST_PROXY = '172.30.250.20/32'
  }],
]) {
  test(`configuration check catches: ${name}`, () => {
    const config = goodConfig()
    mutate(config)
    assert.ok(v.tlsConfigProblems(config).length >= 1)
  })
}

test('cookie check requires every protective attribute', () => {
  const good = '__Secure-x=1; Max-Age=9; Path=/api/auth; HttpOnly; Secure; SameSite=Strict'
  assert.deepEqual(v.cookieProblems([good], '__Secure-x'), [])
  assert.equal(v.cookieProblems([], '__Secure-x').length, 1)
  assert.ok(v.cookieProblems(['__Secure-x=1; HttpOnly; SameSite=Strict'], '__Secure-x').length >= 1)
  assert.ok(v.cookieProblems(['__Secure-x=1; Secure; SameSite=Strict'], '__Secure-x').length >= 1)
  assert.ok(v.cookieProblems(['__Secure-x=1; Secure; HttpOnly; SameSite=Lax'], '__Secure-x').length >= 1)
})

test('security header check needs each header exactly once', () => {
  const raw = (...pairs) => pairs.flat()
  const base = [
    ['Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'"],
    ['X-Content-Type-Options', 'nosniff'],
    ['Referrer-Policy', 'same-origin'],
  ]
  const hsts = ['Strict-Transport-Security', 'max-age=31536000']
  assert.deepEqual(v.headerProblems(raw(...base, hsts), { hsts: true }), [])
  assert.deepEqual(v.headerProblems(raw(...base), { hsts: false }), [])
  assert.equal(v.headerProblems(raw(...base), { hsts: true }).length, 1)
  assert.equal(v.headerProblems(raw(...base, hsts), { hsts: false }).length, 1)
  assert.equal(v.headerProblems(raw(...base, hsts, hsts), { hsts: true }).length, 1)
  assert.equal(v.headerProblems(raw(base[1], base[2], hsts), { hsts: true }).length, 1)
  assert.equal(v.headerProblems(raw(...base, hsts, ['Server', 'nginx/1.30.6']), { hsts: true }).length, 1)
})

test('WebSocket frames round-trip, including split delivery and long payloads', () => {
  for (const text of ['0{"sid":"a"}', 'x'.repeat(70000)]) {
    const client = v.encodeClientFrame(text)
    assert.equal(client[1] & 0x80, 0x80, 'client frames must be masked')
    const header = text.length < 126 ? 2 : text.length < 65536 ? 4 : 10
    const mask = client.subarray(header, header + 4)
    const unmasked = Buffer.from(client.subarray(header + 4).map((byte, i) => byte ^ mask[i % 4]))
    assert.equal(unmasked.toString(), text)
  }
  const server = Buffer.concat([Buffer.from([0x81, 2]), Buffer.from('40'), Buffer.from([0x81, 1]), Buffer.from('2')])
  const first = v.decodeServerFrames(server.subarray(0, 3))
  assert.deepEqual(first.frames, [])
  const all = v.decodeServerFrames(server)
  assert.deepEqual(
    all.frames.map((f) => f.text),
    ['40', '2']
  )
  assert.equal(all.rest.length, 0)
  const long = Buffer.concat([Buffer.from([0x81, 126, 0x01, 0x00]), Buffer.alloc(256, 0x61)])
  assert.equal(v.decodeServerFrames(long).frames[0].text.length, 256)
})

test('nginx TLS configuration keeps the protections the backend depends on', () => {
  const conf = read('frontend/nginx.tls.conf')
  assert.match(conf, /ssl_protocols TLSv1\.2 TLSv1\.3;/)
  assert.doesNotMatch(conf, /TLSv1(\.1)?[ ;]/, 'old protocol versions must stay off')
  assert.match(conf, /listen 8443 ssl;/)
  assert.doesNotMatch(conf, /listen\s+(8080|80)\b/)
  const listens = [...conf.matchAll(/^\s*listen\s+([^;]+);/gm)].map((m) => m[1])
  assert.deepEqual(listens.sort(), ['127.0.0.1:8081', '8443 ssl'])
  assert.match(conf, /proxy_set_header X-Forwarded-Proto https;/, 'must be literal, never copied from the client')
  assert.match(conf, /proxy_set_header X-Forwarded-For \$remote_addr;/, 'must overwrite anything the client sent')
  assert.doesNotMatch(conf, /proxy_add_x_forwarded_for/)
  assert.match(conf, /proxy_set_header Upgrade \$http_upgrade;/)
  for (const header of ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy']) {
    assert.match(conf, new RegExp(`proxy_hide_header ${header};`), `${header} would be sent twice`)
  }
  assert.match(conf, /server_tokens off;/)
  assert.doesNotMatch(conf, /location[^{]*\{[^}]*proxy_set_header/, 'a per-location proxy_set_header silently drops the server-level headers')
  assert.match(conf, /localhost\s+"";/, 'HSTS on localhost would break the plain-HTTP development dashboard')
})

test('the overlay preserves the development stack and keeps secrets out of Git', () => {
  const overlay = read('docker-compose.tls.yml')
  assert.match(overlay, /ports: !reset \[\]/, 'without !reset Compose merges in the published backend port')
  assert.match(overlay, /ports: !override/)
  assert.match(overlay, /TLS_CERT_DIR:\?/)
  assert.match(overlay, /TLS_PUBLIC_ORIGIN:\?/)
  assert.doesNotMatch(overlay, /ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT|windows-firewall/)
  const base = read('docker-compose.yml')
  assert.match(base, /NODE_ENV: development/)
  assert.match(base, /BACKEND_BIND_ADDRESS:-127\.0\.0\.1}:5000:5000/)
  assert.match(base, /DASHBOARD_BIND_ADDRESS:-127\.0\.0\.1}:8080:8080/)
  assert.match(read('.gitignore'), /^deployment\/tls\/$/m)
  const tracked = spawnSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).stdout.split('\n')
  assert.deepEqual(tracked.filter((f) => /^deployment\/tls\/|^deployment\/.*\.(pem|key|crt)$/.test(f)), [])
})

test('the workflow proves TLS cleanup after failure and scans the images', () => {
  const workflow = read('.github/workflows/deployment.yml')
  const job = workflow.slice(workflow.indexOf('\n  tls:'))
  assert.ok(workflow.includes('\n  tls:'), 'deployment.yml has no tls job')
  assert.match(job, /tls_verify\.cjs --inject-failure/)
  assert.match(job, /scan_images\.sh/)
  assert.match(job, /if: always\(\)[\s\S]*down -v --remove-orphans/)
})

test('refuses to start containers outside CI without --disposable', () => {
  const env = { ...process.env }
  delete env.CI
  const r = spawnSync(process.execPath, [path.join(__dirname, 'tls_verify.cjs')], { encoding: 'utf8', env })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Refusing to run outside CI/)
})

// A real TLS server, so the verifier's own client is proven to reject what it claims to reject.
test('the HTTPS client verifies certificates and tells a server refusal from a client error', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-tls-test-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const certs = v.issueCerts(dir, ['sentinel.test', 'localhost'])
  assert.ok(!fs.existsSync(path.join(dir, 'ca', 'ca.key')), 'the CA key must not outlive issuing')
  const server = https.createServer(
    { key: fs.readFileSync(certs.key), cert: fs.readFileSync(certs.cert), minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3' },
    (req, res) => {
      res.setHeader('X-Seen-Host', req.headers.host)
      res.end('{"ok":true}')
    }
  )
  server.on('upgrade', (req, socket) => {
    const accept = crypto.createHash('sha1').update(req.headers['sec-websocket-key'] + v.WS_GUID).digest('base64')
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`)
    socket.write(Buffer.concat([Buffer.from([0x81, 12]), Buffer.from('0{"sid":"a"}')]))
    socket.once('data', () => {
      socket.write(Buffer.concat([Buffer.from([0x81, 2]), Buffer.from('40')]))
      socket.end()
    })
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  t.after(() => server.close())
  const target = { host: '127.0.0.1', port: server.address().port, servername: 'sentinel.test', ca: fs.readFileSync(certs.ca) }

  const ok = await v.tlsRequest(target, 'GET', '/')
  assert.equal(ok.status, 200)
  assert.equal(ok.json.ok, true)
  assert.equal(ok.headers['x-seen-host'], `sentinel.test:${target.port}`)

  await assert.rejects(v.tlsRequest({ ...target, ca: undefined }, 'GET', '/'), /certificate|self.signed|issuer/i)
  await assert.rejects(v.tlsRequest({ ...target, servername: 'other.test' }, 'GET', '/'), /altnames|alt name/i)

  assert.equal((await v.protocolProbe(target, 'TLSv1.2')).accepted, true)
  assert.equal((await v.protocolProbe(target, 'TLSv1.3')).accepted, true)
  const old = await v.protocolProbe(target, 'TLSv1.1')
  assert.equal(old.accepted, false)
  assert.equal(old.refusedByServer, true, `expected a server refusal, got: ${old.error}`)

  const ws = await v.wsConnect(target, { origin: 'https://sentinel.test:8443' })
  assert.equal(ws.upgraded, true)
  assert.equal(ws.closedAt(), null, 'an open socket has no close time')
  const opened = Date.now()
  assert.match(await ws.next(), /^0\{/)
  ws.send('40{"token":"t"}')
  assert.equal(await ws.next(), '40')
  await ws.closed(3000)
  assert.ok(ws.closedAt() >= opened, 'the close time is when the socket really closed, not when it was checked')

  assert.equal(await v.portOpen('127.0.0.1', target.port), true)
  const unused = await new Promise((resolve) => {
    const probe = tls.createServer().listen(0, '127.0.0.1', () => {
      const { port } = probe.address()
      probe.close(() => resolve(port))
    })
  })
  assert.equal(await v.portOpen('127.0.0.1', unused), false)
})
