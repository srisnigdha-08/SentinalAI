'use strict'
// Checks the safety logic of compose_verify.cjs without Docker. Run: node --test scripts/deploy/compose_verify.test.cjs
const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const path = require('path')
const { spawnSync } = require('child_process')
const v = require('./compose_verify.cjs')

test('generated secrets are unique and strong', () => {
  const a = v.buildSecrets()
  const b = v.buildSecrets()
  assert.ok(Object.values(a).every((s) => s.length >= 64))
  assert.equal(new Set([...Object.values(a), ...Object.values(b)]).size, Object.values(a).length * 2)
})

test('secret values are removed from output', () => {
  const clean = v.redactor({ A: 'value-one', B: 'value-two' })
  assert.equal(clean('x value-one y value-two value-one'), 'x [REDACTED] y [REDACTED] [REDACTED]')
})

test('configured ports: loopback passes, other bindings and a published MongoDB fail', () => {
  const ok = { services: { backend: { ports: [{ host_ip: '127.0.0.1', published: '5000' }] }, mongo: {} } }
  assert.deepEqual(v.publishProblems(ok), [])
  assert.equal(v.publishProblems({ services: { backend: { ports: [{ host_ip: '0.0.0.0', published: '5000' }] } } }).length, 1)
  assert.equal(v.publishProblems({ services: { backend: { ports: [{ published: '5000' }] } } }).length, 1)
  assert.ok(v.publishProblems({ services: { mongo: { ports: [{ host_ip: '127.0.0.1', published: '27017' }] } } }).length >= 1)
})

test('running containers: anything off loopback is reported', () => {
  const line = (url) => JSON.stringify({ Service: 'backend', Publishers: [{ URL: url, PublishedPort: 5000 }] })
  assert.deepEqual(v.livePublishProblems(line('127.0.0.1')), [])
  assert.equal(v.livePublishProblems(line('0.0.0.0')).length, 1)
  assert.deepEqual(v.livePublishProblems(JSON.stringify({ Service: 'mongo', Publishers: [{ URL: '', PublishedPort: 0 }] })), [])
})

test('enabling real firewall enforcement is reported', () => {
  assert.deepEqual(v.enforcementProblems({ services: { backend: { environment: {} } } }), [])
  assert.equal(v.enforcementProblems({ services: { backend: { environment: { ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'true' } } } }).length, 1)
  assert.equal(v.enforcementProblems({ services: { backend: { environment: { CONTAINMENT_BACKEND: 'windows-firewall' } } } }).length, 1)
})

test('the repository Compose file itself passes the configured checks', () => {
  const text = fs.readFileSync(path.join(__dirname, '..', '..', 'docker-compose.yml'), 'utf8')
  assert.doesNotMatch(text, /ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT|windows-firewall/)
  assert.doesNotMatch(text, /^\s+- "?(\d+:\d+|0\.0\.0\.0:)/m, 'a port is published without a loopback default')
})

test('cleanup reports anything left behind, and a listing that failed is not "nothing left"', () => {
  const empty = { status: 0, stdout: '' }
  assert.deepEqual(v.leftoverProblems({ containers: empty, networks: empty, volumes: { status: 0, stdout: '\n' } }), [])
  assert.equal(v.leftoverProblems({ containers: { status: 0, stdout: 'abc123\n' }, volumes: empty }).length, 1)
  assert.equal(v.leftoverProblems({ networks: { status: 0, stdout: 'net1\n' } }).length, 1)
  assert.equal(v.leftoverProblems({ volumes: { status: 1, stdout: '' } }).length, 1)
  assert.equal(v.leftoverProblems({ containers: { status: null, stdout: null } }).length, 1)
})

test('the workflow proves cleanup after a failed run and always removes leftovers', () => {
  const workflow = fs.readFileSync(path.join(__dirname, '..', '..', '.github', 'workflows', 'deployment.yml'), 'utf8')
  assert.match(workflow, /compose_verify\.cjs --inject-failure/)
  assert.match(workflow, /if: always\(\)[\s\S]*down -v --remove-orphans/)
  assert.ok(workflow.indexOf('--inject-failure') < workflow.indexOf('scan_images.sh'))
})

test('the scan script removes its cache volume on every exit path', () => {
  const scan = fs.readFileSync(path.join(__dirname, 'scan_images.sh'), 'utf8')
  assert.match(scan, /trap '[^']*docker volume rm sentinel-trivy-cache[^']*' EXIT/)
})

test('refuses to start containers outside CI without --disposable', () => {
  const env = { ...process.env }
  delete env.CI
  const r = spawnSync(process.execPath, [path.join(__dirname, 'compose_verify.cjs')], { encoding: 'utf8', env })
  assert.equal(r.status, 2)
  assert.match(r.stderr, /Refusing to run outside CI/)
})
