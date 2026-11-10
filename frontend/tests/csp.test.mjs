import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { CONTENT_SECURITY_POLICY } from '../csp.js'

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')

test('nginx sends exactly the CSP defined in csp.js', () => {
  const m = read('../nginx.conf').match(/add_header Content-Security-Policy "([^"]+)" always;/)
  assert.ok(m, 'nginx.conf has no Content-Security-Policy header')
  assert.equal(m[1], CONTENT_SECURITY_POLICY)
})

test('nginx sends the same CSP over TLS', () => {
  const m = read('../nginx.tls.conf').match(/add_header Content-Security-Policy "([^"]+)" always;/)
  assert.ok(m, 'nginx.tls.conf has no Content-Security-Policy header')
  assert.equal(m[1], CONTENT_SECURITY_POLICY)
})

test('the CSP allows no inline or eval script and no framing', () => {
  const script = CONTENT_SECURITY_POLICY.split('; ').find((d) => d.startsWith('script-src'))
  assert.equal(script, "script-src 'self'")
  assert.match(CONTENT_SECURITY_POLICY, /frame-ancestors 'none'/)
  assert.match(CONTENT_SECURITY_POLICY, /object-src 'none'/)
})

test('index.html has no inline script the CSP would block', () => {
  const scripts = [...read('../index.html').matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
  assert.ok(scripts.length > 0)
  for (const [, attrs, body] of scripts) {
    assert.match(attrs, /src=/)
    assert.equal(body.trim(), '')
  }
})
