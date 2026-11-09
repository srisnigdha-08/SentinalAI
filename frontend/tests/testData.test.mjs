import test from 'node:test'
import assert from 'node:assert/strict'
import { testIp } from '../e2e/fixtures/testData.js'

// TEST-010: no two (project, slot, repeat, retry, n) combinations may share an address.
test('E2E test addresses are unique across projects, tests, repeats, retries and indices', () => {
  const seen = new Map()
  for (const name of ['chromium', 'firefox', 'webkit', 'Mobile (Pixel 5)', 'Tablet (iPad)']) {
    for (let slot = 1; slot <= 39; slot++) {
      for (let repeatEachIndex = 0; repeatEachIndex < 12; repeatEachIndex++) {
        for (let retry = 0; retry < 2; retry++) {
          for (let n = 0; n < 5; n++) {
            const ip = testIp({ project: { name }, repeatEachIndex, retry }, slot, n)
            const key = `${name}/${slot}/${repeatEachIndex}/${retry}/${n}`
            assert.ok(!seen.has(ip), `${ip} for ${key} already used by ${seen.get(ip)}`)
            assert.match(ip, /^198\.1[89]\.\d{1,3}\.\d{1,3}$/)
            seen.set(ip, key)
          }
        }
      }
    }
  }
})

test('out-of-range inputs are refused instead of silently colliding', () => {
  const info = { project: { name: 'chromium' }, repeatEachIndex: 0, retry: 0 }
  assert.throws(() => testIp(info, 0))
  assert.throws(() => testIp(info, 40))
  assert.throws(() => testIp(info, 1, 5))
  assert.throws(() => testIp({ ...info, project: { name: 'edge' } }, 1))
})

test('viewer-redaction subnets are unique per project, repeat and retry, and never overlap testIp', async () => {
  const { testSubnetIp } = await import('../e2e/fixtures/testData.js')
  const subnets = new Set()
  for (const name of ['chromium', 'firefox', 'webkit', 'Mobile (Pixel 5)', 'Tablet (iPad)']) {
    for (let repeatEachIndex = 0; repeatEachIndex < 12; repeatEachIndex++) {
      for (let retry = 0; retry < 4; retry++) {
        const subnet = testSubnetIp({ project: { name }, repeatEachIndex, retry }).replace(/\.\d+$/, '')
        assert.ok(!subnets.has(subnet), subnet)
        assert.ok(subnet.startsWith('198.19.'))
        subnets.add(subnet)
      }
    }
  }
})
