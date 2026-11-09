import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

// CI-002: the first GitHub run of e2e.yml (draft PR #1) failed 14 of 82 Chromium tests. Locally the test backend reads
// the git-ignored backend/.env.test (RATE_LIMIT_MAX=100000); CI has no such file, so the backend used the production
// default of 1000 API requests per 15 min per IP. The serial suite, all from one IP, exhausted it part-way through and
// every sign-in failed until the window reset. Reproduced locally with the CI environment (14 failed); the same run
// with only RATE_LIMIT_MAX raised: 82/82.
const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')
const workflow = read('../../.github/workflows/e2e.yml')
const server = read('../../backend/server.js')
const envValue = (name) => workflow.match(new RegExp(`^\\s+${name}:\\s*'?([^'\\s#]+)`, 'm'))?.[1]

test('the E2E workflow gives the test backend a rate-limit budget for the whole suite', () => {
  const max = Number(envValue('RATE_LIMIT_MAX'))
  assert.ok(Number.isFinite(max) && max >= 10000, `e2e.yml must set RATE_LIMIT_MAX >= 10000 (found ${envValue('RATE_LIMIT_MAX')})`)
})

test('the production default is unchanged (the larger budget is CI configuration only)', () => {
  assert.match(server, /max: parseInt\(process\.env\.RATE_LIMIT_MAX\) \|\| 1000,/)
})

test('the workflow still sets every secret the backend refuses to start without', () => {
  for (const name of ['JWT_SECRET', 'JWT_REFRESH_SECRET', 'HONEYPOT_API_KEY', 'SENTINEL_KEY']) {
    assert.ok(envValue(name), `${name} missing from e2e.yml env`)
  }
})
