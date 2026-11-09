import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'

// Guards the CI configuration itself: a workflow that drifts from these rules still "passes", so nothing else notices.
const dir = new URL('../../.github/workflows/', import.meta.url)
const workflows = readdirSync(dir)
  .filter((f) => f.endsWith('.yml'))
  .map((name) => ({ name, text: readFileSync(new URL(name, dir), 'utf8') }))

test('every workflow that installs Node uses the supported LTS line', () => {
  for (const { name, text } of workflows) {
    for (const match of text.matchAll(/node-version:\s*'?(\d+)/g)) {
      assert.equal(match[1], '24', `${name} uses Node ${match[1]}; E2E ran on an end-of-life Node 20 before this`)
    }
  }
})

test('the backend declares the Node line it is tested on', () => {
  const pkg = JSON.parse(readFileSync(new URL('../../backend/package.json', import.meta.url), 'utf8'))
  assert.equal(pkg.engines?.node, '>=24')
})

test('every action is pinned to a full commit SHA', () => {
  for (const { name, text } of workflows) {
    for (const match of text.matchAll(/uses:\s*(\S+)/g)) {
      assert.match(match[1], /@[0-9a-f]{40}$/, `${name}: ${match[1]} is not pinned to a commit`)
    }
  }
})

test('every workflow defaults to a read-only token', () => {
  for (const { name, text } of workflows) {
    assert.match(text, /^permissions:\r?\n {2}contents: read\r?$/m, `${name} has no read-only top-level permissions`)
    assert.doesNotMatch(text, /write-all|pull_request_target/, name)
  }
})

test('CI fails on high-severity advisories in production dependencies', () => {
  const ci = workflows.find((w) => w.name === 'ci.yml').text
  const gates = ci.match(/npm audit --omit=dev --audit-level=high/g) || []
  assert.equal(gates.length, 2, 'expected one gate for backend and one for frontend')
})

test('code scanning runs, and only its job can write security results', () => {
  const codeql = workflows.find((w) => w.name === 'codeql.yml')?.text
  assert.ok(codeql, 'codeql.yml is missing')
  assert.match(codeql, /security-events: write/)
  assert.match(codeql, /languages: javascript-typescript/)
})

test('Dependabot watches npm and actions, and leaves the ML dependencies and Jest upgrades alone', () => {
  const config = readFileSync(new URL('../../.github/dependabot.yml', import.meta.url), 'utf8')
  for (const ecosystem of ['npm', 'github-actions']) assert.match(config, new RegExp(`package-ecosystem: ${ecosystem}`))
  assert.doesNotMatch(config, /package-ecosystem: pip/, 'model artifacts depend on the pinned ML libraries')
  assert.match(config, /dependency-name: jest/)
})

test('every base and service image is pinned to a digest', () => {
  for (const file of ['backend/Dockerfile', 'frontend/Dockerfile', 'ai-engine/Dockerfile']) {
    const text = readFileSync(new URL(`../../${file}`, import.meta.url), 'utf8')
    for (const match of text.matchAll(/^FROM\s+(\S+)/gm)) {
      assert.match(match[1], /@sha256:[0-9a-f]{64}$/, `${file}: ${match[1]} is not pinned`)
    }
  }
  const compose = readFileSync(new URL('../../docker-compose.yml', import.meta.url), 'utf8')
  for (const match of compose.matchAll(/^\s+image:\s+(\S+)/gm)) {
    assert.match(match[1], /@sha256:[0-9a-f]{64}$/, `compose: ${match[1]} is not pinned`)
  }
})

test('the image scanner is pinned by digest and does not get the Docker socket', () => {
  const scan = readFileSync(new URL('../../scripts/deploy/scan_images.sh', import.meta.url), 'utf8')
  assert.match(scan, /aquasec\/trivy@sha256:[0-9a-f]{64}/)
  assert.doesNotMatch(scan, /docker\.sock/)
  assert.doesNotMatch(workflows.find((w) => w.name === 'deployment.yml').text, /trivy-action|setup-trivy/)
})
