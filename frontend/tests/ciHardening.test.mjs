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
