import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { personaLabel, isSimulatedWindows, EXPERIMENTAL_PERSONAS } from '../src/utils/personaLabels.js'

// Rank 7: the dashboard never presents windows_srv as a real Windows host.
test('windows_srv is always labelled as a simulated, experimental shell', () => {
  assert.equal(personaLabel('windows_srv'), 'windows_srv (simulated Windows shell, experimental)')
  assert.equal(isSimulatedWindows('windows_srv'), true)
  assert.deepEqual(Object.keys(EXPERIMENTAL_PERSONAS), ['windows_srv'])
})

test('Linux personas and missing values are shown as before', () => {
  for (const p of ['ubuntu_22', 'debian_11', 'centos_7', 'aws_ec2', 'raspberry_pi']) assert.equal(personaLabel(p), p)
  assert.equal(personaLabel(null), 'Not recorded')
  assert.equal(personaLabel(undefined), 'Not recorded')
  assert.equal(personaLabel('', '—'), '—')
})

test('every view that names the served persona uses the label', () => {
  for (const f of ['../src/components/attackTimeline/SessionSelector.jsx', '../src/components/attackTimeline/SessionReplay.jsx',
    '../src/pages/HoneypotAnalytics.jsx']) {
    const src = readFileSync(new URL(f, import.meta.url), 'utf8')
    assert.match(src, /personaLabel\(/, f)
  }
})
