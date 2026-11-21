import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  REAL_FIREWALL_BACKENDS,
  adapterDisplayName,
  containmentOutcome,
  enforcementEngineLabel,
  isRealFirewallBackend,
  isRealFirewallStatus,
  manualBlockOutcome,
} from '../src/utils/containmentLabels.js'

const actionResponse = (action) => ({ data: { data: { action } } })
const blockResponse = (enforcement) => ({ data: { data: { enforcement } } })

test('only windows-firewall and linux-iptables are real backends; everything else is simulated', () => {
  assert.deepEqual(Object.keys(REAL_FIREWALL_BACKENDS).sort(), ['linux-iptables', 'windows-firewall'])
  for (const b of ['mock', 'simulated', undefined, null, '', 'Windows-Firewall', 'nft', '__proto__', 'toString'])
    assert.equal(isRealFirewallBackend(b), false, String(b))
})

test('status is real only when the backend says a real adapter is in use', () => {
  assert.equal(isRealFirewallStatus({ backend: 'mock', realEnforcementEnabled: true }), false)
  assert.equal(isRealFirewallStatus({ backend: 'windows-firewall', realEnforcementEnabled: false }), false)
  assert.equal(isRealFirewallStatus(null), false)
  assert.equal(isRealFirewallStatus({ backend: 'linux-iptables', realEnforcementEnabled: true }), true)
  assert.match(adapterDisplayName({ backend: 'mock', realEnforcementEnabled: false }), /MockContainmentAdapter \(In-Memory Simulation\)/)
  assert.match(
    adapterDisplayName({ backend: 'linux-iptables', realEnforcementEnabled: true, adapterName: 'LinuxIptablesAdapter' }),
    /LinuxIptablesAdapter \(Linux iptables, host OS\)/
  )
})

test('an active mock containment is described as simulated, a real one by its firewall', () => {
  assert.match(containmentOutcome('203.0.113.5', actionResponse({ enforcementStatus: 'ACTIVE', enforcementBackend: 'mock' })), /Simulated containment recorded .* no firewall rule applied/)
  assert.match(
    containmentOutcome('203.0.113.5', actionResponse({ enforcementStatus: 'ACTIVE', enforcementBackend: 'linux-iptables' })),
    /Linux iptables rule applied and verified/
  )
  assert.match(manualBlockOutcome('203.0.113.5', blockResponse({ status: 'ACTIVE', backend: 'linux-iptables' })), /blocked by a Linux iptables rule/)
  assert.match(manualBlockOutcome('203.0.113.5', blockResponse({ status: 'ACTIVE', backend: 'mock' })), /simulated firewall rule/)
  assert.doesNotMatch(manualBlockOutcome('203.0.113.5', blockResponse({ status: 'FAILED', backend: 'windows-firewall' })), /blocked by/)
})

test('failures, verification failures and cleanup outcomes are visible, not just the status', () => {
  const failed = containmentOutcome(
    '203.0.113.6',
    actionResponse({
      enforcementStatus: 'FAILED',
      enforcementBackend: 'windows-firewall',
      failureReason: 'ENFORCEMENT_NOT_VERIFIED: the rule was not found | CLEANUP_UNCONFIRMED: a rule may remain; flagged for reconciliation',
    })
  )
  assert.match(failed, /FAILED/)
  assert.match(failed, /ENFORCEMENT_NOT_VERIFIED/)
  assert.match(failed, /CLEANUP_UNCONFIRMED/)
  assert.doesNotMatch(failed, /rule applied/)
  assert.match(containmentOutcome('203.0.113.7', actionResponse({ enforcementStatus: 'ROLLBACK_FAILED' })), /ROLLBACK_FAILED/)
  assert.equal(
    containmentOutcome('203.0.113.8', actionResponse({ enforcementStatus: 'FAILED', failureReason: 'x'.repeat(1000) })).length < 320,
    true
  )
})

test('the Settings panel decides real vs simulated through the shared helper, for both real backends', () => {
  const settings = readFileSync(new URL('../src/pages/Settings.jsx', import.meta.url), 'utf8')
  assert.match(settings, /isRealFirewallStatus\(containmentStatus\)/)
  assert.match(settings, /adapterDisplayName\(containmentStatus\)/)
  assert.doesNotMatch(settings, /'windows-firewall'/) // no backend-specific check left that could miss linux-iptables
  assert.match(settings, /SIMULATION \/ MOCK ADAPTER/)
})

test('the confirmation dialog names each real firewall correctly and everything else as the mock', () => {
  assert.deepEqual(enforcementEngineLabel({ backend: 'linux-iptables', realEnforcementEnabled: true }), {
    simulated: false, engine: 'LINUX IPTABLES (HOST)', mode: 'Live Host Rules',
  })
  assert.equal(enforcementEngineLabel({ backend: 'windows-firewall', realEnforcementEnabled: true }).engine,
    'WINDOWS FIREWALL (HOST)')
  for (const status of [
    null, undefined, {}, { backend: 'mock' }, { backend: 'mock', realEnforcementEnabled: true },
    { backend: 'windows-firewall', realEnforcementEnabled: false }, { backend: 'linux-iptables' },
    { backend: 'simulated', realEnforcementEnabled: true }, { backend: 'nft', realEnforcementEnabled: true },
  ]) {
    const label = enforcementEngineLabel(status)
    assert.equal(label.simulated, true, JSON.stringify(status))
    assert.equal(label.engine, 'SIMULATION / MOCK ADAPTER', JSON.stringify(status))
    assert.equal(label.mode, 'Safe Dev Mode')
  }
})

test('the confirmation dialog takes its label from the shared helper, with no hard-coded firewall name', () => {
  const modal = readFileSync(new URL('../src/components/ContainmentConfirmModal.jsx', import.meta.url), 'utf8')
  assert.match(modal, /enforcementEngineLabel\(backendInfo\)/)
  assert.doesNotMatch(modal, /WINDOWS FIREWALL|IPTABLES/i)
})
