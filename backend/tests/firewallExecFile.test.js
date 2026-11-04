'use strict'
/**
 * WindowsFirewallAdapter runs netsh through execFile (argument array, no shell) and validates
 * targets as real IPs/CIDRs. A recording runner stands in for netsh, so no OS command executes.
 */
const WindowsFirewallAdapter = require('../services/containment/WindowsFirewallAdapter')

const makeAdapter = (stdout = 'Ok.') => {
  const calls = []
  const adapter = new WindowsFirewallAdapter({
    enabled: true,
    runNetsh: async (args, timeout) => {
      calls.push({ args, timeout })
      return { stdout, stderr: '' }
    },
  })
  // NODE_ENV=test keeps the real gate closed; bypass it only for this recording runner.
  adapter._assertEnabled = () => {}
  return { adapter, calls }
}

describe('WindowsFirewallAdapter execFile hardening', () => {
  test('applyRule passes netsh arguments as an array, one value per element', async () => {
    const { adapter, calls } = makeAdapter()
    const res = await adapter.applyRule({ containmentId: 'abc-123', target: '203.0.113.7' })

    expect(res.success).toBe(true)
    expect(calls).toHaveLength(1)
    expect(calls[0].args).toEqual([
      'advfirewall',
      'firewall',
      'add',
      'rule',
      'name=SentinelAI-Rule-abc-123',
      'dir=in',
      'action=block',
      'remoteip=203.0.113.7',
      'description=SentinelAI Automated Containment abc-123',
    ])
    expect(calls[0].timeout).toBe(10000)
  })

  test('removeRule targets only the SentinelAI rule namespace', async () => {
    const { adapter, calls } = makeAdapter()
    await adapter.removeRule({ ruleName: 'SentinelAI-Rule-abc-123' })
    expect(calls[0].args).toEqual(['advfirewall', 'firewall', 'delete', 'rule', 'name=SentinelAI-Rule-abc-123'])
    await expect(adapter.removeRule({ ruleName: 'Core-Networking-DNS' })).rejects.toThrow(/unauthorized rule name/)
  })

  test('_sanitizeTarget rejects strings made of allowed characters that are not addresses', () => {
    const adapter = new WindowsFirewallAdapter({ enabled: false })
    expect(adapter._sanitizeTarget('203.0.113.0/24')).toBe('203.0.113.0/24')
    expect(adapter._sanitizeTarget('2001:db8::/64')).toBe('2001:db8::/64')
    for (const bad of [':::', '1.2.3.4/99', '999.1.1.1', '1.2.3.4/24/8', 'abc', '2001:db8::/129', '/24']) {
      expect(() => adapter._sanitizeTarget(bad)).toThrow(/Invalid target address/)
    }
  })

  test('verifyRule reads the Enabled field instead of any "Yes" in the output', async () => {
    const disabled = makeAdapter('Rule Name: SentinelAI-Rule-x\nEnabled: No\nEdge traversal: Yes\n').adapter
    await expect(disabled.verifyRule({ ruleName: 'SentinelAI-Rule-x' })).resolves.toMatchObject({
      exists: true,
      active: false,
    })
    const enabled = makeAdapter('Rule Name: SentinelAI-Rule-x\nEnabled: Yes\n').adapter
    await expect(enabled.verifyRule({ ruleName: 'SentinelAI-Rule-x' })).resolves.toMatchObject({ active: true })
  })

  test('the default runner is execFile-based (no shell exec in the adapter source)', () => {
    const source = require('fs').readFileSync(require.resolve('../services/containment/WindowsFirewallAdapter'), 'utf8')
    expect(source).toMatch(/execFile/)
    expect(source).not.toMatch(/\bexec\(|promisify\(exec\)/)
  })
})

// CONT-003: recovery may release a target lock only on a positive "absent" answer. A recording runner stands in for
// netsh; nothing executes.
describe('WindowsFirewallAdapter.inspectRule (read-only, tri-state)', () => {
  const withRunner = (runNetsh) => {
    const calls = []
    const adapter = new WindowsFirewallAdapter({
      enabled: true,
      runNetsh: async (args) => {
        calls.push(args)
        return runNetsh()
      },
    })
    adapter._assertEnabled = () => {}
    return { adapter, calls }
  }
  const netshError = (message, stdout = '') => Object.assign(new Error(message), { stdout, stderr: '' })
  const rule = { containmentId: 'c-1', ruleName: 'SentinelAI-Rule-c-1' }

  test('PRESENT when netsh lists the rule; only "show rule" is ever run', async () => {
    const { adapter, calls } = withRunner(async () => ({ stdout: 'Rule Name: SentinelAI-Rule-c-1\nEnabled: Yes\n' }))
    await expect(adapter.inspectRule(rule)).resolves.toMatchObject({ state: 'PRESENT' })
    expect(calls).toEqual([['advfirewall', 'firewall', 'show', 'rule', 'name=SentinelAI-Rule-c-1']])
  })

  test('ABSENT only on netsh\'s own "No rules match" answer', async () => {
    const { adapter } = withRunner(async () => {
      throw netshError('Command failed: netsh', '\r\nNo rules match the specified criteria.\r\n')
    })
    await expect(adapter.inspectRule(rule)).resolves.toMatchObject({ state: 'ABSENT' })
  })

  test.each([
    ['a timeout', netshError('Command failed: netsh (ETIMEDOUT)')],
    ['access denied', netshError('Command failed: netsh', 'The requested operation requires elevation.')],
    ['localised output', netshError('Command failed: netsh', 'Keine Regeln entsprechen den angegebenen Kriterien.')],
  ])('UNKNOWN (never ABSENT) on %s', async (_label, error) => {
    const { adapter } = withRunner(async () => {
      throw error
    })
    await expect(adapter.inspectRule(rule)).resolves.toMatchObject({ state: 'UNKNOWN' })
  })

  test('UNKNOWN when netsh succeeds without naming the rule', async () => {
    const { adapter } = withRunner(async () => ({ stdout: 'Ok.' }))
    await expect(adapter.inspectRule(rule)).resolves.toMatchObject({ state: 'UNKNOWN' })
  })

  test('with the safety gate closed it throws (adapter unavailable), it does not answer ABSENT', async () => {
    const gated = new WindowsFirewallAdapter({
      enabled: false,
      runNetsh: async () => {
        throw new Error('netsh must not run')
      },
    })
    await expect(gated.inspectRule(rule)).rejects.toMatchObject({ code: 'FIREWALL_ENFORCEMENT_DISABLED' })
  })

  test('the interface default is UNKNOWN, so an adapter without inspection never releases a lock', async () => {
    const Interface = require('../services/containment/adapterInterface')
    await expect(new Interface().inspectRule(rule)).resolves.toMatchObject({ state: 'UNKNOWN' })
  })
})
