'use strict'

const WindowsFirewallAdapter = require('../services/containment/WindowsFirewallAdapter')
const {
  assertIsolatedVMEnvironment,
  assertSafeTestTarget,
  SAFE_TEST_TARGET,
  VM_MARKER_ENV,
} = require('./helpers/vmFirewallHarness')
const { validateTarget, checkSafetyExclusions } = require('../services/containmentPolicyService')

describe('Phase 6F — Isolated Windows Firewall Adapter Safety Tests', () => {
  describe('VM Harness Fail-Closed Guards', () => {
    test('assertIsolatedVMEnvironment fails closed on host workstation', () => {
      // Ensure environment variable is not set to true
      delete process.env[VM_MARKER_ENV]
      expect(() => assertIsolatedVMEnvironment()).toThrow(/CRITICAL SAFETY REFUSAL/)
    })

    test('assertSafeTestTarget permits RFC 5737 TEST-NET-1 and rejects LAN/loopback/public targets', () => {
      expect(() => assertSafeTestTarget(SAFE_TEST_TARGET)).not.toThrow()
      expect(() => assertSafeTestTarget('192.0.2.42')).not.toThrow()

      // Forbidden targets
      expect(() => assertSafeTestTarget('127.0.0.1')).toThrow(/TARGET SAFETY REFUSAL/)
      expect(() => assertSafeTestTarget('192.168.1.1')).toThrow(/TARGET SAFETY REFUSAL/)
      expect(() => assertSafeTestTarget('10.0.0.1')).toThrow(/TARGET SAFETY REFUSAL/)
      expect(() => assertSafeTestTarget('8.8.8.8')).toThrow(/TARGET SAFETY REFUSAL/)
    })
  })

  describe('WindowsFirewallAdapter Safety Properties', () => {
    test('adapter strictly refuses execution when safety gate is disabled', async () => {
      const adapter = new WindowsFirewallAdapter({ enabled: false })
      expect(adapter.enabled).toBe(false)
      expect(adapter.getBackendType()).toBe('windows-firewall')

      await expect(
        adapter.applyRule({ containmentId: 'test-1', target: '192.0.2.1' })
      ).rejects.toMatchObject({
        code: 'FIREWALL_ENFORCEMENT_DISABLED',
      })

      await expect(
        adapter.removeRule({ containmentId: 'test-1', ruleId: 'SentinelAI-Rule-test-1' })
      ).rejects.toMatchObject({
        code: 'FIREWALL_ENFORCEMENT_DISABLED',
      })

      await expect(
        adapter.verifyRule({ containmentId: 'test-1', ruleId: 'SentinelAI-Rule-test-1' })
      ).rejects.toMatchObject({
        code: 'FIREWALL_ENFORCEMENT_DISABLED',
      })

      await expect(adapter.listActiveRules()).rejects.toMatchObject({
        code: 'FIREWALL_ENFORCEMENT_DISABLED',
      })
    })

    test('_sanitizeTarget rejects command injection characters', () => {
      const adapter = new WindowsFirewallAdapter({ enabled: false })

      // Valid addresses
      expect(adapter._sanitizeTarget('192.0.2.1')).toBe('192.0.2.1')
      expect(adapter._sanitizeTarget('2001:db8::1')).toBe('2001:db8::1')
      expect(adapter._sanitizeTarget('192.0.2.0/24')).toBe('192.0.2.0/24')

      // Injection attempts
      expect(() => adapter._sanitizeTarget('192.0.2.1 & calc.exe')).toThrow(/Invalid target address characters/)
      expect(() => adapter._sanitizeTarget('192.0.2.1; netsh')).toThrow(/Invalid target address characters/)
      expect(() => adapter._sanitizeTarget('192.0.2.1 | whoami')).toThrow(/Invalid target address characters/)
      expect(() => adapter._sanitizeTarget('192.0.2.1`calc`')).toThrow(/Invalid target address characters/)
      expect(() => adapter._sanitizeTarget('192.0.2.1\nwhoami')).toThrow(/Invalid target address characters/)
      expect(() => adapter._sanitizeTarget('192.0.2.1$(whoami)')).toThrow(/Invalid target address characters/)
    })

    test('_sanitizeRuleName strictly enforces SentinelAI-Rule- prefix and valid chars', () => {
      const adapter = new WindowsFirewallAdapter({ enabled: false })

      expect(adapter._sanitizeRuleName('SentinelAI-Rule-12345')).toBe('SentinelAI-Rule-12345')
      expect(adapter._sanitizeRuleName('SentinelAI-Rule-block-threat-01')).toBe('SentinelAI-Rule-block-threat-01')

      // Non-SentinelAI rule names
      expect(() => adapter._sanitizeRuleName('Allow-All-Inbound')).toThrow(/Invalid or unauthorized rule name/)
      expect(() => adapter._sanitizeRuleName('Core-Networking-DNS')).toThrow(/Invalid or unauthorized rule name/)
      // Injection in rule name
      expect(() => adapter._sanitizeRuleName('SentinelAI-Rule-&calc')).toThrow(/Invalid or unauthorized rule name/)
      expect(() => adapter._sanitizeRuleName('SentinelAI-Rule-;netsh')).toThrow(/Invalid or unauthorized rule name/)
    })
  })

  describe('Policy Engine IP/CIDR Safety Boundaries', () => {
    test('rejects loopback addresses', () => {
      expect(checkSafetyExclusions(validateTarget('127.0.0.1')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('127.0.0.53')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('::1')).isSafe).toBe(false)
    })

    test('rejects link-local and multicast addresses', () => {
      expect(checkSafetyExclusions(validateTarget('169.254.1.1')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('fe80::1')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('224.0.0.1')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('239.255.255.250')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('ff02::1')).isSafe).toBe(false)
    })

    test('validates CIDR prefix ranges properly', () => {
      expect(validateTarget('192.0.2.0/24').isValid).toBe(true)
      expect(validateTarget('192.0.2.0/33').isValid).toBe(false)
      expect(validateTarget('2001:db8::/64').isValid).toBe(true)
      expect(validateTarget('2001:db8::/129').isValid).toBe(false)
    })
  })
})
