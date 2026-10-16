'use strict'

/**
 * tests/containmentLifecycle.test.js
 *
 * Comprehensive Phase 4 Containment & Response Hardening Test Suite:
 *
 * 1. Policy Engine Deterministic Validation & Safety Exclusions
 * 2. State Machine Transitions & Concurrency Token Invariants
 * 3. Adapter Abstraction (Mock, Windows Firewall Gate, Factory Fallback)
 * 4. Containment Service End-to-End Orchestration & Idempotency
 * 5. Automatic Reconciliation & TTL Expiration Sweeper
 * 6. Audit Logging & Credential Redaction
 */

const {
  validateTarget,
  checkSafetyExclusions,
  checkRequesterAuthorization,
  calculateExpiration,
  evaluatePolicy,
  normalizeTarget,
  DEFAULT_CONTAINMENT_DURATION_SECONDS,
} = require('../services/containmentPolicyService')

const ContainmentAction = require('../models/ContainmentAction')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const WindowsFirewallAdapter = require('../services/containment/WindowsFirewallAdapter')
const {
  getContainmentAdapter,
  setContainmentAdapter,
  resetContainmentAdapter,
} = require('../services/containment/adapterFactory')

const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')

const { sanitizeDetails, logContainmentAudit } = require('../utils/containmentAudit')

describe('Phase 4: Containment & Response Policy Hardening', () => {
  // ==========================================================================
  // 1. POLICY ENGINE TESTS
  // ==========================================================================
  describe('1. Containment Policy Engine: Target Validation & Safety Exclusions', () => {
    test('1.1: Validates standard IPv4 addresses', () => {
      expect(normalizeTarget('  198.51.100.14  ')).toBe('198.51.100.14')
      const res = validateTarget('198.51.100.14')
      expect(res.isValid).toBe(true)
      expect(res.targetType).toBe('ipv4')
      expect(res.normalizedTarget).toBe('198.51.100.14')
    })

    test('1.2: Validates standard IPv6 addresses', () => {
      const res = validateTarget('2001:0db8:85a3:0000:0000:8a2e:0370:7334')
      expect(res.isValid).toBe(true)
      expect(res.targetType).toBe('ipv6')
    })

    test('1.3: Validates valid CIDR blocks', () => {
      const res = validateTarget('198.51.100.0/24')
      expect(res.isValid).toBe(true)
      expect(res.targetType).toBe('cidr')
      expect(res.prefix).toBe(24)
    })

    test('1.4: Rejects malformed IP addresses and non-IP strings', () => {
      expect(validateTarget('999.999.999.999').isValid).toBe(false)
      expect(validateTarget('not-an-ip').isValid).toBe(false)
      expect(validateTarget('').isValid).toBe(false)
      expect(validateTarget(null).isValid).toBe(false)
    })

    test('1.5: Rejects invalid CIDR prefixes', () => {
      expect(validateTarget('192.168.1.0/33').isValid).toBe(false)
      expect(validateTarget('192.168.1.0/-1').isValid).toBe(false)
      expect(validateTarget('192.168.1.0/abc').isValid).toBe(false)
    })

    test('1.6: Self-lockout prevention: Rejects loopback addresses (127.0.0.1, ::1, localhost)', () => {
      const check1 = checkSafetyExclusions(validateTarget('127.0.0.1'))
      expect(check1.isSafe).toBe(false)
      expect(check1.decision).toBe('DENIED')

      const check2 = checkSafetyExclusions(validateTarget('127.0.0.50'))
      expect(check2.isSafe).toBe(false)

      const check3 = checkSafetyExclusions(validateTarget('::1'))
      expect(check3.isSafe).toBe(false)

      const check4 = checkSafetyExclusions({ normalizedTarget: 'localhost', ipPart: 'localhost' })
      expect(check4.isSafe).toBe(false)
    })

    test('1.7: Safety exclusion: Rejects broadcast (255.255.255.255) and multicast (224.0.0.0/4)', () => {
      expect(checkSafetyExclusions(validateTarget('255.255.255.255')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('224.0.0.1')).isSafe).toBe(false)
      expect(checkSafetyExclusions(validateTarget('239.255.0.1')).isSafe).toBe(false)
    })

    test('1.8: Broad CIDR protection: Rejects /0 and IPv4 prefixes broader than /24', () => {
      const broad0 = checkSafetyExclusions(validateTarget('0.0.0.0/0'))
      expect(broad0.isSafe).toBe(false)

      const broad16 = checkSafetyExclusions(validateTarget('10.0.0.0/16'))
      expect(broad16.isSafe).toBe(false)
      expect(broad16.reason).toContain('too broad')

      const broad8 = checkSafetyExclusions(validateTarget('172.16.0.0/8'))
      expect(broad8.isSafe).toBe(false)

      // /24 is safe
      const safe24 = checkSafetyExclusions(validateTarget('198.51.100.0/24'))
      expect(safe24.isSafe).toBe(true)
    })

    test('1.9: Requester authorization: Enforces authentication, active status, and password change invariant', () => {
      // Unauthenticated
      expect(checkRequesterAuthorization(null).authorized).toBe(false)

      // mustChangePassword === true
      const pendingUser = { _id: 'user-1', role: 'admin', mustChangePassword: true, status: 'active' }
      const resPending = checkRequesterAuthorization(pendingUser)
      expect(resPending.authorized).toBe(false)
      expect(resPending.reason).toContain('Password change required')

      // Inactive user
      const inactiveUser = { _id: 'user-2', role: 'admin', mustChangePassword: false, status: 'suspended' }
      expect(checkRequesterAuthorization(inactiveUser).authorized).toBe(false)

      // Viewer cannot contain
      const viewerUser = { _id: 'user-3', role: 'viewer', mustChangePassword: false, status: 'active' }
      expect(checkRequesterAuthorization(viewerUser).authorized).toBe(false)

      // Analyst can contain single IP
      const analystUser = { _id: 'user-4', role: 'analyst', mustChangePassword: false, status: 'active' }
      expect(checkRequesterAuthorization(analystUser, { targetType: 'ipv4' }).authorized).toBe(true)

      // Analyst cannot contain CIDR (requires admin)
      expect(checkRequesterAuthorization(analystUser, { targetType: 'cidr' }).authorized).toBe(false)

      // Admin can contain CIDR
      const adminUser = { _id: 'user-5', role: 'admin', mustChangePassword: false, status: 'active' }
      expect(checkRequesterAuthorization(adminUser, { targetType: 'cidr' }).authorized).toBe(true)
    })

    test('1.10: Expiration calculation: Bounds duration to [60, 2592000] and defaults to 3600s', () => {
      // Default
      const expDefault = calculateExpiration()
      expect(expDefault.valid).toBe(true)
      expect(expDefault.durationSeconds).toBe(DEFAULT_CONTAINMENT_DURATION_SECONDS)
      expect(expDefault.expiresAt).toBeInstanceOf(Date)

      // Below min (59s)
      expect(calculateExpiration(59).valid).toBe(false)

      // Above max (31 days)
      expect(calculateExpiration(31 * 86400).valid).toBe(false)

      // Permanent
      const expPerm = calculateExpiration(null, true)
      expect(expPerm.valid).toBe(true)
      expect(expPerm.expiresAt).toBeNull()
    })

    test('1.11: Master evaluatePolicy combines all checks deterministically', () => {
      const admin = { _id: 'admin-1', role: 'admin', mustChangePassword: false, status: 'active' }

      // Valid case
      const validRes = evaluatePolicy({
        target: '203.0.113.50',
        durationSeconds: 7200,
        requester: admin,
      })
      expect(validRes.decision).toBe('ALLOWED')
      expect(validRes.targetInfo.normalizedTarget).toBe('203.0.113.50')

      // Self-lockout case
      const loopbackRes = evaluatePolicy({
        target: '127.0.0.1',
        requester: admin,
      })
      expect(loopbackRes.decision).toBe('DENIED')
      expect(loopbackRes.reason).toContain('loopback')
    })

    test('1.12: Adversarial IP policy: Link-local (169.254.0.0/16, fe80::/10) and unspecified (0.0.0.0, ::) are strictly denied', () => {
      // IPv4 Link-local
      const ipv4LinkLocal = checkSafetyExclusions(validateTarget('169.254.1.100'))
      expect(ipv4LinkLocal.isSafe).toBe(false)
      expect(ipv4LinkLocal.decision).toBe('DENIED')

      // IPv6 Link-local
      const ipv6LinkLocal = checkSafetyExclusions(validateTarget('fe80::1ff:fe00:1'))
      expect(ipv6LinkLocal.isSafe).toBe(false)
      expect(ipv6LinkLocal.decision).toBe('DENIED')

      // IPv4 Unspecified
      const ipv4Unspec = checkSafetyExclusions(validateTarget('0.0.0.0'))
      expect(ipv4Unspec.isSafe).toBe(false)

      // IPv6 Unspecified
      const ipv6Unspec = checkSafetyExclusions(validateTarget('::'))
      expect(ipv6Unspec.isSafe).toBe(false)
    })

    test('1.13: Adversarial IP policy: IPv4-mapped IPv6 addresses are unwrapped and evaluated against safety exclusions', () => {
      // IPv4-mapped loopback
      const mappedLoopback = checkSafetyExclusions(validateTarget('::ffff:127.0.0.1'))
      expect(mappedLoopback.isSafe).toBe(false)
      expect(mappedLoopback.decision).toBe('DENIED')
      expect(mappedLoopback.reason).toContain('IPv4-mapped')

      // IPv4-mapped link-local
      const mappedLinkLocal = checkSafetyExclusions(validateTarget('::ffff:169.254.5.5'))
      expect(mappedLinkLocal.isSafe).toBe(false)
      expect(mappedLinkLocal.decision).toBe('DENIED')

      // IPv4-mapped unspecified
      const mappedUnspecified = checkSafetyExclusions(validateTarget('::ffff:0.0.0.0'))
      expect(mappedUnspecified.isSafe).toBe(false)
      expect(mappedUnspecified.decision).toBe('DENIED')

      // IPv4-mapped public IP is allowed
      const mappedPublic = checkSafetyExclusions(validateTarget('::ffff:203.0.113.195'))
      expect(mappedPublic.isSafe).toBe(true)
      expect(mappedPublic.decision).toBe('ALLOWED')
    })

    test('1.14: Core service port policy: Target strings containing ports are rejected by validation', () => {
      // Core service ports
      expect(validateTarget('192.168.1.1:5000').isValid).toBe(false)
      expect(validateTarget('192.168.1.1:5000').error).toContain('core service port 5000')

      expect(validateTarget('10.0.0.1:8000').isValid).toBe(false)
      expect(validateTarget('10.0.0.1:8000').error).toContain('core service port 8000')

      expect(validateTarget('127.0.0.1:27017').isValid).toBe(false)
      expect(validateTarget('127.0.0.1:27017').error).toContain('core service port 27017')

      expect(validateTarget('192.0.2.1:3000').isValid).toBe(false)
      expect(validateTarget('192.0.2.1:3000').error).toContain('core service port 3000')

      // Generic port in L3 target
      expect(validateTarget('192.0.2.1:8080').isValid).toBe(false)
      expect(validateTarget('192.0.2.1:8080').error).toContain('port specification')
    })

    test('1.15: IPv6 CIDR prefix boundaries: /64 is allowed, < /64 is denied as too broad, > /128 is invalid', () => {
      // /64 allowed
      const cidr64 = checkSafetyExclusions(validateTarget('2001:db8::/64'))
      expect(cidr64.isSafe).toBe(true)

      // /48 too broad
      const cidr48 = checkSafetyExclusions(validateTarget('2001:db8::/48'))
      expect(cidr48.isSafe).toBe(false)
      expect(cidr48.decision).toBe('DENIED')
      expect(cidr48.reason).toContain('too broad')

      // /32 too broad
      const cidr32 = checkSafetyExclusions(validateTarget('2001:db8::/32'))
      expect(cidr32.isSafe).toBe(false)

      // > 128 invalid
      const cidr129 = validateTarget('2001:db8::/129')
      expect(cidr129.isValid).toBe(false)
      expect(cidr129.error).toContain('between 0 and 128')
    })
  })

  // ==========================================================================
  // 2. STATE MACHINE TESTS
  // ==========================================================================
  describe('2. State Machine: Typed Transitions & Concurrency Control', () => {
    test('2.1: Validates complete forward happy path: REQUESTED -> VALIDATING -> APPROVED -> APPLYING -> ACTIVE', () => {
      const action = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
      })

      expect(action.enforcementStatus).toBe('REQUESTED')
      expect(action.version).toBe(0)

      action.transitionTo('VALIDATING')
      expect(action.enforcementStatus).toBe('VALIDATING')
      expect(action.version).toBe(1)

      action.transitionTo('APPROVED')
      expect(action.enforcementStatus).toBe('APPROVED')
      expect(action.version).toBe(2)

      action.transitionTo('APPLYING')
      expect(action.enforcementStatus).toBe('APPLYING')
      expect(action.version).toBe(3)

      action.transitionTo('ACTIVE')
      expect(action.enforcementStatus).toBe('ACTIVE')
      expect(action.version).toBe(4)
    })

    test('2.2: Validates teardown path: ACTIVE -> EXPIRING -> ROLLING_BACK -> ROLLED_BACK', () => {
      const action = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'ACTIVE',
      })

      action.transitionTo('EXPIRING')
      expect(action.enforcementStatus).toBe('EXPIRING')

      action.transitionTo('ROLLING_BACK')
      expect(action.enforcementStatus).toBe('ROLLING_BACK')

      action.transitionTo('ROLLED_BACK')
      expect(action.enforcementStatus).toBe('ROLLED_BACK')
    })

    test('2.3: Rejects illegal state jumps (e.g. REQUESTED -> ACTIVE)', () => {
      const action = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'REQUESTED',
      })

      expect(() => {
        action.transitionTo('ACTIVE')
      }).toThrow(/Invalid containment transition/)
    })

    test('2.4: Terminal states cannot transition to active states', () => {
      const rolledBack = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'ROLLED_BACK',
      })

      expect(() => {
        rolledBack.transitionTo('ACTIVE')
      }).toThrow()

      const rejected = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'REJECTED',
      })

      expect(() => {
        rejected.transitionTo('APPROVED')
      }).toThrow()
    })

    test('2.5: Concurrency safety: conflicting concurrent state transitions are rejected', () => {
      const action = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'ACTIVE',
      })

      // Thread A begins rollback
      action.transitionTo('ROLLING_BACK')
      expect(action.enforcementStatus).toBe('ROLLING_BACK')

      // Concurrent Thread B attempts to transition from ACTIVE or directly to EXPIRING/FAILED
      expect(() => {
        action.transitionTo('EXPIRING')
      }).toThrow(/Invalid containment transition/)

      expect(() => {
        action.transitionTo('ACTIVE')
      }).toThrow(/Invalid containment transition/)
    })

    test('2.6: Idempotent duplicate rollback protection', () => {
      const action = new ContainmentAction({
        target: '198.51.100.20',
        normalizedTarget: '198.51.100.20',
        enforcementStatus: 'ROLLED_BACK',
      })

      expect(() => {
        action.transitionTo('ROLLING_BACK')
      }).toThrow(/Invalid containment transition/)
    })
  })

  // ==========================================================================
  // 3. ADAPTER TESTS
  // ==========================================================================
  describe('3. Containment Adapters: Mock & Windows Firewall Safety Gate', () => {
    let mockAdapter

    beforeEach(() => {
      mockAdapter = new MockContainmentAdapter()
    })

    test('3.1: MockAdapter applies, verifies, lists, and removes rules in-memory', async () => {
      const applyRes = await mockAdapter.applyRule({
        containmentId: 'test-c1',
        target: '203.0.113.10',
        targetType: 'ipv4',
      })

      expect(applyRes.success).toBe(true)
      expect(applyRes.ruleId).toBe('mock-rule-test-c1')

      const verifyRes = await mockAdapter.verifyRule({ containmentId: 'test-c1' })
      expect(verifyRes.exists).toBe(true)
      expect(verifyRes.active).toBe(true)

      const activeRules = await mockAdapter.listActiveRules()
      expect(activeRules.length).toBe(1)
      expect(activeRules[0].target).toBe('203.0.113.10')

      const removeRes = await mockAdapter.removeRule({ containmentId: 'test-c1' })
      expect(removeRes.success).toBe(true)

      const postVerify = await mockAdapter.verifyRule({ containmentId: 'test-c1' })
      expect(postVerify.exists).toBe(false)
    })

    test('3.2: MockAdapter supports failure simulation for testing compensation', async () => {
      mockAdapter.setFailNextApply('Simulated driver timeout')
      const applyFail = await mockAdapter.applyRule({
        containmentId: 'test-fail-1',
        target: '203.0.113.11',
      })
      expect(applyFail.success).toBe(false)
      expect(applyFail.stderr).toContain('Simulated driver timeout')

      mockAdapter.setFailNextRemove('Simulated rule locked')
      const removeFail = await mockAdapter.removeRule({
        containmentId: 'test-fail-2',
      })
      expect(removeFail.success).toBe(false)
      expect(removeFail.stderr).toContain('Simulated rule locked')
    })

    test('3.3: WindowsFirewallAdapter strictly blocks execution when safety gate is disabled', async () => {
      const originalEnv = process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT
      process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = 'false'

      const fwAdapter = new WindowsFirewallAdapter({ enabled: false })
      expect(fwAdapter.getBackendType()).toBe('windows-firewall')

      await expect(fwAdapter.applyRule({ containmentId: 'test-safe', target: '203.0.113.12' })).rejects.toThrow(
        /disabled by safety gate/
      )

      await expect(fwAdapter.removeRule({ containmentId: 'test-safe', target: '203.0.113.12' })).rejects.toThrow(
        /disabled by safety gate/
      )

      process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = originalEnv
    })

    test('3.4: AdapterFactory safely falls back to Mock adapter when Windows Firewall gate is closed', () => {
      resetContainmentAdapter()
      const originalEnv = process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT
      process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = 'false'

      const adapter = getContainmentAdapter({ backend: 'windows-firewall', forceNew: true })
      expect(adapter.getBackendType()).toBe('mock')

      setContainmentAdapter(adapter)
      expect(getContainmentAdapter()).toBe(adapter)

      process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT = originalEnv
      resetContainmentAdapter()
    })

    test('3.5: Adapter apply failure returns success: false and does not register active rule', async () => {
      mockAdapter.setFailNextApply('WFP driver device busy')
      const res = await mockAdapter.applyRule({
        containmentId: 'test-fail-apply',
        target: '203.0.113.25',
      })

      expect(res.success).toBe(false)
      expect(res.exitCode).toBe(1)
      expect(res.stderr).toContain('WFP driver device busy')
      expect(await mockAdapter.listActiveRules()).toHaveLength(0)
    })

    test('3.6: Adapter removal failure returns success: false and preserves active rule in map', async () => {
      await mockAdapter.applyRule({
        containmentId: 'test-fail-remove',
        target: '203.0.113.26',
      })
      expect(await mockAdapter.listActiveRules()).toHaveLength(1)

      mockAdapter.setFailNextRemove('WFP rule handle locked')
      const res = await mockAdapter.removeRule({
        containmentId: 'test-fail-remove',
      })

      expect(res.success).toBe(false)
      expect(res.exitCode).toBe(1)
      expect(res.stderr).toContain('WFP rule handle locked')
      expect(await mockAdapter.listActiveRules()).toHaveLength(1)
    })

    test('3.7: WindowsFirewallAdapter target sanitization strictly blocks arbitrary shell injection', () => {
      const fwAdapter = new WindowsFirewallAdapter({ enabled: false })
      const payloads = [
        '1.1.1.1; whoami',
        '1.1.1.1 & dir',
        '1.1.1.1 | calc',
        '1.1.1.1`whoami`',
        '1.1.1.1$(whoami)',
        '1.1.1.1 && id',
        '1.1.1.1\nwhoami',
        '1.1.1.1 "whoami"',
        '1.1.1.1 2.2.2.2',
      ]

      for (const payload of payloads) {
        expect(() => {
          fwAdapter._sanitizeTarget(payload)
        }).toThrow(/Invalid target address characters/)
      }
    })

    test('3.8: WindowsFirewallAdapter rule name sanitization strictly enforces SentinelAI namespace', () => {
      const fwAdapter = new WindowsFirewallAdapter({ enabled: false })

      // Valid SentinelAI rule names
      expect(fwAdapter._sanitizeRuleName('SentinelAI-Rule-abc-123')).toBe('SentinelAI-Rule-abc-123')
      expect(fwAdapter._sanitizeRuleName('SentinelAI-Rule-9999')).toBe('SentinelAI-Rule-9999')

      // Disallowed foreign or malformed rule names
      expect(() => fwAdapter._sanitizeRuleName('Core Networking')).toThrow(/Invalid or unauthorized rule name/)
      expect(() => fwAdapter._sanitizeRuleName('Windows Defender')).toThrow(/Invalid or unauthorized rule name/)
      expect(() => fwAdapter._sanitizeRuleName('SentinelAI-Rule-; calc')).toThrow(/Invalid or unauthorized rule name/)
      expect(() => fwAdapter._sanitizeRuleName('')).toThrow(/Invalid or unauthorized rule name/)
    })
  })

  // ==========================================================================
  // 4. RECONCILIATION & AUDIT TESTS
  // ==========================================================================
  describe('4. Reconciliation & Structured Audit Logging', () => {
    test('4.1: Audit logger redacts sensitive credentials in details', () => {
      const sanitized = sanitizeDetails({
        target: '203.0.113.99',
        password: 'SuperSecretPassword123',
        nested: {
          authToken: 'jwt.token.string',
          safeParam: 'public-data',
        },
      })

      expect(sanitized.password).toBe('[REDACTED]')
      expect(sanitized.nested.authToken).toBe('[REDACTED]')
      expect(sanitized.nested.safeParam).toBe('public-data')
    })

    test('4.2: Structured audit log format conforms to spec', () => {
      const entry = logContainmentAudit({
        action: 'CONTAINMENT_ACTIVE',
        containmentId: 'c-audit-test',
        target: '203.0.113.99',
        actionType: 'block_ip',
        policyDecision: 'ALLOWED',
        enforcementBackend: 'mock',
        enforcementStatus: 'ACTIVE',
        operatorId: 'user-audit-1',
        operatorEmail: 'admin@sentinelai.local',
        operatorRole: 'admin',
        details: { ruleId: 'mock-rule-1' },
      })

      expect(entry.auditType).toBe('CONTAINMENT_AUDIT')
      expect(entry.action).toBe('CONTAINMENT_ACTIVE')
      expect(entry.operator.email).toBe('admin@sentinelai.local')
      expect(entry.timestamp).toBeDefined()
    })

    test('4.3: ContainmentReconciliationService handles empty expired queue gracefully', async () => {
      const reconciler = new ContainmentReconciliationService()
      const originalFind = ContainmentAction.find
      ContainmentAction.find = jest.fn().mockResolvedValue([])

      const res = await reconciler.reconcileExpiredActions()
      expect(res.processed).toBe(0)
      expect(res.successful).toBe(0)
      expect(res.failed).toBe(0)

      ContainmentAction.find = originalFind
    })

    test('4.4: Restart recovery & stale state: Reconciler recovers and rolls back expired active rules left by previous process', async () => {
      const reconciler = new ContainmentReconciliationService()
      const BlockedIP = require('../models/BlockedIP')
      const ThreatLog = require('../models/ThreatLog')

      const origDeleteOne = BlockedIP.deleteOne
      const origThreatFind = ThreatLog.find
      BlockedIP.deleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 })
      ThreatLog.find = jest.fn().mockResolvedValue([])

      const staleAction = new ContainmentAction({
        containmentId: 'stale-c-1',
        target: '203.0.113.88',
        normalizedTarget: '203.0.113.88',
        enforcementStatus: 'ACTIVE',
        expiresAt: new Date(Date.now() - 60000), // Expired 1 minute ago
        enforcementDetails: { ruleId: 'mock-rule-stale-c-1', ruleName: 'SentinelAI-Mock-stale-c-1' },
      })
      staleAction.save = jest.fn().mockResolvedValue(staleAction)

      const originalFind = ContainmentAction.find
      ContainmentAction.find = jest.fn().mockResolvedValue([staleAction])

      const res = await reconciler.reconcileExpiredActions()
      expect(res.processed).toBe(1)
      expect(res.successful).toBe(1)
      expect(staleAction.enforcementStatus).toBe('ROLLED_BACK')
      expect(staleAction.rolledBackAt).toBeInstanceOf(Date)

      ContainmentAction.find = originalFind
      BlockedIP.deleteOne = origDeleteOne
      ThreatLog.find = origThreatFind
    })

    test('4.5: Reconciler failure handling: Failed adapter removal marks action as ROLLBACK_FAILED', async () => {
      const reconciler = new ContainmentReconciliationService()

      const failingAdapter = new MockContainmentAdapter()
      failingAdapter.setFailNextRemove('Kernel resource locked')
      setContainmentAdapter(failingAdapter)

      const staleAction = new ContainmentAction({
        containmentId: 'stale-fail-c-2',
        target: '203.0.113.89',
        normalizedTarget: '203.0.113.89',
        enforcementStatus: 'ACTIVE',
        expiresAt: new Date(Date.now() - 60000),
        enforcementDetails: { ruleId: 'mock-rule-stale-fail-c-2' },
      })
      staleAction.save = jest.fn().mockResolvedValue(staleAction)

      const originalFind = ContainmentAction.find
      ContainmentAction.find = jest.fn().mockResolvedValue([staleAction])

      const res = await reconciler.reconcileExpiredActions()
      expect(res.processed).toBe(1)
      expect(res.failed).toBe(1)
      expect(staleAction.enforcementStatus).toBe('ROLLBACK_FAILED')
      expect(staleAction.failureReason).toContain('Kernel resource locked')

      ContainmentAction.find = originalFind
      resetContainmentAdapter()
    })

    test('4.6: Reconciler preserves permanent containment actions (expiresAt === null)', async () => {
      const reconciler = new ContainmentReconciliationService()
      const originalFind = ContainmentAction.find

      // Mock DB query simulating Mongo query matching { enforcementStatus: 'ACTIVE', expiresAt: { $ne: null, $lte: now } }
      const actionsInDb = [
        new ContainmentAction({
          containmentId: 'perm-action-1',
          target: '203.0.113.77',
          normalizedTarget: '203.0.113.77',
          isPermanent: true,
          expiresAt: null,
          enforcementStatus: 'ACTIVE',
        }),
      ]

      // Mongoose filter logic
      ContainmentAction.find = jest.fn().mockImplementation((query) => {
        const results = actionsInDb.filter((a) => {
          if (query.enforcementStatus && a.enforcementStatus !== query.enforcementStatus) return false
          if (query.expiresAt?.$ne === null && a.expiresAt === null) return false
          return true
        })
        return Promise.resolve(results)
      })

      const res = await reconciler.reconcileExpiredActions()
      expect(res.processed).toBe(0)
      expect(actionsInDb[0].enforcementStatus).toBe('ACTIVE')

      ContainmentAction.find = originalFind
    })

    test('4.7: Repeated reconciliation runs are idempotent and ignore unexpired actions', async () => {
      const reconciler = new ContainmentReconciliationService()
      const originalFind = ContainmentAction.find

      const unexpiredAction = new ContainmentAction({
        containmentId: 'unexpired-1',
        target: '203.0.113.66',
        normalizedTarget: '203.0.113.66',
        isPermanent: false,
        expiresAt: new Date(Date.now() + 3600000), // 1 hour in the future
        enforcementStatus: 'ACTIVE',
      })

      ContainmentAction.find = jest.fn().mockImplementation((_query) => {
        const now = new Date()
        if (unexpiredAction.expiresAt <= now) return Promise.resolve([unexpiredAction])
        return Promise.resolve([])
      })

      // Run 1
      const run1 = await reconciler.reconcileExpiredActions()
      expect(run1.processed).toBe(0)
      expect(unexpiredAction.enforcementStatus).toBe('ACTIVE')

      // Run 2
      const run2 = await reconciler.reconcileExpiredActions()
      expect(run2.processed).toBe(0)
      expect(unexpiredAction.enforcementStatus).toBe('ACTIVE')

      ContainmentAction.find = originalFind
    })

    test('4.8: Reconciler retries and recovers actions in ROLLBACK_FAILED status', async () => {
      const reconciler = new ContainmentReconciliationService()
      const BlockedIP = require('../models/BlockedIP')
      const ThreatLog = require('../models/ThreatLog')

      const origDeleteOne = BlockedIP.deleteOne
      const origThreatFind = ThreatLog.find
      BlockedIP.deleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 })
      ThreatLog.find = jest.fn().mockResolvedValue([])

      // Action previously failed rollback
      const failedAction = new ContainmentAction({
        containmentId: 'retry-c-3',
        target: '203.0.113.91',
        normalizedTarget: '203.0.113.91',
        enforcementStatus: 'ROLLBACK_FAILED',
        expiresAt: new Date(Date.now() - 120000),
        enforcementDetails: { ruleId: 'mock-rule-retry-c-3' },
      })
      failedAction.save = jest.fn().mockResolvedValue(failedAction)

      const originalFind = ContainmentAction.find
      ContainmentAction.find = jest.fn().mockResolvedValue([failedAction])

      // Adapter succeeds on retry
      const res = await reconciler.reconcileExpiredActions()
      expect(res.processed).toBe(1)
      expect(res.successful).toBe(1)
      expect(failedAction.enforcementStatus).toBe('ROLLED_BACK')
      expect(failedAction.rolledBackAt).toBeInstanceOf(Date)

      ContainmentAction.find = originalFind
      BlockedIP.deleteOne = origDeleteOne
      ThreatLog.find = origThreatFind
    })
  })
})
