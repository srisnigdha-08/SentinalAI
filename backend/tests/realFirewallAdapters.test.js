'use strict'
/**
 * Real host-firewall adapters with MOCKED command execution: no netsh/iptables ever runs here. Covers the
 * real-enforcement gate (enforcementSafety), the Linux iptables adapter's commands, duplicate prevention and
 * verification, the factory's refusal in tests, and the containment service's post-apply verification (a command
 * that "succeeded" without creating a rule fails the action and the half-created rule is removed).
 */
const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')

jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))

const { realEnforcementDecision, confirmationPhrase } = require('../services/containment/enforcementSafety')
const LinuxIptablesAdapter = require('../services/containment/LinuxIptablesAdapter')
const WindowsFirewallAdapter = require('../services/containment/WindowsFirewallAdapter')
const factory = require('../services/containment/adapterFactory')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')

const HOST = 'lab-host'
const realEnv = (extra = {}) => ({
  CONTAINMENT_BACKEND: 'linux-iptables',
  ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT: 'true',
  CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase(HOST),
  ...extra,
})

describe('real-enforcement gate', () => {
  test('all guards satisfied (outside tests) -> allowed', () => {
    expect(realEnforcementDecision(realEnv(), HOST)).toMatchObject({ allowed: true, backend: 'linux-iptables' })
  })

  test.each([
    [{ CONTAINMENT_BACKEND: 'mock' }, 'not a real firewall backend'],
    [{ ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT: 'false' }, 'ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT'],
    [{ CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: 'yes' }, 'does not match this host'],
    [{ CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase('other-host') }, 'does not match this host'],
    [{ NODE_ENV: 'test' }, 'test environment'],
    [{ JEST_WORKER_ID: '1' }, 'test environment'],
    [{ CONTAINMENT_DRY_RUN: 'true' }, 'CONTAINMENT_DRY_RUN'],
  ])('%j refuses (%s)', (override, reason) => {
    const d = realEnforcementDecision(realEnv(override), HOST)
    expect(d.allowed).toBe(false)
    expect(d.reasons.join(' ')).toContain(reason)
  })

  test('the Windows backend needs its own flag plus the same host-bound confirmation', () => {
    const env = { CONTAINMENT_BACKEND: 'windows-firewall', ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'true' }
    expect(realEnforcementDecision(env, HOST).allowed).toBe(false)
    expect(realEnforcementDecision({ ...env, CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase(HOST) }, HOST).allowed).toBe(true)
  })

  test('the factory never returns a real adapter during tests, whatever the configuration', () => {
    const saved = { ...process.env }
    Object.assign(process.env, realEnv(), { CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase() })
    try {
      factory.resetContainmentAdapter()
      expect(factory.getContainmentAdapter({ forceNew: true })).toBeInstanceOf(MockContainmentAdapter)
      expect(factory.describeEnforcement()).toMatchObject({ hostFirewall: 'simulated', backend: 'mock', cowrieDenylist: 'cowrie_denylist' })
    } finally {
      process.env = saved
      factory.resetContainmentAdapter()
    }
  })
})

/** Records argv; `exists` decides what `iptables -C` answers. */
function fakeRunner({ exists = () => false, failOn = null } = {}) {
  const calls = []
  const run = async (argv) => {
    calls.push(argv)
    const op = argv.find((a) => ['-C', '-I', '-D'].includes(a))
    if (failOn === op) throw Object.assign(new Error('iptables failed'), { code: 4, stderr: 'iptables: Permission denied' })
    if (op === '-C' && !exists(calls)) throw Object.assign(new Error('no rule'), { code: 1, stderr: 'iptables: Bad rule (does a matching rule exist in that chain?).' })
    return { stdout: '', stderr: '' }
  }
  return { run, calls }
}

describe('LinuxIptablesAdapter (mocked execution, NODE_ENV temporarily not "test")', () => {
  let savedEnv
  beforeEach(() => {
    savedEnv = process.env.NODE_ENV
    process.env.NODE_ENV = 'development' // the adapter itself also refuses under NODE_ENV=test
  })
  afterEach(() => {
    process.env.NODE_ENV = savedEnv
  })

  const adapter = (r, opts = {}) => new LinuxIptablesAdapter({ enabled: true, run: r.run, prefix: ['wsl', '-d', 'Ubuntu', '--', 'sudo', '-n'], ...opts })

  test('apply checks first, then inserts a tagged DROP rule through the configured prefix, without a shell', async () => {
    const r = fakeRunner()
    const res = await adapter(r).applyRule({ containmentId: 'abc-1', target: '203.0.113.5' })
    expect(res).toMatchObject({ success: true, ruleName: 'SentinelAI-Rule-abc-1' })
    expect(r.calls[0]).toEqual(['wsl', '-d', 'Ubuntu', '--', 'sudo', '-n', 'iptables', '-w', '-C', 'INPUT', '-s', '203.0.113.5',
      '-m', 'comment', '--comment', 'SentinelAI-Rule-abc-1', '-j', 'DROP'])
    expect(r.calls[1]).toContain('-I')
  })

  test('duplicate prevention: an existing identical rule is not inserted again', async () => {
    const r = fakeRunner({ exists: () => true })
    const res = await adapter(r).applyRule({ containmentId: 'abc-2', target: '203.0.113.6' })
    expect(res.details.alreadyPresent).toBe(true)
    expect(r.calls.filter((a) => a.includes('-I'))).toHaveLength(0)
  })

  test('IPv6 targets use ip6tables', async () => {
    const r = fakeRunner()
    await adapter(r).applyRule({ containmentId: 'v6', target: '2001:db8::5' })
    expect(r.calls[1]).toContain('ip6tables')
  })

  test.each(['203.0.113.5; rm -rf /', '999.1.1.1', '1.2.3.4/40', '', '$(id)'])('invalid target %p is refused before any command', async (t) => {
    const r = fakeRunner()
    await expect(adapter(r).applyRule({ containmentId: 'x', target: t })).rejects.toThrow(/Invalid target/)
    expect(r.calls).toHaveLength(0)
  })

  test('foreign rule names are refused (only SentinelAI-tagged rules are touched)', async () => {
    const r = fakeRunner()
    await expect(adapter(r).removeRule({ containmentId: 'x', target: '203.0.113.5', ruleName: 'ssh-allow' })).rejects.toThrow(/unauthorized rule name/)
  })

  test('a failing insert is reported as a failure with stderr', async () => {
    const r = fakeRunner({ failOn: '-I' })
    const res = await adapter(r).applyRule({ containmentId: 'f', target: '203.0.113.7' })
    expect(res.success).toBe(false)
    expect(res.stderr).toMatch(/Permission denied/)
  })

  test('verify, remove and inspect', async () => {
    let present = true
    const r = fakeRunner({ exists: () => present })
    const a = adapter(r)
    expect(await a.verifyRule({ containmentId: 'v', target: '203.0.113.8' })).toMatchObject({ exists: true, active: true })
    expect((await a.inspectRule({ containmentId: 'v', target: '203.0.113.8' })).state).toBe('PRESENT')
    await a.removeRule({ containmentId: 'v', target: '203.0.113.8' })
    expect(r.calls.at(-1)).toContain('-D')
    present = false
    expect((await a.inspectRule({ containmentId: 'v', target: '203.0.113.8' })).state).toBe('ABSENT')
    const res = await a.removeRule({ containmentId: 'v', target: '203.0.113.8' })
    expect(res).toMatchObject({ success: true, details: { alreadyAbsent: true } })
  })

  test('disabled unless explicitly enabled, and always under NODE_ENV=test', async () => {
    const r = fakeRunner()
    await expect(new LinuxIptablesAdapter({ run: r.run }).applyRule({ containmentId: 'd', target: '203.0.113.9' })).rejects.toThrow(/disabled/)
    process.env.NODE_ENV = 'test'
    await expect(adapter(r).applyRule({ containmentId: 'd', target: '203.0.113.9' })).rejects.toThrow(/disabled/)
    expect(r.calls).toHaveLength(0)
  })

  test('the command prefix must be a JSON array of simple words', () => {
    expect(LinuxIptablesAdapter.parsePrefix('["wsl","-d","Ubuntu","--","sudo","-n"]')).toHaveLength(6)
    expect(() => LinuxIptablesAdapter.parsePrefix('["sh","-c","x; y"]')).toThrow()
    expect(() => LinuxIptablesAdapter.parsePrefix('wsl sudo')).toThrow()
  })

  test('both real adapters ask for post-apply verification', () => {
    expect(new LinuxIptablesAdapter({ enabled: false }).requiresPostApplyVerification).toBe(true)
    expect(new WindowsFirewallAdapter({ enabled: false }).requiresPostApplyVerification).toBe(true)
  })
})

describe('containment service: post-apply verification (in-memory DB)', () => {
  const ContainmentAction = require('../models/ContainmentAction')
  const containment = require('../services/containmentService')
  const ADMIN = { id: new mongoose.Types.ObjectId().toString(), name: 'Admin', role: 'admin', status: 'active' }
  let mongo

  /** A "real" adapter double: the apply command succeeds, but the rule exists only if `creates` is true. */
  class Unverifiable extends MockContainmentAdapter {
    constructor(creates) {
      super()
      this.creates = creates
      this.removed = []
    }
    get requiresPostApplyVerification() {
      return true
    }
    async verifyRule() {
      return { exists: this.creates, active: this.creates }
    }
    async removeRule(p) {
      this.removed.push(p.ruleName)
      return super.removeRule(p)
    }
  }

  beforeAll(async () => {
    mongo = await MongoMemoryServer.create()
    await mongoose.connect(mongo.getUri())
    await ContainmentAction.init()
  })
  afterAll(async () => {
    factory.resetContainmentAdapter()
    await mongoose.disconnect()
    await mongo.stop()
  })
  afterEach(async () => {
    factory.resetContainmentAdapter()
    await ContainmentAction.deleteMany({})
  })

  test('a rule missing after a "successful" apply fails the action and is cleaned up', async () => {
    const a = new Unverifiable(false)
    factory.setContainmentAdapter(a)
    await expect(
      containment.requestContainment({ target: '198.51.100.60', requester: ADMIN, reason: 'verify', emitEvents: false })
    ).rejects.toThrow(/ENFORCEMENT_NOT_VERIFIED/)
    const doc = await ContainmentAction.findOne({ normalizedTarget: '198.51.100.60' }).lean()
    expect(doc.enforcementStatus).toBe('FAILED')
    expect(doc.failureReason).toMatch(/ENFORCEMENT_NOT_VERIFIED/)
    expect(a.removed).toHaveLength(1)
  })

  test('a verified rule becomes ACTIVE', async () => {
    factory.setContainmentAdapter(new Unverifiable(true))
    const res = await containment.requestContainment({ target: '198.51.100.61', requester: ADMIN, reason: 'verify', emitEvents: false })
    expect(res.action.enforcementStatus).toBe('ACTIVE')
  })

  test('the mock adapter is not re-verified (simulated enforcement path unchanged)', async () => {
    const m = new MockContainmentAdapter()
    const spy = jest.spyOn(m, 'verifyRule')
    factory.setContainmentAdapter(m)
    await containment.requestContainment({ target: '198.51.100.62', requester: ADMIN, reason: 'mock', emitEvents: false })
    expect(spy).not.toHaveBeenCalled()
  })
})
