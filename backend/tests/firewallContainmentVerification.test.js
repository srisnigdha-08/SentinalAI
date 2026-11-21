'use strict'
/**
 * Host-firewall containment, verified with MOCKED command execution only (docs/CONTAINMENT_ENFORCEMENT.md,
 * "How it is verified").
 *
 * child_process.execFile is replaced for this whole file by a recorder that refuses to run anything, so even an
 * adapter built without an injected runner cannot start netsh, iptables, ip6tables, nft or wsl. The real
 * WindowsFirewallAdapter and LinuxIptablesAdapter classes run against in-memory fake firewalls that answer the way
 * netsh / iptables do (including their failure messages), through the real containment service, the real
 * ContainmentAction state machine and an in-memory MongoDB. No real firewall rule is ever created, changed or removed.
 */
const recordedExecFile = []
const everyExecFileCall = [] // never reset: checked once at the end of the file
jest.mock('child_process', () => {
  const actual = jest.requireActual('child_process')
  return {
    ...actual,
    execFile: jest.fn((file, args, opts, cb) => {
      recordedExecFile.push({ file, args, opts })
      everyExecFileCall.push(file)
      const err = Object.assign(new Error('BLOCKED: no real command may run in tests'), { code: 'EBLOCKED' })
      if (typeof cb === 'function') return cb(err, '', '')
      throw err
    }),
  }
})
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }))
jest.mock('../websocket/socketManager', () => ({
  emitIPBlocked: jest.fn(),
  emitIPUnblocked: jest.fn(),
  emitNewAlert: jest.fn(),
  emitNewThreat: jest.fn(),
  emitThreatUpdated: jest.fn(),
  emitContainmentUpdate: jest.fn(),
  emitToRoom: jest.fn(),
}))
const audit = []
jest.mock('../utils/containmentAudit', () => {
  const actual = jest.requireActual('../utils/containmentAudit')
  return { ...actual, logContainmentAudit: jest.fn((e) => audit.push(e)) }
})

const mongoose = require('mongoose')
const { MongoMemoryServer } = require('mongodb-memory-server')
const WindowsFirewallAdapter = require('../services/containment/WindowsFirewallAdapter')
const LinuxIptablesAdapter = require('../services/containment/LinuxIptablesAdapter')
const MockContainmentAdapter = require('../services/containment/MockContainmentAdapter')
const factory = require('../services/containment/adapterFactory')
const { confirmationPhrase, realEnforcementDecision } = require('../services/containment/enforcementSafety')

const ADMIN = { id: new mongoose.Types.ObjectId().toString(), name: 'Admin', role: 'admin', status: 'active' }
const ANALYST = { id: new mongoose.Types.ObjectId().toString(), name: 'Analyst', role: 'analyst', status: 'active' }
const VIEWER = { id: new mongoose.Types.ObjectId().toString(), name: 'Viewer', role: 'viewer', status: 'active' }
const SHELL_META = /[;&|`$<>\n\r"'\\]/

// ── fake firewalls ────────────────────────────────────────────────────────────────────────────────────────────────
/** netsh advfirewall stand-in. Rules: name -> { remoteip, dir, action, enabled }. Failure modes are opt-in. */
function fakeNetsh(mode = {}) {
  const rules = new Map()
  const calls = []
  const noMatch = () =>
    Object.assign(new Error('Command failed: netsh'), {
      code: 1,
      stdout: '\r\nNo rules match the specified criteria.\r\n',
      stderr: '',
    })
  const kv = (args, key) => (args.find((a) => a.startsWith(`${key}=`)) || '').slice(key.length + 1)
  const run = async (args) => {
    calls.push(args)
    const verb = args[2]
    const name = kv(args, 'name')
    if (verb === 'add') {
      if (mode.addFails)
        throw Object.assign(new Error('access denied'), {
          code: 1,
          stderr: 'The requested operation requires elevation (Run as administrator).',
        })
      if (mode.addMissingBinary) throw Object.assign(new Error('spawn netsh ENOENT'), { code: 'ENOENT' })
      if (!mode.addNoop)
        rules.set(name, {
          remoteip: mode.wrongRemote || kv(args, 'remoteip'),
          dir: 'In',
          action: mode.allowAction ? 'Allow' : 'Block',
          enabled: 'Yes',
        })
      if (mode.addTimesOutAfterCreate)
        throw Object.assign(new Error('netsh timed out'), { code: 'ETIMEDOUT', killed: true })
      return { stdout: 'Ok.\r\n', stderr: '' }
    }
    if (verb === 'delete') {
      if (mode.deleteFails) throw Object.assign(new Error('access denied'), { code: 1, stderr: 'Access is denied.' })
      if (!rules.has(name)) throw noMatch()
      if (!mode.deleteNoop) rules.delete(name)
      return { stdout: '\r\nDeleted 1 rule(s).\r\nOk.\r\n', stderr: '' }
    }
    if (verb === 'show') {
      if (mode.showFails)
        throw Object.assign(new Error('rpc unavailable'), { code: 1, stderr: 'The RPC server is unavailable.' })
      const r = rules.get(name)
      if (!r) throw noMatch()
      return {
        stdout:
          `\r\nRule Name:                            ${name}\r\n` +
          '----------------------------------------------------------------------\r\n' +
          `Enabled:                              ${r.enabled}\r\nDirection:                            ${r.dir}\r\n` +
          'Profiles:                             Domain,Private,Public\r\n' +
          `RemoteIP:                             ${r.remoteip}/32\r\nProtocol:                             Any\r\n` +
          `Action:                               ${r.action}\r\nOk.\r\n`,
        stderr: '',
      }
    }
    throw new Error(`unexpected netsh verb ${verb}`)
  }
  return { run, rules, calls, mode }
}

/** iptables / ip6tables stand-in. Rules keyed by tool|source|comment. */
function fakeIptables(mode = {}) {
  const rules = new Set()
  const calls = []
  const run = async (argv) => {
    calls.push(argv)
    const tool = argv.find((a) => a === 'iptables' || a === 'ip6tables')
    const op = argv.find((a) => ['-C', '-I', '-D'].includes(a))
    const key = `${tool}|${argv[argv.indexOf('-s') + 1]}|${argv[argv.indexOf('--comment') + 1]}`
    const absent = () =>
      Object.assign(new Error('no rule'), {
        code: 1,
        stderr: 'iptables: Bad rule (does a matching rule exist in that chain?).',
      })
    if (op === '-C') {
      if (mode.checkFails) throw Object.assign(new Error('sudo'), { code: 1, stderr: 'sudo: a password is required' })
      if (!rules.has(key)) throw absent()
      return { stdout: '', stderr: '' }
    }
    if (op === '-I') {
      if (mode.insertFails)
        throw Object.assign(new Error('perm'), {
          code: 4,
          stderr: 'iptables v1.8.7 (nf_tables): Could not fetch rule set generation id: Permission denied',
        })
      if (!mode.insertNoop) rules.add(key)
      if (mode.insertCreatesThenFails) throw Object.assign(new Error('killed'), { code: 'ETIMEDOUT', stderr: '' })
      return { stdout: '', stderr: '' }
    }
    if (op === '-D') {
      if (mode.deleteFails)
        throw Object.assign(new Error('perm'), { code: 4, stderr: 'iptables: Permission denied (you must be root).' })
      if (!rules.has(key)) throw absent()
      if (!mode.deleteNoop) rules.delete(key)
      return { stdout: '', stderr: '' }
    }
    throw new Error(`unexpected iptables op ${op}`)
  }
  return { run, rules, calls, mode }
}

const windows = (fw, enabled = true) => new WindowsFirewallAdapter({ enabled, runNetsh: fw.run })
const linux = (fw, enabled = true) =>
  new LinuxIptablesAdapter({ enabled, run: fw.run, prefix: ['wsl', '-d', 'Ubuntu', '--', 'sudo', '-n'] })

// The adapters also refuse under NODE_ENV=test; the gate's enabled branch is exercised with it set to development
// for the duration of each test (the fake runners and the execFile recorder still stand in for every command).
let savedNodeEnv
beforeEach(() => {
  savedNodeEnv = process.env.NODE_ENV
  process.env.NODE_ENV = 'development'
  audit.length = 0
  recordedExecFile.length = 0
})
afterEach(() => {
  process.env.NODE_ENV = savedNodeEnv
  factory.resetContainmentAdapter()
})
afterAll(() => {
  // The only execFile calls in this whole file are the three deliberate default-runner probes (one netsh, two wsl),
  // and the recorder refused each of them: no process was started.
  expect(everyExecFileCall).toHaveLength(3)
})

// ── 1. command construction, executable allowlisting, argument safety ────────────────────────────────────────────
describe('command construction and argument safety (no command runs)', () => {
  test('Windows: every argument is its own array element; only netsh advfirewall verbs are used', async () => {
    const fw = fakeNetsh()
    const a = windows(fw)
    await a.applyRule({ containmentId: 'c-1', target: '203.0.113.10' })
    await a.verifyRule({ containmentId: 'c-1', target: '203.0.113.10' })
    await a.removeRule({ containmentId: 'c-1', target: '203.0.113.10' })
    expect(fw.calls.map((c) => c.slice(0, 4).join(' '))).toEqual([
      'advfirewall firewall add rule',
      'advfirewall firewall show rule',
      'advfirewall firewall delete rule',
    ])
    expect(fw.calls[0]).toEqual([
      'advfirewall',
      'firewall',
      'add',
      'rule',
      'name=SentinelAI-Rule-c-1',
      'dir=in',
      'action=block',
      'remoteip=203.0.113.10',
      'description=SentinelAI Automated Containment c-1',
    ])
    for (const args of fw.calls) for (const arg of args.slice(0, 5)) expect(arg).not.toMatch(SHELL_META)
  })

  test('Linux: allowlisted programs only, prefix first, target and tag as separate arguments', async () => {
    const fw = fakeIptables()
    await linux(fw).applyRule({ containmentId: 'c-2', target: '203.0.113.11' })
    for (const argv of fw.calls) {
      expect(argv.slice(0, 6)).toEqual(['wsl', '-d', 'Ubuntu', '--', 'sudo', '-n'])
      expect(argv.slice(6)).toEqual(
        expect.arrayContaining(['-s', '203.0.113.11', '--comment', 'SentinelAI-Rule-c-2', '-j', 'DROP'])
      )
      for (const arg of argv) expect(arg).not.toMatch(SHELL_META)
    }
    for (const bad of ['sh', 'bash', 'cmd.exe', 'powershell', 'nft', 'netsh', '/usr/sbin/iptables', 'iptables;id'])
      expect(() => LinuxIptablesAdapter.resolveExecutable(bad)).toThrow(/not allowed/)
  })

  test.each([
    '203.0.113.5; netsh advfirewall reset',
    '203.0.113.5 & calc',
    '$(whoami)',
    '`id`',
    '203.0.113.5\nremoteip=any',
    '999.1.1.1',
    '1.2.3.4/33',
    '::/200',
    'any',
    '',
    null,
  ])('target %p is refused by both adapters before any command', async (target) => {
    const n = fakeNetsh()
    const l = fakeIptables()
    await expect(windows(n).applyRule({ containmentId: 'x', target })).rejects.toThrow(/Invalid target/)
    await expect(linux(l).applyRule({ containmentId: 'x', target })).rejects.toThrow(/Invalid target/)
    expect(n.calls).toHaveLength(0)
    expect(l.calls).toHaveLength(0)
  })

  test.each([
    'allow-ssh',
    'SentinelAI-Rule-',
    'SentinelAI-Rule-x name=all',
    'SentinelAI-Rule-x;y',
    'SentinelAI-Rule-'.padEnd(100, 'a'),
  ])('foreign or malformed rule name %p is refused for remove and verify', async (ruleName) => {
    const n = fakeNetsh()
    const l = fakeIptables()
    await expect(windows(n).removeRule({ containmentId: 'x', ruleName })).rejects.toThrow(/rule name/)
    await expect(linux(l).removeRule({ containmentId: 'x', target: '203.0.113.5', ruleName })).rejects.toThrow(
      /rule name/
    )
    expect(n.calls).toHaveLength(0)
    expect(l.calls).toHaveLength(0)
  })

  test('hostile containment ids are stripped to [A-Za-z0-9-] before they reach an argument', async () => {
    const fw = fakeNetsh()
    await windows(fw).applyRule({ containmentId: 'ab"; netsh advfirewall reset; "', target: '203.0.113.12' })
    expect(fw.calls[0]).toContain('name=SentinelAI-Rule-abnetshadvfirewallreset')
    expect(fw.calls[0].join(' ')).not.toMatch(/[;"]/)
  })

  test('default runners go through execFile (no shell) with absolute Windows system paths', async () => {
    const w = new WindowsFirewallAdapter({ enabled: true })
    const r = await w.applyRule({ containmentId: 'exec-1', target: '203.0.113.13' })
    expect(r.success).toBe(false) // the recorder refused: nothing ran
    expect(r.exitCode).toBe(1) // a string process code is never passed on as the exit code
    expect(recordedExecFile).toHaveLength(1)
    expect(recordedExecFile[0].file).toBe(WindowsFirewallAdapter.netshPath())
    expect(Array.isArray(recordedExecFile[0].args)).toBe(true)
    expect(recordedExecFile[0].opts.shell).toBeUndefined()

    const l = new LinuxIptablesAdapter({ enabled: true, prefix: ['wsl', '-d', 'Ubuntu', '--', 'sudo', '-n'] })
    await l.applyRule({ containmentId: 'exec-2', target: '203.0.113.14' })
    const linuxCall = recordedExecFile[1]
    expect(linuxCall.file).toBe(LinuxIptablesAdapter.executablePath('wsl'))
    expect(linuxCall.opts.shell).toBeUndefined()
  })

  test('netsh and wsl resolve to System32 on Windows; a hostile SystemRoot falls back to C:\\Windows', () => {
    const { netshPath } = WindowsFirewallAdapter
    const { executablePath } = LinuxIptablesAdapter
    expect(netshPath({ SystemRoot: 'C:\\Windows' }, 'win32')).toBe('C:\\Windows\\System32\\netsh.exe')
    expect(netshPath({ SystemRoot: 'D:\\WINNT' }, 'win32')).toBe('D:\\WINNT\\System32\\netsh.exe')
    for (const hostile of ['C:\\x";calc', '\\\\evil\\share', '..\\..\\tmp', 'C:\\Windows & calc', undefined])
      expect(netshPath({ SystemRoot: hostile }, 'win32')).toBe('C:\\Windows\\System32\\netsh.exe')
    expect(executablePath('wsl', { SystemRoot: 'C:\\Windows' }, 'win32')).toBe('C:\\Windows\\System32\\wsl.exe')
    expect(executablePath('iptables', {}, 'linux')).toBe('iptables')
    expect(() => executablePath('sh', {}, 'linux')).toThrow(/not allowed/)
    expect(netshPath({}, 'linux')).toBe('netsh')
  })
})

// ── 2. gates: disabled by default, host-bound confirmation, mock default ─────────────────────────────────────────
describe('safety gates', () => {
  test('adapters are disabled unless explicitly enabled, and always under NODE_ENV=test or CONTAINMENT_DRY_RUN', async () => {
    const n = fakeNetsh()
    const l = fakeIptables()
    for (const adapter of [new LinuxIptablesAdapter({ run: l.run }), windows(n, false)])
      await expect(adapter.applyRule({ containmentId: 'g', target: '203.0.113.20' })).rejects.toMatchObject({
        code: 'FIREWALL_ENFORCEMENT_DISABLED',
      })
    for (const env of [{ NODE_ENV: 'test' }, { CONTAINMENT_DRY_RUN: 'true' }]) {
      const saved = { ...process.env }
      Object.assign(process.env, env)
      try {
        await expect(windows(n).applyRule({ containmentId: 'g', target: '203.0.113.20' })).rejects.toThrow(/disabled/)
        await expect(linux(l).applyRule({ containmentId: 'g', target: '203.0.113.20' })).rejects.toThrow(/disabled/)
        await expect(windows(n).removeRule({ containmentId: 'g' })).rejects.toThrow(/disabled/)
        await expect(linux(l).verifyRule({ containmentId: 'g', target: '203.0.113.20' })).rejects.toThrow(/disabled/)
      } finally {
        process.env = saved
      }
    }
    expect(n.calls).toHaveLength(0)
    expect(l.calls).toHaveLength(0)
  })

  test("the factory selects a real adapter only with backend + flag + this host's confirmation, outside tests", () => {
    const saved = { ...process.env }
    const base = {
      CONTAINMENT_BACKEND: 'windows-firewall',
      ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: 'true',
      CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase(),
    }
    const pick = (env) => {
      process.env = { ...saved }
      for (const k of ['JEST_WORKER_ID', 'NODE_ENV', 'CONTAINMENT_DRY_RUN']) delete process.env[k]
      for (const [k, v] of Object.entries(env))
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      factory.resetContainmentAdapter()
      return factory.getContainmentAdapter({ forceNew: true })
    }
    try {
      // Every incomplete or wrong configuration falls back to the mock (simulated) adapter
      expect(pick({})).toBeInstanceOf(MockContainmentAdapter)
      expect(pick({ ...base, CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: undefined })).toBeInstanceOf(MockContainmentAdapter)
      expect(
        pick({ ...base, CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: 'I-AUTHORIZE-FIREWALL-CHANGES-ON-other-host' })
      ).toBeInstanceOf(MockContainmentAdapter)
      expect(
        pick({ ...base, CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase().toLowerCase() })
      ).toBeInstanceOf(MockContainmentAdapter)
      expect(pick({ ...base, ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: '1' })).toBeInstanceOf(MockContainmentAdapter)
      expect(
        pick({
          ...base,
          ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT: 'true',
          ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT: undefined,
        })
      ).toBeInstanceOf(MockContainmentAdapter)
      expect(pick({ ...base, CONTAINMENT_BACKEND: 'Windows-Firewall' })).toBeInstanceOf(MockContainmentAdapter)
      expect(pick({ ...base, CONTAINMENT_BACKEND: 'nft' })).toBeInstanceOf(MockContainmentAdapter)
      expect(pick({ ...base, CONTAINMENT_DRY_RUN: 'true' })).toBeInstanceOf(MockContainmentAdapter)
      // Only the complete set selects the real class. It is constructed, never used: no method is called here.
      expect(pick(base)).toBeInstanceOf(WindowsFirewallAdapter)
      expect(recordedExecFile).toHaveLength(0)
    } finally {
      process.env = saved
      factory.resetContainmentAdapter()
    }
  })

  test('inside Jest the factory always returns the mock, whatever is configured', () => {
    const saved = { ...process.env }
    try {
      Object.assign(process.env, {
        CONTAINMENT_BACKEND: 'linux-iptables',
        ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT: 'true',
        CONTAINMENT_REAL_ENFORCEMENT_CONFIRM: confirmationPhrase(),
      })
      factory.resetContainmentAdapter()
      expect(factory.getContainmentAdapter({ forceNew: true })).toBeInstanceOf(MockContainmentAdapter)
      expect(realEnforcementDecision(process.env).reasons).toContain('test environment')
      expect(factory.describeEnforcement()).toMatchObject({ hostFirewall: 'simulated', backend: 'mock' })
    } finally {
      process.env = saved
      factory.resetContainmentAdapter()
    }
  })
})

// ── 3. lifecycle through the real containment service (in-memory MongoDB) ────────────────────────────────────────
describe('containment lifecycle with mocked firewalls', () => {
  const ContainmentAction = require('../models/ContainmentAction')
  const containment = require('../services/containmentService')
  const { ContainmentReconciliationService } = require('../services/containmentReconciliationService')
  let mongo

  beforeAll(async () => {
    mongo = await MongoMemoryServer.create()
    await mongoose.connect(mongo.getUri())
    await ContainmentAction.init()
  })
  afterAll(async () => {
    await mongoose.disconnect()
    await mongo.stop()
  })
  afterEach(async () => {
    await Promise.all(['ContainmentAction', 'BlockedIP', 'ThreatLog'].map((m) => mongoose.models[m]?.deleteMany({})))
  })

  const request = (target, requester = ADMIN, extra = {}) =>
    containment.requestContainment({ target, requester, reason: 'lifecycle test', emitEvents: false, ...extra })
  const load = (target) => ContainmentAction.findOne({ normalizedTarget: target }).lean()
  const actions = () => audit.map((e) => e.action)

  const BACKENDS = [
    ['windows-firewall', fakeNetsh, windows, (fw) => fw.rules.size],
    ['linux-iptables', fakeIptables, linux, (fw) => fw.rules.size],
  ]

  describe.each(BACKENDS)('%s', (backend, makeFw, makeAdapter, ruleCount) => {
    const use = (mode) => {
      const fw = makeFw(mode)
      factory.setContainmentAdapter(makeAdapter(fw))
      return fw
    }

    test('valid request: REQUESTED -> VALIDATING -> APPROVED -> APPLYING -> verified -> ACTIVE, audited', async () => {
      const fw = use()
      const res = await request('203.0.113.30')
      expect(res.action.enforcementStatus).toBe('ACTIVE')
      const doc = await load('203.0.113.30')
      expect(doc).toMatchObject({ enforcementStatus: 'ACTIVE', enforcementBackend: backend, failureReason: null })
      expect(doc.enforcementDetails.ruleName).toBe(`SentinelAI-Rule-${doc.containmentId}`)
      expect(ruleCount(fw)).toBe(1)
      expect(actions()).toEqual(['CONTAINMENT_REQUESTED', 'ENFORCEMENT_VERIFIED', 'CONTAINMENT_ACTIVE'])
      expect(audit.every((e) => e.containmentId === doc.containmentId)).toBe(true)
      expect(audit[0]).toMatchObject({ enforcementBackend: backend, operatorRole: 'admin', target: '203.0.113.30' })
    })

    test('invalid IP is refused by policy before the adapter; nothing runs', async () => {
      const fw = use()
      await expect(request('not-an-ip')).rejects.toMatchObject({ statusCode: 403 })
      await expect(request('203.0.113.999')).rejects.toMatchObject({ statusCode: 403 })
      expect(fw.calls).toHaveLength(0)
      expect(actions()).toContain('CONTAINMENT_REJECTED')
      expect(actions()).not.toContain('CONTAINMENT_ACTIVE')
    })

    test('missing or insufficient authorization never reaches apply', async () => {
      const fw = use()
      await expect(request('203.0.113.31', null)).rejects.toMatchObject({ statusCode: 403 })
      await expect(request('203.0.113.32', VIEWER)).rejects.toMatchObject({ statusCode: 403 })
      await expect(request('203.0.113.33', { ...ANALYST, status: 'disabled' })).rejects.toMatchObject({
        statusCode: 403,
      })
      await expect(request('203.0.113.34', { ...ANALYST, mustChangePassword: true })).rejects.toMatchObject({
        statusCode: 403,
      })
      await expect(request('198.51.100.0/24', ANALYST)).rejects.toMatchObject({ statusCode: 403 }) // CIDR: admin only
      expect(fw.calls).toHaveLength(0)
      const docs = await ContainmentAction.find({}).lean()
      expect(docs.every((d) => d.enforcementStatus === 'REJECTED')).toBe(true)
    })

    test('protected targets (loopback) are refused before the adapter', async () => {
      const fw = use()
      await expect(request('127.0.0.1')).rejects.toMatchObject({ statusCode: 403 })
      expect(fw.calls).toHaveLength(0)
    })

    test('gate closed: the adapter refuses, nothing is applied, cleanup is not attempted, FAILED is recorded', async () => {
      const fw = makeFw()
      factory.setContainmentAdapter(makeAdapter(fw, false))
      await expect(request('203.0.113.35')).rejects.toMatchObject({ statusCode: 502 })
      expect(fw.calls).toHaveLength(0)
      const doc = await load('203.0.113.35')
      expect(doc.enforcementStatus).toBe('FAILED')
      expect(doc.failureReason).toMatch(/disabled by safety gate/)
      expect(doc.recovery.lateRule).toBeNull()
      expect(audit.find((e) => e.action === 'ENFORCEMENT_FAILED').details.cleanup).toBe('NOT_APPLIED')
    })

    test('apply command failure: FAILED with the error, inspected, no rule left', async () => {
      const fw = use(backend === 'windows-firewall' ? { addFails: true } : { insertFails: true })
      await expect(request('203.0.113.36')).rejects.toMatchObject({ statusCode: 502 })
      const doc = await load('203.0.113.36')
      expect(doc.enforcementStatus).toBe('FAILED')
      expect(doc.failureReason).toMatch(/elevation|Permission denied/)
      expect(doc.failureReason).toMatch(/CLEANUP: no rule was left behind/)
      expect(typeof doc.enforcementDetails.exitCode).toBe('number')
      expect(ruleCount(fw)).toBe(0)
      expect(actions()).toEqual(['CONTAINMENT_REQUESTED', 'FAILED_APPLY_CLEANUP', 'ENFORCEMENT_FAILED'])
      expect(audit[1].details.outcome).toBe('NOT_PRESENT')
    })

    test('post-apply verification failure: the command "succeeded" but no rule exists -> FAILED, never ACTIVE', async () => {
      const fw = use(backend === 'windows-firewall' ? { addNoop: true } : { insertNoop: true })
      await expect(request('203.0.113.37')).rejects.toThrow(/ENFORCEMENT_NOT_VERIFIED/)
      const doc = await load('203.0.113.37')
      expect(doc.enforcementStatus).toBe('FAILED')
      expect(doc.appliedAt).toBeNull()
      expect(actions()).toEqual([
        'CONTAINMENT_REQUESTED',
        'ENFORCEMENT_NOT_VERIFIED',
        'FAILED_APPLY_CLEANUP',
        'ENFORCEMENT_FAILED',
      ])
      expect(ruleCount(fw)).toBe(0)
    })

    test('partial application: the rule was created, then the command failed -> removed and confirmed', async () => {
      const fw = use(
        backend === 'windows-firewall' ? { addTimesOutAfterCreate: true } : { insertCreatesThenFails: true }
      )
      await expect(request('203.0.113.38')).rejects.toMatchObject({ statusCode: 502 })
      const doc = await load('203.0.113.38')
      expect(doc.enforcementStatus).toBe('FAILED')
      expect(doc.failureReason).toMatch(/CLEANUP: the partially applied rule was removed and confirmed absent/)
      expect(doc.recovery.lateRule).toBeNull()
      expect(ruleCount(fw)).toBe(0)
      expect(audit.find((e) => e.action === 'FAILED_APPLY_CLEANUP').details).toMatchObject({
        outcome: 'REMOVED',
        before: 'PRESENT',
        after: 'ABSENT',
        removal: 'SUCCEEDED',
      })
    })

    test('cleanup that fails is reported as unconfirmed, flagged, and finished later by reconciliation', async () => {
      const fw = use(
        backend === 'windows-firewall'
          ? { addTimesOutAfterCreate: true, deleteFails: true }
          : { insertCreatesThenFails: true, deleteFails: true }
      )
      await expect(request('203.0.113.39')).rejects.toMatchObject({ statusCode: 502 })
      let doc = await load('203.0.113.39')
      expect(doc.enforcementStatus).toBe('FAILED') // never ACTIVE, and never reported as cleaned
      expect(doc.failureReason).toMatch(/CLEANUP_UNCONFIRMED/)
      expect(doc.recovery.lateRule).toBe('PRESENT_UNREMOVED')
      expect(ruleCount(fw)).toBe(1)
      expect(actions()).toContain('FAILED_APPLY_CLEANUP_UNCONFIRMED')
      expect(actions()).not.toContain('FAILED_APPLY_CLEANUP')

      // The operator recovery view lists it as needing investigation
      const svc = new ContainmentReconciliationService()
      const report = await svc.getRecoveryReport()
      expect(report.items.find((i) => i.target === '203.0.113.39')).toMatchObject({
        lateRule: 'PRESENT_UNREMOVED',
        needsInvestigation: true,
      })
      // Once removal works again, the existing late-rule pass removes it and confirms it is gone
      fw.mode.deleteFails = false
      expect(await svc.removeLateRules()).toMatchObject({ processed: 1, removed: 1 })
      doc = await load('203.0.113.39')
      expect(doc.recovery.lateRule).toBe('REMOVED')
      expect(ruleCount(fw)).toBe(0)
    })

    test('explicit release removes the rule and confirms it; a second release is refused', async () => {
      const fw = use()
      const { action } = await request('203.0.113.40')
      audit.length = 0
      const res = await containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      expect(res.action.enforcementStatus).toBe('ROLLED_BACK')
      expect(ruleCount(fw)).toBe(0)
      expect(actions()).toEqual(['ROLLBACK_INITIATED', 'CONTAINMENT_ROLLED_BACK'])
      await expect(
        containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      ).rejects.toMatchObject({ statusCode: 400 })
      expect((await load('203.0.113.40')).enforcementStatus).toBe('ROLLED_BACK')
    })

    test('release of a rule someone already deleted succeeds (already absent), not ROLLBACK_FAILED', async () => {
      const fw = use()
      const { action } = await request('203.0.113.41')
      fw.rules.clear() // removed outside SentinelAI
      const res = await containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      expect(res.action.enforcementStatus).toBe('ROLLED_BACK')
    })

    test('a removal that reports success but leaves the rule is ROLLBACK_FAILED; a retry completes it', async () => {
      const fw = use()
      const { action } = await request('203.0.113.42')
      fw.mode.deleteNoop = true
      await expect(
        containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      ).rejects.toThrow(/RELEASE_NOT_VERIFIED/)
      expect((await load('203.0.113.42')).enforcementStatus).toBe('ROLLBACK_FAILED')
      expect(ruleCount(fw)).toBe(1)
      fw.mode.deleteNoop = false
      const res = await containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      expect(res.action.enforcementStatus).toBe('ROLLED_BACK')
      expect(ruleCount(fw)).toBe(0)
    })

    test('a removal command failure is ROLLBACK_FAILED with a numeric exit code, and the rule is still reported', async () => {
      const fw = use()
      const { action } = await request('203.0.113.43')
      fw.mode.deleteFails = true
      await expect(
        containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      ).rejects.toMatchObject({ statusCode: 502 })
      const doc = await load('203.0.113.43')
      expect(doc.enforcementStatus).toBe('ROLLBACK_FAILED')
      expect(typeof doc.rollbackDetails.exitCode).toBe('number')
      expect(ruleCount(fw)).toBe(1)
      expect((await containment.getContainmentStatus()).failedContainmentCount).toBe(1)
    })

    test('duplicate requests: the active action is returned, no second rule; idempotency keys replay', async () => {
      const fw = use()
      const first = await request('203.0.113.44', ADMIN, { idempotencyKey: `k-${backend}` })
      const callsAfterFirst = fw.calls.length
      const second = await request('203.0.113.44')
      expect(second.alreadyActive).toBe(true)
      expect(String(second.action._id)).toBe(String(first.action._id))
      const third = await request('203.0.113.44', ADMIN, { idempotencyKey: `k-${backend}` })
      expect(third.idempotent).toBe(true)
      expect(fw.calls.length).toBe(callsAfterFirst)
      expect(ruleCount(fw)).toBe(1)
      expect(await ContainmentAction.countDocuments({ normalizedTarget: '203.0.113.44' })).toBe(1)
      expect(actions()).toEqual(expect.arrayContaining(['ALREADY_ACTIVE_HIT', 'IDEMPOTENT_HIT']))
    })

    test('concurrent duplicate requests create one action and one rule', async () => {
      const fw = use()
      const results = await Promise.all([request('203.0.113.45'), request('203.0.113.45'), request('203.0.113.45')])
      expect(results.filter((r) => !r.alreadyActive)).toHaveLength(1)
      expect(ruleCount(fw)).toBe(1)
      expect(await ContainmentAction.countDocuments({ normalizedTarget: '203.0.113.45' })).toBe(1)
    })

    test('invalid durations are refused; an expired action is released by TTL reconciliation and confirmed', async () => {
      const fw = use()
      await expect(request('203.0.113.46', ADMIN, { durationSeconds: -5 })).rejects.toMatchObject({ statusCode: 403 })
      await expect(request('203.0.113.47', ADMIN, { durationSeconds: 'soon' })).rejects.toMatchObject({
        statusCode: 403,
      })
      expect(fw.calls).toHaveLength(0)
      const { action } = await request('203.0.113.48', ADMIN, { durationSeconds: 3600 })
      await ContainmentAction.updateOne({ _id: action._id }, { $set: { expiresAt: new Date(Date.now() - 1000) } })
      const svc = new ContainmentReconciliationService()
      expect(await svc.reconcileExpiredActions()).toMatchObject({ processed: 1, successful: 1 })
      expect((await load('203.0.113.48')).enforcementStatus).toBe('ROLLED_BACK')
      expect(ruleCount(fw)).toBe(0)
    })

    test('an expiry whose removal leaves the rule in place is ROLLBACK_FAILED, not ROLLED_BACK', async () => {
      const fw = use()
      const { action } = await request('203.0.113.49', ADMIN, { durationSeconds: 3600 })
      await ContainmentAction.updateOne({ _id: action._id }, { $set: { expiresAt: new Date(Date.now() - 1000) } })
      fw.mode.deleteNoop = true
      const svc = new ContainmentReconciliationService()
      expect(await svc.reconcileExpiredActions()).toMatchObject({ processed: 1, failed: 1 })
      const doc = await load('203.0.113.49')
      expect(doc.enforcementStatus).toBe('ROLLBACK_FAILED')
      expect(doc.failureReason).toMatch(/RELEASE_NOT_VERIFIED/)
    })

    test('rollback of an unknown or FAILED action is refused', async () => {
      use(backend === 'windows-firewall' ? { addFails: true } : { insertFails: true })
      await expect(containment.rollbackContainment({ containmentId: 'nope', operator: ADMIN })).rejects.toMatchObject({
        statusCode: 404,
      })
      await expect(request('203.0.113.50')).rejects.toBeTruthy()
      const doc = await load('203.0.113.50')
      await expect(
        containment.rollbackContainment({ containmentId: doc.containmentId, operator: ADMIN })
      ).rejects.toMatchObject({ statusCode: 400 })
    })

    test('status reports what is in use', async () => {
      use()
      const s = await containment.getContainmentStatus()
      expect(s).toMatchObject({ backend, realEnforcementEnabled: true, simulated: false })
    })
  })

  describe('backend-specific behaviour', () => {
    test('Windows: a rule that exists but does not block this target fails verification and is removed', async () => {
      for (const mode of [{ wrongRemote: '198.51.100.99' }, { allowAction: true }]) {
        audit.length = 0
        const fw = fakeNetsh(mode)
        factory.setContainmentAdapter(windows(fw))
        const target = mode.allowAction ? '203.0.113.60' : '203.0.113.61'
        await expect(request(target)).rejects.toThrow(/ENFORCEMENT_NOT_VERIFIED/)
        expect((await load(target)).enforcementStatus).toBe('FAILED')
        expect(fw.rules.size).toBe(0)
        expect(audit.find((e) => e.action === 'FAILED_APPLY_CLEANUP').details.outcome).toBe('REMOVED')
      }
    })

    test('Windows: a missing netsh (ENOENT) is a recorded FAILED action, not a crash', async () => {
      const fw = fakeNetsh({ addMissingBinary: true })
      factory.setContainmentAdapter(windows(fw))
      await expect(request('203.0.113.62')).rejects.toMatchObject({ statusCode: 502 })
      const doc = await load('203.0.113.62')
      expect(doc.enforcementStatus).toBe('FAILED')
      expect(doc.enforcementDetails.exitCode).toBe(1)
    })

    test('Windows: a lookup that cannot answer after a failed apply is flagged, never assumed clean', async () => {
      const fw = fakeNetsh({ addFails: true, showFails: true })
      factory.setContainmentAdapter(windows(fw))
      await expect(request('203.0.113.63')).rejects.toBeTruthy()
      const doc = await load('203.0.113.63')
      expect(doc.recovery.lateRule).toBe('PRESENT_UNREMOVED')
      expect(doc.failureReason).toMatch(/CLEANUP_UNCONFIRMED/)
    })

    test('Linux: the enforcement backend is stored (it was missing from the model enum)', async () => {
      factory.setContainmentAdapter(linux(fakeIptables()))
      await request('203.0.113.64')
      expect((await load('203.0.113.64')).enforcementBackend).toBe('linux-iptables')
      expect(ContainmentAction.ENFORCEMENT_BACKENDS).toContain('linux-iptables')
    })

    test('Linux: a presence check that errors (no sudo) is not taken as "already removed"', async () => {
      const fw = fakeIptables()
      factory.setContainmentAdapter(linux(fw))
      const { action } = await request('203.0.113.65')
      fw.mode.checkFails = true
      fw.mode.deleteFails = true
      await expect(
        containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      ).rejects.toMatchObject({ statusCode: 502 })
      expect((await load('203.0.113.65')).enforcementStatus).toBe('ROLLBACK_FAILED')
      expect(fw.rules.size).toBe(1)
      // with the check failing but the delete allowed, the delete runs and decides
      fw.mode.deleteFails = false
      const res = await containment.rollbackContainment({ containmentId: action.containmentId, operator: ADMIN })
      expect(res.action.enforcementStatus).toBe('ROLLED_BACK')
      expect(fw.rules.size).toBe(0)
    })

    test('Linux: an identical rule already present is not inserted twice; IPv6 uses ip6tables', async () => {
      const fw = fakeIptables()
      const a = linux(fw)
      factory.setContainmentAdapter(a)
      await a.applyRule({ containmentId: 'pre', target: '203.0.113.66', ruleName: 'SentinelAI-Rule-pre' })
      const r = await a.applyRule({ containmentId: 'pre', target: '203.0.113.66', ruleName: 'SentinelAI-Rule-pre' })
      expect(r.details.alreadyPresent).toBe(true)
      expect(fw.calls.filter((c) => c.includes('-I'))).toHaveLength(1)
      await request('2001:db8::66')
      expect(fw.calls.at(-1)).toContain('ip6tables')
    })

    test('the mock adapter stays the simulated default: no verification, no cleanup inspection', async () => {
      factory.resetContainmentAdapter()
      process.env.NODE_ENV = 'test'
      const m = factory.getContainmentAdapter({ forceNew: true })
      expect(m).toBeInstanceOf(MockContainmentAdapter)
      const verify = jest.spyOn(m, 'verifyRule')
      const inspect = jest.spyOn(m, 'inspectRule')
      const res = await request('203.0.113.67')
      expect(res.action).toMatchObject({ enforcementStatus: 'ACTIVE', enforcementBackend: 'mock' })
      expect(verify).not.toHaveBeenCalled()
      expect(inspect).not.toHaveBeenCalled()
      expect(await containment.getContainmentStatus()).toMatchObject({ realEnforcementEnabled: false, simulated: true })
    })
  })
})

describe('capability report for host-firewall containment', () => {
  test('adapters verified (mocked), real enforcement not enabled, mock tested-simulated, Cowrie separate', async () => {
    process.env.NODE_ENV = 'test'
    factory.resetContainmentAdapter()
    const { getCapabilities, LABELS } = require('../services/capabilityService')
    const byId = Object.fromEntries((await getCapabilities()).items.map((i) => [i.id, i]))
    expect(LABELS.implemented_and_tested_simulated).toBeDefined()
    expect(byId.firewall_adapters).toMatchObject({ label: 'implemented_and_verified' })
    expect(byId.firewall_adapters.facts.realRulesTested).toBe(false)
    expect(byId.firewall_adapters.summary).toMatch(/MOCKED command execution/)
    expect(byId.host_firewall).toMatchObject({ label: 'implemented_not_enabled' })
    expect(byId.host_firewall.summary).toMatch(/have not been created or tested/)
    expect(byId.host_firewall.facts).toMatchObject({ active: false, realRulesTested: false })
    expect(byId.mock_containment).toMatchObject({ label: 'implemented_and_tested_simulated' })
    expect(byId.mock_containment.facts).toMatchObject({ inUse: true, hostFirewallChanged: false })
    expect(byId.cowrie_denylist.label).toBe('implemented_and_tested')
    const fs = require('fs')
    const path = require('path')
    for (const f of byId.firewall_adapters.facts.evidence)
      expect(fs.existsSync(path.join(__dirname, '..', '..', f))).toBe(true)
  })
})
