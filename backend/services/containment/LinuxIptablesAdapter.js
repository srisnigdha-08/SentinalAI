'use strict'
/**
 * Linux host-firewall adapter (iptables / ip6tables), for the host that actually receives attacker traffic: in this
 * project's lab that is the WSL Ubuntu instance running Cowrie. Disabled unless the factory's real-enforcement gate
 * passes (services/containment/enforcementSafety.js); never runs under NODE_ENV=test or CONTAINMENT_DRY_RUN.
 *
 * Commands are executed WITHOUT a shell (argument arrays). CONTAINMENT_LINUX_COMMAND_PREFIX (a JSON array, e.g.
 * ["wsl","-d","Ubuntu","--","sudo","-n"]) is prepended, so the backend on Windows can reach WSL's firewall with a
 * passwordless, narrowly scoped sudo rule the owner creates. Rules are tagged with a comment
 * "SentinelAI-Rule-<id>" and only rules carrying that tag are ever checked or removed.
 * verifyRule uses `iptables -C` (exit 0 = the exact rule exists): the containment service calls it after every
 * apply, so a command that "succeeded" without creating the rule fails the action.
 */
const net = require('net')
const { execFile } = require('child_process')
const ContainmentAdapterInterface = require('./adapterInterface')
const logger = require('../../utils/logger')

const execFilePromise = (file, args, opts) =>
  new Promise((resolve, reject) =>
    execFile(file, args, opts, (err, stdout, stderr) =>
      err ? reject(Object.assign(err, { stdout, stderr })) : resolve({ stdout, stderr })
    )
  )

function parsePrefix(raw) {
  if (!raw) return []
  try {
    const v = JSON.parse(raw)
    if (Array.isArray(v) && v.every((s) => typeof s === 'string' && /^[A-Za-z0-9_./=-]+$/.test(s))) return v
  } catch {
    /* fall through */
  }
  throw new Error('CONTAINMENT_LINUX_COMMAND_PREFIX must be a JSON array of simple words')
}

class LinuxIptablesAdapter extends ContainmentAdapterInterface {
  constructor(options = {}) {
    super()
    this.enabled = options.enabled === true
    this.prefix = options.prefix || parsePrefix(process.env.CONTAINMENT_LINUX_COMMAND_PREFIX)
    this._run =
      options.run || ((argv, timeout) => execFilePromise(argv[0], argv.slice(1), { timeout, windowsHide: true }))
  }

  getBackendType() {
    return 'linux-iptables'
  }

  get requiresPostApplyVerification() {
    return true
  }

  _assertEnabled() {
    if (!this.enabled || process.env.NODE_ENV === 'test' || process.env.CONTAINMENT_DRY_RUN === 'true') {
      const err = new Error('Real Linux firewall enforcement is disabled by safety gate.')
      err.code = 'FIREWALL_ENFORCEMENT_DISABLED'
      throw err
    }
  }

  _target(target) {
    const clean = typeof target === 'string' ? target.trim() : ''
    const [ip, prefix, ...rest] = clean.split('/')
    const family = net.isIP(ip)
    const prefixOk = prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= (family === 6 ? 128 : 32))
    if (!family || rest.length || !prefixOk) throw new Error(`Invalid target address: ${target}`)
    return { clean, tool: family === 6 ? 'ip6tables' : 'iptables' }
  }

  _ruleName(containmentId, ruleName) {
    const name = ruleName || `SentinelAI-Rule-${String(containmentId).replace(/[^a-zA-Z0-9-]/g, '')}`
    if (!/^SentinelAI-Rule-[A-Za-z0-9-]{1,64}$/.test(name))
      throw new Error(`Invalid or unauthorized rule name: ${name}`)
    return name
  }

  _argv(tool, op, target, name) {
    // -w waits for the xtables lock instead of failing when another process holds it
    return [...this.prefix, tool, '-w', op, 'INPUT', '-s', target, '-m', 'comment', '--comment', name, '-j', 'DROP']
  }

  async _exec(argv) {
    const t0 = Date.now()
    try {
      const { stdout, stderr } = await this._run(argv, 10000)
      return {
        ok: true,
        exitCode: 0,
        stdout: (stdout || '').trim(),
        stderr: (stderr || '').trim(),
        ms: Date.now() - t0,
      }
    } catch (err) {
      return {
        ok: false,
        exitCode: typeof err.code === 'number' ? err.code : 1,
        stdout: (err.stdout || '').trim(),
        stderr: (err.stderr || err.message || '').toString().trim(),
        ms: Date.now() - t0,
      }
    }
  }

  async applyRule({ containmentId, target, ruleName }) {
    this._assertEnabled()
    const { clean, tool } = this._target(target)
    const name = this._ruleName(containmentId, ruleName)
    const exists = await this._exec(this._argv(tool, '-C', clean, name))
    const r = exists.ok ? exists : await this._exec(this._argv(tool, '-I', clean, name)) // never duplicated
    if (!r.ok) logger.error(`[LinuxIptablesAdapter] Rule creation failed: ${r.stderr}`)
    return {
      success: r.ok,
      ruleId: r.ok ? name : null,
      ruleName: name,
      exitCode: r.exitCode,
      stdout: r.stdout,
      stderr: r.stderr,
      executionDurationMs: r.ms,
      details: { target: clean, tool, alreadyPresent: exists.ok },
    }
  }

  async removeRule({ containmentId, ruleId, target, ruleName }) {
    this._assertEnabled()
    const { clean, tool } = this._target(target)
    const name = this._ruleName(containmentId, ruleName || ruleId)
    const present = await this._exec(this._argv(tool, '-C', clean, name))
    if (!present.ok) {
      return {
        success: true,
        exitCode: 0,
        stdout: '',
        stderr: '',
        executionDurationMs: present.ms,
        details: { alreadyAbsent: true },
      }
    }
    const r = await this._exec(this._argv(tool, '-D', clean, name))
    return {
      success: r.ok,
      exitCode: r.exitCode,
      stdout: r.stdout,
      stderr: r.stderr,
      executionDurationMs: r.ms,
      details: { target: clean },
    }
  }

  async verifyRule({ containmentId, ruleId, target, ruleName }) {
    this._assertEnabled()
    const { clean, tool } = this._target(target)
    const name = this._ruleName(containmentId, ruleName || ruleId)
    const r = await this._exec(this._argv(tool, '-C', clean, name))
    return { exists: r.ok, active: r.ok, details: { ruleName: name, exitCode: r.exitCode } }
  }

  async inspectRule({ containmentId, ruleId, target, ruleName }) {
    if (!this.enabled) return { state: 'UNKNOWN', details: { reason: 'adapter disabled' } }
    const { clean, tool } = this._target(target)
    const name = this._ruleName(containmentId, ruleName || ruleId)
    const r = await this._exec(this._argv(tool, '-C', clean, name))
    if (r.ok) return { state: 'PRESENT', details: { ruleName: name } }
    // iptables -C exits 1 with "does a matching rule exist" when absent; anything else (no sudo, no binary) is unknown
    if (r.exitCode === 1 && /matching rule|Bad rule/i.test(r.stderr))
      return { state: 'ABSENT', details: { ruleName: name } }
    return { state: 'UNKNOWN', details: { ruleName: name, exitCode: r.exitCode } }
  }
}

module.exports = LinuxIptablesAdapter
module.exports.parsePrefix = parsePrefix
