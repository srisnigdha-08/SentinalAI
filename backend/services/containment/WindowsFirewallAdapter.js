'use strict'

const { execFile } = require('child_process')
const net = require('net')
const util = require('util')
const execFilePromise = util.promisify(execFile)
const logger = require('../../utils/logger')
const ContainmentAdapterInterface = require('./adapterInterface')

/**
 * WindowsFirewallAdapter
 *
 * Windows Advanced Firewall enforcement adapter via netsh advfirewall.
 *
 * CRITICAL SAFETY GATING:
 * Real host-level enforcement is STRICTLY DISABLED by default.
 * It is only enabled when ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'.
 * When disabled, it safely refuses execution to preserve host connectivity.
 */
class WindowsFirewallAdapter extends ContainmentAdapterInterface {
  constructor(options = {}) {
    super()
    this.enabled =
      options.enabled !== undefined ? options.enabled : process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true'
    // netsh runs without a shell: arguments are passed as an array, so no metacharacter can start a new command.
    this._runNetsh =
      options.runNetsh || ((args, timeout) => execFilePromise('netsh', args, { timeout, windowsHide: true }))
  }

  getBackendType() {
    return 'windows-firewall'
  }

  /**
   * Internal safety check to verify execution permission.
   */
  _assertEnabled() {
    if (!this.enabled || process.env.NODE_ENV === 'test' || process.env.CONTAINMENT_DRY_RUN === 'true') {
      const msg =
        'Real Windows Firewall enforcement is disabled by safety gate. (ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT is not true, or NODE_ENV=test / CONTAINMENT_DRY_RUN=true).'
      logger.warn(`[WindowsFirewallAdapter] ${msg}`)
      const err = new Error(msg)
      err.code = 'FIREWALL_ENFORCEMENT_DISABLED'
      throw err
    }
  }

  /**
   * Validates target string to prevent command injection.
   */
  _sanitizeTarget(target) {
    if (typeof target !== 'string' || !/^[0-9a-fA-F.:/]+$/.test(target.trim())) {
      throw new Error(`Invalid target address characters: ${target}`)
    }
    const clean = target.trim()
    // Character checks alone accept strings such as ':::' or '1.2.3.4/99'; require a real IP or CIDR.
    const [ip, prefix, ...rest] = clean.split('/')
    const family = net.isIP(ip)
    const prefixValid =
      prefix === undefined || (/^\d{1,3}$/.test(prefix) && Number(prefix) <= (family === 6 ? 128 : 32))
    if (!family || rest.length > 0 || !prefixValid) {
      throw new Error(`Invalid target address: ${clean}`)
    }
    return clean
  }

  /**
   * Formats a standardized, discoverable rule name.
   */
  _formatRuleName(containmentId) {
    const cleanId = String(containmentId).replace(/[^a-zA-Z0-9-]/g, '')
    return `SentinelAI-Rule-${cleanId}`
  }

  /**
   * Validates rule name to ensure it strictly belongs to SentinelAI namespace.
   */
  _sanitizeRuleName(ruleName) {
    if (
      typeof ruleName !== 'string' ||
      !ruleName.startsWith('SentinelAI-Rule-') ||
      !/^[a-zA-Z0-9_-]+$/.test(ruleName)
    ) {
      throw new Error(`Invalid or unauthorized rule name: ${ruleName}`)
    }
    return ruleName
  }

  async applyRule({ containmentId, target, _targetType, ruleName }) {
    this._assertEnabled()
    const startTime = Date.now()
    const safeTarget = this._sanitizeTarget(target)
    const rawRuleName = ruleName || this._formatRuleName(containmentId)
    const assignedRuleName = this._sanitizeRuleName(rawRuleName)

    // Execute netsh rule addition: block inbound traffic from remote IP/CIDR
    // containmentId is interpolated into a shell string: restrict it like the rule name
    const safeId = String(containmentId).replace(/[^a-zA-Z0-9-]/g, '')
    const args = [
      'advfirewall',
      'firewall',
      'add',
      'rule',
      `name=${assignedRuleName}`,
      'dir=in',
      'action=block',
      `remoteip=${safeTarget}`,
      `description=SentinelAI Automated Containment ${safeId}`,
    ]
    const cmd = `netsh ${args.join(' ')}`

    try {
      logger.info(`[WindowsFirewallAdapter] Executing: ${cmd}`)
      const { stdout, stderr } = await this._runNetsh(args, 10000)
      const duration = Date.now() - startTime

      return {
        success: true,
        ruleId: assignedRuleName,
        ruleName: assignedRuleName,
        exitCode: 0,
        stdout: (stdout || '').trim(),
        stderr: (stderr || '').trim(),
        executionDurationMs: duration,
        details: { target: safeTarget, command: cmd },
      }
    } catch (err) {
      const duration = Date.now() - startTime
      logger.error(`[WindowsFirewallAdapter] Rule creation failed: ${err.message}`)
      return {
        success: false,
        ruleId: null,
        ruleName: assignedRuleName,
        exitCode: err.code || 1,
        stdout: (err.stdout || '').trim(),
        stderr: (err.stderr || err.message).trim(),
        executionDurationMs: duration,
        details: { target: safeTarget, command: cmd, error: err.message },
      }
    }
  }

  async removeRule({ containmentId, ruleId, _target, ruleName }) {
    this._assertEnabled()
    const startTime = Date.now()
    const rawRuleName = ruleName || ruleId || this._formatRuleName(containmentId)
    const assignedRuleName = this._sanitizeRuleName(rawRuleName)

    const args = ['advfirewall', 'firewall', 'delete', 'rule', `name=${assignedRuleName}`]
    const cmd = `netsh ${args.join(' ')}`

    try {
      logger.info(`[WindowsFirewallAdapter] Executing: ${cmd}`)
      const { stdout, stderr } = await this._runNetsh(args, 10000)
      const duration = Date.now() - startTime

      return {
        success: true,
        exitCode: 0,
        stdout: (stdout || '').trim(),
        stderr: (stderr || '').trim(),
        executionDurationMs: duration,
        details: { ruleName: assignedRuleName, command: cmd },
      }
    } catch (err) {
      const duration = Date.now() - startTime
      logger.error(`[WindowsFirewallAdapter] Rule removal failed: ${err.message}`)
      return {
        success: false,
        exitCode: err.code || 1,
        stdout: (err.stdout || '').trim(),
        stderr: (err.stderr || err.message).trim(),
        executionDurationMs: duration,
        details: { ruleName: assignedRuleName, command: cmd, error: err.message },
      }
    }
  }

  async verifyRule({ containmentId, ruleId, _target, ruleName }) {
    this._assertEnabled()
    const rawRuleName = ruleName || ruleId || this._formatRuleName(containmentId)
    const assignedRuleName = this._sanitizeRuleName(rawRuleName)
    const args = ['advfirewall', 'firewall', 'show', 'rule', `name=${assignedRuleName}`]

    try {
      // netsh exits non-zero when no rule matches, so reaching this line means the rule exists.
      const { stdout } = await this._runNetsh(args, 5000)
      const exists = stdout.includes(assignedRuleName)
      // Match the "Enabled:" line only; a bare includes('Yes') matched any field. Non-English output
      // falls back to "exists", since rules this adapter creates are enabled by default.
      const enabledLine = stdout.match(/^\s*Enabled:\s*(\S+)/m)
      return {
        exists,
        active: exists && (enabledLine ? enabledLine[1] === 'Yes' : true),
        details: { rawOutput: stdout.trim() },
      }
    } catch (err) {
      return {
        exists: false,
        active: false,
        details: { error: err.message },
      }
    }
  }

  async listActiveRules() {
    this._assertEnabled()
    try {
      const { stdout } = await this._runNetsh(['advfirewall', 'firewall', 'show', 'rule', 'name=all'], 15000)
      const rules = []
      const lines = stdout.split('\n')
      let currentRule = null

      for (const line of lines) {
        const trimmed = line.trim()
        if (trimmed.startsWith('Rule Name:')) {
          const name = trimmed.replace('Rule Name:', '').trim()
          if (name.startsWith('SentinelAI-Rule-')) {
            currentRule = { ruleName: name, ruleId: name }
            rules.push(currentRule)
          } else {
            currentRule = null
          }
        }
      }

      return rules
    } catch (err) {
      logger.error(`[WindowsFirewallAdapter] List rules failed: ${err.message}`)
      return []
    }
  }
}

module.exports = WindowsFirewallAdapter
