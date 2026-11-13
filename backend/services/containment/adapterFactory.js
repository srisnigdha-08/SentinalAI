'use strict'

const MockContainmentAdapter = require('./MockContainmentAdapter')
const WindowsFirewallAdapter = require('./WindowsFirewallAdapter')
const LinuxIptablesAdapter = require('./LinuxIptablesAdapter')
const { realEnforcementDecision } = require('./enforcementSafety')
const logger = require('../../utils/logger')

let currentAdapter = null

/**
 * Resolves or initializes the containment adapter based on configuration.
 *
 * Defaults safely to MockContainmentAdapter. A real host-firewall adapter is created only when every guard in
 * enforcementSafety.realEnforcementDecision passes (backend, enable flag, host-bound confirmation, not a test).
 *
 * @param {Object} [options]
 * @param {string} [options.backend] - 'mock' | 'simulated' | 'windows-firewall' | 'linux-iptables'
 * @returns {import('./adapterInterface')}
 */
const getContainmentAdapter = (options = {}) => {
  if (currentAdapter && !options.backend && !options.forceNew) {
    return currentAdapter
  }

  const env = options.backend ? { ...process.env, CONTAINMENT_BACKEND: options.backend } : process.env

  if (env.NODE_ENV === 'test' || env.CONTAINMENT_DRY_RUN === 'true') {
    logger.info(
      '[AdapterFactory] Safety lock: Test environment or CONTAINMENT_DRY_RUN detected. Forcing MockContainmentAdapter.'
    )
    currentAdapter = new MockContainmentAdapter()
    return currentAdapter
  }

  const decision = realEnforcementDecision(env)
  if (decision.allowed && decision.backend === 'windows-firewall') {
    logger.info('[AdapterFactory] Initializing WindowsFirewallAdapter (REAL ENFORCEMENT)')
    currentAdapter = new WindowsFirewallAdapter({ enabled: true })
  } else if (decision.allowed && decision.backend === 'linux-iptables') {
    logger.info('[AdapterFactory] Initializing LinuxIptablesAdapter (REAL ENFORCEMENT)')
    currentAdapter = new LinuxIptablesAdapter({ enabled: true })
  } else {
    if (['windows-firewall', 'linux-iptables'].includes(decision.backend)) {
      logger.warn(
        `[AdapterFactory] Real ${decision.backend} enforcement was requested but the safety gate refused it ` +
          `(${decision.reasons.join('; ')}). Falling back to MockContainmentAdapter.`
      )
    }
    logger.info('[AdapterFactory] Using MockContainmentAdapter (SAFE SIMULATION)')
    currentAdapter = new MockContainmentAdapter()
  }

  return currentAdapter
}

/**
 * What enforcement actually exists right now, for the dashboard. Cowrie's own deny-list refusal is always real for
 * the honeypot; host-firewall enforcement is reported only when a real adapter is active.
 */
const describeEnforcement = () => {
  const adapter = getContainmentAdapter()
  const backend = adapter.getBackendType()
  const real = backend === 'windows-firewall' || backend === 'linux-iptables'
  const requested = process.env.CONTAINMENT_BACKEND || 'mock'
  return {
    hostFirewall: real ? 'host_firewall' : 'simulated',
    backend,
    requestedBackend: requested,
    refusedReasons: real ? [] : realEnforcementDecision(process.env).reasons,
    cowrieDenylist: 'cowrie_denylist',
    verifiedAfterApply: Boolean(adapter.requiresPostApplyVerification),
  }
}

/**
 * Allows test suites to override or inject custom adapters.
 */
const setContainmentAdapter = (adapter) => {
  currentAdapter = adapter
}

/**
 * Resets the active adapter.
 */
const resetContainmentAdapter = () => {
  currentAdapter = null
}

module.exports = {
  getContainmentAdapter,
  setContainmentAdapter,
  resetContainmentAdapter,
  describeEnforcement,
}
