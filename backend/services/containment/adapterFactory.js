'use strict'

const MockContainmentAdapter = require('./MockContainmentAdapter')
const WindowsFirewallAdapter = require('./WindowsFirewallAdapter')
const logger = require('../../utils/logger')

let currentAdapter = null

/**
 * Resolves or initializes the containment adapter based on configuration.
 *
 * Defaults safely to MockContainmentAdapter.
 *
 * @param {Object} [options]
 * @param {string} [options.backend] - 'mock' | 'simulated' | 'windows-firewall'
 * @returns {import('./adapterInterface')}
 */
const getContainmentAdapter = (options = {}) => {
  if (currentAdapter && !options.backend && !options.forceNew) {
    return currentAdapter
  }

  const requestedBackend = options.backend || process.env.CONTAINMENT_BACKEND || 'mock'

  if (process.env.NODE_ENV === 'test' || process.env.CONTAINMENT_DRY_RUN === 'true') {
    logger.info(
      '[AdapterFactory] Safety lock: Test environment or CONTAINMENT_DRY_RUN detected. Forcing MockContainmentAdapter.'
    )
    currentAdapter = new MockContainmentAdapter()
    return currentAdapter
  }

  if (requestedBackend === 'windows-firewall' && process.env.ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT === 'true') {
    logger.info('[AdapterFactory] Initializing WindowsFirewallAdapter (REAL ENFORCEMENT)')
    currentAdapter = new WindowsFirewallAdapter({ enabled: true })
  } else {
    if (requestedBackend === 'windows-firewall') {
      logger.warn(
        '[AdapterFactory] Real Windows Firewall was requested but safety gate ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT is false. Falling back to MockContainmentAdapter.'
      )
    }
    logger.info('[AdapterFactory] Using MockContainmentAdapter (SAFE SIMULATION)')
    currentAdapter = new MockContainmentAdapter()
  }

  return currentAdapter
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
}
