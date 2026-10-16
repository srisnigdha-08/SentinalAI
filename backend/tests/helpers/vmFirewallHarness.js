'use strict'

const fs = require('fs')
const { exec } = require('child_process')
const util = require('util')
const execPromise = util.promisify(exec)

const VM_MARKER_ENV = 'SENTINELAI_ISOLATED_TEST_VM'
const VM_MARKER_FILE = 'C:\\sentinelai_vm_marker.txt'
const SAFE_TEST_TARGET = '192.0.2.100' // RFC 5737 TEST-NET-1 (Safe Documentation / Test IP)
const TEST_RULE_PREFIX = 'SentinelAI-VMTest-'

/**
 * Asserts that the current process is running inside an approved isolated test VM.
 * Fails closed immediately if run on a developer workstation.
 */
function assertIsolatedVMEnvironment() {
  const isEnvSet = process.env[VM_MARKER_ENV] === 'true'
  const isMarkerPresent = fs.existsSync(VM_MARKER_FILE)

  if (!isEnvSet || !isMarkerPresent) {
    throw new Error(
      'CRITICAL SAFETY REFUSAL: Real Windows Firewall execution is strictly prohibited on the host workstation. ' +
        `Execution requires both environment variable ${VM_MARKER_ENV}=true AND marker file ${VM_MARKER_FILE} to be present.`
    )
  }
}

/**
 * Validates that the target IP strictly belongs to the safe test-net range.
 */
function assertSafeTestTarget(ip) {
  if (typeof ip !== 'string' || !ip.startsWith('192.0.2.')) {
    throw new Error(
      `TARGET SAFETY REFUSAL: Target '${ip}' is not within RFC 5737 TEST-NET-1 (192.0.2.0/24). Production, loopback, and LAN targets are forbidden.`
    )
  }
}

/**
 * Enumerates all existing rules matching the test prefix.
 */
async function getTestRuleInventory() {
  assertIsolatedVMEnvironment()
  try {
    const { stdout } = await execPromise('netsh advfirewall firewall show rule name=all', { timeout: 10000 })
    const rules = []
    const lines = stdout.split('\n')
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith('Rule Name:')) {
        const name = trimmed.replace('Rule Name:', '').trim()
        if (name.startsWith(TEST_RULE_PREFIX)) {
          rules.push(name)
        }
      }
    }
    return rules
  } catch {
    return []
  }
}

/**
 * Removes any leftover rules matching the test prefix.
 */
async function cleanupTestRules() {
  assertIsolatedVMEnvironment()
  const leftovers = await getTestRuleInventory()
  for (const rule of leftovers) {
    try {
      await execPromise(`netsh advfirewall firewall delete rule name="${rule}"`, { timeout: 5000 })
    } catch {}
  }
  return leftovers.length
}

module.exports = {
  assertIsolatedVMEnvironment,
  assertSafeTestTarget,
  getTestRuleInventory,
  cleanupTestRules,
  SAFE_TEST_TARGET,
  TEST_RULE_PREFIX,
  VM_MARKER_ENV,
  VM_MARKER_FILE,
}
