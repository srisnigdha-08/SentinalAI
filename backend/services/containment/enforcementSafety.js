'use strict'
/**
 * Gate for REAL host-firewall enforcement (docs/CONTAINMENT_ENFORCEMENT.md). Real enforcement needs all of:
 *   1. CONTAINMENT_BACKEND = windows-firewall | linux-iptables
 *   2. that backend's enable flag: ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT=true / ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT=true
 *   3. CONTAINMENT_REAL_ENFORCEMENT_CONFIRM = I-AUTHORIZE-FIREWALL-CHANGES-ON-<this host's name>
 *      (bound to the machine, so a copied .env does not switch enforcement on elsewhere)
 *   4. not NODE_ENV=test, not CONTAINMENT_DRY_RUN=true, not inside a Jest worker
 * Anything less resolves to the mock (simulated) adapter. Ordinary startup and every test therefore stay simulated.
 */
const os = require('os')

const REAL_BACKENDS = {
  'windows-firewall': 'ENABLE_REAL_WINDOWS_FIREWALL_ENFORCEMENT',
  'linux-iptables': 'ENABLE_REAL_LINUX_FIREWALL_ENFORCEMENT',
}

const confirmationPhrase = (host = os.hostname()) => `I-AUTHORIZE-FIREWALL-CHANGES-ON-${host}`

/** { allowed, backend, reasons[] } — pure apart from the host name (injectable). */
function realEnforcementDecision(env = process.env, host = os.hostname()) {
  const backend = env.CONTAINMENT_BACKEND || 'mock'
  const reasons = []
  if (!REAL_BACKENDS[backend]) return { allowed: false, backend, reasons: ['CONTAINMENT_BACKEND is not a real firewall backend'] }
  if (env[REAL_BACKENDS[backend]] !== 'true') reasons.push(`${REAL_BACKENDS[backend]} is not "true"`)
  if (env.CONTAINMENT_REAL_ENFORCEMENT_CONFIRM !== confirmationPhrase(host))
    reasons.push('CONTAINMENT_REAL_ENFORCEMENT_CONFIRM does not match this host')
  if (env.NODE_ENV === 'test' || env.JEST_WORKER_ID !== undefined) reasons.push('test environment')
  if (env.CONTAINMENT_DRY_RUN === 'true') reasons.push('CONTAINMENT_DRY_RUN=true')
  return { allowed: reasons.length === 0, backend, reasons }
}

module.exports = { REAL_BACKENDS, confirmationPhrase, realEnforcementDecision }
