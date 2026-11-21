// Operator-facing wording for containment outcomes. Keep these honest: a deny-list entry or a
// mock-adapter rule is not a host firewall change.

export const DENY_LIST_NOTE = 'honeypot deny-list only; no host firewall rule'

// The only backends that change a real host firewall. Everything else (mock, simulated, unknown) is simulated.
export const REAL_FIREWALL_BACKENDS = Object.freeze({
  'windows-firewall': 'Windows Firewall',
  'linux-iptables': 'Linux iptables',
})
export const isRealFirewallBackend = (backend) =>
  typeof backend === 'string' && Object.prototype.hasOwnProperty.call(REAL_FIREWALL_BACKENDS, backend)

// GET /api/containment/status: real only when the backend says a real adapter is the one in use.
export const isRealFirewallStatus = (status) =>
  Boolean(status) && status.realEnforcementEnabled === true && isRealFirewallBackend(status.backend)

// Containment confirmation dialog: which engine the block will go through. A host firewall is named only when the
// backend reports that exact real adapter in use; anything else (mock, simulated, unknown, missing) is the mock.
export function enforcementEngineLabel(status) {
  if (isRealFirewallStatus(status))
    return { simulated: false, engine: `${REAL_FIREWALL_BACKENDS[status.backend].toUpperCase()} (HOST)`, mode: 'Live Host Rules' }
  return { simulated: true, engine: 'SIMULATION / MOCK ADAPTER', mode: 'Safe Dev Mode' }
}

export function adapterDisplayName(status) {
  if (isRealFirewallStatus(status))
    return `${status.adapterName || 'Host firewall adapter'} (${REAL_FIREWALL_BACKENDS[status.backend]}, host OS)`
  return 'MockContainmentAdapter (In-Memory Simulation)'
}

export function denyListRecorded(ip) {
  return `IP ${ip} added to deny-list (${DENY_LIST_NOTE})`
}

// `response` is the axios response from threatAPI.blockIP / blockIPManual, which now also report the
// containment adapter result as `enforcement` (status, backend).
export function manualBlockOutcome(ip, response) {
  const e = response?.data?.data?.enforcement
  if (e?.status === 'ACTIVE' && isRealFirewallBackend(e.backend)) {
    return `IP ${ip} added to deny-list and blocked by a ${REAL_FIREWALL_BACKENDS[e.backend]} rule`
  }
  if (e?.status === 'ACTIVE') {
    return `IP ${ip} added to deny-list (simulated firewall rule, ${e.backend || 'mock'} adapter)`
  }
  return `${denyListRecorded(ip)}; adapter enforcement did not complete`
}

// `response` is the axios response from containmentAPI.requestAction
export function containmentOutcome(target, response) {
  const action = response?.data?.data?.action
  const backend = action?.enforcementBackend
  if (action?.enforcementStatus && action.enforcementStatus !== 'ACTIVE') {
    // Failures say why (apply failure, ENFORCEMENT_NOT_VERIFIED, cleanup outcome), not only the status
    const why = typeof action.failureReason === 'string' && action.failureReason ? ` (${action.failureReason.slice(0, 240)})` : ''
    return `Containment for ${target}: ${action.enforcementStatus}${why}`
  }
  if (isRealFirewallBackend(backend)) return `${REAL_FIREWALL_BACKENDS[backend]} rule applied and verified for ${target}`
  return `Simulated containment recorded for ${target} (${backend || 'mock'} adapter; no firewall rule applied)`
}
