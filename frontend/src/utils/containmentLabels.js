// Operator-facing wording for containment outcomes. Keep these honest: a deny-list entry or a
// mock-adapter rule is not a host firewall change.

export const DENY_LIST_NOTE = 'honeypot deny-list only; no host firewall rule'

export function denyListRecorded(ip) {
  return `IP ${ip} added to deny-list (${DENY_LIST_NOTE})`
}

// `response` is the axios response from containmentAPI.requestAction
export function containmentOutcome(target, response) {
  const action = response?.data?.data?.action
  const backend = action?.enforcementBackend
  if (action?.enforcementStatus && action.enforcementStatus !== 'ACTIVE') {
    return `Containment for ${target}: ${action.enforcementStatus}`
  }
  if (backend === 'windows-firewall') return `Windows Firewall rule applied for ${target}`
  return `Simulated containment recorded for ${target} (${backend || 'mock'} adapter; no firewall rule applied)`
}
