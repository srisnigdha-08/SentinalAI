'use strict'

/**
 * ContainmentAdapterInterface
 *
 * Defines the contract that all containment enforcement adapters must implement.
 */
class ContainmentAdapterInterface {
  /**
   * Applies a containment rule on the target.
   *
   * @param {Object} params
   * @param {string} params.containmentId - Unique action ID
   * @param {string} params.target - Validated IP or CIDR
   * @param {string} params.targetType - 'ipv4' | 'ipv6' | 'cidr'
   * @param {string} [params.ruleName] - Custom or generated rule name
   * @returns {Promise<{
   *   success: boolean,
   *   ruleId: string,
   *   ruleName: string,
   *   exitCode: number,
   *   stdout: string,
   *   stderr: string,
   *   executionDurationMs: number,
   *   details?: Object
   * }>}
   */
  async applyRule(_params) {
    throw new Error('applyRule() must be implemented by adapter')
  }

  /**
   * Removes / rolls back a containment rule.
   *
   * @param {Object} params
   * @param {string} params.containmentId - Unique action ID
   * @param {string} params.ruleId - Adapter rule ID
   * @param {string} params.target - Validated IP or CIDR
   * @param {string} [params.ruleName] - Rule name
   * @returns {Promise<{
   *   success: boolean,
   *   exitCode: number,
   *   stdout: string,
   *   stderr: string,
   *   executionDurationMs: number,
   *   details?: Object
   * }>}
   */
  async removeRule(_params) {
    throw new Error('removeRule() must be implemented by adapter')
  }

  /**
   * Verifies if a containment rule currently exists and is active.
   *
   * @param {Object} params
   * @param {string} params.containmentId
   * @param {string} params.ruleId
   * @param {string} params.target
   * @param {string} [params.ruleName]
   * @returns {Promise<{
   *   exists: boolean,
   *   active: boolean,
   *   details?: Object
   * }>}
   */
  async verifyRule(_params) {
    throw new Error('verifyRule() must be implemented by adapter')
  }

  /**
   * Read-only, tri-state rule lookup used to recover interrupted applications (CONT-003). Unlike verifyRule, an
   * error is never reported as "absent": ABSENT only when the backend positively says the rule does not exist.
   * A throw means the adapter is unavailable. The default answers UNKNOWN, so an adapter that cannot inspect its
   * rules never causes a lock to be released while a rule might still be enforced.
   *
   * @returns {Promise<{ state: 'PRESENT' | 'ABSENT' | 'UNKNOWN', details?: Object }>}
   */
  async inspectRule(_params) {
    return { state: 'UNKNOWN', details: { reason: 'adapter does not support rule inspection' } }
  }

  /**
   * Lists all active rules managed by this adapter.
   *
   * @returns {Promise<Array<{
   *   ruleId: string,
   *   ruleName: string,
   *   target: string,
   *   targetType: string,
   *   appliedAt: Date
   * }>>}
   */
  async listActiveRules() {
    throw new Error('listActiveRules() must be implemented by adapter')
  }

  /**
   * Returns the backend identifier ('mock', 'simulated', 'windows-firewall').
   *
   * @returns {string}
   */
  getBackendType() {
    throw new Error('getBackendType() must be implemented by adapter')
  }
}

module.exports = ContainmentAdapterInterface
