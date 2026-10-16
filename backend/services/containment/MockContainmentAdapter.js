'use strict'

const ContainmentAdapterInterface = require('./adapterInterface')

/**
 * MockContainmentAdapter
 *
 * Safe in-memory adapter for testing and simulation.
 * Does not mutate host firewall or system settings.
 */
class MockContainmentAdapter extends ContainmentAdapterInterface {
  constructor() {
    super()
    this.activeRules = new Map() // ruleId -> ruleData
    this.failNextApply = null // Error or string to throw on next apply
    this.failNextRemove = null // Error or string to throw on next remove
    this.applyDelayMs = 0
  }

  getBackendType() {
    return 'mock'
  }

  setFailNextApply(err) {
    this.failNextApply = err
  }

  setFailNextRemove(err) {
    this.failNextRemove = err
  }

  setApplyDelayMs(ms) {
    this.applyDelayMs = ms
  }

  clear() {
    this.activeRules.clear()
    this.failNextApply = null
    this.failNextRemove = null
    this.applyDelayMs = 0
  }

  async applyRule({ containmentId, target, targetType, ruleName }) {
    const startTime = Date.now()

    if (this.applyDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.applyDelayMs))
    }

    if (this.failNextApply) {
      const errToThrow =
        this.failNextApply instanceof Error ? this.failNextApply : new Error(String(this.failNextApply))
      this.failNextApply = null
      const duration = Date.now() - startTime
      return {
        success: false,
        ruleId: null,
        ruleName: ruleName || `SentinelAI-Mock-${containmentId}`,
        exitCode: 1,
        stdout: '',
        stderr: errToThrow.message,
        executionDurationMs: duration,
        details: { simulatedFailure: true, error: errToThrow.message },
      }
    }

    const assignedRuleName = ruleName || `SentinelAI-Mock-${containmentId}`
    const ruleId = `mock-rule-${containmentId}`
    const ruleData = {
      ruleId,
      ruleName: assignedRuleName,
      containmentId,
      target,
      targetType: targetType || 'ipv4',
      appliedAt: new Date(),
    }

    this.activeRules.set(ruleId, ruleData)
    const duration = Date.now() - startTime

    return {
      success: true,
      ruleId,
      ruleName: assignedRuleName,
      exitCode: 0,
      stdout: `Mock containment rule ${assignedRuleName} applied for target ${target}`,
      stderr: '',
      executionDurationMs: duration,
      details: { adapter: 'MockContainmentAdapter', target },
    }
  }

  async removeRule({ containmentId, ruleId, target, _ruleName }) {
    const startTime = Date.now()

    if (this.failNextRemove) {
      const errToThrow =
        this.failNextRemove instanceof Error ? this.failNextRemove : new Error(String(this.failNextRemove))
      this.failNextRemove = null
      const duration = Date.now() - startTime
      return {
        success: false,
        exitCode: 1,
        stdout: '',
        stderr: errToThrow.message,
        executionDurationMs: duration,
        details: { simulatedFailure: true, error: errToThrow.message },
      }
    }

    const resolvedRuleId = ruleId || `mock-rule-${containmentId}`
    const existed = this.activeRules.delete(resolvedRuleId)
    const duration = Date.now() - startTime

    return {
      success: true,
      exitCode: 0,
      stdout: existed
        ? `Mock containment rule ${resolvedRuleId} removed for target ${target}`
        : `Rule ${resolvedRuleId} was already removed or absent`,
      stderr: '',
      executionDurationMs: duration,
      details: { adapter: 'MockContainmentAdapter', existed },
    }
  }

  async verifyRule({ containmentId, ruleId, _target, _ruleName }) {
    const resolvedRuleId = ruleId || `mock-rule-${containmentId}`
    const rule = this.activeRules.get(resolvedRuleId)

    if (rule) {
      return {
        exists: true,
        active: true,
        details: { ...rule },
      }
    }

    return {
      exists: false,
      active: false,
      details: { searchedRuleId: resolvedRuleId },
    }
  }

  async listActiveRules() {
    return Array.from(this.activeRules.values())
  }
}

module.exports = MockContainmentAdapter
