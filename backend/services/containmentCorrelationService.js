'use strict'
/**
 * Detection-to-containment correlation (docs/CONTAINMENT_ENFORCEMENT.md §Correlation).
 *
 * Under the default policy AUTO_BLOCK_POLICY=correlated a single suspicious flow never causes an automatic block.
 * An automatic containment request needs, from one source address inside CORRELATION_WINDOW_SECONDS:
 *   * at least CORRELATION_MIN_FLOWS suspicious flows (stored threats at or above the alert line), and
 *   * at least CORRELATION_MIN_BLOCK_LINE_FLOWS of them at or above the block line.
 * A flow at the block line that does not meet this is NEEDS_APPROVAL: the threat is kept for an analyst, who can
 * approve containment with the existing manual block. Other outcomes:
 *   SUPPRESSED_TRUSTED   the source is protected (loopback, link-local, CONTAINMENT_PROTECTED_TARGETS) or listed in
 *                        CONTAINMENT_TRUSTED_IPS (IPs or CIDRs)
 *   SUPPRESSED_DUPLICATE the source is already contained, or was requested within CORRELATION_COOLDOWN_SECONDS
 *   MONITOR              below the block line
 * AUTO_BLOCK_POLICY=single_flow restores the original behaviour (one flow at the block line) for simulated
 * enforcement only: with a real host-firewall adapter the correlated policy is always used.
 * Every decision returns its reasons and evidence; callers store them on the threat (containmentDecision).
 * Single host: the window is evaluated on this backend's own database. There is no cross-node correlation.
 */
const net = require('net')
const logger = require('../utils/logger')

const num = (v, d, min) => {
  const n = Number(v)
  return Number.isFinite(n) && n >= min ? n : d
}

function config(env = process.env) {
  return {
    policy: env.AUTO_BLOCK_POLICY === 'single_flow' ? 'single_flow' : 'correlated',
    windowSeconds: num(env.CORRELATION_WINDOW_SECONDS, 300, 10),
    minFlows: Math.floor(num(env.CORRELATION_MIN_FLOWS, 3, 2)),
    minBlockLineFlows: Math.floor(num(env.CORRELATION_MIN_BLOCK_LINE_FLOWS, 2, 1)),
    cooldownSeconds: num(env.CORRELATION_COOLDOWN_SECONDS, 600, 0),
    trusted: String(env.CONTAINMENT_TRUSTED_IPS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  }
}

function isTrusted(ip, trusted) {
  if (!net.isIP(ip) || !trusted.length) return false
  const list = new net.BlockList()
  for (const entry of trusted) {
    const [addr, prefix] = entry.split('/')
    const fam = net.isIP(addr)
    if (!fam) continue
    const type = fam === 6 ? 'ipv6' : 'ipv4'
    if (prefix === undefined) list.addAddress(addr, type)
    else if (/^\d{1,3}$/.test(prefix)) list.addSubnet(addr, Number(prefix), type)
  }
  return list.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4')
}

/**
 * @param {object} p { sourceIP, attackType, threatScore, isAnomaly, alertThreshold, blockThreshold, now? }
 * @param {object} [deps] injectable { ThreatLog, ContainmentAction, BlockedIP, checkTargetSafety, realEnforcement, env }
 * @returns {Promise<{decision, policy, reasons: string[], evidence: object, evaluatedAt: Date}>}
 */
async function evaluate(p, deps = {}) {
  const env = deps.env || process.env
  const cfg = config(env)
  const now = p.now ? new Date(p.now) : new Date()
  // The same pure gate the adapter factory uses: real enforcement exists only when it allows it.
  const realEnforcement =
    deps.realEnforcement !== undefined
      ? deps.realEnforcement
      : require('./containment/enforcementSafety').realEnforcementDecision(env).allowed
  const policy = realEnforcement ? 'correlated' : cfg.policy
  const out = (decision, reasons, evidence = {}) => ({ decision, policy, reasons, evidence, evaluatedAt: now })
  const score = Number(p.threatScore)

  if (!(score >= p.blockThreshold)) return out('MONITOR', ['below the block line'])
  if (isTrusted(p.sourceIP, cfg.trusted)) return out('SUPPRESSED_TRUSTED', ['listed in CONTAINMENT_TRUSTED_IPS'])

  if (policy === 'single_flow') {
    // The original behaviour, unchanged: executeAutoBlock still applies the protected-target refusal and the
    // idempotent deny-list upsert itself. Simulated enforcement only (a real adapter forces "correlated").
    return out('AUTO_BLOCK', ['single_flow policy: one flow at or above the block line (simulated enforcement only)'], {
      flows: 1,
      blockLineFlows: 1,
    })
  }

  const checkTargetSafety = deps.checkTargetSafety || require('./containmentPolicyService').checkTargetSafety
  const safety = checkTargetSafety(p.sourceIP)
  if (!safety.isSafe) return out('SUPPRESSED_TRUSTED', [`protected target: ${safety.reason}`])

  const ContainmentAction = deps.ContainmentAction || require('../models/ContainmentAction')
  const BlockedIP = deps.BlockedIP || require('../models/BlockedIP')
  const since = new Date(now.getTime() - cfg.cooldownSeconds * 1000)
  const [blocked, recent] = await Promise.all([
    BlockedIP.exists({ ip: p.sourceIP }),
    cfg.cooldownSeconds > 0
      ? ContainmentAction.exists({
          $or: [{ target: p.sourceIP }, { normalizedTarget: p.sourceIP }],
          createdAt: { $gte: since },
          enforcementStatus: { $nin: ['FAILED', 'REJECTED'] },
        })
      : null,
  ])
  if (blocked) return out('SUPPRESSED_DUPLICATE', ['source is already on the deny-list'])
  if (recent) return out('SUPPRESSED_DUPLICATE', [`containment requested within the last ${cfg.cooldownSeconds} s`])

  const ThreatLog = deps.ThreatLog || require('../models/ThreatLog')
  const windowStart = new Date(now.getTime() - cfg.windowSeconds * 1000)
  const prior = await ThreatLog.find({
    sourceIP: p.sourceIP,
    createdAt: { $gte: windowStart, $lte: now },
    status: { $nin: ['FALSE_POSITIVE'] },
    aiScore: { $gte: p.alertThreshold },
  })
    .select('aiScore attackType createdAt')
    .limit(500)
    .lean()
  const scores = prior.map((t) => Number(t.aiScore) || 0).concat(score)
  const flows = scores.length
  const blockLineFlows = scores.filter((s) => s >= p.blockThreshold).length
  const attackTypes = [
    ...new Set(
      prior
        .map((t) => t.attackType)
        .concat(p.attackType)
        .filter(Boolean)
    ),
  ]
  const times = prior.map((t) => new Date(t.createdAt).getTime()).concat(now.getTime())
  const evidence = {
    windowSeconds: cfg.windowSeconds,
    flows,
    blockLineFlows,
    attackTypes,
    maxScore: Math.max(...scores),
    anomalyOnCurrentFlow: Boolean(p.isAnomaly),
    firstSeen: new Date(Math.min(...times)),
    lastSeen: now,
    thresholds: { minFlows: cfg.minFlows, minBlockLineFlows: cfg.minBlockLineFlows },
  }
  if (flows >= cfg.minFlows && blockLineFlows >= cfg.minBlockLineFlows) {
    return out(
      'AUTO_BLOCK',
      [
        `${flows} suspicious flows from this source in ${cfg.windowSeconds} s (needs ${cfg.minFlows})`,
        `${blockLineFlows} at or above the block line (needs ${cfg.minBlockLineFlows})`,
      ],
      evidence
    )
  }
  const reasons = [
    `only ${flows} suspicious flow(s) in ${cfg.windowSeconds} s (needs ${cfg.minFlows}) and ${blockLineFlows} at the block line (needs ${cfg.minBlockLineFlows})`,
    'held for analyst approval: a single or few flows never trigger an automatic block',
  ]
  return out('NEEDS_APPROVAL', reasons, evidence)
}

/** evaluate(), but never throws: a failure falls back to NEEDS_APPROVAL (fail closed: no automatic block). */
async function evaluateSafely(p, deps) {
  try {
    return await evaluate(p, deps)
  } catch (err) {
    logger.error(`[Correlation] evaluation failed (${err.message}); holding for approval`)
    return {
      decision: 'NEEDS_APPROVAL',
      policy: 'correlated',
      reasons: ['correlation could not be evaluated; held for analyst approval'],
      evidence: {},
      evaluatedAt: new Date(),
    }
  }
}

module.exports = { evaluate, evaluateSafely, config, isTrusted }
