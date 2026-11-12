/**
 * Persona-rotation decisions (RL-001). The learner is asked for a recommendation only when no decision is
 * pending for the persona being served; every caller (rotator, its second request, the Honeypot Analytics page,
 * a second rotator) then gets the same decisionId until it is applied, acknowledged ("keep"), failed or superseded.
 * The learning policy itself is unchanged: the draw is still the engine's epsilon-greedy / UCB1 choice, and the Q
 * update is still credited to the persona each session was actually served (servedProfile).
 */
const crypto = require('crypto')
const DeceptionDecision = require('../models/DeceptionDecision')

const ttlMs = () => (parseInt(process.env.DECEPTION_DECISION_TTL_MINUTES, 10) || 120) * 60000
const close = (status, extra = {}) => ({ $set: { status, closedAt: new Date(), ...extra }, $unset: { pendingLock: 1 } })
const conflict = (message) => Object.assign(new Error(message), { statusCode: 409 })

/** The pending decision for `activeProfile`, drawing (and persisting) one if there is none. null: engine down. */
async function currentDecision(
  activeProfile,
  { recommend = require('./aiEngineService').getDeceptionRecommendation } = {}
) {
  // A pending decision drawn for another persona (someone recorded a different one) or too old is never applied
  await DeceptionDecision.updateMany(
    {
      status: 'PENDING',
      $or: [{ state: { $ne: activeProfile } }, { createdAt: { $lt: new Date(Date.now() - ttlMs()) } }],
    },
    close('SUPERSEDED')
  )
  const existing = await DeceptionDecision.findOne({ status: 'PENDING', state: activeProfile }).lean()
  if (existing) return { decision: existing, reused: true }
  const rec = await recommend(activeProfile)
  if (!rec) return null
  try {
    const created = await DeceptionDecision.create({
      decisionId: crypto.randomUUID(),
      state: activeProfile,
      action: rec.nextProfile,
      explored: Boolean(rec.explored),
      policy: rec.policy || 'q_learning',
      provenance: rec.learnerStats?.provenance || null,
      pendingLock: 'PENDING',
    })
    return { decision: created.toObject(), reused: false }
  } catch (err) {
    // A concurrent caller persisted its draw first: use that one (this draw is discarded; it changed nothing)
    if (err?.code !== 11000) throw err
    const winner = await DeceptionDecision.findOne({ status: 'PENDING' }).lean()
    if (!winner) throw err
    return { decision: winner, reused: true }
  }
}

/**
 * Marks a pending decision applied (the rotator served `profile`, or kept the current persona when the decision
 * said so). Compare-and-set: it must still be PENDING, drawn for `currentProfile`, and `profile` must be its action.
 */
async function applyDecision(decisionId, profile, currentProfile, appliedBy) {
  const updated = await DeceptionDecision.findOneAndUpdate(
    { decisionId, status: 'PENDING', state: currentProfile, action: profile },
    close('APPLIED', { appliedProfile: profile, appliedAt: new Date(), appliedBy }),
    { new: true }
  ).lean()
  if (!updated) throw conflict('Decision is not pending for the current persona, or the profile is not its action')
  return updated
}

/** The rotator could not serve the decision (restart failed; cowrie.cfg was restored). */
async function failDecision(decisionId, reason) {
  const updated = await DeceptionDecision.findOneAndUpdate(
    { decisionId, status: 'PENDING' },
    close('FAILED', { failureReason: String(reason || 'apply failed').slice(0, 500) }),
    { new: true }
  ).lean()
  if (!updated) throw conflict('Decision is not pending')
  return updated
}

const view = (d) =>
  d && {
    decisionId: d.decisionId,
    state: d.state,
    action: d.action,
    explored: d.explored,
    status: d.status,
    createdAt: d.createdAt,
  }

/**
 * Read-only snapshot for the Honeypot Analytics "Adaptive Deception" panel (its Refresh button). Unlike
 * currentDecision it never asks the learner for a draw and writes nothing: it reports the pending decision if
 * one exists, the most recent closed one (applied, failed, superseded/expired), how many sessions have been
 * scored (real) or skipped (synthetic demo-*), and persona policy v2's shadow evidence, which is never applied.
 */
async function status(activeProfile) {
  const HoneypotSession = require('../models/HoneypotSession')
  const syntheticId = /^demo-/i
  const [pending, lastClosed, scored, synthetic, scoringPending, shadowCount, shadowAgree, latestShadow] =
    await Promise.all([
      DeceptionDecision.findOne({ status: 'PENDING' }).lean(),
      DeceptionDecision.findOne({ status: { $ne: 'PENDING' } })
        .sort({ closedAt: -1, updatedAt: -1 })
        .lean(),
      HoneypotSession.countDocuments({ deceptionScoredAt: { $ne: null }, sessionId: { $not: syntheticId } }),
      HoneypotSession.countDocuments({ sessionId: syntheticId }),
      HoneypotSession.countDocuments({ deceptionScoringPending: true }),
      HoneypotSession.countDocuments({ 'shadowPolicy.recommendation': { $ne: null } }),
      HoneypotSession.countDocuments({
        'shadowPolicy.recommendation': { $ne: null },
        $expr: { $eq: ['$shadowPolicy.recommendation', '$recommendedProfile'] },
      }),
      HoneypotSession.findOne({ 'shadowPolicy.recommendation': { $ne: null } })
        .sort({ deceptionScoredAt: -1, _id: -1 })
        .select('shadowPolicy deceptionScoredAt recommendedProfile deceptionPolicy')
        .lean(),
    ])
  const closedView = (d) =>
    d && {
      ...view(d),
      // SUPERSEDED covers both "expired (TTL)" and "persona changed before it was applied"
      appliedProfile: d.appliedProfile || null,
      closedAt: d.closedAt || null,
      failureReason: d.failureReason || null,
    }
  return {
    activeProfile,
    pendingDecision: pending ? { ...view(pending), forActivePersona: pending.state === activeProfile } : null,
    lastClosedDecision: closedView(lastClosed),
    learning: {
      scoredRealSessions: scored,
      syntheticSessionsSkipped: synthetic,
      sessionsAwaitingScoring: scoringPending,
    },
    shadow: {
      mode: 'shadow (recorded only, never applied)',
      sessionsWithEvidence: shadowCount,
      agreementsWithActivePolicy: shadowAgree,
      latest: latestShadow
        ? {
            version: latestShadow.shadowPolicy?.version || null,
            mode: latestShadow.shadowPolicy?.mode || null,
            recommendation: latestShadow.shadowPolicy?.recommendation || null,
            learned: latestShadow.shadowPolicy?.learned ?? null,
            activePolicy: latestShadow.deceptionPolicy || null,
            activeRecommendation: latestShadow.recommendedProfile || null,
            scoredAt: latestShadow.deceptionScoredAt || null,
          }
        : null,
    },
  }
}

module.exports = { currentDecision, applyDecision, failDecision, view, status }
