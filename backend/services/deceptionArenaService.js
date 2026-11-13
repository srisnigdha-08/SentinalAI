'use strict'
/**
 * Deception Arena: experiment records (create, cancel, read) and the local runner protocol (claim, append trial,
 * complete, fail). Reads never write. Every state change is a conditional update, so a cancelled or finished
 * experiment cannot be revived by a late runner call.
 */
const { v4: uuidv4 } = require('uuid')
const DeceptionExperiment = require('../models/DeceptionExperiment')
const HoneypotSession = require('../models/HoneypotSession')
const { DECEPTION_PROFILES, SERVABLE_DECEPTION_PROFILES } = require('../utils/deceptionProfiles')
const { parsePagination } = require('../utils/querySecurity')
const { SCENARIOS, evaluate } = require('../utils/deceptionArenaMetrics')

const STALE_MS = 10 * 60 * 1000
const MAX_EVENTS = 300
const LIST_FIELDS =
  'experimentId name description mode scenario baselinePersona adaptiveEnabled trialsPerStrategy maxTrialSeconds seed status cancelRequested createdBy startedAt completedAt heartbeatAt failureReason createdAt'

class ArenaError extends Error {
  constructor(message, status = 400) {
    super(message)
    this.status = status
  }
}

const runnerEnabled = () => String(process.env.DECEPTION_ARENA_RUNNER_ENABLED || '').toLowerCase() === 'true'
const event = (type, detail = '') => ({ type, at: new Date(), detail: String(detail).slice(0, 300) })
const intIn = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null)
const stalled = (e) =>
  e.status === 'RUNNING' && (!e.heartbeatAt || Date.now() - new Date(e.heartbeatAt).getTime() > STALE_MS)

function validateConfig(body = {}) {
  const errors = []
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  if (name.length < 3 || name.length > 80) errors.push('name must be 3-80 characters')
  const description = body.description === undefined ? '' : body.description
  if (typeof description !== 'string' || description.length > 500)
    errors.push('description must be text up to 500 characters')
  if (typeof body.scenario !== 'string' || !SCENARIOS[body.scenario])
    errors.push('scenario must be one of the allowlisted scenarios')
  // Unsupported personas (windows_srv) cannot be a baseline: Cowrie could never serve them
  if (typeof body.baselinePersona !== 'string' || !SERVABLE_DECEPTION_PROFILES.includes(body.baselinePersona))
    errors.push('baselinePersona must be a servable persona')
  const trials = intIn(body.trialsPerStrategy, 1, 50)
  if (trials === null) errors.push('trialsPerStrategy must be an integer 1-50')
  const maxSec = body.maxTrialSeconds === undefined ? 600 : intIn(body.maxTrialSeconds, 30, 3600)
  if (maxSec === null) errors.push('maxTrialSeconds must be an integer 30-3600')
  const seed = body.seed === undefined ? Math.floor(Math.random() * 1e6) : intIn(body.seed, 0, 1e9)
  if (seed === null) errors.push('seed must be an integer 0-1000000000')
  if (body.adaptiveEnabled !== undefined && typeof body.adaptiveEnabled !== 'boolean')
    errors.push('adaptiveEnabled must be boolean')
  if (errors.length) throw Object.assign(new ArenaError('Invalid experiment configuration', 422), { errors })
  return {
    name,
    description: description.trim(),
    scenario: body.scenario,
    baselinePersona: body.baselinePersona,
    trialsPerStrategy: trials,
    maxTrialSeconds: maxSec,
    seed,
    adaptiveEnabled: body.adaptiveEnabled !== false,
  }
}

async function createExperiment(body, user) {
  const cfg = validateConfig(body)
  const doc = await DeceptionExperiment.create({
    ...cfg,
    experimentId: uuidv4(),
    createdBy: { email: user?.email || null, role: user?.role || null },
    events: [
      event('EXPERIMENT_CREATED', `${cfg.scenario}, ${cfg.trialsPerStrategy} trials per strategy, seed ${cfg.seed}`),
    ],
  })
  return doc.toObject()
}

async function cancelExperiment(experimentId, user) {
  const by = `by ${user?.email || 'user'}`
  // Not started yet, or a runner that stopped reporting: cancel outright.
  const direct = await DeceptionExperiment.findOneAndUpdate(
    {
      experimentId,
      $or: [
        { status: 'CREATED' },
        { status: 'RUNNING', $or: [{ heartbeatAt: null }, { heartbeatAt: { $lt: new Date(Date.now() - STALE_MS) } }] },
      ],
    },
    {
      $set: { status: 'CANCELLED', completedAt: new Date(), cancelRequested: true },
      $push: { events: event('EXPERIMENT_CANCELLED', by) },
    },
    { new: true }
  ).lean()
  if (direct) return direct
  // Running: ask the runner to stop after the current trial.
  const running = await DeceptionExperiment.findOneAndUpdate(
    { experimentId, status: 'RUNNING', cancelRequested: false },
    { $set: { cancelRequested: true }, $push: { events: event('CANCEL_REQUESTED', by) } },
    { new: true }
  ).lean()
  if (running) return running
  const exists = await DeceptionExperiment.exists({ experimentId })
  throw new ArenaError(exists ? 'Experiment is already finished or cancelling' : 'Not found', exists ? 409 : 404)
}

async function listExperiments(query = {}) {
  const { page, limit, skip } = parsePagination({
    page: query.page,
    limit: query.limit,
    defaultLimit: 20,
    maxLimit: 50,
  })
  const filter = {}
  if (typeof query.status === 'string' && DeceptionExperiment.STATUSES.includes(query.status))
    filter.status = query.status
  if (typeof query.scenario === 'string' && SCENARIOS[query.scenario]) filter.scenario = query.scenario
  const [total, rows] = await Promise.all([
    DeceptionExperiment.countDocuments(filter),
    DeceptionExperiment.aggregate([
      { $match: filter },
      { $sort: { createdAt: -1, _id: -1 } },
      { $skip: skip },
      { $limit: limit },
      {
        $project: {
          ...Object.fromEntries(LIST_FIELDS.split(' ').map((f) => [f, 1])),
          trialCount: { $size: '$trials' },
        },
      },
    ]),
  ])
  return {
    data: rows.map((r) => ({ ...r, stalled: stalled(r), kind: SCENARIOS[r.scenario]?.kind })),
    total,
    page,
    limit,
  }
}

async function getExperiment(experimentId) {
  const doc = await DeceptionExperiment.findOne({ experimentId }).lean()
  if (!doc) return null
  return { experiment: { ...doc, stalled: stalled(doc), kind: SCENARIOS[doc.scenario]?.kind }, results: evaluate(doc) }
}

/**
 * Recorded Cowrie sessions by the persona they were served under. Observational only: different attackers and
 * times, so it is never compared as if it were part of an experiment.
 */
async function observational() {
  const [byPersona, recent, unattributed] = await Promise.all([
    HoneypotSession.aggregate([
      { $match: { servedProfile: { $ne: null } } },
      {
        $group: {
          _id: '$servedProfile',
          sessions: { $sum: 1 },
          synthetic: { $sum: { $cond: [{ $regexMatch: { input: '$sessionId', regex: /^demo-/i } }, 1, 0] } },
          meanDuration: { $avg: '$durationSeconds' },
          meanCommands: { $avg: '$commandCount' },
        },
      },
      { $sort: { sessions: -1 } },
      { $limit: 10 },
    ]),
    HoneypotSession.find({ servedProfile: { $ne: null } })
      .select('sessionId servedProfile startTime durationSeconds commandCount status')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean(),
    HoneypotSession.countDocuments({ servedProfile: null }),
  ])
  return {
    byPersona: byPersona.map((p) => ({
      persona: p._id,
      sessions: p.sessions,
      synthetic: p.synthetic,
      meanDurationSeconds: p.meanDuration === null ? null : Math.round(p.meanDuration * 10) / 10,
      meanCommands: p.meanCommands === null ? null : Math.round(p.meanCommands * 10) / 10,
    })),
    recent,
    unattributed,
  }
}

// ---- Runner protocol (SENTINEL_KEY + DECEPTION_ARENA_RUNNER_ENABLED=true) ----
async function claim(experimentId, runnerVersion) {
  const doc = await DeceptionExperiment.findOneAndUpdate(
    { experimentId, status: 'CREATED', cancelRequested: false },
    {
      $set: { status: 'RUNNING', startedAt: new Date(), heartbeatAt: new Date() },
      $push: { events: event('RUN_STARTED', `runner ${String(runnerVersion || 'unknown').slice(0, 40)}`) },
    },
    { new: true }
  ).lean()
  if (!doc) throw new ArenaError('Experiment is not waiting to run', 409)
  const { scenario, baselinePersona, trialsPerStrategy, maxTrialSeconds, seed, adaptiveEnabled } = doc
  return { config: { scenario, baselinePersona, trialsPerStrategy, maxTrialSeconds, seed, adaptiveEnabled } }
}

function validateTrial(t, exp) {
  const bad = (m) => {
    throw new ArenaError(`Invalid trial: ${m}`, 422)
  }
  if (!t || typeof t !== 'object') bad('missing')
  if (!['STATIC', 'ADAPTIVE'].includes(t.strategy)) bad('strategy')
  if (t.strategy === 'ADAPTIVE' && !exp.adaptiveEnabled) bad('adaptive disabled')
  if (intIn(t.index, 0, exp.trialsPerStrategy - 1) === null) bad('index')
  if (!DECEPTION_PROFILES.includes(t.persona)) bad('persona')
  const commands = Array.isArray(t.commands) ? t.commands : bad('commands')
  if (commands.length > 50) bad('too many commands')
  const cleanCmds = commands.map((c) => {
    if (!c || typeof c.command !== 'string' || c.command.length > 200) bad('command')
    if (c.intent !== undefined && c.intent !== null && (typeof c.intent !== 'string' || c.intent.length > 40))
      bad('intent')
    return { command: c.command, intent: c.intent || null }
  })
  const dur = t.durationSeconds
  if (!(typeof dur === 'number' && Number.isFinite(dur) && dur >= 0 && dur <= exp.maxTrialSeconds))
    bad('durationSeconds')
  if (!DeceptionExperiment.TERMINATIONS.includes(t.termination)) bad('termination')
  if (!(typeof t.reward === 'number' && Number.isFinite(t.reward) && t.reward >= -10 && t.reward <= 20)) bad('reward')
  let decision = null
  if (t.strategy === 'ADAPTIVE') {
    const d = t.decision
    if (!d || typeof d !== 'object') bad('decision')
    for (const k of ['state', 'recommendedPersona', 'appliedPersona']) if (!DECEPTION_PROFILES.includes(d[k])) bad(k)
    if (d.appliedPersona !== t.persona) bad('appliedPersona must be the persona served')
    const q = d.qValues && typeof d.qValues === 'object' ? d.qValues : {}
    const qValues = {}
    for (const [k, v] of Object.entries(q)) {
      if (!DECEPTION_PROFILES.includes(k) || typeof v !== 'number' || !Number.isFinite(v)) bad('qValues')
      qValues[k] = v
    }
    decision = {
      state: d.state,
      recommendedPersona: d.recommendedPersona,
      appliedPersona: d.appliedPersona,
      explored: d.explored === true,
      policy: typeof d.policy === 'string' ? d.policy.slice(0, 20) : null,
      epsilon: typeof d.epsilon === 'number' && Number.isFinite(d.epsilon) ? d.epsilon : null,
      qValues,
    }
  } else if (t.persona !== exp.baselinePersona) bad('static trials must serve the baseline persona')
  const date = (v) => {
    const x = new Date(v)
    return Number.isNaN(x.getTime()) ? null : x
  }
  return {
    strategy: t.strategy,
    index: t.index,
    pairPosition: t.pairPosition === 1 ? 1 : 0,
    persona: t.persona,
    decision,
    durationSeconds: dur,
    commands: cleanCmds,
    loginSucceeded: typeof t.loginSucceeded === 'boolean' ? t.loginSucceeded : null,
    termination: t.termination,
    fingerprinted: t.fingerprinted === true,
    reward: t.reward,
    startedAt: date(t.startedAt),
    endedAt: date(t.endedAt),
  }
}

async function appendTrial(experimentId, trial) {
  const exp = await DeceptionExperiment.findOne({ experimentId })
    .select('status adaptiveEnabled trialsPerStrategy maxTrialSeconds baselinePersona cancelRequested')
    .lean()
  if (!exp) throw new ArenaError('Not found', 404)
  if (exp.status !== 'RUNNING') return { cancelRequested: true, accepted: false }
  const clean = validateTrial(trial, exp)
  const label = `${clean.strategy} #${clean.index + 1}: ${clean.persona}, ${clean.commands.length} commands, ${clean.termination}`
  // Idempotent: a retried delivery of the same (strategy, index) matches nothing and adds nothing.
  const updated = await DeceptionExperiment.findOneAndUpdate(
    {
      experimentId,
      status: 'RUNNING',
      trials: { $not: { $elemMatch: { strategy: clean.strategy, index: clean.index } } },
    },
    {
      $push: {
        trials: clean,
        events: {
          $each: [
            ...(clean.decision
              ? [
                  event(
                    'PERSONA_RECOMMENDED',
                    `${clean.decision.state} -> ${clean.decision.recommendedPersona}${clean.decision.explored ? ' (exploration)' : ''}; applied ${clean.decision.appliedPersona}`
                  ),
                ]
              : []),
            event('TRIAL_COMPLETED', label),
          ],
          $slice: -MAX_EVENTS,
        },
      },
      $set: { heartbeatAt: new Date() },
    },
    { new: true, projection: { cancelRequested: 1 } }
  ).lean()
  return { accepted: Boolean(updated), cancelRequested: Boolean((updated || exp).cancelRequested) }
}

function cleanProvenance(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw new ArenaError('provenance must be an object', 422)
  const text = JSON.stringify(p)
  if (text.length > 6000) throw new ArenaError('provenance too large', 422)
  return JSON.parse(text)
}

async function complete(experimentId, provenance) {
  const prov = cleanProvenance(provenance)
  const h = prov.qTableHashes
  const hashesOk = h && JSON.stringify(h.before) === JSON.stringify(h.after)
  const exp = await DeceptionExperiment.findOne({ experimentId, status: 'RUNNING' })
    .select('cancelRequested trials.strategy')
    .lean()
  if (!exp) throw new ArenaError('Experiment is not running', 409)
  const status = !hashesOk ? 'FAILED' : exp.cancelRequested || prov.cancelled ? 'CANCELLED' : 'COMPLETED'
  const doc = await DeceptionExperiment.findOneAndUpdate(
    { experimentId, status: 'RUNNING' },
    {
      $set: {
        status,
        provenance: prov,
        completedAt: new Date(),
        ...(hashesOk ? {} : { failureReason: 'Runner did not report unchanged Q-table hashes' }),
      },
      $push: {
        events: event(
          status === 'COMPLETED' ? 'RESULTS_AGGREGATED' : `RUN_${status}`,
          `${exp.trials.length} trials recorded`
        ),
      },
    },
    { new: true }
  ).lean()
  if (!doc) throw new ArenaError('Experiment is not running', 409)
  return { status }
}

async function fail(experimentId, reason) {
  const doc = await DeceptionExperiment.findOneAndUpdate(
    { experimentId, status: 'RUNNING' },
    {
      $set: {
        status: 'FAILED',
        completedAt: new Date(),
        failureReason: String(reason || 'Runner failed').slice(0, 500),
      },
      $push: { events: event('RUN_FAILED', String(reason || '').slice(0, 300)) },
    },
    { new: true }
  ).lean()
  if (!doc) throw new ArenaError('Experiment is not running', 409)
  return { status: 'FAILED' }
}

module.exports = {
  ArenaError,
  runnerEnabled,
  validateConfig,
  createExperiment,
  cancelExperiment,
  listExperiments,
  getExperiment,
  observational,
  claim,
  appendTrial,
  complete,
  fail,
  STALE_MS,
}
