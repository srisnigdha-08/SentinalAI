'use strict'
const express = require('express')
const router = express.Router()
const svc = require('../services/deceptionArenaService')
const { protect, restrictTo } = require('../middleware/auth')
const { sendSuccess, sendError } = require('../utils/apiResponse')
const { isSentinelKey, isHoneypotKey } = require('../utils/apiKeys')
const { SCENARIOS, MIN_PAIRS_FOR_INTERVAL, LIVE_CAVEAT } = require('../utils/deceptionArenaMetrics')
const { logAudit } = require('../utils/auditLogger')

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const validId = (req, res, next) => (UUID.test(req.params.id) ? next() : sendError(res, 'Invalid experiment ID', 400))
const handle = (fn) => async (req, res, next) => {
  try {
    await fn(req, res)
  } catch (err) {
    if (err instanceof svc.ArenaError) return sendError(res, err.message, err.status, err.errors || null)
    next(err)
  }
}

/**
 * @openapi
 * /deception-arena/scenarios:
 *   get:
 *     tags: [Deception Arena]
 *     summary: Allowlisted experiment scenarios, personas and whether the local runner is enabled
 *     security: [{ BearerAuth: [] }]
 *     responses: { 200: { description: Scenario allowlist } }
 */
router.get(
  '/scenarios',
  protect,
  handle(async (req, res) =>
    sendSuccess(res, {
      scenarios: Object.entries(SCENARIOS).map(([id, s]) => ({ id, ...s })),
      personas: require('../utils/deceptionProfiles').SERVABLE_DECEPTION_PROFILES,
      runnerEnabled: svc.runnerEnabled(),
      minPairsForInterval: MIN_PAIRS_FOR_INTERVAL,
      liveCaveat: LIVE_CAVEAT,
      liveMode: {
        available: false,
        reason:
          'Scored live sessions update the deployed Q-table and persona changes restart Cowrie, so live trials cannot be isolated safely.',
      },
    })
  )
)

/**
 * @openapi
 * /deception-arena/observational:
 *   get:
 *     tags: [Deception Arena]
 *     summary: Recorded Cowrie sessions grouped by served persona (observational, not an experiment)
 *     security: [{ BearerAuth: [] }]
 *     responses: { 200: { description: Per-persona aggregates and recent sessions } }
 */
router.get(
  '/observational',
  protect,
  handle(async (req, res) => sendSuccess(res, await svc.observational()))
)

/**
 * @openapi
 * /deception-arena/experiments:
 *   get:
 *     tags: [Deception Arena]
 *     summary: Static-vs-Adaptive experiments (no trials), newest first
 *     security: [{ BearerAuth: [] }]
 *     responses: { 200: { description: Paginated experiments } }
 *   post:
 *     tags: [Deception Arena]
 *     summary: Create a bounded experiment from an allowlisted scenario (admin, analyst). Does not run anything.
 *     security: [{ BearerAuth: [] }]
 *     responses: { 201: { description: Created }, 422: { description: Invalid configuration } }
 */
router.get(
  '/experiments',
  protect,
  handle(async (req, res) => {
    const r = await svc.listExperiments(req.query)
    res.status(200).json({
      success: true,
      data: r.data,
      pagination: { total: r.total, page: r.page, limit: r.limit, pages: Math.ceil(r.total / r.limit) },
      timestamp: new Date().toISOString(),
    })
  })
)
router.post(
  '/experiments',
  protect,
  restrictTo('admin', 'analyst'),
  handle(async (req, res) => {
    const exp = await svc.createExperiment(req.body, req.user)
    await logAudit({
      action: 'DECEPTION_EXPERIMENT_CREATED',
      actor: req.user,
      target: { identifier: exp.experimentId, type: 'DeceptionExperiment' },
      status: 'SUCCESS',
      details: {
        event: 'deception_experiment_created',
        scenario: exp.scenario,
        trialsPerStrategy: exp.trialsPerStrategy,
      },
      ip: req.ip,
    }).catch(() => {})
    sendSuccess(res, { experiment: exp }, 'Created', 201)
  })
)

/**
 * @openapi
 * /deception-arena/experiments/{id}:
 *   get:
 *     tags: [Deception Arena]
 *     summary: One experiment with trials, metrics and deterministic conclusions
 *     security: [{ BearerAuth: [] }]
 *     parameters: [{ in: path, name: id, required: true, schema: { type: string } }]
 *     responses: { 200: { description: Experiment }, 404: { description: Not found } }
 */
router.get(
  '/experiments/:id',
  protect,
  validId,
  handle(async (req, res) => {
    const r = await svc.getExperiment(req.params.id)
    if (!r) return sendError(res, 'Not found', 404)
    sendSuccess(res, r)
  })
)

/**
 * @openapi
 * /deception-arena/experiments/{id}/cancel:
 *   post:
 *     tags: [Deception Arena]
 *     summary: Cancel a waiting experiment, or ask a running one to stop after its current trial (admin, analyst)
 *     security: [{ BearerAuth: [] }]
 *     parameters: [{ in: path, name: id, required: true, schema: { type: string } }]
 *     responses: { 200: { description: Cancelled or cancel requested }, 409: { description: Already finished } }
 */
router.post(
  '/experiments/:id/cancel',
  protect,
  restrictTo('admin', 'analyst'),
  validId,
  handle(async (req, res) => sendSuccess(res, { experiment: await svc.cancelExperiment(req.params.id, req.user) }))
)

// ---- Local runner protocol: SENTINEL_KEY only, and only with DECEPTION_ARENA_RUNNER_ENABLED=true ----
const runnerOnly = (req, res, next) => {
  const key = req.headers['x-api-key']
  if (!key) return sendError(res, 'Missing API key', 401)
  if (isHoneypotKey(key) && !isSentinelKey(key)) return sendError(res, 'This key may not run experiments', 403)
  if (!isSentinelKey(key)) return sendError(res, 'Invalid API key', 401)
  if (!svc.runnerEnabled())
    return sendError(
      res,
      'Deception Arena runner is disabled (set DECEPTION_ARENA_RUNNER_ENABLED=true in a local lab)',
      403
    )
  next()
}

/**
 * @openapi
 * /deception-arena/runner/{id}/{step}:
 *   post:
 *     tags: [Deception Arena]
 *     summary: Local runner protocol (claim, trials, complete, fail). SENTINEL_KEY and DECEPTION_ARENA_RUNNER_ENABLED=true.
 *     parameters:
 *       - { in: path, name: id, required: true, schema: { type: string } }
 *       - { in: path, name: step, required: true, schema: { type: string, enum: [claim, trials, complete, fail] } }
 *     responses: { 200: { description: OK }, 403: { description: Runner disabled }, 409: { description: Wrong state } }
 */
router.post(
  '/runner/:id/claim',
  runnerOnly,
  validId,
  handle(async (req, res) => sendSuccess(res, await svc.claim(req.params.id, req.body?.runnerVersion)))
)
router.post(
  '/runner/:id/trials',
  runnerOnly,
  validId,
  handle(async (req, res) => sendSuccess(res, await svc.appendTrial(req.params.id, req.body?.trial)))
)
router.post(
  '/runner/:id/complete',
  runnerOnly,
  validId,
  handle(async (req, res) => sendSuccess(res, await svc.complete(req.params.id, req.body?.provenance)))
)
router.post(
  '/runner/:id/fail',
  runnerOnly,
  validId,
  handle(async (req, res) => sendSuccess(res, await svc.fail(req.params.id, req.body?.reason)))
)

module.exports = router
