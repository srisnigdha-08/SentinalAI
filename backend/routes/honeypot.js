const express = require('express')
const router = express.Router()
const {
  getSessions,
  getSession,
  createSession,
  addCommands,
  closeSession,
  getHoneypotAnalytics,
  getNodes,
  getHoneypotStatus,
} = require('../controllers/honeypotController')
const { protect, restrictTo, requirePermission } = require('../middleware/auth')
const { validateObjectId } = require('../middleware/validate')
const honeypotService = require('../services/honeypotService')
const { sendSuccess, sendError } = require('../utils/apiResponse')
const { logAudit } = require('../utils/auditLogger')

router.use(protect)

router.get('/status', getHoneypotStatus)

/**
 * @openapi
 * /honeypot/analytics:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Retrieve aggregate analytics and deception metrics for honeypot deployments
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Honeypot analytics retrieved successfully
 */
router.get('/analytics', getHoneypotAnalytics)

/**
 * @openapi
 * /honeypot/nodes:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: List all active honeypot deployment nodes
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: List of honeypot nodes
 */
router.get('/nodes', getNodes)

/**
 * @openapi
 * /honeypot/deception/profile:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Deception persona Cowrie is recorded as serving (the Q-learner's action)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Active profile and where it was resolved from (setting, env or default)
 *   put:
 *     tags:
 *       - Honeypot
 *     summary: Record the persona applied with honeypot/switch_profile.py (does not reconfigure Cowrie)
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [profile]
 *             properties:
 *               profile:
 *                 type: string
 *                 enum: [ubuntu_22, debian_11, centos_7, windows_srv, aws_ec2, raspberry_pi]
 *     responses:
 *       200:
 *         description: Profile recorded
 *       400:
 *         description: Unknown profile
 */
router.get('/deception/profile', async (req, res, next) => {
  try {
    sendSuccess(res, { ...(await honeypotService.getActiveProfile()), profiles: honeypotService.DECEPTION_PROFILES })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/deception/recommendation:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Persona the Q-learner recommends serving next (applied by honeypot/deception_rotator.py)
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Active profile and the recommended next profile
 *       503:
 *         description: AI engine unreachable
 */
router.get('/deception/recommendation', restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    const active = await honeypotService.getActiveProfile()
    // RL-001: viewing this page shows the pending decision; it no longer draws a new one on every view
    const current = await require('../services/deceptionDecisionService').currentDecision(active.profile)
    if (!current) return sendError(res, 'AI engine unreachable', 503)
    sendSuccess(res, {
      activeProfile: active.profile,
      nextProfile: current.decision.action,
      explored: current.decision.explored,
      policy: current.decision.policy,
      decisionId: current.decision.decisionId,
      decisionReused: current.reused,
      // Seed episodes (synthetic warm start) vs sessions scored here, as of the draw; null from older engines.
      provenance: current.decision.provenance || null,
      // M7: the rotator does not restart Cowrie while attackers are connected.
      activeSessions: await require('../models/HoneypotSession')
        .countDocuments({ status: 'active' })
        .catch(() => null),
    })
  } catch (err) {
    next(err)
  }
})

router.put('/deception/profile', requirePermission('settings:write'), async (req, res, next) => {
  try {
    const profile = typeof req.body?.profile === 'string' ? req.body.profile.trim() : ''
    const decisionId = typeof req.body?.decisionId === 'string' ? req.body.decisionId.trim() : ''
    const previous = await honeypotService.getActiveProfile()
    if (decisionId) {
      // RL-001: recording a specific decision (deprecated login rotator); compare-and-set as on the ingest route
      await require('../services/deceptionDecisionService').applyDecision(
        decisionId,
        profile,
        previous.profile,
        req.user?.email || 'user'
      )
    }
    await honeypotService.setActiveProfile(profile)
    await logAudit({
      action: 'SETTINGS_CHANGED',
      actor: req.user,
      target: { identifier: 'deceptionActiveProfile', type: 'SystemSetting' },
      status: 'SUCCESS',
      details: { from: previous.profile, to: profile },
      ip: req.ip,
    })
    sendSuccess(res, { profile, previous: previous.profile }, 'Active deception profile recorded')
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/sessions:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Query honeypot attacker sessions with pagination and filters
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *           default: 1
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 20
 *     responses:
 *       200:
 *         description: Paginated honeypot sessions
 *   post:
 *     tags:
 *       - Honeypot
 *     summary: Create a honeypot session record
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sessionId
 *               - sourceIP
 *             properties:
 *               sessionId:
 *                 type: string
 *               sourceIP:
 *                 type: string
 *     responses:
 *       201:
 *         description: Honeypot session created
 */
/**
 * @openapi
 * /honeypot/attackers:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Attacker profiles grouped by SSH client fingerprint (HASSH)
 *     description: Sessions, source IPs, client banners, usernames tried, commands and logins per HASSH.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: query
 *         name: days
 *         schema:
 *           type: integer
 *           default: 30
 *     responses:
 *       200:
 *         description: Attacker profiles, most active first
 */
router.get('/attackers', restrictTo('admin', 'analyst'), async (req, res, next) => {
  try {
    sendSuccess(res, { profiles: await honeypotService.getAttackerProfiles({ days: req.query.days }) })
  } catch (err) {
    next(err)
  }
})

router.route('/sessions').get(getSessions).post(restrictTo('admin', 'analyst'), createSession)

/**
 * @openapi
 * /honeypot/sessions/{id}:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Get single honeypot session details by ID
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session details retrieved
 *       404:
 *         description: Session not found
 */
router.route('/sessions/:id').get(validateObjectId, getSession)

/**
 * @openapi
 * /honeypot/sessions/{id}/timeline:
 *   get:
 *     tags:
 *       - Honeypot
 *     summary: Read-only evidence for the Attack Time Machine replay of one recorded session
 *     description: >
 *       The session, per-command MITRE mappings, and only the records that reference this session or its linked
 *       threat (no source-IP correlation). Containment records are returned to admin and analyst only; viewers get
 *       the standard honeypot redaction. Never writes and never triggers any action.
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Evidence bundle
 *       404:
 *         description: Session not found
 */
router.get('/sessions/:id/timeline', validateObjectId, async (req, res, next) => {
  try {
    const evidence = await require('../services/attackTimelineService').getSessionEvidence(
      req.params.id,
      req.user?.role || 'viewer'
    )
    if (!evidence) return sendError(res, 'Not found', 404)
    sendSuccess(res, evidence)
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/sessions/{id}/commands:
 *   post:
 *     tags:
 *       - Honeypot
 *     summary: Append attacker commands to an active honeypot session
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               commands:
 *                 type: array
 *                 items:
 *                   type: object
 *     responses:
 *       200:
 *         description: Commands appended successfully
 */
router.post('/sessions/:id/commands', validateObjectId, restrictTo('admin', 'analyst'), addCommands)

/**
 * @openapi
 * /honeypot/sessions/{id}/close:
 *   put:
 *     tags:
 *       - Honeypot
 *     summary: Close an active honeypot session and trigger AI evaluation
 *     description: Ordinary completed closes are idempotent. Explicit reclassification preserves closure time and existing containment.
 *     requestBody:
 *       required: false
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               reclassify: { type: boolean, default: false }
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Session closure attempt completed or previously completed record returned
 *       409:
 *         description: Analysis is in progress or a failed attempt requires review
 */
router.put('/sessions/:id/close', validateObjectId, restrictTo('admin', 'analyst'), closeSession)

module.exports = router
