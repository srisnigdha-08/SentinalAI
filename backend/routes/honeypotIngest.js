const express = require('express')
const router = express.Router()
const { sendSuccess, sendError } = require('../utils/apiResponse')
const { isValidIP, parseDate } = require('../utils/querySecurity')
const logger = require('../utils/logger')
const { redactCapturedCredentials } = require('../utils/redact')
const { DECEPTION_PROFILES } = require('../utils/deceptionProfiles')

const { isHoneypotKey } = require('../utils/apiKeys')

/**
 * H3: optional binding of the honeypot key to the honeypot host(s). With HONEYPOT_ALLOWED_SOURCES set
 * ("203.0.113.5,10.0.66.0/24"), a request carrying the key from any other address is refused, so a leaked
 * key cannot be replayed from elsewhere. req.ip honours the backend's trust-proxy setting.
 */
const allowedSources = () =>
  String(process.env.HONEYPOT_ALLOWED_SOURCES || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

const ipv4ToInt = (ip) => ip.split('.').reduce((n, o) => (n << 8) + (parseInt(o, 10) & 255), 0) >>> 0
const sourceMatches = (ip, rule) => {
  const addr = String(ip || '').replace(/^::ffff:/, '')
  if (!rule.includes('/')) return addr === rule.replace(/^::ffff:/, '')
  const [base, bits] = rule.split('/')
  const prefix = parseInt(bits, 10)
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr) || !/^\d+\.\d+\.\d+\.\d+$/.test(base) || !(prefix >= 0 && prefix <= 32))
    return false
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  return (ipv4ToInt(addr) & mask) === (ipv4ToInt(base) & mask)
}
const sourceAllowed = (ip) => {
  const rules = allowedSources()
  return rules.length === 0 || rules.some((rule) => sourceMatches(ip, rule))
}

// The honeypot host's own key only (L8): the AI engine's SENTINEL_KEY never needs these routes, and accepting
// it here widened what a leaked AI-engine key could do.
const internalAuth = (req, res, next) => {
  const key = req.headers['x-api-key']
  if (!key) return sendError(res, 'Missing API key', 401)
  if (!isHoneypotKey(key)) return sendError(res, 'Invalid API key', 401)
  if (!sourceAllowed(req.ip)) return sendError(res, 'Honeypot key not accepted from this address', 403)
  next()
}

/**
 * @openapi
 * /honeypot/ingest/check-block:
 *   get:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Query whether an IP is blocked or retrieve full blocklist
 *     security:
 *       - ApiKeyAuth: []
 *     parameters:
 *       - in: query
 *         name: ip
 *         schema:
 *           type: string
 *         description: Specific IP address to check
 *     responses:
 *       200:
 *         description: Block status or blocked IP list
 *       401:
 *         description: Invalid or missing API key
 */
router.get('/check-block', internalAuth, async (req, res, next) => {
  try {
    // The Cowrie blocker plugin polls this every 2 s: its pulls are the node's liveness signal (L4).
    require('../services/honeypotHeartbeat').beat()
    const { ip } = req.query
    const BlockedIP = require('../models/BlockedIP')
    if (ip !== undefined && ip !== null && ip !== '') {
      if (typeof ip !== 'string' || !isValidIP(ip.trim())) {
        return sendError(res, 'Invalid IP address format', 400)
      }
      const cleanIp = ip.trim()
      const blockedRecord = await BlockedIP.findOne({ ip: cleanIp })
      return sendSuccess(res, { blocked: !!blockedRecord, ip: cleanIp })
    }
    const allBlocked = await BlockedIP.find({}, 'ip').lean()
    sendSuccess(res, { blockedIPs: allBlocked.map((b) => b.ip) })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/deception/recommendation:
 *   get:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Persona the Q-learner recommends next, for honeypot/deception_rotator.py (honeypot key only)
 *     description: >
 *       Machine equivalent of GET /api/honeypot/deception/recommendation, so the rotator on the honeypot host
 *       needs only HONEYPOT_API_KEY instead of an admin login.
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Active profile and recommended next profile
 *       503:
 *         description: AI engine unreachable
 */
router.get('/deception/recommendation', internalAuth, async (req, res, next) => {
  try {
    const honeypotService = require('../services/honeypotService')
    const active = await honeypotService.getActiveProfile()
    // RL-001: the persisted pending decision for this persona (drawn once), not a fresh draw per request
    const current = await require('../services/deceptionDecisionService').currentDecision(active.profile)
    if (!current) return sendError(res, 'AI engine unreachable', 503)
    // M7: a persona switch restarts Cowrie and drops live sessions; the rotator waits while any are open.
    const activeSessions = await require('../models/HoneypotSession')
      .countDocuments({ status: 'active' })
      .catch(() => null) // unknown: the rotator decides
    sendSuccess(res, {
      activeProfile: active.profile,
      nextProfile: current.decision.action,
      explored: current.decision.explored,
      policy: current.decision.policy,
      decisionId: current.decision.decisionId,
      decisionReused: current.reused,
      activeSessions,
    })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/deception/profile:
 *   put:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Record the persona the rotator applied (honeypot key only; one of the six profiles)
 *     security:
 *       - ApiKeyAuth: []
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
router.put('/deception/profile', internalAuth, async (req, res, next) => {
  try {
    const honeypotService = require('../services/honeypotService')
    const profile = typeof req.body?.profile === 'string' ? req.body.profile.trim() : ''
    const decisionId = typeof req.body?.decisionId === 'string' ? req.body.decisionId.trim() : ''
    const previous = await honeypotService.getActiveProfile()
    // With a decisionId the rotator reports applying (or keeping, when action == state) that decision; it must
    // still be pending for the persona being served. Without one this records a persona (legacy / manual).
    const decision = decisionId
      ? await require('../services/deceptionDecisionService').applyDecision(
          decisionId,
          profile,
          previous.profile,
          'honeypot-rotator'
        )
      : null
    await honeypotService.setActiveProfile(profile)
    await require('../utils/auditLogger').logAudit({
      action: 'SETTINGS_CHANGED',
      actor: { id: 'honeypot-rotator', role: 'service' },
      target: { identifier: 'deceptionActiveProfile', type: 'SystemSetting' },
      status: 'SUCCESS',
      details: {
        from: previous.profile,
        to: profile,
        via: 'honeypot ingest key',
        decisionId: decision?.decisionId || null,
      },
      ip: req.ip,
    })
    sendSuccess(
      res,
      { profile, previous: previous.profile, decisionId: decision?.decisionId || null },
      'Active deception profile recorded'
    )
  } catch (err) {
    next(err)
  }
})

// RL-001: the rotator could not serve a decision (restart failed; it restored cowrie.cfg). Honeypot key only.
router.post('/deception/decision/:decisionId/fail', internalAuth, async (req, res, next) => {
  try {
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : 'apply failed'
    const decision = await require('../services/deceptionDecisionService').failDecision(
      String(req.params.decisionId),
      reason
    )
    sendSuccess(res, { decisionId: decision.decisionId, status: decision.status }, 'Decision marked failed')
  } catch (err) {
    next(err)
  }
})

// Accepted honeypot events by type, on the backend's /metrics (Phase 5 monitoring).
const countEvent = (type) =>
  require('../utils/metrics').inc('sentinel_honeypot_events_total', 'Honeypot events accepted by type', { type })

const EVENT_TYPES = [
  'SESSION_OPENED',
  'COMMAND_INPUT',
  'COMMAND_FAILED',
  'FILE_DOWNLOAD',
  'FILE_UPLOAD',
  'TUNNEL_REQUEST',
  'SESSION_CLOSED',
  'CLIENT_KEX',
]

const getCollector = () => {
  try {
    return require('../../honeypot/collectors/session_collector')
  } catch {
    const error = new Error('Honeypot collector unavailable')
    error.statusCode = 503
    throw error
  }
}

const telemetryError = (data, eventType) => {
  if (!data || typeof data.sessionId !== 'string' || !data.sessionId || data.sessionId.length > 128)
    return 'Valid sessionId is required'
  if (eventType !== 'CLIENT_KEX' && (typeof data.sourceIP !== 'string' || !isValidIP(data.sourceIP)))
    return 'Valid sourceIP is required'
  // Optional de-duplication id of the Cowrie event (log_parser.event_id / sentinel_output.event_id)
  if (data.eventId !== undefined && (typeof data.eventId !== 'string' || !/^[0-9a-f]{8,64}$/.test(data.eventId)))
    return 'eventId must be a hex string'
  if (data.clientVersion !== undefined && (typeof data.clientVersion !== 'string' || data.clientVersion.length > 256))
    return 'clientVersion must be a string of at most 256 characters'
  // Persona the honeypot reports it served (log_parser.served_persona); one of the six profiles.
  if (data.servedProfile !== undefined && !DECEPTION_PROFILES.includes(data.servedProfile))
    return 'servedProfile must be one of the deception profiles'
  if (data.ttylog !== undefined) {
    const t = data.ttylog
    if (
      !t ||
      typeof t !== 'object' ||
      typeof t.sha256 !== 'string' ||
      !/^[0-9a-f]{64}$/.test(t.sha256) ||
      !Number.isFinite(t.size) ||
      t.size < 0 ||
      (t.path !== undefined && (typeof t.path !== 'string' || t.path.length > 256))
    )
      return 'ttylog must be {sha256 (64 hex), size, path}'
  }
  if (['COMMAND_INPUT', 'COMMAND_FAILED'].includes(eventType)) {
    if (typeof data.command !== 'string' || !data.command) return 'Nonempty command is required'
    if (data.command.length > 2048) return 'Command length exceeds maximum of 2048 characters'
  }
  if (eventType === 'FILE_DOWNLOAD') {
    if (typeof data.url !== 'string' || !data.url) return 'Download URL is required'
    if (data.url.length > 2048) return 'Download URL exceeds maximum of 2048 characters'
  }
  if (eventType === 'FILE_UPLOAD') {
    if (typeof data.filename !== 'string' || !data.filename || data.filename.length > 1024)
      return 'Upload filename is required (at most 1024 characters)'
    if (data.sha256 !== undefined && (typeof data.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(data.sha256)))
      return 'sha256 must be 64 hex characters'
  }
  if (eventType === 'TUNNEL_REQUEST') {
    if (typeof data.dstIP !== 'string' || !data.dstIP || data.dstIP.length > 255) return 'dstIP is required'
    if (!Number.isInteger(data.dstPort) || data.dstPort < 0 || data.dstPort > 65535) return 'dstPort must be 0-65535'
  }
  return null
}

/**
 * @openapi
 * /honeypot/ingest:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Ingest honeypot event telemetry from daemon/collector
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - eventType
 *             properties:
 *               eventType:
 *                 type: string
 *                 enum: [SESSION_OPENED, COMMAND_INPUT, COMMAND_FAILED, FILE_DOWNLOAD, FILE_UPLOAD, TUNNEL_REQUEST, SESSION_CLOSED, CLIENT_KEX]
 *     responses:
 *       200:
 *         description: Telemetry ingested successfully
 */
router.post('/', internalAuth, async (req, res, next) => {
  try {
    const { eventType, ...data } = req.body || {}
    if (!EVENT_TYPES.includes(eventType)) return sendError(res, 'Unsupported honeypot eventType', 400)
    const invalid = telemetryError(data, eventType)
    if (invalid) return sendError(res, invalid, 400)

    // Redact raw credentials before ingestion/storage
    if (Array.isArray(data.credentials)) {
      data.credentials = redactCapturedCredentials(data.credentials)
    }
    const io = req.app.get('io')
    const c = getCollector()
    let result
    if (c) {
      if (eventType === 'SESSION_OPENED') result = await c.onSessionOpened(data, io)
      else if (eventType === 'COMMAND_INPUT')
        result = await c.onCommandReceived({ ...data, intent: c.classifyIntent(data.command || '') }, io)
      // M1: a failed command marks the stored one; it is not a second command.
      else if (eventType === 'COMMAND_FAILED') result = await c.onCommandFailed(data, io)
      else if (eventType === 'FILE_UPLOAD') result = await c.onFileUpload(data, io)
      else if (eventType === 'TUNNEL_REQUEST') result = await c.onTunnelRequest(data, io)
      else if (eventType === 'FILE_DOWNLOAD') result = await c.onFileDownload(data, io)
      else if (eventType === 'SESSION_CLOSED') result = await c.onSessionClosed(data, io)
      else if (eventType === 'CLIENT_KEX') result = await c.onClientKex(data, io)
    }
    if (!result) return sendError(res, 'Honeypot session not found or event not persisted', 404)
    countEvent(eventType)
    sendSuccess(res, { received: true, eventType })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/flow:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Live detection for one captured network flow (sniffer --detect)
 *     description: >
 *       Runs the full detection pipeline (AI engine prediction, AIPrediction, ThreatLog/alert at or above
 *       the alert line, dashboard push). Only known numeric flow fields are forwarded.
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [sourceIP]
 *             properties:
 *               sourceIP: { type: string }
 *               destinationIP: { type: string }
 *               timestamp: { type: string, format: date-time }
 *     responses:
 *       200:
 *         description: Prediction stored and pushed
 *       400:
 *         description: Invalid IP or too few flow fields
 */
router.post('/flow', internalAuth, async (req, res, next) => {
  try {
    const { FLOW_FIELDS, MIN_FLOW_FIELDS, parseFlowFields } = require('../utils/flowFields')
    const body = req.body || {}
    if (typeof body.sourceIP !== 'string' || !isValidIP(body.sourceIP.trim()))
      return sendError(res, 'Valid sourceIP is required', 400)
    const record = { sourceIP: body.sourceIP.trim() }
    if (typeof body.destinationIP === 'string' && isValidIP(body.destinationIP.trim()))
      record.destinationIP = body.destinationIP.trim()
    if (body.timestamp && parseDate(body.timestamp)) record.timestamp = parseDate(body.timestamp).toISOString()
    const { fields, invalid } = parseFlowFields(body)
    if (invalid.length > 0) {
      // An invalid value must not reach the engine as a missing field, where it would be replaced by a default.
      const metrics = require('../utils/metrics')
      for (const field of invalid)
        metrics.inc('sentinel_flow_ingest_rejected_total', 'Flow fields rejected as invalid numbers', { field })
      logger.warn(`[Honeypot Ingest] Flow rejected, invalid numeric field(s): ${invalid.join(', ')}`)
      return sendError(res, `Invalid numeric value for: ${invalid.join(', ')}`, 400)
    }
    Object.assign(record, fields)
    if (Object.keys(record).filter((k) => FLOW_FIELDS.includes(k)).length < MIN_FLOW_FIELDS)
      return sendError(res, `At least ${MIN_FLOW_FIELDS} numeric flow fields are required`, 400)

    const result = await require('../services/aiEngineService').runFullPipeline(record, req.app.get('io'))
    sendSuccess(res, {
      predictedClass: result.predictedClass,
      threatScore: result.threatScore,
      action: result.action,
      predictionId: result._id,
    })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/match-session:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Match incoming connection to active honeypot session
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sourceIP
 *               - sourcePort
 *               - startTime
 *             properties:
 *               sourceIP:
 *                 type: string
 *               sourcePort:
 *                 type: integer
 *               startTime:
 *                 type: string
 *                 format: date-time
 *     responses:
 *       200:
 *         description: Matching result
 */
router.post('/match-session', internalAuth, async (req, res, next) => {
  try {
    const { sourceIP, sourcePort, startTime } = req.body || {}
    if (!sourceIP || typeof sourceIP !== 'string' || !isValidIP(sourceIP.trim())) {
      return sendError(res, 'Valid sourceIP is required', 400)
    }
    const cleanPort = parseInt(sourcePort, 10)
    if (isNaN(cleanPort) || cleanPort < 1 || cleanPort > 65535) {
      return sendError(res, 'Valid sourcePort is required', 400)
    }
    const targetTime = parseDate(startTime)
    if (!targetTime) {
      return sendError(res, 'Valid startTime is required', 400)
    }
    const cleanIP = sourceIP.trim()
    const HoneypotSession = require('../models/HoneypotSession')
    const sessions = await HoneypotSession.find({ sourceIP: cleanIP, sourcePort: cleanPort })
      .sort({ startTime: -1 })
      .limit(20)
    let matched = null
    let minDiff = Infinity
    for (const s of sessions) {
      if (!s.startTime) continue
      const diff = Math.abs(s.startTime.getTime() - targetTime.getTime()) / 1000
      if (diff <= 5.0 && diff < minDiff) {
        minDiff = diff
        matched = s
      }
    }
    if (matched) {
      return sendSuccess(res, {
        matched: true,
        sessionId: matched.sessionId,
        aiClassification: matched.aiClassification || null,
      })
    }
    return sendSuccess(res, { matched: false })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/command:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Ingest single honeypot command execution
 *     security:
 *       - ApiKeyAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - sessionId
 *               - command
 *             properties:
 *               sessionId:
 *                 type: string
 *               command:
 *                 type: string
 *     responses:
 *       200:
 *         description: Command ingested and scored
 */
router.post('/command', internalAuth, async (req, res, next) => {
  try {
    const invalid = telemetryError(req.body, 'COMMAND_INPUT')
    if (invalid) return sendError(res, invalid, 400)
    const c = getCollector()
    // Intent and malware flags are derived server-side; caller-supplied values are not trusted.
    const intent = c ? c.classifyIntent(req.body.command) : 'UNKNOWN'
    const data = { ...req.body, intent, isMalware: intent === 'MALWARE_DOWNLOAD' }
    const s = c ? await c.onCommandReceived(data, req.app.get('io')) : null
    if (!s) return sendError(res, 'Honeypot session not found', 404)
    countEvent('COMMAND_INPUT')
    sendSuccess(res, { received: true, deceptionScore: s?.deceptionScore })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/download:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Ingest file download telemetry from honeypot session
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Download event processed
 */
router.post('/download', internalAuth, async (req, res, next) => {
  try {
    const invalid = telemetryError(req.body, 'FILE_DOWNLOAD')
    if (invalid) return sendError(res, invalid, 400)
    const c = getCollector()
    const session = await c.onFileDownload(req.body, req.app.get('io'))
    if (!session) return sendError(res, 'Honeypot session not found', 404)
    countEvent('FILE_DOWNLOAD')
    sendSuccess(res, { received: true })
  } catch (err) {
    next(err)
  }
})

/**
 * @openapi
 * /honeypot/ingest/close:
 *   post:
 *     tags:
 *       - Honeypot Ingest
 *     summary: Ingest session closure event from collector
 *     security:
 *       - ApiKeyAuth: []
 *     responses:
 *       200:
 *         description: Session closed event processed
 */
router.post('/close', internalAuth, async (req, res, next) => {
  try {
    const invalid = telemetryError(req.body, 'SESSION_CLOSED')
    if (invalid) return sendError(res, invalid, 400)
    const c = getCollector()
    const s = c ? await c.onSessionClosed(req.body, req.app.get('io')) : null
    if (!s) return sendError(res, 'Honeypot session not found', 404)
    countEvent('SESSION_CLOSED')
    sendSuccess(res, { received: true, durationSeconds: s?.durationSeconds })
  } catch (err) {
    next(err)
  }
})

module.exports = router
