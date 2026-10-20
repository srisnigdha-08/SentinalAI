const express = require('express')
const router = express.Router()
const { sendSuccess, sendError } = require('../utils/apiResponse')
const { isValidIP, parseDate } = require('../utils/querySecurity')
const { redactCapturedCredentials } = require('../utils/redact')

const { isHoneypotKey, isSentinelKey } = require('../utils/apiKeys')

const internalAuth = (req, res, next) => {
  const key = req.headers['x-api-key']
  if (!key) return sendError(res, 'Missing API key', 401)
  if (!isHoneypotKey(key) && !isSentinelKey(key)) return sendError(res, 'Invalid API key', 401)
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
  if (['COMMAND_INPUT', 'COMMAND_FAILED'].includes(eventType)) {
    if (typeof data.command !== 'string' || !data.command) return 'Nonempty command is required'
    if (data.command.length > 2048) return 'Command length exceeds maximum of 2048 characters'
  }
  if (eventType === 'FILE_DOWNLOAD') {
    if (typeof data.url !== 'string' || !data.url) return 'Download URL is required'
    if (data.url.length > 2048) return 'Download URL exceeds maximum of 2048 characters'
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
 *                 enum: [SESSION_OPENED, COMMAND_INPUT, COMMAND_FAILED, FILE_DOWNLOAD, SESSION_CLOSED, CLIENT_KEX]
 *     responses:
 *       200:
 *         description: Telemetry ingested successfully
 */
router.post('/', internalAuth, async (req, res, next) => {
  try {
    const { eventType, ...data } = req.body || {}
    if (
      !['SESSION_OPENED', 'COMMAND_INPUT', 'COMMAND_FAILED', 'FILE_DOWNLOAD', 'SESSION_CLOSED', 'CLIENT_KEX'].includes(
        eventType
      )
    )
      return sendError(res, 'Unsupported honeypot eventType', 400)
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
      else if (['COMMAND_INPUT', 'COMMAND_FAILED'].includes(eventType))
        result = await c.onCommandReceived({ ...data, intent: c.classifyIntent(data.command || '') }, io)
      else if (eventType === 'FILE_DOWNLOAD') result = await c.onFileDownload(data, io)
      else if (eventType === 'SESSION_CLOSED') result = await c.onSessionClosed(data, io)
      else if (eventType === 'CLIENT_KEX') result = await c.onClientKex(data, io)
    }
    if (!result) return sendError(res, 'Honeypot session not found or event not persisted', 404)
    sendSuccess(res, { received: true, eventType })
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
    sendSuccess(res, { received: true, durationSeconds: s?.durationSeconds })
  } catch (err) {
    next(err)
  }
})

module.exports = router
