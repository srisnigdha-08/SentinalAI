const honeypotService = require('../services/honeypotService')
const alertService = require('../services/alertService')
const socketManager = require('../websocket/socketManager')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const logger = require('../utils/logger')
const { v4: uuidv4 } = require('uuid')
const { redactHoneypotSession, redactIP } = require('../utils/redact')
const sessionForRole = (session, role) => {
  return redactHoneypotSession(session, role || 'viewer')
}

const getSessions = async (req, res, next) => {
  try {
    const r = await honeypotService.findSessions(req.query)
    sendPaginated(
      res,
      r.data.map((session) => sessionForRole(session, req.user?.role)),
      r.total,
      r.page,
      r.limit
    )
  } catch (err) {
    next(err)
  }
}
const getSession = async (req, res, next) => {
  try {
    const s = await honeypotService.findSessionById(req.params.id)
    if (!s) return sendError(res, 'Not found', 404)
    sendSuccess(res, { session: sessionForRole(s, req.user?.role) })
  } catch (err) {
    next(err)
  }
}
const createSession = async (req, res, next) => {
  try {
    const { sourceIP, sourcePort, honeypotNode = 'SSH-COWRIE-01', protocol = 'SSH', geoLocation } = req.body
    const session = await honeypotService.createSession({
      sessionId: 'sess-' + uuidv4().split('-')[0],
      sourceIP,
      sourcePort,
      honeypotNode,
      protocol,
      geoLocation: geoLocation || {},
    })
    const alert = await alertService.createAlertFromSession(session)
    socketManager.emitHoneypotEvent('honeypot_session_opened', { sessionId: session.sessionId, sourceIP, honeypotNode })
    socketManager.emitNewAlert(alert)
    logger.info('[HP] Session: ' + session.sessionId + ' from ' + sourceIP)
    sendSuccess(res, { session }, 'Created', 201)
  } catch (err) {
    next(err)
  }
}
const addCommands = async (req, res, next) => {
  try {
    const { commands } = req.body || {}
    if (!Array.isArray(commands)) return sendError(res, 'commands must be array', 400)
    if (commands.length > 100) return sendError(res, 'commands array exceeds maximum length of 100', 400)
    const sanitizedCommands = commands
      .filter((c) => c && typeof c === 'object')
      .map((c) => ({
        command: typeof c.command === 'string' ? c.command.slice(0, 1000) : '',
        timestamp: c.timestamp ? new Date(c.timestamp) : new Date(),
        intent: typeof c.intent === 'string' ? c.intent.slice(0, 100) : undefined,
      }))
    const session = await honeypotService.appendCommands(req.params.id, sanitizedCommands)
    if (!session) return sendError(res, 'Not found', 404)
    socketManager.emitHoneypotEvent('honeypot_command', {
      sessionId: session.sessionId,
      sourceIP: session.sourceIP,
      command: sanitizedCommands[sanitizedCommands.length - 1]?.command,
      deceptionScore: session.deceptionScore,
    })
    sendSuccess(res, { session }, 'Commands recorded')
  } catch (err) {
    next(err)
  }
}
const closeSession = async (req, res, next) => {
  try {
    const session = await honeypotService.closeSession(req.params.id, { reclassify: req.body?.reclassify === true })
    if (!session) return sendError(res, 'Not found', 404)
    socketManager.emitHoneypotEvent('honeypot_session_closed', {
      sessionId: session.sessionId,
      sourceIP: session.sourceIP,
      durationSeconds: session.durationSeconds,
      deceptionScore: session.deceptionScore,
    })
    sendSuccess(res, { session }, 'Closed')
  } catch (err) {
    next(err)
  }
}
const getHoneypotAnalytics = async (req, res, next) => {
  try {
    const role = req.user?.role || 'viewer'
    const analytics = await honeypotService.getFullAnalytics()
    if (role === 'viewer') {
      if (Array.isArray(analytics?.intelligence?.topAttackers)) {
        analytics.intelligence.topAttackers = analytics.intelligence.topAttackers.map((a) => ({
          ...a,
          _id: redactIP(a._id),
        }))
      }
      if (Array.isArray(analytics?.charts?.topCommands)) {
        analytics.charts.topCommands = analytics.charts.topCommands.map((c) => ({
          ...c,
          _id: '[REDACTED_COMMAND]',
        }))
      }
    }
    sendSuccess(res, analytics)
  } catch (err) {
    next(err)
  }
}
const getNodes = async (req, res, next) => {
  try {
    sendSuccess(res, { nodes: await honeypotService.getNodeStatus() })
  } catch (err) {
    next(err)
  }
}
const getHoneypotStatus = async (req, res, next) => {
  try {
    const HoneypotSession = require('../models/HoneypotSession')
    const total = await HoneypotSession.countDocuments()
    const latest = await HoneypotSession.findOne().sort({ createdAt: -1 })
    const now = Date.now()
    const lastIngestTime = latest ? new Date(latest.createdAt).getTime() : null
    const recentTelemetry = lastIngestTime ? now - lastIngestTime < 15 * 60 * 1000 : false
    // L4: the Cowrie blocker's deny-list polls show the daemon is up even when no attacker is connecting.
    const daemon = require('../services/honeypotHeartbeat').status()
    const isLive = recentTelemetry || daemon.liveness === 'online'

    sendSuccess(res, {
      collector: 'available',
      liveTelemetry: isLive,
      status: isLive ? 'active' : 'idle',
      daemon,
      reason: recentTelemetry
        ? 'Live honeypot telemetry stream detected within last 15 minutes'
        : daemon.liveness === 'online'
          ? 'Cowrie connected (blocker plugin polling); no sessions in the last 15 minutes'
          : 'No active Cowrie daemon connected on host',
      lastIngestTimestamp: latest ? latest.createdAt : null,
      totalSessionsIngested: total,
      liveTelemetryBlocked: !isLive,
      blockReason: isLive ? null : 'No Cowrie heartbeat and no telemetry in the last 15 minutes',
    })
  } catch (err) {
    next(err)
  }
}
module.exports = {
  getSessions,
  getSession,
  createSession,
  addCommands,
  closeSession,
  getHoneypotAnalytics,
  getNodes,
  getHoneypotStatus,
}
