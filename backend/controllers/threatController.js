const threatService = require('../services/threatService')
const alertService = require('../services/alertService')
const socketManager = require('../websocket/socketManager')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const logger = require('../utils/logger')
const { isValidIP, parsePagination } = require('../utils/querySecurity')
const getThreats = async (req, res, next) => {
  try {
    const r = await threatService.findThreats(req.query)
    sendPaginated(res, r.data, r.total, r.page, r.limit)
  } catch (err) {
    next(err)
  }
}
const getAnalytics = async (req, res, next) => {
  try {
    sendSuccess(res, await threatService.getDashboardAnalytics(), 'Analytics retrieved')
  } catch (err) {
    next(err)
  }
}
const getVectorTrend = async (req, res, next) => {
  try {
    const days = Math.min(Math.max(1, parseInt(req.query.days, 10) || 7), 90)
    const now = new Date()
    sendSuccess(res, {
      trend: await threatService.getAttackVectorTrend(days, now),
      reporting: require('../utils/reportingTime').metadata(days, now),
    })
  } catch (err) {
    next(err)
  }
}
const getRecent = async (req, res, next) => {
  try {
    sendSuccess(res, { threats: await threatService.getRecentThreats(parseInt(req.query.limit) || 10) })
  } catch (err) {
    next(err)
  }
}
const getThreat = async (req, res, next) => {
  try {
    const t = await threatService.findThreatById(req.params.id)
    if (!t) return sendError(res, 'Not found', 404)
    sendSuccess(res, { threat: t })
  } catch (err) {
    next(err)
  }
}
const ALLOWED_THREAT_STATUSES = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED']
const ALLOWED_THREAT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const createThreat = async (req, res, next) => {
  try {
    const { sourceIP, attackType, severity } = req.body || {}
    if (!sourceIP || typeof sourceIP !== 'string' || !isValidIP(sourceIP.trim())) {
      return sendError(res, 'Valid sourceIP is required', 400)
    }
    if (!attackType || typeof attackType !== 'string' || attackType.length > 100) {
      return sendError(res, 'Valid attackType is required', 400)
    }
    if (severity && (typeof severity !== 'string' || !ALLOWED_THREAT_SEVERITIES.includes(severity.toUpperCase()))) {
      return sendError(res, 'Invalid severity level', 400)
    }
    const cleanData = {
      ...req.body,
      sourceIP: sourceIP.trim(),
      attackType: attackType.trim(),
      severity: severity ? severity.toUpperCase() : 'MEDIUM',
    }
    const threat = await threatService.createThreat(cleanData)
    if (['CRITICAL', 'HIGH'].includes(threat.severity)) {
      const alert = await alertService.createAlertFromThreat(threat)
      socketManager.emitNewAlert(alert)
    }
    socketManager.emitNewThreat(threat)
    logger.info('Threat created: ' + threat.attackType + ' from ' + threat.sourceIP)
    sendSuccess(res, { threat }, 'Threat logged', 201)
  } catch (err) {
    next(err)
  }
}
const updateThreat = async (req, res, next) => {
  try {
    const allowed = ['status', 'notes', 'handledBy', 'autonomousAction']
    const updates = {}
    allowed.forEach((f) => {
      if (req.body[f] !== undefined) updates[f] = req.body[f]
    })
    if (updates.status !== undefined) {
      if (typeof updates.status !== 'string' || !ALLOWED_THREAT_STATUSES.includes(updates.status.toUpperCase())) {
        return sendError(res, 'Invalid threat status', 400)
      }
      updates.status = updates.status.toUpperCase()
    }
    if (updates.notes !== undefined) {
      if (typeof updates.notes !== 'string' || updates.notes.length > 1000) {
        return sendError(res, 'Notes must be a string up to 1000 characters', 400)
      }
    }
    const threat = await threatService.updateThreat(req.params.id, updates)
    if (!threat) return sendError(res, 'Not found', 404)
    socketManager.emitThreatUpdated(threat)
    sendSuccess(res, { threat }, 'Updated')
  } catch (err) {
    next(err)
  }
}
const blockIP = async (req, res, next) => {
  try {
    const threat = await threatService.blockThreatIP(req.params.id, req.user._id)
    if (!threat) return sendError(res, 'Not found', 404)
    const alert = await alertService.createAlert({
      title: 'IP Address Blocked',
      message: 'IP ' + threat.sourceIP + ' blocked by ' + req.user.name,
      severity: 'HIGH',
      type: 'IP_BLOCKED',
      sourceRef: { refModel: 'ThreatLog', refId: threat._id },
    })
    socketManager.emitIPBlocked(threat.sourceIP, req.user.name, threat._id)
    socketManager.emitThreatUpdated(threat)
    socketManager.emitNewAlert(alert)
    logger.info('IP ' + threat.sourceIP + ' blocked by ' + req.user.email)
    sendSuccess(res, { threat, blockedIP: threat.sourceIP }, 'IP blocked')
  } catch (err) {
    next(err)
  }
}
const deleteThreat = async (req, res, next) => {
  try {
    const t = await threatService.deleteThreat(req.params.id)
    if (!t) return sendError(res, 'Not found', 404)
    sendSuccess(res, {}, 'Deleted')
  } catch (err) {
    next(err)
  }
}

const getSettings = async (req, res, next) => {
  try {
    const SystemSetting = require('../models/SystemSetting')
    let autoBlock = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
    if (!autoBlock) {
      autoBlock = await SystemSetting.create({ key: 'autoBlockEnabled', value: false })
    }
    sendSuccess(res, { autoBlockEnabled: autoBlock.value })
  } catch (err) {
    next(err)
  }
}

const updateSettings = async (req, res, next) => {
  try {
    const { autoBlockEnabled } = req.body
    if (autoBlockEnabled === undefined) {
      return sendError(res, 'autoBlockEnabled field is required', 400)
    }
    const SystemSetting = require('../models/SystemSetting')
    const autoBlock = await SystemSetting.findOneAndUpdate(
      { key: 'autoBlockEnabled' },
      { value: autoBlockEnabled === true },
      { upsert: true, new: true }
    )
    logger.info(`System setting autoBlockEnabled updated to ${autoBlock.value} by admin ${req.user.email}`)
    sendSuccess(res, { autoBlockEnabled: autoBlock.value }, 'Settings updated')
  } catch (err) {
    next(err)
  }
}

const getBlockedIPs = async (req, res, next) => {
  try {
    const { page = 1, limit = 50 } = req.query
    const { limit: safeLimit, skip } = parsePagination({
      page,
      limit,
      defaultLimit: 50,
      maxLimit: 100,
    })
    const BlockedIP = require('../models/BlockedIP')
    const list = await BlockedIP.find()
      .populate('blockedBy', 'name email')
      .populate('threatRef', 'attackType severity')
      .sort({ blockedAt: -1 })
      .skip(skip)
      .limit(safeLimit)
    sendSuccess(res, { blockedIPs: list })
  } catch (err) {
    next(err)
  }
}

const blockIPManual = async (req, res, next) => {
  try {
    const { ip, reason } = req.body
    if (!ip || typeof ip !== 'string') return sendError(res, 'IP address is required', 400)
    const cleanIP = ip.trim()
    if (!isValidIP(cleanIP)) {
      return sendError(res, 'Invalid IP address format', 400)
    }
    const cleanReason = (typeof reason === 'string' ? reason.trim().slice(0, 200) : '') || 'Manual analyst block'

    const containmentService = require('../services/containmentService')
    const { blockedIP, updatedThreats } = await containmentService.blockIPManual({
      ip: cleanIP,
      reason: cleanReason,
      analystId: req.user._id,
      analystName: req.user.name,
      analystEmail: req.user.email,
    })

    if (updatedThreats && updatedThreats.length > 0) {
      updatedThreats.forEach((t) => socketManager.emitThreatUpdated(t))
    }

    const alertService = require('../services/alertService')
    const alert = await alertService.createAlert({
      title: 'IP Address Blocked',
      message: `IP ${cleanIP} blocked manually by ${req.user.name}`,
      severity: 'HIGH',
      type: 'IP_BLOCKED',
    })

    socketManager.emitIPBlocked(cleanIP, req.user.name, null)
    socketManager.emitNewAlert(alert)
    logger.info(`IP ${cleanIP} blocked manually by ${req.user.email}`)

    sendSuccess(res, { blockedIP }, 'IP blocked successfully')
  } catch (err) {
    if (err.isInconsistent) {
      logger.error(`[CRITICAL] Containment inconsistency on blockIPManual: ${err.message}`)
      return sendError(
        res,
        'Containment operation failed with potential state inconsistency. Please contact an administrator.',
        500
      )
    }
    next(err)
  }
}

const unblockIPManual = async (req, res, next) => {
  try {
    const { ip } = req.body
    if (!ip || typeof ip !== 'string') return sendError(res, 'IP address is required', 400)
    const cleanIP = ip.trim()
    if (!isValidIP(cleanIP)) {
      return sendError(res, 'Invalid IP address format', 400)
    }

    const containmentService = require('../services/containmentService')
    const result = await containmentService.unblockIPManual({
      ip: cleanIP,
      analystId: req.user._id,
      analystName: req.user.name,
      analystEmail: req.user.email,
    })

    if (result.notFound) {
      return sendError(res, 'IP is not blocked', 404)
    }

    if (result.restoredThreats && result.restoredThreats.length > 0) {
      result.restoredThreats.forEach((t) => socketManager.emitThreatUpdated(t))
    }

    const alertService = require('../services/alertService')
    const alert = await alertService.createAlert({
      title: 'IP Address Unblocked',
      message: `IP ${cleanIP} unblocked manually by ${req.user.name}`,
      severity: 'INFO',
      type: 'IP_UNBLOCKED',
    })

    socketManager.emitIPUnblocked(cleanIP, req.user.name)
    socketManager.emitNewAlert(alert)
    logger.info(`IP ${cleanIP} unblocked manually by ${req.user.email}`)

    sendSuccess(res, {}, 'IP unblocked successfully')
  } catch (err) {
    if (err.isInconsistent) {
      logger.error(`[CRITICAL] Containment inconsistency on unblockIPManual: ${err.message}`)
      return sendError(
        res,
        'Containment operation failed with potential state inconsistency. Please contact an administrator.',
        500
      )
    }
    next(err)
  }
}

module.exports = {
  getThreats,
  getAnalytics,
  getVectorTrend,
  getRecent,
  getThreat,
  createThreat,
  updateThreat,
  blockIP,
  deleteThreat,
  getSettings,
  updateSettings,
  getBlockedIPs,
  blockIPManual,
  unblockIPManual,
}
