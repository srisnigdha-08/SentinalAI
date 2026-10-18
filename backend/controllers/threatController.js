const threatService = require('../services/threatService')
const alertService = require('../services/alertService')
const socketManager = require('../websocket/socketManager')
const { sendSuccess, sendError, sendPaginated } = require('../utils/apiResponse')
const logger = require('../utils/logger')
const { isValidIP, parsePagination } = require('../utils/querySecurity')
const { redactThreat, redactIP } = require('../utils/redact')

const getThreats = async (req, res, next) => {
  try {
    const r = await threatService.findThreats(req.query)
    const role = req.user?.role || 'viewer'
    const safeData = r.data.map((t) => redactThreat(t, role))
    sendPaginated(res, safeData, r.total, r.page, r.limit)
  } catch (err) {
    next(err)
  }
}
const getAnalytics = async (req, res, next) => {
  try {
    const role = req.user?.role || 'viewer'
    const analytics = await threatService.getDashboardAnalytics()
    if (role === 'viewer') {
      if (Array.isArray(analytics?.intelligence?.topSourceIPs)) {
        analytics.intelligence.topSourceIPs = analytics.intelligence.topSourceIPs.map((t) => ({
          ...t,
          _id: redactIP(t._id),
        }))
      }
      if (Array.isArray(analytics?.topSourceIPs)) {
        analytics.topSourceIPs = analytics.topSourceIPs.map((t) => ({
          ...t,
          _id: redactIP(t._id),
        }))
      }
    }
    sendSuccess(res, analytics, 'Analytics retrieved')
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
    const role = req.user?.role || 'viewer'
    const raw = await threatService.getRecentThreats(parseInt(req.query.limit) || 10)
    const safe = raw.map((t) => redactThreat(t, role))
    sendSuccess(res, { threats: safe })
  } catch (err) {
    next(err)
  }
}
const getThreat = async (req, res, next) => {
  try {
    const t = await threatService.findThreatById(req.params.id)
    if (!t) return sendError(res, 'Not found', 404)
    const role = req.user?.role || 'viewer'
    sendSuccess(res, { threat: redactThreat(t, role) })
  } catch (err) {
    next(err)
  }
}
const ThreatLog = require('../models/ThreatLog')

const ALLOWED_THREAT_STATUSES = [
  'DETECTED',
  'INVESTIGATING',
  'CONTAINED',
  'MONITORING',
  'BLOCKED',
  'ESCALATED',
  'RESOLVED',
  'FALSE_POSITIVE',
  'DEGRADED',
]

const ALLOWED_THREAT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const ALLOWED_ATTACK_TYPES = ThreatLog.ALLOWED_ATTACK_TYPES || [
  'SSH Brute Force',
  'SSH Intrusion Attempt',
  'SQL Injection',
  'Port Scan',
  'DDoS',
  'RCE Attempt',
  'XSS Attempt',
  'Malware Beacon',
  'Credential Stuffing',
  'Ransomware',
  'Lateral Movement',
  'Data Exfiltration',
  'Zero-Day Exploit',
  'Unknown',
  'UNINSPECTED_TRAFFIC',
]

const createThreat = async (req, res, next) => {
  try {
    const { sourceIP, attackType, severity } = req.body || {}
    if (!sourceIP || typeof sourceIP !== 'string' || !isValidIP(sourceIP.trim())) {
      return sendError(res, 'Valid sourceIP is required', 400)
    }
    if (!attackType || typeof attackType !== 'string' || !ALLOWED_ATTACK_TYPES.includes(attackType.trim())) {
      return sendError(res, 'Valid attackType is required', 400)
    }
    if (severity && (typeof severity !== 'string' || !ALLOWED_THREAT_SEVERITIES.includes(severity.toUpperCase()))) {
      return sendError(res, 'Invalid severity level', 400)
    }

    // REL-02: Safe timestamp / eventTime parsing and validation
    let parsedEventTime = null
    const rawTimestamp = req.body && (req.body.timestamp !== undefined ? req.body.timestamp : req.body.eventTime)
    if (rawTimestamp !== undefined && rawTimestamp !== null) {
      let d
      if (typeof rawTimestamp === 'number') {
        d = new Date(rawTimestamp < 1e11 ? rawTimestamp * 1000 : rawTimestamp)
      } else if (typeof rawTimestamp === 'string' && rawTimestamp.trim() !== '') {
        const trimmed = rawTimestamp.trim()
        const num = Number(trimmed)
        if (!isNaN(num) && /^\d+$/.test(trimmed)) {
          d = new Date(num < 1e11 ? num * 1000 : num)
        } else {
          d = new Date(trimmed)
        }
      } else {
        return sendError(res, 'Invalid event timestamp format', 400)
      }

      if (isNaN(d.getTime())) {
        return sendError(res, 'Invalid event timestamp value', 400)
      }

      const nowMs = Date.now()
      if (d.getTime() > nowMs + 60000) {
        return sendError(res, 'Event timestamp cannot be in the future', 400)
      }
      if (d.getTime() < new Date('2000-01-01T00:00:00Z').getTime()) {
        return sendError(res, 'Event timestamp is outside reasonable range', 400)
      }
      parsedEventTime = d
    }

    // SEC-01: Strip client-supplied threat scores and containment actions.
    // Manual threats must never trigger automated blocking or spoof AI telemetry.
    const cleanData = {
      sourceIP: sourceIP.trim(),
      attackType: attackType.trim(),
      severity: severity ? severity.toUpperCase() : 'MEDIUM',
      destinationIP: typeof req.body.destinationIP === 'string' ? req.body.destinationIP.trim().slice(0, 100) : 'INTERNAL',
      targetService: typeof req.body.targetService === 'string' ? req.body.targetService.trim().slice(0, 100) : 'UNKNOWN',
      notes: typeof req.body.notes === 'string' ? req.body.notes.trim().slice(0, 1000) : '',
      handledBy: req.user?._id || null,
      aiScore: 0,
      confidence: 0,
      status: 'DETECTED',
      preBlockStatus: null,
      containmentId: null,
      predictionId: null,
      isAiGenerated: false,
      autonomousAction: {
        taken: false,
        actionType: null,
        actionTime: null,
      },
      eventTime: parsedEventTime,
    }

    if (req.body.geoLocation && typeof req.body.geoLocation === 'object') {
      cleanData.geoLocation = {
        country: typeof req.body.geoLocation.country === 'string' ? req.body.geoLocation.country.slice(0, 100) : 'Unknown',
        city: typeof req.body.geoLocation.city === 'string' ? req.body.geoLocation.city.slice(0, 100) : 'Unknown',
        lat: typeof req.body.geoLocation.lat === 'number' ? req.body.geoLocation.lat : undefined,
        lon: typeof req.body.geoLocation.lon === 'number' ? req.body.geoLocation.lon : undefined,
      }
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
    if (req.body && req.body.status !== undefined) {
      return sendError(
        res,
        'Status cannot be modified via PUT. Use PATCH /api/threats/:id/triage or containment endpoints.',
        400
      )
    }
    const allowed = ['notes', 'tags', 'triageNotes', 'handledBy']
    const updates = {}
    allowed.forEach((f) => {
      if (req.body[f] !== undefined) updates[f] = req.body[f]
    })
    if (updates.notes !== undefined) {
      if (typeof updates.notes !== 'string' || updates.notes.length > 1000) {
        return sendError(res, 'Notes must be a string up to 1000 characters', 400)
      }
    }
    if (updates.tags !== undefined) {
      if (!Array.isArray(updates.tags)) {
        return sendError(res, 'Tags must be an array of strings', 400)
      }
    }
    if (updates.handledBy !== undefined && updates.handledBy !== null) {
      const { isValidObjectId } = require('../utils/querySecurity')
      if (!isValidObjectId(updates.handledBy)) {
        return sendError(res, 'Invalid handledBy user ID', 400)
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
    const { runWithTransactionOrFallback } = require('../utils/transactionHelper')
    const { logAudit } = require('../utils/auditLogger')

    const threat = await runWithTransactionOrFallback({
      transactionFn: async (session) => {
        const blockedThreat = await threatService.blockThreatIP(req.params.id, req.user._id, session)
        if (!blockedThreat) return null

        await logAudit({
          action: 'THREAT_BLOCKED',
          actor: req.user,
          target: { id: blockedThreat._id.toString(), identifier: blockedThreat.sourceIP, type: 'ThreatLog' },
          status: 'SUCCESS',
          details: { sourceIP: blockedThreat.sourceIP },
          ip: req.ip,
          session,
        })
        return blockedThreat
      },
      fallbackFn: async () => {
        const blockedThreat = await threatService.blockThreatIP(req.params.id, req.user._id)
        if (!blockedThreat) return null

        try {
          await logAudit({
            action: 'THREAT_BLOCKED',
            actor: req.user,
            target: { id: blockedThreat._id.toString(), identifier: blockedThreat.sourceIP, type: 'ThreatLog' },
            status: 'SUCCESS',
            details: { sourceIP: blockedThreat.sourceIP },
            ip: req.ip,
          })
        } catch (auditErr) {
          const BlockedIP = require('../models/BlockedIP')
          await BlockedIP.deleteOne({ ip: blockedThreat.sourceIP })
          await ThreatLog.findByIdAndUpdate(blockedThreat._id, { status: blockedThreat.preBlockStatus || 'DETECTED' })
          logger.error(`[AUDIT_FAILURE] Reverted threat block for ${blockedThreat._id} due to audit failure: ${auditErr.message}`)
          const err = new Error('Security audit logging failed; change not applied')
          err.statusCode = 500
          throw err
        }
        return blockedThreat
      },
    })

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
    if (err.message && err.message.includes('Security audit logging failed')) {
      return sendError(res, err.message, err.statusCode || 500)
    }
    next(err)
  }
}
const deleteThreat = async (req, res, next) => {
  try {
    const existing = await ThreatLog.findById(req.params.id)
    if (!existing) return sendError(res, 'Not found', 404)

    const { logAudit } = require('../utils/auditLogger')
    try {
      await logAudit({
        action: 'THREAT_DELETED',
        actor: req.user,
        target: { id: req.params.id, type: 'ThreatLog' },
        status: 'SUCCESS',
        ip: req.ip,
      })
    } catch (auditErr) {
      logger.error(`[AUDIT_FAILURE] Threat deletion aborted for ${req.params.id} due to audit failure: ${auditErr.message}`)
      return sendError(res, 'Security audit logging failed; change not applied', 500)
    }

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
    const prevSettingDoc = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
    const prevValue = prevSettingDoc ? prevSettingDoc.value : false

    const autoBlock = await SystemSetting.findOneAndUpdate(
      { key: 'autoBlockEnabled' },
      { value: autoBlockEnabled === true },
      { upsert: true, new: true }
    )
    logger.info(`System setting autoBlockEnabled updated to ${autoBlock.value} by admin ${req.user.email}`)

    const { logAudit } = require('../utils/auditLogger')
    try {
      await logAudit({
        action: 'SETTINGS_CHANGED',
        actor: req.user,
        target: { identifier: 'autoBlockEnabled', type: 'SystemSetting' },
        status: 'SUCCESS',
        details: { autoBlockEnabled: autoBlock.value },
        ip: req.ip,
      })
    } catch (auditErr) {
      await SystemSetting.findOneAndUpdate(
        { key: 'autoBlockEnabled' },
        { value: prevValue },
        { upsert: true, new: true }
      )
      logger.error(`[AUDIT_FAILURE] Reverted autoBlockEnabled to ${prevValue} due to audit failure: ${auditErr.message}`)
      return sendError(res, 'Security audit logging failed; change not applied', 500)
    }

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
      .lean()
    const role = req.user?.role || 'viewer'
    const safeList = list.map((item) => {
      if (role === 'viewer') {
        return { ...item, ip: redactIP(item.ip) }
      }
      return item
    })
    sendSuccess(res, { blockedIPs: safeList })
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

    const { logAudit } = require('../utils/auditLogger')
    try {
      await logAudit({
        action: 'IP_BLOCKED_MANUAL',
        actor: req.user,
        target: { identifier: cleanIP, type: 'BlockedIP' },
        status: 'SUCCESS',
        details: { reason: cleanReason },
        ip: req.ip,
      })
    } catch (auditErr) {
      await containmentService.unblockIPManual({ ip: cleanIP })
      logger.error(`[AUDIT_FAILURE] Reverted manual IP block for ${cleanIP} due to audit failure: ${auditErr.message}`)
      return sendError(res, 'Security audit logging failed; change not applied', 500)
    }

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

    const { logAudit } = require('../utils/auditLogger')
    try {
      await logAudit({
        action: 'IP_UNBLOCKED_MANUAL',
        actor: req.user,
        target: { identifier: cleanIP, type: 'BlockedIP' },
        status: 'SUCCESS',
        ip: req.ip,
      })
    } catch (auditErr) {
      await containmentService.blockIPManual({ ip: cleanIP, reason: 'Compensating rollback' })
      logger.error(`[AUDIT_FAILURE] Reverted manual IP unblock for ${cleanIP} due to audit failure: ${auditErr.message}`)
      return sendError(res, 'Security audit logging failed; change not applied', 500)
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

const ALLOWED_TRIAGE_TRANSITIONS = {
  DETECTED: ['INVESTIGATING', 'MONITORING', 'ESCALATED', 'FALSE_POSITIVE'],
  INVESTIGATING: ['CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'MONITORING', 'ESCALATED'],
  MONITORING: ['INVESTIGATING', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE'],
  ESCALATED: ['INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'],
  CONTAINED: ['RESOLVED', 'INVESTIGATING'],
  RESOLVED: ['INVESTIGATING', 'DETECTED'],
  FALSE_POSITIVE: ['INVESTIGATING', 'DETECTED'],
  BLOCKED: ['INVESTIGATING', 'CONTAINED', 'RESOLVED'],
  DEGRADED: ['INVESTIGATING', 'RESOLVED'],
}

const triageThreat = async (req, res, next) => {
  try {
    const { status, triageNotes } = req.body || {}
    const updates = {}

    if (status !== undefined) {
      if (typeof status !== 'string' || !ALLOWED_THREAT_STATUSES.includes(status.toUpperCase())) {
        return sendError(res, 'Invalid threat status', 400)
      }
      const targetStatus = status.toUpperCase()
      if (targetStatus === 'BLOCKED') {
        return sendError(
          res,
          "Status 'BLOCKED' requires firewall containment flow. Use containment endpoints.",
          400
        )
      }

      const existingThreat = await ThreatLog.findById(req.params.id)
      if (!existingThreat) return sendError(res, 'Not found', 404)

      if (targetStatus !== existingThreat.status) {
        const allowed = ALLOWED_TRIAGE_TRANSITIONS[existingThreat.status] || []
        if (!allowed.includes(targetStatus)) {
          return sendError(
            res,
            `Invalid status transition from ${existingThreat.status} to ${targetStatus}`,
            400
          )
        }
      }
      updates.status = targetStatus
    }

    if (triageNotes !== undefined) {
      if (typeof triageNotes !== 'string' || triageNotes.length > 1000) {
        return sendError(res, 'Triage notes must be a string up to 1000 characters', 400)
      }
      updates.triageNotes = triageNotes.trim()
    }
    updates.handledBy = req.user?._id || null

    const threat = await threatService.updateThreat(req.params.id, updates)
    if (!threat) return sendError(res, 'Not found', 404)

    socketManager.emitThreatUpdated(threat)

    const { logAudit } = require('../utils/auditLogger')
    await logAudit({
      action: 'THREAT_TRIAGED',
      actor: req.user,
      target: { id: threat._id.toString(), identifier: threat.sourceIP, type: 'ThreatLog' },
      status: 'SUCCESS',
      details: { status: threat.status, triageNotes: threat.triageNotes },
      ip: req.ip,
    })

    sendSuccess(res, { threat }, 'Threat triage updated')
  } catch (err) {
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
  triageThreat,
  blockIP,
  deleteThreat,
  getSettings,
  updateSettings,
  getBlockedIPs,
  blockIPManual,
  unblockIPManual,
}

