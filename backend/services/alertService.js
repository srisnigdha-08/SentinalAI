const Alert = require('../models/Alert')
const logger = require('../utils/logger')
const { parsePagination } = require('../utils/querySecurity')

const ALLOWED_ALERT_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const ALLOWED_ALERT_ROLES = ['admin', 'analyst', 'viewer']
const ALLOWED_ALERT_TYPES = [
  'THREAT_DETECTED',
  'IP_BLOCKED',
  'IP_UNBLOCKED',
  'HONEYPOT_SESSION',
  'AI_PREDICTION',
  'SYSTEM_HEALTH',
  'AUTH_FAILURE',
  'AUTONOMOUS_ACTION',
]

const findAlerts = async ({ page = 1, limit = 20, role, severity, isRead, type } = {}) => {
  const {
    page: safePage,
    limit: safeLimit,
    skip,
  } = parsePagination({
    page,
    limit,
    defaultLimit: 20,
    maxLimit: 100,
  })

  const filter = {}
  if (typeof role === 'string' && ALLOWED_ALERT_ROLES.includes(role.toLowerCase())) {
    filter.targetRoles = role.toLowerCase()
  }
  if (typeof severity === 'string' && ALLOWED_ALERT_SEVERITIES.includes(severity.toUpperCase())) {
    filter.severity = severity.toUpperCase()
  }
  if (isRead !== undefined) {
    if (isRead === true || isRead === 'true') filter.isRead = true
    else if (isRead === false || isRead === 'false') filter.isRead = false
  }
  if (typeof type === 'string' && ALLOWED_ALERT_TYPES.includes(type.toUpperCase())) {
    filter.type = type.toUpperCase()
  }

  const total = await Alert.countDocuments(filter)
  const data = await Alert.find(filter).sort({ createdAt: -1 }).skip(skip).limit(safeLimit).lean()
  return { data, total, page: safePage, limit: safeLimit }
}

const getUnreadCount = (role) => Alert.countDocuments({ targetRoles: role, isRead: false })

const markAsRead = (id, userId) =>
  Alert.findByIdAndUpdate(id, { isRead: true, $push: { readBy: { user: userId } } }, { new: true })

const markAllAsRead = async (role) => {
  const result = await Alert.updateMany({ targetRoles: role, isRead: false }, { isRead: true })
  return result.modifiedCount
}

const createAlert = async (data) => {
  const alert = await Alert.create(data)
  logger.info(`Alert created: [${alert.severity}] ${alert.title}`)
  return alert
}

const createAlertFromThreat = (threat) =>
  createAlert({
    title: `${threat.severity} Threat: ${threat.attackType}`,
    message: `Source IP ${threat.sourceIP} targeted ${threat.targetService}. AI Score: ${((threat.aiScore || 0) * 100).toFixed(0)}%`,
    severity: threat.severity,
    type: 'THREAT_DETECTED',
    sourceRef: { refModel: 'ThreatLog', refId: threat._id },
    targetRoles: threat.severity === 'CRITICAL' ? ['admin', 'analyst'] : ['analyst'],
  })

const createAlertFromSession = (session) =>
  createAlert({
    title: `Honeypot Session: ${session.honeypotNode}`,
    message: `Attacker ${session.sourceIP} (${session.geoLocation?.country || 'Unknown'}) entered ${session.honeypotNode}`,
    severity: 'HIGH',
    type: 'HONEYPOT_SESSION',
    sourceRef: { refModel: 'HoneypotSession', refId: session._id },
    targetRoles: ['admin', 'analyst'],
  })

const deleteAlert = (id) => Alert.findByIdAndDelete(id)

module.exports = {
  findAlerts,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  createAlert,
  createAlertFromThreat,
  createAlertFromSession,
  deleteAlert,
}
