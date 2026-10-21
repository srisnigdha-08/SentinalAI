const reportTime = require('../utils/reportingTime')
const ThreatLog = require('../models/ThreatLog')
const SystemSetting = require('../models/SystemSetting')
const Alert = require('../models/Alert')
const logger = require('../utils/logger')
const { escapeRegex, parsePagination, parseSort, parseDate } = require('../utils/querySecurity')

const ALLOWED_THREAT_SORT_FIELDS = [
  'createdAt',
  'severity',
  'aiScore',
  'confidence',
  'status',
  'attackType',
  'sourceIP',
  'targetService',
]

const ALLOWED_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const ALLOWED_STATUSES = ['DETECTED', 'MONITORING', 'BLOCKED', 'ESCALATED', 'RESOLVED', 'FALSE_POSITIVE', 'DEGRADED']

const findThreats = async ({
  page = 1,
  limit = 20,
  severity,
  status,
  type,
  search,
  startDate,
  endDate,
  sortBy = 'createdAt',
  sortOrder = 'desc',
} = {}) => {
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
  if (typeof severity === 'string' && ALLOWED_SEVERITIES.includes(severity.toUpperCase())) {
    filter.severity = severity.toUpperCase()
  }
  if (typeof status === 'string' && ALLOWED_STATUSES.includes(status.toUpperCase())) {
    filter.status = status.toUpperCase()
  }
  if (typeof type === 'string' && type.trim()) {
    filter.attackType = type.trim().slice(0, 100)
  }

  const start = parseDate(startDate)
  const end = parseDate(endDate)
  if (start || end) {
    filter.createdAt = {}
    if (start) filter.createdAt.$gte = start
    if (end) filter.createdAt.$lte = end
  }

  const safeSearch = escapeRegex(search)
  if (safeSearch) {
    filter.$or = [
      { sourceIP: { $regex: safeSearch, $options: 'i' } },
      { attackType: { $regex: safeSearch, $options: 'i' } },
      { targetService: { $regex: safeSearch, $options: 'i' } },
    ]
  }

  const sort = parseSort(sortBy, sortOrder, ALLOWED_THREAT_SORT_FIELDS, 'createdAt')
  const total = await ThreatLog.countDocuments(filter)
  const data = await ThreatLog.find(filter)
    .sort(sort)
    .skip(skip)
    .limit(safeLimit)
    .populate('handledBy', 'name email')
    .lean()
  return { data, total, page: safePage, limit: safeLimit }
}

const findThreatById = (id) => ThreatLog.findById(id).populate('handledBy', 'name email role').select('+rawPayload')

const createThreat = async (data) => {
  const isAiGenerated = Boolean(data.isAiGenerated)
  const score = isAiGenerated ? data.aiScore || 0 : 0
  const aiEngineService = require('./aiEngineService')
  const containmentService = require('./containmentService')

  const setting = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
  const autoBlockEnabled = setting ? setting.value === true : false
  const blockThreshold = await aiEngineService.getBlockThreshold()

  const shouldBlock = isAiGenerated && score >= blockThreshold && autoBlockEnabled
  const actionTaken = shouldBlock

  let status = 'DETECTED'
  if (data.status === 'DEGRADED') {
    status = 'DEGRADED'
  } else if (shouldBlock) {
    status = 'BLOCKED'
  } else if (score >= 0.7) {
    status = 'MONITORING'
  } else if (data.status && ALLOWED_STATUSES.includes(data.status)) {
    status = data.status
  }

  const threat = await ThreatLog.create({
    ...data,
    aiScore: score,
    confidence: isAiGenerated ? data.confidence || 0 : 0,
    status,
    preBlockStatus: shouldBlock ? (score >= 0.7 ? 'MONITORING' : 'DETECTED') : null,
    autonomousAction: {
      taken: actionTaken,
      actionType: actionTaken ? 'IP_BLOCKED' : null,
      actionTime: actionTaken ? new Date() : null,
    },
    eventTime: data.eventTime || null,
  })

  if (actionTaken) {
    try {
      await containmentService.executeAutoBlock({
        threat,
        threatScore: score,
        source: 'AI Engine',
        sourceRef: { refModel: 'ThreatLog', refId: threat._id },
      })
    } catch (e) {
      logger.error(`[AI Auto-Block] Failed during createThreat: ${e.message}`)
    }
  }

  // Asynchronous Threat Intelligence Enrichment (Phase 2.4B - Option B)
  if (threat.aiScore >= 0.7) {
    try {
      const threatIntelService = require('./threatIntelService')
      setImmediate(() => {
        threatIntelService.enrichThreat(threat).catch((e) => {
          logger.debug('[ThreatService] Background Threat Intel enrichment error: ' + e.message)
        })
      })
    } catch (e) {
      logger.debug('[ThreatService] Failed to dispatch Threat Intel enrichment: ' + e.message)
    }
  }

  logger.info(`Threat created: ${threat.attackType} from ${threat.sourceIP}`)
  return threat
}

const updateThreat = (id, updates) => ThreatLog.findByIdAndUpdate(id, updates, { new: true, runValidators: true })
const deleteThreat = async (id) => {
  const deleted = await ThreatLog.findByIdAndDelete(id)
  if (deleted) {
    await Alert.deleteMany({ 'sourceRef.refModel': 'ThreatLog', 'sourceRef.refId': deleted._id })
  }
  return deleted
}
const blockThreatIP = async (id, analystId, session = null) => {
  const containmentService = require('./containmentService')
  return containmentService.blockThreat(id, analystId, 'Manual threat block', session)
}

const getRecentThreats = (limit = 10) => {
  const safeLimit = Math.min(Math.max(1, parseInt(limit, 10) || 10), 100)
  return ThreatLog.find().sort({ createdAt: -1 }).limit(safeLimit).lean()
}

const getAttackVectorTrend = async (days = 7, now = new Date()) => {
  const safeDays = Math.min(Math.max(1, parseInt(days, 10) || 7), 90)
  return ThreatLog.aggregate([
    { $match: { createdAt: reportTime.filter(safeDays, now) } },
    {
      $group: {
        _id: { date: reportTime.dayGroup(), type: '$attackType' },
        count: { $sum: 1 },
      },
    },
    { $sort: { '_id.date': 1 } },
  ])
}

const getDashboardAnalytics = async (now = new Date()) => {
  const today = reportTime.filter(1, now)
  const weekAgo = reportTime.filter(7, now)
  const [
    totalToday,
    totalAllTime,
    bySeverityToday,
    byStatusAllTime,
    byAttackType,
    hourlyToday,
    weeklyTrend,
    topSourceIPs,
    avgAIScore,
    blockedCount,
  ] = await Promise.all([
    ThreatLog.countDocuments({ createdAt: today }),
    ThreatLog.countDocuments(),
    ThreatLog.aggregate([
      { $match: { createdAt: today } },
      { $group: { _id: '$severity', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),
    ThreatLog.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    ThreatLog.aggregate([
      { $group: { _id: '$attackType', count: { $sum: 1 }, avgScore: { $avg: '$aiScore' } } },
      { $sort: { count: -1 } },
      { $limit: 7 },
    ]),
    ThreatLog.aggregate([
      { $match: { createdAt: today } },
      {
        $group: {
          _id: reportTime.hourGroup(),
          count: { $sum: 1 },
          blocked: { $sum: { $cond: [{ $eq: ['$status', 'BLOCKED'] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]),
    ThreatLog.aggregate([
      { $match: { createdAt: weekAgo } },
      {
        $group: {
          _id: reportTime.dayGroup(),
          total: { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'CRITICAL'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: ['$severity', 'HIGH'] }, 1, 0] } },
          medium: { $sum: { $cond: [{ $eq: ['$severity', 'MEDIUM'] }, 1, 0] } },
          low: { $sum: { $cond: [{ $eq: ['$severity', 'LOW'] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]),
    ThreatLog.aggregate([
      { $group: { _id: '$sourceIP', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]),
    ThreatLog.aggregate([{ $group: { _id: null, avg: { $avg: '$aiScore' } } }]),
    ThreatLog.countDocuments({ status: 'BLOCKED' }),
  ])
  const hourlyFull = Array.from({ length: 24 }, (_, i) => {
    const h = hourlyToday.find((x) => x._id === i)
    return { hour: `${String(i).padStart(2, '0')}:00`, count: h?.count || 0, blocked: h?.blocked || 0 }
  })
  return {
    kpis: {
      totalToday,
      totalAllTime,
      blockedCount,
      avgAIScore: parseFloat((avgAIScore[0]?.avg || 0).toFixed(3)),
      blockRate: totalAllTime > 0 ? parseFloat(((blockedCount / totalAllTime) * 100).toFixed(1)) : 0,
    },
    reporting: reportTime.reporting(now),
    charts: { bySeverityToday, byStatusAllTime, byAttackType, hourlyToday: hourlyFull, weeklyTrend },
    intelligence: { topSourceIPs },
  }
}

module.exports = {
  findThreats,
  findThreatById,
  createThreat,
  updateThreat,
  deleteThreat,
  blockThreatIP,
  getRecentThreats,
  getAttackVectorTrend,
  getDashboardAnalytics,
}
