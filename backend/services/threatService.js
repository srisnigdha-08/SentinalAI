const reportTime = require('../utils/reportingTime')
const ThreatLog = require('../models/ThreatLog')
const SystemSetting = require('../models/SystemSetting')
const Alert = require('../models/Alert')
const logger = require('../utils/logger')
const { currentAlertLine } = require('../utils/severity')
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

const MONGO_MAX_TIME_EXPIRED = 50
const positiveInt = (value, fallback) => {
  const n = Number(value)
  return Number.isInteger(n) && n > 0 ? n : fallback
}

const badRequest = (message) => Object.assign(new Error(message), { statusCode: 400 })
// Opaque keyset cursor: base64url of {"t": createdAt ISO, "id": ObjectId hex}. Decoding validates both strictly,
// so a crafted cursor can only ever become a date and an ObjectId in the range filter.
const encodeCursor = (doc) =>
  Buffer.from(JSON.stringify({ t: new Date(doc.createdAt).toISOString(), id: String(doc._id) })).toString('base64url')
const decodeCursor = (value) => {
  if (typeof value !== 'string' || value.length > 200 || !/^[A-Za-z0-9_-]+$/.test(value)) return null
  try {
    const { t, id } = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
    const date = typeof t === 'string' ? new Date(t) : null
    if (!date || Number.isNaN(date.getTime()) || typeof id !== 'string' || !/^[a-f0-9]{24}$/.test(id)) return null
    return { t: date, id: new (require('mongoose').Types.ObjectId)(id) }
  } catch {
    return null
  }
}

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
  after,
} = {}) => {
  const {
    page: safePage,
    limit: safeLimit,
    skip: pageSkip,
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

  let sort = parseSort(sortBy, sortOrder, ALLOWED_THREAT_SORT_FIELDS, 'createdAt')
  // L8: newest-first lists get _id as the tie-breaker (served by the { ..., createdAt: -1, _id: -1 } indexes) and
  // support keyset pagination: `after` (the previous page's nextCursor) continues below that row instead of
  // skipping every earlier one, so deep pages cost the same as the first. Page numbers keep working.
  const keyset = sort.createdAt === -1 && Object.keys(sort).length === 1
  if (keyset) sort = { createdAt: -1, _id: -1 }
  let skip = pageSkip
  const query = { ...filter }
  if (after !== undefined) {
    if (!keyset) throw badRequest('after can only be used with the default newest-first order')
    const cursor = decodeCursor(after)
    if (!cursor) throw badRequest('Invalid cursor')
    query.$and = [
      ...(query.$and || []),
      { $or: [{ createdAt: { $lt: cursor.t } }, { createdAt: cursor.t, _id: { $lt: cursor.id } }] },
    ]
    skip = 0
  }
  // Search is an unanchored match over three fields, so few matches means scanning the collection; bound it.
  const limited = safeSearch ? { maxTimeMS: positiveInt(process.env.THREAT_SEARCH_MAX_MS, 5000) } : null
  try {
    // total counts the whole filtered list (not what is left after the cursor), as page numbers expect.
    const total = await ThreatLog.countDocuments(filter, ...(limited ? [limited] : []))
    const data = await ThreatLog.find(query, ...(limited ? [null, limited] : []))
      .sort(sort)
      .skip(skip)
      .limit(safeLimit)
      .populate('handledBy', 'name email')
      .lean()
    const last = data[data.length - 1]
    const nextCursor = keyset && data.length === safeLimit && last?.createdAt ? encodeCursor(last) : null
    return { data, total, page: safePage, limit: safeLimit, nextCursor }
  } catch (err) {
    if (limited && err?.code === MONGO_MAX_TIME_EXPIRED) {
      const tooSlow = new Error('Search took too long; add a filter or use a more specific term')
      tooSlow.statusCode = 422
      throw tooSlow
    }
    throw err
  }
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
  // Same alert line as the AI pipeline (THR-002; was a fixed 0.70). Read after getBlockThreshold refreshed the cache.
  const alertThreshold = currentAlertLine()

  // Correlation (containmentCorrelationService): one flow alone never auto-blocks under the default policy.
  let containmentDecision
  if (isAiGenerated && score >= blockThreshold && data.status !== 'DEGRADED') {
    containmentDecision = autoBlockEnabled
      ? await require('./containmentCorrelationService').evaluateSafely({
          sourceIP: data.sourceIP,
          attackType: data.attackType,
          threatScore: score,
          alertThreshold,
          blockThreshold,
        })
      : { decision: 'DISABLED', reasons: ['auto-block is off'], evaluatedAt: new Date() }
  }
  const shouldBlock = Boolean(containmentDecision && containmentDecision.decision === 'AUTO_BLOCK')
  const actionTaken = shouldBlock

  let status = 'DETECTED'
  if (data.status === 'DEGRADED') {
    status = 'DEGRADED'
  } else if (shouldBlock) {
    status = 'BLOCKED'
  } else if (score >= alertThreshold) {
    status = 'MONITORING'
  } else if (data.status && ALLOWED_STATUSES.includes(data.status)) {
    status = data.status
  }

  const threat = await ThreatLog.create({
    ...data,
    aiScore: score,
    confidence: isAiGenerated ? data.confidence || 0 : 0,
    status,
    preBlockStatus: shouldBlock ? (score >= alertThreshold ? 'MONITORING' : 'DETECTED') : null,
    autonomousAction: {
      taken: actionTaken,
      actionType: actionTaken ? 'IP_BLOCKED' : null,
      actionTime: actionTaken ? new Date() : null,
    },
    eventTime: data.eventTime || null,
    // Always the server's own decision (undefined clears anything a caller put in `data`)
    containmentDecision,
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
  if (threat.aiScore >= alertThreshold) {
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

// M2: every open dashboard asks for these figures every 30 s, and five of them scan the whole collection. Results are
// cached for DASHBOARD_CACHE_MS (default 15 s; 0 disables; tests default to 0) and concurrent requests share one
// computation. Each caller gets its own deep copy: the controller redacts IPs for viewers in place.
let dashboardCache = { at: 0, promise: null }
const dashboardCacheMs = () => {
  const n = parseInt(process.env.DASHBOARD_CACHE_MS, 10)
  if (Number.isInteger(n) && n >= 0) return n
  return process.env.NODE_ENV === 'test' ? 0 : 15000
}
const resetDashboardCache = () => {
  dashboardCache = { at: 0, promise: null }
}

const getDashboardAnalytics = async (now) => {
  const ttl = dashboardCacheMs()
  // An explicit `now` (tests, reports for another moment) is never served from or stored in the cache.
  if (now !== undefined || ttl === 0) return computeDashboardAnalytics(now || new Date())
  const at = Date.now()
  if (!dashboardCache.promise || at - dashboardCache.at >= ttl) {
    const promise = computeDashboardAnalytics(new Date())
    dashboardCache = { at, promise }
    // A failed computation must not be served for the rest of the window.
    promise.catch(() => {
      if (dashboardCache.promise === promise) resetDashboardCache()
    })
  }
  return structuredClone(await dashboardCache.promise)
}

const computeDashboardAnalytics = async (now) => {
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
    // Collection metadata instead of a full count (exact on a cleanly shut down server; may lag after a crash).
    ThreatLog.estimatedDocumentCount(),
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
  resetDashboardCache,
}
