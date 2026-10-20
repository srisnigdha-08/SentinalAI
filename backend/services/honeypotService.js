const reportTime = require('../utils/reportingTime')
const HoneypotSession = require('../models/HoneypotSession')
const logger = require('../utils/logger')
const aiSvc = require('./aiEngineService')
const { escapeRegex, parsePagination } = require('../utils/querySecurity')
const { redactCapturedCredentials } = require('../utils/redact')

// Must match PROFILES in ai-engine/rl_engine/deception_scorer.py and honeypot/switch_profile.py.
const DECEPTION_PROFILES = ['ubuntu_22', 'debian_11', 'centos_7', 'windows_srv', 'aws_ec2', 'raspberry_pi']
const ACTIVE_PROFILE_KEY = 'deceptionActiveProfile'

/**
 * The persona Cowrie is currently serving. An operator records it (PUT /api/honeypot/deception/profile)
 * after applying switch_profile.py; DECEPTION_ACTIVE_PROFILE / the shipped CentOS 7 config are fallbacks.
 */
const getActiveProfile = async () => {
  const SystemSetting = require('../models/SystemSetting')
  const setting = await SystemSetting.findOne({ key: ACTIVE_PROFILE_KEY })
  if (setting && DECEPTION_PROFILES.includes(setting.value)) return { profile: setting.value, source: 'setting' }
  if (DECEPTION_PROFILES.includes(process.env.DECEPTION_ACTIVE_PROFILE))
    return { profile: process.env.DECEPTION_ACTIVE_PROFILE, source: 'env' }
  return { profile: 'centos_7', source: 'default' }
}

const setActiveProfile = async (profile) => {
  if (!DECEPTION_PROFILES.includes(profile)) {
    const error = new Error(`Unknown deception profile. Allowed: ${DECEPTION_PROFILES.join(', ')}`)
    error.statusCode = 400
    throw error
  }
  const SystemSetting = require('../models/SystemSetting')
  await SystemSetting.findOneAndUpdate({ key: ACTIVE_PROFILE_KEY }, { value: profile }, { upsert: true, new: true })
  return profile
}

const findPreviousServedProfile = async (excludeId) => {
  try {
    return await HoneypotSession.findOne({ _id: { $ne: excludeId }, servedProfile: { $ne: null } })
      .sort({ createdAt: -1 })
      .select('servedProfile')
      .lean()
  } catch (err) {
    // Without a previous session the learner falls back to its in-memory last state.
    logger.debug('[HP] Previous served profile lookup failed: ' + err.message)
    return null
  }
}

const findSessions = async ({ page = 1, limit = 20, node, status, ip } = {}) => {
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
  if (typeof node === 'string' && node.trim()) {
    filter.honeypotNode = node.trim().slice(0, 50)
  }
  if (typeof status === 'string' && ['active', 'closed', 'analysed'].includes(status.toLowerCase())) {
    filter.status = status.toLowerCase()
  }

  const safeIp = escapeRegex(ip)
  if (safeIp) {
    filter.sourceIP = { $regex: safeIp, $options: 'i' }
  }

  const total = await HoneypotSession.countDocuments(filter)
  const data = await HoneypotSession.find(filter)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(safeLimit)
    .populate('linkedThreatLog', 'severity status aiScore')
    .lean()
  return { data, total, page: safePage, limit: safeLimit }
}

const findSessionById = (id) => HoneypotSession.findById(id).populate('linkedThreatLog')
const findBySessionId = (sessionId) => HoneypotSession.findOne({ sessionId })

const createSession = async (data) => {
  const session = await HoneypotSession.create(data)
  logger.info(`[HP] Session ${session.sessionId} from ${session.sourceIP}`)
  return session
}

const appendCommands = async (id, commands) => {
  const session = await HoneypotSession.findById(id)
  if (!session) return null
  session.commands.push(...commands)
  const text = commands.map((c) => c.command || '').join(' ')
  const SENSITIVE = ['/etc/passwd', '/etc/shadow', '/.ssh/', '/root/']
  SENSITIVE.forEach((f) => {
    if (text.includes(f) && !session.filesAccessed.includes(f)) session.filesAccessed.push(f)
  })
  const urls = text.match(/https?:\/\/[^\s]+/g) || []
  session.iocExtracted.urls.push(...urls.filter((u) => !session.iocExtracted.urls.includes(u)))
  if (/wget|curl/i.test(text)) session.malwareDownloaded.push(...urls)
  const n = session.commands.length
  session.deceptionScore = Math.min(
    100,
    n * 3 + session.filesAccessed.length * 10 + session.iocExtracted.urls.length * 8
  )
  session.engagementLevel = n >= 20 ? 'deep' : n >= 10 ? 'high' : n >= 5 ? 'medium' : n >= 2 ? 'low' : 'minimal'
  await session.save()
  return session
}

const closeSession = async (id, { reclassify = false, telemetry = {} } = {}) => {
  const existing = await HoneypotSession.findById(id)
  if (!existing) return null
  if (existing.closureAnalysisState === 'complete' && !reclassify) return existing
  const attemptId = require('node:crypto').randomUUID()
  // Claim before credentials, inference or containment. A failed/in-flight attempt requires review,
  // never an automatic retry that might repeat a partly completed external side effect.
  const session = await HoneypotSession.findOneAndUpdate(
    { _id: id, closureAnalysisState: { $nin: reclassify ? ['processing'] : ['processing', 'complete', 'failed'] } },
    { $set: { closureAnalysisState: 'processing', closureAttemptId: attemptId, closureAnalysisStartedAt: new Date() } },
    { new: true }
  )
  if (!session) {
    const error = new Error('Closure already processed, in progress, or requires explicit review/reclassification')
    error.statusCode = 409
    throw error
  }
  try {
    const result = await analyseClosure(session, telemetry)
    await HoneypotSession.updateOne(
      { _id: id, closureAttemptId: attemptId, closureAnalysisState: 'processing' },
      { $set: { closureAnalysisState: 'complete', closureAnalysisCompletedAt: new Date() } }
    )
    result.closureAnalysisState = 'complete'
    return result
  } catch (error) {
    await HoneypotSession.updateOne(
      { _id: id, closureAttemptId: attemptId, closureAnalysisState: 'processing' },
      { $set: { closureAnalysisState: 'failed' } }
    ).catch(() => {})
    throw error
  }
}

const analyseClosure = async (session, telemetry) => {
  if (!session.endTime) {
    session.endTime = new Date()
    session.durationSeconds =
      Number.isFinite(telemetry.durationSeconds) && telemetry.durationSeconds >= 0
        ? telemetry.durationSeconds
        : Math.floor((session.endTime - session.startTime) / 1000)
    if (Array.isArray(telemetry.credentials)) {
      session.credentials.push(...redactCapturedCredentials(telemetry.credentials))
    }
    if (typeof telemetry.hassh === 'string') session.hassh = telemetry.hassh
  }
  session.status = 'closed'
  // Credit the reward to the persona actually served, and give the learner the persona served in the
  // previous session as its state, so a recorded profile switch becomes a real state transition.
  if (!session.servedProfile) session.servedProfile = (await getActiveProfile()).profile
  const previous = await findPreviousServedProfile(session._id)
  const payload = {
    sessionId: session.sessionId,
    sourceIP: session.sourceIP,
    durationSeconds: session.durationSeconds,
    loginSucceeded: session.credentials.some((c) => c.success),
    commands: session.commands,
    iocCount: session.iocExtracted?.urls?.length || 0,
    // The persona Cowrie actually served. Recommendations are not applied automatically, so this is
    // the recorded active profile, not session.recommendedProfile.
    deceptionProfile: session.servedProfile,
    previousProfile: previous?.servedProfile || undefined,
  }
  // Only pass startTime if the session stores a trustworthy event timestamp; never substitute processing time
  if (session.startTime && (session.startTime instanceof Date || typeof session.startTime === 'string')) {
    const parsedStart = new Date(session.startTime)
    if (!isNaN(parsedStart.getTime())) {
      payload.startTime = parsedStart.toISOString()
    }
  }
  const aiRes = await aiSvc.predictHoneypotSession(payload)
  if (aiRes?.success && aiRes?.result) {
    session.aiClassification = aiRes.result.predictedClass || null
    session.aiThreatScore = aiRes.result.threatScore || 0
    logger.info(
      `[HP] AI classified session ${session.sessionId}: ${session.aiClassification} (${session.aiThreatScore})`
    )

    const score = session.aiThreatScore
    const aiResult = aiRes.result
    let predictionCreatedThreat = false

    // Store genuine AI prediction so AI Analytics metrics, charts, and logs are updated
    try {
      const aiDbSvc = require('./aiService')
      const prediction = await aiDbSvc.storePrediction({
        inputSource: 'honeypot_log',
        sourceIP: session.sourceIP,
        targetIP: session.honeypotNode || 'INTERNAL',
        predictedClass: session.aiClassification || 'SSH Brute Force',
        classProbabilities: aiResult.classProbabilities,
        threatScore: score,
        // Session features are rule-synthesised (see predictor.predict_from_honeypot); say so in the record
        modelVersion: `${aiResult.modelVersion || 'v2.1'}+${aiResult.classificationMethod || 'rule_profile_synthetic_flow'}`,
        modelType: 'random_forest',
        isAnomaly: aiResult.isAnomaly || false,
        anomalyScore: aiResult.anomalyScore || 0,
        inferenceTimeMs: aiResult.inferenceTimeMs ?? null,
        generatedThreat: session.linkedThreatLog || null,
        rawFeatures: payload,
      })
      if (!session.linkedThreatLog && prediction?.generatedThreat) {
        session.linkedThreatLog = prediction.generatedThreat
        // storePrediction already applies containment and emits the new threat.
        predictionCreatedThreat = true
      }
    } catch (predErr) {
      logger.error('[HP] Failed to store AI prediction: ' + predErr.message)
    }

    const SystemSetting = require('../models/SystemSetting')
    const setting = await SystemSetting.findOne({ key: 'autoBlockEnabled' })
    const autoBlockEnabled = setting ? setting.value === true : false
    const blockThreshold = await aiSvc.getBlockThreshold()
    const shouldBlock = score >= blockThreshold && autoBlockEnabled

    if (session.linkedThreatLog && !predictionCreatedThreat) {
      const ThreatLog = require('../models/ThreatLog')
      const mappedSeverity = score >= 0.85 ? 'CRITICAL' : score >= 0.7 ? 'HIGH' : score >= 0.4 ? 'MEDIUM' : 'LOW'
      const validAttackTypes = [
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
      ]
      const resolvedAttackType =
        session.aiClassification && validAttackTypes.includes(session.aiClassification)
          ? session.aiClassification
          : 'SSH Brute Force'

      const existingThreat = await ThreatLog.findById(session.linkedThreatLog)
      if (existingThreat) {
        existingThreat.attackType = resolvedAttackType
        existingThreat.aiScore = score
        existingThreat.severity = mappedSeverity
        if (existingThreat.notes?.startsWith('[SESSION_OPEN_HEURISTIC]')) {
          existingThreat.notes = existingThreat.notes.replace(
            /^\[SESSION_OPEN_HEURISTIC\][^\r\n]*/,
            '[RF_IF_RECLASSIFIED] RF/IF inference replaced the initial fixed SSH session-open signal.'
          )
        }

        if (shouldBlock && existingThreat.status !== 'BLOCKED') {
          existingThreat.preBlockStatus = score >= 0.7 ? 'MONITORING' : 'DETECTED'
          existingThreat.status = 'BLOCKED'
          existingThreat.autonomousAction = { taken: true, actionType: 'IP_BLOCKED', actionTime: new Date() }
          await existingThreat.save()

          try {
            const containmentService = require('./containmentService')
            await containmentService.executeAutoBlock({
              threat: existingThreat,
              threatScore: score,
              source: 'AI Classifier',
              sourceRef: { refModel: 'HoneypotSession', refId: session._id },
            })
          } catch (autoErr) {
            logger.error(`[AI Auto-Block Session] Auto-block execution failed: ${autoErr.message}`)
          }
        } else {
          // Reclassification must not undo an existing containment decision.
          if (existingThreat.status !== 'BLOCKED') {
            existingThreat.status = score >= 0.7 ? 'MONITORING' : 'DETECTED'
          }
          await existingThreat.save()
        }

        try {
          const socketManager = require('../websocket/socketManager')
          socketManager.emitThreatUpdated(existingThreat)
        } catch (e) {
          logger.debug('[HP] Threat update emission failed: ' + e.message)
        }
      }
    } else if (!predictionCreatedThreat && shouldBlock) {
      const BlockedIP = require('../models/BlockedIP')
      const { checkTargetSafety } = require('./containmentPolicyService')
      const safety = checkTargetSafety(session.sourceIP)
      try {
        if (!safety.isSafe) {
          logger.warn(`[AI Auto-Block Session] Refused for ${session.sourceIP}: ${safety.reason}`)
          return finishClosure(session, payload)
        }
        const block = await BlockedIP.findOneAndUpdate(
          { ip: session.sourceIP },
          {
            $setOnInsert: {
              ip: session.sourceIP,
              reason: `AI Honeypot Session Block (threatScore = ${score})`,
              blockedAt: new Date(),
              blockedBy: null,
              threatRef: null,
            },
          },
          { upsert: true, new: true, includeResultMetadata: true }
        )
        // An already blocked IP does not produce a second containment alert/action.
        if (block?.lastErrorObject?.upserted) {
          const socketManager = require('../websocket/socketManager')
          const alertService = require('./alertService')
          const alert = await alertService.createAlert({
            title: 'IP Added to Deny-List (Auto)',
            message: `IP ${session.sourceIP} added to the SentinelAI deny-list by the honeypot session scorer (Score: ${Math.round(score * 100)}%). Enforced by the honeypot blocker only; no host firewall rule was applied.`,
            severity: 'HIGH',
            type: 'IP_BLOCKED',
            sourceRef: { refModel: 'HoneypotSession', refId: session._id },
          })
          socketManager.emitIPBlocked(session.sourceIP, 'AI Classifier', null)
          socketManager.emitNewAlert(alert)
        }
      } catch (err) {
        logger.error(`[AI Auto-Block Session] BlockedIP or alert failed: ${err.message}`)
      }
    }
  }
  return finishClosure(session, payload)
}

const finishClosure = async (session, payload) => {
  const decRes = await aiSvc.getDeceptionScore(payload)
  if (decRes?.success && decRes?.result) {
    session.qDeceptionScore = decRes.result.deceptionScore || 0
    session.recommendedProfile = decRes.result.nextProfile || 'ubuntu_22'
    logger.info(
      `[HP] Q-learner scored session ${session.sessionId}: ${session.qDeceptionScore} (Next Profile: ${session.recommendedProfile})`
    )
  }
  await session.save()
  logger.info(`[HP] Session ${session.sessionId} closed. Duration: ${session.durationSeconds}s`)

  try {
    const campaignSvc = require('./campaignService')
    await campaignSvc.clusterSession(session)
  } catch (err) {
    logger.error(`[HP] Campaign clustering failed for session ${session.sessionId}: ${err.message}`)
  }

  return session
}

const getFullAnalytics = async (now = new Date()) => {
  const today = reportTime.filter(1, now)
  const weekAgo = reportTime.filter(7, now)
  const [
    totalToday,
    uniqueIPsToday,
    nodeSummary,
    topCommands,
    topAttackers,
    engagementDist,
    dailySessions,
    avgEngagement,
  ] = await Promise.all([
    HoneypotSession.countDocuments({ createdAt: today }),
    HoneypotSession.distinct('sourceIP', { createdAt: today }),
    HoneypotSession.aggregate([
      { $match: { createdAt: today } },
      {
        $group: {
          _id: '$honeypotNode',
          sessions: { $sum: 1 },
          avgDuration: { $avg: '$durationSeconds' },
          avgDeception: { $avg: '$deceptionScore' },
        },
      },
      { $sort: { sessions: -1 } },
    ]),
    HoneypotSession.aggregate([
      { $unwind: '$commands' },
      { $group: { _id: '$commands.command', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]),
    HoneypotSession.aggregate([
      {
        $group: {
          _id: '$sourceIP',
          sessions: { $sum: 1 },
          avgDeception: { $avg: '$deceptionScore' },
          totalCommands: { $sum: { $size: '$commands' } },
        },
      },
      { $sort: { sessions: -1 } },
      { $limit: 10 },
    ]),
    HoneypotSession.aggregate([{ $group: { _id: '$engagementLevel', count: { $sum: 1 } } }]),
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
      { $group: { _id: reportTime.dayGroup(), sessions: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]),
    HoneypotSession.aggregate([
      {
        $group: {
          _id: null,
          avgDuration: { $avg: '$durationSeconds' },
          avgDeception: { $avg: '$deceptionScore' },
          avgCommands: { $avg: { $size: '$commands' } },
        },
      },
    ]),
  ])
  const avg = avgEngagement[0] || { avgDuration: 0, avgDeception: 0, avgCommands: 0 }
  return {
    reporting: reportTime.reporting(now),
    kpis: {
      totalToday,
      uniqueIPsToday: uniqueIPsToday.length,
      avgDurationSecs: Math.round(avg.avgDuration || 0),
      avgDeceptionScore: parseFloat((avg.avgDeception || 0).toFixed(1)),
      avgCommandsPerSession: parseFloat((avg.avgCommands || 0).toFixed(1)),
    },
    charts: { nodeSummary, topCommands, engagementDist, dailySessions },
    intelligence: { topAttackers },
  }
}

const getNodeStatus = async (now = new Date()) => {
  const today = reportTime.filter(1, now)
  // Only nodes that exist in this repository. HTTP/FTP/SMTP decoys were listed here previously but
  // were never implemented; do not re-add them without a real collector.
  const NODES = [{ name: 'SSH-COWRIE-01', protocol: 'SSH', port: 2222 }]
  return Promise.all(
    NODES.map(async (node) => {
      const [sessionsToday, activeSessions] = await Promise.all([
        HoneypotSession.countDocuments({ honeypotNode: node.name, createdAt: today }),
        HoneypotSession.countDocuments({ honeypotNode: node.name, status: 'active' }),
      ])
      return { ...node, sessionsToday, activeSessions, status: sessionsToday > 0 ? 'active' : 'idle' }
    })
  )
}

module.exports = {
  findSessions,
  findSessionById,
  findBySessionId,
  createSession,
  appendCommands,
  closeSession,
  getFullAnalytics,
  getNodeStatus,
  getActiveProfile,
  setActiveProfile,
  DECEPTION_PROFILES,
}
