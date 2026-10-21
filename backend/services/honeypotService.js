const reportTime = require('../utils/reportingTime')
const HoneypotSession = require('../models/HoneypotSession')
const logger = require('../utils/logger')
const aiSvc = require('./aiEngineService')
const { escapeRegex, parsePagination } = require('../utils/querySecurity')
const { redactCapturedCredentials } = require('../utils/redact')
const mitreMapping = require('../utils/mitreMapping')

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

// The persona served in the session that started before this one (the learner's state). Bounded by this
// session's start, so a closure that is analysed late (or retried) is not given a later session's persona.
const findPreviousServedProfile = async (excludeId, before) => {
  try {
    const filter = { _id: { $ne: excludeId }, servedProfile: { $ne: null } }
    if (before instanceof Date && !Number.isNaN(before.getTime())) filter.createdAt = { $lt: before }
    return await HoneypotSession.findOne(filter).sort({ createdAt: -1 }).select('servedProfile').lean()
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

// M4: per-session array caps, so one long or brute-force session cannot approach MongoDB's 16 MB document
// limit (commands are ≤ 2048 chars each). Totals are kept in commandCount / credentialCount.
const limits = () => ({
  commands: parseInt(process.env.HONEYPOT_MAX_COMMANDS, 10) || 2000,
  credentials: parseInt(process.env.HONEYPOT_MAX_CREDENTIALS, 10) || 500,
  eventIds: parseInt(process.env.HONEYPOT_MAX_EVENT_IDS, 10) || 5000,
})

/**
 * H3: true once this hour's honeypot-originated auto-blocks reach HONEYPOT_AUTOBLOCK_MAX_PER_HOUR (default
 * 20). Counts deny-list entries written by the honeypot closure paths ("AI Classifier" via executeAutoBlock,
 * "AI Honeypot Session Block" via the direct path). Fails closed: an unreadable count blocks nothing.
 */
const honeypotAutoBlockBudgetSpent = async (now = new Date()) => {
  const cap = parseInt(process.env.HONEYPOT_AUTOBLOCK_MAX_PER_HOUR, 10)
  const max = Number.isInteger(cap) && cap >= 0 ? cap : 20
  try {
    const BlockedIP = require('../models/BlockedIP')
    const recent = await BlockedIP.countDocuments({
      blockedAt: { $gte: new Date(now.getTime() - 3600 * 1000) },
      reason: { $regex: /^(AI Classifier|AI Honeypot Session Block)/ },
    })
    return recent >= max
  } catch (err) {
    logger.warn('[HP] Auto-block budget unreadable, not blocking: ' + err.message)
    return true
  }
}

/**
 * One "awaiting approval" alert per threat for a honeypot block the policy withheld; the analyst blocks it
 * (or not) through the normal manual containment flow. Failures are logged, never thrown into the closure.
 */
const requestBlockApproval = async (threat, session, score, reason) => {
  try {
    const Alert = require('../models/Alert')
    const title = 'Honeypot block awaiting approval'
    if (await Alert.exists({ title, 'sourceRef.refId': threat._id })) return null
    const alert = await require('./alertService').createAlert({
      title,
      message: `${session.sourceIP} scored ${Math.round(score * 100)}% in the honeypot; not blocked (${reason}). Review the threat and block it manually if warranted.`,
      severity: 'HIGH',
      type: 'AUTONOMOUS_ACTION',
      sourceRef: { refModel: 'ThreatLog', refId: threat._id },
      targetRoles: ['admin', 'analyst'],
    })
    require('../websocket/socketManager').emitNewAlert?.(alert)
    return alert
  } catch (err) {
    logger.error('[HP] Block approval alert failed: ' + err.message)
    return null
  }
}

const SENSITIVE_FILES = ['/etc/passwd', '/etc/shadow', '/.ssh/', '/root/', '/.aws/credentials']
const sensitiveFilesIn = (text) => SENSITIVE_FILES.filter((f) => text.includes(f))
const urlsIn = (text) => text.match(/https?:\/\/[^\s]+/g) || []
const validDate = (value) => {
  const date = value ? new Date(value) : new Date()
  return Number.isNaN(date.getTime()) ? new Date() : date
}

// Every value below is attacker-controlled and goes through $literal, so a string such as "$x" is
// stored as text instead of being evaluated as a field path inside the update pipeline.
const unionWith = (path, values) => ({ $setUnion: [{ $ifNull: [path, []] }, { $literal: values }] })

/**
 * Atomically records honeypot activity and recomputes the derived scores in the same update, so
 * concurrent command/download events for one session cannot overwrite each other (read-modify-save
 * lost updates). deceptionScore = min(100, 3*commands + 10*sensitiveFiles + 8*urls + 15*downloads).
 * With an eventId, an event already applied to the session matches nothing and changes nothing: the
 * existing document is returned with $locals.duplicateEvent = true (replays, parser restarts, parser and
 * output plugin both delivering). Returns null when no session matches `filter`.
 */
const recordSessionActivity = async (
  filter,
  { commands = [], files = [], ips = [], urls = [], hashes = [], malware = [], downloads = 0, eventId } = {}
) => {
  // pre('save') does not run for updates; MITRE techniques are derived from intents and only ever grow.
  // Intent-level and per-command techniques (e.g. T1003.008 for /etc/shadow); the set only ever grows.
  const techniques = mitreMapping.getMitreTechniquesForSession(commands)
  const guarded = eventId ? { ...filter, ingestEventIds: { $ne: eventId } } : filter
  const max = limits()
  const updated = await HoneypotSession.findOneAndUpdate(
    guarded,
    [
      {
        $set: {
          ...(eventId && {
            // Most recent ids only (M4): replays of very old events are rare and bounded by the parser offset.
            ingestEventIds: {
              $slice: [
                { $concatArrays: [{ $ifNull: ['$ingestEventIds', []] }, { $literal: [eventId] }] },
                -max.eventIds,
              ],
            },
          }),
          // First max.commands kept (an attacker's opening commands are the most telling); all are counted.
          // Field references in this stage still see the pre-update document.
          commands: {
            $slice: [{ $concatArrays: [{ $ifNull: ['$commands', []] }, { $literal: commands }] }, max.commands],
          },
          // max(): documents created with commands (seed, older records) may carry a zero or missing count.
          commandCount: {
            $add: [
              { $max: [{ $ifNull: ['$commandCount', 0] }, { $size: { $ifNull: ['$commands', []] } }] },
              commands.length,
            ],
          },
          filesAccessed: unionWith('$filesAccessed', files),
          'iocExtracted.ips': unionWith('$iocExtracted.ips', ips),
          'iocExtracted.urls': unionWith('$iocExtracted.urls', urls),
          'iocExtracted.hashes': unionWith('$iocExtracted.hashes', hashes),
          malwareDownloaded: unionWith('$malwareDownloaded', malware),
          mitreTechniques: unionWith('$mitreTechniques', techniques),
          downloadCount: { $add: [{ $ifNull: ['$downloadCount', 0] }, downloads] },
        },
      },
      {
        $set: {
          deceptionScore: {
            $min: [
              100,
              {
                $add: [
                  { $multiply: ['$commandCount', 3] },
                  { $multiply: [{ $size: '$filesAccessed' }, 10] },
                  { $multiply: [{ $size: '$iocExtracted.urls' }, 8] },
                  { $multiply: ['$downloadCount', 15] },
                ],
              },
            ],
          },
          engagementLevel: {
            $switch: {
              branches: [
                { case: { $gte: ['$commandCount', 20] }, then: 'deep' },
                { case: { $gte: ['$commandCount', 10] }, then: 'high' },
                { case: { $gte: ['$commandCount', 5] }, then: 'medium' },
                { case: { $gte: ['$commandCount', 2] }, then: 'low' },
              ],
              default: 'minimal',
            },
          },
        },
      },
    ],
    { new: true }
  )
  if (updated || !eventId) return updated
  const already = await HoneypotSession.findOne({ ...filter, ingestEventIds: eventId })
  if (already) already.$locals.duplicateEvent = true
  return already
}

const appendCommands = async (id, commands) => {
  const text = commands.map((c) => c.command || '').join(' ')
  const urls = urlsIn(text)
  return recordSessionActivity(
    { _id: id },
    {
      // The pipeline bypasses schema validation, so enforce what CmdSchema requires here.
      commands: commands
        .filter((c) => typeof c.command === 'string' && c.command.length > 0)
        .map((c) => ({
          command: c.command,
          timestamp: validDate(c.timestamp),
          output: c.output || '',
          success: Boolean(c.success),
          intent: c.intent || null,
        })),
      files: sensitiveFilesIn(text),
      urls,
      malware: /wget|curl/i.test(text) ? urls : [],
    }
  )
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

/**
 * classify / score select the AI classification and the Q-learner update (both on a normal closure; only
 * the pending ones on a deferred retry). Either one that could not reach the AI engine is flagged pending
 * (aiAnalysisPending / deceptionScoringPending) for retryDeferredAnalysis instead of being silently lost.
 */
/**
 * Re-runs only the AI steps a completed closure could not finish because the AI engine was unreachable
 * (aiAnalysisPending / deceptionScoringPending). Claimed with the same compare-and-set as closeSession, so
 * it cannot overlap a closure or reclassification; each claim counts one attempt. Returns null when there
 * is nothing pending or another attempt holds the session.
 */
const retryDeferredAnalysis = async (id) => {
  const attemptId = require('node:crypto').randomUUID()
  const session = await HoneypotSession.findOneAndUpdate(
    {
      _id: id,
      closureAnalysisState: 'complete',
      $or: [{ aiAnalysisPending: true }, { deceptionScoringPending: true }],
    },
    {
      $set: { closureAnalysisState: 'processing', closureAttemptId: attemptId, closureAnalysisStartedAt: new Date() },
      $inc: { deferredAnalysisAttempts: 1 },
    },
    { new: true }
  )
  if (!session) return null
  try {
    const result = await analyseClosure(
      session,
      {},
      { classify: session.aiAnalysisPending, score: session.deceptionScoringPending, retry: true }
    )
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

const analyseClosure = async (session, telemetry, { classify = true, score: scoreQ = true, retry = false } = {}) => {
  if (!session.endTime) {
    session.endTime = new Date()
    session.durationSeconds =
      Number.isFinite(telemetry.durationSeconds) && telemetry.durationSeconds >= 0
        ? telemetry.durationSeconds
        : Math.floor((session.endTime - session.startTime) / 1000)
    if (Array.isArray(telemetry.credentials)) {
      const creds = redactCapturedCredentials(telemetry.credentials)
      session.credentialCount = Math.max(session.credentialCount || 0, session.credentials.length) + creds.length
      // M4: a brute-force session can carry thousands of attempts; keep the first ones, count all of them.
      session.credentials.push(...creds.slice(0, Math.max(0, limits().credentials - session.credentials.length)))
    }
    // An empty hassh (no kex seen by the sender) must not erase one stored from the CLIENT_KEX event.
    if (typeof telemetry.hassh === 'string' && telemetry.hassh) session.hassh = telemetry.hassh
    if (telemetry.ttylog && typeof telemetry.ttylog.sha256 === 'string') {
      const { sha256, size, path } = telemetry.ttylog
      session.ttylog = { sha256, size, path: typeof path === 'string' ? path : undefined }
    }
  }
  session.status = 'closed'
  // Credit the reward to the persona actually served, and give the learner the persona served in the
  // previous session as its state, so a recorded profile switch becomes a real state transition.
  if (!session.servedProfile) session.servedProfile = (await getActiveProfile()).profile
  const previous = await findPreviousServedProfile(session._id, session.createdAt)
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
  const finishOptions = { score: scoreQ, retry }
  const aiRes = classify ? await aiSvc.predictHoneypotSession(payload) : null
  if (classify) session.aiAnalysisPending = !(aiRes?.success && aiRes?.result)
  if (aiRes?.success && aiRes?.result) {
    session.aiClassification = aiRes.result.predictedClass || null
    session.aiThreatScore = aiRes.result.threatScore || 0
    session.aiClassificationMethod = aiRes.result.classificationMethod || 'honeypot_rules'
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
        // Cowrie sessions are classified by rules, not by a model (see predictor.predict_from_honeypot)
        modelVersion: `${aiResult.modelVersion || 'honeypot_rules_v2'}+${aiResult.classificationMethod || 'honeypot_rules'}`,
        modelType: 'rules',
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
    const alertThreshold = await aiSvc.getAlertThreshold()
    let shouldBlock = score >= blockThreshold && autoBlockEnabled
    // Honeypot-originated blocks can need a human (Phase 5): always with HONEYPOT_AUTOBLOCK_MODE=approve, and
    // (H3) once the hourly cap is reached, since anyone holding HONEYPOT_API_KEY can fabricate high scores.
    let approvalReason = null
    if (shouldBlock && String(process.env.HONEYPOT_AUTOBLOCK_MODE || '').toLowerCase() === 'approve') {
      approvalReason = 'HONEYPOT_AUTOBLOCK_MODE=approve'
    } else if (shouldBlock && (await honeypotAutoBlockBudgetSpent())) {
      approvalReason = 'hourly honeypot auto-block cap reached'
    }
    if (approvalReason) {
      shouldBlock = false
      logger.warn(`[AI Auto-Block Session] ${session.sourceIP} left for approval: ${approvalReason}`)
    }

    if (session.linkedThreatLog && !predictionCreatedThreat) {
      const ThreatLog = require('../models/ThreatLog')
      const mappedSeverity = require('../utils/severity').severityFor(score, { alertThreshold, blockThreshold })
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
        // M1: sessions from one IP share a threat, so a later, milder session must not downgrade it.
        const heuristic = Boolean(existingThreat.notes?.startsWith('[SESSION_OPEN_HEURISTIC]'))
        const raise = heuristic || !(score < (existingThreat.aiScore || 0))
        if (raise) {
          existingThreat.attackType = resolvedAttackType
          existingThreat.aiScore = score
          existingThreat.severity = mappedSeverity
        }
        if (heuristic) {
          existingThreat.notes = existingThreat.notes.replace(
            /^\[SESSION_OPEN_HEURISTIC\][^\r\n]*/,
            // Honeypot sessions are classified by rules (predictor.predict_from_honeypot), never RF/IF.
            '[HONEYPOT_RULES_RECLASSIFIED] Honeypot rule classification replaced the initial fixed SSH session-open signal.'
          )
        }

        if (shouldBlock && existingThreat.status !== 'BLOCKED') {
          existingThreat.preBlockStatus = score >= alertThreshold ? 'MONITORING' : 'DETECTED'
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
          if (existingThreat.status !== 'BLOCKED' && raise) {
            existingThreat.status = score >= alertThreshold ? 'MONITORING' : 'DETECTED'
          }
          await existingThreat.save()
        }

        try {
          const socketManager = require('../websocket/socketManager')
          socketManager.emitThreatUpdated(existingThreat)
        } catch (e) {
          logger.debug('[HP] Threat update emission failed: ' + e.message)
        }
        if (approvalReason) await requestBlockApproval(existingThreat, session, score, approvalReason)
        // Phase 5: honeypot threats get the same background AbuseIPDB enrichment as flow threats
        // (threatIntelService applies its own score/key/cache policy; a no-op without ABUSEIPDB_API_KEY).
        if (raise && score >= alertThreshold) {
          setImmediate(() => {
            try {
              require('./threatIntelService')
                .enrichThreat(existingThreat)
                .catch((e) => logger.debug('[HP] Threat intel enrichment error: ' + e.message))
            } catch (e) {
              logger.debug('[HP] Threat intel enrichment unavailable: ' + e.message)
            }
          })
        }
      }
    } else if (!predictionCreatedThreat && shouldBlock) {
      const BlockedIP = require('../models/BlockedIP')
      const { checkTargetSafety } = require('./containmentPolicyService')
      const safety = checkTargetSafety(session.sourceIP)
      try {
        if (!safety.isSafe) {
          logger.warn(`[AI Auto-Block Session] Refused for ${session.sourceIP}: ${safety.reason}`)
          return finishClosure(session, payload, finishOptions)
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
  return finishClosure(session, payload, finishOptions)
}

// Sessions invented by `log_parser.py --demo` travel the real ingest path. They must not train the deception
// Q-learner, whose table is meant to reflect attackers. Same convention as retentionService (demo-*).
const isSyntheticSession = (sessionId) => /^demo-/i.test(String(sessionId || ''))

const finishClosure = async (session, payload, { score = true, retry = false } = {}) => {
  const synthetic = isSyntheticSession(session.sessionId)
  if (synthetic) logger.info(`[HP] Synthetic session ${session.sessionId}: Q-learner update skipped`)
  const decRes = synthetic || !score ? null : await aiSvc.getDeceptionScore(payload)
  if (synthetic) session.deceptionScoringPending = false
  else if (score) session.deceptionScoringPending = !(decRes?.success && decRes?.result)
  if (decRes?.success && decRes?.result) {
    session.qDeceptionScore = decRes.result.deceptionScore || 0
    session.recommendedProfile = decRes.result.nextProfile || null
    logger.info(
      `[HP] Q-learner scored session ${session.sessionId}: ${session.qDeceptionScore} (Next Profile: ${session.recommendedProfile})`
    )
  }
  await session.save()
  logger.info(`[HP] Session ${session.sessionId} closed. Duration: ${session.durationSeconds}s`)
  // A deferred retry re-runs only the AI steps; the session was clustered when it closed.
  if (retry) return session

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
    // Every aggregate below is bounded to the 7-day reporting window (M6): unbounded $unwind/$group
    // over all sessions grew linearly with history.
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
      { $unwind: '$commands' },
      { $group: { _id: '$commands.command', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]),
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
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
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
      { $group: { _id: '$engagementLevel', count: { $sum: 1 } } },
    ]),
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
      { $group: { _id: reportTime.dayGroup(), sessions: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]),
    HoneypotSession.aggregate([
      { $match: { createdAt: weekAgo } },
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
    reporting: { ...reportTime.reporting(now), analyticsWindow: reportTime.metadata(7, now) },
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

const topCounts = (values, n = 5) => {
  const counts = new Map()
  for (const v of values) if (v) counts.set(v, (counts.get(v) || 0) + 1)
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, n)
    .map(([value, count]) => ({ value, count }))
}

/**
 * Attacker profiles (Phase 5): sessions grouped by SSH client fingerprint (HASSH) over the last `days`,
 * with the client banners, source IPs, usernames tried, commands run and how many sessions logged in.
 * One HASSH is one client implementation/configuration, so a botnet's members usually share it.
 */
const getAttackerProfiles = async ({ days = 30, limit = 50, now = new Date() } = {}) => {
  const safeDays = Math.min(Math.max(parseInt(days, 10) || 30, 1), 365)
  const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200)
  const groups = await HoneypotSession.aggregate([
    { $match: { createdAt: { $gte: new Date(now.getTime() - safeDays * 86400000) }, hassh: { $nin: [null, ''] } } },
    {
      $group: {
        _id: '$hassh',
        sessions: { $sum: 1 },
        ips: { $addToSet: '$sourceIP' },
        clientVersions: { $addToSet: '$clientVersion' },
        usernames: { $push: '$credentials.username' },
        commands: { $push: '$commands.command' },
        loggedInSessions: { $sum: { $cond: [{ $in: [true, { $ifNull: ['$credentials.success', []] }] }, 1, 0] } },
        firstSeen: { $min: '$createdAt' },
        lastSeen: { $max: '$createdAt' },
      },
    },
    { $sort: { sessions: -1, lastSeen: -1 } },
    { $limit: safeLimit },
  ])
  return groups.map((g) => ({
    hassh: g._id,
    sessions: g.sessions,
    distinctIPs: g.ips.length,
    ips: g.ips.slice(0, 10),
    clientVersions: g.clientVersions.filter(Boolean),
    topUsernames: topCounts(g.usernames.flat()),
    topCommands: topCounts(g.commands.flat()),
    loggedInSessions: g.loggedInSessions,
    firstSeen: g.firstSeen,
    lastSeen: g.lastSeen,
  }))
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
      // L4: liveness comes from the blocker plugin's polls, not from whether an attacker connected today.
      const { liveness, lastSeen } = require('./honeypotHeartbeat').status(now)
      const status = liveness === 'online' ? 'active' : liveness
      return { ...node, sessionsToday, activeSessions, status, liveness, lastSeen }
    })
  )
}

module.exports = {
  findSessions,
  findSessionById,
  findBySessionId,
  createSession,
  appendCommands,
  recordSessionActivity,
  sensitiveFilesIn,
  closeSession,
  retryDeferredAnalysis,
  getFullAnalytics,
  getNodeStatus,
  getAttackerProfiles,
  getActiveProfile,
  setActiveProfile,
  DECEPTION_PROFILES,
}
